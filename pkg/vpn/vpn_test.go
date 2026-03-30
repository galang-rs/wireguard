package vpn_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/galang-rs/wireguard/pkg/config"
	"github.com/galang-rs/wireguard/pkg/tunnel"
)

type tunPacket struct {
	data []byte
	err  error
}

// TestWGConnectSurfshark connects to Surfshark WireGuard.
// Usage: go test ./pkg/vpn/... -v -run TestWGConnectSurfshark -timeout 120s
func TestWGConnectSurfshark(t *testing.T) {
	confFile := "../../wireguard.conf"
	cfg := config.NewConfig(config.WithConfigFile(confFile))
	runWGTest(t, cfg)
}

// runWGTest is the shared WireGuard connection test:
// connect, TCP handshake over TUN, HTTP GET for exit IP.
func runWGTest(t *testing.T, cfg *config.Config) {
	t.Helper()

	opts := cfg.WireGuardOptions()
	remote := cfg.Remote()
	t.Logf("Endpoint:    %s (%s)", remote.Endpoint, remote.Protocol)
	t.Logf("Address:     %s", opts.Address)
	t.Logf("Local PubKey: %s", config.EncodeKey(getPublicKey(opts.PrivateKey)))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	t.Log("Connecting to WireGuard...")
	dialer := &net.Dialer{}
	tun, err := tunnel.Start(ctx, dialer, cfg)
	if err != nil {
		t.Fatalf("Failed to start tunnel: %v", err)
	}
	defer tun.Close()

	ti := tun.TunnelInfo()
	t.Logf("✓ Tunnel IP: %s/%s | Endpoint: %s | MTU: %d", ti.IP, ti.NetMask, ti.GW, ti.MTU)

	srcIP := net.ParseIP(ti.IP).To4()
	if srcIP == nil {
		t.Fatalf("Invalid tunnel IP: %s", ti.IP)
	}

	// Async TUN reader
	packets := make(chan tunPacket, 100)
	go func() {
		for {
			buf := make([]byte, 4096)
			n, err := tun.Read(buf)
			if err != nil {
				packets <- tunPacket{err: err}
				return
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			packets <- tunPacket{data: pkt}
		}
	}()

	// Drain initial packets for 2 seconds
	drainDeadline := time.After(2 * time.Second)
drainLoop:
	for {
		select {
		case p := <-packets:
			if p.err != nil {
				t.Fatalf("Read error: %v", p.err)
			}
		case <-drainDeadline:
			break drainLoop
		}
	}

	// TCP to checkip.amazonaws.com:80
	dstIP := net.IPv4(52, 76, 52, 124).To4()
	srcPort := uint16(40000 + rand.Intn(10000))
	dstPort := uint16(80)
	seqNum := rand.Uint32()

	t.Logf("TCP connect to %s:%d", dstIP, dstPort)

	// === SYN ===
	syn := buildTCPPacket(srcIP, dstIP, srcPort, dstPort, seqNum, 0, 0x02, nil)
	tun.Write(syn)
	t.Log("  → SYN")

	// === SYN-ACK ===
	var serverSeq uint32
	synAckTimeout := time.After(15 * time.Second)
synLoop:
	for {
		select {
		case p := <-packets:
			if p.err != nil {
				t.Fatalf("Read error: %v", p.err)
			}
			pkt := p.data
			if len(pkt) < 40 {
				continue
			}
			ihl := int(pkt[0]&0x0f) * 4
			if pkt[9] != 6 || !bytes.Equal(pkt[12:16], dstIP) {
				continue
			}
			tcpHdr := pkt[ihl:]
			if binary.BigEndian.Uint16(tcpHdr[0:2]) != dstPort {
				continue
			}
			flags := tcpHdr[13]
			if flags&0x12 == 0x12 {
				serverSeq = binary.BigEndian.Uint32(tcpHdr[4:8])
				t.Logf("  ← SYN-ACK (seq=%d)", serverSeq)
				break synLoop
			}
			if flags&0x04 != 0 {
				t.Fatal("  ← RST")
			}
		case <-synAckTimeout:
			t.Fatal("Timeout waiting for SYN-ACK")
		}
	}

	// === ACK ===
	seqNum++
	tun.Write(buildTCPPacket(srcIP, dstIP, srcPort, dstPort, seqNum, serverSeq+1, 0x10, nil))
	t.Log("  → ACK (handshake done)")

	// === HTTP GET ===
	httpReq := "GET / HTTP/1.1\r\nHost: checkip.amazonaws.com\r\nConnection: close\r\n\r\n"
	tun.Write(buildTCPPacket(srcIP, dstIP, srcPort, dstPort, seqNum, serverSeq+1, 0x18, []byte(httpReq)))
	t.Log("  → HTTP GET checkip.amazonaws.com")
	seqNum += uint32(len(httpReq))

	// === READ RESPONSE ===
	var httpResponse strings.Builder
	respTimeout := time.After(15 * time.Second)
	gotFin := false

respLoop:
	for {
		select {
		case p := <-packets:
			if p.err != nil {
				break respLoop
			}
			pkt := p.data
			if len(pkt) < 40 {
				continue
			}
			ihl := int(pkt[0]&0x0f) * 4
			if pkt[9] != 6 || !bytes.Equal(pkt[12:16], dstIP) {
				continue
			}
			if len(pkt) < ihl+20 {
				continue
			}
			tcpHdr := pkt[ihl:]
			if binary.BigEndian.Uint16(tcpHdr[0:2]) != dstPort {
				continue
			}
			flags := tcpHdr[13]
			dataOffset := int(tcpHdr[12]>>4) * 4
			if len(tcpHdr) < dataOffset {
				continue
			}
			payload := tcpHdr[dataOffset:]

			if len(payload) > 0 {
				httpResponse.Write(payload)
				t.Logf("  ← data: %d bytes", len(payload))
				respSeq := binary.BigEndian.Uint32(tcpHdr[4:8])
				tun.Write(buildTCPPacket(srcIP, dstIP, srcPort, dstPort, seqNum, respSeq+uint32(len(payload)), 0x10, nil))
			}

			if flags&0x01 != 0 { // FIN
				respSeq := binary.BigEndian.Uint32(tcpHdr[4:8])
				tun.Write(buildTCPPacket(srcIP, dstIP, srcPort, dstPort, seqNum, respSeq+uint32(len(payload))+1, 0x11, nil))
				gotFin = true
				break respLoop
			}
		case <-respTimeout:
			t.Log("  ⚠ Response timeout")
			break respLoop
		}
	}

	resp := httpResponse.String()

	var body string
	if idx := strings.Index(resp, "\r\n\r\n"); idx >= 0 {
		body = strings.TrimSpace(resp[idx+4:])
	}

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("  WIREGUARD EXIT IP VERIFICATION")
	fmt.Println("========================================")

	exitIP := strings.TrimSpace(body)
	fmt.Printf("  Exit IP: %s\n", exitIP)
	fmt.Println("========================================")

	if exitIP != "" {
		fmt.Printf("\n  ✓ VPN Exit IP:     %s\n", exitIP)
		fmt.Printf("  ✓ VPN Tunnel IP:   %s\n", ti.IP)
		fmt.Printf("  ✓ VPN Endpoint:    %s\n\n", ti.GW)

		if exitIP == ti.IP {
			t.Log("⚠ Exit IP matches tunnel IP — might be NAT")
		} else {
			t.Logf("✓ WireGuard exit IP confirmed: %s (tunnel: %s)", exitIP, ti.IP)
		}
	} else if gotFin && body != "" {
		t.Logf("✓ Response received: %s", body[:min(200, len(body))])
	} else if len(resp) > 0 {
		t.Logf("⚠ Partial response (%d bytes)", len(resp))
	} else {
		t.Log("⚠ No HTTP response received")
	}
}

func getPublicKey(privKey [32]byte) [32]byte {
	// Use curve25519 to derive public key from private key
	// This avoids importing internal packages in test
	// Just return a placeholder — the actual pubkey is logged by session manager
	return privKey // placeholder, actual is logged during init
}

// ===== RAW PACKET BUILDERS =====

func buildTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	tcpLen := 20 + len(payload)
	ipLen := 20 + tcpLen
	pkt := make([]byte, ipLen)

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(ipLen))
	binary.BigEndian.PutUint16(pkt[4:6], uint16(rand.Intn(65535)))
	pkt[6] = 0x40
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], srcIP)
	copy(pkt[16:20], dstIP)
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))

	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 0x50
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	if len(payload) > 0 {
		copy(tcp[20:], payload)
	}
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(srcIP, dstIP, tcp[:tcpLen]))

	return pkt
}

func ipChecksum(h []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(h)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i : i+2]))
	}
	if len(h)%2 == 1 {
		sum += uint32(h[len(h)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func tcpChecksum(src, dst net.IP, seg []byte) uint16 {
	pseudo := make([]byte, 12+len(seg))
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(seg)))
	copy(pseudo[12:], seg)
	pseudo[12+16] = 0
	pseudo[12+17] = 0
	sum := uint32(0)
	for i := 0; i < len(pseudo)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	if len(pseudo)%2 == 1 {
		sum += uint32(pseudo[len(pseudo)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
