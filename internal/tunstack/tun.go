// Package tunstack provides a pure-Go TUN device that reads/writes raw IP packets
// through the WireGuard tunnel. Same architecture as the OpenVPN version.
package tunstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/galang-rs/wireguard/internal/crypto"
	"github.com/galang-rs/wireguard/internal/domain"
	"github.com/galang-rs/wireguard/internal/session"
	"github.com/galang-rs/wireguard/internal/transport/data"
	"github.com/galang-rs/wireguard/internal/transport/handshake"
	"github.com/galang-rs/wireguard/internal/transport/muxer"
	"github.com/galang-rs/wireguard/internal/transport/networkio"
	"github.com/galang-rs/wireguard/internal/worker"
	"github.com/galang-rs/wireguard/pkg/config"
)

var (
	// handshakeTimeout is the max time to wait for handshake completion.
	handshakeTimeout = 30 * time.Second

	// ErrCannotHandshake is the error returned when WireGuard handshake fails.
	ErrCannotHandshake = errors.New("wireguard: handshake error")
)

// TUN is a virtual network device that reads/writes raw IP packets
// through the WireGuard tunnel.
type TUN struct {
	closeOnce  sync.Once
	conn       *networkio.UDPConn
	Hangup     chan any
	logger     config.Logger
	session    *session.Manager
	tunDown    chan []byte // IP packets going to the VPN (outbound)
	tunUp      chan []byte // IP packets from the VPN (inbound)
	whenDoneFn func()
}

// StartTUN initializes and starts the WireGuard tunnel, returning a TUN device.
func StartTUN(ctx context.Context, conn *networkio.UDPConn, cfg *config.Config) (*TUN, error) {
	sessionManager, err := session.NewManager(cfg)
	if err != nil {
		return nil, err
	}

	tunnel := &TUN{
		conn:       conn,
		Hangup:     make(chan any),
		logger:     cfg.Logger(),
		session:    sessionManager,
		tunDown:    make(chan []byte),
		tunUp:      make(chan []byte),
		whenDoneFn: func() {},
	}

	// Start all protocol workers
	wm := startWorkers(cfg, conn, sessionManager, tunnel)
	tunnel.whenDone(func() {
		wm.StartShutdown()
		wm.WaitWorkersShutdown()
	})

	// Wait for handshake completion
	timer := time.NewTimer(handshakeTimeout)
	select {
	case <-sessionManager.Ready:
		timer.Stop()
		return tunnel, nil
	case failure := <-sessionManager.Failure:
		timer.Stop()
		err := fmt.Errorf("%w: %s", ErrCannotHandshake, failure)
		tunnel.Close()
		return nil, err
	case <-timer.C:
		err := fmt.Errorf("%w: handshake timeout", ErrCannotHandshake)
		tunnel.Close()
		return nil, err
	case <-ctx.Done():
		timer.Stop()
		err := fmt.Errorf("%w: %w", ErrCannotHandshake, ctx.Err())
		tunnel.Close()
		return nil, err
	}
}

func (t *TUN) whenDone(fn func()) { t.whenDoneFn = fn }

// Close shuts down the TUN device and all workers.
func (t *TUN) Close() error {
	t.closeOnce.Do(func() {
		close(t.Hangup)
		t.conn.Close()
		t.whenDoneFn()
	})
	return nil
}

// Read reads a decrypted IP packet from the VPN (blocks until available).
func (t *TUN) Read(data []byte) (int, error) {
	select {
	case packet := <-t.tunUp:
		copy(data, packet)
		return len(packet), nil
	case <-t.Hangup:
		return 0, net.ErrClosed
	}
}

// Write sends an IP packet through the VPN.
func (t *TUN) Write(data []byte) (int, error) {
	buf := make([]byte, len(data))
	copy(buf, data)
	select {
	case t.tunDown <- buf:
		return len(data), nil
	case <-t.Hangup:
		return 0, net.ErrClosed
	}
}

// TunnelInfo returns the tunnel configuration (IP, GW, MTU, etc.)
func (t *TUN) TunnelInfo() domain.TunnelInfo {
	return t.session.TunnelInfo()
}

// LocalAddr returns the TUN local address.
func (t *TUN) LocalAddr() net.Addr {
	return &tunAddr{addr: t.session.TunnelInfo().IP, net: "tun"}
}

// RemoteAddr returns the TUN remote (gateway) address.
func (t *TUN) RemoteAddr() net.Addr {
	return &tunAddr{addr: t.session.TunnelInfo().GW, net: "tun"}
}

func (t *TUN) SetDeadline(tm time.Time) error     { return nil }
func (t *TUN) SetReadDeadline(tm time.Time) error  { return nil }
func (t *TUN) SetWriteDeadline(tm time.Time) error { return nil }

type tunAddr struct {
	addr string
	net  string
}

func (a *tunAddr) Network() string { return a.net }
func (a *tunAddr) String() string  { return a.addr }

// --- channel wiring helper ---

func connectChannel[T any](signal chan T, slot **chan T) {
	if signal == nil {
		panic("connectChannel: signal is nil")
	}
	*slot = &signal
}

// startWorkers wires and starts all transport layer workers.
func startWorkers(cfg *config.Config, conn *networkio.UDPConn,
	sm *session.Manager, tun *TUN) *worker.Manager {

	wm := worker.NewManager(cfg.Logger())

	nio := &networkio.Service{MuxerToNetwork: make(chan []byte, 16)}
	mx := &muxer.Service{
		TriggerHandshake:       make(chan any, 1),
		HandshakeOrDataToMuxer: make(chan []byte, 16),
		NetworkToMuxer:         make(chan []byte, 16),
	}

	connectChannel(nio.MuxerToNetwork, &mx.MuxerToNetwork)
	connectChannel(mx.NetworkToMuxer, &nio.NetworkToMuxer)

	dc := &data.Service{
		MuxerToData: make(chan []byte, 16),
		KeyReady:    make(chan *crypto.KeyPair, 1),
		TUNToData:   tun.tunDown,
		DataToTUN:   tun.tunUp,
	}

	connectChannel(dc.MuxerToData, &mx.MuxerToData)
	connectChannel(mx.HandshakeOrDataToMuxer, &dc.HandshakeOrDataToMuxer)

	hs := &handshake.Service{
		MuxerToHandshake: make(chan []byte, 4),
		KeyReady:         dc.KeyReady,
	}

	connectChannel(hs.MuxerToHandshake, &mx.MuxerToHandshake)
	connectChannel(mx.HandshakeOrDataToMuxer, &hs.HandshakeOrDataToMuxer)

	nio.StartWorkers(cfg, wm, conn)
	mx.StartWorkers(cfg, wm, sm)
	hs.StartWorkers(cfg, wm, sm)
	dc.StartWorkers(cfg, wm, sm)

	// Trigger the handshake initiation
	mx.TriggerHandshake <- true
	return wm
}
