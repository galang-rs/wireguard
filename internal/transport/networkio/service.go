// Package networkio handles low-level UDP network I/O for WireGuard.
// WireGuard always uses UDP — no TCP framing needed.
package networkio

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/galang-rs/wireguard/internal/worker"
	"github.com/galang-rs/wireguard/pkg/config"
)

// UDPConn wraps a net.Conn for UDP datagram I/O.
type UDPConn struct {
	net.Conn
	mu sync.Mutex
}

// ReadPacket reads one UDP datagram.
func (c *UDPConn) ReadPacket() ([]byte, error) {
	buf := make([]byte, 65536)
	n, err := c.Conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// WritePacket writes one UDP datagram.
func (c *UDPConn) WritePacket(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.Conn.Write(data)
	return err
}

// Dial dials a UDP connection to the WireGuard peer.
func Dial(ctx context.Context, dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}, endpoint string) (*UDPConn, error) {
	conn, err := dialer.DialContext(ctx, "udp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("networkio: dial udp %s: %w", endpoint, err)
	}
	return &UDPConn{Conn: conn}, nil
}

// Service is the NetworkIO service handling raw UDP I/O.
type Service struct {
	// MuxerToNetwork moves bytes from the muxer to the network.
	MuxerToNetwork chan []byte

	// NetworkToMuxer is a pointer set during wiring.
	NetworkToMuxer *chan []byte
}

// StartWorkers starts the network I/O workers.
func (svc *Service) StartWorkers(cfg *config.Config, wm *worker.Manager, conn *UDPConn) {
	ws := &nioWorkerState{
		logger:         cfg.Logger(),
		conn:           conn,
		muxerToNetwork: svc.MuxerToNetwork,
		networkToMuxer: *svc.NetworkToMuxer,
		workersManager: wm,
	}
	wm.StartWorker(ws.readWorker)
	wm.StartWorker(ws.writeWorker)
}

type nioWorkerState struct {
	logger         config.Logger
	conn           *UDPConn
	muxerToNetwork <-chan []byte
	networkToMuxer chan<- []byte
	workersManager *worker.Manager
}

func (ws *nioWorkerState) readWorker() {
	defer func() {
		ws.workersManager.OnWorkerDone("networkio: readWorker")
		ws.workersManager.StartShutdown()
	}()
	ws.logger.Debugf("networkio: readWorker: started")

	for {
		data, err := ws.conn.ReadPacket()
		if err != nil {
			ws.logger.Warnf("networkio: readWorker: %s", err)
			return
		}
		select {
		case ws.networkToMuxer <- data:
		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

func (ws *nioWorkerState) writeWorker() {
	defer func() {
		ws.workersManager.OnWorkerDone("networkio: writeWorker")
		ws.workersManager.StartShutdown()
	}()
	ws.logger.Debugf("networkio: writeWorker: started")

	for {
		select {
		case data := <-ws.muxerToNetwork:
			if err := ws.conn.WritePacket(data); err != nil {
				ws.logger.Warnf("networkio: writeWorker: %s", err)
				return
			}
		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}
