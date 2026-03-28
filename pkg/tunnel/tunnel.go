// Package tunnel contains the public tunnel API for WireGuard.
package tunnel

import (
	"context"
	"errors"
	"net"

	"github.com/galang-rs/wireguard/internal/transport/networkio"
	"github.com/galang-rs/wireguard/internal/tunstack"
	"github.com/galang-rs/wireguard/pkg/config"
)

// SimpleDialer establishes network connections.
type SimpleDialer interface {
	DialContext(ctx context.Context, network, endpoint string) (net.Conn, error)
}

// TUN is the public VPN tunnel type (alias of internal tunstack.TUN).
type TUN = tunstack.TUN

// Start starts a WireGuard tunnel and returns a TUN device for raw IP packet I/O.
//
// Usage:
//
//	cfg := config.NewConfig(config.WithConfigFile("wg0.conf"))
//	tun, err := tunnel.Start(ctx, &net.Dialer{}, cfg)
//	// tun.Read() returns decrypted IP packets
//	// tun.Write() sends IP packets through VPN
//	// tun.TunnelInfo() returns assigned IP/GW/MTU
func Start(ctx context.Context, underlyingDialer SimpleDialer, cfg *config.Config) (*TUN, error) {
	if underlyingDialer == nil {
		return nil, errors.New("tunnel: underlyingDialer is nil")
	}

	remote := cfg.Remote()
	conn, err := networkio.Dial(ctx, underlyingDialer, remote.Endpoint)
	if err != nil {
		cfg.Logger().Errorf("tunnel: dial failed: %s", err)
		return nil, err
	}

	return tunstack.StartTUN(ctx, conn, cfg)
}
