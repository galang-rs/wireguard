package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/galang-rs/wireguard/pkg/config"
	"github.com/galang-rs/wireguard/pkg/tunnel"
)

func main() {
	// 1. Load configuration from .conf file
	configFile := "wg0.conf"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		fmt.Printf("Error: %s not found.\n", configFile)
		fmt.Println("Usage: wg [config.conf]")
		os.Exit(1)
	}

	cfg := config.NewConfig(config.WithConfigFile(configFile))

	// 2. Print connection info
	opts := cfg.WireGuardOptions()
	remote := cfg.Remote()
	fmt.Printf("Endpoint: %s (%s)\n", remote.Endpoint, remote.Protocol)
	fmt.Printf("Address:  %s\n", opts.Address)
	fmt.Printf("Peer PK:  %s...%s\n",
		config.EncodeKey(opts.Peer.PublicKey)[:8],
		config.EncodeKey(opts.Peer.PublicKey)[36:])
	if opts.Peer.HasPresharedKey {
		fmt.Printf("PSK:      ✓ (configured)\n")
	}
	if len(opts.Peer.AllowedIPs) > 0 {
		fmt.Printf("Allowed:  %v\n", opts.Peer.AllowedIPs)
	}

	// 3. Start VPN tunnel
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialer := &net.Dialer{}

	fmt.Println("\nStarting WireGuard tunnel...")
	tun, err := tunnel.Start(ctx, dialer, cfg)
	if err != nil {
		fmt.Printf("Failed to start VPN: %v\n", err)
		os.Exit(1)
	}
	defer tun.Close()

	// 4. Print tunnel info
	ti := tun.TunnelInfo()
	fmt.Printf("\n✓ WireGuard Connected!\n")
	fmt.Printf("  Tunnel IP: %s/%s\n", ti.IP, ti.NetMask)
	fmt.Printf("  Endpoint:  %s\n", ti.GW)
	if ti.MTU > 0 {
		fmt.Printf("  MTU:       %d\n", ti.MTU)
	}
	fmt.Println("\nPress Ctrl+C to disconnect.")

	// 5. Handle termination
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case <-sigCh:
		fmt.Println("\nDisconnecting...")
	case <-tun.Hangup:
		fmt.Println("\nConnection closed.")
	}
}
