package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ReadConfigFile parses a WireGuard .conf file in standard INI format.
//
// Supported format:
//
//	[Interface]
//	PrivateKey = <base64>
//	Address = 10.0.0.2/24
//	DNS = 1.1.1.1, 8.8.8.8
//	MTU = 1420
//
//	[Peer]
//	PublicKey = <base64>
//	PresharedKey = <base64>
//	Endpoint = vpn.example.com:51820
//	AllowedIPs = 0.0.0.0/0, ::/0
//	PersistentKeepalive = 25
func ReadConfigFile(filePath string) (*WireGuardOptions, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadConfig, err)
	}
	defer f.Close()

	opts := &WireGuardOptions{}
	scanner := bufio.NewScanner(f)
	section := "" // "Interface" or "Peer"

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(line[1 : len(line)-1])
			continue
		}

		// Key = Value
		eqIdx := strings.IndexByte(line, '=')
		if eqIdx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eqIdx])
		value := strings.TrimSpace(line[eqIdx+1:])
		keyLower := strings.ToLower(key)

		switch section {
		case "interface":
			if err := parseInterfaceOption(opts, keyLower, value); err != nil {
				return nil, err
			}
		case "peer":
			if err := parsePeerOption(opts, keyLower, value); err != nil {
				return nil, err
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: read config: %s", ErrBadConfig, err)
	}

	// Validate minimum config
	if !opts.HasAuth() {
		return nil, fmt.Errorf("%w: missing PrivateKey or Peer PublicKey", ErrBadConfig)
	}

	return opts, nil
}

func parseInterfaceOption(opts *WireGuardOptions, key, value string) error {
	switch key {
	case "privatekey":
		k, err := DecodeKey(value)
		if err != nil {
			return err
		}
		opts.PrivateKey = k
	case "address":
		opts.Address = value
	case "dns":
		parts := strings.Split(value, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				opts.DNS = append(opts.DNS, p)
			}
		}
	case "mtu":
		mtu, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("%w: invalid MTU: %s", ErrBadConfig, value)
		}
		opts.MTU = mtu
	}
	return nil
}

func parsePeerOption(opts *WireGuardOptions, key, value string) error {
	switch key {
	case "publickey":
		k, err := DecodeKey(value)
		if err != nil {
			return err
		}
		opts.Peer.PublicKey = k
	case "presharedkey":
		k, err := DecodeKey(value)
		if err != nil {
			return err
		}
		opts.Peer.PresharedKey = k
		opts.Peer.HasPresharedKey = true
	case "endpoint":
		opts.Peer.Endpoint = value
	case "allowedips":
		parts := strings.Split(value, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				opts.Peer.AllowedIPs = append(opts.Peer.AllowedIPs, p)
			}
		}
	case "persistentkeepalive":
		secs, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("%w: invalid PersistentKeepalive: %s", ErrBadConfig, value)
		}
		opts.Peer.PersistentKeepalive = secs
	}
	return nil
}
