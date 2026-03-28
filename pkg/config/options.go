package config

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// ErrBadConfig is the error returned for invalid WireGuard config files.
var ErrBadConfig = errors.New("wireguard: bad config")

// WireGuardOptions holds all WireGuard configuration.
type WireGuardOptions struct {
	// Interface section
	PrivateKey [32]byte
	Address    string   // e.g. "10.0.0.2/24"
	DNS        []string // e.g. ["1.1.1.1", "8.8.8.8"]
	MTU        int      // e.g. 1420

	// Peer section
	Peer PeerOptions
}

// PeerOptions holds a single peer's configuration.
type PeerOptions struct {
	PublicKey           [32]byte
	PresharedKey        [32]byte
	HasPresharedKey     bool
	Endpoint            string   // e.g. "vpn.example.com:51820"
	AllowedIPs          []string // e.g. ["0.0.0.0/0", "::/0"]
	PersistentKeepalive int      // seconds, 0 = disabled
}

// HasAuth returns true if the minimum config is available (private key + peer public key).
func (o *WireGuardOptions) HasAuth() bool {
	zeroKey := [32]byte{}
	return o.PrivateKey != zeroKey && o.Peer.PublicKey != zeroKey
}

// DecodeKey decodes a base64-encoded WireGuard key (standard encoding).
func DecodeKey(s string) ([32]byte, error) {
	var key [32]byte
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return key, fmt.Errorf("%w: invalid key encoding: %s", ErrBadConfig, err)
	}
	if len(decoded) != 32 {
		return key, fmt.Errorf("%w: key must be 32 bytes, got %d", ErrBadConfig, len(decoded))
	}
	copy(key[:], decoded)
	return key, nil
}

// EncodeKey encodes a key to base64.
func EncodeKey(key [32]byte) string {
	return base64.StdEncoding.EncodeToString(key[:])
}
