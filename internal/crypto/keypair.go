package crypto

import "sync/atomic"

// KeyPair holds the derived transport encryption keys after a successful handshake.
type KeyPair struct {
	// SendKey is the key used to encrypt outgoing packets.
	SendKey [KeySize]byte

	// RecvKey is the key used to decrypt incoming packets.
	RecvKey [KeySize]byte

	// SendNonce is the atomic nonce counter for outgoing packets.
	SendNonce atomic.Uint64

	// LocalIndex is our sender index for transport messages.
	LocalIndex uint32

	// RemoteIndex is the peer's sender index (our receiver index).
	RemoteIndex uint32
}

// NextSendNonce atomically increments and returns the next nonce for sending.
func (kp *KeyPair) NextSendNonce() uint64 {
	return kp.SendNonce.Add(1) - 1
}
