package crypto

import (
	"golang.org/x/crypto/blake2s"
)

const (
	// LabelMAC1 is the label used for MAC1 computation.
	LabelMAC1 = "mac1----"
)

// MAC1Key derives the MAC1 key from a peer's public key.
// mac1_key = HASH("mac1----" || peer_public_key)
func MAC1Key(peerPublicKey [KeySize]byte) [HashSize]byte {
	return Hash(append([]byte(LabelMAC1), peerPublicKey[:]...))
}

// ComputeMAC1 computes the MAC1 for a message.
// mac1 = BLAKE2s-128(mac1_key, message_without_macs)
func ComputeMAC1(mac1Key [HashSize]byte, messageWithoutMACs []byte) [16]byte {
	mac, _ := blake2s.New128(mac1Key[:])
	mac.Write(messageWithoutMACs)
	var result [16]byte
	copy(result[:], mac.Sum(nil))
	return result
}

// ComputeMAC2 computes the MAC2 for a message using a cookie.
// mac2 = BLAKE2s-128(cookie, message_without_mac2)
func ComputeMAC2(cookie [KeySize]byte, messageWithoutMAC2 []byte) [16]byte {
	mac, _ := blake2s.New128(cookie[:])
	mac.Write(messageWithoutMAC2)
	var result [16]byte
	copy(result[:], mac.Sum(nil))
	return result
}
