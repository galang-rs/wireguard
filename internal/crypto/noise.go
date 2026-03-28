// Package crypto implements the WireGuard cryptographic primitives.
// Uses Noise IKpsk2 protocol with:
//   - Curve25519 for DH
//   - ChaCha20-Poly1305 for AEAD
//   - BLAKE2s for hashing and HMAC
package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"hash"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	// NoiseConstruction is the Noise protocol name.
	NoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"

	// WGIdentifier is the WireGuard protocol identifier.
	WGIdentifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"

	// KeySize is the size of a Curve25519 key.
	KeySize = 32

	// NonceSize is the size of ChaCha20-Poly1305 nonce.
	NonceSize = 12

	// TagSize is the size of Poly1305 tag.
	TagSize = 16

	// HashSize is the size of BLAKE2s-256 output.
	HashSize = 32

	// TAI64NSize is the size of TAI64N timestamp.
	TAI64NSize = 12
)

// InitialChainingKey is HASH(NoiseConstruction).
var InitialChainingKey [HashSize]byte

// InitialHash is HASH(HASH(NoiseConstruction) || WGIdentifier).
var InitialHash [HashSize]byte

func init() {
	InitialChainingKey = Hash([]byte(NoiseConstruction))
	h := Hash(append(InitialChainingKey[:], []byte(WGIdentifier)...))
	InitialHash = h
}

// blake2sNew256 returns a new unkeyed BLAKE2s-256 hash.
func blake2sNew256() hash.Hash {
	h, _ := blake2s.New256(nil)
	return h
}

// Hash computes BLAKE2s-256(data).
func Hash(data []byte) [HashSize]byte {
	return blake2s.Sum256(data)
}

// HMAC1 computes HMAC-BLAKE2s(key, data) using Go's standard crypto/hmac.
func HMAC1(key []byte, data []byte) [HashSize]byte {
	mac := hmac.New(blake2sNew256, key)
	mac.Write(data)
	var result [HashSize]byte
	copy(result[:], mac.Sum(nil))
	return result
}

// KDF1 derives one key: HMAC(HMAC(key, input), 0x01).
func KDF1(key []byte, input []byte) [HashSize]byte {
	t0 := HMAC1(key, input)
	return HMAC1(t0[:], []byte{0x01})
}

// KDF2 derives two keys from key and input.
func KDF2(key []byte, input []byte) ([HashSize]byte, [HashSize]byte) {
	t0 := HMAC1(key, input)
	t1 := HMAC1(t0[:], []byte{0x01})
	// t2 = HMAC(t0, t1 || 0x02)
	buf := make([]byte, HashSize+1)
	copy(buf, t1[:])
	buf[HashSize] = 0x02
	t2 := HMAC1(t0[:], buf)
	return t1, t2
}

// KDF3 derives three keys from key and input.
func KDF3(key []byte, input []byte) ([HashSize]byte, [HashSize]byte, [HashSize]byte) {
	t0 := HMAC1(key, input)
	t1 := HMAC1(t0[:], []byte{0x01})
	// t2 = HMAC(t0, t1 || 0x02)
	buf2 := make([]byte, HashSize+1)
	copy(buf2, t1[:])
	buf2[HashSize] = 0x02
	t2 := HMAC1(t0[:], buf2)
	// t3 = HMAC(t0, t2 || 0x03)
	buf3 := make([]byte, HashSize+1)
	copy(buf3, t2[:])
	buf3[HashSize] = 0x03
	t3 := HMAC1(t0[:], buf3)
	return t1, t2, t3
}

// DH performs Curve25519 Diffie-Hellman key exchange.
func DH(privateKey, publicKey [KeySize]byte) ([KeySize]byte, error) {
	shared, err := curve25519.X25519(privateKey[:], publicKey[:])
	if err != nil {
		return [KeySize]byte{}, err
	}
	var result [KeySize]byte
	copy(result[:], shared)
	return result, nil
}

// AEADEncrypt encrypts plaintext using ChaCha20-Poly1305.
// nonce is a 64-bit counter encoded as 4 bytes zero || 8 bytes LE counter.
func AEADEncrypt(key [KeySize]byte, counter uint64, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	var nonce [NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], counter)
	return aead.Seal(nil, nonce[:], plaintext, aad), nil
}

// AEADDecrypt decrypts ciphertext using ChaCha20-Poly1305.
func AEADDecrypt(key [KeySize]byte, counter uint64, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	var nonce [NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], counter)
	return aead.Open(nil, nonce[:], ciphertext, aad)
}

// GenerateKeyPair generates a Curve25519 key pair.
func GenerateKeyPair() (privateKey, publicKey [KeySize]byte, err error) {
	if _, err = rand.Read(privateKey[:]); err != nil {
		return
	}
	// Clamp private key
	privateKey[0] &= 248
	privateKey[31] = (privateKey[31] & 127) | 64
	pub, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return
	}
	copy(publicKey[:], pub)
	return
}

// PublicKeyFromPrivate derives the public key from a private key.
func PublicKeyFromPrivate(privateKey [KeySize]byte) ([KeySize]byte, error) {
	pub, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return [KeySize]byte{}, err
	}
	var result [KeySize]byte
	copy(result[:], pub)
	return result, nil
}

// TAI64N returns the current time encoded as TAI64N (12 bytes).
//
// TAI64N encoding:
//   - bytes 0-7: seconds since 1970 + 2^62  (big-endian uint64)
//   - bytes 8-11: nanoseconds              (big-endian uint32)
func TAI64N() [TAI64NSize]byte {
	var stamp [TAI64NSize]byte
	now := time.Now()
	// TAI64 base offset: 2^62 = 4611686018427387904
	secs := uint64(now.Unix()) + 4611686018427387904
	binary.BigEndian.PutUint64(stamp[0:8], secs)
	binary.BigEndian.PutUint32(stamp[8:12], uint32(now.Nanosecond()))
	return stamp
}

// MixHash mixes data into the handshake hash.
func MixHash(hash *[HashSize]byte, data []byte) {
	*hash = Hash(append(hash[:], data...))
}

// MixKey updates the chaining key using KDF2 and returns the derived key.
func MixKey(chainingKey *[HashSize]byte, data []byte) [HashSize]byte {
	ck, k := KDF2(chainingKey[:], data)
	*chainingKey = ck
	return k
}
