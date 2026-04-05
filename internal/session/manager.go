// Package session manages the WireGuard session state, handshake, and keypairs.
package session

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/galang-rs/wireguard/internal/crypto"
	"github.com/galang-rs/wireguard/internal/domain"
	"github.com/galang-rs/wireguard/pkg/config"
)

// Manager manages the WireGuard session. Concurrency-safe.
type Manager struct {
	mu sync.Mutex

	// Static keys
	localPrivate [crypto.KeySize]byte
	localPublic  [crypto.KeySize]byte
	peerPublic   [crypto.KeySize]byte
	presharedKey [crypto.KeySize]byte
	hasPSK       bool

	// Handshake state
	handshake     *Handshake
	state         domain.HandshakeState
	activeKeyPair *crypto.KeyPair

	// Tunnel info (from config)
	tunnelInfo domain.TunnelInfo

	logger config.Logger

	// Ready signals that transport keys are derived.
	Ready chan any

	// Failure receives unrecoverable errors.
	Failure chan error
}

// NewManager creates a new session Manager from config.
func NewManager(cfg *config.Config) (*Manager, error) {
	opts := cfg.WireGuardOptions()

	localPublic, err := crypto.PublicKeyFromPrivate(opts.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("session: derive public key: %w", err)
	}

	// Parse tunnel IP from Address (e.g. "10.0.0.2/24")
	ti := domain.TunnelInfo{
		DNS: opts.DNS,
	}
	if opts.Address != "" {
		ip, mask := parseAddress(opts.Address)
		ti.IP = ip
		ti.NetMask = mask
	}
	if opts.MTU > 0 {
		ti.MTU = opts.MTU
	} else {
		ti.MTU = 1420 // WireGuard default
	}
	if opts.Peer.Endpoint != "" {
		ti.GW = opts.Peer.Endpoint
	}

	sm := &Manager{
		localPrivate: opts.PrivateKey,
		localPublic:  localPublic,
		peerPublic:   opts.Peer.PublicKey,
		presharedKey: opts.Peer.PresharedKey,
		hasPSK:       opts.Peer.HasPresharedKey,
		state:        domain.StateIdle,
		tunnelInfo:   ti,
		logger:       cfg.Logger(),
		Ready:        make(chan any),
		Failure:      make(chan error, 1),
	}

	cfg.Logger().Infof("session: local pubkey = %s", base64.StdEncoding.EncodeToString(localPublic[:]))
	cfg.Logger().Infof("session: peer  pubkey = %s", base64.StdEncoding.EncodeToString(opts.Peer.PublicKey[:]))

	return sm, nil
}

// parseAddress splits "10.0.0.2/24" into IP and mask.
func parseAddress(addr string) (string, string) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == '/' {
			return addr[:i], addr[i+1:]
		}
	}
	return addr, ""
}

// LocalPublicKey returns our public key.
func (m *Manager) LocalPublicKey() [crypto.KeySize]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.localPublic
}

// PeerPublicKey returns the peer's public key.
func (m *Manager) PeerPublicKey() [crypto.KeySize]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.peerPublic
}

// SetState sets the handshake state.
func (m *Manager) SetState(s domain.HandshakeState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logger.Infof("[@] %s -> %s", m.state, s)
	m.state = s
	if s == domain.StateEstablished {
		select {
		case m.Ready <- true:
		default:
		}
	}
}

// State returns the current handshake state.
func (m *Manager) State() domain.HandshakeState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// ActiveKeyPair returns the current transport keypair.
func (m *Manager) ActiveKeyPair() *crypto.KeyPair {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeKeyPair
}

// SetActiveKeyPair sets the transport keypair.
func (m *Manager) SetActiveKeyPair(kp *crypto.KeyPair) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeKeyPair = kp
}

// TunnelInfo returns a copy of the current TunnelInfo.
func (m *Manager) TunnelInfo() domain.TunnelInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tunnelInfo
}

// CreateInitiation creates a handshake initiation message (Noise IKpsk2).
//
// Protocol steps (from WireGuard whitepaper):
//   Ci := HASH(CONSTRUCTION)
//   Hi := HASH(Ci || IDENTIFIER)
//   Hi := HASH(Hi || Spubr)
//   (Eprivi, Epubi) := DH-Generate()
//   Ci := KDF1(Ci, Epubi)
//   msg.ephemeral := Epubi
//   Hi := HASH(Hi || msg.ephemeral)
//   (Ci, κ) := KDF2(Ci, DH(Eprivi, Spubr))
//   msg.static := AEAD(κ, 0, Spubi, Hi)
//   Hi := HASH(Hi || msg.static)
//   (Ci, κ) := KDF2(Ci, DH(Sprivi, Spubr))
//   msg.timestamp := AEAD(κ, 0, TAI64N(), Hi)
//   Hi := HASH(Hi || msg.timestamp)
func (m *Manager) CreateInitiation() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	hs := &Handshake{}
	hs.chainingKey = crypto.InitialChainingKey
	hs.hash = crypto.InitialHash

	m.logger.Debugf("handshake: Ci  = %s", hex.EncodeToString(hs.chainingKey[:]))
	m.logger.Debugf("handshake: Hi  = %s", hex.EncodeToString(hs.hash[:]))

	// Hi := HASH(Hi || Spubr)
	crypto.MixHash(&hs.hash, m.peerPublic[:])
	m.logger.Debugf("handshake: Hi after peer pubkey = %s", hex.EncodeToString(hs.hash[:]))

	// Generate ephemeral keypair
	var err error
	hs.localEphemPrivate, hs.localEphemPublic, err = crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral: %w", err)
	}

	// Generate random sender index
	var indexBuf [4]byte
	if _, err := rand.Read(indexBuf[:]); err != nil {
		return nil, err
	}
	hs.localIndex = binary.LittleEndian.Uint32(indexBuf[:])

	msg := &domain.HandshakeInitiation{
		SenderIndex: hs.localIndex,
	}

	// Ci := KDF1(Ci, Epubi)
	hs.chainingKey = crypto.KDF1(hs.chainingKey[:], hs.localEphemPublic[:])

	// msg.ephemeral := Epubi
	copy(msg.Ephemeral[:], hs.localEphemPublic[:])

	// Hi := HASH(Hi || msg.ephemeral)
	crypto.MixHash(&hs.hash, msg.Ephemeral[:])

	m.logger.Debugf("handshake: Ci after KDF1(ephem)  = %s", hex.EncodeToString(hs.chainingKey[:]))
	m.logger.Debugf("handshake: Hi after ephem         = %s", hex.EncodeToString(hs.hash[:]))

	// (Ci, κ) := KDF2(Ci, DH(Eprivi, Spubr))
	ss, err := crypto.DH(hs.localEphemPrivate, m.peerPublic)
	if err != nil {
		return nil, fmt.Errorf("DH ephemeral-static: %w", err)
	}
	key := crypto.MixKey(&hs.chainingKey, ss[:])

	// msg.static := AEAD(κ, 0, Spubi, Hi)
	staticEnc, err := crypto.AEADEncrypt(key, 0, m.localPublic[:], hs.hash[:])
	if err != nil {
		return nil, fmt.Errorf("encrypt static: %w", err)
	}
	if len(staticEnc) != 48 {
		return nil, fmt.Errorf("unexpected static ciphertext size: %d (want 48)", len(staticEnc))
	}
	copy(msg.Static[:], staticEnc)

	// Hi := HASH(Hi || msg.static)
	crypto.MixHash(&hs.hash, msg.Static[:])

	// (Ci, κ) := KDF2(Ci, DH(Sprivi, Spubr))
	ss, err = crypto.DH(m.localPrivate, m.peerPublic)
	if err != nil {
		return nil, fmt.Errorf("DH static-static: %w", err)
	}
	key = crypto.MixKey(&hs.chainingKey, ss[:])

	// msg.timestamp := AEAD(κ, 0, TAI64N(), Hi)
	timestamp := crypto.TAI64N()
	tsEnc, err := crypto.AEADEncrypt(key, 0, timestamp[:], hs.hash[:])
	if err != nil {
		return nil, fmt.Errorf("encrypt timestamp: %w", err)
	}
	if len(tsEnc) != 28 {
		return nil, fmt.Errorf("unexpected timestamp ciphertext size: %d (want 28)", len(tsEnc))
	}
	copy(msg.Timestamp[:], tsEnc)

	// Hi := HASH(Hi || msg.timestamp)
	crypto.MixHash(&hs.hash, msg.Timestamp[:])

	// Save handshake state
	m.handshake = hs

	// Serialize message
	buf := msg.MarshalBinary()

	// Compute MAC1
	// mac1 = MAC(HASH(LABEL_MAC1 || Spubr), msg[0:116])
	mac1Key := crypto.MAC1Key(m.peerPublic)
	mac1 := crypto.ComputeMAC1(mac1Key, buf[:116])
	copy(buf[116:132], mac1[:])

	// MAC2 is zero (no cookie yet)

	m.logger.Infof("session: created initiation (index=%d, len=%d)", hs.localIndex, len(buf))
	m.logger.Debugf("handshake: msg hex = %s", hex.EncodeToString(buf[:32]))
	return buf, nil
}

// ConsumeResponse processes a handshake response and derives transport keys.
//
// Protocol steps (initiator consuming response):
//   Hi := HASH(Hi || msg.ephemeral)
//   Ci := KDF1(Ci, msg.ephemeral)
//   (Ci, κ) := KDF2(Ci, DH(Eprivi, msg.ephemeral))   -- ee
//   (Ci, κ) := KDF2(Ci, DH(Sprivi, msg.ephemeral))   -- se
//   (Ci, τ, κ) := KDF3(Ci, Q)                         -- PSK
//   Hi := HASH(Hi || τ)
//   AEAD-Open(κ, 0, msg.empty, Hi)                    -- verify
//   Hi := HASH(Hi || msg.empty)
//   (Tsend, Trecv) := KDF2(Ci, ε)                     -- transport keys
func (m *Manager) ConsumeResponse(data []byte) (*crypto.KeyPair, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.handshake == nil {
		return nil, fmt.Errorf("session: no pending handshake")
	}
	hs := m.handshake

	resp, err := domain.ParseHandshakeResponse(data)
	if err != nil {
		return nil, err
	}

	// Verify receiver index matches
	if resp.ReceiverIndex != hs.localIndex {
		return nil, fmt.Errorf("session: unexpected receiver index: got %d, want %d", resp.ReceiverIndex, hs.localIndex)
	}

	hs.remoteIndex = resp.SenderIndex

	// Hi := HASH(Hi || msg.ephemeral)
	crypto.MixHash(&hs.hash, resp.Ephemeral[:])

	// Ci := KDF1(Ci, msg.ephemeral)
	hs.chainingKey = crypto.KDF1(hs.chainingKey[:], resp.Ephemeral[:])

	// (Ci, κ) := KDF2(Ci, DH(Eprivi, msg.ephemeral))  -- ee
	ss, err := crypto.DH(hs.localEphemPrivate, resp.Ephemeral)
	if err != nil {
		return nil, fmt.Errorf("DH ee: %w", err)
	}
	key := crypto.MixKey(&hs.chainingKey, ss[:])
	_ = key

	// (Ci, κ) := KDF2(Ci, DH(Sprivi, msg.ephemeral))  -- se
	ss, err = crypto.DH(m.localPrivate, resp.Ephemeral)
	if err != nil {
		return nil, fmt.Errorf("DH se: %w", err)
	}
	key = crypto.MixKey(&hs.chainingKey, ss[:])
	_ = key

	// (Ci, τ, κ) := KDF3(Ci, Q)                        -- PSK
	psk := m.presharedKey
	if !m.hasPSK {
		psk = [32]byte{} // zero PSK
	}
	t1, t2, t3 := crypto.KDF3(hs.chainingKey[:], psk[:])
	hs.chainingKey = t1
	crypto.MixHash(&hs.hash, t2[:])
	key = t3

	// Verify AEAD: decrypt empty (0-byte plaintext + poly1305 tag = 16 bytes)
	_, err = crypto.AEADDecrypt(key, 0, resp.Empty[:], hs.hash[:])
	if err != nil {
		return nil, fmt.Errorf("session: invalid handshake response AEAD: %w", err)
	}

	// Hi := HASH(Hi || msg.empty)
	crypto.MixHash(&hs.hash, resp.Empty[:])

	// (Tsend, Trecv) := KDF2(Ci, ε)
	sendKey, recvKey := crypto.KDF2(hs.chainingKey[:], nil)

	kp := &crypto.KeyPair{
		SendKey:     sendKey,
		RecvKey:     recvKey,
		LocalIndex:  hs.localIndex,
		RemoteIndex: hs.remoteIndex,
	}

	m.activeKeyPair = kp
	m.handshake = nil // handshake complete

	m.logger.Infof("session: handshake complete (local=%d, remote=%d)", kp.LocalIndex, kp.RemoteIndex)
	return kp, nil
}

// ConsumeInitiation processes an incoming handshake initiation from the peer
// (responder side of Noise IKpsk2). Returns a response message and derived keypair.
//
// Protocol steps (responder consuming initiation):
//   Ci := HASH(CONSTRUCTION)
//   Hi := HASH(Ci || IDENTIFIER)
//   Hi := HASH(Hi || Spubr)         -- our public key is the "responder" here
//   Ci := KDF1(Ci, msg.ephemeral)
//   Hi := HASH(Hi || msg.ephemeral)
//   (Ci, κ) := KDF2(Ci, DH(Sprivi, msg.ephemeral))   -- static-ephemeral
//   AEAD-Open(κ, 0, msg.static, Hi) → peer_pubkey     -- decrypt peer's static
//   Hi := HASH(Hi || msg.static)
//   (Ci, κ) := KDF2(Ci, DH(Sprivi, peer_pubkey))      -- static-static
//   AEAD-Open(κ, 0, msg.timestamp, Hi) → timestamp     -- decrypt timestamp
//   Hi := HASH(Hi || msg.timestamp)
func (m *Manager) ConsumeInitiation(data []byte) ([]byte, *crypto.KeyPair, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	msg, err := domain.ParseHandshakeInitiation(data)
	if err != nil {
		return nil, nil, fmt.Errorf("session: parse initiation: %w", err)
	}

	hs := &Handshake{}
	hs.chainingKey = crypto.InitialChainingKey
	hs.hash = crypto.InitialHash
	hs.remoteIndex = msg.SenderIndex

	// Hi := HASH(Hi || Spubi)  -- our public key (we are the responder)
	crypto.MixHash(&hs.hash, m.localPublic[:])

	// Ci := KDF1(Ci, msg.ephemeral)
	hs.chainingKey = crypto.KDF1(hs.chainingKey[:], msg.Ephemeral[:])

	// Hi := HASH(Hi || msg.ephemeral)
	crypto.MixHash(&hs.hash, msg.Ephemeral[:])

	// (Ci, κ) := KDF2(Ci, DH(Sprivi, msg.ephemeral))  -- se
	var peerEphemeral [crypto.KeySize]byte
	copy(peerEphemeral[:], msg.Ephemeral[:])
	ss, err := crypto.DH(m.localPrivate, peerEphemeral)
	if err != nil {
		return nil, nil, fmt.Errorf("DH se: %w", err)
	}
	key := crypto.MixKey(&hs.chainingKey, ss[:])

	// Decrypt static: AEAD-Open(κ, 0, msg.static, Hi) → peer_pubkey
	peerStaticRaw, err := crypto.AEADDecrypt(key, 0, msg.Static[:], hs.hash[:])
	if err != nil {
		return nil, nil, fmt.Errorf("session: decrypt static: %w", err)
	}
	var peerStatic [crypto.KeySize]byte
	copy(peerStatic[:], peerStaticRaw)

	// Verify peer public key matches what we expect
	if peerStatic != m.peerPublic {
		return nil, nil, fmt.Errorf("session: peer public key mismatch in initiation")
	}

	// Hi := HASH(Hi || msg.static)
	crypto.MixHash(&hs.hash, msg.Static[:])

	// (Ci, κ) := KDF2(Ci, DH(Sprivi, peer_pubkey))  -- ss
	ss, err = crypto.DH(m.localPrivate, peerStatic)
	if err != nil {
		return nil, nil, fmt.Errorf("DH ss: %w", err)
	}
	key = crypto.MixKey(&hs.chainingKey, ss[:])

	// Decrypt timestamp: AEAD-Open(κ, 0, msg.timestamp, Hi)
	_, err = crypto.AEADDecrypt(key, 0, msg.Timestamp[:], hs.hash[:])
	if err != nil {
		return nil, nil, fmt.Errorf("session: decrypt timestamp: %w", err)
	}

	// Hi := HASH(Hi || msg.timestamp)
	crypto.MixHash(&hs.hash, msg.Timestamp[:])

	// --- Now create the response ---

	// Generate our ephemeral key pair
	hs.localEphemPrivate, hs.localEphemPublic, err = crypto.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral: %w", err)
	}

	// Generate random sender index
	var indexBuf [4]byte
	if _, err := rand.Read(indexBuf[:]); err != nil {
		return nil, nil, err
	}
	hs.localIndex = binary.LittleEndian.Uint32(indexBuf[:])

	resp := &domain.HandshakeResponse{
		SenderIndex:   hs.localIndex,
		ReceiverIndex: hs.remoteIndex,
	}

	// Hi := HASH(Hi || msg.ephemeral)
	copy(resp.Ephemeral[:], hs.localEphemPublic[:])
	crypto.MixHash(&hs.hash, resp.Ephemeral[:])

	// Ci := KDF1(Ci, msg.ephemeral)
	hs.chainingKey = crypto.KDF1(hs.chainingKey[:], resp.Ephemeral[:])

	// (Ci, κ) := KDF2(Ci, DH(Eprivi, Epubr))  -- ee
	ss, err = crypto.DH(hs.localEphemPrivate, peerEphemeral)
	if err != nil {
		return nil, nil, fmt.Errorf("DH ee: %w", err)
	}
	key = crypto.MixKey(&hs.chainingKey, ss[:])
	_ = key

	// (Ci, κ) := KDF2(Ci, DH(Eprivi, Spubr))  -- es
	ss, err = crypto.DH(hs.localEphemPrivate, peerStatic)
	if err != nil {
		return nil, nil, fmt.Errorf("DH es: %w", err)
	}
	key = crypto.MixKey(&hs.chainingKey, ss[:])
	_ = key

	// (Ci, τ, κ) := KDF3(Ci, Q)  -- PSK
	psk := m.presharedKey
	if !m.hasPSK {
		psk = [32]byte{}
	}
	t1, t2, t3 := crypto.KDF3(hs.chainingKey[:], psk[:])
	hs.chainingKey = t1
	crypto.MixHash(&hs.hash, t2[:])
	key = t3

	// msg.empty := AEAD(κ, 0, ε, Hi)
	emptyEnc, err := crypto.AEADEncrypt(key, 0, nil, hs.hash[:])
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt empty: %w", err)
	}
	copy(resp.Empty[:], emptyEnc)

	// Hi := HASH(Hi || msg.empty)
	crypto.MixHash(&hs.hash, resp.Empty[:])

	// Derive transport keys: (Trecv, Tsend) := KDF2(Ci, ε)
	// Note: responder's send = initiator's recv, so keys are swapped
	recvKey, sendKey := crypto.KDF2(hs.chainingKey[:], nil)

	kp := &crypto.KeyPair{
		SendKey:     sendKey,
		RecvKey:     recvKey,
		LocalIndex:  hs.localIndex,
		RemoteIndex: hs.remoteIndex,
	}

	// Serialize response
	buf := resp.MarshalBinary()

	// Compute MAC1: mac1 = MAC(HASH(LABEL_MAC1 || Spubr), msg[0:60])
	mac1Key := crypto.MAC1Key(m.peerPublic)
	mac1 := crypto.ComputeMAC1(mac1Key, buf[:60])
	copy(buf[60:76], mac1[:])
	// MAC2 is zero (no cookie)

	m.handshake = hs
	m.activeKeyPair = kp

	m.logger.Infof("session: consumed initiation, created response (local=%d, remote=%d)", kp.LocalIndex, kp.RemoteIndex)
	return buf, kp, nil
}

// Handshake holds the in-progress handshake state.
type Handshake struct {
	chainingKey       [crypto.HashSize]byte
	hash              [crypto.HashSize]byte
	localEphemPrivate [crypto.KeySize]byte
	localEphemPublic  [crypto.KeySize]byte
	localIndex        uint32
	remoteIndex       uint32
}
