// Package domain contains pure domain types for the WireGuard protocol.
// This package has zero external dependencies — only Go stdlib.
package domain

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// WireGuard message types.
const (
	MessageInitiation  = uint32(1)
	MessageResponse    = uint32(2)
	MessageCookieReply = uint32(3)
	MessageTransport   = uint32(4)
)

// Message sizes.
const (
	MessageInitiationSize  = 148
	MessageResponseSize    = 92
	MessageCookieReplySize = 64
	MessageTransportMinSize = 32 // header only, no payload
)

// Errors
var (
	ErrMessageTooShort = errors.New("wireguard: message too short")
	ErrUnknownMessage  = errors.New("wireguard: unknown message type")
)

// MessageTypeString returns a human-readable string for the message type.
func MessageTypeString(t uint32) string {
	switch t {
	case MessageInitiation:
		return "HANDSHAKE_INITIATION"
	case MessageResponse:
		return "HANDSHAKE_RESPONSE"
	case MessageCookieReply:
		return "COOKIE_REPLY"
	case MessageTransport:
		return "TRANSPORT_DATA"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

// ParseMessageType extracts the message type from the first 4 bytes (little-endian).
func ParseMessageType(data []byte) (uint32, error) {
	if len(data) < 4 {
		return 0, ErrMessageTooShort
	}
	return binary.LittleEndian.Uint32(data[:4]), nil
}

// HandshakeInitiation is the first message sent by the initiator (148 bytes).
//
// Wire format:
//   type(4) sender(4) ephemeral(32) static(48) timestamp(28) mac1(16) mac2(16)
type HandshakeInitiation struct {
	SenderIndex  uint32
	Ephemeral    [32]byte
	Static       [48]byte // AEAD encrypted
	Timestamp    [28]byte // AEAD encrypted
	MAC1         [16]byte
	MAC2         [16]byte
}

// MarshalBinary serializes the initiation message.
func (m *HandshakeInitiation) MarshalBinary() []byte {
	buf := make([]byte, MessageInitiationSize)
	binary.LittleEndian.PutUint32(buf[0:4], MessageInitiation)
	binary.LittleEndian.PutUint32(buf[4:8], m.SenderIndex)
	copy(buf[8:40], m.Ephemeral[:])
	copy(buf[40:88], m.Static[:])
	copy(buf[88:116], m.Timestamp[:])
	copy(buf[116:132], m.MAC1[:])
	copy(buf[132:148], m.MAC2[:])
	return buf
}

// ParseHandshakeInitiation parses a handshake initiation message.
func ParseHandshakeInitiation(data []byte) (*HandshakeInitiation, error) {
	if len(data) < MessageInitiationSize {
		return nil, fmt.Errorf("%w: need %d, got %d", ErrMessageTooShort, MessageInitiationSize, len(data))
	}
	m := &HandshakeInitiation{
		SenderIndex: binary.LittleEndian.Uint32(data[4:8]),
	}
	copy(m.Ephemeral[:], data[8:40])
	copy(m.Static[:], data[40:88])
	copy(m.Timestamp[:], data[88:116])
	copy(m.MAC1[:], data[116:132])
	copy(m.MAC2[:], data[132:148])
	return m, nil
}

// HandshakeResponse is the response to a handshake initiation (92 bytes).
//
// Wire format:
//   type(4) sender(4) receiver(4) ephemeral(32) empty(16) mac1(16) mac2(16)
type HandshakeResponse struct {
	SenderIndex   uint32
	ReceiverIndex uint32
	Ephemeral     [32]byte
	Empty         [16]byte // AEAD encrypted empty payload
	MAC1          [16]byte
	MAC2          [16]byte
}

// ParseHandshakeResponse parses a handshake response message.
func ParseHandshakeResponse(data []byte) (*HandshakeResponse, error) {
	if len(data) < MessageResponseSize {
		return nil, fmt.Errorf("%w: need %d, got %d", ErrMessageTooShort, MessageResponseSize, len(data))
	}
	m := &HandshakeResponse{
		SenderIndex:   binary.LittleEndian.Uint32(data[4:8]),
		ReceiverIndex: binary.LittleEndian.Uint32(data[8:12]),
	}
	copy(m.Ephemeral[:], data[12:44])
	copy(m.Empty[:], data[44:60])
	copy(m.MAC1[:], data[60:76])
	copy(m.MAC2[:], data[76:92])
	return m, nil
}

// MarshalBinary serializes the response message.
func (m *HandshakeResponse) MarshalBinary() []byte {
	buf := make([]byte, MessageResponseSize)
	binary.LittleEndian.PutUint32(buf[0:4], MessageResponse)
	binary.LittleEndian.PutUint32(buf[4:8], m.SenderIndex)
	binary.LittleEndian.PutUint32(buf[8:12], m.ReceiverIndex)
	copy(buf[12:44], m.Ephemeral[:])
	copy(buf[44:60], m.Empty[:])
	copy(buf[60:76], m.MAC1[:])
	copy(buf[76:92], m.MAC2[:])
	return buf
}

// TransportData is an encrypted data message (variable length).
//
// Wire format:
//   type(4) receiver(4) counter(8) encrypted_payload(variable)
type TransportData struct {
	ReceiverIndex uint32
	Counter       uint64
	Payload       []byte // encrypted IP packet (ChaCha20-Poly1305)
}

// MarshalBinary serializes the transport data message.
func (m *TransportData) MarshalBinary() []byte {
	buf := make([]byte, 16+len(m.Payload))
	binary.LittleEndian.PutUint32(buf[0:4], MessageTransport)
	binary.LittleEndian.PutUint32(buf[4:8], m.ReceiverIndex)
	binary.LittleEndian.PutUint64(buf[8:16], m.Counter)
	copy(buf[16:], m.Payload)
	return buf
}

// ParseTransportData parses a transport data message.
func ParseTransportData(data []byte) (*TransportData, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("%w: transport message too short: %d", ErrMessageTooShort, len(data))
	}
	return &TransportData{
		ReceiverIndex: binary.LittleEndian.Uint32(data[4:8]),
		Counter:       binary.LittleEndian.Uint64(data[8:16]),
		Payload:       data[16:],
	}, nil
}

// CookieReply is a cookie reply message (64 bytes).
//
// Wire format:
//   type(4) receiver(4) nonce(24) cookie(32)
type CookieReply struct {
	ReceiverIndex uint32
	Nonce         [24]byte
	Cookie        [32]byte // XChaCha20-Poly1305 encrypted cookie
}

// ParseCookieReply parses a cookie reply message.
func ParseCookieReply(data []byte) (*CookieReply, error) {
	if len(data) < MessageCookieReplySize {
		return nil, fmt.Errorf("%w: cookie reply too short: %d", ErrMessageTooShort, len(data))
	}
	m := &CookieReply{
		ReceiverIndex: binary.LittleEndian.Uint32(data[4:8]),
	}
	copy(m.Nonce[:], data[8:32])
	copy(m.Cookie[:], data[32:64])
	return m, nil
}
