package domain

// HandshakeState is the state of the WireGuard handshake.
type HandshakeState int

const (
	// StateError means something went wrong.
	StateError = HandshakeState(iota) - 1

	// StateIdle means no handshake is in progress.
	StateIdle

	// StateSentInitiation means we sent a handshake initiation.
	StateSentInitiation

	// StateReceivedResponse means we received a handshake response.
	StateReceivedResponse

	// StateEstablished means the handshake is complete and keys are derived.
	StateEstablished
)

// String maps a HandshakeState to a string.
func (s HandshakeState) String() string {
	switch s {
	case StateError:
		return "ERROR"
	case StateIdle:
		return "IDLE"
	case StateSentInitiation:
		return "SENT_INITIATION"
	case StateReceivedResponse:
		return "RECEIVED_RESPONSE"
	case StateEstablished:
		return "ESTABLISHED"
	default:
		return "UNKNOWN"
	}
}

// TunnelInfo holds state about the VPN tunnel.
type TunnelInfo struct {
	// IP is the assigned tunnel IP (from config Address field).
	IP string

	// GW is the gateway/peer endpoint.
	GW string

	// MTU is the configured MTU.
	MTU int

	// NetMask is the subnet mask (e.g. "/24" from Address).
	NetMask string

	// DNS is the list of DNS servers.
	DNS []string
}
