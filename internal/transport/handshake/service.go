// Package handshake implements the WireGuard Noise IKpsk2 handshake service.
// Replaces the TLS service from the OpenVPN architecture.
package handshake

import (
	"fmt"
	"time"

	"github.com/galang-rs/wireguard/internal/crypto"
	"github.com/galang-rs/wireguard/internal/domain"
	"github.com/galang-rs/wireguard/internal/session"
	"github.com/galang-rs/wireguard/internal/worker"
	"github.com/galang-rs/wireguard/pkg/config"
)

const (
	// RekeyAfterTime is the time after which a new handshake should be initiated.
	RekeyAfterTime = 120 * time.Second // 2 minutes

	// handshakeTimeout is the max time to wait for a handshake response.
	handshakeTimeout = 5 * time.Second

	// handshakeRetries is the number of retries before giving up.
	handshakeRetries = 10
)

// Service is the handshake service.
type Service struct {
	// MuxerToHandshake moves handshake response messages from the muxer.
	MuxerToHandshake chan []byte

	// KeyReady sends the derived KeyPair to the data service.
	KeyReady chan *crypto.KeyPair

	// HandshakeOrDataToMuxer sends serialized messages to the muxer.
	HandshakeOrDataToMuxer *chan []byte
}

// StartWorkers starts the handshake worker.
func (svc *Service) StartWorkers(cfg *config.Config, wm *worker.Manager, sm *session.Manager) {
	ws := &handshakeWorkerState{
		logger:                 cfg.Logger(),
		muxerToHandshake:       svc.MuxerToHandshake,
		keyReady:               svc.KeyReady,
		handshakeOrDataToMuxer: *svc.HandshakeOrDataToMuxer,
		session:                sm,
		workersManager:         wm,
	}
	wm.StartWorker(ws.mainWorker)
}

type handshakeWorkerState struct {
	logger                 config.Logger
	muxerToHandshake       <-chan []byte
	keyReady               chan<- *crypto.KeyPair
	handshakeOrDataToMuxer chan<- []byte
	session                *session.Manager
	workersManager         *worker.Manager
}

func (ws *handshakeWorkerState) mainWorker() {
	workerName := "handshake: mainWorker"
	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()
	ws.logger.Debugf("%s: started, waiting for handshake response", workerName)

	for {
		select {
		case data := <-ws.muxerToHandshake:
			if len(data) < 4 {
				continue
			}
			msgType, _ := domain.ParseMessageType(data)

			switch msgType {
			case domain.MessageResponse:
				ws.logger.Debugf("%s: got handshake response (%d bytes)", workerName, len(data))
				kp, err := ws.session.ConsumeResponse(data)
				if err != nil {
					ws.logger.Errorf("%s: consume response: %s", workerName, err)
					select {
					case ws.session.Failure <- fmt.Errorf("handshake: %w", err):
					default:
					}
					return
				}

				// Send first empty transport message to confirm handshake
				ws.sendKeepalive(kp)

				// Send keypair to data service
				select {
				case ws.keyReady <- kp:
					ws.session.SetState(domain.StateEstablished)
					ws.logger.Infof("%s: handshake complete, transport keys derived", workerName)
				case <-ws.workersManager.ShouldShutdown():
					return
				}

			case domain.MessageInitiation:
				// Peer-initiated re-key: consume initiation and send response.
				ws.logger.Infof("%s: processing peer-initiated re-key", workerName)
				respBytes, kp, err := ws.session.ConsumeInitiation(data)
				if err != nil {
					ws.logger.Errorf("%s: consume initiation: %s", workerName, err)
					continue
				}

				// Send response to network.
				select {
				case ws.handshakeOrDataToMuxer <- respBytes:
					ws.logger.Infof("%s: sent handshake response (%d bytes)", workerName, len(respBytes))
				case <-ws.workersManager.ShouldShutdown():
					return
				}

				// Send keepalive to confirm.
				ws.sendKeepalive(kp)

				// Deliver new keypair to data service.
				select {
				case ws.keyReady <- kp:
					ws.session.SetState(domain.StateEstablished)
					ws.logger.Infof("%s: re-key complete, new transport keys active", workerName)
				case <-ws.workersManager.ShouldShutdown():
					return
				}

			case domain.MessageCookieReply:
				ws.logger.Debugf("%s: got cookie reply (TODO: handle retry)", workerName)
				// In a full implementation, we'd extract the cookie and retry
				// the handshake initiation with MAC2. For now, just log it.

			default:
				ws.logger.Warnf("%s: unexpected message type: %d", workerName, msgType)
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

// sendKeepalive sends an empty transport message to confirm the handshake.
func (ws *handshakeWorkerState) sendKeepalive(kp *crypto.KeyPair) {
	nonce := kp.NextSendNonce()
	encrypted, err := crypto.AEADEncrypt(kp.SendKey, nonce, nil, nil)
	if err != nil {
		ws.logger.Warnf("handshake: keepalive encrypt: %s", err)
		return
	}

	msg := &domain.TransportData{
		ReceiverIndex: kp.RemoteIndex,
		Counter:       nonce,
		Payload:       encrypted,
	}

	data := msg.MarshalBinary()
	select {
	case ws.handshakeOrDataToMuxer <- data:
		ws.logger.Debugf("handshake: sent keepalive (nonce=%d)", nonce)
	case <-ws.workersManager.ShouldShutdown():
	}
}
