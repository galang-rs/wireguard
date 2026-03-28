// Package muxer routes WireGuard messages between the network layer and
// handshake/data services based on message type.
package muxer

import (
	"encoding/hex"
	"time"

	"github.com/galang-rs/wireguard/internal/domain"
	"github.com/galang-rs/wireguard/internal/session"
	"github.com/galang-rs/wireguard/internal/worker"
	"github.com/galang-rs/wireguard/pkg/config"
)

const (
	// handshakeRetryInterval is the time between handshake retransmissions.
	handshakeRetryInterval = 5 * time.Second
	// maxHandshakeRetries is the max number of handshake retries.
	maxHandshakeRetries = 5
)

// Service is the packet muxer service.
type Service struct {
	// TriggerHandshake triggers a new handshake initiation.
	TriggerHandshake chan any

	// HandshakeOrDataToMuxer moves serialized messages from handshake/data to muxer.
	HandshakeOrDataToMuxer chan []byte

	// NetworkToMuxer moves raw bytes from the network to the muxer.
	NetworkToMuxer chan []byte

	// MuxerToNetwork is a pointer set during wiring.
	MuxerToNetwork *chan []byte

	// MuxerToData moves transport data messages to the data service.
	MuxerToData *chan []byte

	// MuxerToHandshake moves handshake response messages to the handshake service.
	MuxerToHandshake *chan []byte
}

// StartWorkers starts the muxer workers.
func (svc *Service) StartWorkers(cfg *config.Config, wm *worker.Manager, sm *session.Manager) {
	ws := &muxerWorkerState{
		logger:                 cfg.Logger(),
		triggerHandshake:       svc.TriggerHandshake,
		handshakeOrDataToMuxer: svc.HandshakeOrDataToMuxer,
		networkToMuxer:         svc.NetworkToMuxer,
		muxerToNetwork:         *svc.MuxerToNetwork,
		muxerToData:            *svc.MuxerToData,
		muxerToHandshake:       *svc.MuxerToHandshake,
		session:                sm,
		workersManager:         wm,
	}
	wm.StartWorker(ws.demuxWorker)
	wm.StartWorker(ws.muxWorker)
}

type muxerWorkerState struct {
	logger                 config.Logger
	triggerHandshake       <-chan any
	handshakeOrDataToMuxer <-chan []byte
	networkToMuxer         <-chan []byte
	muxerToNetwork         chan<- []byte
	muxerToData            chan<- []byte
	muxerToHandshake       chan<- []byte
	session                *session.Manager
	workersManager         *worker.Manager
}

// demuxWorker reads from the network and routes messages by type.
// Also handles handshake initiation with retransmission.
func (ws *muxerWorkerState) demuxWorker() {
	workerName := "muxer: demuxWorker"
	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()
	ws.logger.Debugf("%s: started", workerName)

	var lastInitiation []byte
	var retryTicker *time.Ticker
	var retryC <-chan time.Time
	retries := 0

	for {
		select {
		case <-ws.triggerHandshake:
			ws.logger.Infof("%s: triggering handshake initiation", workerName)
			initMsg, err := ws.session.CreateInitiation()
			if err != nil {
				ws.logger.Errorf("%s: create initiation: %s", workerName, err)
				select {
				case ws.session.Failure <- err:
				default:
				}
				return
			}

			ws.logger.Infof("%s: sending handshake initiation (%d bytes)", workerName, len(initMsg))
			ws.logger.Debugf("%s: init hex[:32] = %s", workerName, hex.EncodeToString(initMsg[:32]))

			select {
			case ws.muxerToNetwork <- initMsg:
				ws.session.SetState(domain.StateSentInitiation)
				lastInitiation = initMsg
				retries = 0
				// Start retry timer
				if retryTicker != nil {
					retryTicker.Stop()
				}
				retryTicker = time.NewTicker(handshakeRetryInterval)
				retryC = retryTicker.C
			case <-ws.workersManager.ShouldShutdown():
				return
			}

		case <-retryC:
			if ws.session.State() == domain.StateEstablished {
				// Handshake done, stop retrying
				if retryTicker != nil {
					retryTicker.Stop()
					retryC = nil
				}
				continue
			}
			retries++
			if retries > maxHandshakeRetries {
				ws.logger.Errorf("%s: handshake failed after %d retries", workerName, maxHandshakeRetries)
				if retryTicker != nil {
					retryTicker.Stop()
				}
				continue
			}
			// Retransmit with a fresh initiation (new timestamp)
			ws.logger.Infof("%s: retransmitting handshake (attempt %d/%d)", workerName, retries, maxHandshakeRetries)
			initMsg, err := ws.session.CreateInitiation()
			if err != nil {
				ws.logger.Errorf("%s: create initiation (retry): %s", workerName, err)
				continue
			}
			lastInitiation = initMsg
			select {
			case ws.muxerToNetwork <- lastInitiation:
			case <-ws.workersManager.ShouldShutdown():
				return
			}

		case rawBytes := <-ws.networkToMuxer:
			if len(rawBytes) < 4 {
				ws.logger.Warnf("%s: message too short: %d", workerName, len(rawBytes))
				continue
			}
			msgType, _ := domain.ParseMessageType(rawBytes)
			ws.logger.Infof("%s: ← received %s (%d bytes)", workerName, domain.MessageTypeString(msgType), len(rawBytes))

			switch msgType {
			case domain.MessageResponse:
				// Stop retry timer
				if retryTicker != nil {
					retryTicker.Stop()
					retryC = nil
				}
				// Route to handshake service
				select {
				case ws.muxerToHandshake <- rawBytes:
				case <-ws.workersManager.ShouldShutdown():
					return
				}

			case domain.MessageCookieReply:
				ws.logger.Infof("%s: got cookie reply", workerName)
				// Route to handshake service
				select {
				case ws.muxerToHandshake <- rawBytes:
				case <-ws.workersManager.ShouldShutdown():
					return
				}

			case domain.MessageTransport:
				// Route to data service
				select {
				case ws.muxerToData <- rawBytes:
				case <-ws.workersManager.ShouldShutdown():
					return
				}

			default:
				ws.logger.Warnf("%s: unknown message type: %d", workerName, msgType)
			}

		case <-ws.workersManager.ShouldShutdown():
			if retryTicker != nil {
				retryTicker.Stop()
			}
			return
		}
	}
}

// muxWorker reads from handshake/data services and sends to the network.
func (ws *muxerWorkerState) muxWorker() {
	workerName := "muxer: muxWorker"
	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()
	ws.logger.Debugf("%s: started", workerName)

	for {
		select {
		case data := <-ws.handshakeOrDataToMuxer:
			ws.logger.Debugf("%s: → sending %d bytes to network", workerName, len(data))
			select {
			case ws.muxerToNetwork <- data:
			case <-ws.workersManager.ShouldShutdown():
				return
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}
