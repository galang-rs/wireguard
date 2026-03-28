// Package data implements the WireGuard data channel (encrypt/decrypt)
// using ChaCha20-Poly1305.
package data

import (
	"time"

	"github.com/galang-rs/wireguard/internal/crypto"
	"github.com/galang-rs/wireguard/internal/domain"
	"github.com/galang-rs/wireguard/internal/session"
	"github.com/galang-rs/wireguard/internal/worker"
	"github.com/galang-rs/wireguard/pkg/config"
)

// Service is the data channel service.
type Service struct {
	// MuxerToData moves transport data messages from the muxer.
	MuxerToData chan []byte

	// KeyReady receives the KeyPair when handshake completes.
	KeyReady chan *crypto.KeyPair

	// TUNToData moves raw IP packets from TUN to data (outbound).
	TUNToData <-chan []byte

	// DataToTUN moves decrypted IP packets from data to TUN (inbound).
	DataToTUN chan<- []byte

	// HandshakeOrDataToMuxer sends encrypted transport messages to muxer.
	HandshakeOrDataToMuxer *chan []byte
}

// StartWorkers starts the data channel workers.
func (svc *Service) StartWorkers(cfg *config.Config, wm *worker.Manager, sm *session.Manager) {
	ws := &dataWorkerState{
		logger:                 cfg.Logger(),
		config:                 cfg,
		muxerToData:            svc.MuxerToData,
		keyReady:               svc.KeyReady,
		tunToData:              svc.TUNToData,
		dataToTun:              svc.DataToTUN,
		handshakeOrDataToMuxer: *svc.HandshakeOrDataToMuxer,
		session:                sm,
		workersManager:         wm,
	}
	wm.StartWorker(ws.decryptWorker)
	wm.StartWorker(ws.encryptWorker)
}

type dataWorkerState struct {
	logger                 config.Logger
	config                 *config.Config
	muxerToData            <-chan []byte
	keyReady               <-chan *crypto.KeyPair
	tunToData              <-chan []byte
	dataToTun              chan<- []byte
	handshakeOrDataToMuxer chan<- []byte
	session                *session.Manager
	workersManager         *worker.Manager

	keyPair *crypto.KeyPair
}

func (ws *dataWorkerState) decryptWorker() {
	workerName := "data: decryptWorker"
	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()
	ws.logger.Debugf("%s: waiting for key", workerName)

	// Wait for key
	select {
	case kp := <-ws.keyReady:
		ws.keyPair = kp
		ws.logger.Debugf("%s: got key, starting decryption", workerName)
	case <-ws.workersManager.ShouldShutdown():
		return
	}

	for {
		select {
		case data := <-ws.muxerToData:
			msg, err := domain.ParseTransportData(data)
			if err != nil {
				ws.logger.Warnf("%s: parse: %s", workerName, err)
				continue
			}

			// Decrypt payload using recv key
			plaintext, err := crypto.AEADDecrypt(ws.keyPair.RecvKey, msg.Counter, msg.Payload, nil)
			if err != nil {
				ws.logger.Warnf("%s: decrypt: %s", workerName, err)
				continue
			}

			// Empty plaintext = keepalive, ignore
			if len(plaintext) == 0 {
				ws.logger.Debugf("%s: keepalive received (counter=%d)", workerName, msg.Counter)
				continue
			}

			ws.logger.Debugf("%s: decrypted %d bytes (counter=%d)", workerName, len(plaintext), msg.Counter)

			select {
			case ws.dataToTun <- plaintext:
			case <-ws.workersManager.ShouldShutdown():
				return
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}

func (ws *dataWorkerState) encryptWorker() {
	workerName := "data: encryptWorker"
	defer func() {
		ws.workersManager.OnWorkerDone(workerName)
		ws.workersManager.StartShutdown()
	}()
	ws.logger.Debugf("%s: started", workerName)

	// Wait until decryptWorker has received the keypair
	for ws.keyPair == nil {
		select {
		case <-ws.workersManager.ShouldShutdown():
			return
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Keepalive interval from config
	keepaliveInterval := 25 * time.Second
	opts := ws.config.WireGuardOptions()
	if opts.Peer.PersistentKeepalive > 0 {
		keepaliveInterval = time.Duration(opts.Peer.PersistentKeepalive) * time.Second
	}

	keepaliveTicker := time.NewTicker(keepaliveInterval)
	defer keepaliveTicker.Stop()

	for {
		select {
		case ipPacket := <-ws.tunToData:
			nonce := ws.keyPair.NextSendNonce()
			ciphertext, err := crypto.AEADEncrypt(ws.keyPair.SendKey, nonce, ipPacket, nil)
			if err != nil {
				ws.logger.Warnf("%s: encrypt: %s", workerName, err)
				continue
			}

			msg := &domain.TransportData{
				ReceiverIndex: ws.keyPair.RemoteIndex,
				Counter:       nonce,
				Payload:       ciphertext,
			}
			data := msg.MarshalBinary()
			ws.logger.Debugf("%s: encrypted %d -> %d bytes (nonce=%d)", workerName, len(ipPacket), len(data), nonce)

			select {
			case ws.handshakeOrDataToMuxer <- data:
			case <-ws.workersManager.ShouldShutdown():
				return
			}

		case <-keepaliveTicker.C:
			// Send keepalive (empty encrypted packet)
			nonce := ws.keyPair.NextSendNonce()
			ciphertext, err := crypto.AEADEncrypt(ws.keyPair.SendKey, nonce, nil, nil)
			if err != nil {
				continue
			}
			msg := &domain.TransportData{
				ReceiverIndex: ws.keyPair.RemoteIndex,
				Counter:       nonce,
				Payload:       ciphertext,
			}
			data := msg.MarshalBinary()
			select {
			case ws.handshakeOrDataToMuxer <- data:
				ws.logger.Debugf("%s: sent keepalive (nonce=%d)", workerName, nonce)
			case <-ws.workersManager.ShouldShutdown():
				return
			}

		case <-ws.workersManager.ShouldShutdown():
			return
		}
	}
}
