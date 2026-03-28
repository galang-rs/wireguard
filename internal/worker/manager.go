// Package worker coordinates the lifecycle of background goroutines
// implementing the WireGuard protocol.
package worker

import (
	"errors"
	"sync"

	"github.com/galang-rs/wireguard/pkg/config"
)

// ErrShutdown is the error returned by a worker that is shutting down.
var ErrShutdown = errors.New("worker is shutting down")

// Manager coordinates the lifecycles of workers implementing the WireGuard protocol.
type Manager struct {
	logger         config.Logger
	shouldShutdown chan any
	shutdownOnce   sync.Once
	wg             *sync.WaitGroup
}

// NewManager creates a new Manager.
func NewManager(logger config.Logger) *Manager {
	return &Manager{
		logger:         logger,
		shouldShutdown: make(chan any),
		shutdownOnce:   sync.Once{},
		wg:             &sync.WaitGroup{},
	}
}

// StartWorker starts a worker in a background goroutine.
func (m *Manager) StartWorker(fx func()) {
	m.wg.Add(1)
	go fx()
}

// OnWorkerDone MUST be called when a worker goroutine terminates.
func (m *Manager) OnWorkerDone(name string) {
	m.logger.Debugf("%s: worker done", name)
	m.wg.Done()
}

// StartShutdown initiates the shutdown of all workers.
func (m *Manager) StartShutdown() {
	m.shutdownOnce.Do(func() {
		close(m.shouldShutdown)
	})
}

// ShouldShutdown returns the channel closed when workers should shut down.
func (m *Manager) ShouldShutdown() <-chan any {
	return m.shouldShutdown
}

// WaitWorkersShutdown blocks until all workers have shut down.
func (m *Manager) WaitWorkersShutdown() {
	m.wg.Wait()
}
