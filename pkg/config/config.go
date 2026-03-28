package config

import (
	"log"
	"net"
)

// Config contains options to initialize the WireGuard tunnel.
type Config struct {
	wgOptions *WireGuardOptions
	logger    Logger
}

// Logger interface used by the VPN stack.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// stdLogger wraps Go's stdlib log as the default Logger.
type stdLogger struct{}

func (l *stdLogger) Debugf(format string, args ...any) { log.Printf("[DEBUG] "+format, args...) }
func (l *stdLogger) Infof(format string, args ...any)  { log.Printf("[INFO]  "+format, args...) }
func (l *stdLogger) Warnf(format string, args ...any)  { log.Printf("[WARN]  "+format, args...) }
func (l *stdLogger) Errorf(format string, args ...any) { log.Printf("[ERROR] "+format, args...) }

// NewConfig returns a Config ready to initialize a VPN tunnel.
func NewConfig(options ...Option) *Config {
	cfg := &Config{
		wgOptions: &WireGuardOptions{},
		logger:    &stdLogger{},
	}
	for _, opt := range options {
		opt(cfg)
	}
	return cfg
}

// Option is a functional option for Config.
type Option func(config *Config)

// WithLogger configures a custom Logger.
func WithLogger(logger Logger) Option {
	return func(config *Config) {
		config.logger = logger
	}
}

// WithConfigFile configures WireGuardOptions parsed from the given .conf file.
func WithConfigFile(configPath string) Option {
	return func(config *Config) {
		opts, err := ReadConfigFile(configPath)
		if err != nil {
			panic("cannot parse config file: " + err.Error())
		}
		config.wgOptions = opts
	}
}

// WithWireGuardOptions configures the WireGuard options directly.
func WithWireGuardOptions(opts *WireGuardOptions) Option {
	return func(config *Config) {
		config.wgOptions = opts
	}
}

// Logger returns the configured logger.
func (c *Config) Logger() Logger { return c.logger }

// WireGuardOptions returns the configured options.
func (c *Config) WireGuardOptions() *WireGuardOptions { return c.wgOptions }

// Remote has info about the WireGuard remote peer.
type Remote struct {
	IPAddr   string
	Endpoint string
	Protocol string
}

// Remote returns the WireGuard peer endpoint info.
func (c *Config) Remote() *Remote {
	peer := c.wgOptions.Peer
	host, port, _ := net.SplitHostPort(peer.Endpoint)
	return &Remote{
		IPAddr:   host,
		Endpoint: net.JoinHostPort(host, port),
		Protocol: "udp",
	}
}
