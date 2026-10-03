package config

import "context"

const (
	// ProtocolVersion is the NervusOS IPC protocol version
	ProtocolVersion = 2
)

// Config holds nervud configuration values
type Config struct {
	ProtocolVersion uint32
}

// Global singleton config instance
var global = &Config{
	ProtocolVersion: ProtocolVersion,
}

// Get returns the global config instance
func Get() *Config {
	return global
}

type Module struct{}

func (e *Module) Name() string {
	return "config"
}

func (e *Module) Start(ctx context.Context, reportFatal func(error)) error {
	<-ctx.Done()
	return nil
}

func (e *Module) Stop(ctx context.Context) error {
	return nil
}
