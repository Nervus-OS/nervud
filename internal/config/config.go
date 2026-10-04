package config

import (
	"context"
	"io/fs"
)

const (
	// ProtocolVersion is the NervusOS IPC protocol version
	ProtocolVersion = 2

	// SocketPath Unix Domain Socket Path
	SocketPath = "/run/nervus/nervud.sock"

	// SocketPerm Socket Permission
	SocketPerm = 0666

	// ComponentRegistryPath is the path to the component registry file
	ComponentRegistryPath = "/run/nervus/components.json"
)

// Config holds nervud configuration values
type Config struct {
	ProtocolVersion       uint32
	SocketPath            string
	SocketPerm            fs.FileMode
	ComponentRegistryPath string
}

// Global singleton config instance
var global = &Config{
	ProtocolVersion:       ProtocolVersion,
	SocketPath:            SocketPath,
	SocketPerm:            SocketPerm,
	ComponentRegistryPath: ComponentRegistryPath,
}

// Get returns the global config instance
func Get() *Config {
	return global
}

type Module struct{}

func (c *Module) Name() string {
	return "config"
}

func (c *Module) Start(ctx context.Context) error {
	return nil
}

func (c *Module) Stop(ctx context.Context) error {
	return nil
}
