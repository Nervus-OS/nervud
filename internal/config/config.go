package config

import (
	"context"
	"io/fs"
)

const (
	// ProtocolVersion is the NervusOS IPC protocol version
	// NervusOS 进程间通信使用的协议版本
	ProtocolVersion = 2

	// SocketPath Unix Domain Socket Path
	SocketPath = "/run/nervus/nervud.sock"

	// SocketPerm Socket Permission
	SocketPerm = 0666

	// ComponentRegistryPath is the path to the component registry file
	// 保存组件注册信息的文件路径
	ComponentRegistryPath = "/var/lib/nervus/components.json"

	// PermissionRegistryPath is the path to the permission registry file
	// 保存权限注册信息的文件路径
	PermissionRegistryPath = "/var/lib/nervus/permissions.json"

	// ComponentIDMin and ComponentIDMax bound the UIDs allocated to components.
	// Each component gets its own UID, and its GID is the same number.
	// 组件 UID 的分配区间；每个组件分配一个 UID，GID 取相同的数字
	ComponentIDMin int32 = 30000
	ComponentIDMax int32 = 99999
)

// Config holds nervud configuration values
type Config struct {
	ProtocolVersion        uint32
	SocketPath             string
	SocketPerm             fs.FileMode
	ComponentRegistryPath  string
	PermissionRegistryPath string
	ComponentIDMin         int32
	ComponentIDMax         int32
}

// Global singleton config instance
var global = &Config{
	ProtocolVersion:        ProtocolVersion,
	SocketPath:             SocketPath,
	SocketPerm:             SocketPerm,
	ComponentRegistryPath:  ComponentRegistryPath,
	PermissionRegistryPath: PermissionRegistryPath,
	ComponentIDMin:         ComponentIDMin,
	ComponentIDMax:         ComponentIDMax,
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
