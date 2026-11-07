package registry

// Credential used to describe the identity information of a component process at runtime, for use when the component starts up.
// 用于描述组件进程运行时的身份信息，供组件启动时使用

// LaunchCredential is the identity a component process runs with.
// It maps directly onto syscall.Credential{Uid, Gid, Groups}.
// 组件进程运行时使用的身份，可直接填入 syscall.Credential
type LaunchCredential struct {
	UID    uint32
	GID    uint32
	Groups []uint32 // supplementary groups / 附属组
}

// SysProcAttrCredential converts it to the value expected by os/exec
// 转换为 syscall.Credential
func (c LaunchCredential) SysProcAttrCredential() *SyscallCredential {
	return &SyscallCredential{Uid: c.UID, Gid: c.GID, Groups: c.Groups}
}

// SyscallCredential mirrors syscall.Credential without importing syscall here,
// keeping this file buildable on every platform.
// 与 syscall.Credential 字段一致，避免在本文件里引入平台相关的 syscall
type SyscallCredential struct {
	Uid    uint32
	Gid    uint32
	Groups []uint32
}
