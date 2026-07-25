//go:build linux

// 本文件是 EnsureAppUser 的 Linux 实现。与 ops.go 同属「可直接触碰 Linux 特权
// 接口」的文件，.golangci.yml 的 depguard 据此放行 x/sys/unix。
package authority

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// osEnsureAppUser 把 UID/GID 登记进 /etc/passwd 与 /etc/group。幂等。
//
// 全程持 /etc/.pwd.lock 排他锁——那是 shadow-utils 的约定，持它才能与系统上
// 其它用户管理工具（useradd/usermod/vipw）互斥。不持锁的话，两个进程同时
// 追加就可能写出交错的半行。
func (g *Gate) osEnsureAppUser(_ context.Context, req EnsureAppUserRequest) (struct{}, error) {
	var zero struct{}

	// O_CREAT：锁文件本身可能不存在（最小镜像没装 shadow-utils）。
	// 0600：它只是个锁，不该被别人读写。
	lockFD, err := unix.Open(pwdLockPath, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return zero, fmt.Errorf("authority: open %s: %w", pwdLockPath, err)
	}
	defer func() { _ = unix.Close(lockFD) }()

	if err := unix.Flock(lockFD, unix.LOCK_EX); err != nil {
		return zero, fmt.Errorf("authority: lock %s: %w", pwdLockPath, err)
	}
	defer func() { _ = unix.Flock(lockFD, unix.LOCK_UN) }()

	if err := ensureGroupLocked(req); err != nil {
		return zero, err
	}
	if err := ensurePasswdLocked(req); err != nil {
		return zero, err
	}
	return zero, nil
}

// ensureGroupLocked 追加 /etc/group 条目（调用方持锁）。
func ensureGroupLocked(req EnsureAppUserRequest) error {
	name, found, err := existingUIDName(groupPath, req.GID)
	if err != nil {
		return err
	}
	if found {
		// 已存在。若不是我们的名字，说明这个 GID 被系统上别的东西占了——
		// 【绝不覆盖】：那会把一个真实用户组的成员关系嫁接到 App 身上。
		if name != req.Name {
			return fmt.Errorf("%w: gid %d belongs to group %q, not %q",
				ErrAppUserConflict, req.GID, name, req.Name)
		}
		return nil
	}
	// name:passwd:gid:members
	return appendLine(groupPath, fmt.Sprintf("%s:x:%d:\n", req.Name, req.GID))
}

// ensurePasswdLocked 追加 /etc/passwd 条目（调用方持锁）。
func ensurePasswdLocked(req EnsureAppUserRequest) error {
	name, found, err := existingUIDName(passwdPath, req.UID)
	if err != nil {
		return err
	}
	if found {
		if name != req.Name {
			return fmt.Errorf("%w: uid %d belongs to user %q, not %q",
				ErrAppUserConflict, req.UID, name, req.Name)
		}
		return nil
	}
	// name:passwd:uid:gid:gecos:home:shell
	//
	// gecos 写包的用途而不是留空：/etc/passwd 是运维排查时会直接看的文件，
	// 一串没有说明的 nervus-app-20000 只会让人困惑。
	return appendLine(passwdPath, fmt.Sprintf("%s:x:%d:%d:Nervus OS app sandbox identity:%s:%s\n",
		req.Name, req.UID, req.GID, appUserHome, appUserShell))
}

// 确保 os 被引用（appendLine 在 appuser.go 里用它；此处仅为构建标签下的可读性）
var _ = os.O_APPEND
