//go:build linux

// 本文件是全仓库第三处可直接触碰 Linux syscall 接口的位置
// （另两处：internal/authority 的 ops.go、internal/scheduler 的 sched.go）
// .golangci.yml 的 depguard 规则据此放行 golang.org/x/sys/unix
//
// 注意本包只放行 syscall / golang.org/x/sys，不放行 os/exec：
// 起进程是权力行使，永远只能走 authority
package sysprobe

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// PeerCred 读取 UDS 对端的内核可信凭证（PID / UID / GID）
//
// SO_PEERCRED 的语义
//
// 凭证是在对端调用 connect(2) 的那一刻由内核快照下来的，不是每次读取时
// 实时采集。这正是我们要的性质：对端连上来之后再 setuid、exec 换皮或被注入，
// 都不会改变这里读到的身份，天生免疫握手后换皮这类竞态
//
// 代价是 PID 会过期：对端进程退出后，它的 PID 可能被内核回收给一个不相干的
// 新进程。因此 PID 只是待核对的线索 - 架构 sec 10.2 用 PID + cgroup + 启动
// 记录交叉核对 Component ID，核对必须在连接建立后尽快完成。绝不允许在
// 连接存活很久之后再拿这个 PID 去 /proc 反查并信任结果
//
// UID 才是身份裁决的依据：它稳定、不受 PID 回收影响，并且按架构 sec 9 与 Package
// 一一对应。调用方拿到 UID 后应先用 authority.Invariants.CheckUID 确认它落在
// App 区段内，再去 Package Registry 查表
//
// 并发
//
// 无状态、不修改 c 的任何属性，可以在任意 goroutine 上并发调用
func PeerCred(c *net.UnixConn) (Ucred, error) {
	if c == nil {
		return Ucred{}, fmt.Errorf("sysprobe: peer cred: nil unix conn")
	}

	// 用 SyscallConn.Control 而不是c.File：
	//
	// File 会 dup 一份 fd 并把原连接切换成阻塞模式，从此 netpoller 不再管这条
	// 连接，SetReadDeadline / SetWriteDeadline 全部失效。对控制面来说这是致命的
	// - sec 10.11 要求每次 Frame 读写都有有限 deadline，slowloris 防护全靠它
	// 一个只是读一下对端身份的函数顺手废掉整条连接的超时能力，是最难查的
	// 那类 bug；peercred_linux_test.go 里有一条回归锁专门盯这件事
	//
	// Control 只在回调期间借用 fd，并保证回调返回前 fd 不会被关闭或复用
	raw, err := c.SyscallConn()
	if err != nil {
		return Ucred{}, fmt.Errorf("sysprobe: peer cred: syscall conn: %w", err)
	}

	var (
		cred    *unix.Ucred
		credErr error
	)
	// 两层错误必须分别检查：Control 自身失败（fd 已关闭等）与回调内 getsockopt
	// 失败是两回事，只查其中一个会把另一种情况当成成功，然后返回零值 Ucred
	// - 那等于把 UID 0 交给上层
	if ctlErr := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); ctlErr != nil {
		return Ucred{}, fmt.Errorf("sysprobe: peer cred: control fd: %w", ctlErr)
	}
	if credErr != nil {
		return Ucred{}, fmt.Errorf("sysprobe: peer cred: getsockopt SO_PEERCRED: %w", credErr)
	}

	return Ucred{PID: cred.Pid, UID: cred.Uid, GID: cred.Gid}, nil
}
