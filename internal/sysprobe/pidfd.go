//go:build linux

// 本文件提供 Component 身份核对所需的两项 pidfd 操作
// 内核观察：SO_PEERPIDFD 拿对端进程的稳定引用（pidfd），以及从 PID 读 cgroup。
//
// 同属 sysprobe 的纯观察准入：只读，不改变任何系统状态、不持有 capability。
// cgroup 路径 -> systemd unit -> Component这层解释是策略，放在 ipc，不在这里。
package sysprobe

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// PeerPIDFD 用 SO_PEERPIDFD 取 UDS 对端进程的 pidfd（Linux 6.5+）
//
// 相比 SO_PEERCRED 的裸 PID，pidfd 是对端进程的稳定引用：只要持有它，即便对端
// PID 被内核回收给别的进程，pidfd 仍唯一指向原进程（或明确报告其已退出），从根本上
// 免疫PID 回收后核对到不相干进程的竞态。调用方拿到 fd 后负责 Close。
//
// 内核 < 6.5 无此选项，返回的 error 满足 errors.Is(err, ErrUnsupportedPlatform)
// 的兄弟：这里回一个可辨识的错误，调用方据此回退到 SO_PEERCRED + /proc owner 复核
func PeerPIDFD(c *net.UnixConn) (int, error) {
	if c == nil {
		return -1, fmt.Errorf("sysprobe: peer pidfd: nil unix conn")
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, fmt.Errorf("sysprobe: peer pidfd: syscall conn: %w", err)
	}
	var (
		pidfd  int
		optErr error
	)
	if ctlErr := raw.Control(func(fd uintptr) {
		pidfd, optErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	}); ctlErr != nil {
		return -1, fmt.Errorf("sysprobe: peer pidfd: control fd: %w", ctlErr)
	}
	if optErr != nil {
		return -1, fmt.Errorf("sysprobe: peer pidfd: getsockopt SO_PEERPIDFD: %w", optErr)
	}
	return pidfd, nil
}

// PIDFromPIDFD 从一个 pidfd 读出它当前指向的 PID（经 /proc/self/fdinfo/<fd> 的 Pid: 行）
//
// 与直接用 SO_PEERCRED 的 PID 不同：只要 pidfd 仍打开且进程存活，这个 PID 就不会
// 被复用，因此拿它去读 /proc/<pid> 是安全的。进程已退出时 Pid 行会是 -1
func PIDFromPIDFD(pidfd int) (int32, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", pidfd))
	if err != nil {
		return 0, fmt.Errorf("sysprobe: read fdinfo: %w", err)
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		if rest, ok := strings.CutPrefix(line, "Pid:"); ok {
			v, perr := strconv.ParseInt(strings.TrimSpace(rest), 10, 32)
			if perr != nil {
				return 0, fmt.Errorf("sysprobe: parse fdinfo Pid: %w", perr)
			}
			if v <= 0 {
				return 0, fmt.Errorf("sysprobe: pidfd refers to a dead process")
			}
			return int32(v), nil
		}
	}
	return 0, fmt.Errorf("sysprobe: fdinfo has no Pid line")
}

// PeerCgroupViaPIDFD 用 SO_PEERPIDFD 的稳定引用读对端进程的 cgroup 路径，全程在
// 函数内管理 pidfd 生命周期（读完即 Close）。这样 ipc 无需 import syscall/x-sys 去
// 关闭裸 fd（depguard 只放行 sysprobe 触碰 syscall）。
//
// 内核 <6.5（无 SO_PEERPIDFD）或对端已退出时返回错误，调用方据此回退到
// SO_PEERCRED PID + ProcOwnerUID 复核路径
func PeerCgroupViaPIDFD(c *net.UnixConn) (string, error) {
	pidfd, err := PeerPIDFD(c)
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(pidfd) }()
	pid, err := PIDFromPIDFD(pidfd)
	if err != nil {
		return "", err
	}
	return CgroupPath(pid)
}

// CgroupPath 读 /proc/<pid>/cgroup 的 cgroup v2（unified）行，返回其路径
//
// cgroup v2 的行形如 "0::/system.slice/nervus-<pkg>-<comp>.service"。返回 "0::" 之后
// 的路径部分。找不到 unified 行（纯 v1 系统）返回错误 - nervud 目标镜像用 v2
func CgroupPath(pid int32) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", fmt.Errorf("sysprobe: read cgroup: %w", err)
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		// unified 行：hierarchy-ID 为 0、controller 为空 -> "0::<path>"
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return rest, nil
		}
	}
	return "", fmt.Errorf("sysprobe: no cgroup v2 unified line for pid %d", pid)
}

// ProcOwnerUID 读 /proc/<pid> 的属主 UID（real UID），用于 SO_PEERCRED 回退路径的
// 二次校验：核对 /proc/<pid> 属主仍等于 SO_PEERCRED 的 UID（ 回退项）
func ProcOwnerUID(pid int32) (uint32, error) {
	var st unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d", pid), &st); err != nil {
		return 0, fmt.Errorf("sysprobe: stat /proc/%d: %w", pid, err)
	}
	return st.Uid, nil
}
