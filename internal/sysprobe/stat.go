//go:build linux

// 本文件是 sysprobe 的路径属主/权限观察（应用层架构决策 §2.7 preflight 用）。
//
// 与 PeerCred 同属「纯观察」准入：只读 lstat(2) 的结果，不改变任何系统状态、
// 不持有任何 capability。preflight 的裁决逻辑（哪些路径、什么规则、是否 fatal）
// 放在 internal/preflight，本文件只提供它需要的、无法在不碰 syscall 的情况下
// 拿到的那一个事实：某个路径的属主 UID/GID、权限位与文件类型
package sysprobe

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// PathStat 是一个路径的属主与权限事实，来自 lstat(2)
//
// 用 lstat 而非 stat：不跟随符号链接。一个本应是「root 拥有的目录」的位置若被
// 换成指向别处的 symlink，preflight 必须看见这个 symlink 本身（IsSymlink=true）
// 并据此 fatal，而不是被透明地带到链接目标去检查一个无关的东西
type PathStat struct {
	UID uint32
	GID uint32
	// Perm 是 st_mode 的低 12 位：含 setuid/setgid/sticky（0o7000）与 rwx（0o777）。
	// preflight 直接对数值比较（如 == 0o0755 或 & 0o1000 判 sticky），不必映射到
	// fs.FileMode 的分散位布局
	Perm      uint32
	IsDir     bool
	IsRegular bool
	IsSymlink bool
}

// LstatPath 返回 path 的属主/权限事实。path 不存在时返回的 error 满足
// errors.Is(err, fs.ErrNotExist)（unix.ENOENT 实现了它），调用方据此区分
// 「不存在」与真正的 I/O 错误
func LstatPath(path string) (PathStat, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return PathStat{}, fmt.Errorf("sysprobe: lstat %s: %w", path, err)
	}
	typ := st.Mode & unix.S_IFMT
	return PathStat{
		UID:       st.Uid,
		GID:       st.Gid,
		Perm:      uint32(st.Mode) & 0o7777,
		IsDir:     typ == unix.S_IFDIR,
		IsRegular: typ == unix.S_IFREG,
		IsSymlink: typ == unix.S_IFLNK,
	}, nil
}
