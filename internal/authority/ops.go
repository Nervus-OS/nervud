//go:build linux

// 本文件是全仓库可直接触碰 Linux 特权接口之一
// .golangci.yml 的 depguard 规则据此放行 syscall / x/sys/unix / os/exec
//
// 路径解析纪律：invariant.go 的字符串检查挡不住 symlink 逃逸，真正的保证在这里
// 由内核完成——一律先 open root 拿 fd，再用 openat2(RESOLVE_BENEATH |
// RESOLVE_NO_SYMLINKS) 做 fd 相对解析；解析成功后只对 fd / (dirfd, leaf) 操作
// 不再触碰完整字符串路径
package authority

import (
	"context"
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/nervus-os/nervud/internal/audit"
)

// resolveParent 打开 path 的父目录并返回 (父目录 fd, 末段名
// 调用方负责 close 返回的 fd。前提：Validate 已证明 path 位于 root 之内
func resolveParent(root, p string) (int, string, error) {
	rel, err := containedRel(p, root)
	if err != nil {
		// Validate 已查过，到这还失败说明调用序被破坏，按错误返回而非 panic
		return -1, "", err
	}

	// O_PATH：只要求路径解析权，不要求读权限；O_NOFOLLOW：root 自身也不许是 symlink
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", fmt.Errorf("open root %s: %w", root, err)
	}

	dir, leaf := splitRel(rel)
	if dir == "" {
		return rootFD, leaf, nil // path 是 root 的直接子项
	}

	how := unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS,
	}
	parentFD, err := unix.Openat2(rootFD, dir, &how)
	_ = unix.Close(rootFD)
	if err != nil {
		return -1, "", fmt.Errorf("resolve %s under %s: %w", dir, root, err)
	}
	return parentFD, leaf, nil
}

// splitRel 把斜杠相对路径拆成父目录和末段。rel 无末段斜杠、已 Clean
func splitRel(rel string) (dir, leaf string) {
	for i := len(rel) - 1; i >= 0; i-- {
		if rel[i] == '/' {
			return rel[:i], rel[i+1:]
		}
	}
	return "", rel
}

func (g *Gate) osCreateDataDir(_ context.Context, req CreateDataDirRequest) (DirHandle, error) {
	parentFD, leaf, err := resolveParent(g.inv.DataRoot, req.Path)
	if err != nil {
		return DirHandle{}, err
	}
	defer func() { _ = unix.Close(parentFD) }()

	// mkdirat 对末段不跟随 symlink：若 leaf 已是链接则 EEXIST，天然安全。
	// mkdirat 成功 = 本调用【创建】了这个目录（若已存在会 EEXIST），因此后续
	// 任一步失败时，回滚删除它是安全的——我们删的一定是自己刚建的
	if err := unix.Mkdirat(parentFD, leaf, req.Perm); err != nil {
		return DirHandle{}, fmt.Errorf("mkdirat %s: %w", leaf, err)
	}

	dh, err := g.finishDataDir(parentFD, leaf, req)
	if err != nil {
		// 回滚：把刚建的空目录删掉。不回滚会留下 root 所有/权限不完整的半成品，
		// 而重试又会在 mkdirat 处撞 EEXIST，从此永远修不好
		//
		// AT_REMOVEDIR 只删【空目录】：若 leaf 在这中间被替换成文件或非空目录
		// （并发攻击），rmdir 会安全失败、绝不误删。相对 parentFD 操作，
		// 与创建同一路径解析口径，不跟随 symlink
		if rmErr := unix.Unlinkat(parentFD, leaf, unix.AT_REMOVEDIR); rmErr != nil {
			// 回滚也失败：两个错误都带出去，别让回滚失败掩盖主因
			return DirHandle{}, fmt.Errorf("%w (rollback rmdir %s failed: %v)", err, leaf, rmErr)
		}
		return DirHandle{}, err
	}
	return dh, nil
}

// finishDataDir 打开刚建的目录并设定属主与权限
//
// 拆成独立函数是为了让 osCreateDataDir 有一个单一的失败出口去做回滚：这里返回
// error，那里就删目录。全部对 fd 操作（Openat2 后 Fchown/Fchmod），杜绝 TOCTOU
func (g *Gate) finishDataDir(parentFD int, leaf string, req CreateDataDirRequest) (DirHandle, error) {
	how := unix.OpenHow{
		Flags:   unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS,
	}
	fd, err := unix.Openat2(parentFD, leaf, &how)
	if err != nil {
		return DirHandle{}, fmt.Errorf("open created dir %s: %w", leaf, err)
	}
	defer func() { _ = unix.Close(fd) }()

	if err := unix.Fchown(fd, int(req.UID), int(req.GID)); err != nil {
		return DirHandle{}, fmt.Errorf("fchown: %w", err)
	}
	// mkdir 的 mode 会被进程 umask 削减，必须显式 chmod 回写成请求值
	if err := unix.Fchmod(fd, req.Perm); err != nil {
		return DirHandle{}, fmt.Errorf("fchmod: %w", err)
	}
	return DirHandle{Path: req.Path}, nil
}

func (g *Gate) osSetOwner(_ context.Context, req SetOwnerRequest) (struct{}, error) {
	parentFD, leaf, err := resolveParent(g.inv.DataRoot, req.Path)
	if err != nil {
		return struct{}{}, err
	}
	defer func() { _ = unix.Close(parentFD) }()

	// AT_SYMLINK_NOFOLLOW：目标是 symlink 时改链接本身的属主，不穿透到链接目标
	if err := unix.Fchownat(parentFD, leaf, int(req.UID), int(req.GID), unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return struct{}{}, fmt.Errorf("fchownat %s: %w", leaf, err)
	}
	return struct{}{}, nil
}

func (g *Gate) osReboot(ctx context.Context, req RebootRequest) (struct{}, error) {
	// 特例：reboot(2) 成功即不返回，do() 里 run 之后的那条审计永远走不到
	// 机器为什么重启了是审计必须能回答的问题，所以本操作在执行前先落一条
	// intent 记录。这是全包唯一允许在 run 内部直接调 auditor 的地方，原因如上
	g.auditor.Record(ctx, audit.Event{
		Action: "Reboot.initiated", Subject: "kernel", Detail: req.Reason,
	})
	// sync 后立即 reboot：reboot(2) 立即生效，不给任何上层留 flush 机会
	unix.Sync()
	if err := unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART); err != nil {
		return struct{}{}, fmt.Errorf("reboot: %w", err)
	}
	return struct{}{}, nil
}
