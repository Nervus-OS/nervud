//go:build linux

// 本文件是 RemovePackageTree 的 Linux 实现：递归删除一个已安装 Package 的代码或
// 数据目录（卸载用，应用层架构决策 §4.2）。
//
// 与 ops.go 同一条路径解析纪律：先在指定 Root 下用 openat2(RESOLVE_BENEATH |
// RESOLVE_NO_SYMLINKS) 拿到目标目录的 fd，之后【全程 dirfd 相对】遍历与 unlink，
// 绝不回到完整字符串路径——否则删除过程中任一级被替换成 symlink，就可能把 rm -rf
// 引到 Root 之外。这对「以 root 递归删除」的操作是硬要求
package authority

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// maxRemoveDepth 限制递归深度，防御深链目录把栈打爆（正常包树远浅于此）
const maxRemoveDepth = 64

func (g *Gate) osRemovePackageTree(_ context.Context, req RemovePackageTreeRequest) (struct{}, error) {
	// resolveParent 已经用 openat2(RESOLVE_BENEATH|NO_SYMLINKS) 保证 leaf 在 Root 内。
	// 注意这里的 root 是请求显式声明、且 Validate 已核对属于 PackageRoot/DataRoot 之一
	parentFD, leaf, err := resolveParent(req.Root, req.Path)
	if err != nil {
		return struct{}{}, err
	}
	defer func() { _ = unix.Close(parentFD) }()

	// 先删掉 leaf 目录树的内容，再 rmdir leaf 自身
	if err := removeChild(parentFD, leaf, 0); err != nil {
		return struct{}{}, err
	}
	return struct{}{}, nil
}

// removeChild 删除 parentFD 下名为 name 的条目（文件或目录树），全程相对 fd 操作
//
// 语义：先尝试当作非目录 unlinkat；EISDIR 则说明是目录，递归清空后 rmdir。用
// AT_SYMLINK 语义的 unlinkat（默认不跟随 symlink）——删到一个 symlink 时删的是
// 链接本身，不会穿透到链接目标
func removeChild(parentFD int, name string, depth int) error {
	if depth > maxRemoveDepth {
		return fmt.Errorf("%w: remove recursion exceeds depth %d", ErrInvariantViolated, maxRemoveDepth)
	}

	// 先按「非目录」删。unlinkat 默认不跟随 symlink，符号链接会在这里被安全删除
	err := unix.Unlinkat(parentFD, name, 0)
	if err == nil {
		return nil
	}
	if err != unix.EISDIR && err != unix.EPERM {
		// ENOENT：已经不在（并发/幂等），当成成功
		if err == unix.ENOENT {
			return nil
		}
		return fmt.Errorf("unlinkat %s: %w", name, err)
	}
	// 是目录：打开它（不跟随 symlink、限定在 parentFD 之下），递归清空
	how := unix.OpenHow{
		Flags:   unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_RDONLY,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS,
	}
	dirFD, oerr := unix.Openat2(parentFD, name, &how)
	if oerr != nil {
		if oerr == unix.ENOENT {
			return nil
		}
		return fmt.Errorf("openat2 dir %s: %w", name, oerr)
	}
	if cerr := removeDirContents(dirFD, depth); cerr != nil {
		_ = unix.Close(dirFD)
		return cerr
	}
	_ = unix.Close(dirFD)

	// 内容已空，删目录自身（相对 parentFD，不跟随 symlink）
	if rerr := unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR); rerr != nil && rerr != unix.ENOENT {
		return fmt.Errorf("rmdir %s: %w", name, rerr)
	}
	return nil
}

// removeDirContents 遍历 dirFD 指向的目录，逐个删除其中的条目（递归）
//
// 用 os.File 包 dup 出来的 fd 读目录项：ReadDir 内部走 getdents，条目只是名字，
// 后续的删除仍相对 dirFD、经 removeChild 的 openat2 解析，不受 ReadDir 快照与
// 真实文件系统之间竞态的影响（被删到不存在时 removeChild 容忍 ENOENT）
func removeDirContents(dirFD int, depth int) error {
	// os.NewFile 接管 fd 的所有权用于 ReadDir；为了不影响调用方对 dirFD 的
	// Close/后续 unlinkat，这里 dup 一份给 os.File
	dup, err := unix.Dup(dirFD)
	if err != nil {
		return fmt.Errorf("dup dirfd: %w", err)
	}
	f := os.NewFile(uintptr(dup), "removedir")
	if f == nil {
		_ = unix.Close(dup)
		return fmt.Errorf("%w: os.NewFile on duped dirfd", ErrInvariantViolated)
	}
	names, rerr := f.Readdirnames(-1)
	_ = f.Close() // 关闭 dup
	if rerr != nil {
		return fmt.Errorf("readdirnames: %w", rerr)
	}

	for _, n := range names {
		if n == "." || n == ".." {
			continue
		}
		if err := removeChild(dirFD, n, depth+1); err != nil {
			return err
		}
	}
	return nil
}
