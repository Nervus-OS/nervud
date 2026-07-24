// 见 doc.go 的包说明
//
// 本文件是完整性复核的一部分：按 manifest 声明的 digest 清单逐文件核对内容。
// 纯计算，不触碰特权接口，因此不受 depguard 的 syscall 边界约束
package pkgregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// ManifestFileName 是包内 manifest 的固定文件名（应用层架构决策 §3.2）
	ManifestFileName = "manifest.json"
	// SignatureFileName 是包内分离签名的固定文件名（应用层架构决策 §3.2）
	SignatureFileName = "manifest.sig"
)

// ErrDigestMismatch 至少一个文件的实际内容与 manifest 声明的 digest 不符
var ErrDigestMismatch = errors.New("pkgregistry: digest verification failed")

// ErrIrregularFile digest 复核遇到非普通文件（symlink/FIFO/设备节点等）。
// 这些不能被 hash（symlink 会跟随到包外、FIFO/设备会永久阻塞 io.Copy），
// 一律拒绝——包里只允许普通文件与目录
var ErrIrregularFile = errors.New("pkgregistry: refusing to hash non-regular file")

// DigestDiff 是完整性复核的结构化结果
//
// 返回完整差异而不是遇到第一个不符就退出：审计需要记录“这个包到底哪里
// 不对”，而不只是“不对”这一个布尔值
type DigestDiff struct {
	Mismatched []string // manifest 声明了 digest，但磁盘内容 hash 不一致
	Missing    []string // manifest 声明了，但磁盘上找不到这个文件
	Extra      []string // 磁盘上存在，但 manifest 未声明
}

// Clean 报告本次复核是否完全通过
func (d DigestDiff) Clean() bool {
	return len(d.Mismatched) == 0 && len(d.Missing) == 0 && len(d.Extra) == 0
}

// VerifyDigests 核对 root 目录下的实际文件与 digests（包内相对路径 -> sha256 hex）
//
// digests 的键必须已经过 validRelPath 校验（ParseManifest 已经做过），本函数
// 不再重复校验路径安全性，只信任调用方已经拒绝过路径穿越
//
// manifest.json 与 manifest.sig 是包的元数据（应用层架构决策 §3.2），无法被
// 自身的 digest 清单覆盖（manifest 不能自散列，sig 也不能写进 manifest 后再签），
// 因此这两个文件名在 Extra 检查里被豁免——它们的完整性由“签名覆盖 manifest 原始
// 字节 + digest 覆盖其余全部文件”这条链间接保证，而不是靠列进 digests
func VerifyDigests(root string, digests map[string]string) (DigestDiff, error) {
	var diff DigestDiff
	seen := make(map[string]bool, len(digests))

	for rel, want := range digests {
		seen[rel] = true
		full := filepath.Join(root, filepath.FromSlash(rel))
		got, err := sha256File(full)
		switch {
		case errors.Is(err, os.ErrNotExist):
			diff.Missing = append(diff.Missing, rel)
			continue
		case err != nil:
			return DigestDiff{}, fmt.Errorf("pkgregistry: hash %s: %w", rel, err)
		case !strings.EqualFold(got, want):
			diff.Mismatched = append(diff.Mismatched, rel)
		}
	}

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// 只允许普通文件：symlink/FIFO/设备节点等非普通类型一律拒绝。symlink 会
		// 跟随到包外、FIFO/设备会让 io.Copy 永久阻塞（应用层架构决策 §3.2 W^X 与
		// 完整性前提）。用 DirEntry.Type() 判断，不跟随 symlink
		if !d.Type().IsRegular() {
			return fmt.Errorf("%w: %s (mode %v)", ErrIrregularFile, p, d.Type())
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		// 包元数据文件豁免 Extra 检查（见函数文档）
		if rel == ManifestFileName || rel == SignatureFileName {
			return nil
		}
		if !seen[rel] {
			diff.Extra = append(diff.Extra, rel)
		}
		return nil
	})
	if err != nil {
		return DigestDiff{}, fmt.Errorf("pkgregistry: walk %s: %w", root, err)
	}

	sort.Strings(diff.Mismatched)
	sort.Strings(diff.Missing)
	sort.Strings(diff.Extra)
	return diff, nil
}

func sha256File(path string) (string, error) {
	// 先 Lstat（不跟随 symlink）确认是普通文件：symlink 会跟随到包外目标，
	// FIFO/设备/socket 会让 io.Copy 永久阻塞（应用层架构决策 §3.2）。os.Open
	// 会跟随 symlink，所以必须在打开【之前】用 Lstat 把关
	li, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !li.Mode().IsRegular() {
		return "", fmt.Errorf("%w: %s (mode %v)", ErrIrregularFile, path, li.Mode())
	}

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	// 打开后再用 Fstat 确认一次仍是普通文件：Lstat 与 Open 之间存在 TOCTOU 窗口，
	// 这道二次核对把“Lstat 看到普通文件、Open 时已被换成 FIFO”这类替换挡在 io.Copy
	// 之前。彻底消除 TOCTOU 需要 O_NOFOLLOW（非跨平台），留待 Linux 侧加固
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%w: %s (mode %v)", ErrIrregularFile, path, info.Mode())
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
