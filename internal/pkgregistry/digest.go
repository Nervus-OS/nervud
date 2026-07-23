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

// ErrDigestMismatch 至少一个文件的实际内容与 manifest 声明的 digest 不符
var ErrDigestMismatch = errors.New("pkgregistry: digest verification failed")

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
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
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
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
