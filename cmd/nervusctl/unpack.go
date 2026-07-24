// 本文件把 .nspkg（zstd 压缩的 tar）解包进一个目标目录。
//
// 安全职责（CLI 侧唯一的重活）：解包发生在提交给 nervud 复核之前，因此这里
// 必须严防 tar-slip / zip-slip - 一个恶意 .nspkg 若带 "../.." 或绝对路径条目，
// 解包时就能写到目标目录之外（CLI 以 root 运行时后果尤重）。因此逐条目校验：
// 名字必须是干净的相对路径、不逃出目标目录，且只接受普通文件与目录，拒绝
// 符号链接/硬链接/设备等一切可用于逃逸或提权的类型。
//
// 注意分工：nervud 会对 staging 里的每个文件按 manifest.Digests 重新做内容复核
// （VerifyDigests），因此内容层面的信任锚在 nervud，不在这里；本文件只保证解包
// 这一步本身不越界。
package main

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// maxEntryBytes 是单个解包条目的字节上限，挡住解压炸弹式的超大条目。64 MiB 对
// 正常 App 载荷绰绰有余；真正的包大小约束由 nervud/manifest 侧负责。
const maxEntryBytes = 64 << 20

// maxTotalEntries 是一个 .nspkg 允许的条目数上限，挡住海量小条目式炸弹。
const maxTotalEntries = 10000

// unpackNspkg 把 nspkgPath 指向的 .nspkg 解包进 destDir（须已存在）。destDir 由
// nervud 经 begin-staging 建好并发回，属主/权限受控。
func unpackNspkg(nspkgPath, destDir string) error {
	f, err := os.Open(nspkgPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	zr, err := zstd.NewReader(f)
	if err != nil {
		return fmt.Errorf("zstd reader: %w", err)
	}
	defer zr.Close()

	// destDir 的绝对、清理形式，用于逐条目的不逃出校验。
	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return err
	}
	absDest = filepath.Clean(absDest)

	tr := tar.NewReader(zr)
	count := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		count++
		if count > maxTotalEntries {
			return fmt.Errorf("archive has too many entries (> %d)", maxTotalEntries)
		}

		target, err := safeJoin(absDest, hdr.Name)
		if err != nil {
			return err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := writeRegular(tr, target, hdr); err != nil {
				return err
			}
		default:
			// 拒绝符号链接/硬链接/设备/FIFO 等一切非常规类型：它们要么可用于逃逸
			// （symlink 指向目标目录外），要么在受签名 App 包里没有合法用途。
			return fmt.Errorf("archive entry %q has unsupported type %d", hdr.Name, hdr.Typeflag)
		}
	}
	return nil
}

// safeJoin 把条目名 name 安全地拼到 base 下，拒绝一切逃逸：空名、绝对路径、
// 清理后仍逃出 base 的（含 ".." 折叠）。返回目标绝对路径。
func safeJoin(base, name string) (string, error) {
	if name == "" {
		return "", errors.New("archive entry has empty name")
	}
	// tar 名字用 '/' 分隔；filepath.Clean 在 linux 上语义一致。绝对路径直接拒。
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("archive entry %q is absolute", name)
	}
	target := filepath.Join(base, name)
	cleaned := filepath.Clean(target)
	// 必须严格位于 base 之内（base 本身不算）。前缀比较带分隔符，防
	// /a/staging-evil 通过 /a/staging 的朴素前缀。
	if cleaned != base && !strings.HasPrefix(cleaned, base+string(os.PathSeparator)) {
		return "", fmt.Errorf("archive entry %q escapes destination", name)
	}
	return cleaned, nil
}

// writeRegular 把当前 tar 条目写成一个普通文件，限流条目大小、创建所需父目录、
// 保留 manifest 声明会用到的执行位（权限低 9 位，不含 setuid/setgid/sticky）。
func writeRegular(tr *tar.Reader, target string, hdr *tar.Header) error {
	if hdr.Size < 0 || hdr.Size > maxEntryBytes {
		return fmt.Errorf("archive entry %q too large (%d bytes)", hdr.Name, hdr.Size)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	// 只取权限低 9 位；显式屏蔽 setuid/setgid/sticky（tar 里带这些位的普通文件在
	// App 包里没有合法用途，且 setuid 落到磁盘是提权隐患）。
	mode := os.FileMode(hdr.Mode).Perm()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	// io.CopyN 上限再兜一次底：即便 hdr.Size 谎报，也不会写超过上限。
	if _, err := io.CopyN(out, tr, hdr.Size); err != nil && !errors.Is(err, io.EOF) {
		_ = out.Close()
		return fmt.Errorf("write %q: %w", target, err)
	}
	return out.Close()
}
