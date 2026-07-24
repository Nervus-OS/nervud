//go:build linux

package preflight

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nervus-os/nervud/internal/sysprobe"
)

// selfOwner 返回当前进程的 uid/gid，测试用它当「nervud 自身」
func selfOwner() (uint32, uint32) {
	return uint32(os.Geteuid()), uint32(os.Getegid())
}

// baseCfg 造一个只含给定规则、属主为当前进程的 Config
func baseCfg(rules ...Rule) Config {
	uid, gid := selfOwner()
	return Config{Rules: rules, OwnerUID: uid, OwnerGID: gid}
}

func TestWritableDirCreatedWhenMissing(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "registry")
	cfg := baseCfg(Rule{Path: target, Kind: kindDir, Perm: 0o700, PermExact: true, Writable: true})

	if err := Run(cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	st, err := sysprobe.LstatPath(target)
	if err != nil {
		t.Fatalf("lstat after create: %v", err)
	}
	if !st.IsDir || st.Perm != 0o700 {
		t.Fatalf("want dir 0700, got isDir=%v perm=%#o", st.IsDir, st.Perm)
	}
}

func TestWritableDirPermCorrected(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	cfg := baseCfg(Rule{Path: dir, Kind: kindDir, Perm: 0o755, PermExact: true, Writable: true})

	if err := Run(cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	st, _ := sysprobe.LstatPath(dir)
	if st.Perm != 0o755 {
		t.Fatalf("perm not corrected: got %#o want 0755", st.Perm)
	}
}

func TestStickyBitPreserved(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "nervus")
	cfg := baseCfg(Rule{Path: runDir, Kind: kindDir, Perm: 0o1755, PermExact: true, Writable: true})

	if err := Run(cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	st, _ := sysprobe.LstatPath(runDir)
	if st.Perm != 0o1755 {
		t.Fatalf("sticky bit lost: got %#o want 01755", st.Perm)
	}
}

func TestReadOnlyMissingIsFatal(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	cfg := baseCfg(Rule{Path: missing, Kind: kindDir, Perm: 0o755, PermExact: true, Writable: false})

	err := Run(cfg)
	if !errors.Is(err, ErrPreflight) {
		t.Fatalf("want ErrPreflight for missing read-only path, got %v", err)
	}
}

func TestReadOnlyWrongPermIsFatalNotCorrected(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	cfg := baseCfg(Rule{Path: dir, Kind: kindDir, Perm: 0o755, PermExact: true, Writable: false})

	if err := Run(cfg); !errors.Is(err, ErrPreflight) {
		t.Fatalf("want ErrPreflight, got %v", err)
	}
	// 关键：只读区【不自动修】——权限必须仍是 0777，证明没有掩盖入侵痕迹
	st, _ := sysprobe.LstatPath(dir)
	if st.Perm != 0o777 {
		t.Fatalf("read-only path was modified: got %#o, must stay 0777", st.Perm)
	}
}

func TestForeignOwnerIsFatal(t *testing.T) {
	dir := t.TempDir()
	// 声明一个不同于当前进程的属主，模拟「被别的进程抢建」——即便可写区也 fatal，
	// 不 chown 洗白
	uid, gid := selfOwner()
	cfg := Config{
		OwnerUID: uid + 1, OwnerGID: gid,
		Rules: []Rule{{Path: dir, Kind: kindDir, Perm: 0o755, PermExact: true, Writable: true}},
	}
	if err := Run(cfg); !errors.Is(err, ErrPreflight) {
		t.Fatalf("want ErrPreflight for foreign-owned writable path, got %v", err)
	}
}

func TestSymlinkRejected(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	cfg := baseCfg(Rule{Path: link, Kind: kindDir, Perm: 0o755, PermExact: true, Writable: true})
	if err := Run(cfg); !errors.Is(err, ErrPreflight) {
		t.Fatalf("want ErrPreflight for symlinked path, got %v", err)
	}
}

func TestFileKindMismatchIsFatal(t *testing.T) {
	root := t.TempDir()
	// 规则说这里应是目录，实际放个普通文件
	f := filepath.Join(root, "x")
	if err := os.WriteFile(f, []byte("hi"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg := baseCfg(Rule{Path: f, Kind: kindDir, Perm: 0o755, PermExact: true, Writable: true})
	if err := Run(cfg); !errors.Is(err, ErrPreflight) {
		t.Fatalf("want ErrPreflight for kind mismatch, got %v", err)
	}
}

func TestNonExactPermOnlyChecksGroupOtherWrite(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "bin")
	// 0o555：group/other 不可写，non-exact 应放行
	if err := os.WriteFile(f, []byte("x"), 0o555); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg := baseCfg(Rule{Path: f, Kind: kindFile, Perm: 0, PermExact: false, Writable: false})
	if err := Run(cfg); err != nil {
		t.Fatalf("0555 should pass non-exact check: %v", err)
	}

	// 0o757：other 可写，non-exact 只读区应 fatal
	if err := os.Chmod(f, 0o757); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := Run(cfg); !errors.Is(err, ErrPreflight) {
		t.Fatalf("0757 (other-writable) must fail non-exact read-only check, got %v", err)
	}
}
