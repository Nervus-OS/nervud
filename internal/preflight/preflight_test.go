//go:build linux

package preflight

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/sysprobe"
)

func selfOwner() (uint32, uint32) {
	return uint32(os.Geteuid()), uint32(os.Getegid())
}

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
	st, _ := sysprobe.LstatPath(dir)
	if st.Perm != 0o777 {
		t.Fatalf("read-only path was modified: got %#o, must stay 0777", st.Perm)
	}
}

func TestForeignOwnerIsFatal(t *testing.T) {
	dir := t.TempDir()
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
	if err := os.WriteFile(f, []byte("x"), 0o555); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg := baseCfg(Rule{Path: f, Kind: kindFile, Perm: 0, PermExact: false, Writable: false})
	if err := Run(cfg); err != nil {
		t.Fatalf("0555 should pass non-exact check: %v", err)
	}

	if err := os.Chmod(f, 0o757); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := Run(cfg); !errors.Is(err, ErrPreflight) {
		t.Fatalf("0757 (other-writable) must fail non-exact read-only check, got %v", err)
	}
}

// 用户文档区必须恰好是 01770, 而且必须是 PermExact.
//
// 这不是一条风格断言, 它是整套运行期授予的安全前提: 能不能写由目录上那条
// u:<uid>:rwx 的 ACL 条目决定 (见 authority/acl_linux.go), 而 ACL 只在
// other 位为空时才说得上话. 这里曾经是 01777 —— 那个值下任何拿到挂载的包
// 都能读写, 授予与撤销全部变成空转, 且没有任何测试会因此变红.
//
// sticky 位同样不可省: 没有它, 任一被授权的包都能删掉其它包与用户的文件.
func TestDefaultConfigUserDataRootIsExactly01770(t *testing.T) {
	inv := authority.DefaultInvariants()
	if inv.UserDataRoot == "" {
		t.Fatal("DefaultInvariants 没给 UserDataRoot")
	}

	var found bool
	for _, r := range DefaultConfig(nil).Rules {
		if r.Path != inv.UserDataRoot {
			continue
		}
		found = true
		if r.Perm != 0o1770 {
			t.Errorf("UserDataRoot perm = %#o, want 01770", r.Perm)
		}
		if !r.PermExact {
			t.Error("UserDataRoot 必须 PermExact: 非精确匹配只堵 group/other 的 w 位, " +
				"01777 会被放过去")
		}
		if r.Perm&0o007 != 0 {
			t.Errorf("UserDataRoot other 位 = %#o, 必须为空, 否则 ACL 形同虚设", r.Perm&0o007)
		}
		if r.Perm&0o1000 == 0 {
			t.Error("UserDataRoot 少了 sticky 位")
		}
		if !r.Writable {
			t.Error("UserDataRoot 应在可写区, 否则权限漂移只报错不修正")
		}
	}
	if !found {
		t.Fatalf("生产规则表里没有 UserDataRoot (%s)", inv.UserDataRoot)
	}
}
