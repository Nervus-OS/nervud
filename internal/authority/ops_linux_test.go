//go:build linux

package authority

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newFSGate(t *testing.T, root string) *Gate {
	t.Helper()
	g, err := New(Config{
		Auditor: &fakeRecorder{},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Invariants: &Invariants{
			DataRoot:    root,
			PackageRoot: root,
			MinAppUID:   20000,
			MaxAppUID:   59999,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

// 创建数据目录时若中途失败（这里用非 root 下 fchown 必然 EPERM 来触发），
// 必须回滚删除半成品目录。否则会留下 root 所有/权限不完整的目录，且重试在
// mkdirat 处撞 EEXIST，从此永远修不好
func TestCreateDataDir_RollsBackOnFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("以 root 运行时 fchown 会成功，无法触发回滚路径")
	}
	root := t.TempDir()
	g := newFSGate(t, root)

	target := filepath.Join(root, "com.example.app")
	req := CreateDataDirRequest{Path: target, UID: 20001, GID: 20001, Perm: 0o700}

	// 非 root：fchown 到 20001 会 EPERM，从而在 mkdirat 之后失败，触发回滚
	if _, err := g.CreatePrivateDataDirectory(context.Background(), SubjectKernel(), req); err == nil {
		t.Fatal("非 root 下 fchown 应当失败")
	}

	// 关键断言：回滚必须删掉半成品目录
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("回滚没有删掉半成品目录: err=%v", err)
	}

	// 重试不能撞 EEXIST：应再次走到 fchown 才失败（证明回滚让 mkdirat 能重来），
	// 而不是在 mkdirat 处就挂
	_, err := g.CreatePrivateDataDirectory(context.Background(), SubjectKernel(), req)
	if err == nil {
		t.Fatal("重试仍应失败（非 root）")
	}
	if strings.Contains(err.Error(), "mkdirat") {
		t.Fatalf("重试撞到了 mkdirat（EEXIST），说明回滚没生效: %v", err)
	}
	if !strings.Contains(err.Error(), "fchown") {
		t.Fatalf("重试的失败点不是 fchown，回滚状态可疑: %v", err)
	}
}

// 成功路径的对照（同样只在非 root 下有意义时跳过）：确认正常创建能留下目录。
// 非 root 无法 chown 到别的 UID，因此用 当前 UID 做一次能成功的创建
func TestCreateDataDir_SuccessLeavesDir(t *testing.T) {
	uid := uint32(os.Getuid())
	if uid == 0 {
		t.Skip("root 下另有 fchown 语义；本用例针对普通用户自我 chown")
	}
	root := t.TempDir()
	g, err := New(Config{
		Auditor: &fakeRecorder{},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		// 把 App 区段设成恰好包含当前 UID，这样 fchown 到自己会成功
		Invariants: &Invariants{DataRoot: root, PackageRoot: root, MinAppUID: uid, MaxAppUID: uid},
	})
	if err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(root, "self.app")
	req := CreateDataDirRequest{Path: target, UID: uid, GID: uint32(os.Getgid()), Perm: 0o700}
	if _, err := g.CreatePrivateDataDirectory(context.Background(), SubjectKernel(), req); err != nil {
		t.Fatalf("自我 chown 的创建应成功: %v", err)
	}
	fi, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("成功后目录应存在: %v", err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("perm = %o, want 700", fi.Mode().Perm())
	}
}

// newStagingDir 构造一个模拟 pkgmanagerd 产出的 staging 目录，内含一个文件
func newStagingDir(t *testing.T, root, name, content string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir staging: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin"), []byte(content), 0o755); err != nil {
		t.Fatalf("write staging file: %v", err)
	}
	return dir
}

func TestInstallVerifiedPackage_Success(t *testing.T) {
	root := t.TempDir()
	g := newFSGate(t, root)

	staging := newStagingDir(t, root, "staging-1", "#!/bin/true")
	destDir := filepath.Join(root, "com.example.app", "1.0.0")

	err := g.InstallVerifiedPackage(context.Background(), SubjectKernel(),
		InstallVerifiedPackageRequest{StagingDir: staging, DestDir: destDir})
	if err != nil {
		t.Fatalf("InstallVerifiedPackage: %v", err)
	}

	if _, err := os.Lstat(staging); !os.IsNotExist(err) {
		t.Fatalf("staging 目录应已被移走: err=%v", err)
	}
	fi, err := os.Lstat(destDir)
	if err != nil {
		t.Fatalf("目标目录应存在: %v", err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("perm = %o, want 755", fi.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(destDir, "bin")); err != nil {
		t.Fatalf("staging 里的文件应随目录一起移动: %v", err)
	}
}

// 同一个 <id>/<version> 提交两次必须整体失败、不能静默覆盖——重复提交或
// 版本号复用都不该被无声吞掉
func TestInstallVerifiedPackage_RejectsDestAlreadyExists(t *testing.T) {
	root := t.TempDir()
	g := newFSGate(t, root)

	destDir := filepath.Join(root, "com.example.app", "1.0.0")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		t.Fatalf("pre-create dest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "marker"), []byte("old"), 0o644); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	staging := newStagingDir(t, root, "staging-2", "new")
	err := g.InstallVerifiedPackage(context.Background(), SubjectKernel(),
		InstallVerifiedPackageRequest{StagingDir: staging, DestDir: destDir})
	if err == nil {
		t.Fatal("已存在的目标版本目录必须拒绝覆盖")
	}
	if !strings.Contains(err.Error(), "renameat2") {
		t.Fatalf("失败点应在 renameat2（RENAME_NOREPLACE），got: %v", err)
	}

	// 已存在的目标内容必须原封不动，staging 也不该被消耗掉
	if _, err := os.Stat(filepath.Join(destDir, "marker")); err != nil {
		t.Fatalf("既有目标内容被破坏: %v", err)
	}
	if _, err := os.Stat(staging); err != nil {
		t.Fatalf("失败时 staging 目录不该被移走: %v", err)
	}
}

// 同一个 Package 装第二个版本时，<id> 目录已经存在——mkdirat 必须把
// EEXIST 当成正常情况而不是错误
func TestInstallVerifiedPackage_SecondVersionReusesIDDir(t *testing.T) {
	root := t.TempDir()
	g := newFSGate(t, root)

	first := newStagingDir(t, root, "staging-v1", "v1")
	if err := g.InstallVerifiedPackage(context.Background(), SubjectKernel(), InstallVerifiedPackageRequest{
		StagingDir: first, DestDir: filepath.Join(root, "com.example.app", "1.0.0"),
	}); err != nil {
		t.Fatalf("install v1: %v", err)
	}

	second := newStagingDir(t, root, "staging-v2", "v2")
	if err := g.InstallVerifiedPackage(context.Background(), SubjectKernel(), InstallVerifiedPackageRequest{
		StagingDir: second, DestDir: filepath.Join(root, "com.example.app", "2.0.0"),
	}); err != nil {
		t.Fatalf("install v2 应当成功（<id> 目录已存在也不该报错）: %v", err)
	}

	if _, err := os.Stat(filepath.Join(root, "com.example.app", "1.0.0", "bin")); err != nil {
		t.Fatalf("v1 不该被 v2 的安装影响: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "com.example.app", "2.0.0", "bin")); err != nil {
		t.Fatalf("v2 应已装好: %v", err)
	}
}
