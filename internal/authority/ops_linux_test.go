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
