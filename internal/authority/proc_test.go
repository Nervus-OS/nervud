package authority

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/nervus-os/nervud/internal/authority/systemd"
)

// fakeSpawner 记录调用，供断言 Gate 是否把请求正确翻成 systemd.UnitSpec
type fakeSpawner struct {
	started  []systemd.UnitSpec
	startErr error
	stopped  []string
}

func (f *fakeSpawner) StartTransientUnit(_ context.Context, spec systemd.UnitSpec) error {
	f.started = append(f.started, spec)
	return f.startErr
}
func (f *fakeSpawner) StopUnit(_ context.Context, name string) error {
	f.stopped = append(f.stopped, name)
	return nil
}
func (f *fakeSpawner) WaitUnit(_ context.Context, _ string) (systemd.ExitInfo, error) {
	return systemd.ExitInfo{ActiveState: "inactive", Result: "success"}, nil
}

func newTestGateWithSpawner(t *testing.T, sp UnitManager, inv *Invariants) (*Gate, *fakeRecorder) {
	t.Helper()
	rec := &fakeRecorder{}
	g, err := New(Config{
		Auditor:    rec,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Invariants: inv,
		Spawner:    sp,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g, rec
}

func validNativeReq() StartSandboxedProcessRequest {
	return StartSandboxedProcessRequest{
		UnitName:   "nervus-com.example.app-main.service",
		Runtime:    RuntimeNative,
		ExecPath:   "/var/lib/nervus/packages/com.example.app/1.0.0/bin",
		WorkingDir: "/var/lib/nervus/package-data/com.example.app",
		UID:        20001, GID: 20001,
	}
}

// --- Validate 分支 ---------------------------------------------------------

func TestStartSandboxed_ValidateNative(t *testing.T) {
	inv := DefaultInvariants()
	if err := validNativeReq().Validate(inv); err != nil {
		t.Fatalf("valid native req rejected: %v", err)
	}
	// native 的 ExecPath 逃出 PackageRoot 必须拒
	r := validNativeReq()
	r.ExecPath = "/usr/bin/evil"
	if err := r.Validate(inv); !errors.Is(err, ErrInvariantViolated) {
		t.Fatalf("native exec outside PackageRoot should fail, got %v", err)
	}
}

func TestStartSandboxed_ValidateJVM(t *testing.T) {
	inv := DefaultInvariants()
	r := StartSandboxedProcessRequest{
		UnitName:       "nervus-com.example.app-main.service",
		Runtime:        RuntimeJVM,
		ExecPath:       PlatformJREExec,
		ContainedPaths: []string{"/var/lib/nervus/packages/com.example.app/1.0.0/lib/app.jar"},
		WorkingDir:     "/var/lib/nervus/package-data/com.example.app",
		UID:            20001, GID: 20001,
	}
	if err := r.Validate(inv); err != nil {
		t.Fatalf("valid jvm req rejected: %v", err)
	}
	// jvm 的 ExecPath 不是平台 JRE 必须拒
	r.ExecPath = "/var/lib/nervus/packages/com.example.app/1.0.0/fakejava"
	if err := r.Validate(inv); !errors.Is(err, ErrInvariantViolated) {
		t.Fatalf("jvm exec != JRE should fail, got %v", err)
	}
	// jvm 的 jar（ContainedPaths）逃出 PackageRoot 必须拒
	r.ExecPath = PlatformJREExec
	r.ContainedPaths = []string{"/etc/shadow"}
	if err := r.Validate(inv); !errors.Is(err, ErrInvariantViolated) {
		t.Fatalf("jvm jar outside PackageRoot should fail, got %v", err)
	}
}

func TestStartSandboxed_ValidateWorkingDirAndUID(t *testing.T) {
	inv := DefaultInvariants()
	// WorkingDir 必须在 DataRoot 之下
	r := validNativeReq()
	r.WorkingDir = "/tmp/evil"
	if err := r.Validate(inv); !errors.Is(err, ErrInvariantViolated) {
		t.Fatalf("workingdir outside DataRoot should fail, got %v", err)
	}
	// UID 0 永远禁止
	r = validNativeReq()
	r.UID = 0
	if err := r.Validate(inv); !errors.Is(err, ErrInvariantViolated) {
		t.Fatalf("uid 0 should fail, got %v", err)
	}
}

// --- Gate 方法：翻译 + 审计 ------------------------------------------------

func TestStartSandboxedProcess_RoutesToSpawnerAndAudits(t *testing.T) {
	sp := &fakeSpawner{}
	g, rec := newTestGateWithSpawner(t, sp, nil)

	h, err := g.StartSandboxedProcess(context.Background(), SubjectKernel(), validNativeReq())
	if err != nil {
		t.Fatalf("StartSandboxedProcess: %v", err)
	}
	if h.Unit() != "nervus-com.example.app-main.service" {
		t.Fatalf("handle unit = %q", h.Unit())
	}
	if len(sp.started) != 1 || sp.started[0].Name != h.Unit() {
		t.Fatalf("spawner not called with unit: %+v", sp.started)
	}
	// 审计必须记一条成功的 StartSandboxedProcess
	found := false
	for _, ev := range rec.events {
		if ev.Action == KindStartSandboxedProcess.String() && !ev.Denied {
			found = true
		}
	}
	if !found {
		t.Fatalf("want StartSandboxedProcess audit, got %+v", rec.events)
	}
}

func TestStartSandboxedProcess_NoSpawnerFailsClosed(t *testing.T) {
	g, _ := newTestGate(t) // 无 spawner
	_, err := g.StartSandboxedProcess(context.Background(), SubjectKernel(), validNativeReq())
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("want ErrUnsupportedPlatform when spawner nil, got %v", err)
	}
}

func TestStopProcess_RoutesToSpawner(t *testing.T) {
	sp := &fakeSpawner{}
	g, _ := newTestGateWithSpawner(t, sp, nil)
	h, err := g.StartSandboxedProcess(context.Background(), SubjectKernel(), validNativeReq())
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := g.StopProcess(context.Background(), SubjectKernel(), StopProcessRequest{Handle: h}); err != nil {
		t.Fatalf("StopProcess: %v", err)
	}
	if len(sp.stopped) != 1 || sp.stopped[0] != h.Unit() {
		t.Fatalf("StopUnit not called: %+v", sp.stopped)
	}
}

// --- RemovePackageTree：真实递归删除 --------------------------------------

func TestRemovePackageTree_DeletesRecursively(t *testing.T) {
	root := t.TempDir()
	inv := &Invariants{
		DataRoot: filepath.Join(root, "data"), PackageRoot: filepath.Join(root, "packages"),
		MinAppUID: 20000, MaxAppUID: 59999,
	}
	if err := os.MkdirAll(inv.PackageRoot, 0o755); err != nil {
		t.Fatalf("mkdir packageroot: %v", err)
	}
	// 造一棵嵌套树 packages/com.example.app/1.0.0/{bin, lib/x.so}
	pkgDir := filepath.Join(inv.PackageRoot, "com.example.app")
	verDir := filepath.Join(pkgDir, "1.0.0", "lib")
	if err := os.MkdirAll(verDir, 0o755); err != nil {
		t.Fatalf("mkdir tree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(verDir, "x.so"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "1.0.0", "bin"), []byte("b"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	g, _ := newTestGateWithSpawner(t, nil, inv)
	err := g.RemovePackageTree(context.Background(), SubjectKernel(),
		RemovePackageTreeRequest{Root: inv.PackageRoot, Path: pkgDir})
	if err != nil {
		t.Fatalf("RemovePackageTree: %v", err)
	}
	if _, err := os.Stat(pkgDir); !os.IsNotExist(err) {
		t.Fatalf("tree not removed: stat err = %v", err)
	}
}

func TestRemovePackageTree_ValidateRejects(t *testing.T) {
	inv := DefaultInvariants()
	// Root 不是受管根
	r := RemovePackageTreeRequest{Root: "/tmp", Path: "/tmp/x"}
	if err := r.Validate(inv); !errors.Is(err, ErrInvariantViolated) {
		t.Fatalf("non-managed root should fail, got %v", err)
	}
	// Path 逃出 Root
	r = RemovePackageTreeRequest{Root: inv.PackageRoot, Path: "/etc/passwd"}
	if err := r.Validate(inv); !errors.Is(err, ErrInvariantViolated) {
		t.Fatalf("path escaping root should fail, got %v", err)
	}
	// Path == Root（想删整个根）也应拒（CheckContained 要求严格在内）
	r = RemovePackageTreeRequest{Root: inv.PackageRoot, Path: inv.PackageRoot}
	if err := r.Validate(inv); !errors.Is(err, ErrInvariantViolated) {
		t.Fatalf("path == root should fail, got %v", err)
	}
}
