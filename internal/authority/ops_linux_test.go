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

func TestCreateDataDir_RollsBackOnFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("fchown succeeds as root, so this test cannot exercise the rollback path")
	}
	root := t.TempDir()
	g := newFSGate(t, root)

	target := filepath.Join(root, "com.example.app")
	req := CreateDataDirRequest{Path: target, UID: 20001, GID: 20001, Perm: 0o700}

	if _, err := g.CreatePrivateDataDirectory(context.Background(), SubjectKernel(), req); err == nil {
		t.Fatal("fchown should fail for a non-root caller")
	}

	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("rollback did not remove the partial directory: err=%v", err)
	}

	_, err := g.CreatePrivateDataDirectory(context.Background(), SubjectKernel(), req)
	if err == nil {
		t.Fatal("retry should still fail for a non-root caller")
	}
	if strings.Contains(err.Error(), "mkdirat") {
		t.Fatalf("retry reached mkdirat (EEXIST), so rollback did not clean up: %v", err)
	}
	if !strings.Contains(err.Error(), "fchown") {
		t.Fatalf("retry failed somewhere other than fchown; rollback state is suspect: %v", err)
	}
}

func TestCreateDataDir_SuccessLeavesDir(t *testing.T) {
	uid := uint32(os.Getuid())
	if uid == 0 {
		t.Skip("root has different fchown semantics; this test covers an unprivileged self-chown")
	}
	root := t.TempDir()
	g, err := New(Config{
		Auditor:    &fakeRecorder{},
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Invariants: &Invariants{DataRoot: root, PackageRoot: root, MinAppUID: uid, MaxAppUID: uid},
	})
	if err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(root, "self.app")
	req := CreateDataDirRequest{Path: target, UID: uid, GID: uint32(os.Getgid()), Perm: 0o700}
	if _, err := g.CreatePrivateDataDirectory(context.Background(), SubjectKernel(), req); err != nil {
		t.Fatalf("creation with a self-chown should succeed: %v", err)
	}
	fi, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("directory should exist after success: %v", err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("perm = %o, want 700", fi.Mode().Perm())
	}
}

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
		t.Fatalf("staging directory should have been moved: err=%v", err)
	}
	fi, err := os.Lstat(destDir)
	if err != nil {
		t.Fatalf("destination directory should exist: %v", err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("perm = %o, want 755", fi.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(destDir, "bin")); err != nil {
		t.Fatalf("files in staging should move with the directory: %v", err)
	}
}

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
		t.Fatal("an existing destination version directory must not be overwritten")
	}
	if !strings.Contains(err.Error(), "renameat2") {
		t.Fatalf("failure should come from renameat2 (RENAME_NOREPLACE), got: %v", err)
	}

	if _, err := os.Stat(filepath.Join(destDir, "marker")); err != nil {
		t.Fatalf("existing destination content was damaged: %v", err)
	}
	if _, err := os.Stat(staging); err != nil {
		t.Fatalf("staging directory should remain after failure: %v", err)
	}
}

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
		t.Fatalf("installing v2 should succeed even when the package ID directory exists: %v", err)
	}

	if _, err := os.Stat(filepath.Join(root, "com.example.app", "1.0.0", "bin")); err != nil {
		t.Fatalf("installing v2 should not affect v1: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "com.example.app", "2.0.0", "bin")); err != nil {
		t.Fatalf("v2 should be installed: %v", err)
	}
}
