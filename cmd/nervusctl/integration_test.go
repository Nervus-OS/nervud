package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nervus-os/nervud/internal/admin"
	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/permission"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

type backend struct {
	mu       sync.Mutex
	packages map[string]pkgregistry.Entry
}

func newBackend() *backend { return &backend{packages: map[string]pkgregistry.Entry{}} }

func (b *backend) Install(_ context.Context, tx pkgregistry.InstallTransaction) (pkgregistry.Entry, error) {
	if len(tx.ManifestBytes) == 0 {
		return pkgregistry.Entry{}, io.ErrUnexpectedEOF
	}
	if _, err := os.Stat(filepath.Join(tx.StagingDir, "bin", "app")); err != nil {
		return pkgregistry.Entry{}, err
	}
	e := pkgregistry.Entry{
		Manifest:           pkgregistry.Manifest{PackageID: "com.example.demo"},
		ActiveVersion:      "1.0.0",
		VersionCode:        100,
		Trust:              identity.TrustOrdinary,
		Source:             pkgregistry.SourceDynamicInstall,
		GrantedPermissions: []string{"nervus.permission.example"},
	}
	b.mu.Lock()
	b.packages[e.Manifest.PackageID] = e
	b.mu.Unlock()
	return e, nil
}

func (b *backend) Uninstall(_ context.Context, pkgID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.packages[pkgID]; !ok {
		return pkgregistry.ErrPackageNotInstalled
	}
	delete(b.packages, pkgID)
	return nil
}

func (b *backend) SetComponentEnabled(_ context.Context, pkg, comp string, _ bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.packages[pkg]; !ok {
		return pkgregistry.ErrPackageNotInstalled
	}
	return nil
}

func (b *backend) List() []pkgregistry.Entry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]pkgregistry.Entry, 0, len(b.packages))
	for _, e := range b.packages {
		out = append(out, e)
	}
	return out
}

func (b *backend) SetRuntimeState(string, string, permission.GrantState) error { return nil }

func startAdmin(t *testing.T, b *backend) string {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "admin.sock")
	stagingRoot := filepath.Join(dir, "staging")
	if err := os.MkdirAll(stagingRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := admin.New(admin.Config{
		SockPath:    sock,
		StagingRoot: stagingRoot,
		AdminUID:    uint32(os.Getuid()),
		Packages:    b,
		Registry:    b,
		Permissions: b,
		Auditor:     audit.New(log),
		Log:         log,
	})
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("admin.Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })
	return sock
}

func TestEndToEndInstallListUninstall(t *testing.T) {
	b := newBackend()
	sock := startAdmin(t, b)

	nspkg := buildNspkg(t, []archiveEntry{
		{name: "manifest.json", body: `{"schema":1,"package_id":"com.example.demo"}`},
		{name: "manifest.sig", body: `{"format":1}`},
		{name: "bin/app", body: "#!/bin/true", mode: 0o755},
	})

	// install
	var out, errb bytes.Buffer
	if code := run([]string{"--sock", sock, "install", nspkg}, &out, &errb); code != 0 {
		t.Fatalf("install exit=%d stderr=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), "installed com.example.demo 1.0.0") {
		t.Fatalf("install output: %q", out.String())
	}
	if !strings.Contains(out.String(), "nervus.permission.example") {
		t.Fatalf("install output missing granted perms: %q", out.String())
	}

	out.Reset()
	errb.Reset()
	if code := run([]string{"--sock", sock, "list"}, &out, &errb); code != 0 {
		t.Fatalf("list exit=%d stderr=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), "com.example.demo") {
		t.Fatalf("list output: %q", out.String())
	}

	out.Reset()
	errb.Reset()
	if code := run([]string{"--sock", sock, "disable", "com.example.demo", "main"}, &out, &errb); code != 0 {
		t.Fatalf("disable exit=%d stderr=%s", code, errb.String())
	}

	out.Reset()
	errb.Reset()
	if code := run([]string{"--sock", sock, "uninstall", "com.example.demo"}, &out, &errb); code != 0 {
		t.Fatalf("uninstall exit=%d stderr=%s", code, errb.String())
	}
	if len(b.List()) != 0 {
		t.Fatalf("package still present after uninstall")
	}
}

func TestEndToEndUninstallMissing(t *testing.T) {
	b := newBackend()
	sock := startAdmin(t, b)
	var out, errb bytes.Buffer
	if code := run([]string{"--sock", sock, "uninstall", "com.nope"}, &out, &errb); code == 0 {
		t.Fatal("want non-zero exit for missing package")
	}
}

func TestRunUsageErrors(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"install"}, &out, &errb); code != 2 {
		t.Fatalf("install without arg exit=%d, want 2", code)
	}
	if code := run(nil, &out, &errb); code != 2 {
		t.Fatalf("no command exit=%d, want 2", code)
	}
	if code := run([]string{"bogus"}, &out, &errb); code != 2 {
		t.Fatalf("unknown command exit=%d, want 2", code)
	}
}
