package admin

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/nervus-os/nervud/internal/adminwire"
	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/permission"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

type fakePkgService struct {
	installTx  []pkgregistry.InstallTransaction
	installErr error
	installOut pkgregistry.Entry
	uninstall  []string
	uninstErr  error
	setEnabled []string // "pkg/comp=enabled"
	setEnabErr error
}

func (f *fakePkgService) Install(_ context.Context, tx pkgregistry.InstallTransaction) (pkgregistry.Entry, error) {
	f.installTx = append(f.installTx, tx)
	if f.installErr != nil {
		return pkgregistry.Entry{}, f.installErr
	}
	return f.installOut, nil
}

func (f *fakePkgService) Uninstall(_ context.Context, pkgID string) error {
	f.uninstall = append(f.uninstall, pkgID)
	return f.uninstErr
}

func (f *fakePkgService) SetComponentEnabled(_ context.Context, pkg, comp string, enabled bool) error {
	f.setEnabled = append(f.setEnabled, pkg+"/"+comp)
	_ = enabled
	return f.setEnabErr
}

type fakeLister struct{ entries []pkgregistry.Entry }

func (f *fakeLister) List() []pkgregistry.Entry { return f.entries }

type fakePermSetter struct {
	calls []string // "pkg perm state"
	err   error
}

func (f *fakePermSetter) SetRuntimeState(pkg, perm string, state permission.GrantState) error {
	f.calls = append(f.calls, pkg+" "+perm)
	_ = state
	return f.err
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func startServer(t *testing.T, adminUID uint32) (*adminwire.Client, *fakePkgService, *fakeLister, *fakePermSetter, string) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "admin.sock")
	stagingRoot := filepath.Join(dir, "staging")
	if err := os.MkdirAll(stagingRoot, 0o700); err != nil {
		t.Fatalf("mkdir staging root: %v", err)
	}

	pkgs := &fakePkgService{}
	reg := &fakeLister{}
	perms := &fakePermSetter{}
	srv, err := New(Config{
		SockPath:    sock,
		StagingRoot: stagingRoot,
		AdminUID:    adminUID,
		Packages:    pkgs,
		Registry:    reg,
		Permissions: perms,
		Auditor:     audit.New(discardLog()),
		Log:         discardLog(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		_ = srv.Stop(context.Background())
	})
	return adminwire.NewClient(sock), pkgs, reg, perms, stagingRoot
}

func TestBeginStagingCreatesChildDir(t *testing.T) {
	client, _, _, _, stagingRoot := startServer(t, uint32(os.Getuid()))
	resp, err := client.Do(adminwire.Request{Cmd: adminwire.CmdBeginStaging})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !resp.OK || resp.StagingDir == "" {
		t.Fatalf("begin-staging failed: %+v", resp)
	}
	if filepath.Dir(resp.StagingDir) != filepath.Clean(stagingRoot) {
		t.Fatalf("staging dir %q not a child of %q", resp.StagingDir, stagingRoot)
	}
	if fi, err := os.Stat(resp.StagingDir); err != nil || !fi.IsDir() {
		t.Fatalf("staging dir not created: %v", err)
	}
}

func TestInstallHappyPath(t *testing.T) {
	client, pkgs, _, _, _ := startServer(t, uint32(os.Getuid()))
	pkgs.installOut = pkgregistry.Entry{
		Manifest:           pkgregistry.Manifest{PackageID: "com.example.app"},
		ActiveVersion:      "1.0.0",
		VersionCode:        100,
		Trust:              identity.TrustOrdinary,
		Source:             pkgregistry.SourceDynamicInstall,
		GrantedPermissions: []string{"perm.a"},
	}

	begin, _ := client.Do(adminwire.Request{Cmd: adminwire.CmdBeginStaging})
	staging := begin.StagingDir
	if err := os.WriteFile(filepath.Join(staging, pkgregistry.ManifestFileName), []byte(`{"schema":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, pkgregistry.SignatureFileName), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(adminwire.Request{Cmd: adminwire.CmdInstall, StagingDir: staging})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !resp.OK || resp.Package == nil {
		t.Fatalf("install failed: %+v", resp)
	}
	if resp.Package.ID != "com.example.app" || len(resp.Package.Granted) != 1 {
		t.Fatalf("unexpected package info: %+v", resp.Package)
	}
	if len(pkgs.installTx) != 1 {
		t.Fatalf("want 1 Install call, got %d", len(pkgs.installTx))
	}
	tx := pkgs.installTx[0]
	if tx.StagingDir != staging || tx.Source != pkgregistry.SourceDynamicInstall {
		t.Fatalf("Install got tx %+v", tx)
	}
	if string(tx.ManifestBytes) != `{"schema":1}` {
		t.Fatalf("manifest bytes not read from staging: %q", tx.ManifestBytes)
	}
}

func TestInstallRejectsPathEscape(t *testing.T) {
	client, pkgs, _, _, stagingRoot := startServer(t, uint32(os.Getuid()))
	cases := []string{
		"/etc",
		filepath.Join(stagingRoot, "..", "evil"),
		stagingRoot,
		filepath.Join(stagingRoot, "a", "b"),
		"relative/path",
		"",
	}
	for _, sd := range cases {
		resp, err := client.Do(adminwire.Request{Cmd: adminwire.CmdInstall, StagingDir: sd})
		if err != nil {
			t.Fatalf("Do(%q): %v", sd, err)
		}
		if resp.OK || resp.Code != adminwire.CodeBadRequest {
			t.Fatalf("staging %q: got %+v, want bad-request", sd, resp)
		}
	}
	if len(pkgs.installTx) != 0 {
		t.Fatalf("pkgregistry must not be touched on escape, got %d installs", len(pkgs.installTx))
	}
}

func TestInstallCleansStagingOnFailure(t *testing.T) {
	client, pkgs, _, _, _ := startServer(t, uint32(os.Getuid()))
	pkgs.installErr = context.DeadlineExceeded

	begin, _ := client.Do(adminwire.Request{Cmd: adminwire.CmdBeginStaging})
	staging := begin.StagingDir
	_ = os.WriteFile(filepath.Join(staging, pkgregistry.ManifestFileName), []byte(`{}`), 0o644)
	_ = os.WriteFile(filepath.Join(staging, pkgregistry.SignatureFileName), []byte(`{}`), 0o644)

	resp, _ := client.Do(adminwire.Request{Cmd: adminwire.CmdInstall, StagingDir: staging})
	if resp.OK || resp.Code != adminwire.CodeFailed {
		t.Fatalf("want failed, got %+v", resp)
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Fatalf("staging dir should be cleaned on failure, stat err = %v", err)
	}
}

func TestListProjectsEntries(t *testing.T) {
	client, _, reg, _, _ := startServer(t, uint32(os.Getuid()))
	reg.entries = []pkgregistry.Entry{
		{
			Manifest: pkgregistry.Manifest{PackageID: "com.a"}, ActiveVersion: "1.0.0",
			Trust: identity.TrustOrdinary, Source: pkgregistry.SourceDynamicInstall,
			DisabledComponents: []string{"main"},
		},
	}
	resp, err := client.Do(adminwire.Request{Cmd: adminwire.CmdList})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !resp.OK || len(resp.Packages) != 1 {
		t.Fatalf("list = %+v", resp)
	}
	p := resp.Packages[0]
	if p.ID != "com.a" || p.Version != "1.0.0" || len(p.Disabled) != 1 {
		t.Fatalf("projected info wrong: %+v", p)
	}
}

func TestUninstallAndSetEnabledAndPermission(t *testing.T) {
	client, pkgs, _, perms, _ := startServer(t, uint32(os.Getuid()))

	if resp, _ := client.Do(adminwire.Request{Cmd: adminwire.CmdUninstall, PackageID: "com.a"}); !resp.OK {
		t.Fatalf("uninstall: %+v", resp)
	}
	if len(pkgs.uninstall) != 1 || pkgs.uninstall[0] != "com.a" {
		t.Fatalf("uninstall not forwarded: %v", pkgs.uninstall)
	}

	if resp, _ := client.Do(adminwire.Request{
		Cmd: adminwire.CmdSetEnabled, PackageID: "com.a", ComponentID: "main", Enabled: false,
	}); !resp.OK {
		t.Fatalf("set-enabled: %+v", resp)
	}
	if len(pkgs.setEnabled) != 1 || pkgs.setEnabled[0] != "com.a/main" {
		t.Fatalf("set-enabled not forwarded: %v", pkgs.setEnabled)
	}

	if resp, _ := client.Do(adminwire.Request{
		Cmd: adminwire.CmdSetPermission, PackageID: "com.a", Permission: "perm.x", GrantState: adminwire.GrantStateGranted,
	}); !resp.OK {
		t.Fatalf("set-permission: %+v", resp)
	}
	if len(perms.calls) != 1 {
		t.Fatalf("set-permission not forwarded: %v", perms.calls)
	}
}

func TestSetPermissionRejectsUnknownState(t *testing.T) {
	client, _, _, _, _ := startServer(t, uint32(os.Getuid()))
	resp, _ := client.Do(adminwire.Request{
		Cmd: adminwire.CmdSetPermission, PackageID: "com.a", Permission: "perm.x", GrantState: "bogus",
	})
	if resp.OK || resp.Code != adminwire.CodeBadRequest {
		t.Fatalf("want bad-request, got %+v", resp)
	}
}

func TestUnknownCommandRejected(t *testing.T) {
	client, _, _, _, _ := startServer(t, uint32(os.Getuid()))
	resp, _ := client.Do(adminwire.Request{Cmd: "frobnicate"})
	if resp.OK || resp.Code != adminwire.CodeBadRequest {
		t.Fatalf("want bad-request, got %+v", resp)
	}
}

func TestRejectsNonAdminUID(t *testing.T) {
	client, pkgs, _, _, _ := startServer(t, uint32(os.Getuid())+1)
	resp, err := client.Do(adminwire.Request{Cmd: adminwire.CmdList})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.OK || resp.Code != adminwire.CodeUnauthorized {
		t.Fatalf("want unauthorized, got %+v", resp)
	}
	if len(pkgs.installTx) != 0 {
		t.Fatal("no operation should have run for a rejected caller")
	}
}

// ---- ServiceUID 放行（pkgmanagerd 装包链路的准入）------------------------

// newServerWithServiceUID 构造一个 Server 并【模拟 Start 时的服务 UID 解析】。
//
// 不真的 Start：chown 到一个不存在的 GID 需要 root，普通开发机跑不了。
// 这里直接调 resolveServiceUID，验的是解析与集合合并本身。
func newServerWithServiceUID(t *testing.T, adminUID, serviceUID uint32) *Server {
	t.Helper()
	dir := t.TempDir()

	reg := &fakeLister{}
	if serviceUID != 0 {
		reg.entries = []pkgregistry.Entry{{
			Manifest: pkgregistry.Manifest{PackageID: testServicePkgID},
			UID:      serviceUID,
		}}
	}
	srv, err := New(Config{
		SockPath:         filepath.Join(dir, "s.sock"),
		StagingRoot:      filepath.Join(dir, "staging"),
		AdminUID:         adminUID,
		ServicePackageID: testServicePkgID,
		Packages:         &fakePkgService{},
		Registry:         reg,
		Permissions:      &fakePermSetter{},
		Auditor:          audit.New(discardLog()),
		Log:              discardLog(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Start 里做的那一步。真实路径上它跑在启动扫描【之后】——装配期查不到 UID，
	// 那正是这个改动要修的 bug。
	srv.resolveServiceUID()
	return srv
}

const testServicePkgID = "nervus.pkgmanagerd"

func TestServiceUID_AdmittedAlongsideAdmin(t *testing.T) {
	srv := newServerWithServiceUID(t, 0, 20001)

	for _, uid := range []uint32{0, 20001} {
		if _, ok := srv.allowedUIDs[uid]; !ok {
			t.Errorf("uid %d should be admitted", uid)
		}
	}
	// 别的包（哪怕也在 App 段）不能连：放行的是一个特定服务，不是一个区段
	if _, ok := srv.allowedUIDs[20002]; ok {
		t.Error("a different package UID must not be admitted")
	}
}

func TestServiceUID_ZeroDoesNotAdmitRootThroughBackDoor(t *testing.T) {
	// ServiceUID 由 Registry 查询结果填充，查不到时零值恰好是 0。若把它无条件
	// 加进允许集合，一个「包没装」的普通状况就会静默地把 root 从服务这条口子
	// 又放进来一次——而 root 只应通过 AdminUID 这条明确路径进入。
	//
	// 这里 AdminUID 取一个非 0 值，断言 0 没有被 ServiceUID=0 带进来。
	srv := newServerWithServiceUID(t, 1000, 0)

	if _, ok := srv.allowedUIDs[0]; ok {
		t.Fatal("uid 0 must not be admitted via ServiceUID=0")
	}
	if _, ok := srv.allowedUIDs[1000]; !ok {
		t.Error("admin uid should still be admitted")
	}
	if len(srv.allowedUIDs) != 1 {
		t.Errorf("allowed set = %v, want exactly the admin uid", srv.allowedUIDs)
	}
}

func TestServiceUID_ResolvedAtStartNotAssembly(t *testing.T) {
	// 这条锁住本次修的 bug：UID 是启动扫描时才分配的，装配期查不到。
	// 构造完但还没解析时，允许集合里只该有运维身份。
	dir := t.TempDir()
	reg := &fakeLister{entries: []pkgregistry.Entry{{
		Manifest: pkgregistry.Manifest{PackageID: testServicePkgID},
		UID:      20001,
	}}}
	srv, err := New(Config{
		SockPath: filepath.Join(dir, "s.sock"), StagingRoot: filepath.Join(dir, "staging"),
		AdminUID: 1000, ServicePackageID: testServicePkgID,
		Packages: &fakePkgService{}, Registry: reg, Permissions: &fakePermSetter{},
		Auditor: audit.New(discardLog()), Log: discardLog(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := srv.allowedUIDs[20001]; ok {
		t.Error("构造期不该已经解析出服务 UID（那时扫描还没跑）")
	}
	srv.resolveServiceUID()
	if _, ok := srv.allowedUIDs[20001]; !ok {
		t.Error("Start 时的解析没有把服务 UID 补进允许集合")
	}
	if srv.serviceUID != 20001 {
		t.Errorf("serviceUID = %d, want 20001", srv.serviceUID)
	}
}

func TestServiceUID_ZeroKeepsSocketPrivate(t *testing.T) {
	// 没有服务放行时，socket 必须保持 0600。放宽到 0660 却没有对应的组归属，
	// 等于把连接权发给 nervud 主组（生产是 root 组）的全部成员。
	srv := newServerWithServiceUID(t, uint32(os.Getuid()), 0)
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })

	fi, err := os.Stat(srv.sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if got := fi.Mode().Perm(); got != socketMode {
		t.Fatalf("socket mode = %o, want %o", got, socketMode)
	}
}
