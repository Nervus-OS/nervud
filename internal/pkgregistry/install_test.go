package pkgregistry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/permission"
)

type fakeInstaller struct {
	installErr error
	dataDirErr error
	installed  []authority.InstallVerifiedPackageRequest
	dataDirs   []authority.CreateDataDirRequest
}

func (f *fakeInstaller) InstallVerifiedPackage(
	_ context.Context, _ authority.Subject, req authority.InstallVerifiedPackageRequest,
) error {
	f.installed = append(f.installed, req)
	return f.installErr
}

func (f *fakeInstaller) CreatePrivateDataDirectory(
	_ context.Context, _ authority.Subject, req authority.CreateDataDirRequest,
) (authority.DirHandle, error) {
	f.dataDirs = append(f.dataDirs, req)
	if f.dataDirErr != nil {
		return authority.DirHandle{}, f.dataDirErr
	}
	return authority.DirHandle{Path: req.Path}, nil
}

type fakeIdentityUpdater struct {
	replaced [][]identity.Package
}

func (f *fakeIdentityUpdater) Replace(pkgs []identity.Package) error {
	f.replaced = append(f.replaced, pkgs)
	return nil
}

type fakeAuditor struct{ events []audit.Event }

func (f *fakeAuditor) Record(_ context.Context, ev audit.Event) { f.events = append(f.events, ev) }

// fakePermissionArbiter 默认放行全部请求权限（透传），镜像 Arbitrate 改造前
// Decision.GrantedPerms 的直通行为，好让不关心权限裁决细节的既有测试不必
// 改动断言；需要覆盖裁决细节的测试单独构造自己的 intersect 函数
type fakePermissionArbiter struct {
	intersect func(requested []string, trust identity.TrustProfile) (granted, denied []string)
	replaced  [][]permission.Grant
}

func (f *fakePermissionArbiter) Intersect(requested []string, trust identity.TrustProfile) (granted, denied []string) {
	if f.intersect != nil {
		return f.intersect(requested, trust)
	}
	return requested, nil
}

func (f *fakePermissionArbiter) Replace(grants []permission.Grant) error {
	f.replaced = append(f.replaced, grants)
	return nil
}

func newTestInstaller(t *testing.T) (*Module, *fakeInstaller, *fakeIdentityUpdater, *fakeAuditor) {
	t.Helper()
	mod, auth, idReg, aud, _ := newTestInstallerWithPerm(t)
	return mod, auth, idReg, aud
}

func newTestInstallerWithPerm(t *testing.T) (*Module, *fakeInstaller, *fakeIdentityUpdater, *fakeAuditor, *fakePermissionArbiter) {
	t.Helper()
	dir := t.TempDir()
	auth := &fakeInstaller{}
	idReg := &fakeIdentityUpdater{}
	perm := &fakePermissionArbiter{}
	aud := &fakeAuditor{}
	registry := NewRegistry()
	mod := New(auth, idReg, perm, registry, aud, nil,
		filepath.Join(dir, "registry"), filepath.Join(dir, "system-packages"),
		filepath.Join(dir, "packages"), filepath.Join(dir, "data"))
	return mod, auth, idReg, aud, perm
}

// newValidStaging 构造一份内容与 manifest digest 一致的 staging 目录，
// 返回 (staging 目录, manifest 原始字节)
func newValidStaging(t *testing.T, root, packageID, version string) (string, []byte) {
	t.Helper()
	staging := filepath.Join(root, "staging")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatalf("mkdir staging: %v", err)
	}
	content := "#!/bin/true"
	if err := os.WriteFile(filepath.Join(staging, "bin"), []byte(content), 0o755); err != nil {
		t.Fatalf("write staging file: %v", err)
	}
	manifest := `{"package_id":"` + packageID + `","version":"` + version + `",` +
		`"digests":{"bin":"` + hashOf(content) + `"},` +
		`"components":[{"id":"main","type":"app","entry":"bin"}]}`
	return staging, []byte(manifest)
}

func TestInstall_Success(t *testing.T) {
	mod, auth, idReg, aud := newTestInstaller(t)
	root := t.TempDir()
	staging, manifestBytes := newValidStaging(t, root, "com.example.app", "1.0.0")

	entry, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifestBytes,
		StagingDir:    staging,
		Source:        SourceDynamicInstall,
	})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	if entry.Manifest.PackageID != "com.example.app" || entry.ActiveVersion != "1.0.0" {
		t.Fatalf("got entry %+v", entry)
	}
	// 动态安装永远只能拿 Ordinary（架构 §7），即便未来签名验证落地也不改变这点
	if entry.Trust != identity.TrustOrdinary {
		t.Fatalf("Trust = %v, want TrustOrdinary", entry.Trust)
	}

	if len(auth.installed) != 1 {
		t.Fatalf("want exactly one InstallVerifiedPackage call, got %d", len(auth.installed))
	}
	if len(auth.dataDirs) != 1 {
		t.Fatalf("want exactly one CreatePrivateDataDirectory call, got %d", len(auth.dataDirs))
	}
	if len(idReg.replaced) != 1 || len(idReg.replaced[0]) != 1 {
		t.Fatalf("identity projection not pushed correctly: %+v", idReg.replaced)
	}
	if mod.registry.Len() != 1 {
		t.Fatalf("Registry.Len() = %d, want 1", mod.registry.Len())
	}

	// 审计必须记到一次成功
	found := false
	for _, ev := range aud.events {
		if ev.Action == "pkgregistry.Install" && !ev.Denied {
			found = true
		}
	}
	if !found {
		t.Fatalf("want a successful pkgregistry.Install audit event, got %+v", aud.events)
	}
}

func TestInstall_RejectsOnDigestMismatch(t *testing.T) {
	mod, auth, idReg, _ := newTestInstaller(t)
	root := t.TempDir()
	staging, manifestBytes := newValidStaging(t, root, "com.example.app", "1.0.0")

	// 篡改 staging 里的文件内容，使其与 manifest 声明的 digest 不再一致
	if err := os.WriteFile(filepath.Join(staging, "bin"), []byte("tampered"), 0o755); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	_, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifestBytes, StagingDir: staging, Source: SourceDynamicInstall,
	})
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("err = %v, want ErrDigestMismatch", err)
	}
	// digest 复核失败必须在触碰 Authority 之前就短路，不留半成品
	if len(auth.installed) != 0 || len(auth.dataDirs) != 0 {
		t.Fatalf("Authority 不该被调用: installed=%d dataDirs=%d", len(auth.installed), len(auth.dataDirs))
	}
	if len(idReg.replaced) != 0 {
		t.Fatal("identity 不该被更新")
	}
	if mod.registry.Len() != 0 {
		t.Fatal("Registry 不该被更新")
	}
}

func TestInstall_RejectsMalformedManifest(t *testing.T) {
	mod, auth, _, _ := newTestInstaller(t)
	_, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: []byte(`{"package_id":""}`),
		StagingDir:    t.TempDir(),
		Source:        SourceDynamicInstall,
	})
	if !errors.Is(err, ErrEmptyPackageID) {
		t.Fatalf("err = %v, want ErrEmptyPackageID", err)
	}
	if len(auth.installed) != 0 {
		t.Fatal("Authority 不该被调用")
	}
}

func TestInstall_PropagatesAuthorityFailure(t *testing.T) {
	mod, auth, idReg, aud := newTestInstaller(t)
	auth.installErr = errors.New("boom: disk full")

	root := t.TempDir()
	staging, manifestBytes := newValidStaging(t, root, "com.example.app", "1.0.0")

	_, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifestBytes, StagingDir: staging, Source: SourceDynamicInstall,
	})
	if err == nil {
		t.Fatal("want error")
	}
	if mod.registry.Len() != 0 {
		t.Fatal("Authority 失败后不该提交 Registry")
	}
	if len(idReg.replaced) != 0 {
		t.Fatal("Authority 失败后不该更新 identity")
	}

	found := false
	for _, ev := range aud.events {
		if ev.Action == "pkgregistry.Install" && ev.Denied {
			found = true
		}
	}
	if !found {
		t.Fatalf("want a denied pkgregistry.Install audit event, got %+v", aud.events)
	}
}

// Install 必须把 permission.Intersect 的裁决结果（而不是请求权限的直通拷贝）
// 写进 Entry.GrantedPermissions，并把被拒绝的部分记入审计——这是本次改造要
// 补上的、此前被丢弃的那步计算（见 arbitrate.go 顶部注释）
func TestInstall_ComputesGrantedPermissions(t *testing.T) {
	mod, _, _, aud, perm := newTestInstallerWithPerm(t)
	perm.intersect = func(requested []string, _ identity.TrustProfile) (granted, denied []string) {
		return []string{"perm.granted"}, []string{"perm.denied"}
	}

	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatalf("mkdir staging: %v", err)
	}
	content := "#!/bin/true"
	if err := os.WriteFile(filepath.Join(staging, "bin"), []byte(content), 0o755); err != nil {
		t.Fatalf("write staging file: %v", err)
	}
	manifestBytes := []byte(`{"package_id":"com.example.app","version":"1.0.0",` +
		`"digests":{"bin":"` + hashOf(content) + `"},` +
		`"permissions":["perm.granted","perm.denied"],` +
		`"components":[{"id":"main","type":"app","entry":"bin"}]}`)

	entry, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifestBytes, StagingDir: staging, Source: SourceDynamicInstall,
	})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(entry.GrantedPermissions) != 1 || entry.GrantedPermissions[0] != "perm.granted" {
		t.Fatalf("GrantedPermissions = %v, want [perm.granted]", entry.GrantedPermissions)
	}

	found := false
	for _, ev := range aud.events {
		if ev.Action == "pkgregistry.Intersect" && ev.Denied {
			found = true
		}
	}
	if !found {
		t.Fatalf("want a denied pkgregistry.Intersect audit event, got %+v", aud.events)
	}

	if len(perm.replaced) != 1 || len(perm.replaced[0]) != 1 {
		t.Fatalf("permission 投影未被正确推送: %+v", perm.replaced)
	}
	if got := perm.replaced[0][0]; got.PackageID != "com.example.app" || len(got.Permissions) != 1 {
		t.Fatalf("投影内容 = %+v", got)
	}
}

// 同一个 Package 重复安装新版本必须覆盖旧版本，而不是在 Registry 里堆积两条
func TestInstall_UpgradeReplacesOldVersion(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)

	root1 := t.TempDir()
	staging1, manifest1 := newValidStaging(t, root1, "com.example.app", "1.0.0")
	if _, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifest1, StagingDir: staging1, Source: SourceDynamicInstall,
	}); err != nil {
		t.Fatalf("install v1: %v", err)
	}

	root2 := t.TempDir()
	staging2, manifest2 := newValidStaging(t, root2, "com.example.app", "2.0.0")
	if _, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifest2, StagingDir: staging2, Source: SourceDynamicInstall,
	}); err != nil {
		t.Fatalf("install v2: %v", err)
	}

	if mod.registry.Len() != 1 {
		t.Fatalf("Len() = %d, want 1（升级应覆盖，不应堆积）", mod.registry.Len())
	}
	e, ok := mod.registry.Lookup("com.example.app")
	if !ok || e.ActiveVersion != "2.0.0" {
		t.Fatalf("got %+v, want active version 2.0.0", e)
	}
}
