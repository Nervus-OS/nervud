package pkgregistry

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/authority"
	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/permission"
)

func newDevKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate dev key: %v", err)
	}
	return priv
}

func signManifest(t *testing.T, priv ed25519.PrivateKey, manifestBytes []byte) []byte {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	msg := append(append([]byte{}, manifestSigDomain...), manifestBytes...)
	sig := ed25519.Sign(priv, msg)
	sb := SignatureBlock{
		Format: 1,
		Signatures: []Signature{{
			Role: RoleDeveloper, Alg: SigAlgEd25519,
			KeyID: keyIDOf(pub),
			Key:   base64.StdEncoding.EncodeToString(pub),
			Sig:   base64.StdEncoding.EncodeToString(sig),
		}},
	}
	data, err := json.Marshal(sb)
	if err != nil {
		t.Fatalf("marshal sig block: %v", err)
	}
	return data
}

func testABI() string {
	if tok := hostABIToken(); tok != "" {
		return tok
	}
	return ABILinuxX86_64
}

type fakeInstaller struct {
	installErr    error
	dataDirErr    error
	removeErr     error
	appUserErr    error
	userAccessErr error
	installed     []authority.InstallVerifiedPackageRequest
	dataDirs      []authority.CreateDataDirRequest
	removed       []authority.RemovePackageTreeRequest
	appUsers      []authority.EnsureAppUserRequest
	userAccess    []authority.SetUserDataAccessRequest
}

// 卸载必须连带摘掉用户文档区的 ACL 条目, 否则 UID 复用会把写权限白送给新包
func (f *fakeInstaller) SetUserDataAccess(
	_ context.Context, _ authority.Subject, req authority.SetUserDataAccessRequest,
) error {
	f.userAccess = append(f.userAccess, req)
	return f.userAccessErr
}

func (f *fakeInstaller) EnsureAppUser(
	_ context.Context, _ authority.Subject, req authority.EnsureAppUserRequest,
) error {
	f.appUsers = append(f.appUsers, req)
	return f.appUserErr
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

func (f *fakeInstaller) RemovePackageTree(
	_ context.Context, _ authority.Subject, req authority.RemovePackageTreeRequest,
) error {
	f.removed = append(f.removed, req)
	return f.removeErr
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

type fakePermissionArbiter struct {
	intersect   func(requested []string, trust identity.TrustProfile, signerRoles []string) (granted, denied []string)
	intersectAt func(
		definitions *catalog.Snapshot,
		requested []string,
		source catalog.SourceKind,
		trust identity.TrustProfile,
		signers catalog.SignerEvidence,
	) (granted, denied []string)
	replaced [][]permission.Grant
	cleared  []string
	clearErr error

	// runtimeStates 记下每一次 SetRuntimeState, 供安装期同意的断言使用
	runtimeStates []fakeRuntimeGrant
	runtimeErr    error
}

// fakeRuntimeGrant 是一次 SetRuntimeState 调用的记录
type fakeRuntimeGrant struct {
	pkg   string
	perm  string
	state permission.GrantState
}

func (f *fakePermissionArbiter) IntersectAt(
	definitions *catalog.Snapshot,
	requested []string,
	source catalog.SourceKind,
	trust identity.TrustProfile,
	signers catalog.SignerEvidence,
) (granted, denied []string) {
	if f.intersectAt != nil {
		return f.intersectAt(definitions, requested, source, trust, signers)
	}
	if f.intersect != nil {
		return f.intersect(requested, trust, signers.Roles)
	}
	return requested, nil
}

func (f *fakePermissionArbiter) Replace(grants []permission.Grant) error {
	f.replaced = append(f.replaced, grants)
	return nil
}

func (f *fakePermissionArbiter) ClearPackage(pkg string) error {
	f.cleared = append(f.cleared, pkg)
	return f.clearErr
}

func (f *fakePermissionArbiter) SetRuntimeState(
	pkg, permissionID string, state permission.GrantState,
) error {
	f.runtimeStates = append(f.runtimeStates,
		fakeRuntimeGrant{pkg: pkg, perm: permissionID, state: state})
	return f.runtimeErr
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
	definitions, err := catalog.NewDefaultRegistry()
	if err != nil {
		t.Fatalf("new catalog: %v", err)
	}
	mod := New(auth, idReg, perm, registry, definitions, TrustStore{}, aud, nil,
		filepath.Join(dir, "registry"), filepath.Join(dir, "system-packages"),
		filepath.Join(dir, "packages"), filepath.Join(dir, "data"))
	return mod, auth, idReg, aud, perm
}

func newValidStaging(t *testing.T, root, packageID, version string) (string, []byte, []byte) {
	t.Helper()
	return newValidStagingWithKey(t, root, packageID, version, 100, newDevKey(t))
}

func newValidStagingWithKey(
	t *testing.T, root, packageID, version string, versionCode uint64, priv ed25519.PrivateKey,
) (string, []byte, []byte) {
	t.Helper()
	staging := filepath.Join(root, "staging")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatalf("mkdir staging: %v", err)
	}
	content := "#!/bin/true"
	if err := os.WriteFile(filepath.Join(staging, "bin"), []byte(content), 0o755); err != nil {
		t.Fatalf("write staging file: %v", err)
	}
	manifest := fmt.Sprintf(`{"schema":1,"package_id":%q,"version":%q,"version_code":%d,`+
		`"min_nervus_api":1,"target_nervus_api":1,"supported_abis":[%q],`+
		`"digests":{"bin":%q},`+
		`"components":[{"id":"main","type":"app","entry":"bin","runtime":"native","launch_mode":"manual"}]}`,
		packageID, version, versionCode, testABI(), hashOf(content))
	mb := []byte(manifest)
	sig := signManifest(t, priv, mb)
	writeStagingMetadata(t, staging, mb, sig)
	return staging, mb, sig
}

func writeStagingMetadata(t *testing.T, staging string, manifestBytes, sig []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(staging, ManifestFileName), manifestBytes, 0o644); err != nil {
		t.Fatalf("write staging manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(staging, SignatureFileName), sig, 0o644); err != nil {
		t.Fatalf("write staging sig: %v", err)
	}
}

// 安装期同意测试用到的三条内核 bootstrap 权限. 各代表一类判据:
//
//	permStorageUser   USER_CONSENT - 有运行期状态, 是同意能作用的唯一一档
//	permPkgQuery      NORMAL       - 装上即生效, 没有运行期状态
//	permMotionControl USER_CONSENT - 但测试里不申请它, 用来验证"不在授予集合里"
const (
	permStorageUser   = "perm.storage.user"
	permPkgQuery      = "perm.pkg.query"
	permMotionControl = "perm.motion.control"
)

// newStagingWithPermissions 造一个声明了 permissions 的 staging.
//
// fakePermissionArbiter 的默认 IntersectAt 原样批准全部请求, 因此 requested
// 就是最终的 GrantedPermissions - 这正是要的: 本组测试关心的是同意清单怎么被
// 裁剪, 不是安装期裁决本身
func newStagingWithPermissions(
	t *testing.T, root, packageID string, permissions []string,
) (string, []byte, []byte) {
	t.Helper()
	staging := filepath.Join(root, "staging")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatalf("mkdir staging: %v", err)
	}
	content := "#!/bin/true"
	if err := os.WriteFile(filepath.Join(staging, "bin"), []byte(content), 0o755); err != nil {
		t.Fatalf("write staging file: %v", err)
	}
	quoted := make([]string, 0, len(permissions))
	for _, p := range permissions {
		quoted = append(quoted, fmt.Sprintf("%q", p))
	}
	manifest := fmt.Sprintf(`{"schema":1,"package_id":%q,"version":"1.0.0","version_code":1,`+
		`"min_nervus_api":1,"target_nervus_api":1,"supported_abis":[%q],`+
		`"digests":{"bin":%q},"permissions":[%s],`+
		`"components":[{"id":"main","type":"app","entry":"bin","runtime":"native","launch_mode":"manual"}]}`,
		packageID, testABI(), hashOf(content), strings.Join(quoted, ","))
	mb := []byte(manifest)
	sig := signManifest(t, newDevKey(t), mb)
	writeStagingMetadata(t, staging, mb, sig)
	return staging, mb, sig
}

// TestInstallConsent_OnlyUserConsentInsideInstallSet 钉住安装期同意的裁剪判据.
//
// 确认屏递进来的清单是【上限而不是授权依据】: 只有同时满足"在安装期授予集合里"
// 与"是 USER_CONSENT 这一档"的那些才落库. 少了任一条, 一个夸大的清单就能让包
// 拿到没被裁决批准的权限, 或者给 NORMAL 权限写进一个它根本没有的运行期状态
func TestInstallConsent_OnlyUserConsentInsideInstallSet(t *testing.T) {
	mod, _, _, _, perm := newTestInstallerWithPerm(t)
	root := t.TempDir()

	// 只申请这两条: 一条 USER_CONSENT, 一条 NORMAL
	staging, manifestBytes, sig := newStagingWithPermissions(
		t, root, "com.example.consent", []string{permStorageUser, permPkgQuery})

	if _, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifestBytes,
		SigBlock:      sig,
		StagingDir:    staging,
		Source:        SourceDynamicInstall,
		ConsentedPermissions: []string{
			permStorageUser,   // 该落: USER_CONSENT 且在授予集合里
			permPkgQuery,      // 不该落: NORMAL 没有运行期状态这回事
			permMotionControl, // 不该落: 压根没申请, 不在授予集合里
		},
	}); err != nil {
		t.Fatalf("Install: %v", err)
	}

	if len(perm.runtimeStates) != 1 {
		t.Fatalf("SetRuntimeState calls = %+v, want exactly 1", perm.runtimeStates)
	}
	got := perm.runtimeStates[0]
	if got.pkg != "com.example.consent" || got.perm != permStorageUser {
		t.Fatalf("granted %s/%s, want com.example.consent/%s", got.pkg, got.perm, permStorageUser)
	}
	if got.state != permission.GrantStateGranted {
		t.Fatalf("state = %v, want Granted", got.state)
	}
}

// TestInstallConsent_EmptyConsentGrantsNothing: 没有同意任何权限时装包照常成功,
// 只是一条运行期授予都不落. 用户之后仍可以在设置里补上
func TestInstallConsent_EmptyConsentGrantsNothing(t *testing.T) {
	mod, _, _, _, perm := newTestInstallerWithPerm(t)
	root := t.TempDir()
	staging, manifestBytes, sig := newStagingWithPermissions(
		t, root, "com.example.noconsent", []string{permStorageUser})

	if _, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifestBytes,
		SigBlock:      sig,
		StagingDir:    staging,
		Source:        SourceDynamicInstall,
	}); err != nil {
		t.Fatalf("Install: %v", err)
	}

	if len(perm.runtimeStates) != 0 {
		t.Fatalf("SetRuntimeState calls = %+v, want none", perm.runtimeStates)
	}
}

func TestInstall_Success(t *testing.T) {
	mod, auth, idReg, aud := newTestInstaller(t)
	root := t.TempDir()
	staging, manifestBytes, sig := newValidStaging(t, root, "com.example.app", "1.0.0")

	entry, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifestBytes,
		SigBlock:      sig,
		StagingDir:    staging,
		Source:        SourceDynamicInstall,
	})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	if entry.Manifest.PackageID != "com.example.app" || entry.ActiveVersion != "1.0.0" {
		t.Fatalf("got entry %+v", entry)
	}
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
	staging, manifestBytes, sig := newValidStaging(t, root, "com.example.app", "1.0.0")

	if err := os.WriteFile(filepath.Join(staging, "bin"), []byte("tampered"), 0o755); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	_, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifestBytes, SigBlock: sig, StagingDir: staging, Source: SourceDynamicInstall,
	})
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("err = %v, want ErrDigestMismatch", err)
	}
	if len(auth.installed) != 0 || len(auth.dataDirs) != 0 {
		t.Fatalf("Authority should not be called: installed=%d dataDirs=%d", len(auth.installed), len(auth.dataDirs))
	}
	if len(idReg.replaced) != 0 {
		t.Fatal("identity should not be updated")
	}
	if mod.registry.Len() != 0 {
		t.Fatal("Registry should not be updated")
	}
}

func TestInstall_RejectsMalformedManifest(t *testing.T) {
	mod, auth, _, _ := newTestInstaller(t)
	_, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: []byte(`{"schema":1,"package_id":""}`),
		StagingDir:    t.TempDir(),
		Source:        SourceDynamicInstall,
	})
	if !errors.Is(err, ErrEmptyPackageID) {
		t.Fatalf("err = %v, want ErrEmptyPackageID", err)
	}
	if len(auth.installed) != 0 {
		t.Fatal("Authority should not be called")
	}
}

func TestInstall_PropagatesAuthorityFailure(t *testing.T) {
	mod, auth, idReg, aud := newTestInstaller(t)
	auth.installErr = errors.New("boom: disk full")

	root := t.TempDir()
	staging, manifestBytes, sig := newValidStaging(t, root, "com.example.app", "1.0.0")

	_, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifestBytes, SigBlock: sig, StagingDir: staging, Source: SourceDynamicInstall,
	})
	if err == nil {
		t.Fatal("want error")
	}
	if mod.registry.Len() != 0 {
		t.Fatal("Registry should not be committed after an Authority failure")
	}
	if len(idReg.replaced) != 0 {
		t.Fatal("identity should not be updated after an Authority failure")
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

func TestInstall_ComputesGrantedPermissions(t *testing.T) {
	mod, _, _, aud, perm := newTestInstallerWithPerm(t)
	perm.intersect = func(requested []string, _ identity.TrustProfile, _ []string) (granted, denied []string) {
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
	manifestBytes := []byte(fmt.Sprintf(`{"schema":1,"package_id":"com.example.app","version":"1.0.0",`+
		`"version_code":100,"min_nervus_api":1,"target_nervus_api":1,"supported_abis":[%q],`+
		`"digests":{"bin":%q},`+
		`"permissions":["perm.granted","perm.denied"],`+
		`"components":[{"id":"main","type":"app","entry":"bin","runtime":"native","launch_mode":"manual"}]}`,
		testABI(), hashOf(content)))
	sig := signManifest(t, newDevKey(t), manifestBytes)
	writeStagingMetadata(t, staging, manifestBytes, sig)

	entry, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifestBytes, SigBlock: sig, StagingDir: staging, Source: SourceDynamicInstall,
	})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(entry.GrantedPermissions) != 1 || entry.GrantedPermissions[0] != "perm.granted" {
		t.Fatalf("GrantedPermissions = %v, want [perm.granted]", entry.GrantedPermissions)
	}

	found := false
	for _, ev := range aud.events {
		if ev.Action == "pkgregistry.IntersectAt" && ev.Denied {
			found = true
		}
	}
	if !found {
		t.Fatalf("want a denied pkgregistry.IntersectAt audit event, got %+v", aud.events)
	}

	if len(perm.replaced) != 1 || len(perm.replaced[0]) != 1 {
		t.Fatalf("permission projection was not published correctly: %+v", perm.replaced)
	}
	if got := perm.replaced[0][0]; got.PackageID != "com.example.app" || len(got.Permissions) != 1 {
		t.Fatalf("projection content = %+v", got)
	}
}

func TestInstall_UpgradeReplacesOldVersion(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	key := newDevKey(t)

	root1 := t.TempDir()
	staging1, manifest1, sig1 := newValidStagingWithKey(t, root1, "com.example.app", "1.0.0", 100, key)
	if _, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifest1, SigBlock: sig1, StagingDir: staging1, Source: SourceDynamicInstall,
	}); err != nil {
		t.Fatalf("install v1: %v", err)
	}

	root2 := t.TempDir()
	staging2, manifest2, sig2 := newValidStagingWithKey(t, root2, "com.example.app", "2.0.0", 200, key)
	if _, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifest2, SigBlock: sig2, StagingDir: staging2, Source: SourceDynamicInstall,
	}); err != nil {
		t.Fatalf("install v2: %v", err)
	}

	if mod.registry.Len() != 1 {
		t.Fatalf("Len() = %d, want 1 because an upgrade should replace rather than accumulate", mod.registry.Len())
	}
	e, ok := mod.registry.Lookup("com.example.app")
	if !ok || e.ActiveVersion != "2.0.0" || e.VersionCode != 200 {
		t.Fatalf("got %+v, want active version 2.0.0 code 200", e)
	}
}

func newProvisionModule(t *testing.T, auth *fakeInstaller) *Module {
	t.Helper()
	dir := t.TempDir()
	definitions, err := catalog.NewDefaultRegistry()
	if err != nil {
		t.Fatalf("new catalog: %v", err)
	}
	return New(auth, &fakeIdentityUpdater{}, &fakePermissionArbiter{}, NewRegistry(),
		definitions, TrustStore{}, &fakeAuditor{}, nil,
		filepath.Join(dir, "registry"), filepath.Join(dir, "system-packages"),
		filepath.Join(dir, "packages"), filepath.Join(dir, "data"))
}

//

//

func TestInstall_EnsuresAppUser(t *testing.T) {
	mod, auth, _, _ := newTestInstaller(t)
	root := t.TempDir()
	staging, manifestBytes, sig := newValidStaging(t, root, "com.example.app", "1.0.0")

	entry, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifestBytes,
		SigBlock:      sig,
		StagingDir:    staging,
		Source:        SourceDynamicInstall,
	})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	if len(auth.appUsers) != 1 {
		t.Fatalf("unexpected package registry result; EnsureAppUser %d, want 1", len(auth.appUsers))
	}
	u := auth.appUsers[0]
	if u.UID != entry.UID || u.GID != entry.UID {
		t.Errorf("unexpected package registry result; uid/gid = %d/%d, want %d/%d GID UID", u.UID, u.GID, entry.UID, entry.UID)
	}
	if u.Name != authority.AppUserName(entry.UID) {
		t.Errorf("name = %q, want %q", u.Name, authority.AppUserName(entry.UID))
	}
}

//

func TestInstall_EnsuresAppUserOnUpgradeToo(t *testing.T) {
	mod, auth, _, _ := newTestInstaller(t)
	root := t.TempDir()

	key := newDevKey(t)
	for i, ver := range []string{"1.0.0", "1.0.1"} {
		staging, manifestBytes, sig := newValidStagingWithKey(
			t, root, "com.example.app", ver, uint64(100+i), key)
		if _, err := mod.Install(context.Background(), InstallTransaction{
			ManifestBytes: manifestBytes,
			SigBlock:      sig,
			StagingDir:    staging,
			Source:        SourceDynamicInstall,
		}); err != nil {
			t.Fatalf("Install %s: %v", ver, err)
		}
	}

	if len(auth.appUsers) != 2 {
		t.Errorf("unexpected package registry result; EnsureAppUser %d, want 2", len(auth.appUsers))
	}

	if len(auth.dataDirs) != 1 {
		t.Errorf("unexpected package registry result; CreatePrivateDataDirectory %d, want 1", len(auth.dataDirs))
	}
}

//

func TestInstall_SameVersionAsksToReplace(t *testing.T) {
	mod, auth, _, _ := newTestInstaller(t)
	root := t.TempDir()
	key := newDevKey(t)

	staging, mb, sig := newValidStagingWithKey(t, root, "com.example.app", "1.0.0", 100, key)
	if _, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: mb, SigBlock: sig, StagingDir: staging, Source: SourceDynamicInstall,
	}); err != nil {
		t.Fatalf("unexpected package registry result; value = %v", err)
	}
	if auth.installed[0].ReplaceExisting {
		t.Error("unexpected package registry result; ReplaceExisting")
	}

	staging2, mb2, sig2 := newValidStagingWithKey(t, root, "com.example.app", "1.0.0", 100, key)
	if _, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: mb2, SigBlock: sig2, StagingDir: staging2, Source: SourceDynamicInstall,
	}); err != nil {
		t.Fatalf("unexpected package registry result; value = %v", err)
	}
	if len(auth.installed) != 2 {
		t.Fatalf("unexpected package registry result; InstallVerifiedPackage %d, want 2", len(auth.installed))
	}
	if !auth.installed[1].ReplaceExisting {
		t.Error("unexpected package registry result; ReplaceExisting renameat2 EEXIST")
	}
}

func TestInstall_UpgradeDoesNotAskToReplace(t *testing.T) {
	mod, auth, _, _ := newTestInstaller(t)
	root := t.TempDir()
	key := newDevKey(t)

	for i, ver := range []string{"1.0.0", "1.0.1"} {
		staging, mb, sig := newValidStagingWithKey(t, root, "com.example.app", ver, uint64(100+i), key)
		if _, err := mod.Install(context.Background(), InstallTransaction{
			ManifestBytes: mb, SigBlock: sig, StagingDir: staging, Source: SourceDynamicInstall,
		}); err != nil {
			t.Fatalf("Install %s: %v", ver, err)
		}
	}
	for i, req := range auth.installed {
		if req.ReplaceExisting {
			t.Errorf("unexpected package registry result; value = %d ReplaceExisting", i+1)
		}
	}
}

//

func TestInstall_FailedReplaceKeepsCodeDir(t *testing.T) {
	mod, auth, _, _ := newTestInstaller(t)
	root := t.TempDir()
	key := newDevKey(t)

	staging, mb, sig := newValidStagingWithKey(t, root, "com.example.app", "1.0.0", 100, key)
	if _, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: mb, SigBlock: sig, StagingDir: staging, Source: SourceDynamicInstall,
	}); err != nil {
		t.Fatalf("unexpected package registry result; value = %v", err)
	}
	auth.removed = nil

	//

	auth.appUserErr = errors.New("injected failure after code landed")
	staging2, mb2, sig2 := newValidStagingWithKey(t, root, "com.example.app", "1.0.0", 100, key)
	_, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: mb2, SigBlock: sig2, StagingDir: staging2, Source: SourceDynamicInstall,
	})
	if err == nil {
		t.Fatal("unexpected package registry result; Install")
	}

	for _, r := range auth.removed {
		if r.Root == mod.packageRoot {
			t.Fatalf("unexpected package registry result; value = %s", r.Path)
		}
	}
}

func TestProvision_CreatesUserAndDataDir(t *testing.T) {

	auth := &fakeInstaller{}
	m := newProvisionModule(t, auth)

	e := Entry{
		Manifest: Manifest{PackageID: "nervus.example"},
		UID:      20005,
		Source:   SourceSystemImage,
	}
	if err := m.provisionEntry(context.Background(), e); err != nil {
		t.Fatalf("provisionEntry: %v", err)
	}

	if len(auth.appUsers) != 1 {
		t.Fatalf("unexpected package registry result; EnsureAppUser %d, want 1", len(auth.appUsers))
	}
	u := auth.appUsers[0]
	if u.UID != 20005 || u.GID != 20005 {
		t.Errorf("unexpected package registry result; uid/gid = %d/%d, want 20005/20005 GID UID", u.UID, u.GID)
	}
	if u.Name != authority.AppUserName(20005) {
		t.Errorf("name = %q, want %q", u.Name, authority.AppUserName(20005))
	}

	if len(auth.dataDirs) != 1 {
		t.Fatalf("unexpected package registry result; CreatePrivateDataDirectory %d, want 1", len(auth.dataDirs))
	}
	d := auth.dataDirs[0]
	if d.Perm != 0o700 {
		t.Errorf("unexpected package registry result; perm = %#o, want 0700", d.Perm)
	}
	if d.UID != 20005 {
		t.Errorf("data dir uid = %d, want 20005", d.UID)
	}
}

func TestProvision_IsIdempotent(t *testing.T) {

	auth := &fakeInstaller{dataDirErr: fmt.Errorf("%w: nervus.example", authority.ErrAlreadyExists)}
	m := newProvisionModule(t, auth)

	e := Entry{Manifest: Manifest{PackageID: "nervus.example"}, UID: 20006}
	if err := m.provisionEntry(context.Background(), e); err != nil {
		t.Fatalf("unexpected package registry result; value = %v", err)
	}
}

func TestProvision_RealDataDirErrorStillFails(t *testing.T) {

	auth := &fakeInstaller{dataDirErr: errors.New("permission denied")}
	m := newProvisionModule(t, auth)

	e := Entry{Manifest: Manifest{PackageID: "nervus.example"}, UID: 20007}
	if err := m.provisionEntry(context.Background(), e); err == nil {
		t.Fatal("unexpected package registry result")
	}
}

func TestProvisionAll_OneFailureDoesNotBlockOthers(t *testing.T) {

	auth := &fakeInstaller{appUserErr: errors.New("boom")}
	m := newProvisionModule(t, auth)

	entries := []Entry{
		{Manifest: Manifest{PackageID: "a"}, UID: 20010},
		{Manifest: Manifest{PackageID: "b"}, UID: 20011},
	}
	ok := m.provisionAll(context.Background(), entries)
	if ok != 0 {
		t.Errorf("unexpected package registry result; ok = %d, want 0", ok)
	}

	if len(auth.appUsers) != 2 {
		t.Fatalf("unexpected package registry result; value = %d", len(auth.appUsers))
	}
}
