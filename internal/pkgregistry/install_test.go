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
	installErr error
	dataDirErr error
	removeErr  error
	appUserErr error
	installed  []authority.InstallVerifiedPackageRequest
	dataDirs   []authority.CreateDataDirRequest
	removed    []authority.RemovePackageTreeRequest
	appUsers   []authority.EnsureAppUserRequest
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

// ---- 运行前置补齐（provision.go）------------------------------------------

// newProvisionModule 构造一个只为 provision 测试用的 Module。
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

// 动态安装也必须建系统用户。
//
// 这条曾经漏过：install.go 在 PackageInstaller 接口里声明了 EnsureAppUser，
// 却一次都没调，只建了数据目录。装出来的包因此没有 passwd 条目，它的组件
// 第一次启动就 217/USER。
//
// 没有立刻暴露，是因为端到端验证用的 fixture 是 launch_mode: "manual"，
// 没人去启动它。换成 always-on 立刻就炸。
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
		t.Fatalf("EnsureAppUser 调用了 %d 次, want 1", len(auth.appUsers))
	}
	u := auth.appUsers[0]
	if u.UID != entry.UID || u.GID != entry.UID {
		t.Errorf("uid/gid = %d/%d, want %d/%d（GID 恒等于 UID）", u.UID, u.GID, entry.UID, entry.UID)
	}
	if u.Name != authority.AppUserName(entry.UID) {
		t.Errorf("name = %q, want %q", u.Name, authority.AppUserName(entry.UID))
	}
}

// 升级路径【也要】确保用户存在，不能跟数据目录一样只在首次安装时做。
//
// 数据目录是本机状态，建了就一直在；/etc/passwd 则可能被镜像 OTA 换掉、
// 被运维清理，或者这个包本来就是随记账文件从别处恢复过来的。EnsureAppUser
// 幂等，无条件调的成本是一次文件读。
func TestInstall_EnsuresAppUserOnUpgradeToo(t *testing.T) {
	mod, auth, _, _ := newTestInstaller(t)
	root := t.TempDir()

	// 两次安装必须用【同一把开发者密钥】：升级要求签名者是已装版本血统的
	// 后继者，换把新钥匙就是身份劫持，内核会拒（这条判断是对的，别绕过它）。
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
		t.Errorf("EnsureAppUser 调用了 %d 次, want 2（每次安装都确保）", len(auth.appUsers))
	}
	// 数据目录反过来：per-package 不是 per-version，升级不该再建一次，
	// 否则 mkdirat 会 EEXIST 失败、拖垮整条升级。
	if len(auth.dataDirs) != 1 {
		t.Errorf("CreatePrivateDataDirectory 调用了 %d 次, want 1（升级不重建）", len(auth.dataDirs))
	}
}

// 同版本重装必须显式要求 authority 覆盖。
//
// checkUpgrade 明写着「同版本重装（修复损坏安装），允许」，但 authority 默认
// 用 RENAME_NOREPLACE 拒绝一切已存在的目标——不把意图说出口，那条策略就交付
// 不了，装包以裸 renameat2 EEXIST 失败、透给调用方一个 INTERNAL。
func TestInstall_SameVersionAsksToReplace(t *testing.T) {
	mod, auth, _, _ := newTestInstaller(t)
	root := t.TempDir()
	key := newDevKey(t)

	// 首装：绝不能要求覆盖——那会把「重复提交 / 版本号复用」这类错误静默吞掉。
	staging, mb, sig := newValidStagingWithKey(t, root, "com.example.app", "1.0.0", 100, key)
	if _, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: mb, SigBlock: sig, StagingDir: staging, Source: SourceDynamicInstall,
	}); err != nil {
		t.Fatalf("首装: %v", err)
	}
	if auth.installed[0].ReplaceExisting {
		t.Error("首装要求了 ReplaceExisting，这会吞掉重复提交这类错误")
	}

	// 同版本重装：必须要求覆盖。
	staging2, mb2, sig2 := newValidStagingWithKey(t, root, "com.example.app", "1.0.0", 100, key)
	if _, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: mb2, SigBlock: sig2, StagingDir: staging2, Source: SourceDynamicInstall,
	}); err != nil {
		t.Fatalf("重装: %v", err)
	}
	if len(auth.installed) != 2 {
		t.Fatalf("InstallVerifiedPackage 调用了 %d 次, want 2", len(auth.installed))
	}
	if !auth.installed[1].ReplaceExisting {
		t.Error("同版本重装没要求 ReplaceExisting，会以 renameat2 EEXIST 失败")
	}
}

// 升级到【新】版本不该要求覆盖：目标路径是一个全新的版本目录，
// 用覆盖语义等于放弃了 RENAME_NOREPLACE 那道「不静默替换」的保护。
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
			t.Errorf("第 %d 次安装（升级到新版本）要求了 ReplaceExisting", i+1)
		}
	}
}

// 覆盖安装失败时【不能删代码目录】。
//
// 那种场景下 destDir 是这个包唯一的代码目录——旧树在 RENAME_EXCHANGE 时被换出
// 并删掉了。删了就得到「记账说装着 version X、盘上什么都没有」，比不回滚糟得多。
func TestInstall_FailedReplaceKeepsCodeDir(t *testing.T) {
	mod, auth, _, _ := newTestInstaller(t)
	root := t.TempDir()
	key := newDevKey(t)

	staging, mb, sig := newValidStagingWithKey(t, root, "com.example.app", "1.0.0", 100, key)
	if _, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: mb, SigBlock: sig, StagingDir: staging, Source: SourceDynamicInstall,
	}); err != nil {
		t.Fatalf("首装: %v", err)
	}
	auth.removed = nil

	// 让重装在落盘之后失败，触发补偿。
	//
	// 注入点选 EnsureAppUser 而不是 CreatePrivateDataDirectory：后者只在
	// !hadPrev 时调，重装路径上根本不跑，注进去不会触发任何失败。
	auth.appUserErr = errors.New("injected failure after code landed")
	staging2, mb2, sig2 := newValidStagingWithKey(t, root, "com.example.app", "1.0.0", 100, key)
	_, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: mb2, SigBlock: sig2, StagingDir: staging2, Source: SourceDynamicInstall,
	})
	if err == nil {
		t.Fatal("注入了失败但 Install 成功了，补偿路径没被走到")
	}

	for _, r := range auth.removed {
		if r.Root == mod.packageRoot {
			t.Fatalf("覆盖安装失败后删掉了代码目录 %s —— 那是这个包唯一的代码目录", r.Path)
		}
	}
}

func TestProvision_CreatesUserAndDataDir(t *testing.T) {
	// 系统镜像包走 scanSystemImage，那条路径分配 UID、登记 Entry，却从不建
	// 用户也不建数据目录。缺前者 systemd 在 step USER 失败（217/USER），
	// 缺后者在 step NAMESPACE 失败（226/NAMESPACE）——两条都是真实撞到的。
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
		t.Fatalf("EnsureAppUser 调用了 %d 次, want 1", len(auth.appUsers))
	}
	u := auth.appUsers[0]
	if u.UID != 20005 || u.GID != 20005 {
		t.Errorf("uid/gid = %d/%d, want 20005/20005（GID 恒等于 UID）", u.UID, u.GID)
	}
	if u.Name != authority.AppUserName(20005) {
		t.Errorf("name = %q, want %q", u.Name, authority.AppUserName(20005))
	}

	if len(auth.dataDirs) != 1 {
		t.Fatalf("CreatePrivateDataDirectory 调用了 %d 次, want 1", len(auth.dataDirs))
	}
	d := auth.dataDirs[0]
	if d.Perm != 0o700 {
		t.Errorf("perm = %#o, want 0700（私有的定义本身）", d.Perm)
	}
	if d.UID != 20005 {
		t.Errorf("data dir uid = %d, want 20005", d.UID)
	}
}

func TestProvision_IsIdempotent(t *testing.T) {
	// 每次启动扫描都会对每个包跑一遍。数据目录已存在时 authority 回
	// ErrAlreadyExists，那在这里是【正常结果】而不是错误。
	auth := &fakeInstaller{dataDirErr: fmt.Errorf("%w: nervus.example", authority.ErrAlreadyExists)}
	m := newProvisionModule(t, auth)

	e := Entry{Manifest: Manifest{PackageID: "nervus.example"}, UID: 20006}
	if err := m.provisionEntry(context.Background(), e); err != nil {
		t.Fatalf("目录已存在不该算失败: %v", err)
	}
}

func TestProvision_RealDataDirErrorStillFails(t *testing.T) {
	// 只有 ErrAlreadyExists 被容忍。别的错误（权限不足、路径逃逸）必须报出来
	// ——否则一个建不出来的数据目录会被静默吞掉，组件随后在 NAMESPACE 失败，
	// 而日志里看不出根因。
	auth := &fakeInstaller{dataDirErr: errors.New("permission denied")}
	m := newProvisionModule(t, auth)

	e := Entry{Manifest: Manifest{PackageID: "nervus.example"}, UID: 20007}
	if err := m.provisionEntry(context.Background(), e); err == nil {
		t.Fatal("真实的目录创建失败必须报出来")
	}
}

func TestProvisionAll_OneFailureDoesNotBlockOthers(t *testing.T) {
	// 一个包的用户建不出来不该让整机起不来。那个包的组件随后会在 systemd 侧
	// 失败，由 service 的监督链按 criticality 处置——那条路径本来就是为
	// 「组件起不来」准备的。
	auth := &fakeInstaller{appUserErr: errors.New("boom")}
	m := newProvisionModule(t, auth)

	entries := []Entry{
		{Manifest: Manifest{PackageID: "a"}, UID: 20010},
		{Manifest: Manifest{PackageID: "b"}, UID: 20011},
	}
	ok := m.provisionAll(context.Background(), entries)
	if ok != 0 {
		t.Errorf("全部失败时 ok = %d, want 0", ok)
	}
	// 关键：第二个包仍然被尝试过，没有在第一个失败时提前返回
	if len(auth.appUsers) != 2 {
		t.Fatalf("只尝试了 %d 个包，第一个失败不该阻断其余", len(auth.appUsers))
	}
}
