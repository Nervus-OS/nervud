package pkgregistry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nervus-os/nervud/internal/identity"
)

// 本文件锁住外部审核指出的合并阻塞项修复（§P0/§P1）。

// P1 #5：Install 只接受动态来源，调用方传 SourceSystemImage 必须被拒
func TestInstall_RejectsSystemImageSource(t *testing.T) {
	mod, auth, _, _ := newTestInstaller(t)
	staging, mb, sig := newValidStaging(t, t.TempDir(), "com.example.app", "1.0.0")
	_, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: mb, SigBlock: sig, StagingDir: staging, Source: SourceSystemImage,
	})
	if !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("Install with SourceSystemImage must be rejected, got %v", err)
	}
	if len(auth.installed) != 0 {
		t.Fatal("Authority 不该被调用")
	}
}

// P1 #5：动态安装不得占用系统镜像包的 package_id
func TestInstall_RejectsShadowingSystemPackage(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	// 先在 Registry 里放一个系统镜像包（模拟 scanSystemImage 的产物）
	if err := mod.registry.Replace([]Entry{{
		Manifest:      Manifest{PackageID: "com.example.app", Version: "1.0.0"},
		ActiveVersion: "1.0.0", VersionCode: 100, UID: 20001,
		Trust: identity.TrustPlatform, Source: SourceSystemImage,
	}}); err != nil {
		t.Fatalf("seed system pkg: %v", err)
	}
	staging, mb, sig := newValidStaging(t, t.TempDir(), "com.example.app", "2.0.0")
	_, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: mb, SigBlock: sig, StagingDir: staging, Source: SourceDynamicInstall,
	})
	if !errors.Is(err, ErrSystemPackageImmutable) {
		t.Fatalf("dynamic install shadowing system pkg must be rejected, got %v", err)
	}
}

// P0 #3：staging 里的 manifest.json 与验签字节不一致（验签 A、落盘 B）必须被拒
func TestInstall_RejectsStagingManifestMismatch(t *testing.T) {
	mod, auth, _, _ := newTestInstaller(t)
	staging, mb, sig := newValidStaging(t, t.TempDir(), "com.example.app", "1.0.0")
	// 把 staging 里的 manifest.json 换成另一份（tx.ManifestBytes 仍是验过签的 mb）
	tampered := append([]byte(nil), mb...)
	tampered[len(tampered)-1] = ' ' // 破坏最后一个字节，破坏逐字节一致
	if err := os.WriteFile(filepath.Join(staging, ManifestFileName), tampered, 0o644); err != nil {
		t.Fatalf("tamper staging manifest: %v", err)
	}
	_, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: mb, SigBlock: sig, StagingDir: staging, Source: SourceDynamicInstall,
	})
	if !errors.Is(err, ErrStagingMetadataMismatch) {
		t.Fatalf("staging manifest mismatch must be rejected, got %v", err)
	}
	if len(auth.installed) != 0 {
		t.Fatal("Authority 不该被调用")
	}
}

// P1 #6：升级后必须通知 Service 切到新版本（ReloadPackage），否则旧版本继续跑
func TestInstall_UpgradeTriggersReload(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	stopper := &fakeStopper{}
	mod.SetLifecycleHooks(stopper, nil)
	key := newDevKey(t)

	s1, m1, sig1 := newValidStagingWithKey(t, t.TempDir(), "com.example.app", "1.0.0", 100, key)
	if _, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: m1, SigBlock: sig1, StagingDir: s1, Source: SourceDynamicInstall,
	}); err != nil {
		t.Fatalf("install v1: %v", err)
	}
	// 全新安装不该 reload
	if len(stopper.reloaded) != 0 {
		t.Fatalf("fresh install must not reload: %+v", stopper.reloaded)
	}

	s2, m2, sig2 := newValidStagingWithKey(t, t.TempDir(), "com.example.app", "2.0.0", 200, key)
	if _, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: m2, SigBlock: sig2, StagingDir: s2, Source: SourceDynamicInstall,
	}); err != nil {
		t.Fatalf("upgrade v2: %v", err)
	}
	// 升级必须 reload，让旧版本停、新版本起
	if len(stopper.reloaded) != 1 || stopper.reloaded[0] != "com.example.app" {
		t.Fatalf("upgrade must reload package: %+v", stopper.reloaded)
	}
}

// P1 #7：卸载必须清运行期权限授予（否则同 ID 重装继承旧危险授权）
func TestUninstall_ClearsRuntimeGrants(t *testing.T) {
	mod, _, _, _, perm := newTestInstallerWithPerm(t)
	mod.SetLifecycleHooks(&fakeStopper{}, nil)
	installOne(t, mod, "com.example.app")

	if err := mod.Uninstall(context.Background(), "com.example.app"); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	found := false
	for _, p := range perm.cleared {
		if p == "com.example.app" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Uninstall must clear runtime grants: cleared=%+v", perm.cleared)
	}
}
