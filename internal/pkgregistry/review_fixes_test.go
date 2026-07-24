package pkgregistry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nervus-os/nervud/internal/identity"
)

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
		t.Fatal("Authority should not be called")
	}
}

func TestInstall_RejectsShadowingSystemPackage(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
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

func TestInstall_RejectsStagingManifestMismatch(t *testing.T) {
	mod, auth, _, _ := newTestInstaller(t)
	staging, mb, sig := newValidStaging(t, t.TempDir(), "com.example.app", "1.0.0")
	tampered := append([]byte(nil), mb...)
	tampered[len(tampered)-1] = ' '
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
		t.Fatal("Authority should not be called")
	}
}

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
	if len(stopper.reloaded) != 0 {
		t.Fatalf("fresh install must not reload: %+v", stopper.reloaded)
	}

	s2, m2, sig2 := newValidStagingWithKey(t, t.TempDir(), "com.example.app", "2.0.0", 200, key)
	if _, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: m2, SigBlock: sig2, StagingDir: s2, Source: SourceDynamicInstall,
	}); err != nil {
		t.Fatalf("upgrade v2: %v", err)
	}
	if len(stopper.reloaded) != 1 || stopper.reloaded[0] != "com.example.app" {
		t.Fatalf("upgrade must reload package: %+v", stopper.reloaded)
	}
}

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
