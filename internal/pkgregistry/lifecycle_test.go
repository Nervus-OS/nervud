package pkgregistry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/identity"
)

type fakeStopper struct {
	stopped   []string
	reloaded  []string
	stopErr   error
	reloadErr error
}

type fakeTransferRevoker struct {
	packages  []string
	resources []catalog.RevokedResource
}

func (f *fakeTransferRevoker) RevokePackage(packageID string) {
	f.packages = append(f.packages, packageID)
}

func (f *fakeTransferRevoker) RevokeResource(resourceHandle string, generation uint64) {
	f.resources = append(f.resources, catalog.RevokedResource{
		Handle: resourceHandle, Generation: generation,
	})
}

func (f *fakeStopper) StopComponent(_ context.Context, pkg, comp string) error {
	f.stopped = append(f.stopped, pkg+"/"+comp)
	return f.stopErr
}

func (f *fakeStopper) ReloadPackage(_ context.Context, pkg string) error {
	f.reloaded = append(f.reloaded, pkg)
	return f.reloadErr
}

func installOne(t *testing.T, mod *Module, pkgID string) Entry {
	t.Helper()
	staging, mb, sig := newValidStaging(t, t.TempDir(), pkgID, "1.0.0")
	e, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: mb, SigBlock: sig, StagingDir: staging, Source: SourceDynamicInstall,
	})
	if err != nil {
		t.Fatalf("install %s: %v", pkgID, err)
	}
	return e
}

func TestUninstall_RemovesEverything(t *testing.T) {
	mod, auth, idReg, _ := newTestInstaller(t)
	stopper := &fakeStopper{}
	transferRevoker := &fakeTransferRevoker{}
	mod.SetLifecycleHooks(stopper, nil)
	mod.SetTransferRevoker(transferRevoker)

	e := installOne(t, mod, "com.example.app")
	if mod.registry.Len() != 1 {
		t.Fatalf("expected 1 installed, got %d", mod.registry.Len())
	}

	if err := mod.Uninstall(context.Background(), "com.example.app"); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	if mod.registry.Len() != 0 {
		t.Fatalf("registry not cleared: %d", mod.registry.Len())
	}
	if len(stopper.stopped) != 1 || stopper.stopped[0] != "com.example.app/main" {
		t.Fatalf("component not stopped: %+v", stopper.stopped)
	}
	if len(transferRevoker.packages) != 1 ||
		transferRevoker.packages[0] != "com.example.app" {
		t.Fatalf("transfer sessions not revoked: %+v", transferRevoker.packages)
	}
	var rmCode, rmData bool
	for _, r := range auth.removed {
		if r.Root == mod.packageRoot && r.Path == filepath.Join(mod.packageRoot, "com.example.app") {
			rmCode = true
		}
		if r.Root == mod.dataRoot && r.Path == filepath.Join(mod.dataRoot, "com.example.app") {
			rmData = true
		}
	}
	if !rmCode || !rmData {
		t.Fatalf("code/data not removed: %+v", auth.removed)
	}
	sp, _ := stateFilePath(mod.stateDir, "com.example.app")
	if _, err := os.Stat(sp); !os.IsNotExist(err) {
		t.Fatalf("ledger not removed: %v", err)
	}
	last := idReg.replaced[len(idReg.replaced)-1]
	if len(last) != 0 {
		t.Fatalf("identity projection not empty after uninstall: %+v", last)
	}
	_ = e
}

func TestUninstall_UIDNotReused(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	mod.SetLifecycleHooks(&fakeStopper{}, nil)

	e1 := installOne(t, mod, "com.example.app")
	if err := mod.Uninstall(context.Background(), "com.example.app"); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	e2 := installOne(t, mod, "com.example.app")
	if e2.UID == e1.UID {
		t.Fatalf("UID reused after uninstall: both %d", e1.UID)
	}
	if e2.UID < e1.UID {
		t.Fatalf("UID went backwards: %d -> %d", e1.UID, e2.UID)
	}
}

func TestUninstall_FailureLeavesFailClosedRetryableTombstone(t *testing.T) {
	mod, auth, idReg, _, perm := newTestInstallerWithPerm(t)
	stopper := &fakeStopper{}
	mod.SetLifecycleHooks(stopper, nil)
	installOne(t, mod, "com.example.app")

	auth.removeErr = errors.New("storage unavailable")
	err := mod.Uninstall(context.Background(), "com.example.app")
	if err == nil {
		t.Fatal("Uninstall succeeded despite filesystem cleanup failure")
	}
	if mod.registry.Len() != 0 {
		t.Fatalf("pending removal remained active in Registry: %d", mod.registry.Len())
	}
	state, ok := mod.readState("com.example.app")
	if !ok || !state.RemovalPending || len(state.RemovalComponents) != 1 ||
		state.RemovalComponents[0] != "main" {
		t.Fatalf("removal tombstone = %+v, ok=%v", state, ok)
	}
	if last := idReg.replaced[len(idReg.replaced)-1]; len(last) != 0 {
		t.Fatalf("identity remained published after failed cleanup: %+v", last)
	}
	if last := perm.replaced[len(perm.replaced)-1]; len(last) != 0 {
		t.Fatalf("permissions remained published after failed cleanup: %+v", last)
	}
	if err := mod.SetComponentEnabled(
		context.Background(), "com.example.app", "main", true,
	); !errors.Is(err, ErrPackageNotInstalled) {
		t.Fatalf("pending package was lifecycle-addressable: %v", err)
	}

	staging, manifest, sig := newValidStaging(
		t, t.TempDir(), "com.example.app", "1.0.0")
	_, err = mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: manifest,
		SigBlock:      sig,
		StagingDir:    staging,
		Source:        SourceDynamicInstall,
	})
	if !errors.Is(err, ErrPackageRemovalPending) {
		t.Fatalf("install over tombstone error = %v, want ErrPackageRemovalPending", err)
	}

	auth.removeErr = nil
	if err := mod.Uninstall(context.Background(), "com.example.app"); err != nil {
		t.Fatalf("retry Uninstall: %v", err)
	}
	statePath, _ := stateFilePath(mod.stateDir, "com.example.app")
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("tombstone remained after successful retry: %v", err)
	}
}

func TestUninstall_ClearGrantFailureDefersFilesystemDeletion(t *testing.T) {
	mod, auth, _, _, perm := newTestInstallerWithPerm(t)
	mod.SetLifecycleHooks(&fakeStopper{}, nil)
	installOne(t, mod, "com.example.app")

	perm.clearErr = errors.New("grant ledger unavailable")
	if err := mod.Uninstall(context.Background(), "com.example.app"); err == nil {
		t.Fatal("Uninstall succeeded despite runtime-grant cleanup failure")
	}
	if len(auth.removed) != 0 {
		t.Fatalf("filesystem deletion ran before grant cleanup succeeded: %+v", auth.removed)
	}
	state, ok := mod.readState("com.example.app")
	if !ok || !state.RemovalPending {
		t.Fatalf("missing removal tombstone after grant failure: %+v, ok=%v", state, ok)
	}

	perm.clearErr = nil
	if err := mod.Uninstall(context.Background(), "com.example.app"); err != nil {
		t.Fatalf("retry Uninstall: %v", err)
	}
	if len(auth.removed) != 2 {
		t.Fatalf("retry did not delete code and data: %+v", auth.removed)
	}
}

func TestUninstall_UnknownPackage(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	if err := mod.Uninstall(context.Background(), "com.nope"); !errors.Is(err, ErrPackageNotInstalled) {
		t.Fatalf("want ErrPackageNotInstalled, got %v", err)
	}
}

func TestSetComponentEnabled_OrdinaryDisableAndReenable(t *testing.T) {
	mod, _, _, _ := newTestInstaller(t)
	stopper := &fakeStopper{}
	mod.SetLifecycleHooks(stopper, nil)
	installOne(t, mod, "com.example.app")

	if err := mod.SetComponentEnabled(context.Background(), "com.example.app", "main", false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	e, _ := mod.registry.Lookup("com.example.app")
	if !e.ComponentDisabled("main") {
		t.Fatal("component should be disabled")
	}
	if len(stopper.stopped) != 1 {
		t.Fatalf("disable should stop the instance: %+v", stopper.stopped)
	}
	st, _ := mod.readState("com.example.app")
	if len(st.DisabledComponents) != 1 || st.DisabledComponents[0] != "main" {
		t.Fatalf("disabled not persisted: %+v", st.DisabledComponents)
	}

	if err := mod.SetComponentEnabled(context.Background(), "com.example.app", "main", true); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	e, _ = mod.registry.Lookup("com.example.app")
	if e.ComponentDisabled("main") {
		t.Fatal("component should be re-enabled")
	}
}

func TestCanDisable_ProtectedAndSystem(t *testing.T) {
	ord := Entry{Trust: identity.TrustOrdinary, Manifest: Manifest{
		PackageID:  "com.third.party",
		Components: []Component{{ID: "main", Disableable: false}},
	}}
	if can, _ := ord.CanDisable("main"); !can {
		t.Fatal("Ordinary component must always be disableable")
	}

	prot := Entry{Trust: identity.TrustPlatform, Manifest: Manifest{
		PackageID:  "nervus.settings",
		Components: []Component{{ID: "main", Disableable: true}},
	}}
	if can, why := prot.CanDisable("main"); can || why != "protected" {
		t.Fatalf("protected component must not be disableable, got can=%v why=%q", can, why)
	}

	sys := Entry{Trust: identity.TrustPlatform, Manifest: Manifest{
		PackageID:  "com.oem.tool",
		Components: []Component{{ID: "main", Disableable: false}},
	}}
	if can, why := sys.CanDisable("main"); can || why != "not disableable" {
		t.Fatalf("non-disableable system component, got can=%v why=%q", can, why)
	}

	sys2 := Entry{Trust: identity.TrustPlatform, Manifest: Manifest{
		PackageID:  "com.oem.tool",
		Components: []Component{{ID: "main", Disableable: true}},
	}}
	if can, _ := sys2.CanDisable("main"); !can {
		t.Fatal("disableable system component should be disableable")
	}
}

func TestInstall_CompensatesOnPostInstallFailure(t *testing.T) {
	mod, auth, _, _ := newTestInstaller(t)
	auth.dataDirErr = errors.New("boom: data dir")

	staging, mb, sig := newValidStaging(t, t.TempDir(), "com.example.app", "1.0.0")
	_, err := mod.Install(context.Background(), InstallTransaction{
		ManifestBytes: mb, SigBlock: sig, StagingDir: staging, Source: SourceDynamicInstall,
	})
	if err == nil {
		t.Fatal("want install error")
	}
	destDir := filepath.Join(mod.packageRoot, "com.example.app", "1.0.0")
	found := false
	for _, r := range auth.removed {
		if r.Root == mod.packageRoot && r.Path == destDir {
			found = true
		}
	}
	if !found {
		t.Fatalf("orphan code dir not compensated: removed=%+v", auth.removed)
	}
	if mod.registry.Len() != 0 {
		t.Fatalf("registry should be empty after failed install, got %d", mod.registry.Len())
	}
}
