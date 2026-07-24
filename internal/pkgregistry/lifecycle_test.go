package pkgregistry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nervus-os/nervud/internal/identity"
)

type fakeStopper struct {
	stopped   []string
	reloaded  []string
	stopErr   error
	reloadErr error
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
	mod.SetLifecycleHooks(stopper, nil)

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
