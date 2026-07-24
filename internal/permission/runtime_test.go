package permission

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nervus-os/nervud/internal/identity"
)

func grant(t *testing.T, r *Registry, pkg string, perms ...string) {
	t.Helper()
	if err := r.Replace([]Grant{{PackageID: pkg, Permissions: perms}}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
}

func TestAllowed_GrantInstallNoRuntimeNeeded(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	grant(t, r, "com.a", "perm.diagnostics.read")
	if !r.Allowed("com.a", "perm.diagnostics.read") {
		t.Fatal("GrantInstall perm should be allowed once in install-set")
	}
}

func TestAllowed_GrantUserRequiresRuntimeGrant(t *testing.T) {
	skipIfGrantAll(t)
	r := NewRegistry(DefaultCatalog())
	grant(t, r, "com.a", "perm.camera.capture")

	if r.Allowed("com.a", "perm.camera.capture") {
		t.Fatal("GrantUser perm must NOT be allowed before runtime grant")
	}
	if err := r.SetRuntimeState("com.a", "perm.camera.capture", GrantStateGranted); err != nil {
		t.Fatalf("SetRuntimeState: %v", err)
	}
	if !r.Allowed("com.a", "perm.camera.capture") {
		t.Fatal("GrantUser perm should be allowed after runtime grant")
	}
	if err := r.SetRuntimeState("com.a", "perm.camera.capture", GrantStateDenied); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if r.Allowed("com.a", "perm.camera.capture") {
		t.Fatal("revoked GrantUser perm must be denied immediately")
	}
}

func TestAllowed_NotInInstallSetAlwaysDenied(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	if err := r.SetRuntimeState("com.a", "perm.camera.capture", GrantStateGranted); err != nil {
		t.Fatalf("SetRuntimeState: %v", err)
	}
	if r.Allowed("com.a", "perm.camera.capture") {
		t.Fatal("perm not in install-set must be denied even if runtime-granted")
	}
}

func TestSetRuntimeState_RejectsNonUserPerm(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	if err := r.SetRuntimeState("com.a", "perm.diagnostics.read", GrantStateGranted); err == nil {
		t.Fatal("SetRuntimeState on a non-GrantUser perm should error")
	}
	if err := r.SetRuntimeState("com.a", "perm.nope", GrantStateGranted); err == nil {
		t.Fatal("SetRuntimeState on unknown perm should error")
	}
}

type fakeRevoker struct{ revoked []string }

func (f *fakeRevoker) RevokeByPackage(pkg string) error {
	f.revoked = append(f.revoked, pkg)
	return nil
}

func TestRevokeMotionPerm_TriggersLeaseRevoker(t *testing.T) {
	dir := t.TempDir()
	r := NewRegistry(DefaultCatalog())
	rev := &fakeRevoker{}
	r.SetGrantStore(dir, rev, nil)
	grant(t, r, "com.a", "perm.motion.control")

	if err := r.SetRuntimeState("com.a", "perm.motion.control", GrantStateGranted); err != nil {
		t.Fatalf("grant motion: %v", err)
	}
	if len(rev.revoked) != 0 {
		t.Fatalf("granting must not revoke: %+v", rev.revoked)
	}
	if err := r.SetRuntimeState("com.a", "perm.motion.control", GrantStateDenied); err != nil {
		t.Fatalf("revoke motion: %v", err)
	}
	if len(rev.revoked) != 1 || rev.revoked[0] != "com.a" {
		t.Fatalf("revoking motion perm must call RevokeByPackage: %+v", rev.revoked)
	}

	grant(t, r, "com.a", "perm.motion.control", "perm.camera.capture")
	_ = r.SetRuntimeState("com.a", "perm.camera.capture", GrantStateGranted)
	_ = r.SetRuntimeState("com.a", "perm.camera.capture", GrantStateDenied)
	if len(rev.revoked) != 1 {
		t.Fatalf("revoking non-motion perm must NOT revoke leases: %+v", rev.revoked)
	}
}

func TestGrantState_Persistence(t *testing.T) {
	dir := t.TempDir()

	r1 := NewRegistry(DefaultCatalog())
	r1.SetGrantStore(dir, nil, nil)
	if err := r1.SetRuntimeState("com.a", "perm.camera.capture", GrantStateGranted); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, grantStateFile)); err != nil {
		t.Fatalf("grant state file not written: %v", err)
	}

	r2 := NewRegistry(DefaultCatalog())
	r2.SetGrantStore(dir, nil, nil)
	if r2.GrantStateOf("com.a", "perm.camera.capture") != GrantStateGranted {
		t.Fatal("grant state not restored from disk")
	}
	grant(t, r2, "com.a", "perm.camera.capture")
	if !r2.Allowed("com.a", "perm.camera.capture") {
		t.Fatal("restored grant should make Allowed true")
	}
}

func TestIntersect_RequireSignerRole(t *testing.T) {
	skipIfGrantAll(t)
	r := NewRegistry(DefaultCatalog())
	g, d := r.Intersect([]string{"perm.authority.reboot"}, identity.TrustPlatform, []string{"platform-systemapp"})
	if len(g) != 0 || len(d) != 1 {
		t.Fatalf("reboot without platform-release role must be denied: g=%v d=%v", g, d)
	}
	g, d = r.Intersect([]string{"perm.authority.reboot"}, identity.TrustPlatform, []string{"platform-release"})
	if len(g) != 1 || len(d) != 0 {
		t.Fatalf("reboot with platform-release role should be granted: g=%v d=%v", g, d)
	}
}

func TestIntersect_RegisterSplit(t *testing.T) {
	skipIfGrantAll(t)
	r := NewRegistry(DefaultCatalog())
	g, _ := r.Intersect([]string{"perm.service.register.private"}, identity.TrustOrdinary, []string{"developer"})
	if len(g) != 1 {
		t.Fatalf("register.private should be grantable to Ordinary: %v", g)
	}
	_, d := r.Intersect([]string{"perm.service.register"}, identity.TrustOrdinary, []string{"developer"})
	if len(d) != 1 {
		t.Fatalf("cross-package register must require OEM+: denied=%v", d)
	}
}
