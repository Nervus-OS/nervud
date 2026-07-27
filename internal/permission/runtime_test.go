package permission

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/identity"
)

type orderedPermissionRevoker struct{ events *[]string }

func (r orderedPermissionRevoker) RevokePermission(_, _ string) {
	*r.events = append(*r.events, "ipc")
}

type orderedInstallGrantRevoker struct{ events *[]string }

func (r orderedInstallGrantRevoker) RevokeInstallGrant(_, _ string) {
	*r.events = append(*r.events, "sandbox:stop")
}

type orderedRuntimeProjector struct {
	events *[]string
	err    error
}

func (p orderedRuntimeProjector) ProjectRuntimePermission(_, _ string, allowed bool) error {
	if allowed {
		*p.events = append(*p.events, "sandbox:allowed")
	} else {
		*p.events = append(*p.events, "sandbox:denied")
	}
	return p.err
}

func grant(t *testing.T, r *Registry, pkg string, perms ...string) {
	t.Helper()
	if err := r.Replace([]Grant{{PackageID: pkg, Permissions: perms}}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
}

func TestAllowed_GrantInstallNoRuntimeNeeded(t *testing.T) {
	r := NewDefaultRegistry()
	grant(t, r, "com.a", "perm.diagnostics.read")
	if !r.Allowed("com.a", "perm.diagnostics.read") {
		t.Fatal("GrantInstall perm should be allowed once in install-set")
	}
}

func TestAllowed_GrantUserRequiresRuntimeGrant(t *testing.T) {
	r := NewDefaultRegistry()
	grant(t, r, "com.a", "perm.storage.user")

	if r.Allowed("com.a", "perm.storage.user") {
		t.Fatal("GrantUser perm must NOT be allowed before runtime grant")
	}
	if err := r.SetRuntimeState("com.a", "perm.storage.user", GrantStateGranted); err != nil {
		t.Fatalf("SetRuntimeState: %v", err)
	}
	if !r.Allowed("com.a", "perm.storage.user") {
		t.Fatal("GrantUser perm should be allowed after runtime grant")
	}
	if err := r.SetRuntimeState("com.a", "perm.storage.user", GrantStateDenied); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if r.Allowed("com.a", "perm.storage.user") {
		t.Fatal("revoked GrantUser perm must be denied immediately")
	}
}

func TestAllowed_NotInInstallSetAlwaysDenied(t *testing.T) {
	r := NewDefaultRegistry()
	if err := r.SetRuntimeState("com.a", "perm.storage.user", GrantStateGranted); err == nil {
		t.Fatal("SetRuntimeState should reject a package outside the install set")
	}
	if r.Allowed("com.a", "perm.storage.user") {
		t.Fatal("perm not in install-set must be denied even if runtime-granted")
	}
}

func TestSetRuntimeState_RejectsNonUserPerm(t *testing.T) {
	r := NewDefaultRegistry()
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
	r := NewDefaultRegistry()
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

	grant(t, r, "com.a", "perm.motion.control", "perm.storage.user")
	_ = r.SetRuntimeState("com.a", "perm.storage.user", GrantStateGranted)
	_ = r.SetRuntimeState("com.a", "perm.storage.user", GrantStateDenied)
	if len(rev.revoked) != 1 {
		t.Fatalf("revoking non-motion perm must NOT revoke leases: %+v", rev.revoked)
	}
}

func TestGrantState_Persistence(t *testing.T) {
	dir := t.TempDir()

	r1 := NewDefaultRegistry()
	r1.SetGrantStore(dir, nil, nil)
	grant(t, r1, "com.a", "perm.storage.user")
	if err := r1.SetRuntimeState("com.a", "perm.storage.user", GrantStateGranted); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, grantStateFile)); err != nil {
		t.Fatalf("grant state file not written: %v", err)
	}

	r2 := NewDefaultRegistry()
	r2.SetGrantStore(dir, nil, nil)
	if r2.GrantStateOf("com.a", "perm.storage.user") != GrantStateGranted {
		t.Fatal("grant state not restored from disk")
	}
	grant(t, r2, "com.a", "perm.storage.user")
	if !r2.Allowed("com.a", "perm.storage.user") {
		t.Fatal("restored grant should make Allowed true")
	}
}

func TestClearPackage_PersistFailureRestoresMemory(t *testing.T) {
	r := NewDefaultRegistry()
	r.SetGrantStore(t.TempDir(), nil, nil)
	grant(t, r, "com.a", "perm.storage.user")
	if err := r.SetRuntimeState("com.a", "perm.storage.user", GrantStateGranted); err != nil {
		t.Fatalf("grant: %v", err)
	}

	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	r.grants.mu.Lock()
	r.grants.stateDir = blocked
	r.grants.mu.Unlock()

	if err := r.ClearPackage("com.a"); err == nil {
		t.Fatal("ClearPackage succeeded despite an unwritable state path")
	}
	if got := r.GrantStateOf("com.a", "perm.storage.user"); got != GrantStateGranted {
		t.Fatalf("grant state after failed clear = %v, want granted", got)
	}
}

func TestIntersect_RequireSignerRole(t *testing.T) {
	r := NewDefaultRegistry()
	snapshot := r.definitions.Current()
	g, d := r.IntersectAt(
		snapshot,
		[]string{"perm.authority.reboot"},
		catalog.SourceKindSystemImage,
		identity.TrustPlatform,
		catalog.SignerEvidence{Roles: []string{"platform-systemapp"}},
	)
	if len(g) != 0 || len(d) != 1 {
		t.Fatalf("reboot without platform-release role must be denied: g=%v d=%v", g, d)
	}
	g, d = r.IntersectAt(
		snapshot,
		[]string{"perm.authority.reboot"},
		catalog.SourceKindSystemImage,
		identity.TrustPlatform,
		catalog.SignerEvidence{Roles: []string{"platform-release"}},
	)
	if len(g) != 1 || len(d) != 0 {
		t.Fatalf("reboot with platform-release role should be granted: g=%v d=%v", g, d)
	}
}

func TestIntersect_RegisterSplit(t *testing.T) {
	r := NewDefaultRegistry()
	snapshot := r.definitions.Current()
	g, _ := r.IntersectAt(
		snapshot,
		[]string{"perm.service.register.private"},
		catalog.SourceKindDynamicInstall,
		identity.TrustOrdinary,
		catalog.SignerEvidence{Roles: []string{"developer"}},
	)
	if len(g) != 1 {
		t.Fatalf("register.private should be grantable to Ordinary: %v", g)
	}
	_, d := r.IntersectAt(
		snapshot,
		[]string{"perm.service.register"},
		catalog.SourceKindDynamicInstall,
		identity.TrustOrdinary,
		catalog.SignerEvidence{Roles: []string{"developer"}},
	)
	if len(d) != 1 {
		t.Fatalf("cross-package register must require OEM+: denied=%v", d)
	}
}

func TestRuntimeRevocation_ClosesPermissionDataPlane(t *testing.T) {
	r := NewDefaultRegistry()
	revoker := &recordingPermissionRevoker{}
	r.SetPermissionRevoker(revoker)
	grant(t, r, "com.a", "perm.storage.user")
	if err := r.SetRuntimeState("com.a", "perm.storage.user", GrantStateGranted); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := r.SetRuntimeState("com.a", "perm.storage.user", GrantStateDenied); err != nil {
		t.Fatalf("deny: %v", err)
	}
	revoker.mu.Lock()
	defer revoker.mu.Unlock()
	if len(revoker.calls) != 1 || revoker.calls[0] != "com.a/perm.storage.user" {
		t.Fatalf("revocations = %v, want runtime permission revocation", revoker.calls)
	}
}

func TestRuntimeState_RevokesIPCBeforeProjectingSandbox(t *testing.T) {
	r := NewDefaultRegistry()
	grant(t, r, "com.a", "perm.storage.user")
	events := []string{}
	r.SetPermissionRevoker(orderedPermissionRevoker{events: &events})
	r.SetRuntimePermissionProjector(orderedRuntimeProjector{events: &events})

	if err := r.SetRuntimeState("com.a", "perm.storage.user", GrantStateGranted); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if got := events; len(got) != 1 || got[0] != "sandbox:allowed" {
		t.Fatalf("grant events = %v, want sandbox projection only", got)
	}

	events = events[:0]
	if err := r.SetRuntimeState("com.a", "perm.storage.user", GrantStateDenied); err != nil {
		t.Fatalf("deny: %v", err)
	}
	if len(events) != 2 || events[0] != "ipc" || events[1] != "sandbox:denied" {
		t.Fatalf("deny events = %v, want IPC revoke before sandbox projection", events)
	}
}

func TestReplace_RevokesIPCThenStopsSandboxWithoutRuntimeProjection(t *testing.T) {
	r := NewDefaultRegistry()
	events := []string{}
	r.SetPermissionRevoker(orderedPermissionRevoker{events: &events})
	r.SetInstallGrantRevoker(orderedInstallGrantRevoker{events: &events})
	r.SetRuntimePermissionProjector(orderedRuntimeProjector{events: &events})
	grant(t, r, "com.a", "perm.storage.user")

	if err := r.Replace([]Grant{{PackageID: "com.a"}}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if len(events) != 2 || events[0] != "ipc" || events[1] != "sandbox:stop" {
		t.Fatalf("Replace events = %v, want IPC revoke then non-blocking sandbox stop", events)
	}
}

func TestRuntimeProjectionFailure_DoesNotRestoreRevokedGrant(t *testing.T) {
	r := NewDefaultRegistry()
	grant(t, r, "com.a", "perm.storage.user")
	if err := r.SetRuntimeState("com.a", "perm.storage.user", GrantStateGranted); err != nil {
		t.Fatalf("grant: %v", err)
	}
	r.SetRuntimePermissionProjector(orderedRuntimeProjector{
		events: &[]string{},
		err:    errors.New("sandbox teardown failed"),
	})

	err := r.SetRuntimeState("com.a", "perm.storage.user", GrantStateDenied)
	if err == nil {
		t.Fatal("deny succeeded despite sandbox projection failure")
	}
	if r.Allowed("com.a", "perm.storage.user") {
		t.Fatal("projection failure restored the revoked runtime grant")
	}
}
