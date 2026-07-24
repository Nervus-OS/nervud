package control

import (
	"errors"
	"testing"
)

func TestRevokeByPackage_RevokesMatchingPackage(t *testing.T) {
	m, g, rec := newTestModule(t)

	epochBefore := g.Epoch()
	l := mustAcquire(t, m, humanReq(1))
	if l.Owner.PackageID == "" {
		t.Fatal("test setup: lease has empty PackageID")
	}

	if err := m.RevokeByPackage(l.Owner.PackageID); err != nil {
		t.Fatalf("RevokeByPackage: %v", err)
	}

	if cur := m.cur.Load(); cur != nil {
		t.Fatalf("cur still set after RevokeByPackage: %+v", cur)
	}

	if g.Epoch() <= epochBefore+1 {
		t.Fatalf("epoch = %d, want > %d", g.Epoch(), epochBefore+1)
	}

	if !rec.has(actionRevoked) {
		t.Fatalf("expected %q audit event, got %v", actionRevoked, rec.actions())
	}
}

func TestRevokeByPackage_DoesNotRevokeOtherPackage(t *testing.T) {
	m, _, _ := newTestModule(t)

	l := mustAcquire(t, m, humanReq(1))

	if err := m.RevokeByPackage("com.other.package"); err != nil {
		t.Fatalf("RevokeByPackage(other): %v", err)
	}

	if cur := m.cur.Load(); cur == nil || cur.ID != l.ID {
		t.Fatalf("lease was wrongly revoked by unrelated package")
	}
}

func TestRevokeByPackage_IdempotentWhenNoLease(t *testing.T) {
	m, _, _ := newTestModule(t)

	if err := m.RevokeByPackage("com.example.app"); err != nil {
		t.Fatalf("RevokeByPackage with no lease: %v", err)
	}
}

func TestRevokeByPackage_IdempotentEmptyPkgID(t *testing.T) {
	m, _, _ := newTestModule(t)
	mustAcquire(t, m, humanReq(1))

	if err := m.RevokeByPackage(""); err != nil {
		t.Fatalf("RevokeByPackage(\"\") should be nil, got %v", err)
	}
	if m.cur.Load() == nil {
		t.Fatal("lease was wrongly revoked by empty pkgID")
	}
}

func TestRevokeByPackage_EpochIncrements(t *testing.T) {
	m, _, _ := newTestModule(t)

	l := mustAcquire(t, m, humanReq(1))
	if err := m.RevokeByPackage(l.Owner.PackageID); err != nil {
		t.Fatalf("RevokeByPackage: %v", err)
	}

	_, err := m.Check(l.ID, l.Conn)
	if err == nil {
		t.Fatal("Check after RevokeByPackage should fail")
	}
	if !errors.Is(err, ErrControlNotHeld) && !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("Check error = %v, want ErrControlNotHeld or ErrStaleEpoch", err)
	}
}

func TestRevokeByPackage_SatisfiesPermissionLeaseRevoker(t *testing.T) {
	type leaseRevoker interface {
		RevokeByPackage(pkgID string) error
	}
	m, _, _ := newTestModule(t)
	var _ leaseRevoker = m
}
