package control

import (
	"errors"
	"testing"
)

// TestRevokeByPackage_RevokesMatchingPackage 撤销持有租约的包，epoch 递增
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

	// 租约已撤：cur 应为 nil
	if cur := m.cur.Load(); cur != nil {
		t.Fatalf("cur still set after RevokeByPackage: %+v", cur)
	}

	// epoch 应已递增（dropLocked 经 BumpEpochIfNormal）
	if g.Epoch() <= epochBefore+1 {
		// issueLocked 递增一次，dropLocked 再递增一次
		t.Fatalf("epoch = %d, want > %d", g.Epoch(), epochBefore+1)
	}

	// 审计应有 LeaseRevoked
	if !rec.has(actionRevoked) {
		t.Fatalf("expected %q audit event, got %v", actionRevoked, rec.actions())
	}
}

// TestRevokeByPackage_DoesNotRevokeOtherPackage 不误撤其他包的租约
func TestRevokeByPackage_DoesNotRevokeOtherPackage(t *testing.T) {
	m, _, _ := newTestModule(t)

	l := mustAcquire(t, m, humanReq(1))

	if err := m.RevokeByPackage("com.other.package"); err != nil {
		t.Fatalf("RevokeByPackage(other): %v", err)
	}

	// 租约应仍在
	if cur := m.cur.Load(); cur == nil || cur.ID != l.ID {
		t.Fatalf("lease was wrongly revoked by unrelated package")
	}
}

// TestRevokeByPackage_IdempotentWhenNoLease 无租约时幂等返回 nil
func TestRevokeByPackage_IdempotentWhenNoLease(t *testing.T) {
	m, _, _ := newTestModule(t)

	if err := m.RevokeByPackage("com.example.app"); err != nil {
		t.Fatalf("RevokeByPackage with no lease: %v", err)
	}
}

// TestRevokeByPackage_IdempotentEmptyPkgID 空 pkgID 幂等返回 nil
func TestRevokeByPackage_IdempotentEmptyPkgID(t *testing.T) {
	m, _, _ := newTestModule(t)
	mustAcquire(t, m, humanReq(1))

	if err := m.RevokeByPackage(""); err != nil {
		t.Fatalf("RevokeByPackage(\"\") should be nil, got %v", err)
	}
	// 租约不应被撤
	if m.cur.Load() == nil {
		t.Fatal("lease was wrongly revoked by empty pkgID")
	}
}

// TestRevokeByPackage_EpochIncrements 撤租后 epoch 递增，旧租约 Check 失败
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

// TestRevokeByPackage_SatisfiesPermissionLeaseRevoker 确认 *Module 隐式满足
// permission.LeaseRevoker 与 pkgregistry.LeaseRevoker（同一签名）
func TestRevokeByPackage_SatisfiesPermissionLeaseRevoker(t *testing.T) {
	type leaseRevoker interface {
		RevokeByPackage(pkgID string) error
	}
	m, _, _ := newTestModule(t)
	var _ leaseRevoker = m // 编译期断言
}
