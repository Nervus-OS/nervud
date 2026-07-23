package permission

import (
	"testing"

	"github.com/nervus-os/nervud/internal/identity"
)

func testCatalog(t *testing.T) Catalog {
	t.Helper()
	cat, err := NewCatalog([]CatalogEntry{
		{ID: "perm.ordinary", MinTrust: identity.TrustOrdinary},
		{ID: "perm.oem", MinTrust: identity.TrustOEM},
		{ID: "perm.platform", MinTrust: identity.TrustPlatform},
	})
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	return cat
}

func TestIntersect_GrantsWhenTrustMeetsThreshold(t *testing.T) {
	cat := testCatalog(t)
	granted, denied := Intersect([]string{"perm.ordinary", "perm.oem"}, cat, identity.TrustOEM)
	if len(denied) != 0 {
		t.Fatalf("denied = %v, want empty", denied)
	}
	if len(granted) != 2 {
		t.Fatalf("granted = %v, want both", granted)
	}
}

func TestIntersect_DeniesWhenTrustBelowThreshold(t *testing.T) {
	cat := testCatalog(t)
	granted, denied := Intersect([]string{"perm.ordinary", "perm.platform"}, cat, identity.TrustOrdinary)
	if len(granted) != 1 || granted[0] != "perm.ordinary" {
		t.Fatalf("granted = %v, want [perm.ordinary]", granted)
	}
	if len(denied) != 1 || denied[0] != "perm.platform" {
		t.Fatalf("denied = %v, want [perm.platform]", denied)
	}
}

// 未登记在 Catalog 里的权限 ID 一律 fail closed，不能被静默忽略
func TestIntersect_DeniesUnregisteredPermissionID(t *testing.T) {
	cat := testCatalog(t)
	granted, denied := Intersect([]string{"perm.unknown"}, cat, identity.TrustPlatform)
	if len(granted) != 0 {
		t.Fatalf("granted = %v, want empty", granted)
	}
	if len(denied) != 1 || denied[0] != "perm.unknown" {
		t.Fatalf("denied = %v, want [perm.unknown]", denied)
	}
}

func TestIntersect_EmptyRequestYieldsEmptyResult(t *testing.T) {
	cat := testCatalog(t)
	granted, denied := Intersect(nil, cat, identity.TrustPlatform)
	if len(granted) != 0 || len(denied) != 0 {
		t.Fatalf("granted=%v denied=%v, want both empty", granted, denied)
	}
}

// 零值 Catalog（未装配）视为空登记表：所有请求一律被拒，而不是 panic
func TestIntersect_ZeroValueCatalogDeniesEverything(t *testing.T) {
	var cat Catalog
	granted, denied := Intersect([]string{"perm.a", "perm.b"}, cat, identity.TrustPlatform)
	if len(granted) != 0 {
		t.Fatalf("granted = %v, want empty", granted)
	}
	if len(denied) != 2 {
		t.Fatalf("denied = %v, want both denied", denied)
	}
}
