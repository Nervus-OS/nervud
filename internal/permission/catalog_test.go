package permission

import (
	"testing"

	"github.com/nervus-os/nervud/internal/identity"
)

func TestNewCatalog_RejectsEmptyID(t *testing.T) {
	_, err := NewCatalog([]CatalogEntry{{ID: "", MinTrust: identity.TrustOrdinary}})
	if err == nil {
		t.Fatal("空 ID 必须被拒绝")
	}
}

func TestNewCatalog_RejectsInvalidMinTrust(t *testing.T) {
	_, err := NewCatalog([]CatalogEntry{{ID: "perm.a", MinTrust: identity.TrustUnspecified}})
	if err == nil {
		t.Fatal("TrustUnspecified 必须被拒绝")
	}
}

func TestNewCatalog_RejectsDuplicateID(t *testing.T) {
	_, err := NewCatalog([]CatalogEntry{
		{ID: "perm.a", MinTrust: identity.TrustOrdinary},
		{ID: "perm.a", MinTrust: identity.TrustOEM},
	})
	if err == nil {
		t.Fatal("重复 ID 必须被拒绝")
	}
}

func TestCatalog_Lookup(t *testing.T) {
	cat, err := NewCatalog([]CatalogEntry{{ID: "perm.a", MinTrust: identity.TrustOEM}})
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	e, ok := cat.Lookup("perm.a")
	if !ok || e.MinTrust != identity.TrustOEM {
		t.Fatalf("Lookup(perm.a) = %+v, %v", e, ok)
	}
	if _, ok := cat.Lookup("perm.missing"); ok {
		t.Fatal("未登记的权限 ID 不该查到")
	}
}

// 零值 Catalog（未经 NewCatalog）必须 fail-safe：查无一切，不 panic
func TestCatalog_ZeroValueIsFailSafe(t *testing.T) {
	var cat Catalog
	if _, ok := cat.Lookup("perm.a"); ok {
		t.Fatal("零值 Catalog 不该查到任何东西")
	}
	if cat.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", cat.Len())
	}
}

func TestDefaultCatalog_IsSelfConsistent(t *testing.T) {
	cat := DefaultCatalog()
	if cat.Len() == 0 {
		t.Fatal("DefaultCatalog 不该为空")
	}
}
