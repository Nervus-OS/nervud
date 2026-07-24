package permission

import (
	"testing"

	"github.com/nervus-os/nervud/internal/identity"
)

func TestNewCatalog_RejectsEmptyID(t *testing.T) {
	_, err := NewCatalog([]CatalogEntry{{ID: "", MinTrust: identity.TrustOrdinary}})
	if err == nil {
		t.Fatal("an empty ID must be rejected")
	}
}

func TestNewCatalog_RejectsInvalidMinTrust(t *testing.T) {
	_, err := NewCatalog([]CatalogEntry{{ID: "perm.a", MinTrust: identity.TrustUnspecified}})
	if err == nil {
		t.Fatal("TrustUnspecified must be rejected")
	}
}

func TestNewCatalog_RejectsDuplicateID(t *testing.T) {
	_, err := NewCatalog([]CatalogEntry{
		{ID: "perm.a", MinTrust: identity.TrustOrdinary},
		{ID: "perm.a", MinTrust: identity.TrustOEM},
	})
	if err == nil {
		t.Fatal("a duplicate ID must be rejected")
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
		t.Fatal("an unregistered permission ID should not be found")
	}
}

func TestCatalog_ZeroValueIsFailSafe(t *testing.T) {
	var cat Catalog
	if _, ok := cat.Lookup("perm.a"); ok {
		t.Fatal("a zero-value Catalog should not return any entry")
	}
	if cat.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", cat.Len())
	}
}

func TestDefaultCatalog_IsSelfConsistent(t *testing.T) {
	cat := DefaultCatalog()
	if cat.Len() == 0 {
		t.Fatal("DefaultCatalog should not be empty")
	}
}
