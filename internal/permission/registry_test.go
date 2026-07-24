package permission

import (
	"errors"
	"sync"
	"testing"

	"github.com/nervus-os/nervud/internal/identity"
)

func TestRegistryReplace_RejectsEmptyPackageID(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	err := r.Replace([]Grant{{PackageID: "", Permissions: []string{"perm.a"}}})
	if err == nil {
		t.Fatal("an empty package ID must be rejected")
	}
}

func TestRegistryReplace_RejectsDuplicatePackageID(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	err := r.Replace([]Grant{
		{PackageID: "com.a", Permissions: []string{"perm.a"}},
		{PackageID: "com.a", Permissions: []string{"perm.b"}},
	})
	if !errors.Is(err, ErrDuplicatePackageID) {
		t.Fatalf("err = %v, want ErrDuplicatePackageID", err)
	}
}

func TestRegistryReplace_FailureKeepsPreviousSnapshot(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	if err := r.Replace([]Grant{{PackageID: "com.good", Permissions: []string{"perm.diagnostics.read"}}}); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	err := r.Replace([]Grant{
		{PackageID: "com.new", Permissions: []string{"perm.diagnostics.read"}},
		{PackageID: "", Permissions: nil},
	})
	if err == nil {
		t.Fatal("want error")
	}
	if r.Len() != 1 {
		t.Fatalf("Len() = %d, want 1 with the previous snapshot unchanged", r.Len())
	}
	if !r.Allowed("com.good", "perm.diagnostics.read") {
		t.Fatal("the previous grant was lost")
	}
	if r.Allowed("com.new", "perm.diagnostics.read") {
		t.Fatal("a grant from the rejected snapshot leaked into the registry")
	}
}

func TestRegistryAllowed(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	if err := r.Replace([]Grant{{PackageID: "com.a", Permissions: []string{"perm.diagnostics.read"}}}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if !r.Allowed("com.a", "perm.diagnostics.read") {
		t.Fatal("a granted permission should be allowed")
	}
	if r.Allowed("com.a", "perm.service.register") {
		t.Fatal("an ungranted permission should not be allowed")
	}
	if r.Allowed("com.missing", "perm.diagnostics.read") {
		t.Fatal("an unknown Package should not be allowed")
	}
}

func TestRegistryAllowed_ReflectsRevocationImmediately(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	if err := r.Replace([]Grant{{PackageID: "com.a", Permissions: []string{"perm.diagnostics.read"}}}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if !r.Allowed("com.a", "perm.diagnostics.read") {
		t.Fatal("permission should be allowed after grant")
	}

	if err := r.Replace(nil); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if r.Allowed("com.a", "perm.diagnostics.read") {
		t.Fatal("the next Allowed call must reject immediately after revocation")
	}
}

func TestUninitializedRegistry_IsFailSafe(t *testing.T) {
	var empty Registry
	if empty.Allowed("com.a", "perm.diagnostics.read") {
		t.Fatal("Allowed on an uninitialized Registry must return false")
	}
	if empty.Len() != 0 {
		t.Fatal("an uninitialized Registry should have length 0")
	}
	granted, denied := empty.Intersect([]string{"perm.diagnostics.read"}, identity.TrustPlatform, nil)
	if len(granted) != 0 || len(denied) != 1 {
		t.Fatalf("Intersect on an uninitialized Registry should deny everything, got granted=%v denied=%v", granted, denied)
	}

	var nilReg *Registry
	if nilReg.Allowed("com.a", "perm.diagnostics.read") {
		t.Fatal("Allowed on a typed-nil Registry must return false")
	}
	if nilReg.Len() != 0 {
		t.Fatal("a typed-nil Registry should have length 0")
	}
}

func TestRegistryIntersect_UsesOwnCatalog(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	granted, denied := r.Intersect([]string{"perm.diagnostics.read", "perm.platform.control"}, identity.TrustOrdinary, nil)
	if len(granted) != 1 || granted[0] != "perm.diagnostics.read" {
		t.Fatalf("granted = %v, want [perm.diagnostics.read]", granted)
	}
	if len(denied) != 1 || denied[0] != "perm.platform.control" {
		t.Fatalf("denied = %v, want [perm.platform.control]", denied)
	}
}

func TestRegistry_ConcurrentReadWrite(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	if err := r.Replace([]Grant{{PackageID: "com.a", Permissions: []string{"perm.diagnostics.read"}}}); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = r.Allowed("com.a", "perm.diagnostics.read")
			}
		}()
	}

	for i := range 200 {
		grants := []Grant{{PackageID: "com.a", Permissions: []string{"perm.diagnostics.read"}}}
		if i%2 == 0 {
			grants = append(grants, Grant{PackageID: "com.b", Permissions: []string{"perm.service.register"}})
		}
		if err := r.Replace(grants); err != nil {
			t.Fatalf("Replace: %v", err)
		}
	}

	close(stop)
	wg.Wait()
}
