package identity

import (
	"errors"
	"sync"
	"testing"

	"github.com/nervus-os/nervud/internal/sysprobe"
)

func mustReplace(t *testing.T, r *Registry, pkgs ...Package) {
	t.Helper()
	if err := r.Replace(pkgs); err != nil {
		t.Fatalf("Replace: %v", err)
	}
}

func TestReplace_RejectsDuplicateUID(t *testing.T) {
	r := NewRegistry()
	err := r.Replace([]Package{
		{ID: "com.a", UID: 20001, Trust: TrustOrdinary},
		{ID: "com.b", UID: 20001, Trust: TrustOrdinary},
	})
	if !errors.Is(err, ErrDuplicateUID) {
		t.Fatalf("err = %v, want ErrDuplicateUID", err)
	}
}

func TestReplace_RejectsDuplicatePackageID(t *testing.T) {
	r := NewRegistry()
	err := r.Replace([]Package{
		{ID: "com.a", UID: 20001, Trust: TrustOrdinary},
		{ID: "com.a", UID: 20002, Trust: TrustOrdinary},
	})
	if !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("err = %v, want ErrDuplicateID", err)
	}
}

func TestReplace_RejectsUIDZero(t *testing.T) {
	r := NewRegistry()
	if err := r.Replace([]Package{{ID: "com.a", UID: 0, Trust: TrustOrdinary}}); err == nil {
		t.Fatal("UID 0 must be rejected")
	}
}

func TestReplace_RejectsEmptyID(t *testing.T) {
	r := NewRegistry()
	if err := r.Replace([]Package{{ID: "", UID: 20001, Trust: TrustOrdinary}}); err == nil {
		t.Fatal("an empty ID must be rejected")
	}
}

func TestReplace_RejectsUnspecifiedTrust(t *testing.T) {
	r := NewRegistry()
	if err := r.Replace([]Package{{ID: "com.a", UID: 20001}}); err == nil {
		t.Fatal("TrustUnspecified must be rejected")
	}
	if err := r.Replace([]Package{{ID: "com.a", UID: 20001, Trust: TrustProfile(99)}}); err == nil {
		t.Fatal("an undefined TrustProfile must be rejected")
	}
}

func TestReplace_FailureKeepsPreviousSnapshot(t *testing.T) {
	r := NewRegistry()
	mustReplace(t, r, Package{ID: "com.good", UID: 20001, Trust: TrustOrdinary})

	err := r.Replace([]Package{
		{ID: "com.new", UID: 20002, Trust: TrustOrdinary},
		{ID: "com.bad", UID: 0, Trust: TrustOrdinary},
	})
	if err == nil {
		t.Fatal("want error")
	}
	if r.Len() != 1 {
		t.Fatalf("Len = %d, want 1 with the previous snapshot unchanged", r.Len())
	}
	if _, ok := r.Lookup(20001); !ok {
		t.Fatal("the previous entry was lost")
	}
	if _, ok := r.Lookup(20002); ok {
		t.Fatal("an entry from the rejected snapshot leaked into the registry")
	}
}

func TestReplace_EmptyClearsIndex(t *testing.T) {
	r := NewRegistry()
	mustReplace(t, r, Package{ID: "com.a", UID: 20001, Trust: TrustOrdinary})
	mustReplace(t, r)
	if r.Len() != 0 {
		t.Fatalf("Len = %d, want 0", r.Len())
	}
}

// --- Resolve --------------------------------------------------------------

func TestResolve_KnownUID(t *testing.T) {
	r := NewRegistry()
	mustReplace(t, r, Package{ID: "com.example.app", UID: 20001, Trust: TrustPlatform})

	c, err := r.Resolve(sysprobe.Ucred{PID: 4242, UID: 20001, GID: 20001})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.PackageID != "com.example.app" {
		t.Fatalf("PackageID = %q", c.PackageID)
	}
	if c.Trust != TrustPlatform {
		t.Fatalf("Trust = %v, want platform", c.Trust)
	}
	if c.UID != 20001 || c.GID != 20001 || c.PID != 4242 {
		t.Fatalf("kernel credentials were not preserved: %+v", c)
	}
	if c.ComponentID != "" {
		t.Fatalf("ComponentID = %q, want empty", c.ComponentID)
	}
}

func TestResolve_UnknownUID(t *testing.T) {
	r := NewRegistry()
	mustReplace(t, r, Package{ID: "com.a", UID: 20001, Trust: TrustOrdinary})

	_, err := r.Resolve(sysprobe.Ucred{PID: 1, UID: 20002, GID: 20002})
	if !errors.Is(err, ErrUnknownUID) {
		t.Fatalf("err = %v, want ErrUnknownUID", err)
	}
}

func TestResolve_EmptyRegistry(t *testing.T) {
	if _, err := NewRegistry().Resolve(sysprobe.Ucred{UID: 20001}); !errors.Is(err, ErrUnknownUID) {
		t.Fatalf("err = %v, want ErrUnknownUID", err)
	}
}

func TestUninitializedRegistry_IsFailSafe(t *testing.T) {
	var empty Registry
	if _, ok := empty.Lookup(20001); ok {
		t.Fatal("an uninitialized Registry should not return any entry")
	}
	if empty.Len() != 0 {
		t.Fatal("an uninitialized Registry should have length 0")
	}
	if _, err := empty.Resolve(sysprobe.Ucred{UID: 20001}); !errors.Is(err, ErrUnknownUID) {
		t.Fatalf("err = %v, want ErrUnknownUID", err)
	}

	var nilReg *Registry
	if _, ok := nilReg.Lookup(20001); ok {
		t.Fatal("a typed-nil Registry should not return any entry")
	}
	if nilReg.Len() != 0 {
		t.Fatal("a typed-nil Registry should have length 0")
	}
	if _, err := nilReg.Resolve(sysprobe.Ucred{UID: 20001}); !errors.Is(err, ErrUnknownUID) {
		t.Fatalf("err = %v, want ErrUnknownUID", err)
	}
}

func TestRegistry_ConcurrentReadWrite(t *testing.T) {
	r := NewRegistry()
	mustReplace(t, r, Package{ID: "com.a", UID: 20001, Trust: TrustOrdinary})

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
				if p, ok := r.Lookup(20001); ok && p.ID != "com.a" {
					t.Errorf("observed a torn entry: %+v", p)
					return
				}
			}
		}()
	}

	for i := range 200 {
		pkgs := []Package{{ID: "com.a", UID: 20001, Trust: TrustOrdinary}}
		if i%2 == 0 {
			pkgs = append(pkgs, Package{ID: "com.b", UID: 20002, Trust: TrustOEM})
		}
		if err := r.Replace(pkgs); err != nil {
			t.Fatalf("Replace: %v", err)
		}
	}

	close(stop)
	wg.Wait()
}

// --- TrustProfile ---------------------------------------------------------

func TestTrustProfile(t *testing.T) {
	if TrustUnspecified.Valid() {
		t.Fatal("the zero value should not be a valid profile")
	}
	for _, tp := range []TrustProfile{TrustOrdinary, TrustOEM, TrustPlatform} {
		if !tp.Valid() {
			t.Fatalf("%v should be valid", tp)
		}
		if tp.String() == "unspecified" {
			t.Fatalf("String() for %d returned unspecified", tp)
		}
	}
}

func TestCaller_String(t *testing.T) {
	if got := (Caller{}).String(); got != "kernel" {
		t.Fatalf("empty Caller = %q, want kernel", got)
	}
	c := Caller{PackageID: "com.example.app", UID: 20001}
	if got, want := c.String(), "pkg:com.example.app uid:20001"; got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
}
