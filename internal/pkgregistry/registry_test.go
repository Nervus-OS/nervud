package pkgregistry

import (
	"errors"
	"sync"
	"testing"

	"github.com/nervus-os/nervud/internal/identity"
)

func entryFor(id string, uid uint32, trust identity.TrustProfile) Entry {
	return Entry{
		Manifest:      Manifest{PackageID: id, Version: "1.0.0"},
		ActiveVersion: "1.0.0",
		UID:           uid,
		Trust:         trust,
		Source:        SourceDynamicInstall,
	}
}

func mustReplaceRegistry(t *testing.T, r *Registry, entries ...Entry) {
	t.Helper()
	if err := r.Replace(entries); err != nil {
		t.Fatalf("Replace: %v", err)
	}
}

func TestRegistryReplace_RejectsDuplicatePackageID(t *testing.T) {
	r := NewRegistry()
	err := r.Replace([]Entry{
		entryFor("com.a", 20001, identity.TrustOrdinary),
		entryFor("com.a", 20002, identity.TrustOrdinary),
	})
	if !errors.Is(err, ErrDuplicatePackageID) {
		t.Fatalf("err = %v, want ErrDuplicatePackageID", err)
	}
}

func TestRegistryReplace_RejectsUIDOutOfRange(t *testing.T) {
	r := NewRegistry()
	if err := r.Replace([]Entry{entryFor("com.a", 0, identity.TrustOrdinary)}); err == nil {
		t.Fatal("UID 0 must be rejected")
	}
	if err := r.Replace([]Entry{entryFor("com.a", 99999, identity.TrustOrdinary)}); err == nil {
		t.Fatal("a value outside the App UID range must be rejected")
	}
}

func TestRegistryReplace_RejectsEmptyPackageID(t *testing.T) {
	r := NewRegistry()
	if err := r.Replace([]Entry{entryFor("", 20001, identity.TrustOrdinary)}); err == nil {
		t.Fatal("an empty package ID must be rejected")
	}
}

func TestRegistryReplace_RejectsUnspecifiedTrust(t *testing.T) {
	r := NewRegistry()
	if err := r.Replace([]Entry{entryFor("com.a", 20001, identity.TrustUnspecified)}); err == nil {
		t.Fatal("TrustUnspecified must be rejected")
	}
}

func TestRegistryReplace_FailureKeepsPreviousSnapshot(t *testing.T) {
	r := NewRegistry()
	mustReplaceRegistry(t, r, entryFor("com.good", 20001, identity.TrustOrdinary))

	err := r.Replace([]Entry{
		entryFor("com.new", 20002, identity.TrustOrdinary),
		entryFor("com.bad", 0, identity.TrustOrdinary),
	})
	if err == nil {
		t.Fatal("want error")
	}
	if r.Len() != 1 {
		t.Fatalf("Len = %d, want 1 with the previous snapshot unchanged", r.Len())
	}
	if _, ok := r.Lookup("com.good"); !ok {
		t.Fatal("the previous entry was lost")
	}
	if _, ok := r.Lookup("com.new"); ok {
		t.Fatal("an entry from the rejected snapshot leaked into the registry")
	}
}

func TestRegistryLookup_Unknown(t *testing.T) {
	r := NewRegistry()
	if _, ok := r.Lookup("com.missing"); ok {
		t.Fatal("lookup of an unknown package should return false")
	}
}

func TestUninitializedRegistry_IsFailSafe(t *testing.T) {
	var empty Registry
	if _, ok := empty.Lookup("com.a"); ok {
		t.Fatal("an uninitialized Registry should not return any entry")
	}
	if empty.Len() != 0 {
		t.Fatal("an uninitialized Registry should have length 0")
	}
	if empty.List() != nil {
		t.Fatal("List on an uninitialized Registry should be empty")
	}

	var nilReg *Registry
	if _, ok := nilReg.Lookup("com.a"); ok {
		t.Fatal("a typed-nil Registry should not return any entry")
	}
	if nilReg.Len() != 0 {
		t.Fatal("a typed-nil Registry should have length 0")
	}
}

func TestRegistry_ConcurrentReadWrite(t *testing.T) {
	r := NewRegistry()
	mustReplaceRegistry(t, r, entryFor("com.a", 20001, identity.TrustOrdinary))

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
				if e, ok := r.Lookup("com.a"); ok && e.Manifest.PackageID != "com.a" {
					t.Errorf("observed a torn entry: %+v", e)
					return
				}
			}
		}()
	}

	for i := range 200 {
		entries := []Entry{entryFor("com.a", 20001, identity.TrustOrdinary)}
		if i%2 == 0 {
			entries = append(entries, entryFor("com.b", 20002, identity.TrustOEM))
		}
		if err := r.Replace(entries); err != nil {
			t.Fatalf("Replace: %v", err)
		}
	}

	close(stop)
	wg.Wait()
}
