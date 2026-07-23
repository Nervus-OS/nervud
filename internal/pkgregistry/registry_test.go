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
		t.Fatal("uid 0 必须被拒绝")
	}
	if err := r.Replace([]Entry{entryFor("com.a", 99999, identity.TrustOrdinary)}); err == nil {
		t.Fatal("超出 App UID 段的值必须被拒绝")
	}
}

func TestRegistryReplace_RejectsEmptyPackageID(t *testing.T) {
	r := NewRegistry()
	if err := r.Replace([]Entry{entryFor("", 20001, identity.TrustOrdinary)}); err == nil {
		t.Fatal("空 package id 必须被拒绝")
	}
}

func TestRegistryReplace_RejectsUnspecifiedTrust(t *testing.T) {
	r := NewRegistry()
	if err := r.Replace([]Entry{entryFor("com.a", 20001, identity.TrustUnspecified)}); err == nil {
		t.Fatal("TrustUnspecified 必须被拒绝")
	}
}

// 校验失败必须整份拒绝并保留旧快照
func TestRegistryReplace_FailureKeepsPreviousSnapshot(t *testing.T) {
	r := NewRegistry()
	mustReplaceRegistry(t, r, entryFor("com.good", 20001, identity.TrustOrdinary))

	err := r.Replace([]Entry{
		entryFor("com.new", 20002, identity.TrustOrdinary),
		entryFor("com.bad", 0, identity.TrustOrdinary), // 触发拒绝
	})
	if err == nil {
		t.Fatal("want error")
	}
	if r.Len() != 1 {
		t.Fatalf("Len = %d, want 1（旧快照应当原封不动）", r.Len())
	}
	if _, ok := r.Lookup("com.good"); !ok {
		t.Fatal("旧条目丢了")
	}
	if _, ok := r.Lookup("com.new"); ok {
		t.Fatal("被拒绝的快照里的条目泄漏进来了")
	}
}

func TestRegistryLookup_Unknown(t *testing.T) {
	r := NewRegistry()
	if _, ok := r.Lookup("com.missing"); ok {
		t.Fatal("查无此包应返回 false")
	}
}

// 未初始化的 Registry 必须 fail-safe，不 panic
func TestUninitializedRegistry_IsFailSafe(t *testing.T) {
	var empty Registry
	if _, ok := empty.Lookup("com.a"); ok {
		t.Fatal("未初始化 Registry 不该查到任何东西")
	}
	if empty.Len() != 0 {
		t.Fatal("未初始化 Registry 的 Len 应为 0")
	}
	if empty.List() != nil {
		t.Fatal("未初始化 Registry 的 List 应为空")
	}

	var nilReg *Registry
	if _, ok := nilReg.Lookup("com.a"); ok {
		t.Fatal("typed-nil Registry 不该查到任何东西")
	}
	if nilReg.Len() != 0 {
		t.Fatal("typed-nil Registry 的 Len 应为 0")
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
					t.Errorf("读到了撕裂的条目: %+v", e)
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
