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
		t.Fatal("空 package id 必须被拒绝")
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

// 校验失败必须整份拒绝并保留旧快照
func TestRegistryReplace_FailureKeepsPreviousSnapshot(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	if err := r.Replace([]Grant{{PackageID: "com.good", Permissions: []string{"perm.diagnostics.read"}}}); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	err := r.Replace([]Grant{
		{PackageID: "com.new", Permissions: []string{"perm.diagnostics.read"}},
		{PackageID: "", Permissions: nil}, // 触发拒绝
	})
	if err == nil {
		t.Fatal("want error")
	}
	if r.Len() != 1 {
		t.Fatalf("Len() = %d, want 1（旧快照应当原封不动）", r.Len())
	}
	if !r.Allowed("com.good", "perm.diagnostics.read") {
		t.Fatal("旧授权丢了")
	}
	if r.Allowed("com.new", "perm.diagnostics.read") {
		t.Fatal("被拒绝快照里的授权泄漏进来了")
	}
}

func TestRegistryAllowed(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	if err := r.Replace([]Grant{{PackageID: "com.a", Permissions: []string{"perm.diagnostics.read"}}}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if !r.Allowed("com.a", "perm.diagnostics.read") {
		t.Fatal("已授予的权限应放行")
	}
	if r.Allowed("com.a", "perm.service.register") {
		t.Fatal("未授予的权限不该放行")
	}
	if r.Allowed("com.missing", "perm.diagnostics.read") {
		t.Fatal("未知 Package 不该放行")
	}
}

// 撤权的即时性：Replace 之后下一次 Allowed 必须立刻看到新状态，
// 不能被任何缓存挡住（架构 §10.7 的动态撤权要求）
func TestRegistryAllowed_ReflectsRevocationImmediately(t *testing.T) {
	r := NewRegistry(DefaultCatalog())
	if err := r.Replace([]Grant{{PackageID: "com.a", Permissions: []string{"perm.diagnostics.read"}}}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if !r.Allowed("com.a", "perm.diagnostics.read") {
		t.Fatal("授权后应放行")
	}

	if err := r.Replace(nil); err != nil { // 撤权：卸载后全量清空
		t.Fatalf("Replace: %v", err)
	}
	if r.Allowed("com.a", "perm.diagnostics.read") {
		t.Fatal("撤权后下一次 Allowed 必须立刻拒绝")
	}
}

// 未初始化的 Registry 必须 fail-safe 拒绝，不 panic；这里的 fail-safe 方向
// 与 identity/pkgregistry 相同（未初始化 = 谁都不认识 = 全部拒绝）
func TestUninitializedRegistry_IsFailSafe(t *testing.T) {
	var empty Registry
	if empty.Allowed("com.a", "perm.diagnostics.read") {
		t.Fatal("未初始化 Registry 的 Allowed 必须返回 false")
	}
	if empty.Len() != 0 {
		t.Fatal("未初始化 Registry 的 Len 应为 0")
	}
	granted, denied := empty.Intersect([]string{"perm.diagnostics.read"}, identity.TrustPlatform, nil)
	if len(granted) != 0 || len(denied) != 1 {
		t.Fatalf("未初始化 Registry 的 Intersect 应全部拒绝，got granted=%v denied=%v", granted, denied)
	}

	var nilReg *Registry
	if nilReg.Allowed("com.a", "perm.diagnostics.read") {
		t.Fatal("typed-nil Registry 的 Allowed 必须返回 false")
	}
	if nilReg.Len() != 0 {
		t.Fatal("typed-nil Registry 的 Len 应为 0")
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
