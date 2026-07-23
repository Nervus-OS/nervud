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

// --- Replace 校验 ---------------------------------------------------------

// 两个 Package 共用一个 UID 会让 SO_PEERCRED 失去 Package 级隔离能力
// （架构 10.2 明确禁止）。必须在装载时就拒绝，而不是等解析时才发现
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

// 两个 UID 映射同一个 Package ID 也必须拒绝：架构 9 要求 Package 与 UID
// 一一对应，否则权限归属/Endpoint 所有权/审计归因都会指向有歧义的 Package
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
		t.Fatal("UID 0 必须被拒绝")
	}
}

func TestReplace_RejectsEmptyID(t *testing.T) {
	r := NewRegistry()
	if err := r.Replace([]Package{{ID: "", UID: 20001, Trust: TrustOrdinary}}); err == nil {
		t.Fatal("空 ID 必须被拒绝")
	}
}

// 零值 TrustProfile 不是合法结论：漏填必须 fail closed，
// 不能因为没赋值就默默拿到 Ordinary
func TestReplace_RejectsUnspecifiedTrust(t *testing.T) {
	r := NewRegistry()
	if err := r.Replace([]Package{{ID: "com.a", UID: 20001}}); err == nil {
		t.Fatal("TrustUnspecified 必须被拒绝")
	}
	if err := r.Replace([]Package{{ID: "com.a", UID: 20001, Trust: TrustProfile(99)}}); err == nil {
		t.Fatal("未定义的 TrustProfile 必须被拒绝")
	}
}

// 校验失败必须整份拒绝并保留旧快照：宁可继续用上一份已知良好的索引，
// 也不要装载一份自相矛盾的，更不能变成「装了一半」
func TestReplace_FailureKeepsPreviousSnapshot(t *testing.T) {
	r := NewRegistry()
	mustReplace(t, r, Package{ID: "com.good", UID: 20001, Trust: TrustOrdinary})

	err := r.Replace([]Package{
		{ID: "com.new", UID: 20002, Trust: TrustOrdinary},
		{ID: "com.bad", UID: 0, Trust: TrustOrdinary}, // 触发拒绝
	})
	if err == nil {
		t.Fatal("want error")
	}
	if r.Len() != 1 {
		t.Fatalf("Len = %d, want 1（旧快照应当原封不动）", r.Len())
	}
	if _, ok := r.Lookup(20001); !ok {
		t.Fatal("旧条目丢了")
	}
	if _, ok := r.Lookup(20002); ok {
		t.Fatal("被拒绝的快照里的条目泄漏进来了")
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
		t.Fatalf("内核凭证没有原样带过来: %+v", c)
	}
	// ComponentID 必须留空：连接刚建立时只知道是哪个 Package，
	// 具体是哪个 Component 要等握手核对后才能填
	if c.ComponentID != "" {
		t.Fatalf("ComponentID = %q, want 空", c.ComponentID)
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

// 未初始化的 Registry 必须 fail-safe（当空索引、全部拒绝），绝不 panic：
// 一个装配错误不该被首个连接放大成 accept 路径崩溃
func TestUninitializedRegistry_IsFailSafe(t *testing.T) {
	// &Registry{} 未经 NewRegistry：snap 是零值 atomic.Pointer，Load 返回 nil
	var empty Registry
	if _, ok := empty.Lookup(20001); ok {
		t.Fatal("未初始化 Registry 不该查到任何东西")
	}
	if empty.Len() != 0 {
		t.Fatal("未初始化 Registry 的 Len 应为 0")
	}
	if _, err := empty.Resolve(sysprobe.Ucred{UID: 20001}); !errors.Is(err, ErrUnknownUID) {
		t.Fatalf("err = %v, want ErrUnknownUID", err)
	}

	// typed-nil *Registry 同样不能 panic
	var nilReg *Registry
	if _, ok := nilReg.Lookup(20001); ok {
		t.Fatal("typed-nil Registry 不该查到任何东西")
	}
	if nilReg.Len() != 0 {
		t.Fatal("typed-nil Registry 的 Len 应为 0")
	}
	if _, err := nilReg.Resolve(sysprobe.Ucred{UID: 20001}); !errors.Is(err, ErrUnknownUID) {
		t.Fatalf("err = %v, want ErrUnknownUID", err)
	}
}

// --- 并发 -----------------------------------------------------------------

// 读侧无锁是本包的设计前提（装包时的写不能卡住所有新连接）。
// 这条在 -race 下跑，用来证明 Replace 与 Resolve 并发时没有数据竞争
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
				// 无论读到哪一份快照，结果都必须是自洽的：
				// 要么查得到且 ID 正确，要么查不到，不存在中间态
				if p, ok := r.Lookup(20001); ok && p.ID != "com.a" {
					t.Errorf("读到了撕裂的条目: %+v", p)
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
		t.Fatal("零值不该是合法 profile")
	}
	for _, tp := range []TrustProfile{TrustOrdinary, TrustOEM, TrustPlatform} {
		if !tp.Valid() {
			t.Fatalf("%v 应当合法", tp)
		}
		if tp.String() == "unspecified" {
			t.Fatalf("%d 的 String() 落到了 unspecified", tp)
		}
	}
}

func TestCaller_String(t *testing.T) {
	if got := (Caller{}).String(); got != "kernel" {
		t.Fatalf("空 Caller = %q, want kernel", got)
	}
	c := Caller{PackageID: "com.example.app", UID: 20001}
	if got, want := c.String(), "pkg:com.example.app uid:20001"; got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
}
