package resource

import (
	"context"
	"testing"
)

func TestResolve_ExactMatch(t *testing.T) {
	reg := DefaultRegistry()

	handle, ok := reg.Resolve("nervus.resource.motion.base", "main")
	if !ok || handle != "base.main" {
		t.Fatalf("Resolve(base.main type/role) = (%q, %v), want (base.main, true)", handle, ok)
	}
}

func TestResolve_TypeOrRoleMismatchNotFound(t *testing.T) {
	reg := DefaultRegistry()

	cases := []struct {
		name         string
		resourceType string
		role         string
	}{
		{"wrong type", "nervus.resource.camera", "main"},
		{"wrong role", "nervus.resource.motion.base", "front"},
		{"both wrong", "nervus.resource.camera", "front"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, ok := reg.Resolve(c.resourceType, c.role); ok {
				t.Fatalf("Resolve(%q, %q) = ok, want not found", c.resourceType, c.role)
			}
		})
	}
}

func TestValid(t *testing.T) {
	reg := DefaultRegistry()

	if !reg.Valid("base.main") {
		t.Fatal("Valid(base.main) = false, want true")
	}
	if reg.Valid("") {
		t.Fatal("Valid(\"\") = true, want false")
	}
	if reg.Valid("not-a-real-handle") {
		t.Fatal("Valid(unregistered) = true, want false")
	}
}

// TestMultiEntry_RoutesIndependently 锁住"实现是通用查表，不是单条记录的特化
// 逻辑"这个设计前提（设计方案 §7）：即使 v1 只发一条，NewRegistry 传两条不
// 冲突的 Entry 时 Resolve/Valid 都要能正确路由到各自的记录
func TestMultiEntry_RoutesIndependently(t *testing.T) {
	reg, err := NewRegistry([]Entry{
		{Handle: "base.main", Type: "nervus.resource.motion.base", Role: "main", AccessMode: "exclusive_control"},
		{Handle: "camera.front", Type: "nervus.resource.camera", Role: "front", AccessMode: "shared_read"},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	h1, ok1 := reg.Resolve("nervus.resource.motion.base", "main")
	if !ok1 || h1 != "base.main" {
		t.Fatalf("Resolve(motion.base) = (%q, %v), want (base.main, true)", h1, ok1)
	}
	h2, ok2 := reg.Resolve("nervus.resource.camera", "front")
	if !ok2 || h2 != "camera.front" {
		t.Fatalf("Resolve(camera.front) = (%q, %v), want (camera.front, true)", h2, ok2)
	}

	if !reg.Valid("base.main") || !reg.Valid("camera.front") {
		t.Fatal("both handles should be valid")
	}
	if reg.Valid("camera.back") {
		t.Fatal("Valid(unregistered) = true, want false")
	}
}

func TestNewRegistry_RejectsInconsistentTable(t *testing.T) {
	cases := []struct {
		name string
		list []Entry
	}{
		{
			"empty handle",
			[]Entry{{Handle: "", Type: "t", Role: "r"}},
		},
		{
			"empty type",
			[]Entry{{Handle: "h", Type: "", Role: "r"}},
		},
		{
			"empty role",
			[]Entry{{Handle: "h", Type: "t", Role: ""}},
		},
		{
			"duplicate (type, role)",
			[]Entry{
				{Handle: "h1", Type: "t", Role: "r"},
				{Handle: "h2", Type: "t", Role: "r"},
			},
		},
		{
			"duplicate handle",
			[]Entry{
				{Handle: "h", Type: "t1", Role: "r1"},
				{Handle: "h", Type: "t2", Role: "r2"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewRegistry(c.list); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}

// ---- 零值 / 未初始化 fail-safe ------------------------------------------------

func TestNilRegistry_FailSafe(t *testing.T) {
	var r *Registry

	if _, ok := r.Resolve("t", "r"); ok {
		t.Fatal("nil Registry 的 Resolve 不该命中")
	}
	if r.Valid("base.main") {
		t.Fatal("nil Registry 的 Valid 不该为 true")
	}
}

func TestNilModule_FailSafe(t *testing.T) {
	var m *Module

	if _, ok := m.Resolve("t", "r"); ok {
		t.Fatal("nil Module 的 Resolve 不该命中")
	}
	if m.Valid("base.main") {
		t.Fatal("nil Module 的 Valid 不该为 true")
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("nil Module 的 Stop 不该报错: %v", err)
	}
}

func TestModule_NameAndLifecycleAndDelegation(t *testing.T) {
	m := New(DefaultRegistry())
	if m.Name() != "resource" {
		t.Fatalf("Name() = %q, want resource", m.Name())
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	handle, ok := m.Resolve("nervus.resource.motion.base", "main")
	if !ok || handle != "base.main" {
		t.Fatalf("Module.Resolve = (%q, %v), want (base.main, true)", handle, ok)
	}
	if !m.Valid("base.main") {
		t.Fatal("Module.Valid(base.main) = false, want true")
	}
}
