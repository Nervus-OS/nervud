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

func TestNilRegistry_FailSafe(t *testing.T) {
	var r *Registry

	if _, ok := r.Resolve("t", "r"); ok {
		t.Fatal("Resolve on a nil Registry should not match")
	}
	if r.Valid("base.main") {
		t.Fatal("Valid on a nil Registry should not return true")
	}
}

func TestNilModule_FailSafe(t *testing.T) {
	var m *Module

	if _, ok := m.Resolve("t", "r"); ok {
		t.Fatal("Resolve on a nil Module should not match")
	}
	if m.Valid("base.main") {
		t.Fatal("Valid on a nil Module should not return true")
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop on a nil Module should not return an error: %v", err)
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
