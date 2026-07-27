package resource

import (
	"context"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/catalog"
)

// Module exposes resource lookups from the shared, atomically published
// definition catalog. It owns no independent resource table.
type Module struct {
	definitions *catalog.Registry
}

func New(definitions *catalog.Registry) *Module {
	return &Module{definitions: definitions}
}

func (m *Module) Name() string { return "resource" }

func (m *Module) Start(_ context.Context) error { return nil }

func (m *Module) Stop(_ context.Context) error { return nil }

// Resolve reads one current catalog revision and resolves against that
// immutable snapshot.
func (m *Module) Resolve(resourceType, role string) (handle string, ok bool) {
	if m == nil || m.definitions == nil {
		return "", false
	}
	return m.ResolveAt(m.definitions.Current(), resourceType, role)
}

// ResolveAt lets a caller pin multiple decisions to one catalog revision.
func (m *Module) ResolveAt(
	snapshot *catalog.Snapshot,
	resourceType string,
	role string,
) (handle string, ok bool) {
	if m == nil || snapshot == nil {
		return "", false
	}
	definition, ok := snapshot.ResolveResource(resourceType, role)
	if !ok || definition.Handle == "" {
		return "", false
	}
	return definition.Handle, true
}

// ResolveControl resolves only resources whose catalog-owned access mode
// permits an exclusive ControlLease. Sensors declared SHARED_OBSERVE remain
// resolvable for endpoint routing, but can never acquire control authority.
func (m *Module) ResolveControl(
	resourceType, role string,
) (handle string, generation uint64, ok bool) {
	if m == nil || m.definitions == nil {
		return "", 0, false
	}
	definition, ok := m.definitions.Current().ResolveResource(resourceType, role)
	if !ok || definition.Handle == "" ||
		definition.AccessMode != ipcv1.ResourceAccessMode_RESOURCE_ACCESS_MODE_EXCLUSIVE_CONTROL {
		return "", 0, false
	}
	return definition.Handle, definition.DefinitionGeneration, true
}

// Valid reads one current catalog revision and checks the exact handle.
func (m *Module) Valid(handle string) bool {
	if m == nil || m.definitions == nil {
		return false
	}
	return m.ValidAt(m.definitions.Current(), handle)
}

// ValidAt lets a caller pin handle validation to one catalog revision.
func (m *Module) ValidAt(snapshot *catalog.Snapshot, handle string) bool {
	if m == nil || snapshot == nil || handle == "" {
		return false
	}
	_, ok := snapshot.ResourceByHandle(handle)
	return ok
}
