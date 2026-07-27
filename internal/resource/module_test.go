package resource

import (
	"context"
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	ipcregistry "github.com/nervus-os/nervus-ipc/registry"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/identity"
)

const (
	testPackageID    = "com.example.camera"
	testResourceType = "com.example.camera.resource.camera"
	testResourceRole = "camera.front"
)

func TestModuleReadsNewCatalogRevisionAfterPublish(t *testing.T) {
	definitions := mustDefaultCatalog(t)
	module := New(definitions)
	before := definitions.Current()

	if _, ok := module.Resolve(testResourceType, testResourceRole); ok {
		t.Fatal("dynamic resource resolved before its catalog candidate was published")
	}
	if module.Valid(testResourceRole) {
		t.Fatal("dynamic resource handle was valid before publication")
	}

	candidate, err := definitions.Prepare([]catalog.Source{privateResourceSource(t)})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if !definitions.Publish(candidate) {
		t.Fatal("Publish returned false")
	}

	handle, ok := module.Resolve(testResourceType, testResourceRole)
	if !ok || handle != testResourceRole {
		t.Fatalf("Resolve after publish = (%q, %v), want (%q, true)", handle, ok, testResourceRole)
	}
	if !module.Valid(testResourceRole) {
		t.Fatal("Valid after publish = false, want true")
	}
	if handle, generation, ok := module.ResolveControl(testResourceType, testResourceRole); ok ||
		handle != "" || generation != 0 {
		t.Fatalf("ResolveControl(shared-observe) = (%q, %d, %v), want (\"\", 0, false)", handle, generation, ok)
	}

	if _, ok := module.ResolveAt(before, testResourceType, testResourceRole); ok {
		t.Fatal("ResolveAt on the pinned old snapshot observed a later publication")
	}
	if module.ValidAt(before, testResourceRole) {
		t.Fatal("ValidAt on the pinned old snapshot observed a later publication")
	}
}

func TestModuleBootstrapAndUnknownValuesFailClosed(t *testing.T) {
	module := New(mustDefaultCatalog(t))

	handle, ok := module.Resolve(catalog.ResourceMotionBase, "base.main")
	if !ok || handle != "base.main" {
		t.Fatalf("Resolve bootstrap resource = (%q, %v), want (base.main, true)", handle, ok)
	}
	if !module.Valid("base.main") {
		t.Fatal("Valid(base.main) = false, want true")
	}
	if handle, generation, ok := module.ResolveControl(catalog.ResourceMotionBase, "base.main"); !ok || handle != "base.main" || generation == 0 {
		t.Fatalf("ResolveControl bootstrap resource = (%q, %d, %v), want (base.main, nonzero, true)", handle, generation, ok)
	}

	for _, test := range []struct {
		resourceType string
		role         string
	}{
		{resourceType: "unknown.resource", role: "base.main"},
		{resourceType: catalog.ResourceMotionBase, role: "unknown.role"},
		{},
	} {
		if handle, ok := module.Resolve(test.resourceType, test.role); ok || handle != "" {
			t.Fatalf("Resolve(%q, %q) = (%q, %v), want (\"\", false)",
				test.resourceType, test.role, handle, ok)
		}
	}
	if module.Valid("") || module.Valid("unknown.handle") {
		t.Fatal("unknown or empty handles must fail closed")
	}
}

func TestNilInputsFailClosed(t *testing.T) {
	var nilModule *Module
	if _, ok := nilModule.Resolve("type", "role"); ok {
		t.Fatal("Resolve on nil Module matched")
	}
	if nilModule.Valid("handle") {
		t.Fatal("Valid on nil Module matched")
	}
	if _, ok := nilModule.ResolveAt(nil, "type", "role"); ok {
		t.Fatal("ResolveAt on nil Module matched")
	}
	if _, _, ok := nilModule.ResolveControl("type", "role"); ok {
		t.Fatal("ResolveControl on nil Module matched")
	}
	if nilModule.ValidAt(nil, "handle") {
		t.Fatal("ValidAt on nil Module matched")
	}

	module := New(nil)
	if _, ok := module.Resolve("type", "role"); ok {
		t.Fatal("Resolve with nil catalog matched")
	}
	if module.Valid("handle") {
		t.Fatal("Valid with nil catalog matched")
	}
	if _, ok := module.ResolveAt(nil, "type", "role"); ok {
		t.Fatal("ResolveAt with nil snapshot matched")
	}
	if _, _, ok := module.ResolveControl("type", "role"); ok {
		t.Fatal("ResolveControl with nil catalog matched")
	}
	if module.ValidAt(nil, "handle") {
		t.Fatal("ValidAt with nil snapshot matched")
	}
}

func TestModuleLifecycle(t *testing.T) {
	module := New(mustDefaultCatalog(t))
	if got := module.Name(); got != "resource" {
		t.Fatalf("Name() = %q, want resource", got)
	}
	if err := module.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := module.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func mustDefaultCatalog(t *testing.T) *catalog.Registry {
	t.Helper()
	definitions, err := catalog.NewDefaultRegistry()
	if err != nil {
		t.Fatalf("catalog.NewDefaultRegistry: %v", err)
	}
	return definitions
}

func privateResourceSource(t *testing.T) catalog.Source {
	t.Helper()
	descriptor := &ipcv1.ProviderDescriptor{
		PackageId: testPackageID,
		Resources: []*ipcv1.ManagedResource{{
			StableRole:   testResourceRole,
			ResourceType: testResourceType,
			AccessMode:   ipcv1.ResourceAccessMode_RESOURCE_ACCESS_MODE_SHARED_OBSERVE,
			RiskClass:    ipcv1.RiskClass_RISK_CLASS_NORMAL,
		}},
	}
	return catalog.Source{
		PackageID: testPackageID,
		Kind:      catalog.SourceKindDynamicInstall,
		Trust:     identity.TrustOrdinary,
		Signers: catalog.SignerEvidence{
			DeveloperRootID: "com.example.camera.developer-root",
		},
		Artifacts: mustArtifacts(t, descriptor),
	}
}

func mustArtifacts(
	t *testing.T,
	descriptor *ipcv1.ProviderDescriptor,
) *ipcregistry.ProviderArtifacts {
	t.Helper()
	marshal := proto.MarshalOptions{Deterministic: true}
	descriptorWire, err := marshal.Marshal(descriptor)
	if err != nil {
		t.Fatalf("marshal descriptor: %v", err)
	}
	schemaWire, err := marshal.Marshal(&ipcv1.InterfaceSchemaBundleSet{})
	if err != nil {
		t.Fatalf("marshal schema set: %v", err)
	}
	artifacts, err := ipcregistry.ParseProviderArtifacts(descriptorWire, schemaWire)
	if err != nil {
		t.Fatalf("ParseProviderArtifacts: %v", err)
	}
	return artifacts
}
