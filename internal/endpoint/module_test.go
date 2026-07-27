package endpoint

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	basemotionv1 "github.com/nervus-os/nervus-ipc/protocol/interface/basemotionv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	ipcregistry "github.com/nervus-os/nervus-ipc/registry"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

const (
	testProviderPackage   = "com.example.motion"
	testProviderComponent = "main"
	testCallerPackage     = "com.example.caller"
	testMotionPermission  = "perm.motion.control"
)

var errComponentDisabledStub = errors.New("component disabled (stub)")

type fakePkgs struct {
	mu      sync.Mutex
	entries map[string]pkgregistry.Entry
}

func newFakePkgs(entries ...pkgregistry.Entry) *fakePkgs {
	f := &fakePkgs{entries: make(map[string]pkgregistry.Entry)}
	for _, entry := range entries {
		f.entries[entry.Manifest.PackageID] = entry
	}
	return f
}

func (f *fakePkgs) Lookup(id string) (pkgregistry.Entry, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	entry, ok := f.entries[id]
	return entry, ok
}

func (f *fakePkgs) List() []pkgregistry.Entry {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]pkgregistry.Entry, 0, len(f.entries))
	for _, entry := range f.entries {
		out = append(out, entry)
	}
	return out
}

type fakePerm struct {
	mu      sync.Mutex
	granted map[string]map[string]bool
}

func newFakePerm() *fakePerm {
	return &fakePerm{granted: make(map[string]map[string]bool)}
}

func (f *fakePerm) grant(pkg, permission string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.granted[pkg] == nil {
		f.granted[pkg] = make(map[string]bool)
	}
	f.granted[pkg][permission] = true
}

func (f *fakePerm) revoke(pkg, permission string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.granted[pkg], permission)
}

func (f *fakePerm) AllowedAt(
	snapshot *catalog.Snapshot,
	pkg string,
	permission string,
) bool {
	if snapshot == nil {
		return false
	}
	if _, ok := snapshot.Permission(permission); !ok {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.granted[pkg][permission]
}

type fakeStarter struct {
	fn func(ctx context.Context, pkg, comp string) error
}

func (f *fakeStarter) EnsureStarted(ctx context.Context, pkg, comp string) error {
	if f == nil || f.fn == nil {
		return nil
	}
	return f.fn(ctx, pkg, comp)
}

type fakeAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (f *fakeAudit) Record(_ context.Context, event audit.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
}

func serviceEntry(pkg, comp, interfaceID string, visibility pkgregistry.Visibility) pkgregistry.Entry {
	return pkgregistry.Entry{Manifest: pkgregistry.Manifest{
		PackageID: pkg,
		Components: []pkgregistry.Component{{
			ID:   comp,
			Type: pkgregistry.ComponentService,
			Exports: []pkgregistry.Export{{
				Interface:  interfaceID,
				Visibility: visibility,
			}},
		}},
	}}
}

func testModule(
	t *testing.T,
	definitions *catalog.Registry,
	pkgs *fakePkgs,
	perm *fakePerm,
	starter *fakeStarter,
) *Module {
	t.Helper()
	return New(definitions, pkgs, perm, starter, &fakeAudit{}, nil)
}

func defaultCatalog(t *testing.T) *catalog.Registry {
	t.Helper()
	definitions, err := catalog.NewDefaultRegistry()
	if err != nil {
		t.Fatalf("NewDefaultRegistry: %v", err)
	}
	return definitions
}

func publishSources(t *testing.T, definitions *catalog.Registry, sources ...catalog.Source) {
	t.Helper()
	candidate, err := definitions.Prepare(sources)
	if err != nil {
		t.Fatalf("Prepare catalog: %v", err)
	}
	if !definitions.Publish(candidate) {
		t.Fatal("Publish catalog candidate = false")
	}
}

func motionSource(t *testing.T, pkg, comp, keyID string) catalog.Source {
	t.Helper()
	bundle, err := ipcregistry.BuildSchemaBundle(
		catalog.InterfaceMotionBase,
		1,
		basemotionv1.BaseMotionMethod(0).Descriptor(),
	)
	if err != nil {
		t.Fatalf("BuildSchemaBundle: %v", err)
	}
	descriptor := &ipcv1.ProviderDescriptor{
		PackageId: pkg,
		Interfaces: []*ipcv1.ProvidedInterface{{
			InterfaceId: catalog.InterfaceMotionBase,
			InterfaceVersions: []*ipcv1.ProvidedInterfaceVersion{{
				Major:      1,
				SchemaHash: append([]byte(nil), bundle.GetSchemaHash()...),
			}},
			RequiredPermission:      testMotionPermission,
			ResourceRiskFloor:       ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
			CompatibleResourceTypes: []string{catalog.ResourceMotionBase},
			DefaultResourceType:     catalog.ResourceMotionBase,
			DefaultResourceRole:     "base.main",
		}},
		Resources: []*ipcv1.ManagedResource{{
			StableRole:   "base.main",
			ResourceType: catalog.ResourceMotionBase,
			AccessMode:   ipcv1.ResourceAccessMode_RESOURCE_ACCESS_MODE_EXCLUSIVE_CONTROL,
			RiskClass:    ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
		}},
	}
	return catalog.Source{
		PackageID: pkg,
		Kind:      catalog.SourceKindSystemImage,
		Trust:     identity.TrustOEM,
		Signers: catalog.SignerEvidence{
			Roles: []string{"oem-service"},
			VerifiedSigners: []catalog.VerifiedSigner{{
				Role: "oem-service", KeyID: keyID,
			}},
		},
		Exports: []catalog.ExportBinding{{
			ComponentID: comp,
			InterfaceID: catalog.InterfaceMotionBase,
		}},
		Artifacts: mustArtifacts(t, descriptor, &ipcv1.InterfaceSchemaBundleSet{
			Bundles: []*ipcv1.InterfaceSchemaBundle{bundle},
		}),
	}
}

func legacyPackageManagerSource(t *testing.T) catalog.Source {
	t.Helper()
	artifacts, err := catalog.LegacyPackageManagerArtifacts()
	if err != nil {
		t.Fatalf("LegacyPackageManagerArtifacts: %v", err)
	}
	return catalog.Source{
		PackageID: legacyPackageManagerPackage,
		Kind:      catalog.SourceKindSystemImage,
		Trust:     identity.TrustPlatform,
		Signers: catalog.SignerEvidence{
			Roles: []string{platformReleaseSignerRole},
			VerifiedSigners: []catalog.VerifiedSigner{{
				Role: platformReleaseSignerRole, KeyID: "platform-key",
			}},
		},
		Exports: []catalog.ExportBinding{{
			ComponentID: legacyPackageManagerComponent,
			InterfaceID: catalog.InterfacePackageManager,
		}},
		Artifacts: artifacts,
	}
}

func mustArtifacts(
	t *testing.T,
	descriptor *ipcv1.ProviderDescriptor,
	schemas *ipcv1.InterfaceSchemaBundleSet,
) *ipcregistry.ProviderArtifacts {
	t.Helper()
	marshal := proto.MarshalOptions{Deterministic: true}
	descriptorWire, err := marshal.Marshal(descriptor)
	if err != nil {
		t.Fatalf("marshal descriptor: %v", err)
	}
	schemaWire, err := marshal.Marshal(schemas)
	if err != nil {
		t.Fatalf("marshal schemas: %v", err)
	}
	artifacts, err := ipcregistry.ParseProviderArtifacts(descriptorWire, schemaWire)
	if err != nil {
		t.Fatalf("ParseProviderArtifacts: %v", err)
	}
	return artifacts
}

func schemaHash(t *testing.T, definitions *catalog.Registry, interfaceID string, major uint32) []byte {
	t.Helper()
	definition, ok := definitions.Current().Interface(interfaceID, major)
	if !ok {
		t.Fatalf("catalog interface %s@%d missing", interfaceID, major)
	}
	return definition.SchemaHash
}

func registerMotion(
	t *testing.T,
	module *Module,
	definitions *catalog.Registry,
	conn ConnHandle,
	pkg, comp string,
) uint64 {
	t.Helper()
	result := module.RegisterEndpoint(
		conn,
		identity.Caller{PackageID: pkg, ComponentID: comp},
		&ipcv1.RegisterEndpoint{
			RequestId:           1,
			InterfaceId:         catalog.InterfaceMotionBase,
			InterfaceMajor:      1,
			InterfaceSchemaHash: schemaHash(t, definitions, catalog.InterfaceMotionBase, 1),
			ResourceHandle:      "base.main",
		},
	)
	if result.GetSuccess() == nil {
		t.Fatalf("RegisterEndpoint: %+v", result.GetFailure())
	}
	return result.GetSuccess().GetEndpointId()
}

func resolveMotion(t *testing.T, module *Module, conn ConnHandle, caller string) *ipcv1.ResolveEndpointSuccess {
	t.Helper()
	result := module.ResolveEndpoint(
		conn,
		identity.Caller{PackageID: caller},
		&ipcv1.ResolveEndpoint{
			RequestId:         1,
			InterfaceId:       catalog.InterfaceMotionBase,
			MinInterfaceMajor: 1,
			MaxInterfaceMajor: 1,
		},
	)
	if result.GetSuccess() == nil {
		t.Fatalf("ResolveEndpoint: %+v", result.GetFailure())
	}
	return result.GetSuccess()
}

func configuredMotionModule(t *testing.T) (*Module, *catalog.Registry, *fakePerm) {
	t.Helper()
	definitions := defaultCatalog(t)
	publishSources(t, definitions,
		motionSource(t, testProviderPackage, testProviderComponent, "oem-key"))
	permissions := newFakePerm()
	permissions.grant(testProviderPackage, permServiceRegister)
	permissions.grant(testCallerPackage, testMotionPermission)
	module := testModule(
		t,
		definitions,
		newFakePkgs(serviceEntry(
			testProviderPackage,
			testProviderComponent,
			catalog.InterfaceMotionBase,
			pkgregistry.VisibilityPublic,
		)),
		permissions,
		&fakeStarter{},
	)
	return module, definitions, permissions
}

func TestRegisterEndpointValidatesCatalogSchemaAndResource(t *testing.T) {
	module, definitions, _ := configuredMotionModule(t)
	caller := identity.Caller{
		PackageID: testProviderPackage, ComponentID: testProviderComponent,
	}

	valid := &ipcv1.RegisterEndpoint{
		RequestId:           1,
		InterfaceId:         catalog.InterfaceMotionBase,
		InterfaceMajor:      1,
		InterfaceSchemaHash: schemaHash(t, definitions, catalog.InterfaceMotionBase, 1),
		ResourceHandle:      "base.main",
	}
	if result := module.RegisterEndpoint("valid", caller, valid); result.GetSuccess() == nil {
		t.Fatalf("valid registration rejected: %+v", result.GetFailure())
	}

	wrongSchema := proto.Clone(valid).(*ipcv1.RegisterEndpoint)
	wrongSchema.RequestId = 2
	wrongSchema.InterfaceSchemaHash = []byte("wrong")
	if code := module.RegisterEndpoint("wrong-schema", caller, wrongSchema).
		GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION {
		t.Fatalf("wrong schema code = %v, want FAILED_PRECONDITION", code)
	}

	missingResource := proto.Clone(valid).(*ipcv1.RegisterEndpoint)
	missingResource.RequestId = 3
	missingResource.ResourceHandle = ""
	if code := module.RegisterEndpoint("missing-resource", caller, missingResource).
		GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT {
		t.Fatalf("missing resource code = %v, want INVALID_ARGUMENT", code)
	}

	unknownResource := proto.Clone(valid).(*ipcv1.RegisterEndpoint)
	unknownResource.RequestId = 4
	unknownResource.ResourceHandle = "camera.front"
	if code := module.RegisterEndpoint("unknown-resource", caller, unknownResource).
		GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT {
		t.Fatalf("unknown resource code = %v, want INVALID_ARGUMENT", code)
	}
}

func TestRegisterEndpointRejectsComponentOutsideCatalogMembership(t *testing.T) {
	definitions := defaultCatalog(t)
	publishSources(t, definitions,
		motionSource(t, testProviderPackage, testProviderComponent, "oem-key"))
	entry := serviceEntry(
		testProviderPackage, "other", catalog.InterfaceMotionBase, pkgregistry.VisibilityPublic)
	permissions := newFakePerm()
	permissions.grant(testProviderPackage, permServiceRegister)
	module := testModule(t, definitions, newFakePkgs(entry), permissions, &fakeStarter{})

	result := module.RegisterEndpoint(
		"conn",
		identity.Caller{PackageID: testProviderPackage, ComponentID: "other"},
		&ipcv1.RegisterEndpoint{
			RequestId:           1,
			InterfaceId:         catalog.InterfaceMotionBase,
			InterfaceMajor:      1,
			InterfaceSchemaHash: schemaHash(t, definitions, catalog.InterfaceMotionBase, 1),
			ResourceHandle:      "base.main",
		},
	)
	if code := result.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED {
		t.Fatalf("component mismatch code = %v, want PERMISSION_DENIED", code)
	}
}

func TestLegacyPackageManagerEmptySchemaBridgeIsNarrow(t *testing.T) {
	definitions := defaultCatalog(t)
	publishSources(t, definitions, legacyPackageManagerSource(t))
	permissions := newFakePerm()
	permissions.grant(legacyPackageManagerPackage, permServiceRegister)
	module := testModule(
		t,
		definitions,
		newFakePkgs(serviceEntry(
			legacyPackageManagerPackage,
			legacyPackageManagerComponent,
			catalog.InterfacePackageManager,
			pkgregistry.VisibilityPublic,
		)),
		permissions,
		&fakeStarter{},
	)

	result := module.RegisterEndpoint(
		"legacy",
		identity.Caller{
			PackageID:   legacyPackageManagerPackage,
			ComponentID: legacyPackageManagerComponent,
		},
		&ipcv1.RegisterEndpoint{
			RequestId:      1,
			InterfaceId:    catalog.InterfacePackageManager,
			InterfaceMajor: legacyPackageManagerMajor,
		},
	)
	if result.GetSuccess() == nil {
		t.Fatalf("legacy empty hash rejected: %+v", result.GetFailure())
	}

	wrong := module.RegisterEndpoint(
		"legacy-wrong",
		identity.Caller{
			PackageID:   legacyPackageManagerPackage,
			ComponentID: legacyPackageManagerComponent,
		},
		&ipcv1.RegisterEndpoint{
			RequestId:           2,
			InterfaceId:         catalog.InterfacePackageManager,
			InterfaceMajor:      legacyPackageManagerMajor,
			InterfaceSchemaHash: []byte("wrong"),
		},
	)
	if code := wrong.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION {
		t.Fatalf("wrong non-empty legacy hash code = %v, want FAILED_PRECONDITION", code)
	}
}

func TestResolveAndRouteUseOneCatalogContract(t *testing.T) {
	module, definitions, _ := configuredMotionModule(t)
	registerMotion(t, module, definitions, "service", testProviderPackage, testProviderComponent)

	resolved := resolveMotion(t, module, "caller", testCallerPackage)
	if resolved.GetResourceHandle() != "base.main" ||
		resolved.GetCatalogRevision() != definitions.Current().Revision() ||
		string(resolved.GetInterfaceSchemaHash()) !=
			string(schemaHash(t, definitions, catalog.InterfaceMotionBase, 1)) {
		t.Fatalf("resolve success = %+v", resolved)
	}

	route, routeErr := module.Route("caller", resolved.GetEndpointId(), 1)
	if routeErr.Code != ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		t.Fatalf("Route code = %v", routeErr.Code)
	}
	if route.TargetConn != ConnHandle("service") ||
		route.ProviderPackageID != testProviderPackage ||
		route.ProviderComponentID != testProviderComponent ||
		route.InterfaceID != catalog.InterfaceMotionBase ||
		route.Method.MethodID != 1 ||
		route.Method.Request == nil ||
		route.DefinitionGeneration == 0 ||
		route.ProviderGeneration == 0 ||
		route.ResourceGeneration == 0 {
		t.Fatalf("RouteInfo = %+v", route)
	}
	if len(route.RequiredPermissions) != 1 ||
		route.RequiredPermissions[0] != testMotionPermission {
		t.Fatalf("required permissions = %v", route.RequiredPermissions)
	}

	if _, routeErr = module.Route("caller", resolved.GetEndpointId(), 999); routeErr.Code != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("unknown method code = %v, want NOT_FOUND", routeErr.Code)
	}
}

func TestResolveRejectsVersionAndIncompatibleSelector(t *testing.T) {
	module, definitions, _ := configuredMotionModule(t)
	registerMotion(t, module, definitions, "service", testProviderPackage, testProviderComponent)

	version := module.ResolveEndpoint(
		"version",
		identity.Caller{PackageID: testCallerPackage},
		&ipcv1.ResolveEndpoint{
			RequestId:         1,
			InterfaceId:       catalog.InterfaceMotionBase,
			MinInterfaceMajor: 2,
			MaxInterfaceMajor: 2,
		},
	)
	assertResolveReason(
		t, version, ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_VERSION_MISMATCH)

	resource := module.ResolveEndpoint(
		"resource",
		identity.Caller{PackageID: testCallerPackage},
		&ipcv1.ResolveEndpoint{
			RequestId:         2,
			InterfaceId:       catalog.InterfaceMotionBase,
			MinInterfaceMajor: 1,
			MaxInterfaceMajor: 1,
			Selector: &ipcv1.ResourceSelector{
				Type: catalog.ResourceManipulatorArm,
				Role: "arm.main",
			},
		},
	)
	assertResolveReason(
		t, resource, ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_RESOURCE_NOT_FOUND)
}

func TestRouteSeesPermissionRevocationAndCatalogGenerationChange(t *testing.T) {
	module, definitions, permissions := configuredMotionModule(t)
	registerMotion(t, module, definitions, "service", testProviderPackage, testProviderComponent)
	resolved := resolveMotion(t, module, "caller", testCallerPackage)

	if _, routeErr := module.Route("caller", resolved.GetEndpointId(), 1); routeErr.Code != ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		t.Fatalf("initial Route code = %v", routeErr.Code)
	}
	permissions.revoke(testCallerPackage, testMotionPermission)
	if _, routeErr := module.Route("caller", resolved.GetEndpointId(), 1); routeErr.Code != ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED {
		t.Fatalf("revoked Route code = %v, want PERMISSION_DENIED", routeErr.Code)
	}

	permissions.grant(testCallerPackage, testMotionPermission)
	publishSources(t, definitions,
		motionSource(t, testProviderPackage, testProviderComponent, "rotated-oem-key"))
	if _, routeErr := module.Route("caller", resolved.GetEndpointId(), 1); routeErr.Code != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("stale generation Route code = %v, want NOT_FOUND", routeErr.Code)
	}
}

func TestResolveAmbiguousRegistrationsFailsClosed(t *testing.T) {
	module, definitions, _ := configuredMotionModule(t)
	registerMotion(
		t, module, definitions, "one", testProviderPackage, testProviderComponent)
	registerMotion(
		t, module, definitions, "two", testProviderPackage, testProviderComponent)

	result := module.ResolveEndpoint(
		"caller",
		identity.Caller{PackageID: testCallerPackage},
		&ipcv1.ResolveEndpoint{
			RequestId:         1,
			InterfaceId:       catalog.InterfaceMotionBase,
			MinInterfaceMajor: 1,
			MaxInterfaceMajor: 1,
		},
	)
	assertResolveReason(
		t, result, ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_RESOURCE_AMBIGUOUS)
}

func TestResolveOnDemandRegistrationUsesCapturedSnapshot(t *testing.T) {
	definitions := defaultCatalog(t)
	publishSources(t, definitions,
		motionSource(t, testProviderPackage, testProviderComponent, "oem-key"))
	permissions := newFakePerm()
	permissions.grant(testProviderPackage, permServiceRegister)
	permissions.grant(testCallerPackage, testMotionPermission)
	hash := schemaHash(t, definitions, catalog.InterfaceMotionBase, 1)
	registration := make(chan *ipcv1.RegisterEndpointResult, 1)

	var module *Module
	starter := &fakeStarter{fn: func(_ context.Context, pkg, comp string) error {
		go func() {
			time.Sleep(10 * time.Millisecond)
			registration <- module.RegisterEndpoint(
				"service",
				identity.Caller{PackageID: pkg, ComponentID: comp},
				&ipcv1.RegisterEndpoint{
					RequestId:           1,
					InterfaceId:         catalog.InterfaceMotionBase,
					InterfaceMajor:      1,
					InterfaceSchemaHash: hash,
					ResourceHandle:      "base.main",
				},
			)
		}()
		return nil
	}}
	module = testModule(
		t,
		definitions,
		newFakePkgs(serviceEntry(
			testProviderPackage,
			testProviderComponent,
			catalog.InterfaceMotionBase,
			pkgregistry.VisibilityPublic,
		)),
		permissions,
		starter,
	)

	resolved := resolveMotion(t, module, "caller", testCallerPackage)
	if resolved.GetResourceHandle() != "base.main" {
		t.Fatalf("on-demand resource = %q", resolved.GetResourceHandle())
	}
	if registered := <-registration; registered.GetSuccess() == nil {
		t.Fatalf("on-demand registration: %+v", registered.GetFailure())
	}
}

func TestResolveOnDemandDoesNotStartBeforeCatalogAndPermissionProof(t *testing.T) {
	for _, test := range []struct {
		name          string
		publishSource bool
		wantCode      ipcv1.StatusCode
	}{
		{
			name:          "caller permission missing",
			publishSource: true,
			wantCode:      ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED,
		},
		{
			name:          "provider artifacts missing",
			publishSource: false,
			wantCode:      ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			definitions := defaultCatalog(t)
			if test.publishSource {
				publishSources(t, definitions,
					motionSource(t, testProviderPackage, testProviderComponent, "oem-key"))
			}
			starts := 0
			module := testModule(
				t,
				definitions,
				newFakePkgs(serviceEntry(
					testProviderPackage,
					testProviderComponent,
					catalog.InterfaceMotionBase,
					pkgregistry.VisibilityPublic,
				)),
				newFakePerm(),
				&fakeStarter{fn: func(context.Context, string, string) error {
					starts++
					return nil
				}},
			)

			result := module.ResolveEndpoint(
				"caller",
				identity.Caller{PackageID: testCallerPackage},
				&ipcv1.ResolveEndpoint{
					RequestId:         1,
					InterfaceId:       catalog.InterfaceMotionBase,
					MinInterfaceMajor: 1,
					MaxInterfaceMajor: 1,
				},
			)
			if result.GetFailure().GetCode() != test.wantCode {
				t.Fatalf("Resolve code = %v, want %v",
					result.GetFailure().GetCode(), test.wantCode)
			}
			if starts != 0 {
				t.Fatalf("unauthorized Resolve started Provider %d times", starts)
			}
		})
	}
}

func TestUnregisterAndConnectionCloseInvalidateBindings(t *testing.T) {
	module, definitions, _ := configuredMotionModule(t)
	serviceID := registerMotion(
		t, module, definitions, "service", testProviderPackage, testProviderComponent)
	resolved := resolveMotion(t, module, "caller", testCallerPackage)

	unregistered := module.UnregisterEndpoint(
		"service",
		&ipcv1.UnregisterEndpoint{RequestId: 2, EndpointId: serviceID},
	)
	if unregistered.GetSuccess() == nil {
		t.Fatalf("UnregisterEndpoint: %+v", unregistered.GetFailure())
	}
	if _, routeErr := module.Route("caller", resolved.GetEndpointId(), 1); routeErr.Code != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("Route after unregister = %v", routeErr.Code)
	}

	registerMotion(t, module, definitions, "service-2", testProviderPackage, testProviderComponent)
	resolved = resolveMotion(t, module, "caller-2", testCallerPackage)
	module.ConnClosed("service-2")
	if _, routeErr := module.Route("caller-2", resolved.GetEndpointId(), 1); routeErr.Code != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("Route after service close = %v", routeErr.Code)
	}
}

func TestNilModuleFailsClosed(t *testing.T) {
	var module *Module
	if module.RegisterEndpoint(
		"conn", identity.Caller{}, &ipcv1.RegisterEndpoint{RequestId: 1},
	).GetSuccess() != nil {
		t.Fatal("nil RegisterEndpoint succeeded")
	}
	if module.ResolveEndpoint(
		"conn", identity.Caller{}, &ipcv1.ResolveEndpoint{RequestId: 1},
	).GetSuccess() != nil {
		t.Fatal("nil ResolveEndpoint succeeded")
	}
	if _, routeErr := module.Route("conn", 1, 1); routeErr.Code == ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		t.Fatal("nil Route succeeded")
	}
	module.ConnClosed("conn")
	if err := module.Stop(context.Background()); err != nil {
		t.Fatalf("nil Stop: %v", err)
	}
}

func TestStartRejectsIncompleteAssembly(t *testing.T) {
	definitions := defaultCatalog(t)
	complete := testModule(
		t, definitions, newFakePkgs(), newFakePerm(), &fakeStarter{})
	if err := complete.Start(context.Background()); err != nil {
		t.Fatalf("complete Start: %v", err)
	}
	incomplete := New(definitions, nil, newFakePerm(), &fakeStarter{}, nil, nil)
	if err := incomplete.Start(context.Background()); err == nil {
		t.Fatal("incomplete endpoint assembly started")
	}
}

func assertResolveReason(
	t *testing.T,
	result *ipcv1.ResolveEndpointResult,
	want ipcv1.ResolveEndpointReason,
) {
	t.Helper()
	if result.GetFailure() == nil {
		t.Fatalf("Resolve unexpectedly succeeded: %+v", result.GetSuccess())
	}
	detail := &ipcv1.ResolveEndpointErrorDetail{}
	if err := proto.Unmarshal(result.GetFailure().GetErrorDetail(), detail); err != nil {
		t.Fatalf("unmarshal ResolveEndpointErrorDetail: %v", err)
	}
	if detail.GetReason() != want {
		t.Fatalf("resolve reason = %v, want %v", detail.GetReason(), want)
	}
}
