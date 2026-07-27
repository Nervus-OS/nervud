package catalog

import (
	"bytes"
	"strings"
	"testing"

	basemotionv1 "github.com/nervus-os/nervus-ipc/protocol/interface/basemotionv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	dogv1 "github.com/nervus-os/nervus-ipc/protocol/oem/acme/dog/v1"
	ipcregistry "github.com/nervus-os/nervus-ipc/registry"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/identity"
)

const (
	testOEMPackage    = "com.acme.dog"
	testOEMInterface  = "com.acme.dog.interface.raw_gait"
	testOEMPermission = "com.acme.dog.permission.raw_gait"
	testOEMResource   = "com.acme.dog.resource.gait_engine"
	testMotionPackage = "com.acme.motion"
)

func TestDefaultBootstrapContainsStandardAndKernelDefinitions(t *testing.T) {
	registry, err := NewDefaultRegistry()
	if err != nil {
		t.Fatalf("NewDefaultRegistry: %v", err)
	}
	snapshot := registry.Current()
	if snapshot.Revision() != 1 {
		t.Fatalf("revision = %d, want 1", snapshot.Revision())
	}
	iface, ok := snapshot.Interface(InterfaceMotionBase, 1)
	if !ok || len(iface.SchemaHash) != 32 {
		t.Fatal("base-motion schema missing from bootstrap")
	}
	resource, ok := snapshot.ResolveResource(ResourceMotionBase, "base.main")
	if !ok || resource.Handle != "base.main" || resource.ManagerPackageID != "" {
		t.Fatalf("bootstrap base resource = %+v, %v", resource, ok)
	}
	permission, ok := snapshot.Permission("perm.motion.control")
	if !ok || permission.GrantMode != ipcv1.GrantMode_GRANT_MODE_USER_CONSENT {
		t.Fatalf("motion permission = %+v, %v", permission, ok)
	}
	safety, ok := snapshot.ProviderMethod(
		KernelPackageID,
		InterfaceSafetyControl,
		1,
		uint32(1),
	)
	if !ok || !safety.KernelBuiltin {
		t.Fatal("kernel Safety provider method missing")
	}
	transfer, ok := snapshot.ProviderMethod(
		KernelPackageID,
		InterfaceTransferControl,
		1,
		uint32(1),
	)
	if !ok || !transfer.KernelBuiltin {
		t.Fatal("kernel Transfer provider method missing")
	}
	power, ok := snapshot.ProviderMethod(KernelPackageID, InterfacePower, 1, 1)
	if !ok || !power.KernelBuiltin || power.Request != nil || power.Response != nil ||
		power.Meta.GetRequiredPermission() != "perm.authority.power" {
		t.Fatalf("kernel Power method = %+v, %v", power, ok)
	}
	for _, capabilityPermission := range []string{
		"perm.camera.capture",
		"perm.microphone.capture",
		"perm.bluetooth.admin",
		"perm.network.admin",
	} {
		if _, ok := snapshot.Permission(capabilityPermission); ok {
			t.Fatalf("capability permission %q is hard-coded in bootstrap", capabilityPermission)
		}
	}
}

func TestLegacyPackageManagerArtifactsOnlyBindCanonicalInterface(t *testing.T) {
	artifacts, err := LegacyPackageManagerArtifacts()
	if err != nil {
		t.Fatalf("LegacyPackageManagerArtifacts: %v", err)
	}
	if artifacts.Descriptor.GetPackageId() != "nervus.pkgmanagerd" ||
		len(artifacts.Descriptor.GetInterfaces()) != 1 ||
		len(artifacts.Descriptor.GetPermissions()) != 0 ||
		len(artifacts.Descriptor.GetResources()) != 0 ||
		artifacts.Schemas.Len() != 1 {
		t.Fatalf("legacy package-manager artifacts = %+v", artifacts.Descriptor)
	}

	registry := mustDefaultRegistry(t)
	candidate, err := registry.Prepare([]Source{{
		PackageID: "nervus.pkgmanagerd",
		Kind:      SourceKindSystemImage,
		Trust:     identity.TrustPlatform,
		Signers: SignerEvidence{
			Roles: []string{rolePlatformRelease},
			VerifiedSigners: []VerifiedSigner{{
				Role: rolePlatformRelease, KeyID: "platform-release-key",
			}},
		},
		Exports: []ExportBinding{{
			ComponentID: "main",
			InterfaceID: InterfacePackageManager,
		}},
		Artifacts: artifacts,
	}})
	if err != nil {
		t.Fatalf("Prepare legacy package manager: %v", err)
	}
	method, ok := candidate.Snapshot().ProviderMethod(
		"nervus.pkgmanagerd", InterfacePackageManager, 1, 1)
	if !ok || method.Request == nil ||
		string(method.Request.FullName()) != "nervus.interface.pkgmanager.v1.InstallRequest" {
		t.Fatalf("legacy package-manager method = %+v, %v", method, ok)
	}
}

func TestOEMPrivateProviderBuildsWithoutKernelSpecificCode(t *testing.T) {
	registry := mustDefaultRegistry(t)
	source := mustOEMSource(t)

	candidate, err := registry.Prepare([]Source{source})
	if err != nil {
		t.Fatalf("Prepare OEM provider: %v", err)
	}
	if _, ok := registry.Current().Interface(testOEMInterface, 1); ok {
		t.Fatal("Prepare published the candidate")
	}
	snapshot := candidate.Snapshot()
	iface, ok := snapshot.ProviderInterface(testOEMPackage, testOEMInterface, 1)
	if !ok || iface.ComponentID != "main" {
		t.Fatalf("provider interface = %+v, %v", iface, ok)
	}
	providers := snapshot.ProviderInterfaces(testOEMInterface, 1, 1)
	if len(providers) != 1 || providers[0].PackageID != testOEMPackage ||
		providers[0].ComponentID != "main" {
		t.Fatalf("provider range query = %+v", providers)
	}
	providers[0].Definition.SchemaHash[0] ^= 0xff
	unchanged, ok := snapshot.ProviderInterface(testOEMPackage, testOEMInterface, 1)
	if !ok || bytes.Equal(
		providers[0].Definition.SchemaHash, unchanged.Definition.SchemaHash) {
		t.Fatal("provider range result aliases immutable catalog state")
	}
	method, ok := snapshot.ProviderMethod(testOEMPackage, testOEMInterface, 1, 2)
	if !ok || method.Request == nil ||
		string(method.Request.FullName()) != "com.acme.dog.v1.SetRawGaitRequest" {
		t.Fatalf("provider method = %+v, %v", method, ok)
	}
	permission, ok := snapshot.Permission(testOEMPermission)
	if !ok || permission.MinimumTrust != identity.TrustOEM ||
		permission.Owner.PackageID != testOEMPackage {
		t.Fatalf("OEM permission = %+v, %v", permission, ok)
	}
	resource, ok := snapshot.ResolveResource(testOEMResource, "gait.main")
	if !ok || resource.ManagerPackageID != testOEMPackage {
		t.Fatalf("OEM resource = %+v, %v", resource, ok)
	}

	// Query values are defensive copies.
	iface.Definition.SchemaHash[0] ^= 0xff
	method.Meta.RequiredPermission = "mutated"
	again, _ := snapshot.ProviderInterface(testOEMPackage, testOEMInterface, 1)
	againMethod, _ := snapshot.ProviderMethod(testOEMPackage, testOEMInterface, 1, 2)
	if iface.Definition.SchemaHash[0] == again.Definition.SchemaHash[0] ||
		againMethod.Meta.GetRequiredPermission() != testOEMPermission {
		t.Fatal("query result mutated immutable catalog state")
	}
}

func TestUntrustedSourceCannotDefinePlatformPermission(t *testing.T) {
	registry := mustDefaultRegistry(t)
	artifacts := mustPermissionArtifacts(t, "com.example.app", "perm.microphone.capture")
	source := Source{
		PackageID: "com.example.app",
		Kind:      SourceKindDynamicInstall,
		Trust:     identity.TrustOrdinary,
		Signers:   SignerEvidence{DeveloperRootID: "developer-root"},
		Artifacts: artifacts,
	}
	if _, err := registry.Prepare([]Source{source}); err == nil ||
		!strings.Contains(err.Error(), "platform-release") {
		t.Fatalf("Prepare error = %v, want platform namespace rejection", err)
	}
}

func TestSignerRoleWithoutVerifiedIdentityIsRejected(t *testing.T) {
	registry := mustDefaultRegistry(t)
	source := platformPermissionSource(
		t, "nervus.platform.unverified", "perm.example.unverified", "verified-key")
	source.Signers.VerifiedSigners = nil
	source.Signers.DeveloperRootID = "unrelated-developer-root"
	if _, err := registry.Prepare([]Source{source}); err == nil ||
		!strings.Contains(err.Error(), "no verified signer identity") {
		t.Fatalf("Prepare error = %v, want unverified role rejection", err)
	}
}

func TestDynamicSourceCannotCarryElevatedTrust(t *testing.T) {
	registry := mustDefaultRegistry(t)
	source := mustOEMSource(t)
	source.Kind = SourceKindDynamicInstall
	source.Trust = identity.TrustPlatform
	if _, err := registry.Prepare([]Source{source}); err == nil ||
		!strings.Contains(err.Error(), "must have ordinary trust") {
		t.Fatalf("Prepare error = %v, want dynamic trust rejection", err)
	}
}

func TestOrdinarySourceCannotDefinePhysicalProvider(t *testing.T) {
	registry := mustDefaultRegistry(t)
	source := mustOEMSource(t)
	source.Kind = SourceKindDynamicInstall
	source.Trust = identity.TrustOrdinary
	source.Signers = SignerEvidence{DeveloperRootID: "developer-root"}
	if _, err := registry.Prepare([]Source{source}); err == nil ||
		!strings.Contains(err.Error(), "OEM-service") {
		t.Fatalf("Prepare error = %v, want physical-risk authority rejection", err)
	}
}

func TestConflictingPermissionDefinitionsRejectWholeCandidate(t *testing.T) {
	registry := mustDefaultRegistry(t)
	left := platformPermissionSource(t, "nervus.platform.alpha", "perm.example.shared", "key-alpha")
	right := platformPermissionSource(t, "nervus.platform.beta", "perm.example.shared", "key-beta")

	before := registry.Current()
	if _, err := registry.Prepare([]Source{left, right}); err == nil ||
		!strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("Prepare error = %v, want conflict", err)
	}
	if registry.Current() != before {
		t.Fatal("rejected candidate changed current snapshot")
	}
	if _, ok := before.Permission("perm.example.shared"); ok {
		t.Fatal("rejected permission leaked into current snapshot")
	}
}

func TestGenerationRevocationReaddAndCandidateCAS(t *testing.T) {
	registry := mustDefaultRegistry(t)
	source := mustOEMSource(t)
	baseMotion, _ := registry.Current().Interface(InterfaceMotionBase, 1)

	first, err := registry.Prepare([]Source{source})
	if err != nil {
		t.Fatalf("Prepare first: %v", err)
	}
	stale, err := registry.Prepare([]Source{source})
	if err != nil {
		t.Fatalf("Prepare stale: %v", err)
	}
	firstOEM, _ := first.Snapshot().Interface(testOEMInterface, 1)
	firstMethod, ok := first.Snapshot().ProviderMethod(
		testOEMPackage, testOEMInterface, 1, 2)
	if !ok {
		t.Fatal("first provider method missing")
	}
	if firstMethod.CatalogRevision != first.Snapshot().Revision() ||
		firstMethod.DefinitionGeneration != firstOEM.DefinitionGeneration ||
		firstMethod.ProviderGeneration == 0 {
		t.Fatalf("first method generations = catalog %d, definition %d, provider %d",
			firstMethod.CatalogRevision,
			firstMethod.DefinitionGeneration,
			firstMethod.ProviderGeneration)
	}
	if !registry.Publish(first) {
		t.Fatal("Publish first = false")
	}
	if registry.Publish(stale) {
		t.Fatal("stale candidate CAS unexpectedly succeeded")
	}

	same, err := registry.Prepare([]Source{source})
	if err != nil {
		t.Fatalf("Prepare same: %v", err)
	}
	sameOEM, _ := same.Snapshot().Interface(testOEMInterface, 1)
	if sameOEM.DefinitionGeneration != firstOEM.DefinitionGeneration {
		t.Fatalf("unchanged generation %d -> %d",
			firstOEM.DefinitionGeneration, sameOEM.DefinitionGeneration)
	}
	sameMethod, ok := same.Snapshot().ProviderMethod(
		testOEMPackage, testOEMInterface, 1, 2)
	if !ok {
		t.Fatal("unchanged provider method missing")
	}
	if sameMethod.CatalogRevision != same.Snapshot().Revision() ||
		sameMethod.DefinitionGeneration != firstMethod.DefinitionGeneration ||
		sameMethod.ProviderGeneration != firstMethod.ProviderGeneration {
		t.Fatalf("unchanged method generations = catalog %d, definition %d, provider %d",
			sameMethod.CatalogRevision,
			sameMethod.DefinitionGeneration,
			sameMethod.ProviderGeneration)
	}
	if !registry.Publish(same) {
		t.Fatal("Publish same = false")
	}

	removed, err := registry.Prepare(nil)
	if err != nil {
		t.Fatalf("Prepare removal: %v", err)
	}
	if _, ok := removed.Snapshot().Interface(testOEMInterface, 1); ok {
		t.Fatal("removed provider remains in candidate")
	}
	stableBase, _ := removed.Snapshot().Interface(InterfaceMotionBase, 1)
	if stableBase.DefinitionGeneration != baseMotion.DefinitionGeneration {
		t.Fatalf("unrelated bootstrap generation %d -> %d",
			baseMotion.DefinitionGeneration, stableBase.DefinitionGeneration)
	}
	if !registry.Publish(removed) {
		t.Fatal("Publish removal = false")
	}

	readded, err := registry.Prepare([]Source{source})
	if err != nil {
		t.Fatalf("Prepare readd: %v", err)
	}
	readdedOEM, _ := readded.Snapshot().Interface(testOEMInterface, 1)
	if readdedOEM.DefinitionGeneration <= firstOEM.DefinitionGeneration {
		t.Fatalf("readded generation = %d, first = %d",
			readdedOEM.DefinitionGeneration, firstOEM.DefinitionGeneration)
	}
	readdedMethod, ok := readded.Snapshot().ProviderMethod(
		testOEMPackage, testOEMInterface, 1, 2)
	if !ok {
		t.Fatal("readded provider method missing")
	}
	if readdedMethod.CatalogRevision != readded.Snapshot().Revision() ||
		readdedMethod.DefinitionGeneration <= firstMethod.DefinitionGeneration ||
		readdedMethod.ProviderGeneration <= firstMethod.ProviderGeneration {
		t.Fatalf("readded method generations = catalog %d, definition %d, provider %d",
			readdedMethod.CatalogRevision,
			readdedMethod.DefinitionGeneration,
			readdedMethod.ProviderGeneration)
	}
}

func TestStandardResourceManagerSignerChangeBumpsGeneration(t *testing.T) {
	registry := mustDefaultRegistry(t)
	first, err := registry.Prepare([]Source{mustOEMMotionSource(t, "oem-key-1")})
	if err != nil {
		t.Fatalf("Prepare first manager: %v", err)
	}
	firstResource, ok := first.Snapshot().ResolveResource(ResourceMotionBase, "base.main")
	if !ok || firstResource.Owner.PackageID != KernelPackageID ||
		firstResource.ManagerPackageID != testMotionPackage ||
		len(firstResource.ManagerOwner.Signers.VerifiedSigners) != 1 ||
		firstResource.ManagerOwner.Signers.VerifiedSigners[0].KeyID != "oem-key-1" {
		t.Fatalf("first managed resource = %+v, %v", firstResource, ok)
	}
	firstMethod, ok := first.Snapshot().ProviderMethod(
		testMotionPackage, InterfaceMotionBase, 1, 1)
	if !ok {
		t.Fatal("first motion provider method missing")
	}
	if !registry.Publish(first) {
		t.Fatal("Publish first manager = false")
	}

	rotated, err := registry.Prepare([]Source{mustOEMMotionSource(t, "oem-key-2")})
	if err != nil {
		t.Fatalf("Prepare rotated manager: %v", err)
	}
	rotatedResource, _ := rotated.Snapshot().ResolveResource(ResourceMotionBase, "base.main")
	rotatedMethod, _ := rotated.Snapshot().ProviderMethod(
		testMotionPackage, InterfaceMotionBase, 1, 1)
	if rotatedResource.DefinitionGeneration <= firstResource.DefinitionGeneration ||
		rotatedMethod.ProviderGeneration <= firstMethod.ProviderGeneration {
		t.Fatalf("signer rotation did not invalidate resource/provider generations: resource %d -> %d, provider %d -> %d",
			firstResource.DefinitionGeneration,
			rotatedResource.DefinitionGeneration,
			firstMethod.ProviderGeneration,
			rotatedMethod.ProviderGeneration)
	}
}

func mustDefaultRegistry(t *testing.T) *Registry {
	t.Helper()
	registry, err := NewDefaultRegistry()
	if err != nil {
		t.Fatalf("NewDefaultRegistry: %v", err)
	}
	return registry
}

func mustOEMMotionSource(t *testing.T, keyID string) Source {
	t.Helper()
	bundle, err := ipcregistry.BuildSchemaBundle(
		InterfaceMotionBase, 1, basemotionv1.BaseMotionMethod(0).Descriptor())
	if err != nil {
		t.Fatalf("BuildSchemaBundle: %v", err)
	}
	descriptor := &ipcv1.ProviderDescriptor{
		PackageId: testMotionPackage,
		Interfaces: []*ipcv1.ProvidedInterface{bootstrapInterface(
			InterfaceMotionBase,
			bundle,
			"perm.motion.control",
			ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
			[]string{ResourceMotionBase},
			ResourceMotionBase,
			"base.main",
		)},
		Resources: []*ipcv1.ManagedResource{{
			StableRole:   "base.main",
			ResourceType: ResourceMotionBase,
			AccessMode:   ipcv1.ResourceAccessMode_RESOURCE_ACCESS_MODE_EXCLUSIVE_CONTROL,
			RiskClass:    ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
		}},
	}
	return Source{
		PackageID: testMotionPackage,
		Kind:      SourceKindSystemImage,
		Trust:     identity.TrustOEM,
		Signers: SignerEvidence{
			Roles: []string{roleOEMService},
			VerifiedSigners: []VerifiedSigner{{
				Role: roleOEMService, KeyID: keyID,
			}},
		},
		Exports: []ExportBinding{{
			ComponentID: "main",
			InterfaceID: InterfaceMotionBase,
		}},
		Artifacts: mustArtifacts(t, descriptor, &ipcv1.InterfaceSchemaBundleSet{
			Bundles: []*ipcv1.InterfaceSchemaBundle{bundle},
		}),
	}
}

func mustOEMSource(t *testing.T) Source {
	t.Helper()
	bundle, err := ipcregistry.BuildSchemaBundle(
		testOEMInterface, 1, dogv1.RawGaitMethod(0).Descriptor())
	if err != nil {
		t.Fatalf("BuildSchemaBundle: %v", err)
	}
	descriptor := &ipcv1.ProviderDescriptor{
		PackageId: testOEMPackage,
		Interfaces: []*ipcv1.ProvidedInterface{{
			InterfaceId: testOEMInterface,
			InterfaceVersions: []*ipcv1.ProvidedInterfaceVersion{{
				Major: 1, SchemaHash: append([]byte(nil), bundle.GetSchemaHash()...),
			}},
			RequiredPermission:      testOEMPermission,
			ResourceRiskFloor:       ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
			CompatibleResourceTypes: []string{testOEMResource},
			DefaultResourceType:     testOEMResource,
			DefaultResourceRole:     "gait.main",
		}},
		Resources: []*ipcv1.ManagedResource{{
			StableRole:   "gait.main",
			ResourceType: testOEMResource,
			AccessMode:   ipcv1.ResourceAccessMode_RESOURCE_ACCESS_MODE_EXCLUSIVE_CONTROL,
			RiskClass:    ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
		}},
		Permissions: []*ipcv1.DefinedPermission{permissionWire(
			testOEMPermission,
			ipcv1.GrantMode_GRANT_MODE_USER_CONSENT,
			ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_OEM,
			roleOEMService,
		)},
	}
	return Source{
		PackageID: testOEMPackage,
		Kind:      SourceKindSystemImage,
		Trust:     identity.TrustOEM,
		Signers: SignerEvidence{
			Roles: []string{roleOEMService},
			VerifiedSigners: []VerifiedSigner{{
				Role: roleOEMService, KeyID: "acme-oem-service-key",
			}},
		},
		Exports: []ExportBinding{{ComponentID: "main", InterfaceID: testOEMInterface}},
		Artifacts: mustArtifacts(t, descriptor, &ipcv1.InterfaceSchemaBundleSet{
			Bundles: []*ipcv1.InterfaceSchemaBundle{bundle},
		}),
	}
}

func platformPermissionSource(t *testing.T, packageID, permissionID, keyID string) Source {
	t.Helper()
	return Source{
		PackageID: packageID,
		Kind:      SourceKindSystemImage,
		Trust:     identity.TrustPlatform,
		Signers: SignerEvidence{
			Roles: []string{rolePlatformRelease},
			VerifiedSigners: []VerifiedSigner{{
				Role: rolePlatformRelease, KeyID: keyID,
			}},
		},
		Artifacts: mustPermissionArtifacts(t, packageID, permissionID),
	}
}

func mustPermissionArtifacts(t *testing.T, packageID, permissionID string) *ipcregistry.ProviderArtifacts {
	t.Helper()
	return mustArtifacts(t, &ipcv1.ProviderDescriptor{
		PackageId: packageID,
		Permissions: []*ipcv1.DefinedPermission{permissionWire(
			permissionID,
			ipcv1.GrantMode_GRANT_MODE_NORMAL,
			ipcv1.RiskClass_RISK_CLASS_NORMAL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			"",
		)},
	}, &ipcv1.InterfaceSchemaBundleSet{})
}

func permissionWire(
	id string,
	mode ipcv1.GrantMode,
	risk ipcv1.RiskClass,
	minimum ipcv1.PermissionTrustFloor,
	requiredRole string,
) *ipcv1.DefinedPermission {
	return &ipcv1.DefinedPermission{
		Id:                 id,
		GrantMode:          mode,
		RiskClass:          risk,
		MinimumTrust:       minimum,
		RequiredSignerRole: requiredRole,
		DisplayName:        &ipcv1.LocalizedText{ZhCn: "测试权限", En: "Test permission"},
		Description:        &ipcv1.LocalizedText{ZhCn: "测试权限说明", En: "Test permission description"},
	}
}

func mustArtifacts(
	t *testing.T,
	descriptor *ipcv1.ProviderDescriptor,
	bundles *ipcv1.InterfaceSchemaBundleSet,
) *ipcregistry.ProviderArtifacts {
	t.Helper()
	marshal := proto.MarshalOptions{Deterministic: true}
	descriptorWire, err := marshal.Marshal(descriptor)
	if err != nil {
		t.Fatalf("marshal descriptor: %v", err)
	}
	schemaWire, err := marshal.Marshal(bundles)
	if err != nil {
		t.Fatalf("marshal schemas: %v", err)
	}
	artifacts, err := ipcregistry.ParseProviderArtifacts(descriptorWire, schemaWire)
	if err != nil {
		t.Fatalf("ParseProviderArtifacts: %v", err)
	}
	return artifacts
}
