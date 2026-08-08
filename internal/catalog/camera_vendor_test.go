package catalog

import (
	"strings"
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	ipcregistry "github.com/nervus-os/nervus-ipc/registry"

	"github.com/nervus-os/nervud/internal/identity"
)

//

//

//

//

//

//

const (
	testCameraInterface = "nervus.interface.camera"
	testCameraResource  = "nervus.resource.camera"
	testCameraPerm      = "perm.camera.capture"
)

//

//

func cameradSource(t *testing.T, roles ...string) Source {
	t.Helper()

	methods := []*ipcv1.MethodMeta{{
		MethodId:           1,
		RequiredPermission: testCameraPerm,
		RiskClass:          ipcv1.RiskClass_RISK_CLASS_PRIVACY_SENSITIVE,
		IsReadOnly:         true,
	}}
	hash, err := ipcregistry.MethodsHash(methods)
	if err != nil {
		t.Fatalf("MethodsHash: %v", err)
	}

	resources := make([]*ipcv1.ManagedResource, 0, len(roles))
	for _, role := range roles {
		resources = append(resources, &ipcv1.ManagedResource{
			StableRole:   role,
			ResourceType: testCameraResource,
			AccessMode:   ipcv1.ResourceAccessMode_RESOURCE_ACCESS_MODE_SHARED_OBSERVE,
			RiskClass:    ipcv1.RiskClass_RISK_CLASS_PRIVACY_SENSITIVE,

			Labels: map[string]string{"nervus.camera.facing": strings.TrimPrefix(role, "cam.")},
		})
	}

	descriptor := &ipcv1.ProviderDescriptor{
		PackageId: "nervus.camerad",
		Interfaces: []*ipcv1.ProvidedInterface{{
			InterfaceId: testCameraInterface,
			InterfaceVersions: []*ipcv1.ProvidedInterfaceVersion{{
				Major: 1, SchemaHash: hash, Methods: methods,
			}},
			RequiredPermission:      testCameraPerm,
			ResourceRiskFloor:       ipcv1.RiskClass_RISK_CLASS_PRIVACY_SENSITIVE,
			CompatibleResourceTypes: []string{testCameraResource},
		}},
		Resources: resources,
		Permissions: []*ipcv1.DefinedPermission{{
			Id:           testCameraPerm,
			GrantMode:    ipcv1.GrantMode_GRANT_MODE_USER_CONSENT,
			RiskClass:    ipcv1.RiskClass_RISK_CLASS_PRIVACY_SENSITIVE,
			MinimumTrust: ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			DisplayName:  &ipcv1.LocalizedText{ZhCn: "catalog test value 96fdfb", En: "Use the camera"},
			Description:  &ipcv1.LocalizedText{ZhCn: "catalog test value 96fdfb", En: "Use the camera"},
		}},
	}
	return Source{
		PackageID: "nervus.camerad",
		Kind:      SourceKindSystemImage,
		Trust:     identity.TrustPlatform,
		Signers: SignerEvidence{
			Roles: []string{rolePlatformRelease},
			VerifiedSigners: []VerifiedSigner{{
				Role: rolePlatformRelease, KeyID: "platform-release-key",
			}},
		},
		Exports:   []ExportBinding{{ComponentID: "main", InterfaceID: testCameraInterface}},
		Artifacts: mustArtifacts(t, descriptor, noBundles()),
	}
}

func vendorCameraSource(
	t *testing.T, packageID, role string, mutate func(*ipcv1.ManagedResource),
) Source {
	t.Helper()

	resource := &ipcv1.ManagedResource{
		StableRole:   role,
		ResourceType: testCameraResource,
		AccessMode:   ipcv1.ResourceAccessMode_RESOURCE_ACCESS_MODE_SHARED_OBSERVE,
		RiskClass:    ipcv1.RiskClass_RISK_CLASS_PRIVACY_SENSITIVE,
	}
	if mutate != nil {
		mutate(resource)
	}

	descriptor := &ipcv1.ProviderDescriptor{
		PackageId: packageID,
		Resources: []*ipcv1.ManagedResource{resource},
	}
	return Source{
		PackageID: packageID,
		Kind:      SourceKindSystemImage,
		Trust:     identity.TrustOEM,
		Signers: SignerEvidence{
			Roles:           []string{roleOEMService},
			VerifiedSigners: []VerifiedSigner{{Role: roleOEMService, KeyID: packageID + "-key"}},
		},
		Artifacts: mustArtifacts(t, descriptor, noBundles()),
	}
}

func noBundles() *ipcv1.InterfaceSchemaBundleSet {
	return &ipcv1.InterfaceSchemaBundleSet{}
}

//

func TestVendorCamera_CannotIntroduceUnknownStandardType(t *testing.T) {
	registry := mustDefaultRegistry(t)
	_, err := registry.Prepare([]Source{
		vendorCameraSource(t, "com.acme.camera", "cam.front", nil),
	})
	if err == nil {
		t.Fatal("unexpected catalog result; OEM")
	}
	if !strings.Contains(err.Error(), "unknown standard resource type") {
		t.Fatalf("unexpected catalog result; err = %v; expected rejection", err)
	}
}

//

func TestVendorCamera_MayAddInstanceOnceTypeIsKnown(t *testing.T) {
	registry := mustDefaultRegistry(t)
	candidate, err := registry.Prepare([]Source{
		cameradSource(t, "cam.front"),
		vendorCameraSource(t, "com.acme.camera", "cam.wrist", nil),
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	matched := FilterResources(candidate.Snapshot(), testCameraResource, "", nil)
	if len(matched) != 2 {
		t.Fatalf("unexpected catalog result; matched = %+v; expected a different value", matched)
	}

	byRole := make(map[string]ResourceDefinition, len(matched))
	for _, def := range matched {
		byRole[def.StableRole] = def
	}
	if got := byRole["cam.wrist"].ManagerPackageID; got != "com.acme.camera" {
		t.Errorf("cam.wrist manager = %q, want com.acme.camera", got)
	}
	if got := byRole["cam.front"].ManagerPackageID; got != "nervus.camerad" {
		t.Errorf("cam.front manager = %q, want nervus.camerad", got)
	}

	if len(byRole["cam.wrist"].Labels) != 0 {
		t.Errorf("unexpected catalog result; value = %v", byRole["cam.wrist"].Labels)
	}
	front := FilterResources(candidate.Snapshot(), testCameraResource, "",
		map[string]string{"nervus.camera.facing": "front"})
	if len(front) != 1 || front[0].StableRole != "cam.front" {
		t.Fatalf("unexpected catalog result; facing=front %+v, want camerad", front)
	}
}

//

//

func TestVendorCamera_TwoVendorsCannotClaimSameRole(t *testing.T) {
	registry := mustDefaultRegistry(t)
	_, err := registry.Prepare([]Source{
		cameradSource(t, "cam.front"),
		vendorCameraSource(t, "com.acme.camera", "cam.wrist", nil),
		vendorCameraSource(t, "com.globex.camera", "cam.wrist", nil),
	})
	if err == nil {
		t.Fatal("unexpected catalog result; cam.wrist")
	}
	if !strings.Contains(err.Error(), "multiple managers") {
		t.Fatalf("unexpected catalog result; err = %v; expected rejection", err)
	}

	if !strings.Contains(err.Error(), "com.acme.camera") ||
		!strings.Contains(err.Error(), "com.globex.camera") {
		t.Fatalf("unexpected catalog result; err = %v; expected rejection", err)
	}
}

func TestVendorCamera_DifferentRolesCoexist(t *testing.T) {
	registry := mustDefaultRegistry(t)
	candidate, err := registry.Prepare([]Source{
		cameradSource(t, "cam.front", "cam.rear"),
		vendorCameraSource(t, "com.acme.camera", "cam.wrist", nil),
		vendorCameraSource(t, "com.globex.camera", "cam.tool", nil),
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if got := FilterResources(candidate.Snapshot(), testCameraResource, "", nil); len(got) != 4 {
		t.Fatalf("unexpected catalog result; matched = %+v; expected a different value", got)
	}
}

//

func TestVendorCamera_ConflictingContractOnSameRoleIsRejected(t *testing.T) {
	registry := mustDefaultRegistry(t)
	_, err := registry.Prepare([]Source{
		cameradSource(t, "cam.front"),
		vendorCameraSource(t, "com.acme.camera", "cam.wrist", nil),
		vendorCameraSource(t, "com.globex.camera", "cam.wrist", func(r *ipcv1.ManagedResource) {
			r.AccessMode = ipcv1.ResourceAccessMode_RESOURCE_ACCESS_MODE_EXCLUSIVE_CONTROL
		}),
	})
	if err == nil {
		t.Fatal("unexpected catalog result; role")
	}
	if !strings.Contains(err.Error(), "conflicts with definition owned by") {
		t.Fatalf("unexpected catalog result; err = %v; expected rejection", err)
	}
}

//

//

func TestVendorCamera_CannotHijackPlatformRole(t *testing.T) {
	registry := mustDefaultRegistry(t)
	_, err := registry.Prepare([]Source{
		cameradSource(t, "cam.front"),
		vendorCameraSource(t, "com.acme.camera", "cam.front", nil),
	})
	if err == nil {
		t.Fatal("unexpected catalog result; cam.front")
	}
	if !strings.Contains(err.Error(), "conflicts with definition owned by") ||
		!strings.Contains(err.Error(), "nervus.camerad") {
		t.Fatalf("unexpected catalog result; err = %v, want nervus.camerad", err)
	}
}

//

func TestVendorCamera_CannotHijackPlatformRoleByCopyingLabels(t *testing.T) {
	registry := mustDefaultRegistry(t)
	_, err := registry.Prepare([]Source{
		cameradSource(t, "cam.front"),
		vendorCameraSource(t, "com.acme.camera", "cam.front", func(r *ipcv1.ManagedResource) {
			r.Labels = map[string]string{"nervus.camera.facing": "front"}
		}),
	})
	if err == nil {
		t.Fatal("unexpected catalog result; cam.front")
	}
	if !strings.Contains(err.Error(), "platform-release") {
		t.Fatalf("unexpected catalog result; err = %v; expected rejection", err)
	}
}

//

//

func TestVendorCamera_CannotLabelStandardResourceAsPlatformSemantic(t *testing.T) {
	registry := mustDefaultRegistry(t)
	_, err := registry.Prepare([]Source{
		cameradSource(t, "cam.front"),
		vendorCameraSource(t, "com.acme.camera", "cam.side", func(r *ipcv1.ManagedResource) {
			r.Labels = map[string]string{"nervus.camera.facing": "front"}
		}),
	})
	if err == nil {
		t.Fatal("unexpected catalog result")
	}
	if !strings.Contains(err.Error(), "platform-release") {
		t.Fatalf("unexpected catalog result; err = %v; expected rejection", err)
	}
}

func TestVendorCamera_CannotDefineStandardInterface(t *testing.T) {
	registry := mustDefaultRegistry(t)

	methods := []*ipcv1.MethodMeta{{MethodId: 1, RiskClass: ipcv1.RiskClass_RISK_CLASS_NORMAL, IsReadOnly: true}}
	hash, err := ipcregistry.MethodsHash(methods)
	if err != nil {
		t.Fatalf("MethodsHash: %v", err)
	}
	forged := Source{
		PackageID: "com.acme.camera",
		Kind:      SourceKindSystemImage,
		Trust:     identity.TrustOEM,
		Signers: SignerEvidence{
			Roles:           []string{roleOEMService},
			VerifiedSigners: []VerifiedSigner{{Role: roleOEMService, KeyID: "acme-key"}},
		},
		Exports: []ExportBinding{{ComponentID: "main", InterfaceID: testCameraInterface}},
		Artifacts: mustArtifacts(t, &ipcv1.ProviderDescriptor{
			PackageId: "com.acme.camera",
			Interfaces: []*ipcv1.ProvidedInterface{{
				InterfaceId: testCameraInterface,
				InterfaceVersions: []*ipcv1.ProvidedInterfaceVersion{{
					Major: 1, SchemaHash: hash, Methods: methods,
				}},
			}},
		}, noBundles()),
	}

	if _, err := registry.Prepare([]Source{forged}); err == nil {
		t.Fatal("unexpected catalog result")
	} else if !strings.Contains(err.Error(), "platform-release") {
		t.Fatalf("unexpected catalog result; err = %v; expected rejection", err)
	}
}
