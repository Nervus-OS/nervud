package catalog

import (
	"strings"
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	ipcregistry "github.com/nervus-os/nervus-ipc/registry"

	"github.com/nervus-os/nervud/internal/identity"
)

// labelledResourceArtifacts 造一个带标签的 OEM 私有资源。
func labelledResourceArtifacts(t *testing.T, packageID string, labels map[string]string) *ipcregistry.ProviderArtifacts {
	t.Helper()
	interfaceID := packageID + ".interface.cam"
	resourceType := packageID + ".resource.cam"
	permission := packageID + ".permission.cam"

	methods := []*ipcv1.MethodMeta{{
		MethodId:           1,
		RequiredPermission: permission,
		RiskClass:          ipcv1.RiskClass_RISK_CLASS_NORMAL,
		IsReadOnly:         true,
	}}
	hash, err := ipcregistry.MethodsHash(methods)
	if err != nil {
		t.Fatalf("MethodsHash: %v", err)
	}

	descriptor := &ipcv1.ProviderDescriptor{
		PackageId: packageID,
		Interfaces: []*ipcv1.ProvidedInterface{{
			InterfaceId: interfaceID,
			InterfaceVersions: []*ipcv1.ProvidedInterfaceVersion{{
				Major: 1, SchemaHash: hash, Methods: methods,
			}},
			RequiredPermission:      permission,
			ResourceRiskFloor:       ipcv1.RiskClass_RISK_CLASS_NORMAL,
			CompatibleResourceTypes: []string{resourceType},
			DefaultResourceType:     resourceType,
			DefaultResourceRole:     "cam.main",
		}},
		Resources: []*ipcv1.ManagedResource{{
			StableRole:   "cam.main",
			ResourceType: resourceType,
			AccessMode:   ipcv1.ResourceAccessMode_RESOURCE_ACCESS_MODE_SHARED_OBSERVE,
			RiskClass:    ipcv1.RiskClass_RISK_CLASS_NORMAL,
			Labels:       labels,
		}},
		Permissions: []*ipcv1.DefinedPermission{{
			Id:           permission,
			GrantMode:    ipcv1.GrantMode_GRANT_MODE_NORMAL,
			RiskClass:    ipcv1.RiskClass_RISK_CLASS_NORMAL,
			MinimumTrust: ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			DisplayName:  &ipcv1.LocalizedText{ZhCn: "相机", En: "Camera"},
			Description:  &ipcv1.LocalizedText{ZhCn: "相机", En: "Camera"},
		}},
	}
	descriptorWire, schemaWire, err := ipcregistry.MarshalProviderArtifacts(
		descriptor, &ipcv1.InterfaceSchemaBundleSet{})
	if err != nil {
		t.Fatalf("MarshalProviderArtifacts: %v", err)
	}
	artifacts, err := ipcregistry.ParseProviderArtifacts(descriptorWire, schemaWire)
	if err != nil {
		t.Fatalf("ParseProviderArtifacts: %v", err)
	}
	return artifacts
}

func labelledOEMSource(t *testing.T, packageID string, labels map[string]string) Source {
	t.Helper()
	return Source{
		PackageID: packageID,
		Kind:      SourceKindSystemImage,
		Trust:     identity.TrustOEM,
		Signers: SignerEvidence{
			Roles:           []string{roleOEMService},
			VerifiedSigners: []VerifiedSigner{{Role: roleOEMService, KeyID: packageID + "-key"}},
		},
		Exports: []ExportBinding{{
			ComponentID: "main", InterfaceID: packageID + ".interface.cam",
		}},
		Artifacts: labelledResourceArtifacts(t, packageID, labels),
	}
}

// 厂商可以给自己命名空间下的标签。
func TestResourceLabels_PrivateNamespaceAllowed(t *testing.T) {
	registry := mustDefaultRegistry(t)
	source := labelledOEMSource(t, "com.vendor.cam", map[string]string{
		"com.vendor.cam.night_capable": "true",
	})
	candidate, err := registry.Prepare([]Source{source})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	matched, ok := SelectResources(candidate.Snapshot(), &ipcv1.ResourceSelector{
		Type:   "com.vendor.cam.resource.cam",
		Labels: map[string]string{"com.vendor.cam.night_capable": "true"},
	})
	if !ok || len(matched) != 1 {
		t.Fatalf("私有标签选不到: %+v, %v", matched, ok)
	}
}

// 【厂商不得声明平台标签】。能随手写 nervus.camera.facing=front 的话，厂商就能
// 把自己的摄像头伪装成平台语义下的前视摄像头，让按标准标签选设备的 App 选到它。
func TestResourceLabels_VendorCannotForgePlatformLabel(t *testing.T) {
	registry := mustDefaultRegistry(t)
	source := labelledOEMSource(t, "com.vendor.cam", map[string]string{
		"nervus.camera.facing": "front",
	})
	_, err := registry.Prepare([]Source{source})
	if err == nil {
		t.Fatal("厂商伪造平台标签被接受了")
	}
	if !strings.Contains(err.Error(), "platform-release") {
		t.Fatalf("err = %v, want 平台标签授权拒绝", err)
	}
}

// 别人命名空间下的标签同样不行——命名空间规则与接口/权限/资源类型完全同规。
func TestResourceLabels_VendorCannotUseForeignNamespace(t *testing.T) {
	registry := mustDefaultRegistry(t)
	source := labelledOEMSource(t, "com.vendor.cam", map[string]string{
		"com.other.vendor.trusted": "true",
	})
	_, err := registry.Prepare([]Source{source})
	if err == nil {
		t.Fatal("跨命名空间标签被接受了")
	}
	if !strings.Contains(err.Error(), "outside package namespace") {
		t.Fatalf("err = %v, want 命名空间拒绝", err)
	}
}

// 标签是契约的一部分：同一个资源被两方声明了不同标签时必须拒绝，
// 否则 App 按标签选到哪一个取决于发布顺序。
func TestResourceLabels_ArePartOfResourceContract(t *testing.T) {
	left := ResourceDefinition{
		Handle: "cam.main", ResourceType: "t", StableRole: "cam.main",
		Labels: map[string]string{"a": "1"},
	}
	right := left
	right.Labels = map[string]string{"a": "2"}
	if sameResourceContract(left, right) {
		t.Fatal("标签不同却被判成同一份资源契约")
	}
	right.Labels = map[string]string{"a": "1"}
	if !sameResourceContract(left, right) {
		t.Fatal("标签相同却被判成不同契约")
	}
}
