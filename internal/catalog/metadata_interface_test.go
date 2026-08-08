package catalog

import (
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	ipcregistry "github.com/nervus-os/nervus-ipc/registry"

	"github.com/nervus-os/nervud/internal/identity"
)

const (
	metaOEMPackage    = "com.vendor.cam"
	metaOEMInterface  = "com.vendor.cam.interface.stream"
	metaOEMPermission = "com.vendor.cam.permission.stream"
)

func metadataCameraArtifacts(t *testing.T, permission string, maxBPS uint64) *ipcregistry.ProviderArtifacts {
	t.Helper()
	methods := []*ipcv1.MethodMeta{
		{
			MethodId:           1,
			RequiredPermission: permission,
			RiskClass:          ipcv1.RiskClass_RISK_CLASS_NORMAL,
			IsReadOnly:         true,
			Transfer: &ipcv1.TransferPolicy{
				Direction:         ipcv1.TransferDirection_TRANSFER_DIRECTION_PROVIDER_TO_CALLER,
				MaxStreams:        1,
				MaxPacketBytes:    4 << 20,
				MaxBytesPerSecond: maxBPS,
			},
		},
		{
			MethodId:           2,
			RequiredPermission: permission,
			RiskClass:          ipcv1.RiskClass_RISK_CLASS_NORMAL,
		},
	}
	hash, err := ipcregistry.MethodsHash(methods)
	if err != nil {
		t.Fatalf("MethodsHash: %v", err)
	}
	descriptor := &ipcv1.ProviderDescriptor{
		PackageId: metaOEMPackage,
		Interfaces: []*ipcv1.ProvidedInterface{{
			InterfaceId: metaOEMInterface,
			InterfaceVersions: []*ipcv1.ProvidedInterfaceVersion{{
				Major: 1, SchemaHash: hash, Methods: methods,
			}},
			RequiredPermission: permission,
		}},
		Permissions: []*ipcv1.DefinedPermission{{
			Id:           permission,
			GrantMode:    ipcv1.GrantMode_GRANT_MODE_NORMAL,
			RiskClass:    ipcv1.RiskClass_RISK_CLASS_NORMAL,
			MinimumTrust: ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			DisplayName:  &ipcv1.LocalizedText{ZhCn: "catalog test value 1b7e02", En: "Stream"},
			Description:  &ipcv1.LocalizedText{ZhCn: "catalog test value 1b7e02", En: "Stream"},
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

func metadataOEMSource(t *testing.T, keyID string, artifacts *ipcregistry.ProviderArtifacts) Source {
	t.Helper()
	return Source{
		PackageID: metaOEMPackage,
		Kind:      SourceKindSystemImage,
		Trust:     identity.TrustOEM,
		Signers: SignerEvidence{
			Roles: []string{roleOEMService},
			VerifiedSigners: []VerifiedSigner{{
				Role: roleOEMService, KeyID: keyID,
			}},
		},
		Exports: []ExportBinding{{
			ComponentID: "main", InterfaceID: metaOEMInterface,
		}},
		Artifacts: artifacts,
	}
}

//

func TestMetadataInterfaceEntersCatalog(t *testing.T) {
	registry := mustDefaultRegistry(t)
	candidate, err := registry.Prepare([]Source{
		metadataOEMSource(t, "vendor-key", metadataCameraArtifacts(t, metaOEMPermission, 64<<20)),
	})
	if err != nil {
		t.Fatalf("Prepare metadata interface: %v", err)
	}

	snapshot := candidate.Snapshot()
	iface, ok := snapshot.Interface(metaOEMInterface, 1)
	if !ok || iface.RequiredPermission != metaOEMPermission {
		t.Fatalf("interface = %+v, %v", iface, ok)
	}
	if len(iface.SchemaHash) == 0 {
		t.Error("unexpected catalog result")
	}

	method, ok := snapshot.ProviderMethod(metaOEMPackage, metaOEMInterface, 1, 1)
	if !ok {
		t.Fatal("unexpected catalog result; method 1 Catalog")
	}

	if method.Request != nil || method.Response != nil {
		t.Errorf("unexpected catalog result; req=%v resp=%v", method.Request, method.Response)
	}
	if method.Meta.GetTransfer().GetMaxPacketBytes() != 4<<20 {
		t.Errorf("unexpected catalog result; Transfer: %+v", method.Meta.GetTransfer())
	}
}

func TestMetadataInterfaceAllowsIdenticalSecondProvider(t *testing.T) {
	registry := mustDefaultRegistry(t)
	first := metadataOEMSource(t, "vendor-a", metadataCameraArtifacts(t, metaOEMPermission, 64<<20))
	second := metadataOEMSource(t, "vendor-b", metadataCameraArtifacts(t, metaOEMPermission, 64<<20))
	second.PackageID = metaOEMPackage

	if _, err := registry.Prepare([]Source{first}); err != nil {
		t.Fatalf("Prepare first: %v", err)
	}
	if _, err := registry.Prepare([]Source{second}); err != nil {
		t.Fatalf("Prepare second with identical contract: %v", err)
	}
}

func TestMetadataInterfaceRejectsDivergentContract(t *testing.T) {
	registry := mustDefaultRegistry(t)

	loose := metadataCameraArtifacts(t, metaOEMPermission, 1<<30)
	strict := metadataCameraArtifacts(t, metaOEMPermission, 64<<20)

	candidate, err := registry.Prepare([]Source{metadataOEMSource(t, "vendor-a", loose)})
	if err != nil {
		t.Fatalf("Prepare loose: %v", err)
	}
	if !registry.Publish(candidate) {
		t.Fatal("Publish loose failed")
	}

	tighter := metadataOEMSource(t, "vendor-b", strict)
	tighter.PackageID = "com.other.cam"
	tighter.Artifacts.Descriptor.PackageId = "com.other.cam"
	tighter.Exports = []ExportBinding{{ComponentID: "main", InterfaceID: metaOEMInterface}}

	if _, err := registry.Prepare([]Source{tighter}); err == nil {
		t.Fatal("unexpected catalog result; Provider")
	}
}
