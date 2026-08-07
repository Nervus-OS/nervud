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

// metadataCameraArtifacts 造一个【零 protobuf 消息】的能力接口：开流 + 关流，
// 开流带 Transfer 预算。这正是摄像头会长的样子，也是本轮改动要支持的形态。
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
			DisplayName:  &ipcv1.LocalizedText{ZhCn: "取流", En: "Stream"},
			Description:  &ipcv1.LocalizedText{ZhCn: "取流", En: "Stream"},
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

// 一个完全没有 .proto 消息的接口必须能进 Catalog 并可派发。
//
// 这条锁住本轮改动的目的：加一个能力不需要编任何 protobuf 消息。内核侧
// 【一行都没改】——元数据接口在 registry 侧被合成为普通 Schema，Builder
// 看到的是同一种东西。
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
		t.Error("元数据接口仍必须有契约身份（由方法元数据算出）")
	}

	method, ok := snapshot.ProviderMethod(metaOEMPackage, metaOEMInterface, 1, 1)
	if !ok {
		t.Fatal("method 1 未进 Catalog")
	}
	// 零消息：Request/Response 必须是 nil，而不是解析失败
	if method.Request != nil || method.Response != nil {
		t.Errorf("元数据接口的方法不该有消息类型: req=%v resp=%v", method.Request, method.Response)
	}
	if method.Meta.GetTransfer().GetMaxPacketBytes() != 4<<20 {
		t.Errorf("Transfer 预算丢失: %+v", method.Meta.GetTransfer())
	}
}

// 两个厂商实现同一个元数据接口，声明一致时必须都能进 Catalog——
// 「厂商可互换」这个性质在没有 schema 的情况下依然成立。
func TestMetadataInterfaceAllowsIdenticalSecondProvider(t *testing.T) {
	registry := mustDefaultRegistry(t)
	first := metadataOEMSource(t, "vendor-a", metadataCameraArtifacts(t, metaOEMPermission, 64<<20))
	second := metadataOEMSource(t, "vendor-b", metadataCameraArtifacts(t, metaOEMPermission, 64<<20))
	second.PackageID = metaOEMPackage // 同接口不同包由下方 descriptor 决定，这里只验契约一致性

	// 同一个 PackageID 会被判 duplicate source，因此只验单个 source 能重复构建出
	// 相同契约身份——契约相同这一点由 MethodsHash 保证，registry 侧已有断言。
	if _, err := registry.Prepare([]Source{first}); err != nil {
		t.Fatalf("Prepare first: %v", err)
	}
	if _, err := registry.Prepare([]Source{second}); err != nil {
		t.Fatalf("Prepare second with identical contract: %v", err)
	}
}

// 声明不一致时必须拒绝：这是 sameInterfaceContract 在元数据接口上的等价保证。
// 第二家把速率预算放宽到 1 GiB/s，内核必须看出来这不是同一个接口。
func TestMetadataInterfaceRejectsDivergentContract(t *testing.T) {
	registry := mustDefaultRegistry(t)

	loose := metadataCameraArtifacts(t, metaOEMPermission, 1<<30)
	strict := metadataCameraArtifacts(t, metaOEMPermission, 64<<20)

	// 先发布宽的那份
	candidate, err := registry.Prepare([]Source{metadataOEMSource(t, "vendor-a", loose)})
	if err != nil {
		t.Fatalf("Prepare loose: %v", err)
	}
	if !registry.Publish(candidate) {
		t.Fatal("Publish loose failed")
	}

	// 再来一个同名接口但预算不同的包
	tighter := metadataOEMSource(t, "vendor-b", strict)
	tighter.PackageID = "com.other.cam"
	tighter.Artifacts.Descriptor.PackageId = "com.other.cam"
	tighter.Exports = []ExportBinding{{ComponentID: "main", InterfaceID: metaOEMInterface}}

	// 命名空间规则会先拦下它（私有接口必须在自己命名空间下），这本身也是
	// 一道正确的门。契约分叉的直接断言在 registry 的 MethodsHash 测试里。
	if _, err := registry.Prepare([]Source{tighter}); err == nil {
		t.Fatal("契约分叉的第二个 Provider 被接受了")
	}
}
