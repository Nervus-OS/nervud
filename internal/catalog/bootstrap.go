package catalog

import (
	"fmt"

	basemotionv1 "github.com/nervus-os/nervus-ipc/protocol/interface/basemotionv1"
	manipulatorv1 "github.com/nervus-os/nervus-ipc/protocol/interface/manipulatorv1"
	operationv1 "github.com/nervus-os/nervus-ipc/protocol/interface/operationv1"
	pkgmanagerv1 "github.com/nervus-os/nervus-ipc/protocol/interface/pkgmanagerv1"
	resourcedirv1 "github.com/nervus-os/nervus-ipc/protocol/interface/resourcedirv1"
	safetyv1 "github.com/nervus-os/nervus-ipc/protocol/interface/safetyv1"
	transferv1 "github.com/nervus-os/nervus-ipc/protocol/interface/transferv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	ipcregistry "github.com/nervus-os/nervus-ipc/registry"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/identity"
)

// DefaultBootstrap returns kernel-owned definitions that must exist before any
// package can register or consume a provider. Capability-specific additions
// belong in signed ProviderArtifacts, not in this function.
func DefaultBootstrap() ([]Source, error) {
	artifacts, err := buildBootstrapArtifacts()
	if err != nil {
		return nil, err
	}
	kernelSigner := SignerEvidence{
		Roles: []string{rolePlatformRelease},
		VerifiedSigners: []VerifiedSigner{{
			Role: rolePlatformRelease, KeyID: "nervus-kernel-builtin-v1",
		}},
	}
	return []Source{{
		PackageID: KernelPackageID,
		Kind:      SourceKindKernel,
		Trust:     identity.TrustPlatform,
		Signers:   kernelSigner,
		Exports: []ExportBinding{
			{ComponentID: "builtin.safety", InterfaceID: InterfaceSafetyControl},
			{ComponentID: "builtin.transfer", InterfaceID: InterfaceTransferControl},
			{ComponentID: "builtin.resourcedir", InterfaceID: InterfaceResourceDirectory},
			{ComponentID: "builtin.operation", InterfaceID: InterfaceOperationControl},
		},
		Artifacts: artifacts,
		KernelBuiltins: []KernelBuiltin{{
			ComponentID:        "builtin.power",
			InterfaceID:        InterfacePower,
			Major:              1,
			RequiredPermission: "perm.authority.power",
			Methods: []*ipcv1.MethodMeta{
				{
					MethodId:           1,
					RequiredPermission: "perm.authority.power",
					RiskClass:          ipcv1.RiskClass_RISK_CLASS_CRITICAL_SAFETY,
				},
				{
					MethodId:           2,
					RequiredPermission: "perm.authority.power",
					RiskClass:          ipcv1.RiskClass_RISK_CLASS_CRITICAL_SAFETY,
				},
			},
		}},
	}}, nil
}

// BootstrapSources is the explicit construction entry used by main and tests.
func BootstrapSources() ([]Source, error) {
	return DefaultBootstrap()
}

func buildBootstrapArtifacts() (*ipcregistry.ProviderArtifacts, error) {
	baseBundle, err := ipcregistry.BuildSchemaBundle(
		InterfaceMotionBase, 1, basemotionv1.BaseMotionMethod(0).Descriptor())
	if err != nil {
		return nil, fmt.Errorf("catalog: build base-motion bootstrap schema: %w", err)
	}
	manipulatorBundle, err := ipcregistry.BuildSchemaBundle(
		InterfaceManipulatorArm, 1, manipulatorv1.ManipulatorMethod(0).Descriptor())
	if err != nil {
		return nil, fmt.Errorf("catalog: build manipulator bootstrap schema: %w", err)
	}
	packageBundle, err := ipcregistry.BuildSchemaBundle(
		InterfacePackageManager, 1, pkgmanagerv1.PackageManagerMethod(0).Descriptor())
	if err != nil {
		return nil, fmt.Errorf("catalog: build package-manager bootstrap schema: %w", err)
	}
	safetyBundle, err := ipcregistry.BuildSchemaBundle(
		InterfaceSafetyControl, 1, safetyv1.SafetyControlMethod(0).Descriptor())
	if err != nil {
		return nil, fmt.Errorf("catalog: build safety bootstrap schema: %w", err)
	}
	transferBundle, err := ipcregistry.BuildSchemaBundle(
		InterfaceTransferControl, 1, transferv1.TransferControlMethod(0).Descriptor())
	if err != nil {
		return nil, fmt.Errorf("catalog: build transfer bootstrap schema: %w", err)
	}
	resourceDirBundle, err := ipcregistry.BuildSchemaBundle(
		InterfaceResourceDirectory, 1, resourcedirv1.ResourceDirectoryMethod(0).Descriptor())
	if err != nil {
		return nil, fmt.Errorf("catalog: build resource-directory bootstrap schema: %w", err)
	}
	// 带事件枚举: OperationChanged 有载荷, 必须走 bundle 而不是内联到
	// descriptor - 内联那条路是给元数据接口用的, 它不允许 payload_type.
	operationBundle, err := ipcregistry.BuildSchemaBundleWithEvents(
		InterfaceOperationControl, 1,
		operationv1.OperationControlMethod(0).Descriptor(),
		operationv1.OperationControlEvent(0).Descriptor())
	if err != nil {
		return nil, fmt.Errorf("catalog: build operation-control bootstrap schema: %w", err)
	}

	descriptor := &ipcv1.ProviderDescriptor{
		PackageId: KernelPackageID,
		Interfaces: []*ipcv1.ProvidedInterface{
			bootstrapInterface(
				InterfaceMotionBase,
				baseBundle,
				"perm.motion.control",
				ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
				[]string{ResourceMotionBase},
				ResourceMotionBase,
				"base.main",
			),
			bootstrapInterface(
				InterfaceManipulatorArm,
				manipulatorBundle,
				"perm.manipulator.control",
				ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
				[]string{ResourceManipulatorArm},
				ResourceManipulatorArm,
				"arm.main",
			),
			bootstrapInterface(
				InterfacePackageManager,
				packageBundle,
				"perm.pkg.query",
				ipcv1.RiskClass_RISK_CLASS_UNSPECIFIED,
				nil,
				"",
				"",
			),
			bootstrapInterface(
				InterfaceSafetyControl,
				safetyBundle,
				"perm.safety.observe",
				ipcv1.RiskClass_RISK_CLASS_UNSPECIFIED,
				nil,
				"",
				"",
			),
			bootstrapInterface(
				InterfaceTransferControl,
				transferBundle,
				"",
				ipcv1.RiskClass_RISK_CLASS_UNSPECIFIED,
				nil,
				"",
				"",
			),
			// 资源目录不绑任何资源: 它描述的就是资源本身.
			// 绑一个资源会让"列出全部摄像头"先要求解析到某一个摄像头.
			bootstrapInterface(
				InterfaceResourceDirectory,
				resourceDirBundle,
				"perm.resource.query",
				ipcv1.RiskClass_RISK_CLASS_UNSPECIFIED,
				nil,
				"",
				"",
			),
			// 不设 required_permission: 能不能查一个 operation, 由它
			// 自己的所有者关系决定 (Manager.Get 的 canSee), 不由一条全局
			// 权限决定. 加一条权限只会让"持有它就能看全机 operation"
			// 变成一件可能的事.
			bootstrapInterface(
				InterfaceOperationControl,
				operationBundle,
				"",
				ipcv1.RiskClass_RISK_CLASS_UNSPECIFIED,
				nil,
				"",
				"",
			),
		},
		Resources: []*ipcv1.ManagedResource{
			{
				StableRole:   "base.main",
				ResourceType: ResourceMotionBase,
				AccessMode:   ipcv1.ResourceAccessMode_RESOURCE_ACCESS_MODE_EXCLUSIVE_CONTROL,
				RiskClass:    ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
			},
			{
				StableRole:   "arm.main",
				ResourceType: ResourceManipulatorArm,
				AccessMode:   ipcv1.ResourceAccessMode_RESOURCE_ACCESS_MODE_EXCLUSIVE_CONTROL,
				RiskClass:    ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
			},
		},
		Permissions: bootstrapPermissions(),
	}
	bundles := &ipcv1.InterfaceSchemaBundleSet{Bundles: []*ipcv1.InterfaceSchemaBundle{
		baseBundle,
		manipulatorBundle,
		packageBundle,
		safetyBundle,
		transferBundle,
		resourceDirBundle,
		operationBundle,
	}}
	return parseArtifacts(descriptor, bundles, "bootstrap")
}

func parseArtifacts(
	descriptor *ipcv1.ProviderDescriptor,
	bundles *ipcv1.InterfaceSchemaBundleSet,
	label string,
) (*ipcregistry.ProviderArtifacts, error) {
	marshal := proto.MarshalOptions{Deterministic: true}
	descriptorWire, err := marshal.Marshal(descriptor)
	if err != nil {
		return nil, fmt.Errorf("catalog: marshal %s descriptor: %w", label, err)
	}
	schemaWire, err := marshal.Marshal(bundles)
	if err != nil {
		return nil, fmt.Errorf("catalog: marshal %s schemas: %w", label, err)
	}
	artifacts, err := ipcregistry.ParseProviderArtifacts(descriptorWire, schemaWire)
	if err != nil {
		return nil, fmt.Errorf("catalog: validate %s artifacts: %w", label, err)
	}
	return artifacts, nil
}

func bootstrapInterface(
	interfaceID string,
	bundle *ipcv1.InterfaceSchemaBundle,
	requiredPermission string,
	riskFloor ipcv1.RiskClass,
	compatible []string,
	defaultType string,
	defaultRole string,
) *ipcv1.ProvidedInterface {
	return &ipcv1.ProvidedInterface{
		InterfaceId: interfaceID,
		InterfaceVersions: []*ipcv1.ProvidedInterfaceVersion{{
			Major: 1, SchemaHash: append([]byte(nil), bundle.GetSchemaHash()...),
		}},
		RequiredPermission:      requiredPermission,
		ResourceRiskFloor:       riskFloor,
		CompatibleResourceTypes: append([]string(nil), compatible...),
		DefaultResourceType:     defaultType,
		DefaultResourceRole:     defaultRole,
	}
}

func bootstrapPermissions() []*ipcv1.DefinedPermission {
	return []*ipcv1.DefinedPermission{
		bootstrapPermission(
			"perm.diagnostics.read",
			ipcv1.GrantMode_GRANT_MODE_NORMAL,
			ipcv1.RiskClass_RISK_CLASS_NORMAL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			"",
			"",
			"Read diagnostics",
			"Read diagnostics",
		),
		bootstrapPermission(
			"perm.service.register.private",
			ipcv1.GrantMode_GRANT_MODE_NORMAL,
			ipcv1.RiskClass_RISK_CLASS_NORMAL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			"",
			"",
			"Register a package-private service",
			"Register a package-private service",
		),
		bootstrapPermission(
			"perm.service.register",
			ipcv1.GrantMode_GRANT_MODE_PRIVILEGED,
			ipcv1.RiskClass_RISK_CLASS_NORMAL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_OEM,
			"",
			"",
			"Register a public system service",
			"Register a public system service",
		),
		// perm.storage.shared 是服务之间交换配置, 模型, 缓存的门槛.
		//
		// 与 perm.storage.user 刻意分开: 那是"用户的文档", 语义面向 App 与
		// 文件选择器, 因此是 USER_CONSENT + PRIVACY_SENSITIVE; 而两个服务想放个
		// 中间文件, 不该变成"要用户同意访问他的文档".
		//
		// GRANT_MODE_NORMAL + Ordinary: 共享区里本就只该放"拿到这条权限就有资格
		// 看"的东西. 需要更细门槛的数据 (摄像头帧一类) 必须走 Transfer 的内存
		// 句柄 - 那里句柄本身就是凭证, 没有文件系统路径可绕.
		bootstrapPermission(
			"perm.storage.shared",
			ipcv1.GrantMode_GRANT_MODE_NORMAL,
			ipcv1.RiskClass_RISK_CLASS_NORMAL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			"",
			"storage",
			"Read and write the inter-service shared area",
			"Read and write the inter-service shared area",
		),
		bootstrapPermission(
			"perm.storage.user",
			ipcv1.GrantMode_GRANT_MODE_USER_CONSENT,
			ipcv1.RiskClass_RISK_CLASS_PRIVACY_SENSITIVE,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			"",
			"storage",
			"Access user files",
			"Access user files",
		),
		bootstrapPermission(
			"perm.system.launch",
			ipcv1.GrantMode_GRANT_MODE_SYSTEM_ONLY,
			ipcv1.RiskClass_RISK_CLASS_NORMAL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_PLATFORM,
			"",
			"",
			"Launch system components",
			"Launch system components",
		),
		bootstrapPermission(
			"perm.motion.control",
			ipcv1.GrantMode_GRANT_MODE_USER_CONSENT,
			ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			"",
			"motion",
			"Control robot motion",
			"Control robot motion",
		),
		bootstrapPermission(
			"perm.manipulator.control",
			ipcv1.GrantMode_GRANT_MODE_USER_CONSENT,
			ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			"",
			"motion",
			"Control the manipulator",
			"Control the manipulator",
		),
		bootstrapPermission(
			"perm.platform.control",
			ipcv1.GrantMode_GRANT_MODE_PRIVILEGED,
			ipcv1.RiskClass_RISK_CLASS_NORMAL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_PLATFORM,
			"",
			"",
			"Platform control",
			"Platform control",
		),
		bootstrapPermission(
			"perm.authority.reboot",
			ipcv1.GrantMode_GRANT_MODE_SYSTEM_ONLY,
			ipcv1.RiskClass_RISK_CLASS_CRITICAL_SAFETY,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_PLATFORM,
			rolePlatformRelease,
			"",
			"Emergency reboot",
			"Emergency reboot",
		),
		bootstrapPermission(
			"perm.authority.power",
			ipcv1.GrantMode_GRANT_MODE_PRIVILEGED,
			ipcv1.RiskClass_RISK_CLASS_CRITICAL_SAFETY,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_PLATFORM,
			"",
			"",
			"Orderly power control",
			"Orderly power control",
		),
		bootstrapPermission(
			"perm.safety.observe",
			ipcv1.GrantMode_GRANT_MODE_PRIVILEGED,
			ipcv1.RiskClass_RISK_CLASS_NORMAL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_OEM,
			"",
			"",
			"Observe safety state",
			"Observe safety state",
		),
		bootstrapPermission(
			"perm.safety.rearm",
			ipcv1.GrantMode_GRANT_MODE_SYSTEM_ONLY,
			ipcv1.RiskClass_RISK_CLASS_CRITICAL_SAFETY,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_PLATFORM,
			rolePlatformRelease,
			"",
			"Re-arm the safety system",
			"Re-arm the safety system",
		),
		bootstrapPermission(
			"perm.pkg.install",
			ipcv1.GrantMode_GRANT_MODE_USER_CONSENT,
			ipcv1.RiskClass_RISK_CLASS_PRIVACY_SENSITIVE,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			"",
			"",
			"Install or uninstall packages",
			"Install or uninstall packages",
		),
		// perm.pkg.admin 取代了曾经写死在 main.go 里的"哪个 Package ID 能连
		// 管理通道". 持有它的包可以连上 admin UDS 并获得可写 staging 目录.
		//
		// 三重收紧与 perm.safety.rearm 同款, 这不是巧合 - 两者都是"一旦拿到就
		// 能改变整机状态"的能力:
		//  SYSTEM_ONLY -> IntersectAt 要求来源必须是系统镜像包
		//  PLATFORM -> 开发构建降级到 Ordinary 的包拿不到
		//  platform-release 签名角色 -> 必须由平台发布密钥签过
		//
		// 安全边界与之前完全一致: 放行的仍然只是"谁能连上这条 socket".
		// 全部命令依旧投递给同进程的 pkgregistry.Module 复核签名, digest,
		// 升级裁决与权限交集. 变的只是"凭什么放行" - 从内核硬编码的包名,
		// 变成一条包必须在 manifest 里显式声明, 且经过裁决的权限.
		bootstrapPermission(
			"perm.pkg.admin",
			ipcv1.GrantMode_GRANT_MODE_SYSTEM_ONLY,
			ipcv1.RiskClass_RISK_CLASS_CRITICAL_SAFETY,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_PLATFORM,
			rolePlatformRelease,
			"",
			"Administer packages and grants on behalf of the system",
			"Administer packages and grants on behalf of the system",
		),
		// perm.resource.query 是设备发现的门槛.
		//
		// 与 perm.diagnostics.read / perm.pkg.query 同一档 (NORMAL + Ordinary):
		// 它暴露的是"这台机器上有哪些硬件", 而那件事 App 靠反复 Resolve 试探
		// 本来也能问出来 - 目录只是把试探变成一次查询, 没有放大暴露面.
		//
		// 真正的门槛在用上: 拿到摄像头列表不等于能取流, 那要 perm.camera.capture.
		bootstrapPermission(
			"perm.resource.query",
			ipcv1.GrantMode_GRANT_MODE_NORMAL,
			ipcv1.RiskClass_RISK_CLASS_NORMAL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			"",
			"",
			"List hardware resources on this device",
			"List hardware resources on this device",
		),
		bootstrapPermission(
			"perm.pkg.query",
			ipcv1.GrantMode_GRANT_MODE_NORMAL,
			ipcv1.RiskClass_RISK_CLASS_NORMAL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			"",
			"",
			"List installed packages",
			"List installed packages",
		),
		bootstrapPermission(
			"perm.permission.admin",
			ipcv1.GrantMode_GRANT_MODE_SYSTEM_ONLY,
			ipcv1.RiskClass_RISK_CLASS_CRITICAL_SAFETY,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_PLATFORM,
			rolePlatformRelease,
			"",
			"Manage runtime grants",
			"Manage runtime grants",
		),
	}
}

func bootstrapPermission(
	id string,
	mode ipcv1.GrantMode,
	risk ipcv1.RiskClass,
	minimum ipcv1.PermissionTrustFloor,
	requiredRole string,
	group string,
	zhCN string,
	en string,
) *ipcv1.DefinedPermission {
	return &ipcv1.DefinedPermission{
		Id:                 id,
		GrantMode:          mode,
		RiskClass:          risk,
		MinimumTrust:       minimum,
		RequiredSignerRole: requiredRole,
		Group:              group,
		DisplayName:        &ipcv1.LocalizedText{ZhCn: zhCN, En: en},
		Description:        &ipcv1.LocalizedText{ZhCn: zhCN, En: en},
	}
}
