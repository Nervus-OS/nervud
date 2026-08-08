package catalog

import (
	"fmt"

	basemotionv1 "github.com/nervus-os/nervus-ipc/protocol/interface/basemotionv1"
	manipulatorv1 "github.com/nervus-os/nervus-ipc/protocol/interface/manipulatorv1"
	operationv1 "github.com/nervus-os/nervus-ipc/protocol/interface/operationv1"
	permissionv1 "github.com/nervus-os/nervus-ipc/protocol/interface/permissionv1"
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
			{ComponentID: "builtin.permission", InterfaceID: InterfacePermissionAdmin},
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
	permissionBundle, err := ipcregistry.BuildSchemaBundle(
		InterfacePermissionAdmin, 1, permissionv1.PermissionAdminMethod(0).Descriptor())
	if err != nil {
		return nil, fmt.Errorf("catalog: build permission-admin bootstrap schema: %w", err)
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
			// 授权面同样不绑资源: 它管的是权限, 不是设备.
			//
			// required_permission 就是 perm.permission.admin 本身 —— 接口门槛
			// 与方法门槛同一条, 因此拿不到它的调用方连 Resolve 都过不去,
			// 不会走到"能解析但每个方法都被拒"那种半开状态
			bootstrapInterface(
				InterfacePermissionAdmin,
				permissionBundle,
				"perm.permission.admin",
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
		permissionBundle,
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
			permText{
				NameZhCN: "读取诊断信息",
				NameEN:   "Read diagnostics",
				DescZhCN: "读取本机的运行状态与诊断数据",
				DescEN:   "Read this device's runtime status and diagnostic data",
			},
		),
		bootstrapPermission(
			"perm.service.register.private",
			ipcv1.GrantMode_GRANT_MODE_NORMAL,
			ipcv1.RiskClass_RISK_CLASS_NORMAL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			"",
			"",
			permText{
				NameZhCN: "注册包内私有服务",
				NameEN:   "Register a package-private service",
				DescZhCN: "在本应用内部注册只有自己能解析的服务",
				DescEN:   "Register a service inside this package that only the package itself can resolve",
			},
		),
		bootstrapPermission(
			"perm.service.register",
			ipcv1.GrantMode_GRANT_MODE_PRIVILEGED,
			ipcv1.RiskClass_RISK_CLASS_NORMAL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_OEM,
			"",
			"",
			permText{
				NameZhCN: "注册公开系统服务",
				NameEN:   "Register a public system service",
				DescZhCN: "注册可被本机其它应用解析的公开服务",
				DescEN:   "Register a service that other applications on this device can resolve",
			},
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
			permText{
				NameZhCN: "读写服务间共享区",
				NameEN:   "Read and write the inter-service shared area",
				DescZhCN: "在服务之间交换配置、模型与缓存文件，不含访问你的个人文档",
				DescEN:   "Exchange configuration, models and cache files between services; does not include access to your personal documents",
			},
		),
		bootstrapPermission(
			"perm.storage.user",
			ipcv1.GrantMode_GRANT_MODE_USER_CONSENT,
			ipcv1.RiskClass_RISK_CLASS_PRIVACY_SENSITIVE,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			"",
			"storage",
			permText{
				NameZhCN: "访问用户文件",
				NameEN:   "Access user files",
				DescZhCN: "读取和修改你保存在本机上的文档、图片等文件",
				DescEN:   "Read and modify the documents, images and other files you keep on this device",
			},
		),
		bootstrapPermission(
			"perm.system.launch",
			ipcv1.GrantMode_GRANT_MODE_SYSTEM_ONLY,
			ipcv1.RiskClass_RISK_CLASS_NORMAL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_PLATFORM,
			"",
			"",
			permText{
				NameZhCN: "启动系统组件",
				NameEN:   "Launch system components",
				DescZhCN: "拉起本机上的其它应用与系统组件",
				DescEN:   "Start other applications and system components on this device",
			},
		),
		bootstrapPermission(
			"perm.motion.control",
			ipcv1.GrantMode_GRANT_MODE_USER_CONSENT,
			ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			"",
			"motion",
			permText{
				NameZhCN: "控制机器人移动",
				NameEN:   "Control robot motion",
				DescZhCN: "驱动底盘让本机器人移动，可能造成碰撞或人身伤害",
				DescEN:   "Drive the chassis to move this robot, which may cause collisions or injury",
			},
		),
		bootstrapPermission(
			"perm.manipulator.control",
			ipcv1.GrantMode_GRANT_MODE_USER_CONSENT,
			ipcv1.RiskClass_RISK_CLASS_PHYSICAL_CONTROL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			"",
			"motion",
			permText{
				NameZhCN: "控制机械臂",
				NameEN:   "Control the manipulator",
				DescZhCN: "驱动机械臂动作，可能造成碰撞或人身伤害",
				DescEN:   "Move the manipulator, which may cause collisions or injury",
			},
		),
		bootstrapPermission(
			"perm.platform.control",
			ipcv1.GrantMode_GRANT_MODE_PRIVILEGED,
			ipcv1.RiskClass_RISK_CLASS_NORMAL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_PLATFORM,
			"",
			"",
			permText{
				NameZhCN: "平台控制",
				NameEN:   "Platform control",
				DescZhCN: "更改影响整机行为的平台级设置",
				DescEN:   "Change platform-level settings that affect the whole device",
			},
		),
		bootstrapPermission(
			"perm.authority.reboot",
			ipcv1.GrantMode_GRANT_MODE_SYSTEM_ONLY,
			ipcv1.RiskClass_RISK_CLASS_CRITICAL_SAFETY,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_PLATFORM,
			rolePlatformRelease,
			"",
			permText{
				NameZhCN: "紧急重启",
				NameEN:   "Emergency reboot",
				DescZhCN: "不经有序关停直接重启本机，用于故障恢复",
				DescEN:   "Reboot this device immediately without an orderly shutdown, for fault recovery",
			},
		),
		bootstrapPermission(
			"perm.authority.power",
			ipcv1.GrantMode_GRANT_MODE_PRIVILEGED,
			ipcv1.RiskClass_RISK_CLASS_CRITICAL_SAFETY,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_PLATFORM,
			"",
			"",
			permText{
				NameZhCN: "电源控制",
				NameEN:   "Orderly power control",
				DescZhCN: "有序重启或关闭本机",
				DescEN:   "Restart or shut down this device in an orderly way",
			},
		),
		bootstrapPermission(
			"perm.safety.observe",
			ipcv1.GrantMode_GRANT_MODE_PRIVILEGED,
			ipcv1.RiskClass_RISK_CLASS_NORMAL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_OEM,
			"",
			"",
			permText{
				NameZhCN: "观察安全状态",
				NameEN:   "Observe safety state",
				DescZhCN: "读取安全系统的当前状态与状态迁移，不含解除保护的能力",
				DescEN:   "Read the safety system's current state and its transitions; does not include clearing a trip",
			},
		),
		bootstrapPermission(
			"perm.safety.rearm",
			ipcv1.GrantMode_GRANT_MODE_SYSTEM_ONLY,
			ipcv1.RiskClass_RISK_CLASS_CRITICAL_SAFETY,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_PLATFORM,
			rolePlatformRelease,
			"",
			permText{
				NameZhCN: "重置安全系统",
				NameEN:   "Re-arm the safety system",
				DescZhCN: "在安全系统触发后解除保护状态，使机器人恢复可动",
				DescEN:   "Clear the safety system's protective state after a trip, allowing the robot to move again",
			},
		),
		bootstrapPermission(
			"perm.pkg.install",
			ipcv1.GrantMode_GRANT_MODE_USER_CONSENT,
			ipcv1.RiskClass_RISK_CLASS_PRIVACY_SENSITIVE,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			"",
			"",
			permText{
				NameZhCN: "安装和卸载应用",
				NameEN:   "Install or uninstall packages",
				DescZhCN: "在本机上安装、卸载应用，或启用停用它们的组件",
				DescEN:   "Install and uninstall applications on this device, or enable and disable their components",
			},
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
			permText{
				NameZhCN: "代表系统管理应用",
				NameEN:   "Administer packages and grants on behalf of the system",
				DescZhCN: "连接内核管理通道，代表系统执行装包与授权变更",
				DescEN:   "Connect to the kernel administration channel and perform package and grant changes on behalf of the system",
			},
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
			permText{
				NameZhCN: "查看硬件资源",
				NameEN:   "List hardware resources on this device",
				DescZhCN: "列出本机有哪些摄像头、底盘等硬件，不含使用它们的权限",
				DescEN:   "List which cameras, chassis and other hardware this device has; does not include permission to use them",
			},
		),
		bootstrapPermission(
			"perm.pkg.query",
			ipcv1.GrantMode_GRANT_MODE_NORMAL,
			ipcv1.RiskClass_RISK_CLASS_NORMAL,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_ORDINARY,
			"",
			"",
			permText{
				NameZhCN: "查看已安装应用",
				NameEN:   "List installed packages",
				DescZhCN: "列出本机已安装的应用及其组件",
				DescEN:   "List the applications installed on this device and their components",
			},
		),
		bootstrapPermission(
			"perm.permission.admin",
			ipcv1.GrantMode_GRANT_MODE_SYSTEM_ONLY,
			ipcv1.RiskClass_RISK_CLASS_CRITICAL_SAFETY,
			ipcv1.PermissionTrustFloor_PERMISSION_TRUST_FLOOR_PLATFORM,
			rolePlatformRelease,
			"",
			permText{
				NameZhCN: "管理运行期授权",
				NameEN:   "Manage runtime grants",
				DescZhCN: "代表系统查看并更改各应用的敏感权限授予状态",
				DescEN:   "View and change other applications' sensitive permission grants on behalf of the system",
			},
		),
	}
}

// permText 是一条权限的对外文案.
//
// Name 与 Desc 必须分开: 授权屏上前者是那一行的标题 ("访问用户文件"), 后者是
// 标题下面解释这意味着什么的那句话 ("读取和修改你保存在设备上的文档"). 二者
// 曾经共用同一个串, 那样授权屏上标题与说明会一模一样, 等于没有说明.
//
// 中英各一份且都不能省: 这是用户在授权屏上唯一读得到的东西, ZhCn 位置放英文
// 占位等于中文界面上直接显示英文.
type permText struct {
	NameZhCN, NameEN string
	DescZhCN, DescEN string
}

func bootstrapPermission(
	id string,
	mode ipcv1.GrantMode,
	risk ipcv1.RiskClass,
	minimum ipcv1.PermissionTrustFloor,
	requiredRole string,
	group string,
	text permText,
) *ipcv1.DefinedPermission {
	return &ipcv1.DefinedPermission{
		Id:                 id,
		GrantMode:          mode,
		RiskClass:          risk,
		MinimumTrust:       minimum,
		RequiredSignerRole: requiredRole,
		Group:              group,
		DisplayName:        &ipcv1.LocalizedText{ZhCn: text.NameZhCN, En: text.NameEN},
		Description:        &ipcv1.LocalizedText{ZhCn: text.DescZhCN, En: text.DescEN},
	}
}
