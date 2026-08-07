package catalog

import (
	"strings"
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	ipcregistry "github.com/nervus-os/nervus-ipc/registry"

	"github.com/nervus-os/nervud/internal/identity"
)

// 本文件验的是【标准摄像头资源上的归属边界】。
//
// 它在 V2-3.5 时构造不出来：那时没有任何接口把 nervus.resource.camera 列为
// compatible_resource_type，而 authorizeResource 禁止 OEM 引入内核不认识的标准
// 类型——于是「两方抢同一个 role」这种冲突根本走不到冲突检测那一步。
//
// nervus.interface.camera 由 platform-release 签名的 nervus.camerad 声明之后，
// 这条路径才第一次真实存在。
//
// # 谁声明什么（这决定了下面每个用例的形状）
//
//	nervus.camerad（platform-release）
//	  ├─ nervus.interface.camera@1        标准接口
//	  ├─ perm.camera.capture              标准权限
//	  └─ nervus.resource.camera 的实例    ← 板级 JSON 出的语义 role + nervus.* 标签
//
//	厂商包（oem-service）
//	  └─ vendor.*.interface.source@1      私有画面源，camerad 去 Resolve 它
//
// 【语义标签只能由 camerad 给】。厂商提供的是一路画面，不是「这路画面朝哪边」——
// 后者是板级事实，随板子走，不随摄像头模组走。
const (
	testCameraInterface = "nervus.interface.camera"
	testCameraResource  = "nervus.resource.camera"
	testCameraPerm      = "perm.camera.capture"
)

// cameradSource 模拟 platform-release 签名的 nervus.camerad。
//
// 它【必须同时声明接口与资源实例】：ParseProviderArtifacts 要求一个接口列为
// compatible 的资源类型，必须由同一份 descriptor 管着实例。那条不变量拦的是
// 「声明一个自己毫无关系的资源类型为兼容」——那会让接口凭空获得对别人硬件的
// 路由资格。
//
// 【只有它有资格定义 nervus.*】。厂商包签的是 oem-service，定义 nervus.* 接口
// 与 perm.* 权限都会被 authorizeNewInterface / authorizePermissionNamespace 拒绝。
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
			// 平台标签：板级 JSON 的产物，App 按它选设备。
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
			DisplayName:  &ipcv1.LocalizedText{ZhCn: "使用摄像头", En: "Use the camera"},
			Description:  &ipcv1.LocalizedText{ZhCn: "使用摄像头", En: "Use the camera"},
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

// vendorCameraSource 模拟一个 OEM 厂商包，为某个 role 提供一路标准摄像头。
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

// noBundles 是元数据接口的 schema 集合：方法元数据内联在 ProvidedInterface
// 里，没有 protobuf message，因此不需要任何 bundle。
func noBundles() *ipcv1.InterfaceSchemaBundleSet {
	return &ipcv1.InterfaceSchemaBundleSet{}
}

// 【前提】：没有任何接口声明 nervus.resource.camera 之前，OEM 不能凭空引入它。
//
// 这是厂商互换能成立的基础——「标准类型」必须先由平台定义出语义，厂商才是在
// 实现一个已知的东西，而不是在自造一个恰好叫这个名字的东西。
func TestVendorCamera_CannotIntroduceUnknownStandardType(t *testing.T) {
	registry := mustDefaultRegistry(t)
	_, err := registry.Prepare([]Source{
		vendorCameraSource(t, "com.acme.camera", "cam.front", nil),
	})
	if err == nil {
		t.Fatal("OEM 凭空引入了标准资源类型")
	}
	if !strings.Contains(err.Error(), "unknown standard resource type") {
		t.Fatalf("err = %v, want 未知标准类型拒绝", err)
	}
}

// 类型已知之后，厂商可以补一路板级配置里没有的摄像头。
//
// 这是给板级集成商留的口子：camerad 的板级 JSON 认识不了每一块扩展板。补进来的
// 那一路【没有平台标签】，因此只能按 role 选到，选不到「前视」——语义归属仍然
// 留在平台手里。
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
		t.Fatalf("matched = %+v, want 两路", matched)
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
	// 厂商补的那一路没有平台标签，按语义选设备时选不到它。
	if len(byRole["cam.wrist"].Labels) != 0 {
		t.Errorf("厂商资源带上了标签: %v", byRole["cam.wrist"].Labels)
	}
	front := FilterResources(candidate.Snapshot(), testCameraResource, "",
		map[string]string{"nervus.camera.facing": "front"})
	if len(front) != 1 || front[0].StableRole != "cam.front" {
		t.Fatalf("按 facing=front 选到 %+v, want 只有 camerad 声明的那一路", front)
	}
}

// 【两个厂商抢同一个 role 必须被拒】。
//
// 两份声明的契约字段完全一致（同类型、同 role、同访问模式、同风险级、都没标签），
// 所以 sameResourceContract 放行——真正拦住的是「一个资源只能有一个管理者」。
//
// 不拦的后果不是报错，而是【静默的错设备】：cam.wrist 到底路由到谁的摄像头
// 取决于两个包的扫描顺序，换一次装包顺序画面就换一个。
func TestVendorCamera_TwoVendorsCannotClaimSameRole(t *testing.T) {
	registry := mustDefaultRegistry(t)
	_, err := registry.Prepare([]Source{
		cameradSource(t, "cam.front"),
		vendorCameraSource(t, "com.acme.camera", "cam.wrist", nil),
		vendorCameraSource(t, "com.globex.camera", "cam.wrist", nil),
	})
	if err == nil {
		t.Fatal("两个厂商同时占用 cam.wrist 被接受了")
	}
	if !strings.Contains(err.Error(), "multiple managers") {
		t.Fatalf("err = %v, want 多管理者拒绝", err)
	}
	// 错误必须指名【两个】冲突方：只说「有冲突」的话，运维还得自己去翻
	// 全部已装包才能知道要卸掉哪一个。
	if !strings.Contains(err.Error(), "com.acme.camera") ||
		!strings.Contains(err.Error(), "com.globex.camera") {
		t.Fatalf("err = %v, want 指名两个冲突包", err)
	}
}

// 不同 role 互不影响：这才是多摄像头的正常形态。
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
		t.Fatalf("matched = %+v, want 四路", got)
	}
}

// 同一个 role 上契约不一致（一方声明可独占）时，拦住它的是契约比对而不是
// 管理者检查——两条防线各管一头，错误信息也应当不同。
//
// 声明成 EXCLUSIVE_CONTROL 的后果很具体：那一路摄像头会突然变得可被独占，
// 一个 App 拿到租约，其余全部被挡在外面。
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
		t.Fatal("同一 role 上的冲突契约被接受了")
	}
	if !strings.Contains(err.Error(), "conflicts with definition owned by") {
		t.Fatalf("err = %v, want 契约冲突拒绝", err)
	}
}

// 【厂商不能接管平台已经声明的 role】——这是比两个厂商互撞更要紧的一条。
//
// 接管成功意味着 App 请求「前视摄像头」会拿到厂商的设备，而 App 无从察觉：
// role 对得上、类型对得上，画面也确实出得来，只是朝向错了。
//
// 拦住它的是契约比对：平台那一份带 nervus.camera.facing 标签，厂商这一份没有，
// 标签是契约的一部分，两者不同即拒绝。
func TestVendorCamera_CannotHijackPlatformRole(t *testing.T) {
	registry := mustDefaultRegistry(t)
	_, err := registry.Prepare([]Source{
		cameradSource(t, "cam.front"),
		vendorCameraSource(t, "com.acme.camera", "cam.front", nil),
	})
	if err == nil {
		t.Fatal("厂商接管了平台声明的 cam.front")
	}
	if !strings.Contains(err.Error(), "conflicts with definition owned by") ||
		!strings.Contains(err.Error(), "nervus.camerad") {
		t.Fatalf("err = %v, want 指名 nervus.camerad 的契约冲突", err)
	}
}

// 抄一份一模一样的标签也接管不了——那一步先被标签命名空间挡下。
//
// 两条防线【顺序上先后不同、拦的是同一件事】：契约比对拦「标签不一样」，
// 命名空间授权拦「标签一样」。少任何一条，接管就有一条路走得通。
func TestVendorCamera_CannotHijackPlatformRoleByCopyingLabels(t *testing.T) {
	registry := mustDefaultRegistry(t)
	_, err := registry.Prepare([]Source{
		cameradSource(t, "cam.front"),
		vendorCameraSource(t, "com.acme.camera", "cam.front", func(r *ipcv1.ManagedResource) {
			r.Labels = map[string]string{"nervus.camera.facing": "front"}
		}),
	})
	if err == nil {
		t.Fatal("厂商抄标签接管了 cam.front")
	}
	if !strings.Contains(err.Error(), "platform-release") {
		t.Fatalf("err = %v, want 平台标签授权拒绝", err)
	}
}

// 【厂商不能在标准资源上打平台标签】。
//
// 这是伪装成前视摄像头的正路：类型是标准的、role 是自己的，只要能加一个
// nervus.camera.facing=front，按语义选设备的 App 就会选到它。
//
// 语义标签只能由 platform-release 的板级配置给出——厂商提供的是【一路画面】，
// 不是「这路画面朝哪边」。
func TestVendorCamera_CannotLabelStandardResourceAsPlatformSemantic(t *testing.T) {
	registry := mustDefaultRegistry(t)
	_, err := registry.Prepare([]Source{
		cameradSource(t, "cam.front"),
		vendorCameraSource(t, "com.acme.camera", "cam.side", func(r *ipcv1.ManagedResource) {
			r.Labels = map[string]string{"nervus.camera.facing": "front"}
		}),
	})
	if err == nil {
		t.Fatal("厂商在标准资源上打了平台标签")
	}
	if !strings.Contains(err.Error(), "platform-release") {
		t.Fatalf("err = %v, want 平台标签授权拒绝", err)
	}
}

// 厂商也不能定义 nervus.* 接口——否则它可以另造一份「标准摄像头接口」，
// 用一套自己说了算的语义去冒充平台契约。
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
		t.Fatal("厂商定义了平台命名空间下的接口")
	} else if !strings.Contains(err.Error(), "platform-release") {
		t.Fatalf("err = %v, want 平台接口授权拒绝", err)
	}
}
