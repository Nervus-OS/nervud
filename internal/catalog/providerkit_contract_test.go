package catalog

import (
	"testing"

	ipcregistry "github.com/nervus-os/nervus-ipc/registry"
	"github.com/nervus-os/nervus-ipc/registry/providerkit"

	"github.com/nervus-os/nervud/internal/identity"
)

// 本文件钉住一件只在真机上才会暴露的事: nervus-ipc 的 providerkit 为
// Kotlin 系统应用生成的 ProviderArtifacts, 必须与本包 bootstrap 里同名接口的
// 定义【逐字一致】.
//
// # 为什么需要一道专门的测试
//
// permissionui 导出 nervus.interface.permission.ui, 而内核 bootstrap 也定义了
// 同一个接口 (它是标准接口). 两份定义相遇时 Builder 走 sameInterfaceContract:
// 对 InterfaceDefinition 做 reflect.DeepEqual, 再对每条 MethodMeta 与 EventMeta
// 做 proto.Equal. 任何一处不同 (required_permission 写歪一个字、risk floor 多填
// 一档) 都会让第二个 Provider 被拒.
//
// 那个失败【不在编译期, 也不在两个仓库各自的测试里】: providerkit 在 nervus-ipc,
// bootstrap 在这里, 两边都能独立通过自己的测试. 症状是装了 permissionui 的镜像
// 一开机就把它隔离, 而错误信息说的是"接口冲突", 离"两处 required_permission
// 不一致"这个真正的原因很远 —— 而且那时镜像已经烧好了.
//
// 于是把两份定义在这里对撞一次. 这道钉子比产物本身重要.

// providerkitSpecFor 从 providerkit 的集中清单里取一个包的 spec.
//
// 刻意不在本文件里重写一份 spec: 那样测的就变成"我抄的这份与 bootstrap 一致",
// 而真正装进镜像的是 providerkit 那份.
func providerkitSpecFor(t *testing.T, packageID string) providerkit.Spec {
	t.Helper()
	for _, spec := range providerkit.All() {
		if spec.PackageID == packageID {
			return spec
		}
	}
	t.Fatalf("providerkit.All() has no spec for %q", packageID)
	return providerkit.Spec{}
}

// providerkitArtifacts 走 providerkit.Build 生成产物并解析成 Catalog 能吃的形态.
//
// 走 Build 而不是读 committed 的 .binpb 文件: 那两个文件在 nervus-ipc 仓库里,
// 本仓库的测试不该依赖另一个仓库的目录布局 (go module 缓存里的路径不稳定).
// providerkit 自己那道门禁已经钉住"committed 字节 == Build 输出", 因此这里
// 测 Build 的输出等价于测那两个文件.
func providerkitArtifacts(t *testing.T, packageID string) *ipcregistry.ProviderArtifacts {
	t.Helper()
	built, err := providerkit.Build(providerkitSpecFor(t, packageID))
	if err != nil {
		t.Fatalf("providerkit.Build(%q): %v", packageID, err)
	}
	artifacts, err := ipcregistry.ParseProviderArtifacts(built.DescriptorWire, built.SchemaWire)
	if err != nil {
		t.Fatalf("ParseProviderArtifacts(%q): %v", packageID, err)
	}
	return artifacts
}

// permissionUISource 构造一个与真实 permissionui 包等价的 Source.
//
// Trust 与 Signers 必须是 platform-release: nervus.* 前缀的接口由
// authorizeNewInterface 要求该角色 (见 builder.go). permissionui 的 nspkg 里
// signing.role 正是 platform-release, 这里如实反映.
func permissionUISource(t *testing.T) Source {
	t.Helper()
	return Source{
		PackageID: "nervus.permissionui",
		Kind:      SourceKindSystemImage,
		Trust:     identity.TrustPlatform,
		Signers: SignerEvidence{
			Roles: []string{rolePlatformRelease},
			VerifiedSigners: []VerifiedSigner{{
				Role: rolePlatformRelease, KeyID: "platform-release-key",
			}},
		},
		// Exports 必须与 descriptor 里声明的接口一一对应: addArtifacts 是
		// 双向闭合的 —— descriptor 里有而 exports 里没有, 或反之, 两种都拒.
		Exports: []ExportBinding{{
			ComponentID: "main",
			InterfaceID: InterfacePermissionUI,
		}},
		Artifacts: providerkitArtifacts(t, "nervus.permissionui"),
	}
}

// TestProviderkitPermissionUIMatchesBootstrap 是核心门禁.
//
// Prepare 成功即意味着 providerkit 那份定义通过了 sameInterfaceContract ——
// 那个函数是私有的, 但 Prepare 是它唯一的入口, 契约不符会在这里返回错误.
func TestProviderkitPermissionUIMatchesBootstrap(t *testing.T) {
	registry := mustDefaultRegistry(t)
	candidate, err := registry.Prepare([]Source{permissionUISource(t)})
	if err != nil {
		t.Fatalf("providerkit artifacts conflict with bootstrap contract: %v", err)
	}

	// 接口级门槛必须仍是 bootstrap 声明的那条. 单看 Prepare 成功不够:
	// 若将来有人把两边【同时】改成另一个值, 契约依旧自洽, 但 permission.ui
	// 的可见性就悄悄变了. 这里把预期值写死, 让那种改动必须显式经过本测试.
	iface, ok := candidate.Snapshot().Interface(InterfacePermissionUI, 1)
	if !ok {
		t.Fatal("permission.ui interface missing from prepared snapshot")
	}
	if iface.RequiredPermission != "perm.pkg.query" {
		t.Errorf("permission.ui required permission = %q, want perm.pkg.query",
			iface.RequiredPermission)
	}

	// ConfirmInstall (method 1) 的请求类型: 钉住"schema bundle 真的进了 Catalog",
	// 而不是只有一个 hash 对上了. 一个空 descriptor set 也能算出 hash,
	// 但那时方法的 request/response 类型是 nil, 调用路径上无从校验载荷.
	method, ok := candidate.Snapshot().ProviderMethod(
		"nervus.permissionui", InterfacePermissionUI, 1, 1)
	if !ok {
		t.Fatal("permission.ui method 1 missing from prepared snapshot")
	}
	if method.Request == nil ||
		string(method.Request.FullName()) != "nervus.interface.permission.v1.ConfirmInstallRequest" {
		t.Errorf("permission.ui method 1 request = %v, want ConfirmInstallRequest", method.Request)
	}
}

// TestProviderkitPermissionUIWrongPermissionConflicts 反向钉住这道门确实在起作用.
//
// 没有这条, 上面那个测试无法区分"契约一致"与"sameInterfaceContract 根本没被调用".
// 把 required_permission 改成另一条合法权限, Prepare 必须失败.
func TestProviderkitPermissionUIWrongPermissionConflicts(t *testing.T) {
	spec := providerkitSpecFor(t, "nervus.permissionui")
	// 复制一份再改, 不碰 providerkit.All() 返回的那份
	tampered := providerkit.Spec{
		PackageID:  spec.PackageID,
		Interfaces: make([]providerkit.Interface, len(spec.Interfaces)),
	}
	copy(tampered.Interfaces, spec.Interfaces)
	for i := range tampered.Interfaces {
		if tampered.Interfaces[i].ID == InterfacePermissionUI {
			// perm.pkg.install 是一条真实存在的权限, 因此失败原因只能是契约不符,
			// 不会是"引用了未定义的权限"
			tampered.Interfaces[i].RequiredPermission = "perm.pkg.install"
		}
	}

	built, err := providerkit.Build(tampered)
	if err != nil {
		t.Fatalf("providerkit.Build(tampered): %v", err)
	}
	artifacts, err := ipcregistry.ParseProviderArtifacts(built.DescriptorWire, built.SchemaWire)
	if err != nil {
		t.Fatalf("ParseProviderArtifacts(tampered): %v", err)
	}

	source := permissionUISource(t)
	source.Artifacts = artifacts

	registry := mustDefaultRegistry(t)
	if _, err := registry.Prepare([]Source{source}); err == nil {
		t.Fatal("unexpected catalog result; tampered required_permission must conflict with bootstrap")
	}
}
