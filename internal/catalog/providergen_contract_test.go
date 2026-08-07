package catalog

import (
	"testing"

	pkgmanagerv1 "github.com/nervus-os/nervus-ipc/protocol/interface/pkgmanagerv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	ipcregistry "github.com/nervus-os/nervus-ipc/registry"

	"github.com/nervus-os/nervud/internal/identity"
)

// providergenStyleArtifacts 复刻 nervus-system-server 的
// pkgmanagerd/providergen 产出的 ProviderDescriptor —— 不经过
// LegacyPackageManagerArtifacts，即随包分发的真实形态。
//
// 这里刻意手写而不是调用兼容桥：兼容桥正在被拆除，而本测试要断言的正是
// 「拆掉之后这条路仍然通」。
func providergenStyleArtifacts(t *testing.T) *ipcregistry.ProviderArtifacts {
	t.Helper()
	bundle, err := ipcregistry.BuildSchemaBundle(
		InterfacePackageManager, 1, pkgmanagerv1.PackageManagerMethod(0).Descriptor())
	if err != nil {
		t.Fatalf("BuildSchemaBundle: %v", err)
	}
	descriptor := &ipcv1.ProviderDescriptor{
		PackageId: "nervus.pkgmanagerd",
		Interfaces: []*ipcv1.ProvidedInterface{{
			InterfaceId: InterfacePackageManager,
			InterfaceVersions: []*ipcv1.ProvidedInterfaceVersion{{
				Major: 1, SchemaHash: append([]byte(nil), bundle.GetSchemaHash()...),
			}},
			RequiredPermission: "perm.pkg.query",
		}},
	}
	set := &ipcv1.InterfaceSchemaBundleSet{
		Bundles: []*ipcv1.InterfaceSchemaBundle{bundle},
	}
	descriptorWire, schemaWire, err := ipcregistry.MarshalProviderArtifacts(descriptor, set)
	if err != nil {
		t.Fatalf("MarshalProviderArtifacts: %v", err)
	}
	artifacts, err := ipcregistry.ParseProviderArtifacts(descriptorWire, schemaWire)
	if err != nil {
		t.Fatalf("ParseProviderArtifacts: %v", err)
	}
	return artifacts
}

// 内核 bootstrap 已经定义了 nervus.interface.pkg.manager@1。随包分发的契约撞上
// 同一个 key 时，Builder 会走 sameInterfaceContract 逐字段比对。
//
// 这条断言锁住的是一个【跨仓库】约定：providergen 那边任何一个字段写偏
// （required_permission、风险等级、资源字段），这里就会以
// "conflicts with definition owned by" 失败——而不是等到目标机启动时才发现。
func TestProvidergenArtifactsMatchBootstrapContract(t *testing.T) {
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
		Artifacts: providergenStyleArtifacts(t),
	}})
	if err != nil {
		t.Fatalf("Prepare with providergen-style artifacts: %v", err)
	}

	// 方法必须真的可派发：schema 解出了 Request 类型，说明 bundle 是自包含的
	method, ok := candidate.Snapshot().ProviderMethod(
		"nervus.pkgmanagerd", InterfacePackageManager, 1, 1)
	if !ok || method.Request == nil ||
		string(method.Request.FullName()) != "nervus.interface.pkgmanager.v1.InstallRequest" {
		t.Fatalf("package-manager method = %+v, %v", method, ok)
	}
	iface, ok := candidate.Snapshot().Interface(InterfacePackageManager, 1)
	if !ok || iface.RequiredPermission != "perm.pkg.query" {
		t.Fatalf("interface permission = %q, %v; want perm.pkg.query", iface.RequiredPermission, ok)
	}

	// 装包相关的两个权限仍由内核 bootstrap 拥有——随包分发的契约不该、也不能
	// 重新定义它们（authorizePermissionNamespace 只放行 platform-release 定义
	// perm.*，而重复定义会撞 "conflicts with definition owned by"）
	query, ok := candidate.Snapshot().Permission("perm.pkg.query")
	if !ok || query.GrantMode != ipcv1.GrantMode_GRANT_MODE_NORMAL {
		t.Fatalf("package query permission = %+v, %v", query, ok)
	}
	install, ok := candidate.Snapshot().Permission("perm.pkg.install")
	if !ok || install.GrantMode != ipcv1.GrantMode_GRANT_MODE_USER_CONSENT {
		t.Fatalf("package install permission = %+v, %v", install, ok)
	}
}

// required_permission 写偏一个字就必须炸。这条是上面那条的反面证明：
// 如果 sameInterfaceContract 没有真的在比对，上面的通过就毫无意义。
func TestProvidergenArtifactsWithWrongPermissionConflict(t *testing.T) {
	bundle, err := ipcregistry.BuildSchemaBundle(
		InterfacePackageManager, 1, pkgmanagerv1.PackageManagerMethod(0).Descriptor())
	if err != nil {
		t.Fatalf("BuildSchemaBundle: %v", err)
	}
	descriptor := &ipcv1.ProviderDescriptor{
		PackageId: "nervus.pkgmanagerd",
		Interfaces: []*ipcv1.ProvidedInterface{{
			InterfaceId: InterfacePackageManager,
			InterfaceVersions: []*ipcv1.ProvidedInterfaceVersion{{
				Major: 1, SchemaHash: append([]byte(nil), bundle.GetSchemaHash()...),
			}},
			// 内核 bootstrap 用的是 perm.pkg.query
			RequiredPermission: "perm.pkg.install",
		}},
	}
	descriptorWire, schemaWire, err := ipcregistry.MarshalProviderArtifacts(
		descriptor, &ipcv1.InterfaceSchemaBundleSet{
			Bundles: []*ipcv1.InterfaceSchemaBundle{bundle},
		})
	if err != nil {
		t.Fatalf("MarshalProviderArtifacts: %v", err)
	}
	artifacts, err := ipcregistry.ParseProviderArtifacts(descriptorWire, schemaWire)
	if err != nil {
		t.Fatalf("ParseProviderArtifacts: %v", err)
	}

	registry := mustDefaultRegistry(t)
	_, err = registry.Prepare([]Source{{
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
			ComponentID: "main", InterfaceID: InterfacePackageManager,
		}},
		Artifacts: artifacts,
	}})
	if err == nil {
		t.Fatal("契约不一致的 provider 被接受了，sameInterfaceContract 没有生效")
	}
}
