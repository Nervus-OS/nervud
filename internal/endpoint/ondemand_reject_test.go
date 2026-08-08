package endpoint

import (
	"context"
	"errors"
	"strings"
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

// 复刻一次真实现场: pkgmanagerd 被 on-demand 拉起、握手成功、报到时因为
// schema hash 不符被拒、随即退出, 而发起 Resolve 的 Launcher 拿到的却是
// RESOURCE_NOT_FOUND —— 一个指向 selector 的 reason, 与真因毫无关系.
//
// 断言两件事:
//   - reason 不再指向资源. selector 已经在 authorizeOnDemandStart 里解析成功过,
//     否则根本走不到启动这一步, 所以资源类 reason 在这条路径上恒为误导
//   - Resolve 自己的审计行带上被拒的真因, 不需要人去另一条审计里对时间戳
func TestResolveReportsRejectedRegistrationInsteadOfResourceNotFound(t *testing.T) {
	definitions := defaultCatalog(t)
	source, _ := packageManagerSource(t)
	publishSources(t, definitions, source)

	permissions := newFakePerm()
	permissions.grant(packageManagerPackage, permServiceRegister)
	permissions.grant(testCallerPackage, "perm.pkg.query")

	pkgs := newFakePkgs(serviceEntry(
		packageManagerPackage,
		packageManagerComponent,
		catalog.InterfacePackageManager,
		pkgregistry.VisibilityPublic,
	))

	aud := &fakeAudit{}
	var module *Module

	// 启动即报到, 但带一个过期的 hash —— 正是 pkgmanagerd 漏填 SchemaHash 时
	// 内核看到的东西
	starter := &fakeStarter{fn: func(_ context.Context, pkg, comp string) error {
		go module.RegisterEndpoint(
			"provider",
			identity.Caller{PackageID: pkg, ComponentID: comp},
			&ipcv1.RegisterEndpoint{
				RequestId:      1,
				InterfaceId:    catalog.InterfacePackageManager,
				InterfaceMajor: packageManagerMajor,
				// 留空 = 漏填. v2 已经移除了放行空 hash 的兼容桥
			},
		)
		return nil
	}}

	module = New(definitions, pkgs, permissions, starter, aud, nil)

	result := module.ResolveEndpoint(
		"caller",
		identity.Caller{PackageID: testCallerPackage},
		&ipcv1.ResolveEndpoint{
			RequestId:         1,
			InterfaceId:       catalog.InterfacePackageManager,
			MinInterfaceMajor: packageManagerMajor,
			MaxInterfaceMajor: packageManagerMajor,
		},
	)

	if code := result.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE {
		t.Errorf("code = %v, want UNAVAILABLE（提供方存在且已获准启动，只是没就绪）", code)
	}
	assertResolveReason(
		t, result, ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_INTERFACE_NOT_FOUND)

	resolveErr := lastAuditErr(t, aud, "endpoint.ResolveEndpoint")
	if !errors.Is(resolveErr, errOnDemandRejected) {
		t.Fatalf("Resolve 审计 err = %v, want 包住 errOnDemandRejected", resolveErr)
	}
	if !strings.Contains(resolveErr.Error(), "schema hash") {
		t.Errorf("Resolve 审计没带上被拒真因: %v", resolveErr)
	}
	if !strings.Contains(resolveErr.Error(), packageManagerPackage) {
		t.Errorf("Resolve 审计没指出是哪个组件被拒: %v", resolveErr)
	}
}

// 组件压根没起来时不能谎称"被拒": 那会把人指向 RegisterEndpoint 审计,
// 而那里什么都没有.
func TestResolveKeepsTimeoutWhenNothingRegistered(t *testing.T) {
	definitions := defaultCatalog(t)
	source, _ := packageManagerSource(t)
	publishSources(t, definitions, source)

	permissions := newFakePerm()
	permissions.grant(testCallerPackage, "perm.pkg.query")

	aud := &fakeAudit{}
	module := New(
		definitions,
		newFakePkgs(serviceEntry(
			packageManagerPackage,
			packageManagerComponent,
			catalog.InterfacePackageManager,
			pkgregistry.VisibilityPublic,
		)),
		permissions,
		&fakeStarter{}, // 启动成功但永远不报到
		aud,
		nil,
	)

	result := module.ResolveEndpoint(
		"caller",
		identity.Caller{PackageID: testCallerPackage},
		&ipcv1.ResolveEndpoint{
			RequestId:         1,
			InterfaceId:       catalog.InterfacePackageManager,
			MinInterfaceMajor: packageManagerMajor,
			MaxInterfaceMajor: packageManagerMajor,
		},
	)

	assertResolveReason(
		t, result, ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_INTERFACE_NOT_FOUND)
	if err := lastAuditErr(t, aud, "endpoint.ResolveEndpoint"); !errors.Is(err, errOnDemandTimeout) {
		t.Fatalf("Resolve 审计 err = %v, want errOnDemandTimeout", err)
	}
}

func lastAuditErr(t *testing.T, aud *fakeAudit, action string) error {
	t.Helper()
	aud.mu.Lock()
	defer aud.mu.Unlock()
	for i := len(aud.events) - 1; i >= 0; i-- {
		if aud.events[i].Action == action {
			return aud.events[i].Err
		}
	}
	t.Fatalf("审计里没有 %s", action)
	return nil
}
