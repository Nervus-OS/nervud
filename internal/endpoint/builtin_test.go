package endpoint

import (
	"context"
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

const builtinIface = "nervus.interface.test.builtin"

func okHandler(payload []byte) BuiltinHandler {
	return func(context.Context, identity.Caller, uint32, []byte) ([]byte, ipcv1.StatusCode) {
		return payload, ipcv1.StatusCode_STATUS_CODE_OK
	}
}

func TestRegisterBuiltin_RejectsDuplicate(t *testing.T) {
	// 静默覆盖会让「哪个实现在生效」取决于装配顺序——最难排查的那类问题。
	m := newTestModule(newFakePkgs(), newFakePerm(), &fakeStarter{}, &fakeAudit{})

	if err := m.RegisterBuiltin(builtinIface, 1, 0, okHandler(nil)); err != nil {
		t.Fatalf("首次注册应成功: %v", err)
	}
	if err := m.RegisterBuiltin(builtinIface, 1, 0, okHandler(nil)); err == nil {
		t.Fatal("重复注册必须报错，不能静默覆盖")
	}
}

func TestRegisterBuiltin_RejectsEmptyInput(t *testing.T) {
	m := newTestModule(newFakePkgs(), newFakePerm(), &fakeStarter{}, &fakeAudit{})

	if err := m.RegisterBuiltin("", 1, 0, okHandler(nil)); err == nil {
		t.Error("空 interfaceID 必须被拒")
	}
	if err := m.RegisterBuiltin(builtinIface, 1, 0, nil); err == nil {
		t.Error("nil handler 必须被拒：注册一个调不动的 endpoint 比不注册更糟")
	}
}

func TestBuiltin_ResolveAndRoute(t *testing.T) {
	// 内建 endpoint 必须能被【完全标准】的 Resolve 找到：调用方不需要知道
	// 对面是内核还是 Provider。
	pkgs := newFakePkgs(callerEntry("com.caller"))
	perm := newFakePerm()
	m := newTestModule(pkgs, perm, &fakeStarter{}, &fakeAudit{})

	if err := m.RegisterBuiltin(builtinIface, 1, 0, okHandler([]byte("hi"))); err != nil {
		t.Fatalf("RegisterBuiltin: %v", err)
	}

	res := m.ResolveEndpoint("conn-1", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: builtinIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
	})
	if f := res.GetFailure(); f != nil {
		t.Fatalf("Resolve 内建 endpoint 失败: code=%v", f.GetCode())
	}
	epID := res.GetSuccess().GetEndpointId()

	route, rerr := m.Route("conn-1", epID)
	if rerr.Code != ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		t.Fatalf("Route 失败: %v", rerr.Code)
	}
	if route.Builtin == nil {
		t.Fatal("RouteInfo.Builtin 必须非 nil —— 否则 ipc 会当成「没有转发目标」回 UNAVAILABLE")
	}
	// 内建没有连接：TargetConn 必须为 nil，两者互斥
	if route.TargetConn != nil {
		t.Errorf("内建 endpoint 不该有 TargetConn，got %v", route.TargetConn)
	}

	// handler 真的可调用
	out, code := route.Builtin(context.Background(), identity.Caller{}, 1, nil)
	if code != ipcv1.StatusCode_STATUS_CODE_OK || string(out) != "hi" {
		t.Errorf("handler 返回 (%q, %v)", out, code)
	}
}

func TestBuiltin_IsCrossPackageVisible(t *testing.T) {
	// 内建能力属于平台，不属于任何一个 Package，因此不存在「只对同包可见」。
	// 能不能调由权限决定，不由可见性决定。
	pkgs := newFakePkgs(callerEntry("com.a"), callerEntry("com.b"))
	m := newTestModule(pkgs, newFakePerm(), &fakeStarter{}, &fakeAudit{})
	if err := m.RegisterBuiltin(builtinIface, 1, 0, okHandler(nil)); err != nil {
		t.Fatalf("RegisterBuiltin: %v", err)
	}

	for _, pkg := range []string{"com.a", "com.b"} {
		res := m.ResolveEndpoint("conn-"+pkg, identity.Caller{PackageID: pkg}, &ipcv1.ResolveEndpoint{
			RequestId: 1, InterfaceId: builtinIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
		})
		if f := res.GetFailure(); f != nil {
			t.Errorf("%s 无法 Resolve 内建 endpoint: %v", pkg, f.GetCode())
		}
	}
}

func TestBuiltin_StillSubjectToInterfacePermission(t *testing.T) {
	// 【内建不等于免检】。Resolve 阶段照样查 InterfaceCatalog 的接口级门槛——
	// 恰恰因为它由内核实现、能直接操作内核状态，门槛才更该生效。
	pkgs := newFakePkgs(callerEntry("com.caller"))
	perm := newFakePerm() // 不授予任何权限
	m := New(pkgs, perm, &fakeStarter{}, newFakeResourceResolver(), &fakeAudit{}, nil)
	m.catalog = NewInterfaceCatalog([]InterfaceCatalogEntry{
		{InterfaceID: builtinIface, RequiredPermission: "perm.test.gated"},
	})
	if err := m.RegisterBuiltin(builtinIface, 1, 0, okHandler(nil)); err != nil {
		t.Fatalf("RegisterBuiltin: %v", err)
	}

	res := m.ResolveEndpoint("conn-1", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: builtinIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
	})
	f := res.GetFailure()
	if f == nil {
		t.Fatal("缺权限时 Resolve 内建 endpoint 必须被拒")
	}
	if f.GetCode() != ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED {
		t.Errorf("code = %v, want PERMISSION_DENIED", f.GetCode())
	}

	// 授权之后就能拿到
	perm.grant("com.caller", "perm.test.gated")
	res = m.ResolveEndpoint("conn-2", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 2, InterfaceId: builtinIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
	})
	if f := res.GetFailure(); f != nil {
		t.Fatalf("授权后仍被拒: %v", f.GetCode())
	}
}

func TestBuiltin_SurvivesConnectionChurn(t *testing.T) {
	// 内建恒 live：没有会断的连接。外部 registration 靠 conn 断开置 false，
	// 内建的执行发生在进程内，只要 nervud 活着它就可用。
	pkgs := newFakePkgs(callerEntry("com.caller"))
	m := newTestModule(pkgs, newFakePerm(), &fakeStarter{}, &fakeAudit{})
	if err := m.RegisterBuiltin(builtinIface, 1, 0, okHandler(nil)); err != nil {
		t.Fatalf("RegisterBuiltin: %v", err)
	}

	// 一条连接来了又走
	res := m.ResolveEndpoint("conn-gone", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: builtinIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
	})
	if res.GetFailure() != nil {
		t.Fatalf("首次 Resolve 失败")
	}
	m.ConnClosed("conn-gone")

	// 新连接仍然 Resolve 得到
	res = m.ResolveEndpoint("conn-new", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: builtinIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
	})
	if f := res.GetFailure(); f != nil {
		t.Fatalf("连接churn 之后内建 endpoint 不可用了: %v", f.GetCode())
	}
}

var _ = pkgregistry.VisibilityPublic
