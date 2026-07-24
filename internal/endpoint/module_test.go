package endpoint

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/pkgregistry"
)

func unmarshalDetail(b []byte, out proto.Message) error {
	return proto.Unmarshal(b, out)
}

var errComponentDisabledStub = errors.New("component disabled (stub)")

type fakePkgs struct {
	mu      sync.Mutex
	entries map[string]pkgregistry.Entry
}

func newFakePkgs(entries ...pkgregistry.Entry) *fakePkgs {
	f := &fakePkgs{entries: map[string]pkgregistry.Entry{}}
	for _, e := range entries {
		f.entries[e.Manifest.PackageID] = e
	}
	return f
}

func (f *fakePkgs) Lookup(id string) (pkgregistry.Entry, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.entries[id]
	return e, ok
}

func (f *fakePkgs) List() []pkgregistry.Entry {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]pkgregistry.Entry, 0, len(f.entries))
	for _, e := range f.entries {
		out = append(out, e)
	}
	return out
}

type fakePerm struct {
	mu      sync.Mutex
	granted map[string]map[string]bool
}

func newFakePerm() *fakePerm { return &fakePerm{granted: map[string]map[string]bool{}} }

func (f *fakePerm) grant(pkg, perm string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.granted[pkg] == nil {
		f.granted[pkg] = map[string]bool{}
	}
	f.granted[pkg][perm] = true
}

func (f *fakePerm) revoke(pkg, perm string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.granted[pkg], perm)
}

func (f *fakePerm) Allowed(pkg, perm string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.granted[pkg][perm]
}

type fakeStarter struct {
	fn func(ctx context.Context, pkg, comp string) error
}

func (f *fakeStarter) EnsureStarted(ctx context.Context, pkg, comp string) error {
	if f.fn == nil {
		return nil
	}
	return f.fn(ctx, pkg, comp)
}

type fakeResourceResolver struct{}

func newFakeResourceResolver() *fakeResourceResolver { return &fakeResourceResolver{} }

func (f *fakeResourceResolver) Resolve(resourceType, role string) (string, bool) {
	if resourceType == resourceTypeMotionBase && role == resourceRoleMain {
		return "base.main", true
	}
	return "", false
}

func (f *fakeResourceResolver) Valid(handle string) bool {
	return handle == "base.main"
}

type fakeAudit struct {
	mu  sync.Mutex
	evs []audit.Event
}

func (f *fakeAudit) Record(_ context.Context, ev audit.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.evs = append(f.evs, ev)
}

const (
	testIface = "nervus.interface.motion.base"
	testPerm  = "perm.motion.control"
)

func svcEntry(pkg, comp string, vis pkgregistry.Visibility, disabled bool) pkgregistry.Entry {
	e := pkgregistry.Entry{Manifest: pkgregistry.Manifest{
		PackageID: pkg,
		Components: []pkgregistry.Component{
			{ID: comp, Type: pkgregistry.ComponentService, Exports: []pkgregistry.Export{
				{Interface: testIface, Visibility: vis},
			}},
		},
	}}
	if disabled {
		e.DisabledComponents = []string{comp}
	}
	return e
}

func callerEntry(pkg string) pkgregistry.Entry {
	return pkgregistry.Entry{Manifest: pkgregistry.Manifest{PackageID: pkg}}
}

func newTestModule(pkgs *fakePkgs, perm *fakePerm, starter *fakeStarter, aud *fakeAudit) *Module {
	return New(pkgs, perm, starter, newFakeResourceResolver(), aud, nil)
}

// ---- RegisterEndpoint --------------------------------------------------------

func TestRegisterEndpoint_Success(t *testing.T) {
	pkgs := newFakePkgs(svcEntry("com.svc", "comp", pkgregistry.VisibilityPublic, false))
	perm := newFakePerm()
	perm.grant("com.svc", permServiceRegister)
	m := newTestModule(pkgs, perm, &fakeStarter{}, &fakeAudit{})

	caller := identity.Caller{PackageID: "com.svc", ComponentID: "comp"}
	res := m.RegisterEndpoint("conn-a", caller, &ipcv1.RegisterEndpoint{
		RequestId: 1, InterfaceId: testIface, InterfaceMajor: 1, ResourceHandle: "base.main",
	})
	succ := res.GetSuccess()
	if succ == nil {
		t.Fatalf("want success, got %+v", res.GetFailure())
	}
	if succ.GetEndpointId() != 1 {
		t.Fatalf("endpoint_id = %d, want 1", succ.GetEndpointId())
	}

	res2 := m.RegisterEndpoint("conn-a", caller, &ipcv1.RegisterEndpoint{
		RequestId: 2, InterfaceId: testIface, InterfaceMajor: 1,
	})
	if got := res2.GetSuccess().GetEndpointId(); got != 2 {
		t.Fatalf("second endpoint_id = %d, want 2", got)
	}
}

func TestRegisterEndpoint_MissingPermissionDenied(t *testing.T) {
	pkgs := newFakePkgs(svcEntry("com.svc", "comp", pkgregistry.VisibilityPublic, false))
	perm := newFakePerm()
	m := newTestModule(pkgs, perm, &fakeStarter{}, &fakeAudit{})

	caller := identity.Caller{PackageID: "com.svc", ComponentID: "comp"}
	res := m.RegisterEndpoint("conn-a", caller, &ipcv1.RegisterEndpoint{RequestId: 1, InterfaceId: testIface})
	if code := res.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED {
		t.Fatalf("code = %v, want PERMISSION_DENIED", code)
	}
}

func TestRegisterEndpoint_InterfaceNotExportedDenied(t *testing.T) {
	pkgs := newFakePkgs(svcEntry("com.svc", "comp", pkgregistry.VisibilityPublic, false))
	perm := newFakePerm()
	perm.grant("com.svc", permServiceRegister)
	m := newTestModule(pkgs, perm, &fakeStarter{}, &fakeAudit{})

	caller := identity.Caller{PackageID: "com.svc", ComponentID: "comp"}
	res := m.RegisterEndpoint("conn-a", caller, &ipcv1.RegisterEndpoint{RequestId: 1, InterfaceId: "iface.not.declared"})
	if code := res.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED {
		t.Fatalf("code = %v, want PERMISSION_DENIED", code)
	}
}

func TestRegisterEndpoint_ComponentDisabledDenied(t *testing.T) {
	pkgs := newFakePkgs(svcEntry("com.svc", "comp", pkgregistry.VisibilityPublic, true))
	perm := newFakePerm()
	perm.grant("com.svc", permServiceRegister)
	m := newTestModule(pkgs, perm, &fakeStarter{}, &fakeAudit{})

	caller := identity.Caller{PackageID: "com.svc", ComponentID: "comp"}
	res := m.RegisterEndpoint("conn-a", caller, &ipcv1.RegisterEndpoint{RequestId: 1, InterfaceId: testIface})
	if code := res.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED {
		t.Fatalf("code = %v, want PERMISSION_DENIED", code)
	}
}

func TestRegisterEndpoint_BadResourceHandleInvalidArgument(t *testing.T) {
	pkgs := newFakePkgs(svcEntry("com.svc", "comp", pkgregistry.VisibilityPublic, false))
	perm := newFakePerm()
	perm.grant("com.svc", permServiceRegister)
	m := newTestModule(pkgs, perm, &fakeStarter{}, &fakeAudit{})

	caller := identity.Caller{PackageID: "com.svc", ComponentID: "comp"}
	res := m.RegisterEndpoint("conn-a", caller, &ipcv1.RegisterEndpoint{
		RequestId: 1, InterfaceId: testIface, ResourceHandle: "not-a-real-handle",
	})
	if code := res.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT {
		t.Fatalf("code = %v, want INVALID_ARGUMENT", code)
	}
}

func TestRegisterEndpoint_PrivateVisibilityUsesPrivatePermission(t *testing.T) {
	pkgs := newFakePkgs(svcEntry("com.svc", "comp", pkgregistry.VisibilityPackage, false))
	perm := newFakePerm()
	perm.grant("com.svc", permServiceRegisterPrivate)
	m := newTestModule(pkgs, perm, &fakeStarter{}, &fakeAudit{})

	caller := identity.Caller{PackageID: "com.svc", ComponentID: "comp"}
	res := m.RegisterEndpoint("conn-a", caller, &ipcv1.RegisterEndpoint{RequestId: 1, InterfaceId: testIface})
	if res.GetSuccess() == nil {
		t.Fatalf("want success, got %+v", res.GetFailure())
	}
}

// ---- ResolveEndpoint ----------------------------------------------------------

func registerHelper(t *testing.T, m *Module, conn ConnHandle, pkg, comp string, major uint32) uint64 {
	t.Helper()
	res := m.RegisterEndpoint(conn, identity.Caller{PackageID: pkg, ComponentID: comp}, &ipcv1.RegisterEndpoint{
		RequestId: 1, InterfaceId: testIface, InterfaceMajor: major,
	})
	succ := res.GetSuccess()
	if succ == nil {
		t.Fatalf("register setup failed: %+v", res.GetFailure())
	}
	return succ.GetEndpointId()
}

func TestResolveEndpoint_Success(t *testing.T) {
	pkgs := newFakePkgs(
		svcEntry("com.svc", "comp", pkgregistry.VisibilityPublic, false),
		callerEntry("com.caller"),
	)
	perm := newFakePerm()
	perm.grant("com.svc", permServiceRegister)
	perm.grant("com.caller", testPerm)
	m := newTestModule(pkgs, perm, &fakeStarter{}, &fakeAudit{})

	registerHelper(t, m, "conn-svc", "com.svc", "comp", 1)

	caller := identity.Caller{PackageID: "com.caller"}
	res := m.ResolveEndpoint("conn-caller", caller, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: testIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
	})
	succ := res.GetSuccess()
	if succ == nil {
		t.Fatalf("want success, got %+v", res.GetFailure())
	}
	if succ.GetEndpointId() != 1 {
		t.Fatalf("endpoint_id = %d, want 1", succ.GetEndpointId())
	}
	if succ.GetResourceHandle() != "base.main" {
		t.Fatalf("resource_handle = %q, want %q", succ.GetResourceHandle(), "base.main")
	}

	route, rerr := m.Route("conn-caller", succ.GetEndpointId())
	if rerr.Code != ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		t.Fatalf("route err code = %v, want 0", rerr.Code)
	}
	if route.TargetConn != ConnHandle("conn-svc") || route.ServiceEndpointID != 1 {
		t.Fatalf("route = %+v, want TargetConn=conn-svc ServiceEndpointID=1", route)
	}
}

func TestResolveEndpoint_PermissionDenied(t *testing.T) {
	pkgs := newFakePkgs(
		svcEntry("com.svc", "comp", pkgregistry.VisibilityPublic, false),
		callerEntry("com.caller"),
	)
	perm := newFakePerm()
	perm.grant("com.svc", permServiceRegister)
	m := newTestModule(pkgs, perm, &fakeStarter{}, &fakeAudit{})

	registerHelper(t, m, "conn-svc", "com.svc", "comp", 1)

	res := m.ResolveEndpoint("conn-caller", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: testIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
	})
	if code := res.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED {
		t.Fatalf("code = %v, want PERMISSION_DENIED", code)
	}
}

func TestResolveEndpoint_VersionMismatch(t *testing.T) {
	pkgs := newFakePkgs(
		svcEntry("com.svc", "comp", pkgregistry.VisibilityPublic, false),
		callerEntry("com.caller"),
	)
	perm := newFakePerm()
	perm.grant("com.svc", permServiceRegister)
	perm.grant("com.caller", testPerm)
	m := newTestModule(pkgs, perm, &fakeStarter{}, &fakeAudit{})

	registerHelper(t, m, "conn-svc", "com.svc", "comp", 2)

	res := m.ResolveEndpoint("conn-caller", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: testIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
	})
	if code := res.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION {
		t.Fatalf("code = %v, want FAILED_PRECONDITION", code)
	}
	detail := &ipcv1.ResolveEndpointErrorDetail{}
	if err := unmarshalDetail(res.GetFailure().GetErrorDetail(), detail); err != nil {
		t.Fatalf("unmarshal detail: %v", err)
	}
	if detail.GetReason() != ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_VERSION_MISMATCH {
		t.Fatalf("reason = %v, want VERSION_MISMATCH", detail.GetReason())
	}
}

func TestResolveEndpoint_InterfaceNotFound(t *testing.T) {
	pkgs := newFakePkgs(callerEntry("com.caller"))
	perm := newFakePerm()
	perm.grant("com.caller", testPerm)
	m := newTestModule(pkgs, perm, &fakeStarter{}, &fakeAudit{})

	res := m.ResolveEndpoint("conn-caller", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: testIface,
	})
	if code := res.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION {
		t.Fatalf("code = %v, want FAILED_PRECONDITION", code)
	}
}

func TestResolveEndpoint_EmptySelectorMatchesExplicitDefault(t *testing.T) {
	pkgs := newFakePkgs(
		svcEntry("com.svc", "comp", pkgregistry.VisibilityPublic, false),
		callerEntry("com.caller"),
	)
	perm := newFakePerm()
	perm.grant("com.svc", permServiceRegister)
	perm.grant("com.caller", testPerm)
	m := newTestModule(pkgs, perm, &fakeStarter{}, &fakeAudit{})

	registerHelper(t, m, "conn-svc", "com.svc", "comp", 1)

	implicit := m.ResolveEndpoint("conn-implicit", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: testIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
	})
	explicit := m.ResolveEndpoint("conn-explicit", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: testIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
		Selector: &ipcv1.ResourceSelector{Type: resourceTypeMotionBase, Role: resourceRoleMain},
	})

	implicitSucc, explicitSucc := implicit.GetSuccess(), explicit.GetSuccess()
	if implicitSucc == nil || explicitSucc == nil {
		t.Fatalf("want both success, got implicit=%+v explicit=%+v", implicit.GetFailure(), explicit.GetFailure())
	}
	if implicitSucc.GetResourceHandle() != explicitSucc.GetResourceHandle() {
		t.Fatalf("resource_handle mismatch: implicit=%q explicit=%q",
			implicitSucc.GetResourceHandle(), explicitSucc.GetResourceHandle())
	}
}

func TestResolveEndpoint_ExplicitComponentDenied(t *testing.T) {
	m := newTestModule(newFakePkgs(), newFakePerm(), &fakeStarter{}, &fakeAudit{})
	res := m.ResolveEndpoint("conn-caller", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: testIface, ExplicitComponent: "some.other.component",
	})
	if code := res.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED {
		t.Fatalf("code = %v, want PERMISSION_DENIED", code)
	}
}

func TestResolveEndpoint_SelectorMismatchResourceNotFound(t *testing.T) {
	m := newTestModule(newFakePkgs(), newFakePerm(), &fakeStarter{}, &fakeAudit{})
	res := m.ResolveEndpoint("conn-caller", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: testIface,
		Selector: &ipcv1.ResourceSelector{Type: "nervus.resource.camera", Role: "front"},
	})
	if code := res.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION {
		t.Fatalf("code = %v, want FAILED_PRECONDITION", code)
	}
}

func TestResolveEndpoint_AmbiguousWhenTwoCandidates(t *testing.T) {
	pkgs := newFakePkgs(
		svcEntry("com.svc1", "comp", pkgregistry.VisibilityPublic, false),
		svcEntry("com.svc2", "comp", pkgregistry.VisibilityPublic, false),
		callerEntry("com.caller"),
	)
	perm := newFakePerm()
	perm.grant("com.svc1", permServiceRegister)
	perm.grant("com.svc2", permServiceRegister)
	perm.grant("com.caller", testPerm)
	m := newTestModule(pkgs, perm, &fakeStarter{}, &fakeAudit{})

	registerHelper(t, m, "conn-svc1", "com.svc1", "comp", 1)
	registerHelper(t, m, "conn-svc2", "com.svc2", "comp", 1)

	res := m.ResolveEndpoint("conn-caller", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: testIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
	})
	detail := &ipcv1.ResolveEndpointErrorDetail{}
	_ = unmarshalDetail(res.GetFailure().GetErrorDetail(), detail)
	if detail.GetReason() != ipcv1.ResolveEndpointReason_RESOLVE_ENDPOINT_REASON_RESOURCE_AMBIGUOUS {
		t.Fatalf("reason = %v, want RESOURCE_AMBIGUOUS", detail.GetReason())
	}
}

func TestResolveEndpoint_OnDemandStartWakesWaiter(t *testing.T) {
	pkgs := newFakePkgs(
		svcEntry("com.svc", "comp", pkgregistry.VisibilityPublic, false),
		callerEntry("com.caller"),
	)
	perm := newFakePerm()
	perm.grant("com.svc", permServiceRegister)
	perm.grant("com.caller", testPerm)

	var m *Module
	starter := &fakeStarter{fn: func(ctx context.Context, pkg, comp string) error {
		go func() {
			time.Sleep(10 * time.Millisecond)
			m.RegisterEndpoint("conn-svc", identity.Caller{PackageID: pkg, ComponentID: comp}, &ipcv1.RegisterEndpoint{
				RequestId: 1, InterfaceId: testIface, InterfaceMajor: 1,
			})
		}()
		return nil
	}}
	m = newTestModule(pkgs, perm, starter, &fakeAudit{})

	start := time.Now()
	res := m.ResolveEndpoint("conn-caller", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: testIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
	})
	if time.Since(start) > onDemandStartTimeout {
		t.Fatalf("resolve took too long, wait wasn't woken up by Register broadcast")
	}
	if res.GetSuccess() == nil {
		t.Fatalf("want success after on-demand start, got %+v", res.GetFailure())
	}
}

func TestResolveEndpoint_OnDemandStartFailurePropagates(t *testing.T) {
	pkgs := newFakePkgs(
		svcEntry("com.svc", "comp", pkgregistry.VisibilityPublic, false),
		callerEntry("com.caller"),
	)
	perm := newFakePerm()
	perm.grant("com.caller", testPerm)
	starter := &fakeStarter{fn: func(ctx context.Context, pkg, comp string) error {
		return errComponentDisabledStub
	}}
	m := newTestModule(pkgs, perm, starter, &fakeAudit{})

	res := m.ResolveEndpoint("conn-caller", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: testIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
	})
	if code := res.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION {
		t.Fatalf("code = %v, want FAILED_PRECONDITION", code)
	}
}

func TestRoute_PermissionRevokedFailsNextCall(t *testing.T) {
	pkgs := newFakePkgs(
		svcEntry("com.svc", "comp", pkgregistry.VisibilityPublic, false),
		callerEntry("com.caller"),
	)
	perm := newFakePerm()
	perm.grant("com.svc", permServiceRegister)
	perm.grant("com.caller", testPerm)
	m := newTestModule(pkgs, perm, &fakeStarter{}, &fakeAudit{})

	registerHelper(t, m, "conn-svc", "com.svc", "comp", 1)
	res := m.ResolveEndpoint("conn-caller", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: testIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
	})
	id := res.GetSuccess().GetEndpointId()

	if _, rerr := m.Route("conn-caller", id); rerr.Code != ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		t.Fatalf("initial route should succeed, got code %v", rerr.Code)
	}

	perm.revoke("com.caller", testPerm)
	if _, rerr := m.Route("conn-caller", id); rerr.Code != ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED {
		t.Fatalf("route after revoke code = %v, want PERMISSION_DENIED", rerr.Code)
	}
}

func TestRoute_ServiceConnClosedInvalidatesBinding(t *testing.T) {
	pkgs := newFakePkgs(
		svcEntry("com.svc", "comp", pkgregistry.VisibilityPublic, false),
		callerEntry("com.caller"),
	)
	perm := newFakePerm()
	perm.grant("com.svc", permServiceRegister)
	perm.grant("com.caller", testPerm)
	m := newTestModule(pkgs, perm, &fakeStarter{}, &fakeAudit{})

	registerHelper(t, m, "conn-svc", "com.svc", "comp", 1)
	res := m.ResolveEndpoint("conn-caller", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: testIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
	})
	id := res.GetSuccess().GetEndpointId()

	m.ConnClosed("conn-svc")

	if _, rerr := m.Route("conn-caller", id); rerr.Code != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("route after service conn closed code = %v, want NOT_FOUND", rerr.Code)
	}

	res2 := m.ResolveEndpoint("conn-caller-2", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 2, InterfaceId: testIface,
	})
	if res2.GetSuccess() != nil {
		t.Fatalf("want failure after service registrations were cleared, got success")
	}
}

func TestRoute_CallerConnClosedDropsAllBindings(t *testing.T) {
	pkgs := newFakePkgs(
		svcEntry("com.svc", "comp", pkgregistry.VisibilityPublic, false),
		callerEntry("com.caller"),
	)
	perm := newFakePerm()
	perm.grant("com.svc", permServiceRegister)
	perm.grant("com.caller", testPerm)
	m := newTestModule(pkgs, perm, &fakeStarter{}, &fakeAudit{})

	registerHelper(t, m, "conn-svc", "com.svc", "comp", 1)
	res := m.ResolveEndpoint("conn-caller", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: testIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
	})
	id := res.GetSuccess().GetEndpointId()

	m.ConnClosed("conn-caller")

	if _, rerr := m.Route("conn-caller", id); rerr.Code != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("route after caller conn closed code = %v, want NOT_FOUND", rerr.Code)
	}
}

func TestUnregisterEndpoint_InvalidatesBinding(t *testing.T) {
	pkgs := newFakePkgs(
		svcEntry("com.svc", "comp", pkgregistry.VisibilityPublic, false),
		callerEntry("com.caller"),
	)
	perm := newFakePerm()
	perm.grant("com.svc", permServiceRegister)
	perm.grant("com.caller", testPerm)
	m := newTestModule(pkgs, perm, &fakeStarter{}, &fakeAudit{})

	svcID := registerHelper(t, m, "conn-svc", "com.svc", "comp", 1)
	res := m.ResolveEndpoint("conn-caller", identity.Caller{PackageID: "com.caller"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: testIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
	})
	id := res.GetSuccess().GetEndpointId()

	unregRes := m.UnregisterEndpoint("conn-svc", &ipcv1.UnregisterEndpoint{RequestId: 2, EndpointId: svcID})
	if unregRes.GetSuccess() == nil {
		t.Fatalf("want success, got %+v", unregRes.GetFailure())
	}

	if _, rerr := m.Route("conn-caller", id); rerr.Code != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("route after unregister code = %v, want NOT_FOUND", rerr.Code)
	}
}

func TestUnregisterEndpoint_UnknownIDNotFound(t *testing.T) {
	m := newTestModule(newFakePkgs(), newFakePerm(), &fakeStarter{}, &fakeAudit{})
	res := m.UnregisterEndpoint("conn-svc", &ipcv1.UnregisterEndpoint{RequestId: 1, EndpointId: 99})
	if code := res.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("code = %v, want NOT_FOUND", code)
	}
}

func TestNamespaceIsolation_TwoConnsIndependentNumbering(t *testing.T) {
	pkgs := newFakePkgs(
		svcEntry("com.svc", "comp", pkgregistry.VisibilityPublic, false),
		callerEntry("com.caller1"),
		callerEntry("com.caller2"),
	)
	perm := newFakePerm()
	perm.grant("com.svc", permServiceRegister)
	perm.grant("com.caller1", testPerm)
	perm.grant("com.caller2", testPerm)
	m := newTestModule(pkgs, perm, &fakeStarter{}, &fakeAudit{})

	registerHelper(t, m, "conn-svc", "com.svc", "comp", 1)

	res1 := m.ResolveEndpoint("conn-1", identity.Caller{PackageID: "com.caller1"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: testIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
	})
	res2 := m.ResolveEndpoint("conn-2", identity.Caller{PackageID: "com.caller2"}, &ipcv1.ResolveEndpoint{
		RequestId: 1, InterfaceId: testIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
	})
	id1 := res1.GetSuccess().GetEndpointId()
	id2 := res2.GetSuccess().GetEndpointId()
	if id1 != 1 || id2 != 1 {
		t.Fatalf("each connection should number endpoints independently from 1, got id1=%d id2=%d", id1, id2)
	}

	// conn-1 再 Resolve 一次拿到 id=2；conn-2 没有第二次，故它没有编号 2。
	//
	// 这一步是证明「(conn, endpoint_id) 才是查找键」所必需的：上面两条连接的
	// 首个 id 都是 1，用 id=1 去跨连接 Route 一定命中对方自己的 binding，
	// 证不出任何隔离性。必须构造一个「此连接不存在但彼连接存在」的编号。
	res1b := m.ResolveEndpoint("conn-1", identity.Caller{PackageID: "com.caller1"}, &ipcv1.ResolveEndpoint{
		RequestId: 2, InterfaceId: testIface, MinInterfaceMajor: 1, MaxInterfaceMajor: 1,
	})
	id1b := res1b.GetSuccess().GetEndpointId()
	if id1b != 2 {
		t.Fatalf("second resolve on conn-1 should get id 2, got %d", id1b)
	}

	// 隔离性：conn-1 的 2 在 conn-2 上不存在
	if _, rerr := m.Route("conn-2", id1b); rerr.Code != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("cross-conn route code = %v, want NOT_FOUND", rerr.Code)
	}
	// 同一个数字 1 在两条连接上各自可路由，且互不干扰
	if _, rerr := m.Route("conn-1", id1); rerr.Code != ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		t.Fatalf("conn-1 own route code = %v, want 0", rerr.Code)
	}
	if _, rerr := m.Route("conn-2", id2); rerr.Code != ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		t.Fatalf("conn-2 own route code = %v, want 0", rerr.Code)
	}
	if _, rerr := m.Route("conn-1", id1b); rerr.Code != ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		t.Fatalf("conn-1 second route code = %v, want 0", rerr.Code)
	}
}

func TestNilModule_FailSafe(t *testing.T) {
	var m *Module

	if res := m.RegisterEndpoint("c", identity.Caller{}, &ipcv1.RegisterEndpoint{RequestId: 1}); res.GetSuccess() != nil {
		t.Fatal("RegisterEndpoint on a nil Module should not succeed")
	}
	if res := m.ResolveEndpoint("c", identity.Caller{}, &ipcv1.ResolveEndpoint{RequestId: 1}); res.GetSuccess() != nil {
		t.Fatal("ResolveEndpoint on a nil Module should not succeed")
	}
	if res := m.UnregisterEndpoint("c", &ipcv1.UnregisterEndpoint{RequestId: 1}); res.GetSuccess() != nil {
		t.Fatal("UnregisterEndpoint on a nil Module should not succeed")
	}
	if _, rerr := m.Route("c", 1); rerr.Code == ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		t.Fatal("Route on a nil Module should not succeed")
	}
	m.ConnClosed("c")
	_ = m.Stop(context.Background())
}

func TestModule_NameAndLifecycle(t *testing.T) {
	m := newTestModule(newFakePkgs(), newFakePerm(), &fakeStarter{}, &fakeAudit{})
	if m.Name() != "endpoint" {
		t.Fatalf("Name() = %q, want endpoint", m.Name())
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}
