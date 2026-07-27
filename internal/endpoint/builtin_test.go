package endpoint

import (
	"context"
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/identity"
)

func okHandler(payload []byte) BuiltinHandler {
	return func(call BuiltinCall) BuiltinResult {
		return BuiltinResult{
			Payload: append([]byte(nil), payload...),
			Code:    ipcv1.StatusCode_STATUS_CODE_OK,
		}
	}
}

func TestRegisterBuiltinRequiresExactKernelCatalogMembership(t *testing.T) {
	definitions := defaultCatalog(t)
	module := testModule(
		t, definitions, newFakePkgs(), newFakePerm(), &fakeStarter{})

	if err := module.RegisterBuiltin(
		catalog.InterfaceTransferControl, 1, 0, okHandler(nil)); err != nil {
		t.Fatalf("RegisterBuiltin transfer: %v", err)
	}
	if err := module.RegisterBuiltin(
		catalog.InterfaceTransferControl, 1, 0, okHandler(nil)); err == nil {
		t.Fatal("duplicate builtin registration succeeded")
	}
	if err := module.RegisterBuiltin(
		"nervus.interface.not.in.catalog", 1, 0, okHandler(nil)); err == nil {
		t.Fatal("unlisted builtin registration succeeded")
	}
	if err := module.RegisterBuiltin(
		catalog.InterfaceSafetyControl, 2, 0, okHandler(nil)); err == nil {
		t.Fatal("wrong builtin major registration succeeded")
	}
}

func TestBuiltinResolveRouteAndStructuredCall(t *testing.T) {
	definitions := defaultCatalog(t)
	module := testModule(
		t, definitions, newFakePkgs(), newFakePerm(), &fakeStarter{})
	var captured BuiltinCall
	handler := func(call BuiltinCall) BuiltinResult {
		captured = call
		return BuiltinResult{
			Payload: []byte("ok"),
			Code:    ipcv1.StatusCode_STATUS_CODE_OK,
		}
	}
	if err := module.RegisterBuiltin(
		catalog.InterfaceTransferControl, 1, 0, handler); err != nil {
		t.Fatalf("RegisterBuiltin: %v", err)
	}

	caller := identity.Caller{PackageID: testCallerPackage, ComponentID: "app"}
	result := module.ResolveEndpoint(
		"caller-conn",
		caller,
		&ipcv1.ResolveEndpoint{
			RequestId:         1,
			InterfaceId:       catalog.InterfaceTransferControl,
			MinInterfaceMajor: 1,
			MaxInterfaceMajor: 1,
		},
	)
	if result.GetSuccess() == nil {
		t.Fatalf("Resolve builtin: %+v", result.GetFailure())
	}
	route, routeErr := module.Route(
		"caller-conn", result.GetSuccess().GetEndpointId(), 1)
	if routeErr.Code != ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		t.Fatalf("Route builtin code = %v", routeErr.Code)
	}
	if route.Builtin == nil || route.TargetConn != nil ||
		route.ProviderPackageID != catalog.KernelPackageID ||
		route.Method.MethodID != 1 {
		t.Fatalf("builtin RouteInfo = %+v", route)
	}

	ctx := context.Background()
	callResult := route.Builtin(BuiltinCall{
		Context:  ctx,
		Conn:     "caller-conn",
		Caller:   caller,
		MethodID: 1,
		Payload:  []byte("request"),
	})
	if callResult.Code != ipcv1.StatusCode_STATUS_CODE_OK ||
		string(callResult.Payload) != "ok" ||
		captured.Context != ctx ||
		captured.Conn != ConnHandle("caller-conn") ||
		captured.Caller != caller ||
		captured.MethodID != 1 ||
		string(captured.Payload) != "request" {
		t.Fatalf("structured builtin call = %+v, result = %+v", captured, callResult)
	}
}

func TestBuiltinMethodPermissionIsCheckedAtRoute(t *testing.T) {
	definitions := defaultCatalog(t)
	permissions := newFakePerm()
	permissions.grant(testCallerPackage, "perm.safety.observe")
	module := testModule(
		t, definitions, newFakePkgs(), permissions, &fakeStarter{})
	if err := module.RegisterBuiltin(
		catalog.InterfaceSafetyControl, 1, 0, okHandler(nil)); err != nil {
		t.Fatalf("RegisterBuiltin safety: %v", err)
	}

	resolved := module.ResolveEndpoint(
		"caller",
		identity.Caller{PackageID: testCallerPackage},
		&ipcv1.ResolveEndpoint{
			RequestId:         1,
			InterfaceId:       catalog.InterfaceSafetyControl,
			MinInterfaceMajor: 1,
			MaxInterfaceMajor: 1,
		},
	)
	if resolved.GetSuccess() == nil {
		t.Fatalf("Resolve safety: %+v", resolved.GetFailure())
	}
	endpointID := resolved.GetSuccess().GetEndpointId()

	if _, routeErr := module.Route("caller", endpointID, 2); routeErr.Code != ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED {
		t.Fatalf("Rearm without method permission = %v", routeErr.Code)
	}
	permissions.grant(testCallerPackage, "perm.safety.rearm")
	if _, routeErr := module.Route("caller", endpointID, 2); routeErr.Code != ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		t.Fatalf("Rearm with method permission = %v", routeErr.Code)
	}
}

func TestBuiltinSurvivesUnrelatedConnectionClose(t *testing.T) {
	definitions := defaultCatalog(t)
	module := testModule(
		t, definitions, newFakePkgs(), newFakePerm(), &fakeStarter{})
	if err := module.RegisterBuiltin(
		catalog.InterfaceTransferControl, 1, 0, okHandler(nil)); err != nil {
		t.Fatalf("RegisterBuiltin: %v", err)
	}

	first := module.ResolveEndpoint(
		"first",
		identity.Caller{PackageID: testCallerPackage},
		&ipcv1.ResolveEndpoint{
			RequestId:         1,
			InterfaceId:       catalog.InterfaceTransferControl,
			MinInterfaceMajor: 1,
			MaxInterfaceMajor: 1,
		},
	)
	if first.GetSuccess() == nil {
		t.Fatalf("first Resolve: %+v", first.GetFailure())
	}
	module.ConnClosed("first")

	second := module.ResolveEndpoint(
		"second",
		identity.Caller{PackageID: testCallerPackage},
		&ipcv1.ResolveEndpoint{
			RequestId:         2,
			InterfaceId:       catalog.InterfaceTransferControl,
			MinInterfaceMajor: 1,
			MaxInterfaceMajor: 1,
		},
	)
	if second.GetSuccess() == nil {
		t.Fatalf("second Resolve: %+v", second.GetFailure())
	}
}
