package ipc

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	transferv1 "github.com/nervus-os/nervus-ipc/protocol/interface/transferv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/control"
	"github.com/nervus-os/nervud/internal/endpoint"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/pkgregistry"
	"github.com/nervus-os/nervud/internal/transfer"
)

type endpointRevocation struct {
	provider   transfer.ConnID
	endpointID uint64
	generation uint64
}

type recordingTransfer struct {
	beginCalls   int
	beginOrigin  transfer.Origin
	beginReq     *transferv1.BeginTransferRequest
	closedRoutes []uint64
	events       []string
	revocations  []endpointRevocation
	packages     []string
	permissions  [][2]string
	resources    []catalog.RevokedResource
	controls     []struct {
		caller   transfer.ConnID
		resource string
	}
}

func (r *recordingTransfer) Begin(
	origin transfer.Origin,
	req *transferv1.BeginTransferRequest,
) (*transferv1.BeginTransferResponse, error) {
	r.beginCalls++
	r.beginOrigin = origin
	r.beginReq = proto.Clone(req).(*transferv1.BeginTransferRequest)
	return &transferv1.BeginTransferResponse{}, nil
}

func (*recordingTransfer) Commit(transfer.ConnID, []byte) error { return nil }
func (*recordingTransfer) Abort(transfer.ConnID, []byte) error  { return nil }
func (*recordingTransfer) FinishRoute(uint64, bool, []*ipcv1.TransferHandle) error {
	return nil
}
func (r *recordingTransfer) CloseRoute(routeID uint64) {
	r.closedRoutes = append(r.closedRoutes, routeID)
	r.events = append(r.events, fmt.Sprintf("close:%d", routeID))
}
func (*recordingTransfer) ConnClosed(transfer.ConnID) {}
func (r *recordingTransfer) EndpointRevoked(provider transfer.ConnID, endpointID, generation uint64) {
	r.revocations = append(r.revocations, endpointRevocation{
		provider: provider, endpointID: endpointID, generation: generation,
	})
}
func (r *recordingTransfer) RevokePackage(packageID string) {
	r.packages = append(r.packages, packageID)
	r.events = append(r.events, "package:"+packageID)
}
func (r *recordingTransfer) RevokePermission(packageID, permission string) {
	r.permissions = append(r.permissions, [2]string{packageID, permission})
}
func (r *recordingTransfer) RevokeResource(resource string, generation uint64) {
	r.resources = append(r.resources, catalog.RevokedResource{
		Handle: resource, Generation: generation,
	})
}
func (r *recordingTransfer) RevokeControl(caller transfer.ConnID, resource string) {
	r.controls = append(r.controls, struct {
		caller   transfer.ConnID
		resource string
	}{caller: caller, resource: resource})
}

func transferControlTestConn(
	s *Server,
	connID uint64,
	packageID, componentID string,
	pid int32,
	uid, gid uint32,
) *conn {
	return &conn{
		s:        s,
		connID:   control.ConnID(connID),
		outbox:   newOutboundQueue(256 << 10),
		requests: make(map[uint64]int),
		caller: identity.Caller{
			PackageID: packageID, ComponentID: componentID,
			PID: pid, UID: uid, GID: gid,
		},
	}
}

func TestRevokePackageClosesOldProviderRouteBeforeTransferScan(t *testing.T) {
	transfers := &recordingTransfer{}
	s := &Server{dispatch: newDispatchTable(), transfer: transfers}
	caller := transferControlTestConn(s, 10, "com.example.viewer", "ui", 101, 1001, 1001)
	provider := transferControlTestConn(s, 20, "com.example.camera", "service", 202, 1002, 1002)
	routeID := s.dispatch.create(
		caller, 1, provider, time.Now().Add(time.Minute), transferControlTestRoute(), 9)
	payload := marshalBeginTransfer(t, routeID)

	s.RevokePackage(provider.caller.PackageID)

	if _, ok := s.dispatch.origin(routeID, provider); ok {
		t.Fatal("package revocation left the old provider route live")
	}
	if got := s.beginTransferBuiltin(provider, payload).Code; got != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("Begin after package revocation = %v, want NOT_FOUND", got)
	}
	if transfers.beginCalls != 0 {
		t.Fatalf("revoked route reached Transfer.Begin %d times", transfers.beginCalls)
	}
	wantEvents := []string{fmt.Sprintf("close:%d", routeID), "package:" + provider.caller.PackageID}
	if !reflect.DeepEqual(transfers.events, wantEvents) {
		t.Fatalf("revocation order = %v, want %v", transfers.events, wantEvents)
	}

	cancel, ok := provider.outbox.pop()
	if !ok || cancel.GetCancelDispatch().GetRouteId() != routeID ||
		cancel.GetCancelDispatch().GetReason() != ipcv1.CancelDispatchReason_CANCEL_DISPATCH_REASON_UNSPECIFIED {
		t.Fatalf("provider cancellation = %v, want route %d with UNSPECIFIED reason", cancel, routeID)
	}
	response, ok := caller.outbox.pop()
	if !ok || response.GetResponse().GetFailure().GetCode() != ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE {
		t.Fatalf("caller response = %v, want UNAVAILABLE", response)
	}
}

func TestRevokeResourceAlsoInvalidatesControlLease(t *testing.T) {
	transfers := &recordingTransfer{}
	leases := &fakeLeases{}
	s := &Server{dispatch: newDispatchTable(), transfer: transfers, leases: leases}

	s.RevokeResource("arm.main", 7)

	leases.mu.Lock()
	gotLeases := append([]catalog.RevokedResource(nil), leases.resources...)
	leases.mu.Unlock()
	want := []catalog.RevokedResource{{Handle: "arm.main", Generation: 7}}
	if !reflect.DeepEqual(gotLeases, want) {
		t.Fatalf("control resource revocations = %v, want %v", gotLeases, want)
	}
	if !reflect.DeepEqual(transfers.resources, want) {
		t.Fatalf("transfer resource revocations = %v, want %v", transfers.resources, want)
	}
}

func TestRevokeResourceDoesNotRemoveReplacementGenerationRoute(t *testing.T) {
	transfers := &recordingTransfer{}
	s := &Server{dispatch: newDispatchTable(), transfer: transfers}
	caller := transferControlTestConn(s, 10, "com.example.viewer", "ui", 101, 1001, 1001)
	provider := transferControlTestConn(s, 20, "com.example.camera", "service", 202, 1002, 1002)
	oldRoute := transferControlTestRoute()
	replacement := transferControlTestRoute()
	replacement.ResourceGeneration++

	oldID := s.dispatch.create(
		caller, 1, provider, time.Now().Add(time.Minute), oldRoute, 9)
	replacementID := s.dispatch.create(
		caller, 2, provider, time.Now().Add(time.Minute), replacement, 9)

	s.RevokeResource(oldRoute.ResourceHandle, oldRoute.ResourceGeneration)

	if _, live := s.dispatch.origin(oldID, provider); live {
		t.Fatal("obsolete resource generation route remained live")
	}
	if _, live := s.dispatch.origin(replacementID, provider); !live {
		t.Fatal("obsolete resource generation revoked the replacement route")
	}
}

func TestDispatchPublishAndRevocationCannotQueueCancelBeforeDispatch(t *testing.T) {
	transfers := &recordingTransfer{}
	s := &Server{dispatch: newDispatchTable(), transfer: transfers}
	caller := transferControlTestConn(s, 10, "com.example.viewer", "ui", 101, 1001, 1001)
	provider := transferControlTestConn(s, 20, "com.example.camera", "service", 202, 1002, 1002)
	route := transferControlTestRoute()
	epoch := s.dispatch.snapshotEpoch()

	publishEntered := make(chan struct{})
	allowPublish := make(chan struct{})
	s.dispatch.beforePublishEnqueue = func() {
		close(publishEntered)
		<-allowPublish
	}
	published := make(chan dispatchPublishStatus, 1)
	var routeID uint64
	go func() {
		id, status := s.dispatch.publishDispatchAtEpoch(
			epoch, caller, 1, provider, time.Now().Add(time.Minute), route, 9,
			1000, []byte("request"), &ipcv1.CallerContext{PackageId: caller.caller.PackageID},
			nil,
		)
		routeID = id
		published <- status
	}()
	<-publishEntered

	revokeStarted := make(chan struct{})
	revokeDone := make(chan struct{})
	go func() {
		close(revokeStarted)
		s.RevokePackage(caller.caller.PackageID)
		close(revokeDone)
	}()
	<-revokeStarted
	close(allowPublish)

	if status := <-published; status != dispatchPublishOK {
		t.Fatalf("publish status = %v, want dispatchPublishOK", status)
	}
	<-revokeDone

	first, ok := provider.outbox.pop()
	if !ok || first.GetDispatch().GetRouteId() != routeID {
		t.Fatalf("first provider item = %v, want Dispatch route %d", first, routeID)
	}
	second, ok := provider.outbox.pop()
	if !ok || second.GetCancelDispatch().GetRouteId() != routeID {
		t.Fatalf("second provider item = %v, want CancelDispatch route %d", second, routeID)
	}
	if _, live := s.dispatch.origin(routeID, provider); live {
		t.Fatal("revoked route remained live")
	}
}

func TestCoordinatedRevocationSelectorsOnlyRemoveMatchingRoutes(t *testing.T) {
	tests := []struct {
		name   string
		revoke func(*Server, *conn)
		dead   []int
	}{
		{
			name:   "package",
			revoke: func(s *Server, _ *conn) { s.RevokePackage("com.example.a") },
			dead:   []int{0, 1, 3},
		},
		{
			name: "permission package and id",
			revoke: func(s *Server, _ *conn) {
				s.RevokePermission("com.example.a", "camera.read")
			},
			dead: []int{0, 3},
		},
		{
			name:   "resource",
			revoke: func(s *Server, _ *conn) { s.RevokeResource("camera.front", 13) },
			dead:   []int{0, 2, 3},
		},
		{
			name: "control connection resource and method gate",
			revoke: func(s *Server, sourceA *conn) {
				s.RevokeControl(transfer.ConnID(sourceA.connID), "camera.front")
			},
			dead: []int{0},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			transfers := &recordingTransfer{}
			s := &Server{dispatch: newDispatchTable(), transfer: transfers}
			sourceA := transferControlTestConn(s, 10, "com.example.a", "ui", 101, 1001, 1001)
			sourceB := transferControlTestConn(s, 11, "com.example.b", "ui", 102, 1002, 1002)
			provider := transferControlTestConn(s, 20, "com.example.provider", "service", 202, 1003, 1003)

			routes := []endpoint.RouteInfo{
				transferControlTestRoute(),
				transferControlTestRoute(),
				transferControlTestRoute(),
				transferControlTestRoute(),
			}
			routes[1].ResourceHandle = "arm.main"
			routes[1].RequiredPermissions = []string{"arm.control"}
			routes[3].Method.Meta = proto.Clone(routes[3].Method.Meta).(*ipcv1.MethodMeta)
			routes[3].Method.Meta.RequiresControlLease = false

			sources := []*conn{sourceA, sourceA, sourceB, sourceA}
			ids := make([]uint64, len(routes))
			for i := range routes {
				ids[i] = s.dispatch.create(
					sources[i], uint64(i+1), provider, time.Now().Add(time.Minute), routes[i], 9)
			}

			tc.revoke(s, sourceA)
			dead := make(map[int]bool, len(tc.dead))
			for _, index := range tc.dead {
				dead[index] = true
			}
			for i, routeID := range ids {
				_, live := s.dispatch.origin(routeID, provider)
				if live == dead[i] {
					t.Fatalf("route[%d] live=%v, want %v", i, live, !dead[i])
				}
			}
		})
	}
}

func transferControlTestRoute() endpoint.RouteInfo {
	return endpoint.RouteInfo{
		ServiceEndpointID:      71,
		InterfaceID:            "com.example.camera",
		InterfaceMajor:         3,
		ResourceHandle:         "camera.front",
		ResourceGeneration:     13,
		RegistrationGeneration: 12,
		RequiredPermissions:    []string{"camera.read", "privacy.indicator"},
		Method: catalog.MethodDefinition{
			MethodID: 9,
			Meta: &ipcv1.MethodMeta{
				MethodId:             9,
				RequiresControlLease: true,
				Transfer: &ipcv1.TransferPolicy{
					Direction:         ipcv1.TransferDirection_TRANSFER_DIRECTION_PROVIDER_TO_CALLER,
					MaxStreams:        2,
					MaxPacketBytes:    64 << 10,
					MaxBytesPerSecond: 8 << 20,
					AllowedModes: []ipcv1.TransferMode{
						ipcv1.TransferMode_TRANSFER_MODE_FRAMED_RELAY,
					},
				},
			},
		},
	}
}

func marshalBeginTransfer(t *testing.T, routeID uint64) []byte {
	t.Helper()
	wire, err := proto.Marshal(&transferv1.BeginTransferRequest{
		OriginRouteId: routeID,
		Direction:     ipcv1.TransferDirection_TRANSFER_DIRECTION_PROVIDER_TO_CALLER,
		PreferredMode: ipcv1.TransferMode_TRANSFER_MODE_FRAMED_RELAY,
	})
	if err != nil {
		t.Fatalf("marshal BeginTransferRequest: %v", err)
	}
	return wire
}

func TestBeginTransferBuiltinRequiresLiveOwningProviderRoute(t *testing.T) {
	transfers := &recordingTransfer{}
	s := &Server{dispatch: newDispatchTable(), transfer: transfers}
	caller := transferControlTestConn(s, 10, "com.example.viewer", "ui", 101, 1001, 1001)
	provider := transferControlTestConn(s, 20, "com.example.camera", "service", 202, 1002, 1002)
	other := transferControlTestConn(s, 21, "com.example.camera", "service", 202, 1002, 1002)

	routeID := s.dispatch.create(
		caller, 1, provider, time.Now().Add(time.Minute), transferControlTestRoute(), 9)
	payload := marshalBeginTransfer(t, routeID)

	if got := s.beginTransferBuiltin(other, payload).Code; got != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("non-owner Begin code = %v, want NOT_FOUND", got)
	}
	if transfers.beginCalls != 0 {
		t.Fatalf("non-owner reached Transfer.Begin %d times, want 0", transfers.beginCalls)
	}

	if _, status := s.dispatch.complete(routeID, provider); status != completeOK {
		t.Fatalf("complete route status = %v, want completeOK", status)
	}
	if got := s.beginTransferBuiltin(provider, payload).Code; got != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("completed-route Begin code = %v, want NOT_FOUND", got)
	}
	if transfers.beginCalls != 0 {
		t.Fatalf("completed route reached Transfer.Begin %d times, want 0", transfers.beginCalls)
	}
}

func TestTransferBuiltinHandlerRejectsForeignServerAndCancelledCall(t *testing.T) {
	transfers := &recordingTransfer{}
	s := &Server{dispatch: newDispatchTable(), transfer: transfers}
	foreign := &Server{dispatch: newDispatchTable(), transfer: &recordingTransfer{}}
	handler := s.TransferBuiltinHandler()

	result := handler(endpoint.BuiltinCall{
		Context: context.Background(),
		Conn:    transferControlTestConn(foreign, 20, "com.example.camera", "service", 202, 1002, 1002),
		MethodID: uint32(
			transferv1.TransferControlMethod_TRANSFER_CONTROL_METHOD_BEGIN_TRANSFER),
	})
	if result.Code != ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION {
		t.Fatalf("foreign-server call code = %v, want FAILED_PRECONDITION", result.Code)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result = handler(endpoint.BuiltinCall{
		Context: ctx,
		Conn:    transferControlTestConn(s, 20, "com.example.camera", "service", 202, 1002, 1002),
		MethodID: uint32(
			transferv1.TransferControlMethod_TRANSFER_CONTROL_METHOD_BEGIN_TRANSFER),
	})
	if result.Code != ipcv1.StatusCode_STATUS_CODE_DEADLINE_EXCEEDED {
		t.Fatalf("cancelled call code = %v, want DEADLINE_EXCEEDED", result.Code)
	}
	if transfers.beginCalls != 0 {
		t.Fatalf("rejected calls reached Transfer.Begin %d times", transfers.beginCalls)
	}
}

func TestBeginTransferBuiltinBuildsCompleteOrigin(t *testing.T) {
	transfers := &recordingTransfer{}
	s := &Server{
		dispatch: newDispatchTable(), transfer: transfers, leases: &fakeLeases{},
	}
	caller := transferControlTestConn(s, 10, "com.example.viewer", "ui", 101, 1001, 1003)
	provider := transferControlTestConn(s, 20, "com.example.camera", "service", 202, 1002, 1004)
	route := transferControlTestRoute()
	deadline := time.Now().Add(time.Minute)
	routeID := s.dispatch.create(caller, 7, provider, deadline, route, 9)

	result := s.beginTransferBuiltin(provider, marshalBeginTransfer(t, routeID))
	if result.Code != ipcv1.StatusCode_STATUS_CODE_OK {
		t.Fatalf("Begin code = %v, want OK", result.Code)
	}
	var response transferv1.BeginTransferResponse
	if err := proto.Unmarshal(result.Payload, &response); err != nil {
		t.Fatalf("unmarshal BeginTransferResponse: %v", err)
	}
	if transfers.beginCalls != 1 {
		t.Fatalf("Transfer.Begin calls = %d, want 1", transfers.beginCalls)
	}

	origin := transfers.beginOrigin
	if origin.RouteID != routeID || origin.Token == nil || !origin.Token.Open() ||
		!origin.Deadline.Equal(deadline) {
		t.Fatalf("route authority = {id:%d token:%v deadline:%v}, want live route %d until %v",
			origin.RouteID, origin.Token, origin.Deadline, routeID, deadline)
	}
	if origin.Caller != transferPeer(caller) || origin.Provider != transferPeer(provider) {
		t.Fatalf("origin peers = caller %+v provider %+v", origin.Caller, origin.Provider)
	}
	if origin.ProviderEndpointID != route.ServiceEndpointID ||
		origin.BindingGeneration != route.RegistrationGeneration ||
		origin.MethodID != 9 || origin.ResourceHandle != route.ResourceHandle ||
		origin.RequiresControlLease != route.Method.Meta.GetRequiresControlLease() {
		t.Fatalf("origin route metadata is incomplete: %+v", origin)
	}
	if !reflect.DeepEqual(origin.RequiredPermissions, route.RequiredPermissions) {
		t.Fatalf("origin permissions = %v, want %v", origin.RequiredPermissions, route.RequiredPermissions)
	}
	if !proto.Equal(origin.Policy, route.Method.Meta.GetTransfer()) {
		t.Fatalf("origin transfer policy = %v, want %v", origin.Policy, route.Method.Meta.GetTransfer())
	}
	if transfers.beginReq.GetOriginRouteId() != routeID {
		t.Fatalf("forwarded origin_route_id = %d, want %d", transfers.beginReq.GetOriginRouteId(), routeID)
	}
}

func TestBeginTransferBuiltinRechecksRequiredControlLease(t *testing.T) {
	transfers := &recordingTransfer{}
	leases := &fakeLeases{checkErr: control.ErrControlNotHeld}
	s := &Server{dispatch: newDispatchTable(), transfer: transfers, leases: leases}
	caller := transferControlTestConn(s, 10, "com.example.viewer", "ui", 101, 1001, 1003)
	provider := transferControlTestConn(s, 20, "com.example.camera", "service", 202, 1002, 1004)
	route := transferControlTestRoute()
	routeID := s.dispatch.create(
		caller, 7, provider, time.Now().Add(time.Minute), route, 9)

	result := s.beginTransferBuiltin(provider, marshalBeginTransfer(t, routeID))
	if result.Code != ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION {
		t.Fatalf("Begin code = %v, want FAILED_PRECONDITION", result.Code)
	}
	if transfers.beginCalls != 0 {
		t.Fatalf("invalid lease reached Transfer.Begin %d times", transfers.beginCalls)
	}
	leases.mu.Lock()
	checked := append([]struct {
		conn       control.ConnID
		resource   string
		generation uint64
	}(nil), leases.checked...)
	leases.mu.Unlock()
	if len(checked) != 1 || checked[0].conn != caller.connID ||
		checked[0].resource != route.ResourceHandle ||
		checked[0].generation != route.ResourceGeneration {
		t.Fatalf("lease checks = %+v, want caller %d resource %q generation %d",
			checked, caller.connID, route.ResourceHandle, route.ResourceGeneration)
	}
}

func TestUnregisterEndpointRevokesTransferOnlyOnSuccess(t *testing.T) {
	tests := []struct {
		name       string
		result     *ipcv1.UnregisterEndpointResult
		wantRevoke bool
	}{
		{
			name: "success",
			result: &ipcv1.UnregisterEndpointResult{
				RequestId: 1,
				Outcome: &ipcv1.UnregisterEndpointResult_Success{
					Success: &ipcv1.UnregisterEndpointSuccess{},
				},
			},
			wantRevoke: true,
		},
		{
			name: "failure",
			result: &ipcv1.UnregisterEndpointResult{
				RequestId: 1,
				Outcome: &ipcv1.UnregisterEndpointResult_Failure{
					Failure: &ipcv1.Failure{Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			transfers := &recordingTransfer{}
			s := &Server{
				endpoints: &fakeEndpoints{unregResult: tc.result},
				transfer:  transfers,
				dispatch:  newDispatchTable(),
			}
			caller := transferControlTestConn(
				s, 33, "com.example.viewer", "ui", 303, 1003, 1003)
			caller.outbox = newOutboundQueue(64 << 10)
			co := &conn{
				s:             s,
				connID:        44,
				componentType: pkgregistry.ComponentService,
				outbox:        newOutboundQueue(64 << 10),
			}
			routeID := s.dispatch.create(
				caller, 7, co, time.Now().Add(time.Minute), endpoint.RouteInfo{
					ServiceEndpointID: 88,
					Method:            endpoint.RouteInfo{}.Method,
				}, 9)
			req := &ipcv1.UnregisterEndpoint{RequestId: 1, EndpointId: 88}
			if ok := co.handleUnregisterEndpoint(
				&ipcv1.Envelope{Body: &ipcv1.Envelope_UnregisterEndpoint{UnregisterEndpoint: req}}, req,
			); !ok {
				t.Fatal("handleUnregisterEndpoint returned false")
			}

			if tc.wantRevoke {
				want := []endpointRevocation{{provider: 44, endpointID: 88, generation: 0}}
				if !reflect.DeepEqual(transfers.revocations, want) {
					t.Fatalf("revocations = %+v, want %+v", transfers.revocations, want)
				}
				if got := s.beginTransferBuiltin(co, marshalBeginTransfer(t, routeID)).Code; got != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
					t.Fatalf("Begin after successful unregister = %v, want NOT_FOUND", got)
				}
			} else if len(transfers.revocations) != 0 {
				t.Fatalf("failed unregister revoked transfers: %+v", transfers.revocations)
			} else if _, ok := s.dispatch.origin(routeID, co); !ok {
				t.Fatal("failed unregister removed a live route")
			}
		})
	}
}
