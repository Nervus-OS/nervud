package ipc

import (
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/endpoint"
)

func subscribeEnv(reqID, endpointID uint64, eventID uint32) *ipcv1.Envelope {
	return &ipcv1.Envelope{Body: &ipcv1.Envelope_Subscribe{Subscribe: &ipcv1.Subscribe{
		RequestId: reqID, EndpointId: endpointID, EventId: eventID,
	}}}
}

func newSubscribeServer(t *testing.T, class ipcv1.DeliveryClass) (*fakeEndpoints, string) {
	t.Helper()
	meta := &ipcv1.EventMeta{
		EventId:       1,
		DeliveryClass: class,
	}
	fe := &fakeEndpoints{
		eventRoute: endpoint.EventRoute{
			ProviderConn:       "provider",
			ProviderEndpointID: 7,
			InterfaceID:        "nervus.interface.test",
			InterfaceMajor:     1,
			Event:              catalog.EventDefinition{EventID: 1, Meta: meta},
		},
		providerEvent: catalog.EventDefinition{EventID: 1, Meta: meta},
	}
	_, sock := newTestServerWithEndpoints(t, selfUIDInvariants(t), fe)
	return fe, sock
}

//

func TestSubscribe_SuccessCarriesDeliveryClass(t *testing.T) {
	_, sock := newSubscribeServer(t, ipcv1.DeliveryClass_DELIVERY_CLASS_STATE)
	c := dialHandshaked(t, sock)

	if err := WriteFrame(c, mustMarshal(t, subscribeEnv(1, 5, 1))); err != nil {
		t.Fatalf("write: %v", err)
	}
	res := readEnv(t, c).GetSubscribeResult()
	if res == nil {
		t.Fatal("want SubscribeResult")
	}
	if f := res.GetFailure(); f != nil {
		t.Fatalf("unexpected failure: %v", f.GetCode())
	}
	if res.GetRequestId() != 1 {
		t.Errorf("unexpected ipc result; request_id = %d, want 1", res.GetRequestId())
	}
	s := res.GetSuccess()
	if s.GetSubscriptionId() == 0 {
		t.Error("unexpected ipc result; subscription_id 0 0")
	}
	if s.GetDeliveryClass() != ipcv1.DeliveryClass_DELIVERY_CLASS_STATE {
		t.Errorf("delivery_class = %v, want STATE", s.GetDeliveryClass())
	}
}

func TestSubscribe_RouteFailureReturnsResult(t *testing.T) {
	fe, sock := newSubscribeServer(t, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE)
	fe.eventErr = endpoint.RouteError{Code: ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED}
	c := dialHandshaked(t, sock)

	if err := WriteFrame(c, mustMarshal(t, subscribeEnv(1, 5, 1))); err != nil {
		t.Fatalf("write: %v", err)
	}
	res := readEnv(t, c).GetSubscribeResult()
	if res.GetSuccess() != nil {
		t.Fatal("unexpected ipc result")
	}
	if code := res.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED {
		t.Fatalf("code = %v, want PERMISSION_DENIED", code)
	}
}

func TestSubscribe_ZeroRequestIDIsViolation(t *testing.T) {
	_, sock := newSubscribeServer(t, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE)
	c := dialHandshaked(t, sock)

	if err := WriteFrame(c, mustMarshal(t, subscribeEnv(0, 5, 1))); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectClosed(t, c)
}

func TestUnsubscribe_SecondTimeIsNotFound(t *testing.T) {
	_, sock := newSubscribeServer(t, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE)
	c := dialHandshaked(t, sock)

	if err := WriteFrame(c, mustMarshal(t, subscribeEnv(1, 5, 1))); err != nil {
		t.Fatalf("write: %v", err)
	}
	id := readEnv(t, c).GetSubscribeResult().GetSuccess().GetSubscriptionId()

	unsub := func(reqID uint64) *ipcv1.UnsubscribeResult {
		env := &ipcv1.Envelope{Body: &ipcv1.Envelope_Unsubscribe{
			Unsubscribe: &ipcv1.Unsubscribe{RequestId: reqID, SubscriptionId: id},
		}}
		if err := WriteFrame(c, mustMarshal(t, env)); err != nil {
			t.Fatalf("write: %v", err)
		}
		return readEnv(t, c).GetUnsubscribeResult()
	}

	if first := unsub(2); first.GetSuccess() == nil {
		t.Fatalf("unexpected ipc result; value = %v", first.GetFailure().GetCode())
	}
	second := unsub(3)
	if second.GetSuccess() != nil {
		t.Fatal("unexpected ipc result")
	}
	if code := second.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("code = %v, want NOT_FOUND", code)
	}
}

func TestPublishEvent_RejectedFromNonService(t *testing.T) {
	_, sock := newSubscribeServer(t, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE)
	c := dialHandshaked(t, sock)

	env := &ipcv1.Envelope{Body: &ipcv1.Envelope_PublishEvent{
		PublishEvent: &ipcv1.PublishEvent{EndpointId: 7, EventId: 1},
	}}
	if err := WriteFrame(c, mustMarshal(t, env)); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectClosed(t, c)
}

//

func newScopedServer(t *testing.T, admit endpoint.BuiltinSubscribeAdmitter) (*Server, string) {
	t.Helper()
	meta := &ipcv1.EventMeta{
		EventId:       1,
		DeliveryClass: ipcv1.DeliveryClass_DELIVERY_CLASS_STATE,
		Scoped:        true,
	}
	fe := &fakeEndpoints{
		eventRoute: endpoint.EventRoute{
			ProviderConn:       nil,
			ProviderEndpointID: 7,
			InterfaceID:        "nervus.interface.test",
			InterfaceMajor:     1,
			Event:              catalog.EventDefinition{EventID: 1, Meta: meta},
			Admit:              admit,
		},
		providerEvent: catalog.EventDefinition{EventID: 1, Meta: meta},
	}
	return newTestServerWithEndpoints(t, selfUIDInvariants(t), fe)
}

func scopedSubscribeEnv(reqID, scope uint64) *ipcv1.Envelope {
	return &ipcv1.Envelope{Body: &ipcv1.Envelope_Subscribe{Subscribe: &ipcv1.Subscribe{
		RequestId: reqID, EndpointId: 5, EventId: 1, Scope: scope,
	}}}
}

func TestSubscribe_ScopedAdmittedByBuiltin(t *testing.T) {
	var sawScope uint64
	_, sock := newScopedServer(t, func(call endpoint.BuiltinSubscribeCall) endpoint.BuiltinSubscribeResult {
		sawScope = call.Scope
		return endpoint.BuiltinSubscribeResult{Code: ipcv1.StatusCode_STATUS_CODE_OK}
	})
	c := dialHandshaked(t, sock)

	if err := WriteFrame(c, mustMarshal(t, scopedSubscribeEnv(1, 42))); err != nil {
		t.Fatal(err)
	}
	res := readEnv(t, c).GetSubscribeResult()
	if res.GetSuccess() == nil {
		t.Fatalf("unexpected ipc result; value = %v", res.GetFailure().GetCode())
	}
	if sawScope != 42 {
		t.Fatalf("unexpected ipc result; scope = %d, want 42", sawScope)
	}
}

//

func TestSubscribe_ScopedRejectedByBuiltin(t *testing.T) {
	_, sock := newScopedServer(t, func(endpoint.BuiltinSubscribeCall) endpoint.BuiltinSubscribeResult {
		return endpoint.BuiltinSubscribeResult{Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND}
	})
	c := dialHandshaked(t, sock)

	if err := WriteFrame(c, mustMarshal(t, scopedSubscribeEnv(1, 42))); err != nil {
		t.Fatal(err)
	}
	res := readEnv(t, c).GetSubscribeResult()
	if res.GetSuccess() != nil {
		t.Fatal("unexpected ipc result")
	}
	if code := res.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("code = %v, want NOT_FOUND", code)
	}
}

func TestSubscribe_ScopedRequiresNonZeroScope(t *testing.T) {
	_, sock := newScopedServer(t, func(endpoint.BuiltinSubscribeCall) endpoint.BuiltinSubscribeResult {
		t.Error("unexpected ipc result; scope 0")
		return endpoint.BuiltinSubscribeResult{Code: ipcv1.StatusCode_STATUS_CODE_OK}
	})
	c := dialHandshaked(t, sock)

	if err := WriteFrame(c, mustMarshal(t, scopedSubscribeEnv(1, 0))); err != nil {
		t.Fatal(err)
	}
	res := readEnv(t, c).GetSubscribeResult()
	if code := res.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT {
		t.Fatalf("code = %v, want INVALID_ARGUMENT", code)
	}
}

//

func TestSubscribe_UnscopedEventRejectsScope(t *testing.T) {

	_, sock := newSubscribeServer(t, ipcv1.DeliveryClass_DELIVERY_CLASS_STATE)
	c := dialHandshaked(t, sock)

	env := &ipcv1.Envelope{Body: &ipcv1.Envelope_Subscribe{Subscribe: &ipcv1.Subscribe{
		RequestId: 1, EndpointId: 5, EventId: 1, Scope: 42,
	}}}
	if err := WriteFrame(c, mustMarshal(t, env)); err != nil {
		t.Fatal(err)
	}
	res := readEnv(t, c).GetSubscribeResult()
	if res.GetSuccess() != nil {
		t.Fatal("unexpected ipc result; scoped scope")
	}
	if code := res.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT {
		t.Fatalf("code = %v, want INVALID_ARGUMENT", code)
	}
}

func TestSubscribe_ScopedExternalRequiresBinding(t *testing.T) {
	_, sock := newScopedServer(t, nil)
	c := dialHandshaked(t, sock)

	if err := WriteFrame(c, mustMarshal(t, scopedSubscribeEnv(1, 42))); err != nil {
		t.Fatal(err)
	}
	res := readEnv(t, c).GetSubscribeResult()
	if res.GetSuccess() != nil {
		t.Fatal("unexpected ipc result")
	}
}
