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

// newSubscribeServer 造一个订阅链路可用的 Server：fakeEndpoints 放行订阅，
// 并给出一份权威 EventMeta。
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

// 订阅建立后必须回带 subscription_id 与 delivery_class。
//
// delivery_class 不能省：它决定客户端看到 sequence 缺口时该「什么都不做」
// 还是「数据永久丢失」。不告诉它，客户端无从判断。
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
		t.Errorf("request_id = %d, want 1（必须原样回带）", res.GetRequestId())
	}
	s := res.GetSuccess()
	if s.GetSubscriptionId() == 0 {
		t.Error("subscription_id 不能为 0：0 是保留值")
	}
	if s.GetDeliveryClass() != ipcv1.DeliveryClass_DELIVERY_CLASS_STATE {
		t.Errorf("delivery_class = %v, want STATE", s.GetDeliveryClass())
	}
}

// 准入失败时回 SubscribeResult.failure，不关连接——订阅方可能只是订错了
// 一个 event_id，没必要因此丢掉整条连接上的其它工作。
func TestSubscribe_RouteFailureReturnsResult(t *testing.T) {
	fe, sock := newSubscribeServer(t, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE)
	fe.eventErr = endpoint.RouteError{Code: ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED}
	c := dialHandshaked(t, sock)

	if err := WriteFrame(c, mustMarshal(t, subscribeEnv(1, 5, 1))); err != nil {
		t.Fatalf("write: %v", err)
	}
	res := readEnv(t, c).GetSubscribeResult()
	if res.GetSuccess() != nil {
		t.Fatal("准入失败却返回了成功")
	}
	if code := res.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED {
		t.Fatalf("code = %v, want PERMISSION_DENIED", code)
	}
}

// request_id 0 是保留值，与 Request/AcquireControl 同规：协议违规、关连接。
func TestSubscribe_ZeroRequestIDIsViolation(t *testing.T) {
	_, sock := newSubscribeServer(t, ipcv1.DeliveryClass_DELIVERY_CLASS_RELIABLE)
	c := dialHandshaked(t, sock)

	if err := WriteFrame(c, mustMarshal(t, subscribeEnv(0, 5, 1))); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectClosed(t, c)
}

// 退订之后 subscription_id 立即失效，重复退订回 NOT_FOUND。
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
		t.Fatalf("首次退订失败: %v", first.GetFailure().GetCode())
	}
	second := unsub(3)
	if second.GetSuccess() != nil {
		t.Fatal("重复退订被当成成功")
	}
	if code := second.GetFailure().GetCode(); code != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("code = %v, want NOT_FOUND", code)
	}
}

// 【非 Service 发 PublishEvent 是方向错误】：普通 App 不能推事件。
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
