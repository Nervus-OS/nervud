// 本文件把 Envelope 的订阅三件套接到 internal/subscription：
//
//	Subscribe(40)    订阅方 → nervud   建立 (endpoint, event_id) 订阅
//	Unsubscribe(42)  订阅方 → nervud   撤下
//	PublishEvent(53) Provider → nervud 上报一条事件，由 nervud 扇出
//
// 准入全部走 endpoint 模块，与方法调用同源：binding 仍活着、世代未漂移、
// 接口级与事件级权限都通过。本文件不自己做任何安全判定。
package ipc

import (
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/endpoint"
	"github.com/nervus-os/nervud/internal/pkgregistry"
	"github.com/nervus-os/nervud/internal/subscription"
)

// defaultEventPayloadBytes 是 EventMeta.max_payload_bytes 未指定时的保守上限。
//
// 【0 表示采用默认，不表示无限】。事件是推送，订阅方没有背压之外的手段拒收；
// 允许无限大等于让一个 Provider 能撑爆所有订阅方的出站队列。
const defaultEventPayloadBytes = 64 << 10

func subscribeFailure(reqID uint64, code ipcv1.StatusCode) *ipcv1.Envelope {
	return &ipcv1.Envelope{Body: &ipcv1.Envelope_SubscribeResult{
		SubscribeResult: &ipcv1.SubscribeResult{
			RequestId: reqID,
			Outcome: &ipcv1.SubscribeResult_Failure{
				Failure: &ipcv1.Failure{Code: code},
			},
		},
	}}
}

func unsubscribeFailure(reqID uint64, code ipcv1.StatusCode) *ipcv1.Envelope {
	return &ipcv1.Envelope{Body: &ipcv1.Envelope_UnsubscribeResult{
		UnsubscribeResult: &ipcv1.UnsubscribeResult{
			RequestId: reqID,
			Outcome: &ipcv1.UnsubscribeResult_Failure{
				Failure: &ipcv1.Failure{Code: code},
			},
		},
	}}
}

func (co *conn) handleSubscribe(req *ipcv1.Subscribe) bool {
	reqID := req.GetRequestId()
	if reqID == 0 {
		// request_id 0 是保留值，与 Request/AcquireControl 同规
		co.s.auditViolation(co.caller, errZeroRequestID)
		return false
	}
	if co.s.endpoints == nil || co.s.subscriptions == nil {
		return co.enqueue(subscribeFailure(reqID, ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE))
	}

	route, routeErr := co.s.endpoints.RouteEvent(co, req.GetEndpointId(), req.GetEventId())
	if routeErr.Code != ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		return co.enqueue(subscribeFailure(reqID, routeErr.Code))
	}

	scope, code := co.admitSubscription(route, req)
	if code != ipcv1.StatusCode_STATUS_CODE_OK {
		return co.enqueue(subscribeFailure(reqID, code))
	}

	id := co.s.subscriptions.Subscribe(
		co, co, req.GetEndpointId(),
		subscription.Key{
			ProviderConn: route.ProviderConn,
			EndpointID:   route.ProviderEndpointID,
			EventID:      req.GetEventId(),
			Scope:        scope,
		},
		route.Event.Meta,
	)

	// delivery_class 随 SubscribeSuccess 回给订阅方：它决定客户端看到 sequence
	// 缺口时该「什么都不做」还是「数据永久丢失」。不告诉它，客户端无从判断
	return co.enqueue(&ipcv1.Envelope{Body: &ipcv1.Envelope_SubscribeResult{
		SubscribeResult: &ipcv1.SubscribeResult{
			RequestId: reqID,
			Outcome: &ipcv1.SubscribeResult_Success{
				Success: &ipcv1.SubscribeSuccess{
					SubscriptionId: id,
					DeliveryClass:  subscription.DeliveryClassOf(route.Event.Meta),
				},
			},
		},
	}})
}

// admitSubscription 裁决一次订阅的实例作用域。
//
// 【契约说了算】：EventMeta.subscribe_payload_type 非空 = 本事件按实例分，
// 必须有人回答「这个调用方能不能订这个实例」；为空 = endpoint 作用域，
// 谁能 Resolve 到就能订。
//
// 四种组合里只有一种放行，其余全部 fail closed——两侧不一致时，任何一个方向的
// 猜测都会造成实际后果：猜「按实例」会让合法订阅收不到事件，猜「按 endpoint」
// 会把别人的事件送出去。
func (co *conn) admitSubscription(
	route endpoint.EventRoute, req *ipcv1.Subscribe,
) (uint64, ipcv1.StatusCode) {
	scoped := route.Event.Meta.GetSubscribePayloadType() != ""

	if !scoped {
		if len(req.GetPayload()) != 0 {
			// 契约没声明订阅参数，调用方却带了一份。静默忽略会让它以为自己
			// 加了过滤条件，然后收到全部事件却不知道过滤没生效。
			return 0, ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT
		}
		return 0, ipcv1.StatusCode_STATUS_CODE_OK
	}

	if route.Admit == nil {
		// 契约要求按实例订阅，但这个 endpoint 没有准入实现——当前只有内建
		// 支持（见 BuiltinSubscribeAdmitter 的说明）。
		//
		// 【必须拒绝】：放行等于按 endpoint 作用域订阅一个明确声明了要按实例
		// 分的事件，那正是契约在防的泄漏。回 UNAVAILABLE 而不是 INTERNAL——
		// 这是能力缺口，不是调用方的错。
		return 0, ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE
	}

	result := route.Admit(endpoint.BuiltinSubscribeCall{
		Caller:  co.caller,
		EventID: req.GetEventId(),
		Payload: req.GetPayload(),
	})
	if result.Code != ipcv1.StatusCode_STATUS_CODE_OK {
		return 0, result.Code
	}
	if result.Scope == 0 {
		// 准入放行却没给作用域。0 表示「不分实例」，用在这里等于广播——
		// 而这条路径存在的全部理由就是不广播。当成内核装配 bug 拒掉。
		co.log.Error("ipc: builtin subscribe admitter returned OK with zero scope",
			"event_id", req.GetEventId())
		return 0, ipcv1.StatusCode_STATUS_CODE_INTERNAL
	}
	return result.Scope, ipcv1.StatusCode_STATUS_CODE_OK
}

func (co *conn) handleUnsubscribe(req *ipcv1.Unsubscribe) bool {
	reqID := req.GetRequestId()
	if reqID == 0 {
		co.s.auditViolation(co.caller, errZeroRequestID)
		return false
	}
	if co.s.subscriptions == nil {
		return co.enqueue(unsubscribeFailure(reqID, ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE))
	}
	if !co.s.subscriptions.Unsubscribe(co, req.GetSubscriptionId()) {
		return co.enqueue(unsubscribeFailure(reqID, ipcv1.StatusCode_STATUS_CODE_NOT_FOUND))
	}
	// 收到成功结果之后，该 subscription_id 上不会再有任何 Event
	return co.enqueue(&ipcv1.Envelope{Body: &ipcv1.Envelope_UnsubscribeResult{
		UnsubscribeResult: &ipcv1.UnsubscribeResult{
			RequestId: reqID,
			Outcome: &ipcv1.UnsubscribeResult_Success{
				Success: &ipcv1.UnsubscribeSuccess{},
			},
		},
	}})
}

// handlePublishEvent 处理 Provider 的一次事件上报。
//
// 【单向，没有结果】。给它配结果会让 Provider 的事件循环变成请求-响应，
// 一个慢订阅者就能拖住整个 Provider——而背压的正确落点是 nervud 与订阅方之间。
//
// 因此这里的失败（endpoint 不属于本连接、event_id 不在契约里、载荷超限）
// 只记审计并丢弃这一条，不回消息、也不关连接。
func (co *conn) handlePublishEvent(req *ipcv1.PublishEvent) bool {
	if co.s.endpoints == nil || co.s.subscriptions == nil {
		return true
	}
	// 只有 Service 能上报事件：普通 App 发这个 body 属于方向错误
	if co.componentType != pkgregistry.ComponentService {
		co.log.Warn("ipc: non-service sent PublishEvent, closing")
		co.s.auditViolation(co.caller, errUnexpectedBody)
		return false
	}

	event, routeErr := co.s.endpoints.LookupProviderEvent(
		co, req.GetEndpointId(), req.GetEventId())
	if routeErr.Code != ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		// Provider 推了一个它不拥有的 endpoint、或契约里没声明过的事件。
		// 丢弃并审计——这不是能力缺口，是 Provider 侧的 bug 或越权尝试
		co.s.auditPublishRejected(co.caller, req.GetEndpointId(), req.GetEventId(), routeErr.Code)
		return true
	}

	// 载荷上限：0 表示采用保守默认，不表示无限
	maxPayload := int(event.Meta.GetMaxPayloadBytes())
	if maxPayload == 0 {
		maxPayload = defaultEventPayloadBytes
	}
	if len(req.GetPayload()) > maxPayload {
		co.s.auditPublishRejected(co.caller, req.GetEndpointId(), req.GetEventId(),
			ipcv1.StatusCode_STATUS_CODE_RESOURCE_EXHAUSTED)
		return true
	}

	closed := co.s.subscriptions.Publish(
		subscription.Key{
			ProviderConn: endpoint.ConnHandle(co),
			EndpointID:   req.GetEndpointId(),
			EventID:      req.GetEventId(),
		},
		req.GetPayload(),
		req.GetMonotonicTimestampNanos(),
	)
	co.s.closeSubscriptions(closed)
	return true
}

// closeSubscriptions 向被终止的订阅方发 SubscriptionClosed 并清掉登记。
//
// 先发通知再清登记：反过来的话，清掉之后到达的那条通知会被当成
// 「一个不存在的订阅的关闭消息」，而订阅方无从判断它是不是自己漏拆了。
func (s *Server) closeSubscriptions(closed []subscription.Closed) {
	for _, c := range closed {
		target, ok := c.Conn.(*conn)
		if !ok || target == nil {
			continue
		}
		target.Deliver(&ipcv1.Envelope{Body: &ipcv1.Envelope_SubscriptionClosed{
			SubscriptionClosed: &ipcv1.SubscriptionClosed{
				SubscriptionId: c.SubscriptionID,
				Reason:         c.Reason,
			},
		}})
		s.subscriptions.Unsubscribe(c.Conn, c.SubscriptionID)
	}
}
