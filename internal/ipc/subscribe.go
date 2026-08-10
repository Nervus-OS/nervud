// 本文件把 Envelope 的订阅三件套接到 internal/subscription:
//
//	Subscribe(40) 订阅方 -> nervud 建立 (endpoint, event_id) 订阅
//	Unsubscribe(42) 订阅方 -> nervud 撤下
//	PublishEvent(53) Provider -> nervud 上报一条事件, 由 nervud 扇出
//
// 准入全部走 endpoint 模块, 与方法调用同源: binding 仍活着, 世代未漂移,
// 接口级与事件级权限都通过. 本文件不自己做任何安全判定.
package ipc

import (
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/endpoint"
	"github.com/nervus-os/nervud/internal/subscription"
)

// defaultEventPayloadBytes 是 EventMeta.max_payload_bytes 未指定时的保守上限.
//
// 0 表示采用默认, 不表示无限. 事件是推送, 订阅方没有背压之外的手段拒收;
// 允许无限大等于让一个 Provider 能撑爆所有订阅方的出站队列.
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
		// request_id 0 是保留值, 与 Request/AcquireControl 同规
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

	// delivery_class 随 SubscribeSuccess 回给订阅方: 它决定客户端看到 sequence
	// 缺口时该"什么都不做"还是"数据永久丢失". 不告诉它, 客户端无从判断
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

// admitSubscription 裁决一次订阅的实例作用域.
//
// 契约说了算: EventMeta.scoped = 本事件按实例分, Subscribe.scope 必填且
// 必须属于这个调用方; 未声明 = endpoint 作用域, 谁能 Resolve 到就能订.
//
// 两侧不一致时全部 fail closed - 任何一个方向的猜测都有实际后果: 猜"按实例"
// 会让合法订阅收不到事件, 猜"按 endpoint"会把别人的事件送出去.
func (co *conn) admitSubscription(
	route endpoint.EventRoute, req *ipcv1.Subscribe,
) (uint64, ipcv1.StatusCode) {
	scope := req.GetScope()

	if !route.Event.Meta.GetScoped() {
		if scope != 0 {
			// 契约说本事件不分实例, 调用方却指定了一个. 静默忽略会让它以为
			// 自己在观察某一个实例, 实际收到的是全部.
			return 0, ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT
		}
		return 0, ipcv1.StatusCode_STATUS_CODE_OK
	}

	if scope == 0 {
		// 按实例分发的事件必须说清楚要看哪一个. 0 不表示"全部" -
		// 那正是本机制要消灭的广播.
		return 0, ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT
	}

	// 内建 endpoint: 所有权归内核自己, 直接问它.
	if route.Admit != nil {
		result := route.Admit(endpoint.BuiltinSubscribeCall{
			Caller:  co.caller,
			EventID: req.GetEventId(),
			Scope:   scope,
		})
		if result.Code != ipcv1.StatusCode_STATUS_CODE_OK {
			return 0, result.Code
		}
		return scope, ipcv1.StatusCode_STATUS_CODE_OK
	}

	// 外部 Provider: 查归属表. 表由 Provider 经 BindEventScope 预先登记,
	// 未登记即拒绝 - 放行一个没登记的 scope 等于回到广播.
	provider, ok := route.ProviderConn.(*conn)
	if !ok || provider == nil {
		return 0, ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE
	}
	if !co.s.eventScopes.allows(provider, route.ProviderEndpointID, scope, co) {
		// NOT_FOUND 而不是 PERMISSION_DENIED: 后者会告诉调用方"这个实例
		// 存在, 只是不归你" - 那本身就是信息. 与 operation 的不可区分投影一致.
		return 0, ipcv1.StatusCode_STATUS_CODE_NOT_FOUND
	}
	return scope, ipcv1.StatusCode_STATUS_CODE_OK
}

// handleBindEventScope 处理 Provider 的一次实例归属登记.
//
// 单向, 没有结果. 与 PublishEvent 同理: 给它配结果会让 Provider 的处理
// 流程多一次往返, 而它不需要 - 本 body 与随后的 DispatchResult 走同一条有序
// 连接, nervud 生成调用方 Response 时登记必然已经生效.
//
// 因此这里的失败只记审计并丢弃, 不回消息, 也不关连接.
func (co *conn) handleBindEventScope(req *ipcv1.BindEventScope) bool {
	if co.s.endpoints == nil || co.s.eventScopes == nil {
		return true
	}
	// 只有导出接口的组件能登记: 一个纯消费者发这个 body 属于方向错误.
	if !co.componentType.CanProvideInterfaces() {
		co.log.Warn("ipc: component type may not send BindEventScope, closing")
		co.s.auditViolation(co.caller, errUnexpectedBody)
		return false
	}
	if req.GetScope() == 0 {
		co.s.auditScopeRejected(co.caller, req.GetEndpointId(), req.GetScope(),
			ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT)
		return true
	}

	// endpoint 必须真的属于这条连接. 少了这道检查, 任何一个系统服务都能替
	// 别的 endpoint 登记归属 - 进而把自己塞进别人的事件流.
	if !co.s.endpoints.OwnsEndpoint(co, req.GetEndpointId()) {
		co.s.auditScopeRejected(co.caller, req.GetEndpointId(), req.GetScope(),
			ipcv1.StatusCode_STATUS_CODE_NOT_FOUND)
		return true
	}

	if req.GetReleased() {
		co.s.eventScopes.release(co, req.GetEndpointId(), req.GetScope())
		return true
	}

	// 归属靠 route 证明, 不靠自报: Provider 说的是"属于我正在处理的这次
	// 调用的调用方", 而那次调用是谁发起的 nervud 自己知道.
	entry, ok := co.s.dispatch.origin(req.GetOriginRouteId(), co)
	if !ok || entry.source == nil {
		co.s.auditScopeRejected(co.caller, req.GetEndpointId(), req.GetScope(),
			ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION)
		return true
	}
	co.s.eventScopes.bind(co, req.GetEndpointId(), req.GetScope(), entry.source)
	return true
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
	// 收到成功结果之后, 该 subscription_id 上不会再有任何 Event
	return co.enqueue(&ipcv1.Envelope{Body: &ipcv1.Envelope_UnsubscribeResult{
		UnsubscribeResult: &ipcv1.UnsubscribeResult{
			RequestId: reqID,
			Outcome: &ipcv1.UnsubscribeResult_Success{
				Success: &ipcv1.UnsubscribeSuccess{},
			},
		},
	}})
}

// handlePublishEvent 处理 Provider 的一次事件上报.
//
// 单向, 没有结果. 给它配结果会让 Provider 的事件循环变成请求-响应,
// 一个慢订阅者就能拖住整个 Provider - 而背压的正确落点是 nervud 与订阅方之间.
//
// 因此这里的失败 (endpoint 不属于本连接, event_id 不在契约里, 载荷超限)
// 只记审计并丢弃这一条, 不回消息, 也不关连接.
func (co *conn) handlePublishEvent(req *ipcv1.PublishEvent) bool {
	if co.s.endpoints == nil || co.s.subscriptions == nil {
		return true
	}
	// 只有导出接口的组件能上报事件: 一个纯消费者发这个 body 属于方向错误
	if !co.componentType.CanProvideInterfaces() {
		co.log.Warn("ipc: component type may not send PublishEvent, closing")
		co.s.auditViolation(co.caller, errUnexpectedBody)
		return false
	}

	event, routeErr := co.s.endpoints.LookupProviderEvent(
		co, req.GetEndpointId(), req.GetEventId())
	if routeErr.Code != ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		// Provider 推了一个它不拥有的 endpoint, 或契约里没声明过的事件.
		// 丢弃并审计 - 这不是能力缺口, 是 Provider 侧的 bug 或越权尝试
		co.s.auditPublishRejected(co.caller, req.GetEndpointId(), req.GetEventId(), routeErr.Code)
		return true
	}

	// 载荷上限: 0 表示采用保守默认, 不表示无限
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

// closeSubscriptions 向被终止的订阅方发 SubscriptionClosed 并清掉登记.
//
// 先发通知再清登记: 反过来的话, 清掉之后到达的那条通知会被当成
// "一个不存在的订阅的关闭消息", 而订阅方无从判断它是不是自己漏拆了.
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
