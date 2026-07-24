// 本文件是连接内的 Envelope 状态机（架构 10.2）：第一帧 Hello/HelloAck 握手，
// 之后按 body 分派。分帧见 frame.go，帧→Envelope 的良构校验见 envelope.go，
// 连接的准入与帧泵见 ipc.go
//
// 写回契约（架构 10.8）：每条连接自持一个有界 outbound 队列（outbox.go）+ 一个
// 独立的 writer goroutine（runWriter），它是唯一真正调用 co.c.Write 的地方，
// 满足 frame.go 的「每条连接只有一个 writer」约束。帧泵/handleRequest 等任何
// goroutine 都只通过 enqueue 把 Envelope 排队，从不直接碰 socket——这也是
// Dispatch 转发（route.go/dispatch.go）得以安全把 Envelope 写进【另一条】
// 连接的原因：目标连接自己的 writer 才是那次写的实际执行者
package ipc

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/identity"
)

// nervud 实现的控制面协议版本（架构 10.12）
//
// nervud 只实现这一个 major；minor 只增不减，握手时在客户端声明的范围内取交集。
// 重大不兼容提升 major 并拒绝无法协商的连接
const (
	protocolMajor    = 1
	protocolMinorMax = 0
)

// 握手/分派阶段发现的、需要关闭连接的情形。分成两类哨兵是为了让离线审计规则
// 能把「协议违规 / 潜在攻击」与「本 build 尚未实现的能力缺口」区分开——混进
// 一个 Action 里，真正的攻击迹象会被未实现路径的噪音淹没
var (
	// errHandshakeExpectedHello：握手前收到了非 Hello 的 body（架构 10.2：第一帧
	// 必须是 Hello）。属于非法握手状态（架构 10.11），按协议违规关闭
	errHandshakeExpectedHello = errors.New("ipc: first frame must be Hello")

	// errDuplicateHello：握手已完成后又收到 Hello。同样是非法握手状态
	errDuplicateHello = errors.New("ipc: Hello received after handshake completed")

	// errUnexpectedBody：客户端发来了只应由服务端产生的响应/推送 body
	// （Response、Event、*Result 等）。协议违规
	errUnexpectedBody = errors.New("ipc: server-originated body not valid inbound from client")

	// errUnsupportedBody：客户端合法发出、但本 build 尚未实现的控制/调用 body。
	// 不是违规，是能力缺口
	errUnsupportedBody = errors.New("ipc: body not implemented in this build")

	// errZeroRequestID：Request 带保留的 request_id 0（架构 10.6：0 永久保留，
	// 合法请求从 1 起）。协议违规
	errZeroRequestID = errors.New("ipc: Request uses reserved request_id 0")

	// errDispatchResultMismatch：DispatchResult 携带的 route_id 存在，但送回
	// 结果的连接不是登记的目标连接。没有合法解释——没有 Service 会被告知一个
	// 指向别的连接的 route_id，因此这不是能力缺口，是潜在伪装
	errDispatchResultMismatch = errors.New("ipc: DispatchResult route_id targets a different connection")
)

// phase 是连接状态机的阶段
type phase uint8

const (
	// phaseHandshake 等待第一帧 Hello。此阶段只接受 Hello，其它 body 一律按
	// 非法握手状态关闭
	phaseHandshake phase = iota
	// phaseReady 握手完成，按 body 分派
	phaseReady
)

// conn 是一条已准入连接的 Envelope 状态机
//
// 它不拥有 socket 的生命周期（那由 ipc.go 的 admit/release 管理），只在帧泵每
// 解出一个 Envelope 时被调用一次
type conn struct {
	s   *Server
	c   net.Conn
	w   *bufio.Writer
	log *slog.Logger

	// caller 是连接建立时解析出的可信身份。握手成功后 ComponentID 被回填
	// （架构 10.2：nervud 验证声明后确认的 Component，而不是相信自报值）
	caller identity.Caller

	phase phase

	// negMajor/negMinor 标注出站 Envelope 的协议版本。握手前用 nervud 支持的
	// 版本，好让「协商失败的 Failure HelloAck」也能告诉客户端本端到底说哪个版本；
	// 握手成功后更新为选定版本
	negMajor uint32
	negMinor uint32

	// outbox 是本连接的有界 outbound 队列，runWriter 是唯一的消费者
	// （架构 10.8，见 outbox.go）
	outbox *outboundQueue
	// writerDone 在 runWriter 退出时关闭，供 serve() 的收尾等待——必须等 writer
	// 真正停止碰 socket 之后，外层才能安全关闭底层连接
	writerDone chan struct{}

	// inFlight 是本连接当前挂起的 Dispatch 转发数，供 handleRequest 强制
	// ConnectionLimits.max_inflight_requests（架构 10.11 已下发但此前从未强制）
	inFlight atomic.Int32
}

func newConn(s *Server, c net.Conn, caller identity.Caller, log *slog.Logger) *conn {
	return &conn{
		s:          s,
		c:          c,
		w:          bufio.NewWriter(c),
		log:        log,
		caller:     caller,
		phase:      phaseHandshake,
		negMajor:   protocolMajor,
		negMinor:   protocolMinorMax,
		outbox:     newOutboundQueue(maxOutboundQueueBytes),
		writerDone: make(chan struct{}),
	}
}

// runWriter 是本连接唯一真正调用 co.c.Write 的 goroutine：循环从 outbox 取出
// 待写的 Envelope 并序列化写出。写失败（socket 已坏）时关闭 outbox（挡住后续
// enqueue，让并发调用方立刻发现"这条连接已经废了"而不是无声堆积）与底层连接
// 后退出；outbox 被 close 且已排空时正常退出
//
// 生命周期由 serve() 用 s.wg 纳入 Kernel 停机的既有等待协议，具体收尾顺序见
// ipc.go 的 serve()
func (co *conn) runWriter() {
	defer co.s.wg.Done()
	defer close(co.writerDone)

	for {
		env, ok := co.outbox.pop()
		if !ok {
			return
		}
		if err := co.writeEnvelope(env); err != nil {
			co.log.Debug("ipc: writer failed, closing connection", "err", err)
			co.outbox.close()
			_ = co.c.Close()
			return
		}
	}
}

// enqueue 把 env 排进本连接的 outbound 队列，供 runWriter 异步写出。队列已满
// 或已关闭时不做任何静默丢弃——按慢消费者处理：关闭连接并限速审计，返回 false
// 告诉调用方"这条连接已经废了"（调用方可能是转发 Dispatch 的另一条连接的
// goroutine，也可能是本连接自己的帧泵）
func (co *conn) enqueue(env *ipcv1.Envelope) bool {
	if co.outbox.push(env) {
		return true
	}
	co.closeAsSlowConsumer()
	return false
}

// closeAsSlowConsumer 处理 outbound 队列已满/已关闭这类"这条连接跟不上"的
// 情形：关闭连接并限速审计。用独立 Action 与 ProtocolViolation/UnsupportedBody
// 区分——这是资源状况，不是攻击信号（同 auditUnsupported 复用 violationLog
// 令牌桶的理由：两者都以关闭连接收场）
func (co *conn) closeAsSlowConsumer() {
	co.outbox.close()
	_ = co.c.Close()
	if !co.s.violationLog.allow() {
		return
	}
	co.s.auditor.Record(context.Background(), audit.Event{
		Action:  "ipc.SlowConsumerDisconnect",
		Subject: co.caller.String(),
		Denied:  true,
	})
}

// readDeadline 给出当前阶段下等待下一帧的最长时间
//
// 握手窗口比稳态空闲窗口短得多：连上不说话（或说了不是 Hello）不该能长期占住
// 一个连接槽（架构 10.2）。握手完成后转入由 Ping/Pong 维持的空闲窗口
func (co *conn) readDeadline() time.Duration {
	if co.phase == phaseHandshake {
		return co.s.limits.HandshakeTimeout
	}
	return co.s.limits.IdleTimeout
}

// handle 处理一个已良构的 Envelope，返回是否继续读取本连接。
// 返回 false 表示应关闭连接；关闭前的审计与日志由 handle 内部完成
func (co *conn) handle(env *ipcv1.Envelope) bool {
	if co.phase == phaseHandshake {
		return co.handleHandshake(env)
	}
	return co.handleReady(env)
}

// handleHandshake 执行 Hello/HelloAck 握手（架构 10.2）
func (co *conn) handleHandshake(env *ipcv1.Envelope) bool {
	hello := env.GetHello()
	if hello == nil {
		// 架构 10.2：第一帧必须是 Hello。架构 10.11：非法握手状态按协议违规关闭。
		// 这里不发 HelloAck——对端根本没走握手流程，回一个握手结果没有意义
		co.log.Warn("ipc: first frame is not Hello, closing", "body", bodyName(env))
		co.s.auditViolation(co.caller, errHandshakeExpectedHello)
		return false
	}

	major, minor, ok := negotiateVersion(hello, protocolMajor, protocolMinorMax)
	if !ok {
		// 架构 10.2：版本谈不拢时【先发 Failure HelloAck 再关闭】，不要裸关。
		// 裸关会让客户端无法区分「版本不兼容」和「socket 坏了」，而这两者的
		// 正确反应相反——前者不该无脑重连，后者该
		co.log.Warn("ipc: protocol version negotiation failed",
			"client_min_major", hello.GetMinProtocolMajor(),
			"client_max_major", hello.GetMaxProtocolMajor(),
			"client_max_minor", hello.GetMaxProtocolMinor(),
			"server_major", protocolMajor, "server_minor_max", protocolMinorMax)
		co.sendHelloFailure(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION)
		return false
	}

	// 架构 10.2：验证声明，而不是相信声明。客户端在 declared_component_id 里自报的
	// Component 只是待验证线索，必须用对端 cgroup→unit→Component 与内核事实核对，
	// 【核对通过才完成握手】（应用层架构决策 §5.5）。co.c 底层一定是 *net.UnixConn
	// （accept 自 UDS listener），用于 SO_PEERPIDFD
	uc, _ := co.c.(*net.UnixConn)
	componentID, err := co.s.verifyComponent(uc, co.caller, hello.GetDeclaredComponentId())
	if err != nil {
		// 两类失败都回 UNAUTHENTICATED 关闭，但审计区分：
		//   - errComponentMismatch（核对到不一致）：潜在伪装，审计为违规
		//   - 其它（能力缺口：Components 未接线 / 对端不在受管 cgroup / 内核太旧）：
		//     不审计为违规，避免把能力缺口刷成安全告警
		if errors.Is(err, errComponentMismatch) {
			co.log.Warn("ipc: component impersonation suspected, rejecting handshake",
				"declared", hello.GetDeclaredComponentId(), "err", err)
			co.s.auditViolation(co.caller, err)
		} else {
			co.log.Warn("ipc: component not verifiable, rejecting handshake",
				"declared", hello.GetDeclaredComponentId(), "err", err)
		}
		co.sendHelloFailure(ipcv1.StatusCode_STATUS_CODE_UNAUTHENTICATED)
		return false
	}

	co.caller.ComponentID = componentID
	co.negMajor, co.negMinor = major, minor

	// HelloAck 成功：回填核对后的 package_id/component_id（架构 10.2：这不是授予
	// 身份，身份早在 SO_PEERCRED 时就定了，回显只是让 SDK 能尽早发现配置错位），
	// 并下发本连接生效的 ConnectionLimits（架构 10.11 的 wire 投影）
	ack := &ipcv1.Envelope{Body: &ipcv1.Envelope_HelloAck{HelloAck: &ipcv1.HelloAck{
		Outcome: &ipcv1.HelloAck_Success{Success: &ipcv1.HelloAckSuccess{
			ProtocolMajor: major,
			ProtocolMinor: minor,
			PackageId:     co.caller.PackageID,
			ComponentId:   componentID,
			Limits:        co.s.connectionLimits(),
		}},
	}}}
	if !co.enqueue(ack) {
		// 队列已满/连接已废：没什么可审计的（enqueue 失败时该记的审计已经记过），
		// 正常收尾
		co.log.Debug("ipc: enqueue HelloAck failed, closing")
		return false
	}

	co.phase = phaseReady
	co.log.Debug("ipc: handshake complete", "major", major, "minor", minor)
	return true
}

// handleReady 在握手完成后按 body 分派（架构 10.7）
//
// 分派先看方向，再看是否实现——方向错的直接是违规，方向对但没实现的是能力缺口：
//   - Ping→Pong、Pong 接受忽略、Request→Route→Dispatch 转发（handleRequest）、
//     DispatchResult→查表匹配（handleDispatchResult）均已打通
//   - nervud→对端方向的 body（响应/推送/派发给 Service 的 Dispatch）被对端发来 →
//     协议违规，关闭并审计
//   - 对端→nervud 方向合法、但本 build 未实现的 body → 关闭并审计为 UnsupportedBody
//
// 三条都【不静默丢】。方向依据见架构 10.4 的字段表与各消息在 schema 里的方向注释
func (co *conn) handleReady(env *ipcv1.Envelope) bool {
	switch body := env.GetBody().(type) {
	case *ipcv1.Envelope_Ping:
		// 保活：任一侧都可发起 Ping，服务端回 Pong（架构 10.4）
		return co.handlePing(body.Ping)

	case *ipcv1.Envelope_Pong:
		// 保活回复。协议允许任一侧发起 Ping，故 nervud 也是合法的 Pong 接收方。
		// nervud 目前尚不主动 Ping，收到的 Pong 都属未预期；但 Pong 不承载请求、
		// 也不要求回复，取「接受并忽略」而非按违规关闭——它不是「只应由服务端发出
		// 的 body」。等 nervud 发起 Ping 并记录 nonce 后，可收紧为「未匹配即违规」
		co.log.Debug("ipc: unsolicited Pong ignored")
		return true

	case *ipcv1.Envelope_Request:
		return co.handleRequest(body.Request)

	case *ipcv1.Envelope_DispatchResult:
		return co.handleDispatchResult(body.DispatchResult)

	case *ipcv1.Envelope_ResolveEndpoint:
		return co.handleResolveEndpoint(env, body.ResolveEndpoint)

	case *ipcv1.Envelope_RegisterEndpoint:
		return co.handleRegisterEndpoint(env, body.RegisterEndpoint)

	case *ipcv1.Envelope_UnregisterEndpoint:
		return co.handleUnregisterEndpoint(env, body.UnregisterEndpoint)

	case *ipcv1.Envelope_Hello:
		// 握手已完成，再来一个 Hello 是非法握手状态（架构 10.11）
		co.log.Warn("ipc: duplicate Hello after handshake, closing")
		co.s.auditViolation(co.caller, errDuplicateHello)
		return false

	case *ipcv1.Envelope_HelloAck,
		*ipcv1.Envelope_Response,
		*ipcv1.Envelope_ResolveEndpointResult,
		*ipcv1.Envelope_RegisterEndpointResult,
		*ipcv1.Envelope_UnregisterEndpointResult,
		*ipcv1.Envelope_SubscribeResult,
		*ipcv1.Envelope_UnsubscribeResult,
		*ipcv1.Envelope_Event,
		*ipcv1.Envelope_SubscriptionClosed,
		*ipcv1.Envelope_EndpointDied,
		*ipcv1.Envelope_EndpointRevoked,
		*ipcv1.Envelope_Dispatch,
		*ipcv1.Envelope_CancelDispatch:
		// 全是 nervud→对端方向的 body：响应（HelloAck/*Result/Response）、推送
		// （Event/EndpointDied/EndpointRevoked/SubscriptionClosed）、以及 nervud 派发
		// 给 Service 的 Dispatch/CancelDispatch（§10.7：只能由 nervud 发给 Service）。
		// nervud 永远不【接收】它们，收到即协议违规
		co.log.Warn("ipc: server-originated body received from peer, closing", "body", bodyName(env))
		co.s.auditViolation(co.caller, errUnexpectedBody)
		return false

	case *ipcv1.Envelope_Cancel,
		*ipcv1.Envelope_Subscribe,
		*ipcv1.Envelope_Unsubscribe:
		// 对端→nervud 方向合法、但本 build 未实现的 body。Cancel/Subscribe/
		// Unsubscribe 来自 App/Service，各自需要专属回复或路由，凭空造回复违反
		// 架构 10.4/10.7，故关闭并审计为 UnsupportedBody——与协议违规分开，既不
		// 污染安全信号，也不把未来的 ServiceHost 接入误判成攻击。
		// ResolveEndpoint/RegisterEndpoint/UnregisterEndpoint 已随 internal/endpoint
		// 落地迁出本组；DispatchResult 已随本文件的 route 表落地迁出本组（见
		// handleDispatchResult）。各自的 handler 随对应模块（subscription）落地后
		// 迁出
		return co.unsupported(env)

	default:
		// parseEnvelope 已挡掉未知 body（proto3 把不认识的 oneof 分支收进 unknown
		// fields，Body 保持 nil）。走到这里说明 schema 新增了一个本 switch 未覆盖的
		// 已知 body——fail closed 当作未实现处理，而不是静默放行
		return co.unsupported(env)
	}
}

// handlePing 回 Pong，原样回带 nonce（架构 10.4 的保活）
func (co *conn) handlePing(ping *ipcv1.Ping) bool {
	pong := &ipcv1.Envelope{Body: &ipcv1.Envelope_Pong{Pong: &ipcv1.Pong{Nonce: ping.GetNonce()}}}
	return co.enqueue(pong)
}

// handleResolveEndpoint 转发给 internal/endpoint（co.s.endpoints 为 nil 时降级
// 为 unsupported()，见 ipc.Config.Endpoints 的文档）
func (co *conn) handleResolveEndpoint(env *ipcv1.Envelope, req *ipcv1.ResolveEndpoint) bool {
	if co.s.endpoints == nil {
		return co.unsupported(env)
	}
	result := co.s.endpoints.ResolveEndpoint(co, co.caller, req)
	return co.writeResultEnvelope(&ipcv1.Envelope{
		Body: &ipcv1.Envelope_ResolveEndpointResult{ResolveEndpointResult: result},
	})
}

// handleRegisterEndpoint 转发给 internal/endpoint（同上的 nil 降级）
func (co *conn) handleRegisterEndpoint(env *ipcv1.Envelope, req *ipcv1.RegisterEndpoint) bool {
	if co.s.endpoints == nil {
		return co.unsupported(env)
	}
	result := co.s.endpoints.RegisterEndpoint(co, co.caller, req)
	return co.writeResultEnvelope(&ipcv1.Envelope{
		Body: &ipcv1.Envelope_RegisterEndpointResult{RegisterEndpointResult: result},
	})
}

// handleUnregisterEndpoint 转发给 internal/endpoint（同上的 nil 降级）
func (co *conn) handleUnregisterEndpoint(env *ipcv1.Envelope, req *ipcv1.UnregisterEndpoint) bool {
	if co.s.endpoints == nil {
		return co.unsupported(env)
	}
	result := co.s.endpoints.UnregisterEndpoint(co, req)
	return co.writeResultEnvelope(&ipcv1.Envelope{
		Body: &ipcv1.Envelope_UnregisterEndpointResult{UnregisterEndpointResult: result},
	})
}

// writeResultEnvelope 把一个响应/结果类 Envelope 排进 outbox，队列已满/已关闭
// 即关闭连接（enqueue 内部处理）
func (co *conn) writeResultEnvelope(env *ipcv1.Envelope) bool {
	return co.enqueue(env)
}

// handleRequest 处理一个 Request（架构 10.7 的请求管线：Route → Dispatch）
//
// co.s.endpoints 为 nil 时维持既有降级行为：校验 request_id 后恒回 UNAVAILABLE，
// 不静默丢也不裸关连接。非 nil 时，先经 Route() 查表（内部真正调用
// permission.Allowed），成功后把 Request 转成 Dispatch 排进目标 Service 连接的
// outbox、在 route 表登记相关状态，然后【返回 true】——本函数不再原地生成终结
// Response，真正的 Response 由 handleDispatchResult / 超时清道夫 / 目标连接
// 断开三者之一在未来某个时刻通过本连接的 outbox 送达（dispatch.go）
func (co *conn) handleRequest(req *ipcv1.Request) bool {
	// request_id 0 永久保留（架构 10.6：合法请求从 1 起）。在生成任何 Response 之前
	// 按协议违规关闭——回一个 request_id=0 的 Response 等于承认了一个不该存在的
	// 关联键，SDK 侧也永远不会为 0 登记 pending
	if req.GetRequestId() == 0 {
		co.log.Warn("ipc: Request with reserved request_id 0, closing")
		co.s.auditViolation(co.caller, errZeroRequestID)
		return false
	}

	if co.s.endpoints == nil {
		// 降级路径不变：Endpoints 未接线时恒 UNAVAILABLE，不静默丢也不裸关连接
		return co.enqueue(responseEnvelope(failureResponse(
			req.GetRequestId(), ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE)))
	}

	route, rerr := co.s.endpoints.Route(co, req.GetEndpointId())
	if rerr.Code != ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		return co.enqueue(responseEnvelope(failureResponse(req.GetRequestId(), rerr.Code)))
	}

	target, ok := route.TargetConn.(*conn)
	if !ok || target == nil {
		// Route 报告成功，但没有可转发的真实连接（装配缺口，或测试替身故意
		// 留空）。没有变通方案，按不可用处理，而不是假装转发成功
		return co.enqueue(responseEnvelope(failureResponse(
			req.GetRequestId(), ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE)))
	}

	// 准入：本连接自己的 in-flight 预算（架构 10.11 的 ConnectionLimits.
	// max_inflight_requests 此前只下发给客户端参考，从未被服务端强制）
	if co.inFlight.Add(1) > maxInflightRequests {
		co.inFlight.Add(-1)
		return co.enqueue(responseEnvelope(failureResponse(
			req.GetRequestId(), ipcv1.StatusCode_STATUS_CODE_RESOURCE_EXHAUSTED)))
	}

	deadline := time.Now().Add(clampTimeout(req.GetTimeoutMs()))
	remaining := time.Until(deadline)
	if remaining <= 0 {
		co.inFlight.Add(-1)
		return co.enqueue(responseEnvelope(failureResponse(
			req.GetRequestId(), ipcv1.StatusCode_STATUS_CODE_DEADLINE_EXCEEDED)))
	}

	routeID := co.s.dispatch.create(co, req.GetRequestId(), target, deadline)
	dispatch := &ipcv1.Envelope{Body: &ipcv1.Envelope_Dispatch{Dispatch: &ipcv1.Dispatch{
		RouteId:     routeID,
		EndpointId:  route.ServiceEndpointID,
		MethodId:    req.GetMethodId(),
		RemainingMs: uint32(remaining.Milliseconds()),
		Payload:     req.GetPayload(),
		Caller:      callerContext(co.caller),
	}}}

	if !target.enqueue(dispatch) {
		// 目标连接已经废了（已关闭/刚被判定为慢消费者）：不等 ConnClosed 的
		// 时序，当场完成这条 route，避免白等一个不会再回应的 Response
		if e, ok := co.s.dispatch.completeAny(routeID); ok {
			return resolveRoute(e, failureResponse(e.sourceRequestID, ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE))
		}
		return true // 理论上不会发生：routeID 刚创建，唯一删除者只能是上面这行
	}

	return true
}

// handleDispatchResult 处理 Service 送回的 DispatchResult（架构 10.7）：查表
// 匹配才生成对应调用者的终结 Response。未知/已完成的 route_id 是预期内的良性
// 竞态（清道夫或另一次结果已经抢先完成，或断开清理已经摘掉），丢弃但保持连接
// 存活；目标错位（route_id 存在但送回结果的连接并非登记的目标连接）没有合法
// 解释——按协议违规关闭
func (co *conn) handleDispatchResult(dr *ipcv1.DispatchResult) bool {
	e, status := co.s.dispatch.complete(dr.GetRouteId(), co)
	switch status {
	case completeMismatch:
		co.log.Warn("ipc: DispatchResult route_id targets a different connection, closing",
			"route_id", dr.GetRouteId())
		co.s.auditViolation(co.caller, errDispatchResultMismatch)
		return false
	case completeNotFound:
		co.s.auditDispatchRace(co.caller.String(), dr.GetRouteId())
		return true
	}

	resp, ok := dispatchResultToResponse(e.sourceRequestID, dr)
	if !ok {
		// 畸形 outcome（既非 Success 也非 Failure、或取值域非法）：违反 Provider
		// Contract。对调用者归一化为 INTERNAL（dispatchResultToResponse 已经
		// 构造好），完整原因只进审计
		co.s.auditor.Record(context.Background(), audit.Event{
			Action:  "ipc.MalformedDispatchResult",
			Subject: co.caller.String(),
			Denied:  true,
		})
	}
	return resolveRoute(e, resp)
}

// clampTimeout 是架构 10.6/10.7 收紧规则的 v1 落地：0 表示方法默认值（而非
// 无限），结果被夹进 [1ms, maxMethodTimeoutMs]。真正的按方法配置留给未来的
// Method Registry（B2 范畴），这里用两个已经存在的全局常量代替
func clampTimeout(ms uint32) time.Duration {
	if ms == 0 {
		ms = defaultMethodTimeoutMs
	}
	if ms > maxMethodTimeoutMs {
		ms = maxMethodTimeoutMs
	}
	return time.Duration(ms) * time.Millisecond
}

// callerContext 把内核已经核实过的 identity.Caller 投影成可以外传给 Service 的
// CallerContext（架构 10.2：Service 可以读，但不能据此绕过 nervud 已经生效的
// Policy，更不能自行创造身份或权限裁决）。GrantedPermissions 留空：
// internal/permission.Registry 目前只有 Allowed(pkg, perm) 点查询，没有"列出
// 某包全部已授权限"的方法，本次不为这个纯防御性参考字段新增该能力（见计划的
// 范围排除）
func callerContext(c identity.Caller) *ipcv1.CallerContext {
	return &ipcv1.CallerContext{
		PackageId:    c.PackageID,
		ComponentId:  c.ComponentID,
		Uid:          c.UID,
		Gid:          c.GID,
		Pid:          c.PID,
		TrustProfile: trustProfileWire(c.Trust),
	}
}

// trustProfileWire 把 identity.TrustProfile 显式映射到 ipcv1.TrustProfile。
// 两者取值目前恰好一一对应，但用显式 switch 而不是裸类型转换——两个包各自的
// 枚举独立演进，裸转换会在其中一个新增/重排取值时悄悄产生错误映射而不报错
func trustProfileWire(t identity.TrustProfile) ipcv1.TrustProfile {
	switch t {
	case identity.TrustOrdinary:
		return ipcv1.TrustProfile_TRUST_PROFILE_ORDINARY
	case identity.TrustOEM:
		return ipcv1.TrustProfile_TRUST_PROFILE_OEM
	case identity.TrustPlatform:
		return ipcv1.TrustProfile_TRUST_PROFILE_PLATFORM
	default:
		return ipcv1.TrustProfile_TRUST_PROFILE_UNSPECIFIED
	}
}

// dispatchResultToResponse 把 DispatchResult 的 outcome 转成对调用者的
// Response（架构 10.7）：只转发类型安全的 Code，绝不透传 Service 的
// ErrorDetail/PublicMessage（没有权威 method schema 可供解码校验，见计划的
// 范围排除）。outcome 缺失、二选一都未设置、或 code 落在该分支不允许的取值域
// （Success 要求 code ∈ {OK, ACCEPTED}，Failure 要求 code ∉ {UNSPECIFIED, OK,
// ACCEPTED}，均为 status.proto 自带的不变量），一律归一化为 INTERNAL；第二个
// 返回值为 false 时调用方负责记完整原因的审计
func dispatchResultToResponse(reqID uint64, dr *ipcv1.DispatchResult) (*ipcv1.Response, bool) {
	if s := dr.GetSuccess(); s != nil {
		switch s.GetCode() {
		case ipcv1.StatusCode_STATUS_CODE_OK, ipcv1.StatusCode_STATUS_CODE_ACCEPTED:
			return &ipcv1.Response{RequestId: reqID, Outcome: &ipcv1.Response_Success{
				Success: &ipcv1.Success{Code: s.GetCode(), Payload: s.GetPayload()},
			}}, true
		}
		return internalResponse(reqID), false
	}
	if f := dr.GetFailure(); f != nil {
		switch f.GetCode() {
		case ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED,
			ipcv1.StatusCode_STATUS_CODE_OK,
			ipcv1.StatusCode_STATUS_CODE_ACCEPTED:
			return internalResponse(reqID), false
		default:
			return &ipcv1.Response{RequestId: reqID, Outcome: &ipcv1.Response_Failure{
				Failure: &ipcv1.Failure{Code: f.GetCode()},
			}}, true
		}
	}
	return internalResponse(reqID), false
}

func internalResponse(reqID uint64) *ipcv1.Response {
	return failureResponse(reqID, ipcv1.StatusCode_STATUS_CODE_INTERNAL)
}

// failureResponse/responseEnvelope 是构造终结 Response 的两个共用小工具，
// 避免每个失败分支各自重复 outcome 装配的样板代码
func failureResponse(reqID uint64, code ipcv1.StatusCode) *ipcv1.Response {
	return &ipcv1.Response{RequestId: reqID, Outcome: &ipcv1.Response_Failure{
		Failure: &ipcv1.Failure{Code: code},
	}}
}

func responseEnvelope(resp *ipcv1.Response) *ipcv1.Envelope {
	return &ipcv1.Envelope{Body: &ipcv1.Envelope_Response{Response: resp}}
}

// unsupported 关闭连接并审计为 UnsupportedBody
func (co *conn) unsupported(env *ipcv1.Envelope) bool {
	co.log.Warn("ipc: unsupported body in this build, closing", "body", bodyName(env))
	co.s.auditUnsupported(co.caller, errUnsupportedBody)
	return false
}

// sendHelloFailure 发出一个带 Failure 的 HelloAck（不关闭连接，关闭由调用方决定）
func (co *conn) sendHelloFailure(code ipcv1.StatusCode) {
	fail := &ipcv1.Envelope{Body: &ipcv1.Envelope_HelloAck{HelloAck: &ipcv1.HelloAck{
		Outcome: &ipcv1.HelloAck_Failure{Failure: &ipcv1.Failure{Code: code}},
	}}}
	// 调用方（handleHandshake）无论 enqueue 是否成功都会紧接着返回 false 关闭
	// 连接，这里不需要额外处理返回值
	co.enqueue(fail)
}

// writeEnvelope 序列化并写出一个 Envelope，带写出 deadline
//
// 出站 Envelope 一律标注本连接协商到的协议版本。写出经由 conn 自己的缓冲 writer，
// 让「长度 + 正文」合并成一次 syscall（frame.go 的建议）
func (co *conn) writeEnvelope(env *ipcv1.Envelope) error {
	env.ProtocolMajor = co.negMajor
	env.ProtocolMinor = co.negMinor

	b, err := proto.Marshal(env)
	if err != nil {
		// 本端构造出不可序列化的 Envelope 属于 nervud bug，不外发
		return fmt.Errorf("ipc: marshal outbound envelope: %w", err)
	}

	// 架构 10.11：写出必须有有限 deadline，否则一个迟迟不读取的慢消费者能把
	// 帧泵 goroutine 永久挂在 Write 上。控制帧都很小，复用 FrameBodyTimeout
	// 作为写窗口——语义一致：一段已宣告长度的字节必须很快落地
	if err := co.c.SetWriteDeadline(time.Now().Add(co.s.limits.FrameBodyTimeout)); err != nil {
		return err
	}
	if err := WriteFrame(co.w, b); err != nil {
		return err
	}
	return co.w.Flush()
}

// negotiateVersion 在服务端支持的版本 (srvMajor, 该 major 下 minor 上限 srvMinorMax)
// 与客户端 Hello 声明的范围间求交集，选出即刻生效的 (major, minor)。无交集返回
// ok=false（架构 10.2、10.12）
//
// 取 srvMajor/srvMinorMax 为参数而非直接读常量，是为了把「越界」这条逻辑单测到位
func negotiateVersion(h *ipcv1.Hello, srvMajor, srvMinorMax uint32) (major, minor uint32, ok bool) {
	// 服务端只实现 srvMajor 这一个 major，它必须落在客户端闭区间
	// [min_protocol_major, max_protocol_major] 内，否则无从协商。范围本身颠倒
	// （max < min）时该判断自然不成立，一并落到「无交集」
	if h.GetMinProtocolMajor() > srvMajor || h.GetMaxProtocolMajor() < srvMajor {
		return 0, 0, false
	}
	major = srvMajor

	if h.GetMaxProtocolMajor() == srvMajor {
		// 选定的 major 恰是客户端的最高 major：Hello 的 max_protocol_minor 就是
		// 客户端对本 major 的 minor 上限，取它与服务端上限的较小值
		minor = srvMinorMax
		if cm := h.GetMaxProtocolMinor(); cm < minor {
			minor = cm
		}
		return major, minor, true
	}

	// 选定的 major 低于客户端最高 major：Hello 只为最高 major 声明了 minor，对更低
	// 的 major 没有任何 minor 信息。minor 0 是任一实现对某个 major 的保证下限，因此
	// 只能给 0——不能假设「客户端支持更高 major」就等于「它支持我们这个 major 的更高
	// minor」，那会在服务端 minor 抬高后选出客户端从未声明支持的版本
	return major, 0, true
}

// bodyName 返回 Envelope body 的具体类型名，仅用于诊断日志
func bodyName(env *ipcv1.Envelope) string {
	return fmt.Sprintf("%T", env.GetBody())
}
