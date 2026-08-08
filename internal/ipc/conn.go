// 本文件是连接内的 Envelope 状态机: 第一帧 Hello/HelloAck 握手,
// 之后按 body 分派. 分帧见 frame.go, 帧 -> Envelope 的良构校验见 envelope.go,
// 连接的准入与帧泵见 ipc.go
//
// 写回契约: 每条连接自持一个有界 outbound 队列 (outbox.go) + 一个
// 独立的 writer goroutine (runWriter), 它是唯一真正调用 co.c.Write 的地方,
// 满足 frame.go 的每条连接只有一个 writer约束. 帧泵/handleRequest 等任何
// goroutine 都只通过 enqueue 把 Envelope 排队, 从不直接碰 socket - 这也是
// Dispatch 转发 (route.go/dispatch.go) 得以安全把 Envelope 写进另一条
// 连接的原因: 目标连接自己的 writer 才是那次写的实际执行者
package ipc

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/control"
	"github.com/nervus-os/nervud/internal/endpoint"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/operation"
	"github.com/nervus-os/nervud/internal/pkgregistry"
	"github.com/nervus-os/nervud/internal/protocheck"
)

// nervud 实现的控制面协议版本
//
// nervud 只实现这一个 major; minor 只增不减, 握手时在客户端声明的范围内取交集.
// 重大不兼容提升 major 并拒绝无法协商的连接
const (
	// protocolMajor = 2: v2 不向下兼容 v1.
	//
	// 断 wire 的是两条隐式默认的移除: ResolveEndpoint 与 AcquireControl 的空
	// selector 不再隐式指向 {nervus.resource.motion.base, main}. 一个 v1 客户端
	// 留空 selector 去申请底盘租约, 在 v2 上会拿到"解析不到"而不是底盘 -
	// 那种静默的语义变化比拒绝连接危险得多, 所以必须靠 major 拒掉.
	protocolMajor    = 2
	protocolMinorMax = 0
)

// 握手/分派阶段发现的, 需要关闭连接的情形. 分成两类哨兵是为了让离线审计规则
// 能把协议违规 / 潜在攻击与本 build 尚未实现的能力缺口区分开 - 混进
// 一个 Action 里, 真正的攻击迹象会被未实现路径的噪音淹没
var (
	// errHandshakeExpectedHello: 握手前收到了非 Hello 的 body (第一帧
	// 必须是 Hello). 属于非法握手状态, 按协议违规关闭
	errHandshakeExpectedHello = errors.New("ipc: first frame must be Hello")

	// errDuplicateHello: 握手已完成后又收到 Hello. 同样是非法握手状态
	errDuplicateHello = errors.New("ipc: Hello received after handshake completed")

	// errUnexpectedBody: 客户端发来了只应由服务端产生的响应/推送 body
	//  (Response, Event, *Result 等). 协议违规
	errUnexpectedBody = errors.New("ipc: server-originated body not valid inbound from client")

	// errUnsupportedBody: 客户端合法发出, 但本 build 尚未实现的控制/调用 body.
	// 不是违规, 是能力缺口
	errUnsupportedBody = errors.New("ipc: body not implemented in this build")

	// errZeroRequestID: 带关联 ID 的请求使用了保留值 0.
	// 协议明确要求 Request, AcquireControl 和 LaunchComponent 从 1 起.
	errZeroRequestID = errors.New("ipc: request uses reserved request_id 0")

	// errDispatchResultMismatch: DispatchResult 携带的 route_id 存在, 但送回
	// 结果的连接不是登记的目标连接. 没有合法解释 - 没有 Service 会被告知一个
	// 指向别的连接的 route_id, 因此这不是能力缺口, 是潜在伪装
	errDispatchResultMismatch = errors.New("ipc: DispatchResult route_id targets a different connection")
)

// phase 是连接状态机的阶段
type phase uint8

const (
	// phaseHandshake 等待第一帧 Hello. 此阶段只接受 Hello, 其它 body 一律按
	// 非法握手状态关闭
	phaseHandshake phase = iota
	// phaseReady 握手完成, 按 body 分派
	phaseReady
)

// conn 是一条已准入连接的 Envelope 状态机
//
// 它不拥有 socket 的生命周期 (那由 ipc.go 的 admit/release 管理), 只在帧泵每
// 解出一个 Envelope 时被调用一次
type conn struct {
	s   *Server
	c   net.Conn
	w   *bufio.Writer
	log *slog.Logger

	// caller 是连接建立时解析出的可信身份. 握手成功后 ComponentID 被回填
	//  (nervud 验证声明后确认的 Component, 而不是相信自报值)
	caller identity.Caller
	// componentType comes from service.Manager's verified unit mapping, never
	// from Hello. It gates Service-only protocol directions.
	componentType pkgregistry.ComponentType

	phase phase

	// negMajor/negMinor 标注出站 Envelope 的协议版本. 握手前用 nervud 支持的
	// 版本, 好让协商失败的 Failure HelloAck也能告诉客户端本端到底说哪个版本;
	// 握手成功后更新为选定版本
	negMajor uint32
	negMinor uint32

	// outbox 是本连接的有界 outbound 队列, runWriter 是唯一的消费者,
	// 避免多个 goroutine 并发写坏帧边界
	outbox *outboundQueue
	// writerDone 在 runWriter 退出时关闭, 供 serve 的收尾等待 - 必须等 writer
	// 真正停止碰 socket 之后, 外层才能安全关闭底层连接
	writerDone chan struct{}

	// requestMu guards the unified in-flight request tracker. Dispatch and
	// builtin calls both reserve one entry and their canonical payload bytes.
	requestMu    sync.Mutex
	requests     map[uint64]int
	requestBytes int64

	// connID 是本连接在 control 模块里的标识. control 的 ConnID 是 uint64,
	// 而 endpoint 那边用 ConnHandle(interface{}) 直接吃 *conn 指针 - 两套是因为
	// control 的租约表要能被 RevokeConn 按值查, 指针做键在跨模块传递时容易
	// 意外持有已释放的连接.
	connID control.ConnID

	// leaseMu 保护下面两张 lease 句柄映射表.
	//
	// 为什么要映射: wire 上的 lease_id 是 uint64, 而 control.ID 是 [16]byte.
	// 直接把内部 ID 截断成 uint64 会碰撞; 直接把 [16]byte 塞进 uint64 装不下.
	// 于是按连接分配单调递增的对外句柄, 内部 ID 不出进程 - 与 endpoint_id
	// 同一原则: 查找键是 (连接, 句柄), 别处的相同数字不是同一个东西.
	leaseMu   sync.Mutex
	nextLease uint64
	leases    map[uint64]control.ID
	// leaseHandles preserves the wire handle across an idempotent renewal.
	// control returns the same internal ID for that case, and the protocol
	// requires lease_id to remain stable until the lease ends.
	leaseHandles map[control.ID]uint64
}

func newConn(s *Server, c net.Conn, caller identity.Caller, log *slog.Logger) *conn {
	return &conn{
		s:            s,
		c:            c,
		w:            bufio.NewWriter(c),
		log:          log,
		caller:       caller,
		phase:        phaseHandshake,
		negMajor:     protocolMajor,
		negMinor:     protocolMinorMax,
		outbox:       newOutboundQueue(maxOutboundQueueBytes),
		writerDone:   make(chan struct{}),
		connID:       control.ConnID(s.nextConnID.Add(1)),
		leases:       make(map[uint64]control.ID),
		leaseHandles: make(map[control.ID]uint64),
		requests:     make(map[uint64]int),
	}
}

func (co *conn) reserveRequest(requestID uint64, payloadBytes int) ipcv1.StatusCode {
	co.requestMu.Lock()
	defer co.requestMu.Unlock()
	if _, exists := co.requests[requestID]; exists {
		return ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT
	}
	if len(co.requests) >= maxInflightRequests ||
		co.requestBytes+int64(payloadBytes) > maxInflightPayloadBytes {
		return ipcv1.StatusCode_STATUS_CODE_RESOURCE_EXHAUSTED
	}
	co.requests[requestID] = payloadBytes
	co.requestBytes += int64(payloadBytes)
	return ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED
}

func (co *conn) releaseRequest(requestID uint64) {
	co.requestMu.Lock()
	if payloadBytes, ok := co.requests[requestID]; ok {
		delete(co.requests, requestID)
		co.requestBytes -= int64(payloadBytes)
	}
	co.requestMu.Unlock()
}

// leaseConnID 返回本连接在 control 模块里的标识.
func (co *conn) leaseConnID() control.ConnID { return co.connID }

// registerLease 给一个刚签发的租约分配本连接作用域的对外句柄. 同一内部租约的
// 幂等续期复用原句柄; 不同租约即使生命周期不重叠也绝不复用旧数字.
func (co *conn) registerLease(l control.Lease) uint64 {
	co.leaseMu.Lock()
	defer co.leaseMu.Unlock()
	if handle, ok := co.leaseHandles[l.ID]; ok {
		return handle
	}
	if co.leases == nil {
		co.leases = make(map[uint64]control.ID)
	}
	if co.leaseHandles == nil {
		co.leaseHandles = make(map[control.ID]uint64)
	}
	co.nextLease++
	co.leases[co.nextLease] = l.ID
	co.leaseHandles[l.ID] = co.nextLease
	return co.nextLease
}

// lookupLease 把对外句柄翻回内部 control.ID.
func (co *conn) lookupLease(handle uint64) (control.ID, bool) {
	co.leaseMu.Lock()
	defer co.leaseMu.Unlock()
	id, ok := co.leases[handle]
	return id, ok
}

// wireLeaseHandle returns the connection-scoped wire handle for an internal
// lease proof. A valid control lease without a registered handle is not safe to
// dispatch: the Provider must see the same lease_id the caller received.
func (co *conn) wireLeaseHandle(id control.ID) (uint64, bool) {
	co.leaseMu.Lock()
	defer co.leaseMu.Unlock()
	handle, ok := co.leaseHandles[id]
	return handle, ok && handle != 0
}

// forgetLease 注销一个已释放的句柄.
//
// 句柄不复用: 同一连接上的下一个租约拿新号. 复用会让一条迟到的
// ReleaseControl 释放掉一个刚签发的新租约 - 两者的 lease_id 相同, 连接也相同,
// 接收方没有任何办法分辨. 与 request_id 不回绕是同一条理由.
func (co *conn) forgetLease(handle uint64) {
	co.leaseMu.Lock()
	co.forgetLeaseHandleLocked(handle)
	co.leaseMu.Unlock()
}

// forgetLeaseID removes only the wire handle derived from the exact internal
// lease that ended. Terminal notifications can arrive after timeout,
// preemption, Safety revocation, or permission changes; deleting by resource
// would risk removing a newer lease for the same connection and resource.
func (co *conn) forgetLeaseID(id control.ID) {
	co.leaseMu.Lock()
	if handle, ok := co.leaseHandles[id]; ok {
		co.forgetLeaseHandleLocked(handle)
	}
	co.leaseMu.Unlock()
}

func (co *conn) forgetLeaseHandleLocked(handle uint64) {
	if id, ok := co.leases[handle]; ok && co.leaseHandles[id] == handle {
		delete(co.leaseHandles, id)
	}
	delete(co.leases, handle)
}

// runWriter 是本连接唯一真正调用 co.c.Write 的 goroutine: 循环从 outbox 取出
// 待写的 Envelope 并序列化写出. 写失败 (socket 已坏) 时关闭 outbox (挡住后续
// enqueue, 让并发调用方立刻发现"这条连接已经废了"而不是无声堆积) 与底层连接
// 后退出; outbox 被 close 且已排空时正常退出
//
// 生命周期由 serve 用 s.wg 纳入 Kernel 停机的既有等待协议, 具体收尾顺序见
// ipc.go 的 serve
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

// enqueue 把 env 排进本连接的 outbound 队列, 供 runWriter 异步写出. 队列已满
// 或已关闭时不做任何静默丢弃 - 按慢消费者处理: 关闭连接并限速审计, 返回 false
// 告诉调用方"这条连接已经废了" (调用方可能是转发 Dispatch 的另一条连接的
// goroutine, 也可能是本连接自己的帧泵)
func (co *conn) enqueue(env *ipcv1.Envelope) bool {
	if co.outbox.push(env) {
		return true
	}
	co.closeAsSlowConsumer()
	return false
}

// Deliver 实现 subscription.Sink: 尝试排队一条 Event, 队列满时不关闭连接.
//
// 与 enqueue 的区别是刻意的. enqueue 用于请求-响应链路: 那里投递不下意味着
// 对端连自己要的东西都收不动, 关掉是对的. 订阅不同 - 一条订阅跟不上不代表
// 整条连接废了, 同一个订阅方可能还有别的, 消费得动的订阅.
//
// 因此这里只报告成败, 由 subscription.Registry 按 delivery_class 决定
// 合并, 丢弃还是只关掉这一条订阅.
func (co *conn) Deliver(env *ipcv1.Envelope) bool {
	return co.outbox.push(env)
}

// closeAsSlowConsumer 处理 outbound 队列已满/已关闭这类"这条连接跟不上"的
// 情形: 关闭连接并限速审计. 用独立 Action 与 ProtocolViolation/UnsupportedBody
// 区分 - 这是资源状况, 不是攻击信号 (同 auditUnsupported 复用 violationLog
// 令牌桶的理由: 两者都以关闭连接收场)
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
// 握手窗口比稳态空闲窗口短得多: 连上不说话 (或说了不是 Hello) 不该能长期占住
// 一个连接槽. 握手完成后转入由 Ping/Pong 维持的空闲窗口
func (co *conn) readDeadline() time.Duration {
	if co.phase == phaseHandshake {
		return co.s.limits.HandshakeTimeout
	}
	return co.s.limits.IdleTimeout
}

// handle 处理一个已良构的 Envelope, 返回是否继续读取本连接.
// 返回 false 表示应关闭连接; 关闭前的审计与日志由 handle 内部完成
func (co *conn) handle(env *ipcv1.Envelope) bool {
	if co.phase == phaseHandshake {
		return co.handleHandshake(env)
	}
	return co.handleReady(env)
}

// handleHandshake 执行 Hello/HelloAck 握手
func (co *conn) handleHandshake(env *ipcv1.Envelope) bool {
	hello := env.GetHello()
	if hello == nil {
		// 第一帧必须是 Hello. 非法握手状态按协议违规关闭.
		// 这里不发 HelloAck - 对端根本没走握手流程, 回一个握手结果没有意义
		co.log.Warn("ipc: first frame is not Hello, closing", "body", bodyName(env))
		co.s.auditViolation(co.caller, errHandshakeExpectedHello)
		return false
	}

	major, minor, ok := negotiateVersion(hello, protocolMajor, protocolMinorMax)
	if !ok {
		// 版本谈不拢时先发 Failure HelloAck 再关闭, 不要裸关.
		// 裸关会让客户端无法区分版本不兼容和socket 坏了, 而这两者的
		// 正确反应相反 - 前者不该无脑重连, 后者该
		co.log.Warn("ipc: protocol version negotiation failed",
			"client_min_major", hello.GetMinProtocolMajor(),
			"client_max_major", hello.GetMaxProtocolMajor(),
			"client_max_minor", hello.GetMaxProtocolMinor(),
			"server_major", protocolMajor, "server_minor_max", protocolMinorMax)
		co.sendHelloFailure(ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION)
		return false
	}

	// 验证声明, 而不是相信声明. 客户端在 declared_component_id 里自报的
	// Component 只是待验证线索, 必须用对端 cgroup -> unit -> Component 与内核事实核对,
	// 核对通过才完成握手. co.c 底层一定是 *net.UnixConn
	//  (accept 自 UDS listener), 用于 SO_PEERPIDFD
	uc, _ := co.c.(*net.UnixConn)
	instance, err := co.s.verifyComponent(uc, co.caller, hello.GetDeclaredComponentId())
	if err != nil {
		// 两类失败都回 UNAUTHENTICATED 关闭, 但审计区分:
		//  - errComponentMismatch (核对到不一致): 潜在伪装, 审计为违规
		//  - 其它 (能力缺口: Components 未接线 / 对端不在受管 cgroup / 内核太旧):
		//  不审计为违规, 避免把能力缺口刷成安全告警
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

	co.caller.ComponentID = instance.ComponentID
	co.componentType = instance.Type
	co.negMajor, co.negMinor = major, minor

	// HelloAck 成功: 回填核对后的 package_id/component_id (这不是授予
	// 身份, 身份早在 SO_PEERCRED 时就定了, 回显只是让 SDK 能尽早发现配置错位),
	// 并下发本连接生效的 ConnectionLimits (的 wire 投影)
	ack := &ipcv1.Envelope{Body: &ipcv1.Envelope_HelloAck{HelloAck: &ipcv1.HelloAck{
		Outcome: &ipcv1.HelloAck_Success{Success: &ipcv1.HelloAckSuccess{
			ProtocolMajor: major,
			ProtocolMinor: minor,
			PackageId:     co.caller.PackageID,
			ComponentId:   instance.ComponentID,
			Limits:        co.s.connectionLimits(),
		}},
	}}}
	if !co.enqueue(ack) {
		// 队列已满/连接已废: 没什么可审计的 (enqueue 失败时该记的审计已经记过),
		// 正常收尾
		co.log.Debug("ipc: enqueue HelloAck failed, closing")
		return false
	}

	co.phase = phaseReady
	co.log.Debug("ipc: handshake complete", "major", major, "minor", minor)
	return true
}

// handleReady 在握手完成后按 body 分派
//
// 分派先看方向, 再看是否实现 - 方向错的直接是违规, 方向对但没实现的是能力缺口:
//   - Ping -> Pong, Pong 接受忽略, Request -> Route -> Dispatch 转发 (handleRequest),
//     DispatchResult -> 查表匹配 (handleDispatchResult) 均已打通
//   - nervud -> 对端方向的 body (响应/推送/派发给 Service 的 Dispatch) 被对端发来 ->
//     协议违规, 关闭并审计
//   - 对端 -> nervud 方向合法, 但本 build 未实现的 body -> 关闭并审计为 UnsupportedBody
//
// 三条都不静默丢, 避免协议违规被能力缺口掩盖
func (co *conn) handleReady(env *ipcv1.Envelope) bool {
	switch body := env.GetBody().(type) {
	case *ipcv1.Envelope_Ping:
		// 保活: 任一侧都可发起 Ping, 服务端回 Pong
		return co.handlePing(body.Ping)

	case *ipcv1.Envelope_Pong:
		// 保活回复. 协议允许任一侧发起 Ping, 故 nervud 也是合法的 Pong 接收方.
		// nervud 目前尚不主动 Ping, 收到的 Pong 都属未预期; 但 Pong 不承载请求,
		// 也不要求回复, 取接受并忽略而非按违规关闭 - 它不是只应由服务端发出
		// 的 body. 等 nervud 发起 Ping 并记录 nonce 后, 可收紧为未匹配即违规
		co.log.Debug("ipc: unsolicited Pong ignored")
		return true

	case *ipcv1.Envelope_Request:
		return co.handleRequest(body.Request)

	case *ipcv1.Envelope_DispatchResult:
		if co.componentType != pkgregistry.ComponentService {
			co.log.Warn("ipc: non-service sent DispatchResult, closing")
			co.s.auditViolation(co.caller, errUnexpectedBody)
			return false
		}
		return co.handleDispatchResult(body.DispatchResult)

	case *ipcv1.Envelope_ResolveEndpoint:
		return co.handleResolveEndpoint(env, body.ResolveEndpoint)

	case *ipcv1.Envelope_RegisterEndpoint:
		return co.handleRegisterEndpoint(env, body.RegisterEndpoint)

	case *ipcv1.Envelope_UnregisterEndpoint:
		return co.handleUnregisterEndpoint(env, body.UnregisterEndpoint)

	case *ipcv1.Envelope_AcquireControl:
		return co.handleAcquireControl(body.AcquireControl)

	case *ipcv1.Envelope_ReleaseControl:
		return co.handleReleaseControl(body.ReleaseControl)

	case *ipcv1.Envelope_LaunchComponent:
		return co.handleLaunchComponent(body.LaunchComponent)

	case *ipcv1.Envelope_Subscribe:
		return co.handleSubscribe(body.Subscribe)

	case *ipcv1.Envelope_Unsubscribe:
		return co.handleUnsubscribe(body.Unsubscribe)

	case *ipcv1.Envelope_BindEventScope:
		return co.handleBindEventScope(body.BindEventScope)

	case *ipcv1.Envelope_PublishEvent:
		return co.handlePublishEvent(body.PublishEvent)

	case *ipcv1.Envelope_Hello:
		// 握手已完成, 再来一个 Hello 是非法握手状态
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
		*ipcv1.Envelope_CancelDispatch,
		*ipcv1.Envelope_AcquireControlResult,
		*ipcv1.Envelope_LaunchComponentResult,
		*ipcv1.Envelope_ReleaseControlResult:
		// 全是 nervud -> 对端方向的 body: 响应 (HelloAck/*Result/Response), 推送
		//  (Event/EndpointDied/EndpointRevoked/SubscriptionClosed), 以及 nervud 派发
		// 给 Service 的 Dispatch/CancelDispatch (只能由 nervud 发给 Service).
		// nervud 永远不接收它们, 收到即协议违规
		co.log.Warn("ipc: server-originated body received from peer, closing", "body", bodyName(env))
		co.s.auditViolation(co.caller, errUnexpectedBody)
		return false

	case *ipcv1.Envelope_Cancel:
		// 对端 -> nervud 方向合法, 但本 build 未实现. Cancel 需要专属回复与
		// 在途调用追踪, 凭空造回复会让调用方以为取消成功了, 故关闭并审计为
		// UnsupportedBody - 与协议违规分开, 既不污染安全信号, 也不把未来的
		// 接入误判成攻击.
		//
		// Subscribe/Unsubscribe 已随 internal/subscription 落地迁出本组.
		return co.unsupported(env)

	default:
		// parseEnvelope 已挡掉未知 body (proto3 把不认识的 oneof 分支收进 unknown
		// fields, Body 保持 nil). 走到这里说明 schema 新增了一个本 switch 未覆盖的
		// 已知 body - fail closed 当作未实现处理, 而不是静默放行
		return co.unsupported(env)
	}
}

// handlePing 回 Pong, 原样回带 nonce (的保活)
func (co *conn) handlePing(ping *ipcv1.Ping) bool {
	pong := &ipcv1.Envelope{Body: &ipcv1.Envelope_Pong{Pong: &ipcv1.Pong{Nonce: ping.GetNonce()}}}
	return co.enqueue(pong)
}

// handleResolveEndpoint 转发给注入的 EndpointResolver. 依赖未注入时返回
// unsupported, 避免 IPC 在缺少权威路由器时自行猜测绑定结果
func (co *conn) handleResolveEndpoint(env *ipcv1.Envelope, req *ipcv1.ResolveEndpoint) bool {
	if co.s.endpoints == nil {
		return co.unsupported(env)
	}
	result := co.s.endpoints.ResolveEndpoint(co, co.caller, req)
	return co.writeResultEnvelope(&ipcv1.Envelope{
		Body: &ipcv1.Envelope_ResolveEndpointResult{ResolveEndpointResult: result},
	})
}

// handleRegisterEndpoint 转发给 internal/endpoint (同上的 nil 降级)
func (co *conn) handleRegisterEndpoint(env *ipcv1.Envelope, req *ipcv1.RegisterEndpoint) bool {
	if co.s.endpoints == nil {
		return co.unsupported(env)
	}
	if co.componentType != pkgregistry.ComponentService {
		result := &ipcv1.RegisterEndpointResult{
			RequestId: req.GetRequestId(),
			Outcome: &ipcv1.RegisterEndpointResult_Failure{Failure: &ipcv1.Failure{
				Code: ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED,
			}},
		}
		return co.writeResultEnvelope(&ipcv1.Envelope{
			Body: &ipcv1.Envelope_RegisterEndpointResult{RegisterEndpointResult: result},
		})
	}
	result := co.s.endpoints.RegisterEndpoint(co, co.caller, req)
	return co.writeResultEnvelope(&ipcv1.Envelope{
		Body: &ipcv1.Envelope_RegisterEndpointResult{RegisterEndpointResult: result},
	})
}

// handleUnregisterEndpoint 转发给 internal/endpoint (同上的 nil 降级)
func (co *conn) handleUnregisterEndpoint(env *ipcv1.Envelope, req *ipcv1.UnregisterEndpoint) bool {
	if co.s.endpoints == nil {
		return co.unsupported(env)
	}
	if co.componentType != pkgregistry.ComponentService {
		result := &ipcv1.UnregisterEndpointResult{
			RequestId: req.GetRequestId(),
			Outcome: &ipcv1.UnregisterEndpointResult_Failure{Failure: &ipcv1.Failure{
				Code: ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED,
			}},
		}
		return co.writeResultEnvelope(&ipcv1.Envelope{
			Body: &ipcv1.Envelope_UnregisterEndpointResult{UnregisterEndpointResult: result},
		})
	}
	result := co.s.endpoints.UnregisterEndpoint(co, req)
	if result.GetSuccess() != nil {
		co.s.revokeEndpoint(co, req.GetEndpointId(), 0)
	}
	return co.writeResultEnvelope(&ipcv1.Envelope{
		Body: &ipcv1.Envelope_UnregisterEndpointResult{UnregisterEndpointResult: result},
	})
}

// writeResultEnvelope 把一个响应/结果类 Envelope 排进 outbox, 队列已满/已关闭
// 即关闭连接 (enqueue 内部处理)
func (co *conn) writeResultEnvelope(env *ipcv1.Envelope) bool {
	return co.enqueue(env)
}

// handleRequest 处理一个 Request (的请求管线: Route -> Dispatch)
//
// co.s.endpoints 为 nil 时维持既有降级行为: 校验 request_id 后恒回 UNAVAILABLE,
// 不静默丢也不裸关连接. 非 nil 时, 先经 Route 查表 (内部真正调用
// permission.Allowed), 成功后把 Request 转成 Dispatch 排进目标 Service 连接的
// outbox, 在 route 表登记相关状态, 然后返回 true - 本函数不再原地生成终结
// Response, 真正的 Response 由 handleDispatchResult / 超时清道夫 / 目标连接
// 断开三者之一在未来某个时刻通过本连接的 outbox 送达 (dispatch.go)
func (co *conn) handleRequest(req *ipcv1.Request) bool {
	// request_id 0 永久保留 (合法请求从 1 起). 在生成任何 Response 之前
	// 按协议违规关闭 - 回一个 request_id=0 的 Response 等于承认了一个不该存在的
	// 关联键, SDK 侧也永远不会为 0 登记 pending
	if req.GetRequestId() == 0 {
		co.log.Warn("ipc: Request with reserved request_id 0, closing")
		co.s.auditViolation(co.caller, errZeroRequestID)
		return false
	}

	if co.s.endpoints == nil {
		// 降级路径不变: Endpoints 未接线时恒 UNAVAILABLE, 不静默丢也不裸关连接
		return co.enqueue(responseEnvelope(failureResponse(
			req.GetRequestId(), ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE)))
	}

	// Sample the revocation epoch before consulting endpoint/catalog authority.
	// Publishing the route later is conditional on this value remaining stable.
	dispatchEpoch := co.s.dispatch.snapshotEpoch()
	route, rerr := co.s.endpoints.Route(co, req.GetEndpointId(), req.GetMethodId())
	if rerr.Code != ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		return co.enqueue(responseEnvelope(failureResponse(req.GetRequestId(), rerr.Code)))
	}
	if err := protocheck.GateSupport(route.Method.Meta, co.s.operations != nil); err != nil {
		co.s.recordMethodGateFailure(co.caller, route, req.GetMethodId(), err)
		return co.enqueue(responseEnvelope(failureResponse(
			req.GetRequestId(), methodGateCode(err))))
	}
	// 需用户确认的方法: 只有系统确认 UI 自己能发起, 它在调用前刚问过用户.
	// 其余调用方要走它代为发起 (见 protocheck.GateUserConfirmation)
	if err := protocheck.GateUserConfirmation(
		route.Method.Meta, co.callerIsConfirmationUI()); err != nil {
		co.s.recordMethodGateFailure(co.caller, route, req.GetMethodId(), err)
		return co.enqueue(responseEnvelope(failureResponse(
			req.GetRequestId(), methodGateCode(err))))
	}
	payload, err := protocheck.ValidateRequest(
		route.Method.Meta, route.Method.Request, req.GetPayload())
	if err != nil {
		co.s.recordMethodGateFailure(co.caller, route, req.GetMethodId(), err)
		return co.enqueue(responseEnvelope(failureResponse(
			req.GetRequestId(), requestValidationCode(err))))
	}
	requiresControl := methodRequiresControl(route.Method.Meta)
	var leaseProof control.LeaseProof
	if requiresControl {
		if route.ResourceHandle == "" || co.s.leases == nil {
			return co.enqueue(responseEnvelope(failureResponse(
				req.GetRequestId(), ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION)))
		}
		leaseProof, err = co.s.leases.CheckResource(
			co.connID, route.ResourceHandle, route.ResourceGeneration,
		)
		if err != nil {
			return co.enqueue(responseEnvelope(failureResponse(
				req.GetRequestId(), ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION)))
		}
	}
	if code := co.reserveRequest(req.GetRequestId(), len(payload)); code != ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
		return co.enqueue(responseEnvelope(failureResponse(req.GetRequestId(), code)))
	}

	now := time.Now()
	deadline := now.Add(methodTimeout(req.GetTimeoutMs(), route.Method.Meta))
	if requiresControl {
		if !leaseProof.Deadline.After(now) {
			co.releaseRequest(req.GetRequestId())
			return co.enqueue(responseEnvelope(failureResponse(
				req.GetRequestId(), ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION)))
		}
		if leaseProof.Deadline.Before(deadline) {
			deadline = leaseProof.Deadline
		}
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		co.releaseRequest(req.GetRequestId())
		return co.enqueue(responseEnvelope(failureResponse(
			req.GetRequestId(), ipcv1.StatusCode_STATUS_CODE_DEADLINE_EXCEEDED)))
	}

	// 内建 endpoint: 目标是 nervud 自己, 就地执行, 不走 Dispatch.
	//
	// 必须先判 Builtin 再判 TargetConn. 内建没有连接, TargetConn 恒为 nil,
	// 顺序反了会把它当成"路由成功但没有转发目标"直接回 UNAVAILABLE.
	if route.Builtin != nil {
		return co.handleBuiltinRequest(req, route, payload, deadline)
	}

	target, ok := route.TargetConn.(*conn)
	if !ok || target == nil {
		// Route 报告成功, 但没有可转发的真实连接 (装配缺口, 或测试替身故意
		// 留空). 没有变通方案, 按不可用处理, 而不是假装转发成功
		co.releaseRequest(req.GetRequestId())
		return co.enqueue(responseEnvelope(failureResponse(
			req.GetRequestId(), ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE)))
	}
	// 每个 Dispatch 都带 ExecutionContext, 无条件.
	//
	// v1 曾按协商 minor 决定带不带, 并为此在控制方法上多一道"minor 太低就拒"
	// 的分支. v2 从第一天起就带, 两条分支一起移除 - 一个"有时带有时不带"的
	// 字段会让 Provider 侧不得不写两套处理, 而漏写那一套只在特定对端版本下暴露.
	if (route.ResourceHandle == "") != (route.ResourceGeneration == 0) {
		co.releaseRequest(req.GetRequestId())
		return co.enqueue(responseEnvelope(failureResponse(
			req.GetRequestId(), ipcv1.StatusCode_STATUS_CODE_INTERNAL)))
	}
	deadlineNanos, deadlineErr := co.s.monotonicDeadlineNanos(deadline)
	if deadlineErr != nil {
		co.log.Error("ipc: project Dispatch monotonic deadline", "err", deadlineErr)
		co.releaseRequest(req.GetRequestId())
		return co.enqueue(responseEnvelope(failureResponse(
			req.GetRequestId(), ipcv1.StatusCode_STATUS_CODE_INTERNAL)))
	}
	execution := &ipcv1.ExecutionContext{
		DeadlineNanos:      deadlineNanos,
		ResourceHandle:     route.ResourceHandle,
		ResourceGeneration: route.ResourceGeneration,
	}
	if requiresControl {
		leaseID, found := co.wireLeaseHandle(leaseProof.ID)
		controllerClass, validClass := classToWire(leaseProof.Class)
		if !found || !validClass || leaseProof.Epoch == 0 ||
			leaseProof.Resource != route.ResourceHandle ||
			leaseProof.ResourceGeneration != route.ResourceGeneration {
			co.releaseRequest(req.GetRequestId())
			return co.enqueue(responseEnvelope(failureResponse(
				req.GetRequestId(), ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION)))
		}
		execution.LeaseId = leaseID
		execution.ControllerClass = controllerClass
		execution.MotionEpoch = leaseProof.Epoch
	}

	// Operation 在 Dispatch 之前建. 这个顺序让 Provider 收到 Dispatch 时
	// operation_id 已经有效, 因此它可以直接回 DispatchResult{ACCEPTED} -
	// 那个码要求"Operation 必须已经存在".
	//
	// 反过来 (先 Dispatch 再建) 会产生一个窗口: Provider 已经开始动, 而
	// operation 还不存在, 此时它的第一次 ReportProgress 会被拒.
	var operationID uint64
	if route.Method.Meta.GetReturnsOperation() {
		id, code := co.createOperation(route, target, deadline, execution)
		if code != ipcv1.StatusCode_STATUS_CODE_ACCEPTED {
			co.releaseRequest(req.GetRequestId())
			return co.enqueue(responseEnvelope(failureResponse(req.GetRequestId(), code)))
		}
		operationID = id
		execution.OperationId = id
	}

	routeID, publishStatus := co.s.dispatch.publishDispatchAtEpoch(
		dispatchEpoch,
		co,
		req.GetRequestId(),
		target,
		deadline,
		route,
		req.GetMethodId(),
		remainingMillis(remaining),
		payload,
		callerContext(co.caller, route.RequiredPermissions),
		execution,
	)
	// 三条失败路径都要把已经建好的 operation 收敛掉.
	//
	// 不收敛的后果: 一条 PENDING 的 operation 挂在那里, Provider 从来没
	// 收到过 Dispatch, 因此永远不会有人 Accept 或 Complete 它. 它会一直占着
	// 直到 deadline 到期 - 而调用方已经拿到失败响应, 根本不知道它存在.
	failOperation := func(code ipcv1.StatusCode) {
		if operationID == 0 || co.s.operations == nil {
			return
		}
		if err := co.s.operations.Fail(operationID, code, nil); err != nil {
			co.log.Warn("ipc: converge undispatched operation",
				"operation_id", operationID, "err", err)
		}
	}

	switch publishStatus {
	case dispatchPublishEpochChanged:
		failOperation(ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE)
		co.releaseRequest(req.GetRequestId())
		return co.enqueue(responseEnvelope(failureResponse(
			req.GetRequestId(), ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE)))
	case dispatchPublishTargetUnavailable:
		// The table already removed the unpublished route and closed its token.
		// Do connection teardown only after releasing dispatch.mu.
		if target.outbox != nil {
			target.closeAsSlowConsumer()
		}
		co.s.transfer.CloseRoute(routeID)
		failOperation(ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE)
		co.releaseRequest(req.GetRequestId())
		return co.enqueue(responseEnvelope(failureResponse(
			req.GetRequestId(), ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE)))
	case dispatchPublishSequenceExhausted:
		failOperation(ipcv1.StatusCode_STATUS_CODE_INTERNAL)
		co.releaseRequest(req.GetRequestId())
		return co.enqueue(responseEnvelope(failureResponse(
			req.GetRequestId(), ipcv1.StatusCode_STATUS_CODE_INTERNAL)))
	case dispatchPublishOK:
		return true
	default:
		panic("ipc: unknown dispatch publish status")
	}
}

// createOperation 为一次 returns_operation 的调用建 operation.
//
// 返回 ACCEPTED 表示建成; 其余码原样回给调用方 - Create 的前置失败
//
//	(资源无效, 租约过期, epoch 陈旧) 已经是可区分的原因, 不需要再包一层.
func (co *conn) createOperation(
	route endpoint.RouteInfo,
	target *conn,
	deadline time.Time,
	execution *ipcv1.ExecutionContext,
) (uint64, ipcv1.StatusCode) {
	if co.s.operations == nil {
		// GateSupport 已经拦过, 走到这里说明装配在两处不一致.
		return 0, ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE
	}

	// 资源集合: v1 一个 operation 绑一个资源 (见 operation 包的说明).
	// 接口不绑资源时给空集合, Create 会以 INVALID_ARGUMENT 拒 - 那是对的:
	// 一个不绑任何资源的长任务没有可被 Safety 接管的对象.
	var resources []string
	if route.ResourceHandle != "" {
		resources = []string{route.ResourceHandle}
	}

	return co.s.operations.Create(
		co,     // 调用方连接: 断开时收敛
		target, // 执行方连接: 回报侧的归属凭据
		co.caller,
		operation.OriginBinding{
			InterfaceID: route.InterfaceID,
			IfaceMajor:  route.InterfaceMajor,
			IfaceMinor:  route.InterfaceMinor,
			MethodID:    route.Method.MethodID,
			SchemaHash:  route.InterfaceSchemaHash,
		},
		resources,
		execution.GetLeaseId(),
		execution.GetMotionEpoch(),
		deadline,
	)
}

func methodRequiresControl(meta *ipcv1.MethodMeta) bool {
	return meta != nil && (meta.GetRequiresControlLease() || meta.GetIsMotion())
}

// handleDispatchResult 处理 Service 送回的 DispatchResult: 查表
// 匹配才生成对应调用者的终结 Response. 未知/已完成的 route_id 是预期内的良性
// 竞态 (清道夫或另一次结果已经抢先完成, 或断开清理已经摘掉), 丢弃但保持连接
// 存活; 目标错位 (route_id 存在但送回结果的连接并非登记的目标连接) 没有合法
// 解释 - 按协议违规关闭
func (co *conn) handleDispatchResult(dr *ipcv1.DispatchResult) bool {
	e, status := co.s.dispatch.complete(dr.GetRouteId(), co, time.Now())
	switch status {
	case completeMismatch:
		co.log.Warn("ipc: DispatchResult route_id targets a different connection, closing",
			"route_id", dr.GetRouteId())
		co.s.auditViolation(co.caller, errDispatchResultMismatch)
		return false
	case completeNotFound:
		co.s.auditDispatchRace(co.caller.String(), dr.GetRouteId())
		return true
	case completeExpired:
		co.s.transfer.CloseRoute(e.routeID)
		return resolveRoute(e, failureResponse(
			e.sourceRequestID, ipcv1.StatusCode_STATUS_CODE_DEADLINE_EXCEEDED))
	case completeOK:
	}

	resp, valid := co.s.validateDispatchResult(e, dr)
	sourceOK := resolveRoute(e, resp)
	if !valid {
		co.log.Warn("ipc: Provider violated method result contract, closing",
			"route_id", dr.GetRouteId(),
			"interface", e.route.InterfaceID,
			"method_id", e.methodID)
		return false
	}
	return sourceOK
}

// methodTimeout applies the method-declared default and maximum, then the
// connection-wide kernel ceiling. Zero never means unlimited.
func methodTimeout(requested uint32, meta *ipcv1.MethodMeta) time.Duration {
	defaultMS := uint32(defaultMethodTimeoutMs)
	maxMS := uint32(maxMethodTimeoutMs)
	if meta != nil {
		if meta.GetDefaultTimeoutMs() != 0 {
			defaultMS = meta.GetDefaultTimeoutMs()
		}
		if declared := meta.GetMaxTimeoutMs(); declared != 0 && declared < maxMS {
			maxMS = declared
		}
	}
	if defaultMS > maxMS {
		defaultMS = maxMS
	}
	if requested == 0 {
		requested = defaultMS
	}
	if requested > maxMS {
		requested = maxMS
	}
	if requested == 0 {
		requested = 1
	}
	return time.Duration(requested) * time.Millisecond
}

// callerContext 把内核已经核实过的 identity.Caller 投影成可以外传给 Service 的
// CallerContext (Service 可以读, 但不能据此绕过 nervud 已经生效的 Policy, 更不能
// 自行创造身份或权限裁决). granted 只包含 endpoint.Route 在同一个 catalog snapshot
// 上为本次调用逐项核验过的权限, 不暴露这个 Package 的完整授权集合.
func callerContext(c identity.Caller, granted []string) *ipcv1.CallerContext {
	return &ipcv1.CallerContext{
		PackageId:          c.PackageID,
		ComponentId:        c.ComponentID,
		Uid:                c.UID,
		Gid:                c.GID,
		Pid:                c.PID,
		TrustProfile:       trustProfileWire(c.Trust),
		GrantedPermissions: append([]string(nil), granted...),
	}
}

// trustProfileWire 把 identity.TrustProfile 显式映射到 ipcv1.TrustProfile.
// 两者取值目前恰好一一对应, 但用显式 switch 而不是裸类型转换 - 两个包各自的
// 枚举独立演进, 裸转换会在其中一个新增/重排取值时悄悄产生错误映射而不报错
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

func internalResponse(reqID uint64) *ipcv1.Response {
	return failureResponse(reqID, ipcv1.StatusCode_STATUS_CODE_INTERNAL)
}

// failureResponse/responseEnvelope 是构造终结 Response 的两个共用小工具,
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

// sendHelloFailure 发出一个带 Failure 的 HelloAck (不关闭连接, 关闭由调用方决定)
func (co *conn) sendHelloFailure(code ipcv1.StatusCode) {
	fail := &ipcv1.Envelope{Body: &ipcv1.Envelope_HelloAck{HelloAck: &ipcv1.HelloAck{
		Outcome: &ipcv1.HelloAck_Failure{Failure: &ipcv1.Failure{Code: code}},
	}}}
	// 调用方 (handleHandshake) 无论 enqueue 是否成功都会紧接着返回 false 关闭
	// 连接, 这里不需要额外处理返回值
	co.enqueue(fail)
}

// writeEnvelope 序列化并写出一个 Envelope, 带写出 deadline
//
// 出站 Envelope 一律标注本连接协商到的协议版本. 写出经由 conn 自己的缓冲 writer,
// 让长度 + 正文合并成一次 syscall (frame.go 的建议)
func (co *conn) writeEnvelope(env *ipcv1.Envelope) error {
	env.ProtocolMajor = co.negMajor
	env.ProtocolMinor = co.negMinor

	b, err := proto.Marshal(env)
	if err != nil {
		// 本端构造出不可序列化的 Envelope 属于 nervud bug, 不外发
		return fmt.Errorf("ipc: marshal outbound envelope: %w", err)
	}

	// 写出必须有有限 deadline, 否则一个迟迟不读取的慢消费者能把
	// 帧泵 goroutine 永久挂在 Write 上. 控制帧都很小, 复用 FrameBodyTimeout
	// 作为写窗口 - 语义一致: 一段已宣告长度的字节必须很快落地
	if err := co.c.SetWriteDeadline(time.Now().Add(co.s.limits.FrameBodyTimeout)); err != nil {
		return err
	}
	if err := WriteFrame(co.w, b); err != nil {
		return err
	}
	return co.w.Flush()
}

// negotiateVersion 在服务端支持的版本 (srvMajor, 该 major 下 minor 上限 srvMinorMax)
// 与客户端 Hello 声明的范围间求交集, 选出即刻生效的 (major, minor). 无交集返回
// ok=false (, 10.12)
//
// 取 srvMajor/srvMinorMax 为参数而非直接读常量, 是为了把越界这条逻辑单测到位
func negotiateVersion(h *ipcv1.Hello, srvMajor, srvMinorMax uint32) (major, minor uint32, ok bool) {
	// 服务端只实现 srvMajor 这一个 major, 它必须落在客户端闭区间
	// [min_protocol_major, max_protocol_major] 内, 否则无从协商. 范围本身颠倒
	//  (max < min) 时该判断自然不成立, 一并落到无交集
	if h.GetMinProtocolMajor() > srvMajor || h.GetMaxProtocolMajor() < srvMajor {
		return 0, 0, false
	}
	major = srvMajor

	if h.GetMaxProtocolMajor() == srvMajor {
		// 选定的 major 恰是客户端的最高 major: Hello 的 max_protocol_minor 就是
		// 客户端对本 major 的 minor 上限, 取它与服务端上限的较小值
		minor = srvMinorMax
		if cm := h.GetMaxProtocolMinor(); cm < minor {
			minor = cm
		}
		return major, minor, true
	}

	// 选定的 major 低于客户端最高 major: Hello 只为最高 major 声明了 minor, 对更低
	// 的 major 没有任何 minor 信息. minor 0 是任一实现对某个 major 的保证下限, 因此
	// 只能给 0 - 不能假设客户端支持更高 major就等于它支持我们这个 major 的更高
	// minor, 那会在服务端 minor 抬高后选出客户端从未声明支持的版本
	return major, 0, true
}

// bodyName 返回 Envelope body 的具体类型名, 仅用于诊断日志
func bodyName(env *ipcv1.Envelope) string {
	return fmt.Sprintf("%T", env.GetBody())
}

// handleBuiltinRequest 就地执行一次内建 endpoint 调用并回 Response.
//
// 与转发路径的两处不同:
//
//  1. 不占 route 表. 内建没有"等待对端回结果"这回事 - 执行完就有结果,
//     不存在迟到, 重复或撤销后到达的 DispatchResult.
//  2. panic 必须就地拦住. 内建 handler 跑在内核进程里, 一个 panic 会带走
//     整个 nervud - 那比任何一次调用失败都严重. 转发路径没有这个风险,
//     因为 Provider 在别的进程里.
func (co *conn) handleBuiltinRequest(
	req *ipcv1.Request,
	route endpoint.RouteInfo,
	payload []byte,
	deadline time.Time,
) bool {
	// 起 goroutine 而不是同步执行: 读循环不能被一个慢 handler 卡住, 否则这条
	// 连接上后续的 Ping/Cancel 全都读不到, 客户端会误判为失联.
	go func() {
		defer co.releaseRequest(req.GetRequestId())
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()

		resultCh := make(chan endpoint.BuiltinResult, 1)
		go func() {
			resultCh <- co.s.callBuiltin(endpoint.BuiltinCall{
				Context:  ctx,
				Conn:     co,
				Caller:   co.caller,
				MethodID: req.GetMethodId(),
				Payload:  payload,
			}, route.Builtin)
		}()

		var result endpoint.BuiltinResult
		select {
		case result = <-resultCh:
		case <-ctx.Done():
			co.enqueue(responseEnvelope(failureResponse(
				req.GetRequestId(), ipcv1.StatusCode_STATUS_CODE_DEADLINE_EXCEEDED)))
			return
		}

		resp, valid := co.s.validateBuiltinResult(req.GetRequestId(), route, result)
		if !valid {
			co.s.auditor.Record(context.Background(), audit.Event{
				Action:  "ipc.BuiltinContractViolation",
				Subject: co.caller.String(),
				Denied:  true,
				Detail: fmt.Sprintf(
					"interface=%s major=%d method_id=%d",
					route.InterfaceID, route.InterfaceMajor, req.GetMethodId()),
			})
		}
		co.enqueue(responseEnvelope(resp))
	}()
	return true
}

// callBuiltin 执行 handler 并把 panic 转成 INTERNAL.
//
// 内建 handler 跑在内核进程里, panic 会带走整个 nervud - 机器上所有 App 的
// 连接, 在途调用, 以及 Safety 监督链一起消失. 相比之下让这一次调用失败是
// 明显更小的代价.
func (s *Server) callBuiltin(
	call endpoint.BuiltinCall,
	handler endpoint.BuiltinHandler,
) (result endpoint.BuiltinResult) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("ipc: builtin handler panicked",
				"method_id", call.MethodID,
				"caller", call.Caller.PackageID,
				"panic", r)
			result = endpoint.BuiltinResult{
				Code: ipcv1.StatusCode_STATUS_CODE_INTERNAL,
			}
		}
	}()
	return handler(call)
}

func remainingMillis(remaining time.Duration) uint32 {
	if remaining <= 0 {
		return 0
	}
	ms := (remaining + time.Millisecond - 1) / time.Millisecond
	if ms > time.Duration(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(ms)
}
