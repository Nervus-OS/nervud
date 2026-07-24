// 本文件是连接内的 Envelope 状态机（架构 10.2）：第一帧 Hello/HelloAck 握手，
// 之后按 body 分派。分帧见 frame.go，帧→Envelope 的良构校验见 envelope.go，
// 连接的准入与帧泵见 ipc.go
//
// 写回契约：本连接的写出全部由帧泵那一个 goroutine 串行完成（读一帧、至多回
// 一帧、再读下一帧），因此满足 frame.go 的「每条连接只有一个 writer」约束，无需
// 加锁。独立 writer goroutine + 有界 outbound 队列（架构 10.8）随执行层落地，
// 那之前不存在并发写
package ipc

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"
	"google.golang.org/protobuf/proto"

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
}

func newConn(s *Server, c net.Conn, caller identity.Caller, log *slog.Logger) *conn {
	return &conn{
		s:        s,
		c:        c,
		w:        bufio.NewWriter(c),
		log:      log,
		caller:   caller,
		phase:    phaseHandshake,
		negMajor: protocolMajor,
		negMinor: protocolMinorMax,
	}
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
	if err := co.writeEnvelope(ack); err != nil {
		// 客户端已经走了：没什么可审计的，正常收尾
		co.log.Debug("ipc: write HelloAck failed, closing", "err", err)
		return false
	}

	co.phase = phaseReady
	co.log.Debug("ipc: handshake complete", "major", major, "minor", minor)
	return true
}

// handleReady 在握手完成后按 body 分派（架构 10.7）
//
// 分派先看方向，再看是否实现——方向错的直接是违规，方向对但没实现的是能力缺口：
//   - Ping→Pong、Pong 接受忽略、Request→UNAVAILABLE 已打通（请求管线尚未落地）
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
		*ipcv1.Envelope_Unsubscribe,
		*ipcv1.Envelope_DispatchResult:
		// 对端→nervud 方向合法、但本 build 未实现的 body。Cancel/Subscribe/
		// Unsubscribe 来自 App/Service；DispatchResult 由 Service 连接回给 nervud
		// （§10.7，route 追踪落地前无从匹配）。它们各自需要专属回复或路由，凭空
		// 造回复违反架构 10.4/10.7，故关闭并审计为 UnsupportedBody——与协议违规
		// 分开，既不污染安全信号，也不把未来的 ServiceHost 接入误判成攻击。
		// ResolveEndpoint/RegisterEndpoint/UnregisterEndpoint 已随 internal/endpoint
		// 落地迁出本组（见上方 handleResolveEndpoint 等；co.s.endpoints 为 nil 时
		// 它们各自仍会降级回 unsupported()）。各自的 handler 随对应模块
		// （subscription/dispatch）落地后迁出
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
	if err := co.writeEnvelope(pong); err != nil {
		co.log.Debug("ipc: write Pong failed, closing", "err", err)
		return false
	}
	return true
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

// writeResultEnvelope 写出一个响应/结果类 Envelope，写失败即关闭连接
func (co *conn) writeResultEnvelope(env *ipcv1.Envelope) bool {
	if err := co.writeEnvelope(env); err != nil {
		co.log.Debug("ipc: write result envelope failed, closing", "err", err)
		return false
	}
	return true
}

// handleRequest 处理一个 Request（架构 10.7 的请求管线：Route → Dispatch）
//
// co.s.endpoints 为 nil 时维持既有降级行为：校验 request_id 后恒回 UNAVAILABLE，
// 不静默丢也不裸关连接。非 nil 时，先经 Route() 查表——这一步就是架构总览 §7
// 待办列表里等待的那次真正 permission.Allowed 调用（在 endpoint.Route 内部）。
// Dispatch 到 Service 连接的转发本体（route_id 分配/Lane 调度/deadline 收紧）
// 不在 internal/endpoint 范围内（见其设计文档 §1），v1 在 Route 成功之后仍以
// UNAVAILABLE 结束请求，但已经是【真正 Route 之后】的 UNAVAILABLE，而不是无
// 条件恒定值
func (co *conn) handleRequest(req *ipcv1.Request) bool {
	// request_id 0 永久保留（架构 10.6：合法请求从 1 起）。在生成任何 Response 之前
	// 按协议违规关闭——回一个 request_id=0 的 Response 等于承认了一个不该存在的
	// 关联键，SDK 侧也永远不会为 0 登记 pending
	if req.GetRequestId() == 0 {
		co.log.Warn("ipc: Request with reserved request_id 0, closing")
		co.s.auditViolation(co.caller, errZeroRequestID)
		return false
	}

	failCode := ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE
	if co.s.endpoints != nil {
		_, rerr := co.s.endpoints.Route(co, req.GetEndpointId())
		if rerr.Code != ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED {
			failCode = rerr.Code
		}
		// route.TargetConn 已知，但把请求真正转发给该 Service 连接（Dispatch/
		// DispatchResult 关联、Lane 调度）是 ipc 自己的请求管线尚未落地的部分，
		// 不在这里空转——见上方函数注释
	}

	// 用 Response(Failure) 而不是断开：Request 携带 request_id，能以它归位一个
	// 合法的失败终结响应（架构 10.12：断线时 SDK 把 pending 完成为 UNAVAILABLE，
	// 这里等价于在连接仍存活时直接告诉它当前结果）。public_message 留空——
	// 架构 10.4 禁止透传自由文本，本端也没有可归因的模板文本要加
	resp := &ipcv1.Envelope{Body: &ipcv1.Envelope_Response{Response: &ipcv1.Response{
		RequestId: req.GetRequestId(),
		Outcome: &ipcv1.Response_Failure{Failure: &ipcv1.Failure{
			Code: failCode,
		}},
	}}}
	return co.writeResultEnvelope(resp)
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
	if err := co.writeEnvelope(fail); err != nil {
		co.log.Debug("ipc: write Failure HelloAck failed", "err", err)
	}
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
