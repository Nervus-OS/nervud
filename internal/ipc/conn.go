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

	// defaultMethodPayloadBytes 是普通方法默认 request/response 额度（架构 10.3）。
	// 逐方法额度在 Registry 中声明，最终取「方法额度、profile 额度、128 KiB 硬上限」
	// 三者最小值——这里下发的是那条链的默认起点，不是最终裁决
	defaultMethodPayloadBytes = 16 << 10
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

	major, minor, ok := negotiateVersion(hello)
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

	// 架构 10.2：验证声明，而不是相信声明。客户端在 declared_component_id 里
	// 自报的 Component 只是待验证线索，必须用 PID、systemd unit/cgroup 与启动
	// 记录核对。verifyComponent 目前是 stub（见其注释），既不信任自报值也无法
	// 否证它，因此确认到的 ComponentID 暂为空
	componentID, err := co.s.verifyComponent(co.caller, hello.GetDeclaredComponentId())
	if err != nil {
		// 自报 Component 与内核事实不符：身份不成立，按架构 10.12 回
		// UNAUTHENTICATED Failure HelloAck 再关闭，并审计（可能是伪装尝试）。
		// stub 永不走到这里；此分支为真正核对落地后预留
		co.log.Warn("ipc: declared component verification failed",
			"declared", hello.GetDeclaredComponentId(), "err", err)
		co.s.auditViolation(co.caller, err)
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
// 本 build 只打通 Ping→Pong 与 Request→UNAVAILABLE：请求管线（Resolve/Permission/
// Lane/Dispatch）尚未落地。其余 body 分两类处理，都【不静默丢】：
//   - 只应由服务端产生的响应/推送 → 协议违规，关闭并审计
//   - 客户端合法但未实现的控制/调用 body → 关闭并审计为 UnsupportedBody
func (co *conn) handleReady(env *ipcv1.Envelope) bool {
	switch body := env.GetBody().(type) {
	case *ipcv1.Envelope_Ping:
		return co.handlePing(body.Ping)

	case *ipcv1.Envelope_Request:
		// 请求管线未落地。按架构 10.12 回一个以 request_id 归位的 UNAVAILABLE
		// Response，而不是静默丢或裸关连接
		return co.sendRequestUnavailable(body.Request)

	case *ipcv1.Envelope_Hello:
		// 握手已完成，再来一个 Hello 是非法握手状态（架构 10.11）
		co.log.Warn("ipc: duplicate Hello after handshake, closing")
		co.s.auditViolation(co.caller, errDuplicateHello)
		return false

	case *ipcv1.Envelope_HelloAck,
		*ipcv1.Envelope_Response,
		*ipcv1.Envelope_Pong,
		*ipcv1.Envelope_ResolveEndpointResult,
		*ipcv1.Envelope_RegisterEndpointResult,
		*ipcv1.Envelope_UnregisterEndpointResult,
		*ipcv1.Envelope_SubscribeResult,
		*ipcv1.Envelope_UnsubscribeResult,
		*ipcv1.Envelope_Event,
		*ipcv1.Envelope_SubscriptionClosed,
		*ipcv1.Envelope_EndpointDied,
		*ipcv1.Envelope_EndpointRevoked,
		*ipcv1.Envelope_DispatchResult:
		// 这些都是服务端→客户端的响应或推送，客户端永远不该主动发出，收到即协议
		// 违规。（Dispatch/DispatchResult 属于 nervud↔Service 方向；Service 连接
		// 语义落地后 DispatchResult 会迁到那条路径，在此之前它在 App 连接上非法）
		co.log.Warn("ipc: server-originated body received from client, closing", "body", bodyName(env))
		co.s.auditViolation(co.caller, errUnexpectedBody)
		return false

	case *ipcv1.Envelope_ResolveEndpoint,
		*ipcv1.Envelope_RegisterEndpoint,
		*ipcv1.Envelope_UnregisterEndpoint,
		*ipcv1.Envelope_Cancel,
		*ipcv1.Envelope_Subscribe,
		*ipcv1.Envelope_Unsubscribe,
		*ipcv1.Envelope_Dispatch,
		*ipcv1.Envelope_CancelDispatch:
		// 客户端合法但本 build 未实现。它们各自需要专属的 *Result 回复，凭空造一个
		// 未经权威 method schema 校验的回复违反架构 10.4/10.7；因此现在关闭并审计
		// 为 UnsupportedBody（与协议违规分开，避免污染安全信号）。每个 body 的专属
		// handler 随对应模块（endpoint/subscription/dispatch）落地后从这里迁出
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

// sendRequestUnavailable 对一个尚无 handler 的 Request 回终结 Response
//
// 用 UNAVAILABLE 而不是断开：Request 携带 request_id，能以它归位一个合法的失败
// 终结响应（架构 10.12：断线时 SDK 把 pending 完成为 UNAVAILABLE，这里等价于在
// 连接仍存活时直接告诉它「当前不可用」）。public_message 留空——架构 10.4 禁止
// 透传自由文本，本端也没有可归因的模板文本要加
func (co *conn) sendRequestUnavailable(req *ipcv1.Request) bool {
	resp := &ipcv1.Envelope{Body: &ipcv1.Envelope_Response{Response: &ipcv1.Response{
		RequestId: req.GetRequestId(),
		Outcome: &ipcv1.Response_Failure{Failure: &ipcv1.Failure{
			Code: ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE,
		}},
	}}}
	if err := co.writeEnvelope(resp); err != nil {
		co.log.Debug("ipc: write Response failed, closing", "err", err)
		return false
	}
	return true
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

// negotiateVersion 在 nervud 支持的版本与客户端 Hello 声明的范围间求交集，选出即刻
// 生效的 (major, minor)。无交集返回 ok=false（架构 10.2、10.12）
func negotiateVersion(h *ipcv1.Hello) (major, minor uint32, ok bool) {
	// nervud 只实现 protocolMajor 这一个 major，它必须落在客户端闭区间
	// [min_protocol_major, max_protocol_major] 内，否则无从协商。范围本身颠倒
	// （max < min）时该判断自然不成立，一并落到「无交集」
	if h.GetMinProtocolMajor() > protocolMajor || h.GetMaxProtocolMajor() < protocolMajor {
		return 0, 0, false
	}
	major = protocolMajor

	// minor 只增不减：只有当选定 major 恰是客户端的最高 major 时，才受客户端
	// max_protocol_minor 约束；若客户端最高 major 比我们高，说明它对我们这个较低
	// major 支持到任意 minor，取我们自己的上限即可
	clientMinorCeil := uint32(protocolMinorMax)
	if h.GetMaxProtocolMajor() == protocolMajor {
		clientMinorCeil = h.GetMaxProtocolMinor()
	}
	minor = protocolMinorMax
	if clientMinorCeil < minor {
		minor = clientMinorCeil
	}
	return major, minor, true
}

// bodyName 返回 Envelope body 的具体类型名，仅用于诊断日志
func bodyName(env *ipcv1.Envelope) string {
	return fmt.Sprintf("%T", env.GetBody())
}
