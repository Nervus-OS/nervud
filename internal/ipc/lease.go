// 本文件是 ControlLease 的 wire 接线: 把 Envelope 的 AcquireControl(70) /
// ReleaseControl(72) 接到 internal/control 的租约状态机上.
//
// # 为什么这条线以前是断的
//
// control 模块本身早已完整 (申请/续租/释放/抢占/deadman/epoch 递增, 1200 行
// 源码 + 1000 行测试), 但 nervud 的 conn 状态机从来没有处理过这四个 body -
// 内核甚至一度钉在没有这几个消息的旧 protocol 版本上. 结果是: 租约逻辑写完了
// 却没有任何入口, App 拿不到运动 lease, 而 operation.Manager 的 LeaseValidator
// 只能注入 nil, 导致全部运动类 operation 被前置拒绝.
//
// 本文件补的就是那一段.
//
// # 租约是连接作用域的
//
// lease_id 绑本连接, 不可转让, 连接断开即失效 (envelope.proto:
// AcquireControlSuccess.lease_id). 因此 conn 收尾时必须 RevokeConn - 否则一个
// 断了线的 App 仍然"持有"执行器控制权, 谁也抢不走, 直到 TTL 自然到期.
package ipc

import (
	"errors"
	"math"
	"time"

	"google.golang.org/protobuf/proto"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/control"
)

// handleAcquireControl 处理一次租约申请.
func (co *conn) handleAcquireControl(req *ipcv1.AcquireControl) bool {
	reqID := req.GetRequestId()
	if reqID == 0 {
		co.log.Warn("ipc: AcquireControl with reserved request_id 0, closing")
		co.s.auditViolation(co.caller, errZeroRequestID)
		return false
	}

	if co.s.leases == nil {
		// control 未接线 (测试/裁剪构建). 回 UNAVAILABLE 而不是关连接:
		// 这是能力缺口不是协议违规, 客户端重试或降级都合理.
		return co.enqueue(acquireFailure(reqID,
			ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE,
			ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_RESOURCE_UNAVAILABLE))
	}

	class, ok := classFromWire(req.GetControllerClass())
	if !ok {
		// UNSPECIFIED 或未知值. fail closed: 不替客户端猜一个类别 -
		// 猜错的后果是把一个 AI 会话当成人在操作, 抢占矩阵会给它错误的优先级.
		return co.enqueue(acquireFailure(reqID,
			ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
			ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_INVALID_CONTROLLER))
	}

	// Resource 解析: 空 selector 按协议取隐式默认 (BaseMotion 的 base.main).
	// 与 ResolveEndpoint 的 selector 语义保持一致, 否则同一个"留空"在两条
	// 路径上含义不同, 是最容易写出 bug 的那类不一致.
	resource, resourceGeneration, ok := co.s.resolveLeaseResource(req.GetResource())
	if !ok {
		return co.enqueue(acquireFailure(reqID,
			ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_RESOURCE_UNAVAILABLE))
	}

	// 当前策略明确允许调用方选择 controller_class, 并把选择记入审计. Package,
	// Component 和连接身份均已由内核核实, 但 HUMAN/AI 这个值本身仍是自报值;
	// 它会影响抢占优先级, 不能把这段代码描述成可信 class 裁决. 未来若引入会话/
	// 人在场证明, 应在这里把 wire 值与可信策略结果交叉核对.
	co.s.auditLeaseClass(co.caller, class, resource)

	lease, err := co.s.leases.Acquire(control.Request{
		Conn:               co.leaseConnID(),
		Class:              class,
		Resource:           resource,
		ResourceGeneration: resourceGeneration,
		Owner:              co.caller,
		RequestedTTL:       time.Duration(req.GetRequestedDeadlineNanos()),
	})
	if err != nil {
		code, reason := leaseErrToWire(err)
		return co.enqueue(acquireFailure(reqID, code, reason))
	}
	// Catalog publication and its RevokeResource callback are intentionally
	// separate operations. If publication happened after the first resolve but
	// its old-generation revoke completed before Acquire, that scan could not
	// see the lease we just created. Resolve again before exposing a wire handle:
	// either we still observe the exact authority used for the lease, or the
	// newly published generation will revoke it after this check.
	currentResource, currentGeneration, current := co.s.resolveLeaseResource(req.GetResource())
	if !current || currentResource != resource || currentGeneration != resourceGeneration {
		_ = co.s.leases.Release(lease.ID, co.leaseConnID())
		return co.enqueue(acquireFailure(reqID,
			ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_RESOURCE_UNAVAILABLE))
	}
	deadlineNanos, err := co.s.monotonicDeadlineNanos(lease.Deadline)
	if err != nil {
		// Do not leave a lease active when its required wire representation could
		// not be produced. The caller never received a handle for this lease.
		_ = co.s.leases.Release(lease.ID, co.leaseConnID())
		co.s.auditViolation(co.caller, err)
		return co.enqueue(acquireFailure(reqID,
			ipcv1.StatusCode_STATUS_CODE_INTERNAL,
			ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_UNSPECIFIED))
	}

	return co.enqueue(&ipcv1.Envelope{Body: &ipcv1.Envelope_AcquireControlResult{
		AcquireControlResult: &ipcv1.AcquireControlResult{
			RequestId: reqID,
			Outcome: &ipcv1.AcquireControlResult_Success{Success: &ipcv1.AcquireControlSuccess{
				// lease_id 上 wire 是 uint64, 而 control.ID 是 [16]byte.
				// 用连接内单调递增的句柄映射, 不把内部 ID 泄漏出去 -
				// 与 endpoint_id 同一原则: 查找键是 (连接, 句柄).
				LeaseId:        co.registerLease(lease),
				MotionEpoch:    lease.Epoch,
				DeadlineNanos:  deadlineNanos,
				ResourceHandle: lease.Resource,
			}},
		},
	}})
}

// monotonicDeadlineNanos converts a Go monotonic deadline into the absolute
// Linux CLOCK_MONOTONIC domain used by control and Dispatch execution contexts.
func (s *Server) monotonicDeadlineNanos(deadline time.Time) (int64, error) {
	if s == nil || s.monotonicNow == nil {
		return 0, errors.New("ipc: monotonic clock unavailable")
	}
	now, err := s.monotonicNow()
	if err != nil {
		return 0, err
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, errors.New("ipc: control lease expired before response")
	}
	delta := uint64(remaining)
	if now > math.MaxInt64 || delta > math.MaxInt64-now {
		return 0, errors.New("ipc: monotonic lease deadline overflow")
	}
	return int64(now + delta), nil
}

// handleReleaseControl 处理一次主动释放.
func (co *conn) handleReleaseControl(req *ipcv1.ReleaseControl) bool {
	reqID := req.GetRequestId()
	if reqID == 0 {
		co.log.Warn("ipc: ReleaseControl with reserved request_id 0, closing")
		co.s.auditViolation(co.caller, errZeroRequestID)
		return false
	}

	if co.s.leases == nil {
		return co.enqueue(releaseFailure(reqID, ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE))
	}

	id, ok := co.lookupLease(req.GetLeaseId())
	if !ok {
		// 不是本连接持有的 lease_id. 协议规定 FAILED_PRECONDITION.
		// 不关连接: 一个过期/已被抢占的 lease_id 被释放是正常时序
		//  (客户端还没收到撤销通知), 当协议违规处理会频繁踢掉正常客户端.
		return co.enqueue(releaseFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION))
	}

	if err := co.s.leases.Release(id, co.leaseConnID()); err != nil {
		return co.enqueue(releaseFailure(reqID, ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION))
	}
	co.forgetLease(req.GetLeaseId())

	return co.enqueue(&ipcv1.Envelope{Body: &ipcv1.Envelope_ReleaseControlResult{
		ReleaseControlResult: &ipcv1.ReleaseControlResult{
			RequestId: reqID,
			Outcome: &ipcv1.ReleaseControlResult_Success{
				Success: &ipcv1.Success{Code: ipcv1.StatusCode_STATUS_CODE_OK},
			},
		},
	}})
}

// classFromWire 把 wire 的 ControllerClass 翻成 control.Class.
//
// 未知值一律 fail closed: 协议明说"未指定或未知值一律 fail closed",
// 而这里猜错的后果是抢占矩阵用错优先级 - 把 AI 当人, 或反过来.
func classFromWire(c ipcv1.ControllerClass) (control.Class, bool) {
	switch c {
	case ipcv1.ControllerClass_CONTROLLER_CLASS_HUMAN:
		return control.ClassHuman, true
	case ipcv1.ControllerClass_CONTROLLER_CLASS_AI:
		return control.ClassAI, true
	default:
		return control.ClassUnspecified, false
	}
}

func classToWire(c control.Class) (ipcv1.ControllerClass, bool) {
	switch c {
	case control.ClassHuman:
		return ipcv1.ControllerClass_CONTROLLER_CLASS_HUMAN, true
	case control.ClassAI:
		return ipcv1.ControllerClass_CONTROLLER_CLASS_AI, true
	default:
		return ipcv1.ControllerClass_CONTROLLER_CLASS_UNSPECIFIED, false
	}
}

// leaseErrToWire 把 control 的错误翻成 (StatusCode, typed reason).
//
// 外层 code 决定 SDK 的恢复行为, typed reason 决定客户端该退避还是该抢占 -
// envelope.proto 明说"调用者需要"被谁占着"这类可区分原因才知道该退避还是
// 该抢占, 笼统 BUSY 不够". 两者必须一致.
func leaseErrToWire(err error) (ipcv1.StatusCode, ipcv1.ControlLeaseErrorReason) {
	switch {
	case errors.Is(err, control.ErrHeldByHuman):
		return ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_HELD_BY_HUMAN
	case errors.Is(err, control.ErrHeldByAI):
		return ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_HELD_BY_AI
	case errors.Is(err, control.ErrSafetyLatched):
		return ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_SAFETY_LATCHED
	case errors.Is(err, control.ErrUnknownResource):
		return ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_RESOURCE_UNAVAILABLE
	case errors.Is(err, control.ErrInvalidRequest), errors.Is(err, control.ErrPolicyViolation):
		return ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
			ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_INVALID_CONTROLLER
	case errors.Is(err, control.ErrShuttingDown):
		return ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE,
			ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_RESOURCE_UNAVAILABLE
	case errors.Is(err, control.ErrResourceCapacity):
		return ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE,
			ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_RESOURCE_UNAVAILABLE
	default:
		// 认不出来的错误归一化为 INTERNAL + UNSPECIFIED reason.
		// 不猜一个具体原因: 猜错会让客户端按错误的策略退避或抢占.
		return ipcv1.StatusCode_STATUS_CODE_INTERNAL,
			ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_UNSPECIFIED
	}
}

func acquireFailure(reqID uint64, code ipcv1.StatusCode, reason ipcv1.ControlLeaseErrorReason) *ipcv1.Envelope {
	detail, err := proto.Marshal(&ipcv1.ControlLeaseErrorDetail{Reason: reason})
	if err != nil {
		// 编不出 detail 是本端 bug; 仍然要回一个失败, 不能让调用方永远等
		detail = nil
	}
	return &ipcv1.Envelope{Body: &ipcv1.Envelope_AcquireControlResult{
		AcquireControlResult: &ipcv1.AcquireControlResult{
			RequestId: reqID,
			Outcome: &ipcv1.AcquireControlResult_Failure{Failure: &ipcv1.Failure{
				Code:        code,
				ErrorDetail: detail,
			}},
		},
	}}
}

func releaseFailure(reqID uint64, code ipcv1.StatusCode) *ipcv1.Envelope {
	return &ipcv1.Envelope{Body: &ipcv1.Envelope_ReleaseControlResult{
		ReleaseControlResult: &ipcv1.ReleaseControlResult{
			RequestId: reqID,
			Outcome:   &ipcv1.ReleaseControlResult_Failure{Failure: &ipcv1.Failure{Code: code}},
		},
	}}
}
