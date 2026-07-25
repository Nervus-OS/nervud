// 本文件是 ControlLease 的 wire 接线：把 Envelope 的 AcquireControl(70) /
// ReleaseControl(72) 接到 internal/control 的租约状态机上。
//
// # 为什么这条线以前是断的
//
// control 模块本身早已完整（申请/续租/释放/抢占/deadman/epoch 递增，1200 行
// 源码 + 1000 行测试），但 nervud 的 conn 状态机从来没有处理过这四个 body——
// 内核甚至一度钉在没有这几个消息的旧 protocol 版本上。结果是：租约逻辑写完了
// 却没有任何入口，App 拿不到运动 lease，而 operation.Manager 的 LeaseValidator
// 只能注入 nil，导致【全部运动类 operation 被前置拒绝】。
//
// 本文件补的就是那一段。
//
// # 租约是连接作用域的
//
// lease_id 绑本连接、不可转让，连接断开即失效（envelope.proto:
// AcquireControlSuccess.lease_id）。因此 conn 收尾时必须 RevokeConn——否则一个
// 断了线的 App 仍然"持有"执行器控制权，谁也抢不走，直到 TTL 自然到期。
package ipc

import (
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	ipcv1 "github.com/nervus-os/nervus-ipc/go/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/control"
)

// handleAcquireControl 处理一次租约申请。
func (co *conn) handleAcquireControl(req *ipcv1.AcquireControl) bool {
	reqID := req.GetRequestId()

	if co.s.leases == nil {
		// control 未接线（测试/裁剪构建）。回 UNAVAILABLE 而不是关连接：
		// 这是能力缺口不是协议违规，客户端重试或降级都合理。
		return co.enqueue(acquireFailure(reqID,
			ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE,
			ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_RESOURCE_UNAVAILABLE))
	}

	class, ok := classFromWire(req.GetControllerClass())
	if !ok {
		// UNSPECIFIED 或未知值。fail closed：不替客户端猜一个类别——
		// 猜错的后果是把一个 AI 会话当成人在操作，抢占矩阵会给它错误的优先级。
		return co.enqueue(acquireFailure(reqID,
			ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
			ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_INVALID_CONTROLLER))
	}

	// Resource 解析：空 selector 按协议取隐式默认（BaseMotion 的 base.main）。
	// 与 ResolveEndpoint 的 selector 语义保持一致，否则同一个「留空」在两条
	// 路径上含义不同，是最容易写出 bug 的那类不一致。
	resource, ok := co.s.resolveLeaseResource(req.GetResource())
	if !ok {
		return co.enqueue(acquireFailure(reqID,
			ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_RESOURCE_UNAVAILABLE))
	}

	// ⚠ v1：直接采信客户端声明的 controller_class，只记审计。
	//
	// 这与 control/class.go 的「Class 必须由可信调用方根据身份与权限裁决后传入，
	// 不能接受客户端自报值」【暂时不一致】，是一个有意识的 v1 取舍：
	// permission.V1GrantAll 当前把权限执法整体短路了（申请即授予），此刻加一道
	// class 门槛只是做样子——它会无条件放行，却让人以为有防护。
	//
	// 执法恢复（V1GrantAll = false）时必须一并补上：在 permission.DefaultCatalog
	// 里登记 class 对应的权限，并在这里查。grep CONTROL_CLASS_SELF_REPORTED
	// 能找到全部相关位置。
	co.s.auditLeaseClass(co.caller, class, resource)

	lease, err := co.s.leases.Acquire(control.Request{
		Conn:     co.leaseConnID(),
		Class:    class,
		Resource: resource,
		Owner:    co.caller,
		// TTL/Deadman 留 0 = 沿用 Policy 默认。
		//
		// 刻意【不】透传 requested_deadline_nanos：协议说那是「期望值不是承诺」，
		// 而 control.Request 的约定是「非 0 时只能比 Policy 更严，超限即拒绝」。
		// 把一个客户端期望值直接塞进去，会让一个想要更长租约的请求变成硬失败，
		// 而不是被 Policy 收紧——那不是协议要的语义。
		// 真要支持缩短，应当先判断它是否小于 Policy 默认再传，留待 v2。
	})
	if err != nil {
		code, reason := leaseErrToWire(err)
		return co.enqueue(acquireFailure(reqID, code, reason))
	}

	return co.enqueue(&ipcv1.Envelope{Body: &ipcv1.Envelope_AcquireControlResult{
		AcquireControlResult: &ipcv1.AcquireControlResult{
			RequestId: reqID,
			Outcome: &ipcv1.AcquireControlResult_Success{Success: &ipcv1.AcquireControlSuccess{
				// lease_id 上 wire 是 uint64，而 control.ID 是 [16]byte。
				// 用连接内单调递增的句柄映射，不把内部 ID 泄漏出去——
				// 与 endpoint_id 同一原则：查找键是 (连接, 句柄)。
				LeaseId:        co.registerLease(lease),
				MotionEpoch:    lease.Epoch,
				DeadlineNanos:  lease.Deadline.UnixNano(),
				ResourceHandle: lease.Resource,
			}},
		},
	}})
}

// handleReleaseControl 处理一次主动释放。
func (co *conn) handleReleaseControl(req *ipcv1.ReleaseControl) bool {
	reqID := req.GetRequestId()

	if co.s.leases == nil {
		return co.enqueue(releaseFailure(reqID, ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE))
	}

	id, ok := co.lookupLease(req.GetLeaseId())
	if !ok {
		// 不是本连接持有的 lease_id。协议规定 FAILED_PRECONDITION。
		// 【不关连接】：一个过期/已被抢占的 lease_id 被释放是正常时序
		// （客户端还没收到撤销通知），当协议违规处理会频繁踢掉正常客户端。
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

// classFromWire 把 wire 的 ControllerClass 翻成 control.Class。
//
// 未知值一律 fail closed：协议明说「未指定或未知值一律 fail closed」，
// 而这里猜错的后果是抢占矩阵用错优先级——把 AI 当人，或反过来。
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

// leaseErrToWire 把 control 的错误翻成 (StatusCode, typed reason)。
//
// 外层 code 决定 SDK 的恢复行为，typed reason 决定客户端该退避还是该抢占——
// envelope.proto 明说「调用者需要『被谁占着』这类可区分原因才知道该退避还是
// 该抢占，笼统 BUSY 不够」。两者必须一致。
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
	default:
		// 认不出来的错误归一化为 INTERNAL + UNSPECIFIED reason。
		// 不猜一个具体原因：猜错会让客户端按错误的策略退避或抢占。
		return ipcv1.StatusCode_STATUS_CODE_INTERNAL,
			ipcv1.ControlLeaseErrorReason_CONTROL_LEASE_ERROR_REASON_UNSPECIFIED
	}
}

func acquireFailure(reqID uint64, code ipcv1.StatusCode, reason ipcv1.ControlLeaseErrorReason) *ipcv1.Envelope {
	detail, err := proto.Marshal(&ipcv1.ControlLeaseErrorDetail{Reason: reason})
	if err != nil {
		// 编不出 detail 是本端 bug；仍然要回一个失败，不能让调用方永远等
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

// leaseDeadlineFallback 仅用于 Deadline 零值时给一个可解释的 wire 值。
// 正常路径上 control 一定填了 Deadline，这里只是防御性兜底。
var leaseDeadlineFallback = time.Time{}
