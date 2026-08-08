package protocheck

import (
	"errors"
	"fmt"

	"github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

var (
	// ErrNilMethodMeta reports that no authoritative method policy was supplied.
	ErrNilMethodMeta = errors.New("protocheck: nil method metadata")

	// ErrOperationUnsupported 表示本次装配没有 Operation Manager.
	//
	// 它不再是"协议未实现" - wire 契约与 Provider 回报路径都已落地
	//  (nervus.interface.operation.control). 剩下的唯一情形是最小装配
	// 或测试没有注入 Manager, 此时必须拒绝而不是降级成普通调用:
	// 降级会让调用方拿到一个 OK, 而机器还在动, 它以为已经做完了.
	ErrOperationUnsupported = errors.New("protocheck: operation manager is not wired")

	// ErrConfirmationUnsupported is fail-closed until Request carries a
	// kernel-verifiable, single-use confirmation capability.
	ErrConfirmationUnsupported = errors.New("protocheck: user-confirmed methods are unsupported")

	// ErrProviderStatus reports an outcome/code combination that a Provider is
	// not authorized to produce.
	ErrProviderStatus = errors.New("protocheck: invalid provider status")
)

// ProviderOutcome identifies the DispatchResult oneof branch being checked.
type ProviderOutcome uint8

const (
	ProviderOutcomeUnspecified ProviderOutcome = iota
	ProviderOutcomeSuccess
	ProviderOutcomeFailure
)

// GateSupport rejects MethodMeta features for which the current IPC contract
// cannot provide end-to-end enforcement. It must run before dispatch.
//
// operationsWired 说明本次装配有没有 Operation Manager. 它是装配事实而不是
// 调用方输入 - 把它做成参数而不是包级变量, 是为了让"没接线"在测试里可构造,
// 同时不给生产留一个可以运行期翻转的开关.
func GateSupport(meta *ipcv1.MethodMeta, operationsWired bool) error {
	if meta == nil {
		return ErrNilMethodMeta
	}
	if meta.GetReturnsOperation() && !operationsWired {
		return ErrOperationUnsupported
	}
	if meta.GetNeedsUserConfirmation() {
		return ErrConfirmationUnsupported
	}
	return nil
}

// ValidateProviderStatus enforces the Provider-owned subset of StatusCode.
//
// 普通方法只能以 OK 完成. ACCEPTED 曾经完全归内核, 理由是"Operation 必须先
// 存在才谈得上这个应答" - 现在那个前提被顺序保证了: nervud 在 Dispatch
// 之前就建好 Operation 并把 operation_id 放进 ExecutionContext, Provider
// 收到 Dispatch 时它已经存在.
//
// 所以 ACCEPTED 对 returns_operation 的方法是合法的, 且只对它合法:
// 一个普通方法回 ACCEPTED 意味着它声称创建了一个没人拥有的长任务.
//
// 身份与权限裁决仍然完全归内核.
func ValidateProviderStatus(
	meta *ipcv1.MethodMeta, outcome ProviderOutcome, code ipcv1.StatusCode,
	operationsWired bool,
) error {
	if err := GateSupport(meta, operationsWired); err != nil {
		return err
	}

	switch outcome {
	case ProviderOutcomeSuccess:
		if code == ipcv1.StatusCode_STATUS_CODE_OK {
			return nil
		}
		if code == ipcv1.StatusCode_STATUS_CODE_ACCEPTED && meta.GetReturnsOperation() {
			return nil
		}
	case ProviderOutcomeFailure:
		switch code {
		case ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
			ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
			ipcv1.StatusCode_STATUS_CODE_FAILED_PRECONDITION,
			ipcv1.StatusCode_STATUS_CODE_RESOURCE_EXHAUSTED,
			ipcv1.StatusCode_STATUS_CODE_DEADLINE_EXCEEDED,
			ipcv1.StatusCode_STATUS_CODE_CANCELLED,
			ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE,
			ipcv1.StatusCode_STATUS_CODE_INTERNAL:
			return nil
		}
	case ProviderOutcomeUnspecified:
	}

	return fmt.Errorf("%w: outcome=%d code=%s", ErrProviderStatus, outcome, code)
}
