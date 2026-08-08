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

	// ErrConfirmationUnauthorized 表示调用方无权触发一个需要用户确认的方法.
	//
	// 这里曾经是无条件拒绝 (ErrConfirmationUnsupported): 没有任何界面能向用户
	// 提问, 于是 needs_user_confirmation 的方法对所有调用方都不可达 - 包括
	// pkgmanagerd 的 INSTALL/UNINSTALL/SET_COMPONENT_ENABLED, 因此经 IPC 装包
	// 这件事整个是死的.
	//
	// 现在的判据是"调用方就是系统确认 UI 自己". 见 GateUserConfirmation
	ErrConfirmationUnauthorized = errors.New("protocheck: caller may not invoke user-confirmed methods")

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
//
// 本函数【只回答装配能力】, 不回答调用方资格: 它同时跑在请求分派前与 Provider
// 回报的复核路径上 (ValidateProviderStatus), 而后者手上没有调用方. 资格那一问
// 归 GateUserConfirmation, 只在分派时查一次
func GateSupport(meta *ipcv1.MethodMeta, operationsWired bool) error {
	if meta == nil {
		return ErrNilMethodMeta
	}
	if meta.GetReturnsOperation() && !operationsWired {
		return ErrOperationUnsupported
	}
	return nil
}

// GateUserConfirmation 裁决一次对 needs_user_confirmation 方法的调用. 只在请求
// 分派时调用一次, 不在 Provider 回报路径上复核.
//
// callerIsConfirmationUI 由调用方持有 perm.permission.admin 判定. 这条权限是
// SYSTEM_ONLY + PLATFORM 信任 + platform-release 签名角色, 因此持有者只可能是
// 随系统镜像发布的确认 UI 本身 (nervus.permissionui).
//
// # 为什么"是确认 UI"就等于"已确认"
//
// 确认 UI 在发起这次调用之前, 刚刚把待确认的内容显示给用户并拿到了点头 - 它
// 就是那个提问的人. 对它再要一份"用户已确认"的凭据, 只是要它自己给自己签一张
// 条子, 不增加任何保证.
//
// 其余调用方一律拒绝, 安全边界与之前的无条件拒绝完全一致: 一个普通应用仍然
// 无法直接触发装包, 它只能去请确认 UI 代为发起. 这也让确认 UI 成为所有需确认
// 操作的强制漏斗.
//
// 将来若第三方调用方也需要直接触发需确认操作, 再补一条由确认 UI 签发, 内核
// 可核验的一次性凭据 - 那是在本判据之上做加法, 不推翻它
func GateUserConfirmation(meta *ipcv1.MethodMeta, callerIsConfirmationUI bool) error {
	if meta == nil {
		return ErrNilMethodMeta
	}
	if meta.GetNeedsUserConfirmation() && !callerIsConfirmationUI {
		return ErrConfirmationUnauthorized
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
