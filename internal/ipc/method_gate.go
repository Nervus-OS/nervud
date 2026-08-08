package ipc

import (
	"context"
	"errors"
	"fmt"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"

	"github.com/nervus-os/nervud/internal/audit"
	"github.com/nervus-os/nervud/internal/endpoint"
	"github.com/nervus-os/nervud/internal/identity"
	"github.com/nervus-os/nervud/internal/protocheck"
)

func methodGateCode(err error) ipcv1.StatusCode {
	switch {
	case errors.Is(err, protocheck.ErrOperationUnsupported),
		errors.Is(err, protocheck.ErrConfirmationUnauthorized):
		return ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE
	default:
		return ipcv1.StatusCode_STATUS_CODE_INTERNAL
	}
}

func requestValidationCode(err error) ipcv1.StatusCode {
	switch {
	case errors.Is(err, protocheck.ErrNilMethodMeta),
		errors.Is(err, protocheck.ErrDescriptorMismatch):
		return ipcv1.StatusCode_STATUS_CODE_INTERNAL
	case errors.Is(err, protocheck.ErrMessageTooLarge):
		return ipcv1.StatusCode_STATUS_CODE_RESOURCE_EXHAUSTED
	default:
		return ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT
	}
}

func (s *Server) recordMethodGateFailure(
	caller identity.Caller,
	route endpoint.RouteInfo,
	methodID uint32,
	err error,
) {
	s.auditor.Record(context.Background(), audit.Event{
		Action:  "ipc.MethodGateDenied",
		Subject: caller.String(),
		Denied:  true,
		Err:     err,
		Detail: fmt.Sprintf(
			"interface=%s major=%d method_id=%d catalog_revision=%d",
			route.InterfaceID,
			route.InterfaceMajor,
			methodID,
			route.Method.CatalogRevision,
		),
	})
}

// validateDispatchResult applies the authoritative method contract before any
// Provider bytes or transfer credentials reach the caller. false means the
// Provider violated its contract and its control connection must be closed.
func (s *Server) validateDispatchResult(
	entry *routeEntry,
	result *ipcv1.DispatchResult,
) (*ipcv1.Response, bool) {
	meta := entry.route.Method.Meta

	if success := result.GetSuccess(); success != nil {
		if err := protocheck.ValidateProviderStatus(
			meta, protocheck.ProviderOutcomeSuccess, success.GetCode(),
			s.operations != nil); err != nil {
			return s.rejectProviderResult(entry, err)
		}
		// 长任务的 ACCEPTED 走单独一条: 载荷由内核写, 不是 Provider.
		//
		// Provider 不得自己写句柄: operation_id 由 nervud 分配, 状态机也归
		// nervud. 让 Provider 填这个字段等于让它指定"调用方拿到的是哪个
		// operation" - 填错或伪造的后果是取消永远取消不到, 进度永远收不到,
		// 而两边都不报错.
		if meta.GetReturnsOperation() &&
			success.GetCode() == ipcv1.StatusCode_STATUS_CODE_ACCEPTED {
			return s.operationAcceptedResponse(entry, success)
		}

		checked, err := protocheck.ValidateSuccess(
			meta, entry.route.Method.Response, success.GetPayload())
		if err != nil {
			return s.rejectProviderResult(entry, err)
		}
		if err := s.transfer.FinishRoute(
			entry.routeID, true, checked.TransferHandles); err != nil {
			return s.rejectProviderResult(entry, err)
		}
		return &ipcv1.Response{
			RequestId: entry.sourceRequestID,
			Outcome: &ipcv1.Response_Success{Success: &ipcv1.Success{
				Code:    success.GetCode(),
				Payload: checked.Payload,
			}},
		}, true
	}

	if failure := result.GetFailure(); failure != nil {
		if err := protocheck.ValidateProviderStatus(
			meta, protocheck.ProviderOutcomeFailure, failure.GetCode(),
			s.operations != nil); err != nil {
			return s.rejectProviderResult(entry, err)
		}
		if len(failure.GetErrorDetail()) != 0 {
			// The descriptor proves structure, but the current IPC contract has
			// no machine-readable StatusCode -> domain-reason authorization.
			// Rejecting the whole result is safer than forwarding an
			// authenticated-looking but semantically unbound detail.
			if _, err := protocheck.ValidateFailureDetail(
				meta, entry.route.Method.ErrorDetail, failure.GetErrorDetail()); err != nil {
				return s.rejectProviderResult(entry, err)
			}
			return s.rejectProviderResult(entry,
				errors.New("ipc: Provider error_detail has no authorized status mapping"))
		}
		_ = s.transfer.FinishRoute(entry.routeID, false, nil)
		return &ipcv1.Response{
			RequestId: entry.sourceRequestID,
			Outcome: &ipcv1.Response_Failure{Failure: &ipcv1.Failure{
				// PublicMessage is intentionally not forwarded: it is
				// Provider-controlled text, not part of the typed contract.
				Code: failure.GetCode(),
			}},
		}, true
	}

	return s.rejectProviderResult(entry,
		errors.New("ipc: DispatchResult has no outcome"))
}

func (s *Server) validateBuiltinResult(
	requestID uint64,
	route endpoint.RouteInfo,
	result endpoint.BuiltinResult,
) (*ipcv1.Response, bool) {
	if result.Code == ipcv1.StatusCode_STATUS_CODE_OK ||
		result.Code == ipcv1.StatusCode_STATUS_CODE_ACCEPTED {
		if err := protocheck.ValidateProviderStatus(
			route.Method.Meta, protocheck.ProviderOutcomeSuccess, result.Code,
			s.operations != nil); err != nil {
			return internalResponse(requestID), false
		}
		checked, err := protocheck.ValidateSuccess(
			route.Method.Meta, route.Method.Response, result.Payload)
		if err != nil {
			return internalResponse(requestID), false
		}
		return &ipcv1.Response{
			RequestId: requestID,
			Outcome: &ipcv1.Response_Success{Success: &ipcv1.Success{
				Code:    result.Code,
				Payload: checked.Payload,
			}},
		}, true
	}

	if err := protocheck.ValidateProviderStatus(
		route.Method.Meta, protocheck.ProviderOutcomeFailure, result.Code,
		s.operations != nil); err != nil {
		return internalResponse(requestID), false
	}

	// 内建的 typed error_detail. 与外部 Provider 的处置不同: 那一侧整条
	// 拒绝 (StatusCode 与 domain reason 之间没有机器可读的授权关系, 一份来自
	// 外部进程的 detail 看起来已认证却语义无据); 内建的 detail 由内核代码
	// 生成, 与 Code 出自同一处判定, 那条顾虑不成立.
	if len(result.ErrorDetail) == 0 {
		return failureResponse(requestID, result.Code), true
	}
	if route.Method.Meta.GetErrorDetailType() == "" {
		// 契约没声明 error_detail_type, 内建却给了一份. 转发它等于让调用方
		// 拿到一段不知道该按什么类型解的字节 - 而它多半会去猜.
		// 当作内核装配 bug 拒掉, 理由与 Provider 侧同源.
		s.log.Error("ipc: builtin produced an error detail for a method that declares none",
			"interface", route.InterfaceID, "method_id", route.Method.MethodID)
		return internalResponse(requestID), false
	}
	detail, err := protocheck.ValidateFailureDetail(
		route.Method.Meta, route.Method.ErrorDetail, result.ErrorDetail)
	if err != nil {
		s.log.Error("ipc: builtin error detail failed validation",
			"interface", route.InterfaceID, "method_id", route.Method.MethodID, "err", err)
		return internalResponse(requestID), false
	}
	return &ipcv1.Response{
		RequestId: requestID,
		Outcome: &ipcv1.Response_Failure{Failure: &ipcv1.Failure{
			Code: result.Code,
			// PublicMessage 仍然留空: 协议规定它只能由 nervud 从受审计模板
			// 生成, 而 typed detail 已经承载了可区分的原因.
			ErrorDetail: detail,
		}},
	}, true
}

func (s *Server) rejectProviderResult(
	entry *routeEntry,
	err error,
) (*ipcv1.Response, bool) {
	_ = s.transfer.FinishRoute(entry.routeID, false, nil)
	s.auditor.Record(context.Background(), audit.Event{
		Action:  "ipc.ProviderContractViolation",
		Subject: entry.target.caller.String(),
		Denied:  true,
		Err:     err,
		Detail: fmt.Sprintf(
			"route_id=%d interface=%s major=%d method_id=%d provider=%s",
			entry.routeID,
			entry.route.InterfaceID,
			entry.route.InterfaceMajor,
			entry.methodID,
			entry.route.ProviderPackageID,
		),
	})
	return internalResponse(entry.sourceRequestID), false
}
