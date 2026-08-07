package ipc

import (
	"testing"

	operationv1 "github.com/nervus-os/nervus-ipc/protocol/interface/operationv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/endpoint"
)

// 内建 endpoint 的 typed error_detail。
//
// 【外部 Provider 的 detail 被整条拒绝，内建的不】。差别不是信任等级，是
// 那条顾虑在这里根本不成立：Provider 的 detail 来自另一个进程，StatusCode 与
// domain reason 之间没有机器可读的授权关系，一份 detail 看起来「已认证」却
// 语义无据；内建的 detail 由内核代码生成，与 Code 出自同一处判定。

// detailRoute 造一条声明了 error_detail_type 的内建路由。
func detailRoute(t *testing.T, errorDetailType string) endpoint.RouteInfo {
	t.Helper()
	detailDescriptor := (&operationv1.OperationErrorDetail{}).ProtoReflect().Descriptor()
	responseDescriptor := (&operationv1.OperationStatus{}).ProtoReflect().Descriptor()
	return endpoint.RouteInfo{
		InterfaceID:    "nervus.interface.operation.control",
		InterfaceMajor: 1,
		Method: catalog.MethodDefinition{
			InterfaceID: "nervus.interface.operation.control",
			Major:       1,
			MethodID:    1,
			Meta: &ipcv1.MethodMeta{
				MethodId:        1,
				RiskClass:       ipcv1.RiskClass_RISK_CLASS_NORMAL,
				ResponseType:    string(responseDescriptor.FullName()),
				ErrorDetailType: errorDetailType,
			},
			Response:    responseDescriptor,
			ErrorDetail: detailDescriptor,
		},
	}
}

func mustDetailBytes(t *testing.T, reason operationv1.OperationReason) []byte {
	t.Helper()
	wire, err := proto.Marshal(&operationv1.OperationErrorDetail{Reason: reason})
	if err != nil {
		t.Fatalf("marshal detail: %v", err)
	}
	return wire
}

// 内建给出的 typed detail 必须原样到达调用方。
//
// 丢掉它的后果很具体：调用方拿到一个裸 NOT_FOUND，分不清「这个 operation
// 从来不存在」和「它已经过了终态保留期被回收」——而两者的处置相反。
func TestBuiltinDetail_ForwardedToCaller(t *testing.T) {
	s := &Server{log: discardLog()}
	route := detailRoute(t, string(
		(&operationv1.OperationErrorDetail{}).ProtoReflect().Descriptor().FullName()))

	resp, ok := s.validateBuiltinResult(7, route, endpoint.BuiltinResult{
		Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
		ErrorDetail: mustDetailBytes(t,
			operationv1.OperationReason_OPERATION_REASON_NOT_FOUND),
	})
	if !ok {
		t.Fatal("合法的内建 detail 被当成契约违规")
	}
	failure := resp.GetFailure()
	if failure == nil {
		t.Fatalf("want failure, got %+v", resp.GetOutcome())
	}
	if failure.GetCode() != ipcv1.StatusCode_STATUS_CODE_NOT_FOUND {
		t.Fatalf("code = %v", failure.GetCode())
	}

	var detail operationv1.OperationErrorDetail
	if err := proto.Unmarshal(failure.GetErrorDetail(), &detail); err != nil {
		t.Fatalf("detail 解不开: %v", err)
	}
	if detail.GetReason() != operationv1.OperationReason_OPERATION_REASON_NOT_FOUND {
		t.Fatalf("reason = %v", detail.GetReason())
	}
}

// 没有 detail 时仍然回一个干净的失败——detail 是可选的。
func TestBuiltinDetail_AbsentIsFine(t *testing.T) {
	s := &Server{log: discardLog()}
	route := detailRoute(t, string(
		(&operationv1.OperationErrorDetail{}).ProtoReflect().Descriptor().FullName()))

	resp, ok := s.validateBuiltinResult(7, route, endpoint.BuiltinResult{
		Code: ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE,
	})
	if !ok {
		t.Fatal("无 detail 的失败被拒")
	}
	if len(resp.GetFailure().GetErrorDetail()) != 0 {
		t.Fatal("凭空多出了一份 detail")
	}
}

// 【契约没声明 error_detail_type，内建却给了一份 → 拒绝】。
//
// 转发它等于让调用方拿到一段不知道该按什么类型解的字节，而它多半会去猜。
func TestBuiltinDetail_RejectedWhenContractDeclaresNone(t *testing.T) {
	s := &Server{log: discardLog()}
	route := detailRoute(t, "") // 契约没声明

	resp, ok := s.validateBuiltinResult(7, route, endpoint.BuiltinResult{
		Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
		ErrorDetail: mustDetailBytes(t,
			operationv1.OperationReason_OPERATION_REASON_NOT_FOUND),
	})
	if ok {
		t.Fatal("未声明 error_detail_type 却转发了 detail")
	}
	if resp.GetFailure().GetCode() != ipcv1.StatusCode_STATUS_CODE_INTERNAL {
		t.Fatalf("code = %v, want INTERNAL（内核装配 bug）", resp.GetFailure().GetCode())
	}
}

// 解不开的 detail 一律拒绝，不做「尽力而为」的转发。
//
// 一段解不开的字节到了调用方那里只有两种下场：解出垃圾，或者抛异常。
// 两者都比一个裸 code 糟。
func TestBuiltinDetail_MalformedIsRejected(t *testing.T) {
	s := &Server{log: discardLog()}
	route := detailRoute(t, string(
		(&operationv1.OperationErrorDetail{}).ProtoReflect().Descriptor().FullName()))

	resp, ok := s.validateBuiltinResult(7, route, endpoint.BuiltinResult{
		Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
		// 字段号 1 声明为 length-delimited，长度前缀指向缓冲区之外
		ErrorDetail: []byte{0x0a, 0x7f, 0x01},
	})
	if ok {
		t.Fatal("畸形 detail 被转发了")
	}
	if resp.GetFailure().GetCode() != ipcv1.StatusCode_STATUS_CODE_INTERNAL {
		t.Fatalf("code = %v, want INTERNAL", resp.GetFailure().GetCode())
	}
}

// 成功路径【不看 ErrorDetail】：那是失败时的字段。
//
// 两个字段分开的意义就在这里——复用一个的话，「这段字节该按 response_type
// 还是 error_detail_type 解」就取决于 Code，而那是个要读实现才知道的约定。
func TestBuiltinDetail_SuccessIgnoresErrorDetail(t *testing.T) {
	s := &Server{log: discardLog()}
	route := detailRoute(t, string(
		(&operationv1.OperationErrorDetail{}).ProtoReflect().Descriptor().FullName()))

	status, err := proto.Marshal(&operationv1.OperationStatus{OperationId: 3})
	if err != nil {
		t.Fatal(err)
	}
	resp, ok := s.validateBuiltinResult(7, route, endpoint.BuiltinResult{
		Code:    ipcv1.StatusCode_STATUS_CODE_OK,
		Payload: status,
		// 成功时填了 ErrorDetail 是调用方代码的疏忽，但它不该改变结果。
		ErrorDetail: mustDetailBytes(t,
			operationv1.OperationReason_OPERATION_REASON_NOT_FOUND),
	})
	if !ok {
		t.Fatal("成功响应被拒")
	}
	success := resp.GetSuccess()
	if success == nil {
		t.Fatalf("want success, got %+v", resp.GetOutcome())
	}
	var got operationv1.OperationStatus
	if err := proto.Unmarshal(success.GetPayload(), &got); err != nil {
		t.Fatalf("payload 解不开: %v", err)
	}
	if got.GetOperationId() != 3 {
		t.Fatalf("operation_id = %d, want 3", got.GetOperationId())
	}
}
