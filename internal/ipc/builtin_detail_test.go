package ipc

import (
	"testing"

	operationv1 "github.com/nervus-os/nervus-ipc/protocol/interface/operationv1"
	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
	"google.golang.org/protobuf/proto"

	"github.com/nervus-os/nervud/internal/catalog"
	"github.com/nervus-os/nervud/internal/endpoint"
)

//

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

//

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
		t.Fatal("unexpected ipc result; detail")
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
		t.Fatalf("unexpected ipc result; detail: %v", err)
	}
	if detail.GetReason() != operationv1.OperationReason_OPERATION_REASON_NOT_FOUND {
		t.Fatalf("reason = %v", detail.GetReason())
	}
}

func TestBuiltinDetail_AbsentIsFine(t *testing.T) {
	s := &Server{log: discardLog()}
	route := detailRoute(t, string(
		(&operationv1.OperationErrorDetail{}).ProtoReflect().Descriptor().FullName()))

	resp, ok := s.validateBuiltinResult(7, route, endpoint.BuiltinResult{
		Code: ipcv1.StatusCode_STATUS_CODE_UNAVAILABLE,
	})
	if !ok {
		t.Fatal("unexpected ipc result; detail")
	}
	if len(resp.GetFailure().GetErrorDetail()) != 0 {
		t.Fatal("unexpected ipc result; detail")
	}
}

//

func TestBuiltinDetail_RejectedWhenContractDeclaresNone(t *testing.T) {
	s := &Server{log: discardLog()}
	route := detailRoute(t, "")

	resp, ok := s.validateBuiltinResult(7, route, endpoint.BuiltinResult{
		Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,
		ErrorDetail: mustDetailBytes(t,
			operationv1.OperationReason_OPERATION_REASON_NOT_FOUND),
	})
	if ok {
		t.Fatal("unexpected ipc result; error_detail_type detail")
	}
	if resp.GetFailure().GetCode() != ipcv1.StatusCode_STATUS_CODE_INTERNAL {
		t.Fatalf("unexpected ipc result; code = %v, want INTERNAL bug", resp.GetFailure().GetCode())
	}
}

//

func TestBuiltinDetail_MalformedIsRejected(t *testing.T) {
	s := &Server{log: discardLog()}
	route := detailRoute(t, string(
		(&operationv1.OperationErrorDetail{}).ProtoReflect().Descriptor().FullName()))

	resp, ok := s.validateBuiltinResult(7, route, endpoint.BuiltinResult{
		Code: ipcv1.StatusCode_STATUS_CODE_NOT_FOUND,

		ErrorDetail: []byte{0x0a, 0x7f, 0x01},
	})
	if ok {
		t.Fatal("unexpected ipc result; detail")
	}
	if resp.GetFailure().GetCode() != ipcv1.StatusCode_STATUS_CODE_INTERNAL {
		t.Fatalf("code = %v, want INTERNAL", resp.GetFailure().GetCode())
	}
}

//

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

		ErrorDetail: mustDetailBytes(t,
			operationv1.OperationReason_OPERATION_REASON_NOT_FOUND),
	})
	if !ok {
		t.Fatal("unexpected ipc result")
	}
	success := resp.GetSuccess()
	if success == nil {
		t.Fatalf("want success, got %+v", resp.GetOutcome())
	}
	var got operationv1.OperationStatus
	if err := proto.Unmarshal(success.GetPayload(), &got); err != nil {
		t.Fatalf("unexpected ipc result; payload: %v", err)
	}
	if got.GetOperationId() != 3 {
		t.Fatalf("operation_id = %d, want 3", got.GetOperationId())
	}
}
