package protocheck

import (
	"errors"
	"testing"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

func TestGateSupportFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		meta *ipcv1.MethodMeta

		operationsWired bool
		want            error
	}{
		{name: "nil metadata", want: ErrNilMethodMeta},
		{

			name: "operation without manager",
			meta: &ipcv1.MethodMeta{ReturnsOperation: true},
			want: ErrOperationUnsupported,
		},
		{
			name:            "operation with manager",
			meta:            &ipcv1.MethodMeta{ReturnsOperation: true},
			operationsWired: true,
		},
		{
			// 调用方资格归 GateUserConfirmation, 本函数只管装配能力.
			// 这条钉住"不要把资格判定挪回来" —— 挪回来会让 Provider 回报的
			// 复核路径 (ValidateProviderStatus, 手上没有调用方) 一律拒绝
			name: "confirmation is not a support question",
			meta: &ipcv1.MethodMeta{NeedsUserConfirmation: true},
		},
		{name: "supported", meta: &ipcv1.MethodMeta{}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := GateSupport(test.meta, test.operationsWired)
			if test.want == nil {
				if err != nil {
					t.Fatalf("GateSupport() error = %v", err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("GateSupport() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestGateUserConfirmation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		meta *ipcv1.MethodMeta

		callerIsConfirmationUI bool
		want                   error
	}{
		{name: "nil metadata", want: ErrNilMethodMeta},
		{
			// 死锁 B 的回归钉: 普通调用方触发需确认方法必须被拒,
			// 否则任何应用都能绕过确认屏直接装包
			name: "confirmation without authority",
			meta: &ipcv1.MethodMeta{NeedsUserConfirmation: true},
			want: ErrConfirmationUnauthorized,
		},
		{
			// 死锁 B 的解除钉: 确认 UI 自己必须放行,
			// 否则经 IPC 装包对所有人都不通 (改动前就是这样)
			name:                   "confirmation by the confirmation ui",
			meta:                   &ipcv1.MethodMeta{NeedsUserConfirmation: true},
			callerIsConfirmationUI: true,
		},
		{
			// 不需确认的方法不因为调用方没有该权限而被牵连
			name: "method needs no confirmation",
			meta: &ipcv1.MethodMeta{},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := GateUserConfirmation(test.meta, test.callerIsConfirmationUI)
			if test.want == nil {
				if err != nil {
					t.Fatalf("GateUserConfirmation() error = %v", err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("GateUserConfirmation() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestValidateProviderStatus(t *testing.T) {
	t.Parallel()

	supported := &ipcv1.MethodMeta{}
	tests := []struct {
		name            string
		meta            *ipcv1.MethodMeta
		outcome         ProviderOutcome
		code            ipcv1.StatusCode
		operationsWired bool
		want            error
	}{
		{
			name: "success OK",
			meta: supported, outcome: ProviderOutcomeSuccess,
			code: ipcv1.StatusCode_STATUS_CODE_OK,
		},
		{

			name: "plain method cannot accept",
			meta: supported, outcome: ProviderOutcomeSuccess,
			code: ipcv1.StatusCode_STATUS_CODE_ACCEPTED,
			want: ErrProviderStatus,
		},
		{

			name:            "operation method may accept",
			meta:            &ipcv1.MethodMeta{ReturnsOperation: true},
			outcome:         ProviderOutcomeSuccess,
			code:            ipcv1.StatusCode_STATUS_CODE_ACCEPTED,
			operationsWired: true,
		},
		{
			name: "failure invalid argument",
			meta: supported, outcome: ProviderOutcomeFailure,
			code: ipcv1.StatusCode_STATUS_CODE_INVALID_ARGUMENT,
		},
		{
			name: "failure cancelled",
			meta: supported, outcome: ProviderOutcomeFailure,
			code: ipcv1.StatusCode_STATUS_CODE_CANCELLED,
		},
		{
			name: "provider cannot deny permission",
			meta: supported, outcome: ProviderOutcomeFailure,
			code: ipcv1.StatusCode_STATUS_CODE_PERMISSION_DENIED,
			want: ErrProviderStatus,
		},
		{
			name: "provider cannot unauthenticate",
			meta: supported, outcome: ProviderOutcomeFailure,
			code: ipcv1.StatusCode_STATUS_CODE_UNAUTHENTICATED,
			want: ErrProviderStatus,
		},
		{
			name: "zero status",
			meta: supported, outcome: ProviderOutcomeFailure,
			code: ipcv1.StatusCode_STATUS_CODE_UNSPECIFIED,
			want: ErrProviderStatus,
		},
		{
			name: "unknown outcome",
			meta: supported, outcome: ProviderOutcomeUnspecified,
			code: ipcv1.StatusCode_STATUS_CODE_OK,
			want: ErrProviderStatus,
		},
		{
			name:    "unsupported operation is rejected before status",
			meta:    &ipcv1.MethodMeta{ReturnsOperation: true},
			outcome: ProviderOutcomeSuccess,
			code:    ipcv1.StatusCode_STATUS_CODE_ACCEPTED,
			want:    ErrOperationUnsupported,
		},
		{
			// Provider 回报路径不复核调用方资格: 走到这里说明分派时
			// GateUserConfirmation 已经放行过, 再拒一次只会让确认 UI
			// 发起的合法调用拿不到结果
			name:    "confirmation result is not re-litigated here",
			meta:    &ipcv1.MethodMeta{NeedsUserConfirmation: true},
			outcome: ProviderOutcomeSuccess,
			code:    ipcv1.StatusCode_STATUS_CODE_OK,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateProviderStatus(test.meta, test.outcome, test.code, test.operationsWired)
			if test.want == nil {
				if err != nil {
					t.Fatalf("ValidateProviderStatus() error = %v", err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateProviderStatus() error = %v, want %v", err, test.want)
			}
		})
	}
}
