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
		// operationsWired 是装配事实：本次构造有没有 Operation Manager。
		operationsWired bool
		want            error
	}{
		{name: "nil metadata", want: ErrNilMethodMeta},
		{
			// 【没接线时长任务必须被拒】，不是降级成普通调用：降级会让调用方
			// 拿到一个 OK 而机器还在动，它以为已经做完了。
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
			name: "confirmation",
			meta: &ipcv1.MethodMeta{NeedsUserConfirmation: true},
			want: ErrConfirmationUnsupported,
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
			// 【普通方法回 ACCEPTED 仍然违规】：那意味着它声称创建了一个
			// 没人拥有的长任务。
			name: "plain method cannot accept",
			meta: supported, outcome: ProviderOutcomeSuccess,
			code: ipcv1.StatusCode_STATUS_CODE_ACCEPTED,
			want: ErrProviderStatus,
		},
		{
			// 长任务可以。nervud 在 Dispatch 之前就建好了 Operation，
			// 「必须先存在」这个前提由顺序保证。
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
			name:    "unsupported confirmation is rejected before status",
			meta:    &ipcv1.MethodMeta{NeedsUserConfirmation: true},
			outcome: ProviderOutcomeSuccess,
			code:    ipcv1.StatusCode_STATUS_CODE_OK,
			want:    ErrConfirmationUnsupported,
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
