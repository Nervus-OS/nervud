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
		want error
	}{
		{name: "nil metadata", want: ErrNilMethodMeta},
		{
			name: "operation",
			meta: &ipcv1.MethodMeta{ReturnsOperation: true},
			want: ErrOperationUnsupported,
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
			err := GateSupport(test.meta)
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
		name    string
		meta    *ipcv1.MethodMeta
		outcome ProviderOutcome
		code    ipcv1.StatusCode
		want    error
	}{
		{
			name: "success OK",
			meta: supported, outcome: ProviderOutcomeSuccess,
			code: ipcv1.StatusCode_STATUS_CODE_OK,
		},
		{
			name: "provider cannot accept operation",
			meta: supported, outcome: ProviderOutcomeSuccess,
			code: ipcv1.StatusCode_STATUS_CODE_ACCEPTED,
			want: ErrProviderStatus,
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
			err := ValidateProviderStatus(test.meta, test.outcome, test.code)
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
