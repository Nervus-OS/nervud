package protocheck

import (
	"errors"
	"fmt"

	ipcv1 "github.com/nervus-os/nervus-ipc/protocol/ipcv1"
)

var (
	// ErrNilMethodMeta reports that no authoritative method policy was supplied.
	ErrNilMethodMeta = errors.New("protocheck: nil method metadata")

	// ErrOperationUnsupported is fail-closed until the Operation wire contract
	// and Provider reporting path are implemented.
	ErrOperationUnsupported = errors.New("protocheck: operation-returning methods are unsupported")

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
func GateSupport(meta *ipcv1.MethodMeta) error {
	if meta == nil {
		return ErrNilMethodMeta
	}
	if meta.GetReturnsOperation() {
		return ErrOperationUnsupported
	}
	if meta.GetNeedsUserConfirmation() {
		return ErrConfirmationUnsupported
	}
	return nil
}

// ValidateProviderStatus enforces the Provider-owned subset of StatusCode.
//
// A Provider may only complete a non-operation method with OK. ACCEPTED is
// kernel-owned because an Operation must exist before that acknowledgement is
// emitted. Authentication and permission decisions are also kernel-owned.
func ValidateProviderStatus(meta *ipcv1.MethodMeta, outcome ProviderOutcome, code ipcv1.StatusCode) error {
	if err := GateSupport(meta); err != nil {
		return err
	}

	switch outcome {
	case ProviderOutcomeSuccess:
		if code == ipcv1.StatusCode_STATUS_CODE_OK {
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
	}

	return fmt.Errorf("%w: outcome=%d code=%s", ErrProviderStatus, outcome, code)
}
