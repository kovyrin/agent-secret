package approval

import "errors"

type DenialReason string

const DenialReasonComputerLocked DenialReason = "computer_locked"

type ApprovalDeniedError struct {
	Reason DenialReason
}

func (e ApprovalDeniedError) Error() string {
	switch e.Reason {
	case DenialReasonComputerLocked:
		return "Denied: Computer is locked, human approval is impossible"
	default:
		return ErrApprovalDenied.Error()
	}
}

func (e ApprovalDeniedError) Unwrap() error {
	return ErrApprovalDenied
}

func DenialError(reason DenialReason) error {
	if reason == "" {
		return ErrApprovalDenied
	}
	return ApprovalDeniedError{Reason: reason}
}

var (
	ErrApprovalDenied       = errors.New("approval denied")
	ErrApproverLaunchFailed = errors.New("approver launch failed")
	ErrApproverIdentity     = errors.New("approver identity mismatch")
	ErrApproverPeerMismatch = errors.New("approver peer identity mismatch")
	ErrNoPendingApproval    = errors.New("no pending approval request")
	ErrRequestExpired       = errors.New("request expired")
	ErrStaleApproval        = errors.New("stale approval response")
	ErrUnavailable          = errors.New("approval unavailable")
)
