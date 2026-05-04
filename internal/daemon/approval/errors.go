package approval

import "errors"

var (
	ErrApprovalDenied       = errors.New("approval denied")
	ErrApproverLaunchFailed = errors.New("approver launch failed")
	ErrApproverIdentity     = errors.New("approver identity mismatch")
	ErrApproverPeerMismatch = errors.New("approver peer identity mismatch")
	ErrNoPendingApproval    = errors.New("no pending approval request")
	ErrRequestExpired       = errors.New("request expired")
	ErrStaleApproval        = errors.New("stale approval response")
)
