package approval

import "errors"

var (
	ErrApproverLaunchFailed = errors.New("approver launch failed")
	ErrApproverIdentity     = errors.New("approver identity mismatch")
	ErrApproverPeerMismatch = errors.New("approver peer identity mismatch")
	ErrNoPendingApproval    = errors.New("no pending approval request")
	ErrStaleApproval        = errors.New("stale approval response")
)
