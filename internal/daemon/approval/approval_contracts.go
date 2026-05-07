package approval

import (
	"context"

	"github.com/kovyrin/agent-secret/internal/daemon/trust"
	"github.com/kovyrin/agent-secret/internal/peercred"
)

type Approver interface {
	// Approve returns Decision{Approved: false}, nil for user denial.
	// Errors are reserved for approval failures such as timeout, launch failure,
	// cancellation, or malformed approval traffic.
	Approve(ctx context.Context, payload ApprovalRequestPayload) (Decision, error)
}

type Decision struct {
	Approved     bool
	Reusable     bool
	ReusableUses int
	DenialReason DenialReason
}

type ApprovalEndpoint interface {
	FetchPending(ctx context.Context, peer peercred.Info) (ApprovalRequestPayload, error)
	SubmitDecision(ctx context.Context, peer peercred.Info, decision ApprovalDecisionPayload) error
}

type ApproverLauncher interface {
	Launch(ctx context.Context, socketPath string) (ExpectedApprover, error)
}

type ApproverIdentityPolicy interface {
	ValidateApproverExecutable(path string) (ApproverIdentity, error)
}

type ApproverIdentity struct {
	ExecutablePath  string
	BundlePath      string
	BundleID        string
	TeamID          string
	ExpectedTeamID  string
	VerifySignature bool
}

type ExpectedApprover struct {
	PID               int
	ExecutablePath    string
	ExpectedTeamID    string
	VerifySignature   bool
	Exited            <-chan error
	SignatureVerifier trust.CodeSignatureVerifier
}
