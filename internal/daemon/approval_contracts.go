package daemon

import (
	"context"

	"github.com/kovyrin/agent-secret/internal/peercred"
)

type ApprovalEndpoint interface {
	FetchPending(ctx context.Context, peer peercred.Info) (ApprovalRequestPayload, error)
	SubmitDecision(ctx context.Context, peer peercred.Info, decision ApprovalDecisionPayload) error
}

type ApproverLauncher interface {
	Launch(ctx context.Context, socketPath string, payload ApprovalRequestPayload) (ExpectedApprover, error)
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
	signatureVerifier codeSignatureVerifier
	exited            <-chan error
}
