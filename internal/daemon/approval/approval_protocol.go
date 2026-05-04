package approval

import (
	"fmt"
	"slices"
	"time"

	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/request"
)

type ApprovalRequestPayload struct {
	RequestID              string                    `json:"requestID"`
	Nonce                  string                    `json:"nonce"`
	Reason                 string                    `json:"reason"`
	Command                []string                  `json:"command"`
	CWD                    string                    `json:"cwd"`
	ResolvedExecutable     string                    `json:"resolvedExecutable,omitempty"`
	ExpiresAt              time.Time                 `json:"expiresAt"`
	Secrets                []ApprovalRequestedSecret `json:"secrets"`
	OverrideEnv            bool                      `json:"overrideEnv"`
	OverriddenAliases      []string                  `json:"overriddenAliases"`
	AllowMutableExecutable bool                      `json:"allowMutableExecutable"`
	ReusableUses           int                       `json:"reusableUses"`
}

type ApprovalRequestedSecret struct {
	Alias   string `json:"alias"`
	Ref     string `json:"ref"`
	Account string `json:"account,omitempty"`
}

type ApprovalDecisionKind string

const (
	ApprovalDecisionApproveOnce     ApprovalDecisionKind = "approve_once"
	ApprovalDecisionApproveReusable ApprovalDecisionKind = "approve_reusable"
	ApprovalDecisionDeny            ApprovalDecisionKind = "deny"
	ApprovalDecisionTimeout         ApprovalDecisionKind = "timeout"
)

type ApprovalDecisionPayload struct {
	RequestID    string               `json:"requestID"`
	Nonce        string               `json:"nonce"`
	Decision     ApprovalDecisionKind `json:"decision"`
	ReusableUses *int                 `json:"reusableUses,omitempty"`
}

func ValidateReusableDecisionUses(decision ApprovalDecisionPayload, expected int) error {
	if expected <= 0 {
		return fmt.Errorf("%w: invalid pending reusable use count %d", protocol.ErrMalformedEnvelope, expected)
	}
	if decision.ReusableUses == nil {
		return fmt.Errorf("%w: missing reusable use count", protocol.ErrMalformedEnvelope)
	}
	if *decision.ReusableUses != expected {
		return fmt.Errorf(
			"%w: reusable use count %d does not match pending request count %d",
			protocol.ErrMalformedEnvelope,
			*decision.ReusableUses,
			expected,
		)
	}
	return nil
}

func NewRequestPayload(correlation protocol.Correlation, req request.ExecRequest) ApprovalRequestPayload {
	secrets := make([]ApprovalRequestedSecret, 0, len(req.Secrets))
	for _, secret := range req.Secrets {
		secrets = append(secrets, ApprovalRequestedSecret{
			Alias:   secret.Alias,
			Ref:     secret.Ref.Raw,
			Account: secret.Account,
		})
	}
	overriddenAliases := slices.Clone(req.OverriddenAliases)
	if overriddenAliases == nil {
		overriddenAliases = []string{}
	}
	return ApprovalRequestPayload{
		RequestID:              correlation.RequestID,
		Nonce:                  correlation.Nonce,
		Reason:                 req.Reason,
		Command:                slices.Clone(req.Command),
		CWD:                    req.CWD,
		ResolvedExecutable:     req.ResolvedExecutable,
		ExpiresAt:              req.ExpiresAt,
		Secrets:                secrets,
		OverrideEnv:            req.OverrideEnv,
		OverriddenAliases:      overriddenAliases,
		AllowMutableExecutable: req.AllowMutableExecutable,
		ReusableUses:           request.ReusableUsesOrDefault(req.ReusableUses),
	}
}
