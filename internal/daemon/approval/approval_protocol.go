package approval

import (
	"fmt"
	"slices"
	"time"

	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/request"
)

type ApprovalRequestPayload struct {
	RequestID              string                    `json:"request_id"`
	Nonce                  string                    `json:"nonce"`
	Reason                 string                    `json:"reason"`
	Command                []string                  `json:"command"`
	CWD                    string                    `json:"cwd"`
	ResolvedExecutable     string                    `json:"resolved_executable"`
	ExpiresAt              time.Time                 `json:"expires_at"`
	Secrets                []ApprovalRequestedSecret `json:"secrets"`
	OverrideEnv            bool                      `json:"override_env"`
	OverriddenAliases      []string                  `json:"overridden_aliases"`
	AllowMutableExecutable bool                      `json:"allow_mutable_executable"`
	ReusableUses           int                       `json:"reusable_uses"`
}

type ApprovalRequestedSecret struct {
	Alias   string `json:"alias"`
	Ref     string `json:"ref"`
	Account string `json:"account"`
}

type ApprovalDecisionKind string

const (
	ApprovalDecisionApproveOnce     ApprovalDecisionKind = "approve_once"
	ApprovalDecisionApproveReusable ApprovalDecisionKind = "approve_reusable"
	ApprovalDecisionDeny            ApprovalDecisionKind = "deny"
	ApprovalDecisionTimeout         ApprovalDecisionKind = "timeout"
)

type ApprovalDecisionPayload struct {
	RequestID    string               `json:"request_id"`
	Nonce        string               `json:"nonce"`
	Decision     ApprovalDecisionKind `json:"decision"`
	ReusableUses *int                 `json:"reusable_uses,omitempty"`
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

func ValidateDecisionReusableUses(decision ApprovalDecisionPayload, expected int) error {
	if decision.Decision != ApprovalDecisionApproveReusable {
		if decision.ReusableUses != nil {
			return fmt.Errorf("%w: reusable use count is only valid for approve_reusable", protocol.ErrMalformedEnvelope)
		}
		return nil
	}
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
