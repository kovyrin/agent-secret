package approval

import (
	"fmt"
	"slices"
	"time"

	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/request"
)

type ApprovalRequestPayload struct {
	Operation          ApprovalOperation           `json:"operation"`
	AllowsReusable     bool                        `json:"allows_reusable"`
	RequestID          string                      `json:"request_id"`
	Nonce              string                      `json:"nonce"`
	Reason             string                      `json:"reason"`
	Command            []string                    `json:"command"`
	CWD                string                      `json:"cwd"`
	ResolvedExecutable string                      `json:"resolved_executable"`
	ExpiresAt          time.Time                   `json:"expires_at"`
	Resources          []ApprovalRequestedResource `json:"resources"`
	OverrideEnv        bool                        `json:"override_env"`
	OverriddenAliases  []string                    `json:"overridden_aliases"`
	ReusableUses       int                         `json:"reusable_uses"`
}

type ApprovalOperation string

const (
	ApprovalOperationExec             ApprovalOperation = "exec"
	ApprovalOperationItemDescribe     ApprovalOperation = "item_describe"
	ApprovalOperationGCPExec          ApprovalOperation = "gcp_exec"
	ApprovalOperationGCPSessionCreate ApprovalOperation = "gcp_session_create"
)

type ApprovalRequestedResource struct {
	Alias          string   `json:"alias"`
	Ref            string   `json:"ref"`
	Account        string   `json:"account"`
	Provider       string   `json:"provider,omitempty"`
	Project        string   `json:"project,omitempty"`
	ServiceAccount string   `json:"service_account,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
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
	DenialReason DenialReason         `json:"denial_reason,omitempty"`
}

func NewExecPayload(correlation protocol.Correlation, req request.ExecRequest) ApprovalRequestPayload {
	resources := make([]ApprovalRequestedResource, 0, len(req.Secrets))
	for _, secret := range req.Secrets {
		resources = append(resources, ApprovalRequestedResource{
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
		Operation:          ApprovalOperationExec,
		AllowsReusable:     true,
		RequestID:          correlation.RequestID,
		Nonce:              correlation.Nonce,
		Reason:             req.Reason,
		Command:            slices.Clone(req.Command),
		CWD:                req.CWD,
		ResolvedExecutable: req.ResolvedExecutable,
		ExpiresAt:          req.ExpiresAt,
		Resources:          resources,
		OverrideEnv:        req.OverrideEnv,
		OverriddenAliases:  overriddenAliases,
		ReusableUses:       request.ReusableUsesOrDefault(req.ReusableUses),
	}
}

func NewItemDescribePayload(
	correlation protocol.Correlation,
	req request.ItemDescribeRequest,
) ApprovalRequestPayload {
	return ApprovalRequestPayload{
		Operation:          ApprovalOperationItemDescribe,
		AllowsReusable:     false,
		RequestID:          correlation.RequestID,
		Nonce:              correlation.Nonce,
		Reason:             req.Reason,
		Command:            slices.Clone(req.Command),
		CWD:                req.CWD,
		ResolvedExecutable: req.ResolvedExecutable,
		ExpiresAt:          req.ExpiresAt,
		Resources: []ApprovalRequestedResource{
			{
				Alias:   req.Ref.Item,
				Ref:     req.Ref.Raw,
				Account: req.Account,
			},
		},
		OverrideEnv:       false,
		OverriddenAliases: []string{},
		ReusableUses:      1,
	}
}

func NewGCPExecPayload(correlation protocol.Correlation, req request.GCPExecRequest) ApprovalRequestPayload {
	return ApprovalRequestPayload{
		Operation:          ApprovalOperationGCPExec,
		AllowsReusable:     false,
		RequestID:          correlation.RequestID,
		Nonce:              correlation.Nonce,
		Reason:             req.Reason,
		Command:            slices.Clone(req.Command),
		CWD:                req.CWD,
		ResolvedExecutable: req.ResolvedExecutable,
		ExpiresAt:          req.ExpiresAt,
		Resources: []ApprovalRequestedResource{
			gcpApprovalResource(req.Access()),
		},
		OverrideEnv:       false,
		OverriddenAliases: []string{},
		ReusableUses:      1,
	}
}

func NewGCPSessionCreatePayload(
	correlation protocol.Correlation,
	req request.GCPSessionCreateRequest,
	sessionAuditID string,
) ApprovalRequestPayload {
	return ApprovalRequestPayload{
		Operation:          ApprovalOperationGCPSessionCreate,
		AllowsReusable:     false,
		RequestID:          correlation.RequestID,
		Nonce:              correlation.Nonce,
		Reason:             req.Reason,
		Command:            []string{"agent-secret", "gcp", "with-session", sessionAuditID, "--", "..."},
		CWD:                req.ProjectRoot,
		ResolvedExecutable: "agent-secret",
		ExpiresAt:          req.ExpiresAt,
		Resources: []ApprovalRequestedResource{
			gcpApprovalResource(req.Access()),
		},
		OverrideEnv:       false,
		OverriddenAliases: []string{},
		ReusableUses:      req.MaxCommandStarts,
	}
}

func gcpApprovalResource(access request.GCPAccess) ApprovalRequestedResource {
	return ApprovalRequestedResource{
		Alias:          "GCP_ACCESS_TOKEN",
		Ref:            fmt.Sprintf("gcp://projects/%s/serviceAccounts/%s", access.Project, access.ServiceAccount),
		Account:        access.GoogleAccount,
		Provider:       "gcp",
		Project:        access.Project,
		ServiceAccount: access.ServiceAccount,
		Scopes:         slices.Clone(access.Scopes),
	}
}

func ValidateDecision(decision ApprovalDecisionPayload, expectedReusableUses int, allowsReusable bool) error {
	if err := ValidateDecisionReusableUses(decision, expectedReusableUses, allowsReusable); err != nil {
		return err
	}
	return ValidateDecisionDenialReason(decision)
}

func ValidateDecisionReusableUses(decision ApprovalDecisionPayload, expected int, allowsReusable bool) error {
	if decision.Decision != ApprovalDecisionApproveReusable {
		if decision.ReusableUses != nil {
			return fmt.Errorf("%w: reusable use count is only valid for approve_reusable", protocol.ErrMalformedEnvelope)
		}
		return nil
	}
	if !allowsReusable {
		return fmt.Errorf("%w: reusable approval is not valid for this request", protocol.ErrMalformedEnvelope)
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

func ValidateDecisionDenialReason(decision ApprovalDecisionPayload) error {
	if decision.Decision != ApprovalDecisionDeny {
		if decision.DenialReason != "" {
			return fmt.Errorf("%w: denial reason is only valid for deny", protocol.ErrMalformedEnvelope)
		}
		return nil
	}
	switch decision.DenialReason {
	case "", DenialReasonComputerLocked:
		return nil
	default:
		return fmt.Errorf("%w: invalid denial reason %q", protocol.ErrMalformedEnvelope, decision.DenialReason)
	}
}
