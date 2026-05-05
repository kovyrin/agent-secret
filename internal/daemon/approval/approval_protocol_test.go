package approval

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/request"
)

func TestNewRequestPayloadCopiesProtocolFields(t *testing.T) {
	t.Parallel()

	expiresAt := time.Now().Add(time.Minute).UTC()
	req := request.ExecRequest{
		Reason:             "ship safely",
		Command:            []string{"/bin/echo", "hello"},
		CWD:                "/tmp",
		ResolvedExecutable: "/bin/echo",
		ExpiresAt:          expiresAt,
		Secrets: []request.Secret{
			{
				Alias: "TOKEN",
				Ref: request.SecretRef{
					Raw: "op://Vault/Item/token",
				},
				Account: "example.1password.com",
			},
		},
		OverrideEnv:       true,
		OverriddenAliases: []string{"TOKEN"},
	}

	payload := NewRequestPayload(protocol.Correlation{RequestID: "req_1", Nonce: "nonce_1"}, req)
	req.Command[1] = "mutated"
	req.OverriddenAliases[0] = "MUTATED"

	if payload.RequestID != "req_1" || payload.Nonce != "nonce_1" {
		t.Fatalf("correlation = (%q, %q), want req_1/nonce_1", payload.RequestID, payload.Nonce)
	}
	if !slices.Equal(payload.Command, []string{"/bin/echo", "hello"}) {
		t.Fatalf("command = %q, want cloned command", payload.Command)
	}
	if !slices.Equal(payload.OverriddenAliases, []string{"TOKEN"}) {
		t.Fatalf("overridden aliases = %q, want cloned aliases", payload.OverriddenAliases)
	}
	if payload.ReusableUses != request.DefaultReusableUses {
		t.Fatalf("reusable uses = %d, want default %d", payload.ReusableUses, request.DefaultReusableUses)
	}
	if payload.ExpiresAt != expiresAt {
		t.Fatalf("expires at = %v, want %v", payload.ExpiresAt, expiresAt)
	}
	if len(payload.Secrets) != 1 {
		t.Fatalf("secrets = %d, want 1", len(payload.Secrets))
	}
	secret := payload.Secrets[0]
	if secret.Alias != "TOKEN" || secret.Ref != "op://Vault/Item/token" || secret.Account != "example.1password.com" {
		t.Fatalf("secret = %+v, want mapped secret fields", secret)
	}
	if !payload.OverrideEnv {
		t.Fatal("OverrideEnv = false, want true")
	}
}

func TestNewRequestPayloadUsesEmptyOverriddenAliasesSlice(t *testing.T) {
	t.Parallel()

	payload := NewRequestPayload(protocol.Correlation{}, request.ExecRequest{})
	if payload.OverriddenAliases == nil {
		t.Fatal("OverriddenAliases is nil, want empty slice")
	}
}

func TestValidateDecisionReusableUses(t *testing.T) {
	t.Parallel()

	reusableUses2 := 2
	reusableUses3 := 3
	tests := []struct {
		name     string
		decision ApprovalDecisionPayload
		expected int
		wantErr  string
	}{
		{
			name:     "non reusable decision without count",
			decision: ApprovalDecisionPayload{Decision: ApprovalDecisionApproveOnce},
		},
		{
			name: "non reusable decision rejects count",
			decision: ApprovalDecisionPayload{
				Decision:     ApprovalDecisionDeny,
				ReusableUses: &reusableUses3,
			},
			wantErr: "only valid for approve_reusable",
		},
		{
			name:     "reusable rejects invalid pending count",
			decision: ApprovalDecisionPayload{Decision: ApprovalDecisionApproveReusable, ReusableUses: &reusableUses3},
			wantErr:  "invalid pending reusable use count",
		},
		{
			name:     "reusable requires count",
			decision: ApprovalDecisionPayload{Decision: ApprovalDecisionApproveReusable},
			expected: 3,
			wantErr:  "missing reusable use count",
		},
		{
			name:     "reusable count must match pending request",
			decision: ApprovalDecisionPayload{Decision: ApprovalDecisionApproveReusable, ReusableUses: &reusableUses2},
			expected: 3,
			wantErr:  "does not match pending request count",
		},
		{
			name:     "reusable accepts matching count",
			decision: ApprovalDecisionPayload{Decision: ApprovalDecisionApproveReusable, ReusableUses: &reusableUses3},
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateDecisionReusableUses(tt.decision, tt.expected)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("ValidateDecisionReusableUses returned nil error")
				}
				if !errors.Is(err, protocol.ErrMalformedEnvelope) {
					t.Fatalf("error = %v, want ErrMalformedEnvelope", err)
				}
				if !contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateDecisionReusableUses returned error: %v", err)
			}
		})
	}
}

func contains(value string, substring string) bool {
	return strings.Contains(value, substring)
}
