package app

import (
	"strings"
	"testing"
)

func TestParseConfigRejectsCallerSelectedTrustInputs(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"--approver", "/tmp/fake-approver.app"},
		{"--trusted-client", "/tmp/fake-agent-secret"},
	} {
		_, err := parseConfig(args)
		if err == nil {
			t.Fatalf("parseConfig(%v) returned nil error", args)
		}
		if !strings.Contains(err.Error(), "flag provided but not defined") {
			t.Fatalf("parseConfig(%v) error = %v, want unknown flag", args, err)
		}
	}
}

func TestParseConfigDoesNotReadApproverEnvironmentOverride(t *testing.T) {
	t.Setenv("AGENT_SECRET_APPROVER_PATH", "/tmp/fake-approver")

	if _, err := parseConfig([]string{}); err != nil {
		t.Fatalf("parseConfig returned error: %v", err)
	}
}

func TestParseConfigReadsGCPOAuthClientIDFromFlagOrEnvironment(t *testing.T) {
	t.Setenv("AGENT_SECRET_GCP_OAUTH_CLIENT_ID", "env-client-id")

	config, err := parseConfig([]string{})
	if err != nil {
		t.Fatalf("parseConfig returned error: %v", err)
	}
	if config.gcpOAuthClientID != "env-client-id" {
		t.Fatalf("env client id = %q", config.gcpOAuthClientID)
	}

	config, err = parseConfig([]string{"--gcp-oauth-client-id", "flag-client-id"})
	if err != nil {
		t.Fatalf("parseConfig flag returned error: %v", err)
	}
	if config.gcpOAuthClientID != "flag-client-id" {
		t.Fatalf("flag client id = %q", config.gcpOAuthClientID)
	}
}
