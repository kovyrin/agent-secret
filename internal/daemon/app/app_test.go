package app

import (
	"strings"
	"testing"

	"github.com/kovyrin/agent-secret/internal/buildinfo"
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
	resetBundledGCPOAuthClient(t)
	t.Setenv("AGENT_SECRET_GCP_OAUTH_CLIENT_ID", "env-client-id")
	t.Setenv("AGENT_SECRET_GCP_OAUTH_CLIENT_SECRET", "env-client-secret")

	config, err := parseConfig([]string{})
	if err != nil {
		t.Fatalf("parseConfig returned error: %v", err)
	}
	if config.gcpOAuthClientID != "env-client-id" {
		t.Fatalf("env client id = %q", config.gcpOAuthClientID)
	}
	if config.gcpOAuthClientSecret != "env-client-secret" {
		t.Fatalf("env client secret = %q", config.gcpOAuthClientSecret)
	}

	config, err = parseConfig([]string{"--gcp-oauth-client-id", "flag-client-id"})
	if err != nil {
		t.Fatalf("parseConfig flag returned error: %v", err)
	}
	if config.gcpOAuthClientID != "flag-client-id" {
		t.Fatalf("flag client id = %q", config.gcpOAuthClientID)
	}
	if config.gcpOAuthClientSecret != "env-client-secret" {
		t.Fatalf("flag client secret = %q", config.gcpOAuthClientSecret)
	}
}

func TestParseConfigUsesBundledGCPOAuthClientWhenEnvironmentIsEmpty(t *testing.T) {
	resetBundledGCPOAuthClient(t)
	buildinfo.GCPOAuthClientID = "bundled-client-id"
	buildinfo.GCPOAuthClientSecret = "bundled-client-secret"

	config, err := parseConfig([]string{})
	if err != nil {
		t.Fatalf("parseConfig returned error: %v", err)
	}
	if config.gcpOAuthClientID != "bundled-client-id" {
		t.Fatalf("bundled client id = %q", config.gcpOAuthClientID)
	}
	if config.gcpOAuthClientSecret != "bundled-client-secret" {
		t.Fatalf("bundled client secret = %q", config.gcpOAuthClientSecret)
	}

	t.Setenv("AGENT_SECRET_GCP_OAUTH_CLIENT_ID", "env-client-id")
	t.Setenv("AGENT_SECRET_GCP_OAUTH_CLIENT_SECRET", "env-client-secret")
	config, err = parseConfig([]string{})
	if err != nil {
		t.Fatalf("parseConfig with env returned error: %v", err)
	}
	if config.gcpOAuthClientID != "env-client-id" {
		t.Fatalf("env client id = %q", config.gcpOAuthClientID)
	}
	if config.gcpOAuthClientSecret != "env-client-secret" {
		t.Fatalf("env client secret = %q", config.gcpOAuthClientSecret)
	}
}

func resetBundledGCPOAuthClient(t *testing.T) {
	t.Helper()
	originalClientID := buildinfo.GCPOAuthClientID
	originalClientSecret := buildinfo.GCPOAuthClientSecret
	buildinfo.GCPOAuthClientID = ""
	buildinfo.GCPOAuthClientSecret = ""
	t.Cleanup(func() {
		buildinfo.GCPOAuthClientID = originalClientID
		buildinfo.GCPOAuthClientSecret = originalClientSecret
	})
}
