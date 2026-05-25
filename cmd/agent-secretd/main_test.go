package main

import (
	"strings"
	"testing"
)

func TestParseDaemonConfigRejectsCallerSelectedTrustInputs(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"--approver", "/tmp/fake-approver.app"},
		{"--trusted-client", "/tmp/fake-agent-secret"},
	} {
		_, err := parseDaemonConfig(args)
		if err == nil {
			t.Fatalf("parseDaemonConfig(%v) returned nil error", args)
		}
		if !strings.Contains(err.Error(), "flag provided but not defined") {
			t.Fatalf("parseDaemonConfig(%v) error = %v, want unknown flag", args, err)
		}
	}
}

func TestParseDaemonConfigDoesNotReadApproverEnvironmentOverride(t *testing.T) {
	t.Setenv("AGENT_SECRET_APPROVER_PATH", "/tmp/fake-approver")

	if _, err := parseDaemonConfig([]string{}); err != nil {
		t.Fatalf("parseDaemonConfig returned error: %v", err)
	}
}

func TestParseDaemonConfigReadsGCPOAuthClientIDFromFlagOrEnvironment(t *testing.T) {
	t.Setenv("AGENT_SECRET_GCP_OAUTH_CLIENT_ID", "env-client-id")
	t.Setenv("AGENT_SECRET_GCP_OAUTH_CLIENT_SECRET", "env-client-secret")

	config, err := parseDaemonConfig([]string{})
	if err != nil {
		t.Fatalf("parseDaemonConfig returned error: %v", err)
	}
	if config.gcpOAuthClientID != "env-client-id" {
		t.Fatalf("env client id = %q", config.gcpOAuthClientID)
	}
	if config.gcpOAuthClientSecret != "env-client-secret" {
		t.Fatalf("env client secret = %q", config.gcpOAuthClientSecret)
	}

	config, err = parseDaemonConfig([]string{"--gcp-oauth-client-id", "flag-client-id"})
	if err != nil {
		t.Fatalf("parseDaemonConfig flag returned error: %v", err)
	}
	if config.gcpOAuthClientID != "flag-client-id" {
		t.Fatalf("flag client id = %q", config.gcpOAuthClientID)
	}
	if config.gcpOAuthClientSecret != "env-client-secret" {
		t.Fatalf("flag client secret = %q", config.gcpOAuthClientSecret)
	}
}
