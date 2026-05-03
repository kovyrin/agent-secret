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
