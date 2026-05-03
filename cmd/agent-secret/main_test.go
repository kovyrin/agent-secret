package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunHelpWritesUsage(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run help exit code = %d, want 0; stderr = %q", code, stderr.String())
	}
	if got := stdout.String(); !strings.Contains(got, "agent-secret controls short-lived local access") ||
		!strings.Contains(got, "Commands:") {
		t.Fatalf("stdout = %q, want help text", got)
	}
	if got := stderr.String(); got != "" {
		t.Fatalf("stderr = %q, want empty", got)
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"no-such-command"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run unknown command exit code = %d, want 2", code)
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
	if got := stderr.String(); !strings.Contains(got, "unknown command") {
		t.Fatalf("stderr = %q, want unknown command error", got)
	}
}
