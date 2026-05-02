package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/policy"
	"github.com/kovyrin/agent-secret/internal/request"
)

const canaryValue = "synthetic-secret-value"

func TestOpenDefaultCreatesPrivateJSONLAuditLog(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)

	writer, err := OpenDefault(func() time.Time { return now })
	if err != nil {
		t.Fatalf("OpenDefault returned error: %v", err)
	}
	defer func() { _ = writer.Close() }()

	err = writer.Record(context.Background(), Event{
		Type:       EventCommandStarting,
		RequestID:  "req_1",
		Reason:     "Run Terraform plan",
		Command:    []string{"/usr/bin/env", "terraform", "plan"},
		CWD:        "/tmp/project",
		SecretRefs: []SecretRef{{Alias: "TOKEN", Ref: "op://Example Vault/Item/token"}},
	})
	if err != nil {
		t.Fatalf("Record command_starting returned error: %v", err)
	}
	err = writer.Record(context.Background(), Event{
		Type:     EventCommandStarted,
		ChildPID: new(1234),
	})
	if err != nil {
		t.Fatalf("Record command_started returned error: %v", err)
	}

	path := expectedPath(home)
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat audit dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("audit dir mode = %s, want 0700", got)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat audit file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("audit file mode = %s, want 0600", got)
	}

	//nolint:gosec // G304: test reads the audit file path created under the test HOME.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit line count = %d, want 2; data=%q", len(lines), data)
	}

	var event Event
	if err := json.Unmarshal([]byte(lines[0]), &event); err != nil {
		t.Fatalf("unmarshal first event: %v", err)
	}
	if event.Type != EventCommandStarting || !event.Timestamp.Equal(now) {
		t.Fatalf("unexpected first event: %+v", event)
	}
}

func TestOpenDefaultRejectsPermissiveExistingAuditFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := expectedPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir audit dir: %v", err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write audit file: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // G302: this test intentionally creates an insecure audit log to prove rejection.
		t.Fatalf("chmod audit file: %v", err)
	}

	_, err := OpenDefault(time.Now)
	if !errors.Is(err, ErrInsecureAuditLog) {
		t.Fatalf("expected insecure audit log error, got %v", err)
	}
}

func TestDefaultPathIgnoresEnvironmentOverrides(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AGENT_SECRET_AUDIT_PATH", "/tmp/evil/audit.jsonl")

	path, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath returned error: %v", err)
	}
	if path != expectedPath(home) {
		t.Fatalf("default path = %q, want fixed home-relative path %q", path, expectedPath(home))
	}
	if strings.Contains(path, "evil") {
		t.Fatalf("default path honored unsupported override: %q", path)
	}
}

func TestEventShapeIsValueFree(t *testing.T) {
	t.Parallel()

	eventType := reflect.TypeFor[Event]()
	for _, disallowed := range []string{"Env", "Value", "Values", "SecretValue", "SecretValues"} {
		if _, ok := eventType.FieldByName(disallowed); ok {
			t.Fatalf("event unexpectedly exposes %s field", disallowed)
		}
	}

	event := Event{
		Type:       EventCommandCompleted,
		Reason:     "Run Terraform plan",
		Command:    []string{"/usr/bin/env", "terraform", "plan"},
		SecretRefs: []SecretRef{{Alias: "TOKEN", Ref: "op://Example Vault/Item/token"}},
		ExitCode:   new(0),
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	if bytes.Contains(encoded, []byte(canaryValue)) {
		t.Fatalf("audit event contains synthetic secret: %s", encoded)
	}
	if !bytes.Contains(encoded, []byte(`"exit_code":0`)) {
		t.Fatalf("completion event omitted successful exit code: %s", encoded)
	}
}

func TestFromExecRequestUsesValidatedTrimmedReason(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeExecutable(t, dir, "terraform")
	req, err := request.NewExec(request.ExecOptions{
		Reason:     "  Run Terraform plan  ",
		Command:    []string{"terraform", "plan"},
		CWD:        dir,
		Env:        []string{"PATH=" + dir},
		ReceivedAt: time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC),
		Secrets: []request.SecretSpec{
			{Alias: "TOKEN", Ref: "op://Example Vault/Item/token"},
		},
	})
	if err != nil {
		t.Fatalf("NewExec returned error: %v", err)
	}

	encoded, err := json.Marshal(FromExecRequest(EventCommandStarting, "req_1", req))
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	if bytes.Contains(encoded, []byte("  Run Terraform plan  ")) {
		t.Fatalf("audit retained raw pre-trim reason: %s", encoded)
	}
	if !bytes.Contains(encoded, []byte("Run Terraform plan")) {
		t.Fatalf("audit omitted validated reason: %s", encoded)
	}
}

func TestWriterRejectsInvalidEventsAndClosedUse(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writer, err := OpenDefault(time.Now)
	if err != nil {
		t.Fatalf("OpenDefault returned error: %v", err)
	}

	if err := writer.Record(context.Background(), Event{}); !errors.Is(err, ErrInvalidAuditEvent) {
		t.Fatalf("expected invalid event error, got %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if err := writer.Record(context.Background(), Event{Type: EventCommandStarting}); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected closed writer error, got %v", err)
	}
}

func TestWriterPreflightAndApprovalReused(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	writer, err := OpenDefault(func() time.Time { return now })
	if err != nil {
		t.Fatalf("OpenDefault returned error: %v", err)
	}

	if err := writer.Preflight(context.Background()); err != nil {
		t.Fatalf("Preflight returned error: %v", err)
	}
	err = writer.ApprovalReused(context.Background(), policy.ReuseAuditEvent{
		ApprovalID:   "approval_1",
		RemainingTTL: 90 * time.Second,
		RemainingUse: 2,
	})
	if err != nil {
		t.Fatalf("ApprovalReused returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if err := writer.Preflight(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected closed preflight error, got %v", err)
	}

	data, err := os.ReadFile(expectedPath(home))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var event Event
	if err := json.Unmarshal(bytes.TrimSpace(data), &event); err != nil {
		t.Fatalf("unmarshal approval_reused event: %v", err)
	}
	if event.Type != EventApprovalReused || event.ApprovalID != "approval_1" {
		t.Fatalf("unexpected approval_reused event: %+v", event)
	}
	if event.RemainingTTLMillis == nil || *event.RemainingTTLMillis != 90000 {
		t.Fatalf("remaining TTL metadata = %v, want 90000", event.RemainingTTLMillis)
	}
	if event.RemainingUses == nil || *event.RemainingUses != 2 {
		t.Fatalf("remaining uses metadata = %v, want 2", event.RemainingUses)
	}
}

func TestWriterHonorsCanceledContextBeforeWriting(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writer, err := OpenDefault(time.Now)
	if err != nil {
		t.Fatalf("OpenDefault returned error: %v", err)
	}
	defer func() { _ = writer.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := writer.Preflight(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Preflight canceled error = %v, want context.Canceled", err)
	}
	if err := writer.Record(ctx, Event{Type: EventCommandStarting}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Record canceled error = %v, want context.Canceled", err)
	}
}

func TestOpenPathRejectsDirectoryAtAuditPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("mkdir audit path: %v", err)
	}

	_, err := openPath(path, time.Now)
	if !errors.Is(err, ErrInsecureAuditLog) {
		t.Fatalf("expected insecure audit log error, got %v", err)
	}
}

func expectedPath(home string) string {
	return filepath.Join(home, "Library", "Logs", "agent-secret", "audit.jsonl")
}

func writeExecutable(t *testing.T, dir string, name string) {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: audit tests need a runnable fixture executable in command metadata.
		t.Fatalf("write executable: %v", err)
	}
}
