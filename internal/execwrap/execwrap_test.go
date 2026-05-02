package execwrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	syntheticSecret        = "synthetic-secret-value"
	syntheticMultilineText = "-----BEGIN PRIVATE KEY-----\nline one\nline two\n-----END PRIVATE KEY-----\n"
)

type memoryAudit struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (m *memoryAudit) Record(_ context.Context, event AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *memoryAudit) Events() []AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.events)
}

type failingAudit struct {
	failType string
}

func (f failingAudit) Record(_ context.Context, event AuditEvent) error {
	if event.Type == f.failType {
		return errors.New("audit offline")
	}
	return nil
}

func TestMergeEnvRejectsConflictsByDefault(t *testing.T) {
	t.Parallel()

	_, err := MergeEnv([]string{"AGENT_SECRET_CANARY=already-set"}, map[string]string{
		"AGENT_SECRET_CANARY": syntheticSecret,
	}, false)
	if !errors.Is(err, ErrEnvironmentConflict) {
		t.Fatalf("expected environment conflict, got %v", err)
	}
}

func TestMergeEnvCanOverrideExistingAlias(t *testing.T) {
	t.Parallel()

	env, err := MergeEnv([]string{"AGENT_SECRET_CANARY=already-set"}, map[string]string{
		"AGENT_SECRET_CANARY": syntheticSecret,
	}, true)
	if err != nil {
		t.Fatalf("MergeEnv returned error: %v", err)
	}
	if got := findEnv(env, "AGENT_SECRET_CANARY"); got != syntheticSecret {
		t.Fatalf("merged env value = %q, want synthetic secret", got)
	}
}

func TestRunInjectsEnvOnlyIntoChildAndRecordsMetadata(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	audit := &memoryAudit{}
	result, err := Run(context.Background(), Spec{
		Path:          os.Args[0],
		Args:          []string{"-test.run=TestExecHelperProcess", "--", "check-env"},
		Env:           helperEnv("AGENT_SECRET_CANARY", syntheticSecret),
		SecretAliases: []string{"AGENT_SECRET_CANARY"},
		OverrideEnv:   true,
		Stdout:        &stdout,
		Audit:         audit,
	}, nil)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stdout=%q", result.ExitCode, stdout.String())
	}
	if strings.TrimSpace(stdout.String()) != "env-ok" {
		t.Fatalf("stdout = %q, want env-ok", stdout.String())
	}
	if got := os.Getenv("AGENT_SECRET_CANARY"); got == syntheticSecret {
		t.Fatalf("parent environment leaked injected value: %q", got)
	}

	encoded, err := json.Marshal(audit.Events())
	if err != nil {
		t.Fatalf("marshal audit events: %v", err)
	}
	if bytes.Contains(encoded, []byte(syntheticSecret)) {
		t.Fatalf("audit events contain synthetic secret: %s", encoded)
	}
}

func TestRunPreservesMultilineSecretEnvValue(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	result, err := Run(context.Background(), Spec{
		Path:          os.Args[0],
		Args:          []string{"-test.run=TestExecHelperProcess", "--", "check-multiline-env"},
		Env:           helperEnv("AGENT_SECRET_MULTILINE", syntheticMultilineText),
		SecretAliases: []string{"AGENT_SECRET_MULTILINE"},
		OverrideEnv:   true,
		Stdout:        &stdout,
	}, nil)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stdout=%q", result.ExitCode, stdout.String())
	}
	if strings.TrimSpace(stdout.String()) != "multiline-env-ok" {
		t.Fatalf("stdout = %q, want multiline-env-ok", stdout.String())
	}
}

func TestRunForwardsStdinToChild(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	result, err := Run(context.Background(), Spec{
		Path:   os.Args[0],
		Args:   []string{"-test.run=TestExecHelperProcess", "--", "echo-stdin"},
		Env:    helperEnv(),
		Stdin:  strings.NewReader("script-from-stdin\n"),
		Stdout: &stdout,
	}, nil)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stdout=%q", result.ExitCode, stdout.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != "script-from-stdin" {
		t.Fatalf("stdout = %q, want stdin echoed", got)
	}
}

func TestRunPreservesExitCode(t *testing.T) {
	t.Parallel()

	result, err := Run(context.Background(), Spec{
		Path: os.Args[0],
		Args: []string{"-test.run=TestExecHelperProcess", "--", "exit-42"},
		Env:  helperEnv(),
	}, nil)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.ExitCode != 42 {
		t.Fatalf("exit code = %d, want 42", result.ExitCode)
	}
}

func TestRunRejectsMissingCommandPath(t *testing.T) {
	t.Parallel()

	_, err := Run(context.Background(), Spec{}, nil)
	if err == nil {
		t.Fatal("expected missing command path error")
	}
}

func TestRunStopsBeforeSpawnWhenStartingAuditFails(t *testing.T) {
	t.Parallel()

	_, err := Run(context.Background(), Spec{
		Path:  os.Args[0],
		Args:  []string{"-test.run=TestExecHelperProcess", "--", "check-env"},
		Env:   helperEnv("AGENT_SECRET_CANARY", syntheticSecret),
		Audit: failingAudit{failType: "command_starting"},
	}, nil)
	if err == nil {
		t.Fatal("expected command_starting audit failure")
	}
}

func TestRunTerminatesChildWhenStartedAuditFails(t *testing.T) {
	t.Parallel()

	_, err := Run(context.Background(), Spec{
		Path:  os.Args[0],
		Args:  []string{"-test.run=TestExecHelperProcess", "--", "sleep-long"},
		Env:   helperEnv(),
		Audit: failingAudit{failType: "command_started"},
	}, nil)
	if err == nil {
		t.Fatal("expected command_started audit failure")
	}
}

func TestRunForwardsInterruptToChild(t *testing.T) {
	t.Parallel()

	interrupts := make(chan os.Signal, 1)
	var stdout bytes.Buffer

	go func() {
		time.Sleep(200 * time.Millisecond)
		interrupts <- syscall.SIGINT
	}()

	result, err := Run(context.Background(), Spec{
		Path:   os.Args[0],
		Args:   []string{"-test.run=TestExecHelperProcess", "--", "wait-signal"},
		Env:    helperEnv(),
		Stdout: &stdout,
	}, interrupts)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.ExitCode != 130 {
		t.Fatalf("exit code = %d, want 130; stdout=%q", result.ExitCode, stdout.String())
	}
	if !strings.Contains(stdout.String(), "signal-ok") {
		t.Fatalf("child did not observe forwarded signal; stdout=%q", stdout.String())
	}
}

func TestRunTerminatesChildOnContextCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	started := time.Now()
	result, err := Run(ctx, Spec{
		Path: os.Args[0],
		Args: []string{"-test.run=TestExecHelperProcess", "--", "sleep-long"},
		Env:  helperEnv(),
	}, nil)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if time.Since(started) > 3*time.Second {
		t.Fatalf("context cancellation did not terminate the child promptly")
	}
	if result.ExitCode == 0 {
		t.Fatalf("exit code = 0, want cancellation to terminate child")
	}
}

func TestAuditEventShapeIsValueFree(t *testing.T) {
	t.Parallel()

	event := AuditEvent{
		Type:          "command_starting",
		Command:       []string{"/usr/bin/env"},
		SecretAliases: []string{"AGENT_SECRET_CANARY"},
	}
	if reflect.ValueOf(event).FieldByName("Env").IsValid() {
		t.Fatal("audit event unexpectedly has an Env field")
	}

	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	if bytes.Contains(encoded, []byte(syntheticSecret)) {
		t.Fatalf("audit event contains synthetic secret: %s", encoded)
	}
}

func TestResultFromNilState(t *testing.T) {
	t.Parallel()

	result := resultFromState(nil)
	if result.ExitCode != -1 || result.Signal != nil {
		t.Fatalf("nil process state result = %+v", result)
	}
}

func TestExecHelperProcess(t *testing.T) {
	if os.Getenv("AGENT_SECRET_EXEC_HELPER") != "1" {
		return
	}

	mode := ""
	if len(os.Args) > 0 {
		mode = os.Args[len(os.Args)-1]
	}

	switch mode {
	case "check-env":
		if os.Getenv("AGENT_SECRET_CANARY") != syntheticSecret {
			fmt.Println("env-missing")
			os.Exit(42)
		}
		fmt.Println("env-ok")
		os.Exit(0)
	case "check-multiline-env":
		if os.Getenv("AGENT_SECRET_MULTILINE") != syntheticMultilineText {
			fmt.Println("multiline-env-mismatch")
			os.Exit(42)
		}
		fmt.Println("multiline-env-ok")
		os.Exit(0)
	case "echo-stdin":
		if _, err := io.Copy(os.Stdout, os.Stdin); err != nil {
			fmt.Printf("copy-stdin: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	case "exit-42":
		os.Exit(42)
	case "wait-signal":
		signals := make(chan os.Signal, 1)
		signalNotify(signals, syscall.SIGINT)
		fmt.Println("ready")
		<-signals
		fmt.Println("signal-ok")
		os.Exit(130)
	case "sleep-long":
		time.Sleep(10 * time.Second)
		os.Exit(0)
	default:
		fmt.Printf("unknown helper mode %q\n", mode)
		os.Exit(64)
	}
}

func findEnv(env []string, key string) string {
	for _, entry := range env {
		gotKey, value, ok := strings.Cut(entry, "=")
		if ok && gotKey == key {
			return value
		}
	}
	return ""
}

func helperEnv(pairs ...string) map[string]string {
	env := map[string]string{"AGENT_SECRET_EXEC_HELPER": "1"}
	for i := 0; i+1 < len(pairs); i += 2 {
		env[pairs[i]] = pairs[i+1]
	}
	return env
}
