package execwrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/fileidentity"
)

const (
	syntheticSecret        = "synthetic-secret-value"
	syntheticMultilineText = "-----BEGIN PRIVATE KEY-----\nline one\nline two\n-----END PRIVATE KEY-----\n"
)

type lifecycleEvent struct {
	Type     string `json:"type"`
	ChildPID int    `json:"child_pid,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`
	Signal   string `json:"signal,omitempty"`
}

type memoryLifecycle struct {
	mu     sync.Mutex
	events []lifecycleEvent
}

func (m *memoryLifecycle) CommandStarted(_ context.Context, childPID int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, lifecycleEvent{Type: "command_started", ChildPID: childPID})
	return nil
}

func (m *memoryLifecycle) CommandCompleted(_ context.Context, result Result) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	event := lifecycleEvent{Type: "command_completed", ExitCode: result.ExitCode}
	if result.Signal != nil {
		event.Signal = result.Signal.String()
	}
	m.events = append(m.events, event)
	return nil
}

func (m *memoryLifecycle) Events() []lifecycleEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.events)
}

type failingLifecycle struct{}

func (f failingLifecycle) CommandStarted(context.Context, int) error {
	return errors.New("lifecycle reporter offline")
}

func (f failingLifecycle) CommandCompleted(context.Context, Result) error {
	return nil
}

type cancelingLifecycle struct {
	cancel context.CancelFunc
}

func (c cancelingLifecycle) CommandStarted(context.Context, int) error {
	c.cancel()
	return nil
}

func (c cancelingLifecycle) CommandCompleted(context.Context, Result) error {
	return nil
}

type signalTestOutput struct {
	mu              sync.Mutex
	buffer          bytes.Buffer
	ready           chan struct{}
	firstSignal     chan struct{}
	readyOnce       sync.Once
	firstSignalOnce sync.Once
}

func newSignalTestOutput() *signalTestOutput {
	return &signalTestOutput{
		ready:       make(chan struct{}),
		firstSignal: make(chan struct{}),
	}
}

func (o *signalTestOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	n, err := o.buffer.Write(p)
	output := o.buffer.String()
	o.mu.Unlock()

	if strings.Contains(output, "ready") {
		o.readyOnce.Do(func() { close(o.ready) })
	}
	if strings.Contains(output, "signal-1") {
		o.firstSignalOnce.Do(func() { close(o.firstSignal) })
	}
	return n, err
}

func (o *signalTestOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buffer.String()
}

func waitForSignalOutput(output *signalTestOutput, marker <-chan struct{}) (string, bool) {
	select {
	case <-marker:
		return "", true
	case <-time.After(2 * time.Second):
		return output.String(), false
	}
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

func TestMergeEnvRejectsDuplicateConflictsByDefault(t *testing.T) {
	t.Parallel()

	_, err := MergeEnv([]string{
		"AGENT_SECRET_CANARY=first-stale-value",
		"PATH=/usr/bin",
		"AGENT_SECRET_CANARY=second-stale-value",
	}, map[string]string{
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

func TestMergeEnvOverrideRemovesDuplicateExistingAliases(t *testing.T) {
	t.Parallel()

	env, err := MergeEnv([]string{
		"AGENT_SECRET_CANARY=first-stale-value",
		"PATH=/usr/bin",
		"AGENT_SECRET_CANARY=second-stale-value",
		"KEEP=kept",
	}, map[string]string{
		"AGENT_SECRET_CANARY": syntheticSecret,
	}, true)
	if err != nil {
		t.Fatalf("MergeEnv returned error: %v", err)
	}
	want := []string{
		"PATH=/usr/bin",
		"KEEP=kept",
		"AGENT_SECRET_CANARY=" + syntheticSecret,
	}
	if !reflect.DeepEqual(env, want) {
		t.Fatalf("merged env = %v, want %v", env, want)
	}
	if got := countEnv(env, "AGENT_SECRET_CANARY"); got != 1 {
		t.Fatalf("merged env has %d canary entries, want 1: %v", got, env)
	}
	if got := findEnv(env, "AGENT_SECRET_CANARY"); got != syntheticSecret {
		t.Fatalf("merged env value = %q, want synthetic secret", got)
	}
}

func TestRunInjectsEnvOnlyIntoChildAndRecordsMetadata(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	lifecycle := &memoryLifecycle{}
	result, err := Run(context.Background(), Spec{
		Path:         os.Args[0],
		PathIdentity: currentExecutableIdentity(t),
		Args:         []string{"-test.run=TestExecHelperProcess", "--", "check-env"},
		Env:          helperEnv("AGENT_SECRET_CANARY", syntheticSecret),
		OverrideEnv:  true,
		Stdout:       &stdout,
		Lifecycle:    lifecycle,
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

	encoded, err := json.Marshal(lifecycle.Events())
	if err != nil {
		t.Fatalf("marshal lifecycle events: %v", err)
	}
	if bytes.Contains(encoded, []byte(syntheticSecret)) {
		t.Fatalf("lifecycle events contain synthetic secret: %s", encoded)
	}
}

func TestRunPreservesMultilineSecretEnvValue(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	result, err := Run(context.Background(), Spec{
		Path:         os.Args[0],
		PathIdentity: currentExecutableIdentity(t),
		Args:         []string{"-test.run=TestExecHelperProcess", "--", "check-multiline-env"},
		Env:          helperEnv("AGENT_SECRET_MULTILINE", syntheticMultilineText),
		OverrideEnv:  true,
		Stdout:       &stdout,
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
		Path:         os.Args[0],
		PathIdentity: currentExecutableIdentity(t),
		Args:         []string{"-test.run=TestExecHelperProcess", "--", "echo-stdin"},
		Env:          helperEnv(),
		Stdin:        strings.NewReader("script-from-stdin\n"),
		Stdout:       &stdout,
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
		Path:         os.Args[0],
		PathIdentity: currentExecutableIdentity(t),
		Args:         []string{"-test.run=TestExecHelperProcess", "--", "exit-42"},
		Env:          helperEnv(),
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

func TestRunRejectsMissingExecutableIdentity(t *testing.T) {
	t.Parallel()

	_, err := Run(context.Background(), Spec{
		Path: os.Args[0],
		Args: []string{"-test.run=TestExecHelperProcess", "--", "check-env"},
		Env:  helperEnv("AGENT_SECRET_CANARY", syntheticSecret),
	}, nil)
	if !errors.Is(err, ErrExecutableChanged) {
		t.Fatalf("Run error = %v, want %v", err, ErrExecutableChanged)
	}
}

func TestRunRejectsExecutableReplacementBeforeSpawn(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	writeExecwrapExecutable(t, path, "echo original\n")
	identity, err := fileidentity.Capture(path)
	if err != nil {
		t.Fatalf("Capture returned error: %v", err)
	}
	replacement := filepath.Join(dir, "replacement")
	writeExecwrapExecutable(t, replacement, "echo attacker\n")
	if err := os.Rename(replacement, path); err != nil {
		t.Fatalf("replace executable: %v", err)
	}

	var stdout bytes.Buffer
	_, err = Run(context.Background(), Spec{
		Path:         path,
		PathIdentity: identity,
		Env:          helperEnv("AGENT_SECRET_CANARY", syntheticSecret),
		Stdout:       &stdout,
	}, nil)
	if !errors.Is(err, ErrExecutableChanged) {
		t.Fatalf("Run error = %v, want %v", err, ErrExecutableChanged)
	}
	if stdout.Len() != 0 {
		t.Fatalf("replacement executable appears to have run: stdout=%q", stdout.String())
	}
}

func TestRunTerminatesChildWhenStartedLifecycleFails(t *testing.T) {
	t.Parallel()

	_, err := Run(context.Background(), Spec{
		Path:         os.Args[0],
		PathIdentity: currentExecutableIdentity(t),
		Args:         []string{"-test.run=TestExecHelperProcess", "--", "block-forever"},
		Env:          helperEnv(),
		Lifecycle:    failingLifecycle{},
	}, nil)
	if err == nil {
		t.Fatal("expected command_started lifecycle failure")
	}
}

func TestRunForwardsInterruptToChild(t *testing.T) {
	t.Parallel()

	interrupts := make(chan os.Signal, 1)
	stdout := newSignalTestOutput()
	readyErr := make(chan string, 1)

	go func() {
		if output, ok := waitForSignalOutput(stdout, stdout.ready); !ok {
			readyErr <- output
		}
		interrupts <- syscall.SIGINT
	}()

	result, err := Run(context.Background(), Spec{
		Path:         os.Args[0],
		PathIdentity: currentExecutableIdentity(t),
		Args:         []string{"-test.run=TestExecHelperProcess", "--", "wait-signal"},
		Env:          helperEnv(),
		Stdout:       stdout,
	}, interrupts)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	select {
	case output := <-readyErr:
		t.Fatalf("child did not signal readiness before interrupt; stdout=%q", output)
	default:
	}
	if result.ExitCode != 130 {
		t.Fatalf("exit code = %d, want 130; stdout=%q", result.ExitCode, stdout.String())
	}
	if !strings.Contains(stdout.String(), "signal-ok") {
		t.Fatalf("child did not observe forwarded signal; stdout=%q", stdout.String())
	}
}

func TestRunForwardsRepeatedInterruptsToChild(t *testing.T) {
	t.Parallel()

	interrupts := make(chan os.Signal, 2)
	stdout := newSignalTestOutput()
	readyErr := make(chan string, 1)

	go func() {
		if output, ok := waitForSignalOutput(stdout, stdout.ready); !ok {
			readyErr <- output
			interrupts <- syscall.SIGINT
			return
		}
		interrupts <- syscall.SIGINT
		if output, ok := waitForSignalOutput(stdout, stdout.firstSignal); !ok {
			readyErr <- output
			interrupts <- syscall.SIGINT
			return
		}
		interrupts <- syscall.SIGINT
	}()

	result, err := Run(context.Background(), Spec{
		Path:         os.Args[0],
		PathIdentity: currentExecutableIdentity(t),
		Args:         []string{"-test.run=TestExecHelperProcess", "--", "wait-two-signals"},
		Env:          helperEnv(),
		Stdout:       stdout,
	}, interrupts)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	select {
	case output := <-readyErr:
		t.Fatalf("child did not signal expected readiness before interrupt; stdout=%q", output)
	default:
	}
	if result.ExitCode != 130 {
		t.Fatalf("exit code = %d, want 130; stdout=%q", result.ExitCode, stdout.String())
	}
	if !strings.Contains(stdout.String(), "signal-1") || !strings.Contains(stdout.String(), "signal-2") {
		t.Fatalf("child did not observe both forwarded signals; stdout=%q", stdout.String())
	}
}

func TestRunTerminatesChildOnContextCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())

	result, err := Run(ctx, Spec{
		Path:         os.Args[0],
		PathIdentity: currentExecutableIdentity(t),
		Args:         []string{"-test.run=TestExecHelperProcess", "--", "block-forever"},
		Env:          helperEnv(),
		Lifecycle:    cancelingLifecycle{cancel: cancel},
	}, nil)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.ExitCode == 0 {
		t.Fatalf("exit code = 0, want cancellation to terminate child")
	}
}

func TestLifecycleEventShapeIsValueFree(t *testing.T) {
	t.Parallel()

	event := lifecycleEvent{Type: "command_started", ChildPID: 1234}
	if reflect.ValueOf(event).FieldByName("Env").IsValid() {
		t.Fatal("lifecycle event unexpectedly has an Env field")
	}
	if reflect.ValueOf(event).FieldByName("SecretAliases").IsValid() {
		t.Fatal("lifecycle event unexpectedly has a SecretAliases field")
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
	case "wait-two-signals":
		signals := make(chan os.Signal, 2)
		signalNotify(signals, syscall.SIGINT)
		fmt.Println("ready")
		<-signals
		fmt.Println("signal-1")
		<-signals
		fmt.Println("signal-2")
		os.Exit(130)
	case "block-forever":
		signals := make(chan os.Signal, 1)
		signalNotify(signals, syscall.SIGTERM)
		<-signals
		os.Exit(143)
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

func countEnv(env []string, key string) int {
	count := 0
	for _, entry := range env {
		gotKey, _, ok := strings.Cut(entry, "=")
		if ok && gotKey == key {
			count++
		}
	}
	return count
}

func helperEnv(pairs ...string) map[string]string {
	env := map[string]string{"AGENT_SECRET_EXEC_HELPER": "1"}
	for i := 0; i+1 < len(pairs); i += 2 {
		env[pairs[i]] = pairs[i+1]
	}
	return env
}

func currentExecutableIdentity(t *testing.T) fileidentity.Identity {
	t.Helper()
	identity, err := fileidentity.Capture(os.Args[0])
	if err != nil {
		t.Fatalf("capture current executable identity: %v", err)
	}
	return identity
}

func writeExecwrapExecutable(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil { //nolint:gosec // G306: exec wrapper identity tests need executable fixtures.
		t.Fatalf("write executable: %v", err)
	}
}
