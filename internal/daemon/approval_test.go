package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/request"
)

type recordingLauncher struct {
	mu       sync.Mutex
	launched []ApprovalRequestPayload
	expected ExpectedApprover
	err      error
}

type allowApproverIdentityPolicy struct{}

func (allowApproverIdentityPolicy) ValidateApproverExecutable(path string) (ApproverIdentity, error) {
	return ApproverIdentity{ExecutablePath: path}, nil
}

func (l *recordingLauncher) Launch(_ context.Context, _ string, payload ApprovalRequestPayload) (ExpectedApprover, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.launched = append(l.launched, payload)
	if l.err != nil {
		return ExpectedApprover{}, l.err
	}
	return l.expected, nil
}

func (l *recordingLauncher) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.launched)
}

func TestApprovalFixturesDecodeInGo(t *testing.T) {
	t.Parallel()

	requestData := readFixture(t, "approval_request.json")
	var approvalRequest ApprovalRequestPayload
	if err := json.Unmarshal(requestData, &approvalRequest); err != nil {
		t.Fatalf("decode approval request fixture: %v", err)
	}
	if approvalRequest.RequestID != "req_123" || approvalRequest.Nonce != "nonce_456" {
		t.Fatalf("unexpected approval request identifiers: %+v", approvalRequest)
	}
	if approvalRequest.Secrets[0].Ref != "op://Example Vault/Example Item/token" {
		t.Fatalf("unexpected secret ref: %+v", approvalRequest.Secrets)
	}
	if approvalRequest.Secrets[0].Account != "Work" {
		t.Fatalf("unexpected secret account: %+v", approvalRequest.Secrets)
	}

	decisionData := readFixture(t, "approval_decision.json")
	var decision ApprovalDecisionPayload
	if err := json.Unmarshal(decisionData, &decision); err != nil {
		t.Fatalf("decode approval decision fixture: %v", err)
	}
	if decision.Decision != "approve_reusable" || decision.ReusableUses == nil || *decision.ReusableUses != 3 {
		t.Fatalf("unexpected approval decision: %+v", decision)
	}
}

func TestSocketApproverLaunchesAndAcceptsExpectedPeerDecision(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	launcher := &recordingLauncher{expected: ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe}}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))

	resultCh := make(chan ApprovalDecision, 1)
	errCh := make(chan error, 1)
	go func() {
		decision, err := approver.ApproveExec(context.Background(), "req_1", "nonce_1", req)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- decision
	}()
	waitForPending(t, approver)

	payload, err := approver.FetchPending(context.Background(), peerInfoForTest(t, os.Getpid(), exe))
	if err != nil {
		t.Fatalf("FetchPending returned error: %v", err)
	}
	if payload.RequestID != "req_1" || payload.Nonce != "nonce_1" {
		t.Fatalf("unexpected payload identifiers: %+v", payload)
	}
	if payload.Secrets[0].Account != "Work" {
		t.Fatalf("payload secret account = %q, want Work", payload.Secrets[0].Account)
	}
	uses := 3
	err = approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), ApprovalDecisionPayload{
		RequestID:    "req_1",
		Nonce:        "nonce_1",
		Decision:     "approve_reusable",
		ReusableUses: &uses,
	})
	if err != nil {
		t.Fatalf("SubmitDecision returned error: %v", err)
	}

	select {
	case decision := <-resultCh:
		if !decision.Approved || !decision.Reusable {
			t.Fatalf("unexpected approval result: %+v", decision)
		}
	case err := <-errCh:
		t.Fatalf("ApproveExec returned error: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for approval result")
	}
}

func TestSocketApproverRejectsWrongPeerAndStaleNonce(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	launcher := &recordingLauncher{expected: ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe}}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	errCh := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(context.Background(), "req_1", "nonce_1", req)
		errCh <- err
	}()
	waitForPending(t, approver)

	if _, err := approver.FetchPending(context.Background(), peerInfoForTest(t, os.Getpid()+1, exe)); !errors.Is(err, ErrApproverPeerMismatch) {
		t.Fatalf("expected peer mismatch, got %v", err)
	}
	if _, err := approver.FetchPending(context.Background(), peerInfoForTest(t, os.Getpid(), exe)); err != nil {
		t.Fatalf("FetchPending returned error: %v", err)
	}
	err := approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "wrong",
		Decision:  "approve_once",
	})
	if !errors.Is(err, ErrStaleApproval) {
		t.Fatalf("expected stale approval error, got %v", err)
	}
	err = approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  "deny",
	})
	if err != nil {
		t.Fatalf("SubmitDecision deny returned error: %v", err)
	}
	if err := <-errCh; !errors.Is(err, ErrApprovalDenied) {
		t.Fatalf("ApproveExec error = %v, want denial", err)
	}
}

func TestSocketApproverFIFOAndQueuedExpiry(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	now := time.Date(2026, 4, 28, 16, 0, 0, 0, time.UTC)
	launcher := &recordingLauncher{expected: ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe}}
	approver := newSocketApproverForTest(t, launcher, func() time.Time { return now })
	first := approvalTestRequest(t, now.Add(time.Minute))
	expiredSecond := approvalTestRequest(t, now.Add(-time.Second))

	firstErr := make(chan error, 1)
	secondErr := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(context.Background(), "req_1", "nonce_1", first)
		firstErr <- err
	}()
	waitForPending(t, approver)
	go func() {
		_, err := approver.ApproveExec(context.Background(), "req_2", "nonce_2", expiredSecond)
		secondErr <- err
	}()

	payload, err := approver.FetchPending(context.Background(), peerInfoForTest(t, os.Getpid(), exe))
	if err != nil {
		t.Fatalf("FetchPending returned error: %v", err)
	}
	if payload.RequestID != "req_1" {
		t.Fatalf("FIFO displayed request %q first", payload.RequestID)
	}
	if err := approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  "approve_once",
	}); err != nil {
		t.Fatalf("SubmitDecision returned error: %v", err)
	}
	if err := <-firstErr; err != nil {
		t.Fatalf("first approval returned error: %v", err)
	}
	if err := <-secondErr; !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("second approval error = %v, want expired", err)
	}
	if launcher.Count() != 1 {
		t.Fatalf("expired queued request launched approver; launches=%d", launcher.Count())
	}
}

func TestSocketApproverExpiresActiveRequestWithoutDecision(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	launcher := &recordingLauncher{expected: ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe}}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(20*time.Millisecond))

	_, err := approver.ApproveExec(context.Background(), "req_1", "nonce_1", req)
	if !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("ApproveExec error = %v, want expired", err)
	}
}

func TestSocketApproverConstructorValidation(t *testing.T) {
	t.Parallel()

	if _, err := NewSocketApprover("", &recordingLauncher{}, time.Now); err == nil {
		t.Fatal("expected missing socket path error")
	}
	if _, err := NewSocketApprover("/tmp/agent-secret-test.sock", nil, time.Now); !errors.Is(err, ErrApproverLaunchFailed) {
		t.Fatalf("expected launcher error, got %v", err)
	}
}

func TestSocketApproverRejectsInvalidDecision(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	launcher := &recordingLauncher{expected: ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe}}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	errCh := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(context.Background(), "req_1", "nonce_1", req)
		errCh <- err
	}()
	waitForPending(t, approver)

	err := approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  "banana",
	})
	if !errors.Is(err, ErrMalformedEnvelope) {
		t.Fatalf("expected malformed decision error, got %v", err)
	}
	err = approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  "timeout",
	})
	if err != nil {
		t.Fatalf("timeout decision returned error: %v", err)
	}
	if err := <-errCh; !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("ApproveExec error = %v, want expired", err)
	}
}

func TestProcessApproverLauncherExecutablePath(t *testing.T) {
	t.Parallel()

	appPath := filepath.Join(t.TempDir(), "AgentSecretApprover.app")
	got, err := (ProcessApproverLauncher{AppPath: appPath}).executablePath()
	if err != nil {
		t.Fatalf("app executablePath returned error: %v", err)
	}
	want := filepath.Join(appPath, "Contents", "MacOS", "Agent Secret")
	if got != want {
		t.Fatalf("app executable path = %q, want %q", got, want)
	}

	binaryPath := filepath.Join(t.TempDir(), "agent-secret-approver")
	got, err = (ProcessApproverLauncher{AppPath: binaryPath}).executablePath()
	if err != nil {
		t.Fatalf("binary executablePath returned error: %v", err)
	}
	if got != binaryPath {
		t.Fatalf("binary executable path = %q, want %q", got, binaryPath)
	}
}

func TestProcessApproverLauncherPrefersUnifiedAppExecutable(t *testing.T) {
	t.Parallel()

	appPath := filepath.Join(t.TempDir(), "Agent Secret.app")
	unifiedExecutable := filepath.Join(appPath, "Contents", "MacOS", "Agent Secret")
	legacyExecutable := filepath.Join(appPath, "Contents", "MacOS", "agent-secret-approver")
	if err := os.MkdirAll(filepath.Dir(unifiedExecutable), 0o755); err != nil {
		t.Fatalf("create app macos dir: %v", err)
	}
	if err := os.WriteFile(legacyExecutable, []byte("test"), 0o755); err != nil {
		t.Fatalf("write legacy executable: %v", err)
	}
	if err := os.WriteFile(unifiedExecutable, []byte("test"), 0o755); err != nil {
		t.Fatalf("write unified executable: %v", err)
	}

	got, err := (ProcessApproverLauncher{AppPath: appPath}).executablePath()
	if err != nil {
		t.Fatalf("app executablePath returned error: %v", err)
	}
	if got != unifiedExecutable {
		t.Fatalf("app executable path = %q, want unified executable %q", got, unifiedExecutable)
	}
}

func TestApproverCandidatesForBundledExecutables(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	appPath := filepath.Join(root, "Agent Secret.app")
	cliPath := filepath.Join(appPath, "Contents", "Resources", "bin", "agent-secret")
	daemonPath := filepath.Join(
		appPath,
		"Contents",
		"Library",
		"Helpers",
		"AgentSecretDaemon.app",
		"Contents",
		"MacOS",
		"Agent Secret",
	)
	want := filepath.Join(appPath, "Contents", "MacOS", "Agent Secret")

	if !slices.Contains(approverCandidatesForExecutable(cliPath), want) {
		t.Fatalf("cli approver candidates missing top-level app executable")
	}
	if !slices.Contains(approverCandidatesForExecutable(daemonPath), want) {
		t.Fatalf("daemon approver candidates missing top-level app executable")
	}
}

func TestDefaultApproverPathUsesInstalledUnifiedApp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	want := filepath.Join(home, "Applications", "Agent Secret.app", "Contents", "MacOS", "Agent Secret")
	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		t.Fatalf("create app macos dir: %v", err)
	}
	if err := os.WriteFile(want, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write app executable: %v", err)
	}

	got, err := defaultApproverPath()
	if err != nil {
		t.Fatalf("defaultApproverPath returned error: %v", err)
	}
	if got != want {
		t.Fatalf("default approver path = %q, want installed app executable %q", got, want)
	}
}

func TestDefaultApproverPathIgnoresEnvironmentOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AGENT_SECRET_APPROVER_PATH", filepath.Join(t.TempDir(), "PoisonApprover.app"))
	want := filepath.Join(home, "Applications", "Agent Secret.app", "Contents", "MacOS", "Agent Secret")
	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		t.Fatalf("create app macos dir: %v", err)
	}
	if err := os.WriteFile(want, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write app executable: %v", err)
	}

	got, err := defaultApproverPath()
	if err != nil {
		t.Fatalf("defaultApproverPath returned error: %v", err)
	}
	if got != want {
		t.Fatalf("default approver path = %q, want installed app executable %q", got, want)
	}
}

func TestProcessApproverLauncherLaunchesBinary(t *testing.T) {
	t.Parallel()

	helper := filepath.Join(t.TempDir(), "approver-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write helper: %v", err)
	}

	expected, err := (ProcessApproverLauncher{
		AppPath:        helper,
		IdentityPolicy: allowApproverIdentityPolicy{},
	}).Launch(
		context.Background(),
		"/tmp/agent-secret-test.sock",
		ApprovalRequestPayload{},
	)
	if err != nil {
		t.Fatalf("Launch returned error: %v", err)
	}
	if expected.PID <= 0 {
		t.Fatalf("expected launched process pid, got %+v", expected)
	}
	if expected.ExecutablePath != helper {
		t.Fatalf("expected executable path = %q, want %q", expected.ExecutablePath, helper)
	}
}

func TestProcessApproverLauncherHealthCheck(t *testing.T) {
	t.Parallel()

	helper := filepath.Join(t.TempDir(), "approver-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nif [ \"$1\" = \"--health-check\" ]; then echo 'agent-secret-approver: ok'; exit 0; fi\nexit 64\n"), 0o755); err != nil {
		t.Fatalf("write helper: %v", err)
	}

	err := (ProcessApproverLauncher{
		AppPath:        helper,
		IdentityPolicy: allowApproverIdentityPolicy{},
	}).CheckHealth(context.Background())
	if err != nil {
		t.Fatalf("CheckHealth returned error: %v", err)
	}
}

func TestProcessApproverLauncherHealthCheckRejectsUnexpectedOutput(t *testing.T) {
	t.Parallel()

	helper := filepath.Join(t.TempDir(), "approver-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\necho nope\n"), 0o755); err != nil {
		t.Fatalf("write helper: %v", err)
	}

	err := (ProcessApproverLauncher{
		AppPath:        helper,
		IdentityPolicy: allowApproverIdentityPolicy{},
	}).CheckHealth(context.Background())
	if !errors.Is(err, ErrApproverLaunchFailed) {
		t.Fatalf("CheckHealth error = %v, want ErrApproverLaunchFailed", err)
	}
}

func TestProcessApproverLauncherRejectsBareBinaryByDefault(t *testing.T) {
	t.Parallel()

	helper := filepath.Join(t.TempDir(), "agent-secret-approver")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write helper: %v", err)
	}

	_, err := (ProcessApproverLauncher{AppPath: helper}).Launch(
		context.Background(),
		"/tmp/agent-secret-test.sock",
		ApprovalRequestPayload{},
	)
	if !errors.Is(err, ErrApproverIdentity) {
		t.Fatalf("expected approver identity error, got %v", err)
	}
}

func TestProcessApproverLauncherWrapsStartFailure(t *testing.T) {
	t.Parallel()

	_, err := (ProcessApproverLauncher{
		AppPath:        filepath.Join(t.TempDir(), "missing"),
		IdentityPolicy: allowApproverIdentityPolicy{},
	}).Launch(
		context.Background(),
		"/tmp/agent-secret-test.sock",
		ApprovalRequestPayload{},
	)
	if !errors.Is(err, ErrApproverLaunchFailed) {
		t.Fatalf("expected launch failure, got %v", err)
	}
}

func TestBundleApproverIdentityPolicyValidatesBundleMetadata(t *testing.T) {
	t.Parallel()

	executable := writeApproverBundle(t, t.TempDir(), DefaultApproverBundleID, DefaultApproverExecutable)
	identity, err := (BundleApproverIdentityPolicy{VerifySignature: false}).ValidateApproverExecutable(executable)
	if err != nil {
		t.Fatalf("ValidateApproverExecutable returned error: %v", err)
	}
	wantExecutable, err := comparableApproverPath(executable)
	if err != nil {
		t.Fatalf("comparableApproverPath returned error: %v", err)
	}
	if identity.ExecutablePath != wantExecutable {
		t.Fatalf("identity executable = %q, want %q", identity.ExecutablePath, wantExecutable)
	}
	if identity.BundleID != DefaultApproverBundleID {
		t.Fatalf("identity bundle id = %q", identity.BundleID)
	}
}

func TestDefaultApproverIdentityMatchesBundleMetadata(t *testing.T) {
	t.Parallel()

	metadata := readBundleMetadata(t)
	if DefaultApproverBundleID != metadata["AGENT_SECRET_APP_BUNDLE_ID"] {
		t.Fatalf(
			"DefaultApproverBundleID = %q, want bundle metadata %q",
			DefaultApproverBundleID,
			metadata["AGENT_SECRET_APP_BUNDLE_ID"],
		)
	}
	if DefaultApproverExecutable != metadata["AGENT_SECRET_APP_EXECUTABLE"] {
		t.Fatalf(
			"DefaultApproverExecutable = %q, want bundle metadata %q",
			DefaultApproverExecutable,
			metadata["AGENT_SECRET_APP_EXECUTABLE"],
		)
	}
}

func TestBundleApproverIdentityPolicyRejectsWrongBundleID(t *testing.T) {
	t.Parallel()

	executable := writeApproverBundle(t, t.TempDir(), "com.example.fake", DefaultApproverExecutable)
	_, err := (BundleApproverIdentityPolicy{VerifySignature: false}).ValidateApproverExecutable(executable)
	if !errors.Is(err, ErrApproverIdentity) {
		t.Fatalf("expected approver identity error, got %v", err)
	}
}

func newSocketApproverForTest(t *testing.T, launcher ApproverLauncher, now func() time.Time) *SocketApprover {
	t.Helper()
	approver, err := NewSocketApprover("/tmp/agent-secret-test.sock", launcher, now)
	if err != nil {
		t.Fatalf("NewSocketApprover returned error: %v", err)
	}
	return approver
}

func writeApproverBundle(t *testing.T, dir string, bundleID string, executableName string) string {
	t.Helper()
	bundlePath := filepath.Join(dir, "AgentSecretApprover.app")
	macOSPath := filepath.Join(bundlePath, "Contents", "MacOS")
	if err := os.MkdirAll(macOSPath, 0o755); err != nil {
		t.Fatalf("mkdir bundle: %v", err)
	}
	executablePath := filepath.Join(macOSPath, executableName)
	if err := os.WriteFile(executablePath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write executable: %v", err)
	}
	info := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>` + bundleID + `</string>
  <key>CFBundleExecutable</key>
  <string>` + executableName + `</string>
</dict>
</plist>
`
	if err := os.WriteFile(filepath.Join(bundlePath, "Contents", "Info.plist"), []byte(info), 0o644); err != nil {
		t.Fatalf("write Info.plist: %v", err)
	}
	return executablePath
}

func approvalTestRequest(t *testing.T, expiresAt time.Time) request.ExecRequest {
	t.Helper()
	ref, err := request.ParseSecretRef("op://Example/Item/token")
	if err != nil {
		t.Fatalf("ParseSecretRef returned error: %v", err)
	}
	return request.ExecRequest{
		Reason:             "Run Terraform plan",
		Command:            []string{"terraform", "plan"},
		ResolvedExecutable: "/opt/homebrew/bin/terraform",
		CWD:                "/tmp/project",
		Secrets:            []request.Secret{{Alias: "TOKEN", Ref: ref, Account: "Work"}},
		ReceivedAt:         expiresAt.Add(-request.DefaultExecTTL),
		ExpiresAt:          expiresAt,
		TTL:                request.DefaultExecTTL,
		DeliveryMode:       request.DeliveryEnvExec,
	}
}

func peerInfoForTest(t *testing.T, pid int, exe string) peercred.Info {
	t.Helper()
	return peercred.Info{
		UID:            os.Getuid(),
		GID:            os.Getgid(),
		PID:            pid,
		ExecutablePath: exe,
		CWD:            "/tmp",
	}
}

func currentExecutable(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable returned error: %v", err)
	}
	return exe
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(
		filepath.Dir(file),
		"..",
		"..",
		"approver",
		"Tests",
		"AgentSecretApproverTests",
		"Fixtures",
		name,
	)
	//nolint:gosec // G304: test fixture path is derived from runtime.Caller within this repository.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func readBundleMetadata(t *testing.T) map[string]string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(file), "..", "..", "scripts", "bundle-metadata.sh")
	//nolint:gosec // G304: test metadata path is derived from runtime.Caller within this repository.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read bundle metadata: %v", err)
	}

	metadata := make(map[string]string)
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		metadata[key] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return metadata
}

func waitForPending(t *testing.T, approver *SocketApprover) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		approver.mu.Lock()
		ready := approver.active != nil && approver.active.expectedReady
		approver.mu.Unlock()
		if ready {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for pending approval")
}
