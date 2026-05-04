package approval

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/daemon/trust"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/testsupport/appbundle"
)

type allowApproverIdentityPolicy struct{}

func (allowApproverIdentityPolicy) ValidateApproverExecutable(path string) (ApproverIdentity, error) {
	return ApproverIdentity{ExecutablePath: path}, nil
}

type staticApproverIdentityPolicy struct {
	identity ApproverIdentity
}

func (p staticApproverIdentityPolicy) ValidateApproverExecutable(path string) (ApproverIdentity, error) {
	identity := p.identity
	if identity.ExecutablePath == "" {
		identity.ExecutablePath = path
	}
	return identity, nil
}

type fakeHealthCheckRunner struct {
	stdout string
	err    error
}

func (r fakeHealthCheckRunner) RunHealthCheck(ctx context.Context, _ string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return r.stdout, r.err
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

	binaryPath := filepath.Join(t.TempDir(), "agent-secret-app")
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
	if err := os.MkdirAll(filepath.Dir(unifiedExecutable), 0o750); err != nil {
		t.Fatalf("create app macos dir: %v", err)
	}
	if err := os.WriteFile(unifiedExecutable, []byte("test"), 0o755); err != nil { //nolint:gosec // G306: approver tests need runnable app executable fixtures.
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
	if err := os.MkdirAll(filepath.Dir(want), 0o750); err != nil {
		t.Fatalf("create app macos dir: %v", err)
	}
	if err := os.WriteFile(want, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: default approver path tests need runnable app executable fixtures.
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
	if err := os.MkdirAll(filepath.Dir(want), 0o750); err != nil {
		t.Fatalf("create app macos dir: %v", err)
	}
	if err := os.WriteFile(want, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: default approver path tests need runnable app executable fixtures.
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
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: launcher tests need runnable helper executables.
		t.Fatalf("write helper: %v", err)
	}

	expected, err := (ProcessApproverLauncher{
		AppPath:        helper,
		IdentityPolicy: allowApproverIdentityPolicy{},
	}).Launch(
		context.Background(),
		"/tmp/agent-secret-test.sock",
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

func TestProcessApproverLauncherExposesEarlyProcessExit(t *testing.T) {
	t.Parallel()

	helper := filepath.Join(t.TempDir(), "approver-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 42\n"), 0o755); err != nil { //nolint:gosec // G306: launcher tests need runnable helper executables.
		t.Fatalf("write helper: %v", err)
	}

	expected, err := (ProcessApproverLauncher{
		AppPath:        helper,
		IdentityPolicy: allowApproverIdentityPolicy{},
	}).Launch(
		context.Background(),
		"/tmp/agent-secret-test.sock",
	)
	if err != nil {
		t.Fatalf("Launch returned error: %v", err)
	}
	if expected.Exited == nil {
		t.Fatal("expected process exit monitor channel")
	}
	select {
	case err := <-expected.Exited:
		if err == nil {
			t.Fatal("expected non-zero helper exit error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for helper process exit")
	}
}

func TestProcessApproverLauncherCarriesSignaturePolicyToExpectedPeer(t *testing.T) {
	t.Parallel()

	helper := filepath.Join(t.TempDir(), "approver-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: launcher tests need runnable helper executables.
		t.Fatalf("write helper: %v", err)
	}

	expected, err := (ProcessApproverLauncher{
		AppPath: helper,
		IdentityPolicy: staticApproverIdentityPolicy{identity: ApproverIdentity{
			ExpectedTeamID:  "TEAMID",
			VerifySignature: true,
		}},
	}).Launch(
		context.Background(),
		"/tmp/agent-secret-test.sock",
	)
	if err != nil {
		t.Fatalf("Launch returned error: %v", err)
	}
	if expected.ExpectedTeamID != "TEAMID" {
		t.Fatalf("ExpectedTeamID = %q, want TEAMID", expected.ExpectedTeamID)
	}
	if !expected.VerifySignature {
		t.Fatal("VerifySignature = false, want true")
	}
	if expected.SignatureVerifier == nil {
		t.Fatal("SignatureVerifier is nil")
	}
}

func TestProcessApproverLauncherHealthCheck(t *testing.T) {
	t.Parallel()

	err := (ProcessApproverLauncher{
		AppPath:        "/tmp/approver-helper",
		IdentityPolicy: allowApproverIdentityPolicy{},
		healthRunner:   fakeHealthCheckRunner{stdout: "Agent Secret: ok"},
	}).CheckHealth(context.Background())
	if err != nil {
		t.Fatalf("CheckHealth returned error: %v", err)
	}
}

func TestProcessHealthCheckRunnerRunsHelper(t *testing.T) {
	helper := writeHealthCheckHelper(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stdout, err := (processHealthCheckRunner{}).RunHealthCheck(ctx, helper)
	if err != nil {
		t.Fatalf("RunHealthCheck returned error: %v", err)
	}
	if stdout != "Agent Secret: ok" {
		t.Fatalf("RunHealthCheck stdout = %q, want health response", stdout)
	}
}

func TestProcessApproverLauncherHealthCheckRejectsUnexpectedOutput(t *testing.T) {
	t.Parallel()

	err := (ProcessApproverLauncher{
		AppPath:        "/tmp/approver-helper",
		IdentityPolicy: allowApproverIdentityPolicy{},
		healthRunner:   fakeHealthCheckRunner{stdout: "nope"},
	}).CheckHealth(context.Background())
	if !errors.Is(err, ErrApproverLaunchFailed) {
		t.Fatalf("CheckHealth error = %v, want ErrApproverLaunchFailed", err)
	}
}

func TestProcessApproverLauncherHealthCheckPreservesContextErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		makeCtx func(*testing.T) context.Context
		want    error
	}{
		{
			name:    "canceled",
			makeCtx: canceledContext,
			want:    context.Canceled,
		},
		{
			name:    "deadline",
			makeCtx: expiredDeadlineContext,
			want:    context.DeadlineExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (ProcessApproverLauncher{
				AppPath:        "/tmp/approver-helper",
				IdentityPolicy: allowApproverIdentityPolicy{},
				healthRunner:   fakeHealthCheckRunner{stdout: "Agent Secret: ok"},
			}).CheckHealth(tt.makeCtx(t))
			if !errors.Is(err, ErrApproverLaunchFailed) {
				t.Fatalf("CheckHealth error = %v, want ErrApproverLaunchFailed", err)
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("CheckHealth error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestProcessApproverLauncherRejectsBareBinaryByDefault(t *testing.T) {
	t.Parallel()

	helper := filepath.Join(t.TempDir(), "agent-secret-app")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: launcher tests need runnable helper executables.
		t.Fatalf("write helper: %v", err)
	}

	_, err := (ProcessApproverLauncher{AppPath: helper}).Launch(
		context.Background(),
		"/tmp/agent-secret-test.sock",
	)
	if !errors.Is(err, ErrApproverIdentity) {
		t.Fatalf("expected approver identity error, got %v", err)
	}
}

func writeHealthCheckHelper(t *testing.T) string {
	t.Helper()

	helper := filepath.Join(t.TempDir(), "approver-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nif [ \"$1\" = \"--health-check\" ]; then echo 'Agent Secret: ok'; exit 0; fi\nexit 64\n"), 0o755); err != nil { //nolint:gosec // G306: launcher tests need runnable helper executables.
		t.Fatalf("write helper: %v", err)
	}
	return helper
}

func canceledContext(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func expiredDeadlineContext(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	t.Cleanup(cancel)
	return ctx
}

func TestProcessApproverLauncherWrapsStartFailure(t *testing.T) {
	t.Parallel()

	_, err := (ProcessApproverLauncher{
		AppPath:        filepath.Join(t.TempDir(), "missing"),
		IdentityPolicy: allowApproverIdentityPolicy{},
	}).Launch(
		context.Background(),
		"/tmp/agent-secret-test.sock",
	)
	if !errors.Is(err, ErrApproverLaunchFailed) {
		t.Fatalf("expected launch failure, got %v", err)
	}
}

func TestBundleApproverIdentityPolicyValidatesBundleMetadata(t *testing.T) {
	t.Parallel()

	executable := appbundle.WriteApproverBundle(t, t.TempDir(), DefaultApproverBundleID, DefaultApproverExecutable)
	identity, err := (BundleApproverIdentityPolicy{VerifySignature: false}).ValidateApproverExecutable(executable)
	if err != nil {
		t.Fatalf("ValidateApproverExecutable returned error: %v", err)
	}
	wantExecutable, err := comparableApproverPath(executable, ErrApproverIdentity)
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

func TestBundleApproverIdentityPolicyRejectsMissingTeamIDWhenSignatureVerificationEnabled(t *testing.T) {
	t.Parallel()

	executable := appbundle.WriteApproverBundle(t, t.TempDir(), DefaultApproverBundleID, DefaultApproverExecutable)
	_, err := (BundleApproverIdentityPolicy{VerifySignature: true}).ValidateApproverExecutable(executable)
	if !errors.Is(err, ErrApproverIdentity) {
		t.Fatalf("expected approver identity error, got %v", err)
	}
	if !strings.Contains(err.Error(), "expected Developer ID Team ID is required") {
		t.Fatalf("error = %q, want missing Team ID context", err.Error())
	}
}

func TestApproverPeerValidationRejectsMissingTeamIDWhenSignatureVerificationEnabled(t *testing.T) {
	t.Parallel()

	err := ValidateApproverPeer(
		ExpectedApprover{
			PID:             os.Getpid(),
			ExecutablePath:  currentExecutable(t),
			VerifySignature: true,
		},
		peerInfoForTest(t, os.Getpid(), currentExecutable(t)),
	)
	if !errors.Is(err, ErrApproverPeerMismatch) {
		t.Fatalf("expected approver peer mismatch, got %v", err)
	}
	if !strings.Contains(err.Error(), "expected Developer ID Team ID is required") {
		t.Fatalf("error = %q, want missing Team ID context", err.Error())
	}
}

func TestApproverPeerValidationAllowsExplicitDevelopmentTeamIDSentinel(t *testing.T) {
	t.Parallel()

	err := ValidateApproverPeer(
		ExpectedApprover{
			PID:             os.Getpid(),
			ExecutablePath:  currentExecutable(t),
			ExpectedTeamID:  trust.DevelopmentExpectedTeamID,
			VerifySignature: true,
		},
		peerInfoForTest(t, os.Getpid(), currentExecutable(t)),
	)
	if err != nil {
		t.Fatalf("explicit development Team ID sentinel returned error: %v", err)
	}
}

func TestBundleApproverIdentityPolicyRejectsWrongBundleID(t *testing.T) {
	t.Parallel()

	executable := appbundle.WriteApproverBundle(t, t.TempDir(), "com.example.fake", DefaultApproverExecutable)
	_, err := (BundleApproverIdentityPolicy{VerifySignature: false}).ValidateApproverExecutable(executable)
	if !errors.Is(err, ErrApproverIdentity) {
		t.Fatalf("expected approver identity error, got %v", err)
	}
}

func TestBundleApproverIdentityPolicyRejectsWrongExecutableName(t *testing.T) {
	t.Parallel()

	executable := appbundle.WriteApproverBundle(t, t.TempDir(), DefaultApproverBundleID, "Fake Approver")
	_, err := (BundleApproverIdentityPolicy{VerifySignature: false}).ValidateApproverExecutable(executable)
	if !errors.Is(err, ErrApproverIdentity) {
		t.Fatalf("expected approver identity error, got %v", err)
	}
	if !strings.Contains(err.Error(), "executable") {
		t.Fatalf("error = %q, want executable context", err.Error())
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

func readBundleMetadata(t *testing.T) map[string]string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(file), "..", "..", "..", "scripts", "lib", "bundle-metadata.sh")
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
