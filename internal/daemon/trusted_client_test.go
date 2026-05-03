package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kovyrin/agent-secret/internal/peercred"
)

type recordingSignatureVerifier struct {
	pathTeamID    string
	processTeamID string
	pathErr       error
	processErr    error
	paths         []string
	pids          []int
}

func (v *recordingSignatureVerifier) VerifyPath(path string) (string, error) {
	v.paths = append(v.paths, path)
	if v.pathErr != nil {
		return "", v.pathErr
	}
	return v.pathTeamID, nil
}

func (v *recordingSignatureVerifier) VerifyProcess(pid int) (string, error) {
	v.pids = append(v.pids, pid)
	if v.processErr != nil {
		return "", v.processErr
	}
	return v.processTeamID, nil
}

func newTestTrustedExecutableValidator(
	paths []string,
	verifier codeSignatureVerifier,
) TrustedExecutableValidator {
	return TrustedExecutableValidator{
		set: newTrustedExecutableSetWithVerifier(paths, "TEAMID", ErrUntrustedClient, verifier, true),
	}
}

func TestTrustedExecutableValidatorMatchesComparableExecutablePath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := writeExecutableAt(t, dir, "agent-secret-real")
	link := filepath.Join(dir, "agent-secret")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	validator := NewTrustedExecutableValidator([]string{link})
	err := validator.ValidateExecPeer(peercred.Info{ExecutablePath: target})
	if err != nil {
		t.Fatalf("ValidateExecPeer returned error: %v", err)
	}
}

func TestTrustedExecutableValidatorRejectsUnlistedExecutable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	trusted := writeExecutableAt(t, dir, "agent-secret")
	other := writeExecutableAt(t, dir, "raw-client")

	validator := NewTrustedExecutableValidator([]string{trusted})
	err := validator.ValidateExecPeer(peercred.Info{ExecutablePath: other})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("expected ErrUntrustedClient, got %v", err)
	}
}

func TestTrustedExecutableValidatorRejectsExecutableReplacedAfterStartup(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	trusted := writeExecutableAt(t, dir, "agent-secret")
	validator := NewTrustedExecutableValidator([]string{trusted})

	if err := os.Remove(trusted); err != nil {
		t.Fatalf("remove trusted executable: %v", err)
	}
	if err := os.WriteFile(trusted, []byte("#!/bin/sh\nexit 64\n"), 0o755); err != nil { //nolint:gosec // G306: trusted-client tests need a runnable replacement executable.
		t.Fatalf("replace trusted executable: %v", err)
	}

	err := validator.ValidateExecPeer(peercred.Info{ExecutablePath: trusted})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("expected ErrUntrustedClient after replacement, got %v", err)
	}
}

func TestTrustedExecutableValidatorVerifiesPeerProcessSignature(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	trusted := writeExecutableAt(t, dir, "agent-secret")
	verifier := &recordingSignatureVerifier{
		pathTeamID:    "TEAMID",
		processTeamID: "TEAMID",
	}
	validator := newTestTrustedExecutableValidator([]string{trusted}, verifier)

	if err := validator.ValidateExecPeer(peercred.Info{ExecutablePath: trusted, PID: 4321}); err != nil {
		t.Fatalf("ValidateExecPeer returned error: %v", err)
	}
	wantPath := comparablePath(trusted)
	if !slices.Equal(verifier.paths, []string{wantPath}) {
		t.Fatalf("verified paths = %v, want [%s]", verifier.paths, wantPath)
	}
	if !slices.Equal(verifier.pids, []int{4321}) {
		t.Fatalf("verified pids = %v, want [4321]", verifier.pids)
	}
}

func TestTrustedExecutableValidatorRejectsPeerProcessSignatureMismatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	trusted := writeExecutableAt(t, dir, "agent-secret")
	verifier := &recordingSignatureVerifier{
		pathTeamID:    "TEAMID",
		processTeamID: "OTHERTEAM",
	}
	validator := newTestTrustedExecutableValidator([]string{trusted}, verifier)

	err := validator.ValidateExecPeer(peercred.Info{ExecutablePath: trusted, PID: 4321})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("expected ErrUntrustedClient, got %v", err)
	}
	wantPath := comparablePath(trusted)
	if !slices.Equal(verifier.paths, []string{wantPath}) {
		t.Fatalf("verified paths = %v, want [%s]", verifier.paths, wantPath)
	}
	if !slices.Equal(verifier.pids, []int{4321}) {
		t.Fatalf("verified pids = %v, want [4321]", verifier.pids)
	}
}

func TestTrustedExecutableValidatorRejectsMissingPIDForSignatureValidation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	trusted := writeExecutableAt(t, dir, "agent-secret")
	verifier := &recordingSignatureVerifier{
		pathTeamID:    "TEAMID",
		processTeamID: "TEAMID",
	}
	validator := newTestTrustedExecutableValidator([]string{trusted}, verifier)

	err := validator.ValidateExecPeer(peercred.Info{ExecutablePath: trusted})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("expected ErrUntrustedClient, got %v", err)
	}
	if len(verifier.paths) != 0 || len(verifier.pids) != 0 {
		t.Fatalf("signature verifier called for missing pid: paths=%v pids=%v", verifier.paths, verifier.pids)
	}
}

func TestTrustedExecutableValidatorWrapsPeerProcessSignatureFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	trusted := writeExecutableAt(t, dir, "agent-secret")
	verifier := &recordingSignatureVerifier{
		pathTeamID: "TEAMID",
		processErr: errors.New("codesign refused pid"),
	}
	validator := newTestTrustedExecutableValidator([]string{trusted}, verifier)

	err := validator.ValidateExecPeer(peercred.Info{ExecutablePath: trusted, PID: 4321})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("expected ErrUntrustedClient, got %v", err)
	}
	if !strings.Contains(err.Error(), "verify peer process signature") {
		t.Fatalf("error = %q, want peer process signature context", err.Error())
	}
}

func TestTrustedExecutableValidatorSkipsMissingTrustedPath(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "agent-secret")
	validator := NewTrustedExecutableValidator([]string{missing})

	err := validator.ValidateExecPeer(peercred.Info{ExecutablePath: missing})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("expected ErrUntrustedClient for missing trusted path, got %v", err)
	}
}

func TestDefaultTrustedClientPathsIncludeBundledCLIForDaemonHelper(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	appPath := filepath.Join(root, "Agent Secret.app")
	daemonExe := filepath.Join(
		appPath,
		"Contents",
		"Library",
		"Helpers",
		"AgentSecretDaemon.app",
		"Contents",
		"MacOS",
		"Agent Secret",
	)
	wantCLI := filepath.Join(appPath, "Contents", "Resources", "bin", "agent-secret")

	got := trustedClientPathsForExecutable(daemonExe)
	if !slices.Contains(got, wantCLI) {
		t.Fatalf("trusted paths = %v, want bundled CLI %q", got, wantCLI)
	}
}

func TestDefaultTrustedClientPathsDoNotIncludeUserLocalBin(t *testing.T) {
	t.Parallel()

	daemonExe := filepath.Join(t.TempDir(), "agent-secretd")
	got := trustedClientPathsForExecutable(daemonExe)
	for _, path := range got {
		if strings.Contains(path, filepath.Join(".local", "bin", "agent-secret")) {
			t.Fatalf("trusted paths include mutable user command path: %v", got)
		}
	}
}
