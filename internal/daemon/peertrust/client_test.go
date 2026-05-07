package peertrust

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/daemon/trust"
	"github.com/kovyrin/agent-secret/internal/fileidentity"
	"github.com/kovyrin/agent-secret/internal/pathresolve"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/testsupport/appbundle"
)

type recordingSignatureVerifier struct {
	pathTeamID    string
	processTeamID string
	pathErr       error
	processErr    error
	paths         []string
	pids          []int
}

func writeExecutableAt(t *testing.T, dir string, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: peer trust tests need executable fixtures.
		t.Fatalf("write executable: %v", err)
	}
	return path
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

func newTestExecutableValidator(
	paths []string,
	verifier trust.CodeSignatureVerifier,
) ExecutableValidator {
	return ExecutableValidator{
		set: newExecutableSetWithVerifier(paths, "TEAMID", ErrUntrustedClient, verifier, true),
	}
}

func TestExecutableValidatorMatchesComparableExecutablePath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := writeExecutableAt(t, dir, "agent-secret-real")
	link := filepath.Join(dir, "agent-secret")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	validator := NewExecutableValidator([]string{link})
	err := validator.ValidatePeer(peercred.Info{ExecutablePath: target})
	if err != nil {
		t.Fatalf("ValidatePeer returned error: %v", err)
	}
}

func TestExecutableValidatorRejectsUnlistedExecutable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	trusted := writeExecutableAt(t, dir, "agent-secret")
	other := writeExecutableAt(t, dir, "raw-client")

	validator := NewExecutableValidator([]string{trusted})
	err := validator.ValidatePeer(peercred.Info{ExecutablePath: other})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("expected ErrUntrustedClient, got %v", err)
	}
}

func TestExecutableValidatorRejectsBrokenPeerExecutablePath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	trusted := writeExecutableAt(t, dir, "agent-secret")
	broken := filepath.Join(dir, "broken")
	if err := os.Symlink(filepath.Join(dir, "missing"), broken); err != nil {
		t.Fatalf("create broken symlink: %v", err)
	}

	validator := NewExecutableValidator([]string{trusted})
	err := validator.ValidatePeer(peercred.Info{ExecutablePath: broken})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("ValidatePeer error = %v, want ErrUntrustedClient", err)
	}
	if !strings.Contains(err.Error(), "normalize peer executable") {
		t.Fatalf("ValidatePeer error = %q, want normalization context", err.Error())
	}
}

func TestExecutableValidatorRejectsBrokenTrustedExecutablePath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	trusted := writeExecutableAt(t, dir, "agent-secret")
	broken := filepath.Join(dir, "broken")
	if err := os.Symlink(filepath.Join(dir, "missing"), broken); err != nil {
		t.Fatalf("create broken symlink: %v", err)
	}

	validator := NewExecutableValidator([]string{broken})
	err := validator.ValidatePeer(peercred.Info{ExecutablePath: trusted})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("ValidatePeer error = %v, want ErrUntrustedClient", err)
	}
	if !strings.Contains(err.Error(), "canonicalize trusted executable") {
		t.Fatalf("ValidatePeer error = %q, want trusted executable context", err.Error())
	}
}

func TestExecutableValidatorRejectsExecutableReplacedAfterStartup(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	trusted := writeExecutableAt(t, dir, "agent-secret")
	validator := NewExecutableValidator([]string{trusted})

	if err := os.Remove(trusted); err != nil {
		t.Fatalf("remove trusted executable: %v", err)
	}
	if err := os.WriteFile(trusted, []byte("#!/bin/sh\nexit 64\n"), 0o755); err != nil { //nolint:gosec // G306: trusted-client tests need a runnable replacement executable.
		t.Fatalf("replace trusted executable: %v", err)
	}

	err := validator.ValidatePeer(peercred.Info{ExecutablePath: trusted})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("expected ErrUntrustedClient after replacement, got %v", err)
	}
}

func TestExecutableValidatorRejectsExecutableMutatedAfterStartupWhenSignatureDisabled(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	trusted := writeExecutableAt(t, dir, "agent-secret")
	validator := ExecutableValidator{
		set: newExecutableSetWithVerifier(
			[]string{trusted},
			"",
			ErrUntrustedClient,
			&recordingSignatureVerifier{},
			false,
		),
	}

	if err := os.WriteFile(trusted, []byte("#!/bin/sh\nexit 64\n# changed\n"), 0o755); err != nil { //nolint:gosec // G306: trusted-client tests need a mutated executable fixture.
		t.Fatalf("mutate trusted executable: %v", err)
	}

	err := validator.ValidatePeer(peercred.Info{ExecutablePath: trusted})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("expected ErrUntrustedClient after mutation, got %v", err)
	}
	if !errors.Is(err, fileidentity.ErrMismatch) {
		t.Fatalf("expected file identity mismatch after mutation, got %v", err)
	}
}

func TestExecutableValidatorVerifiesPeerProcessSignature(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	trusted := writeExecutableAt(t, dir, "agent-secret")
	verifier := &recordingSignatureVerifier{
		pathTeamID:    "TEAMID",
		processTeamID: "TEAMID",
	}
	validator := newTestExecutableValidator([]string{trusted}, verifier)

	if err := validator.ValidatePeer(peercred.Info{ExecutablePath: trusted, PID: 4321}); err != nil {
		t.Fatalf("ValidatePeer returned error: %v", err)
	}
	wantPath, err := pathresolve.Strict(trusted)
	if err != nil {
		t.Fatalf("resolve trusted path: %v", err)
	}
	if !slices.Equal(verifier.paths, []string{wantPath}) {
		t.Fatalf("verified paths = %v, want [%s]", verifier.paths, wantPath)
	}
	if !slices.Equal(verifier.pids, []int{4321}) {
		t.Fatalf("verified pids = %v, want [4321]", verifier.pids)
	}
}

func TestExecutableValidatorRejectsPeerProcessSignatureMismatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	trusted := writeExecutableAt(t, dir, "agent-secret")
	verifier := &recordingSignatureVerifier{
		pathTeamID:    "TEAMID",
		processTeamID: "OTHERTEAM",
	}
	validator := newTestExecutableValidator([]string{trusted}, verifier)

	err := validator.ValidatePeer(peercred.Info{ExecutablePath: trusted, PID: 4321})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("expected ErrUntrustedClient, got %v", err)
	}
	wantPath, resolveErr := pathresolve.Strict(trusted)
	if resolveErr != nil {
		t.Fatalf("resolve trusted path: %v", resolveErr)
	}
	if !slices.Equal(verifier.paths, []string{wantPath}) {
		t.Fatalf("verified paths = %v, want [%s]", verifier.paths, wantPath)
	}
	if !slices.Equal(verifier.pids, []int{4321}) {
		t.Fatalf("verified pids = %v, want [4321]", verifier.pids)
	}
}

func TestExecutableValidatorRejectsMissingPIDForSignatureValidation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	trusted := writeExecutableAt(t, dir, "agent-secret")
	verifier := &recordingSignatureVerifier{
		pathTeamID:    "TEAMID",
		processTeamID: "TEAMID",
	}
	validator := newTestExecutableValidator([]string{trusted}, verifier)

	err := validator.ValidatePeer(peercred.Info{ExecutablePath: trusted})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("expected ErrUntrustedClient, got %v", err)
	}
	if len(verifier.paths) != 0 || len(verifier.pids) != 0 {
		t.Fatalf("signature verifier called for missing pid: paths=%v pids=%v", verifier.paths, verifier.pids)
	}
}

func TestExecutableValidatorRejectsBundledExecutableWhenTeamIDMissing(t *testing.T) {
	t.Parallel()

	trusted := appbundle.WriteApproverBundle(t, t.TempDir(), approval.DefaultApproverBundleID, approval.DefaultApproverExecutable)
	verifier := &recordingSignatureVerifier{
		pathTeamID:    "TEAMID",
		processTeamID: "TEAMID",
	}
	validator := ExecutableValidator{
		set: newExecutableSetWithVerifier([]string{trusted}, "", ErrUntrustedClient, verifier, true),
	}

	err := validator.ValidatePeer(peercred.Info{ExecutablePath: trusted, PID: 4321})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("expected ErrUntrustedClient, got %v", err)
	}
	if !strings.Contains(err.Error(), "expected Developer ID Team ID is required") {
		t.Fatalf("error = %q, want missing Team ID context", err.Error())
	}
	if len(verifier.paths) != 0 || len(verifier.pids) != 0 {
		t.Fatalf("signature verifier called despite missing expected team: paths=%v pids=%v", verifier.paths, verifier.pids)
	}
}

func TestExecutableValidatorAllowsBundledExecutableWithDevelopmentTeamIDSentinel(t *testing.T) {
	t.Parallel()

	trusted := appbundle.WriteApproverBundle(t, t.TempDir(), approval.DefaultApproverBundleID, approval.DefaultApproverExecutable)
	verifier := &recordingSignatureVerifier{
		pathErr:    errors.New("static verifier should not be called"),
		processErr: errors.New("process verifier should not be called"),
	}
	validator := ExecutableValidator{
		set: newExecutableSetWithVerifier(
			[]string{trusted},
			trust.DevelopmentExpectedTeamID,
			ErrUntrustedClient,
			verifier,
			true,
		),
	}

	if err := validator.ValidatePeer(peercred.Info{ExecutablePath: trusted, PID: 4321}); err != nil {
		t.Fatalf("ValidatePeer returned error for development Team ID sentinel: %v", err)
	}
	if len(verifier.paths) != 0 || len(verifier.pids) != 0 {
		t.Fatalf("signature verifier called for development Team ID sentinel: paths=%v pids=%v", verifier.paths, verifier.pids)
	}
}

func TestExecutableValidatorSkipsSignatureWhenDisabled(t *testing.T) {
	t.Parallel()

	trusted := appbundle.WriteApproverBundle(t, t.TempDir(), approval.DefaultApproverBundleID, approval.DefaultApproverExecutable)
	verifier := &recordingSignatureVerifier{
		pathErr:    errors.New("static verifier should not be called"),
		processErr: errors.New("process verifier should not be called"),
	}
	validator := ExecutableValidator{
		set: newExecutableSetWithVerifier([]string{trusted}, "", ErrUntrustedClient, verifier, false),
	}

	if err := validator.ValidatePeer(peercred.Info{ExecutablePath: trusted, PID: 4321}); err != nil {
		t.Fatalf("ValidatePeer returned error when signature verification disabled: %v", err)
	}
	if len(verifier.paths) != 0 || len(verifier.pids) != 0 {
		t.Fatalf("signature verifier called when verification disabled: paths=%v pids=%v", verifier.paths, verifier.pids)
	}
}

func TestExecutableValidatorWrapsPeerProcessSignatureFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	trusted := writeExecutableAt(t, dir, "agent-secret")
	verifier := &recordingSignatureVerifier{
		pathTeamID: "TEAMID",
		processErr: errors.New("codesign refused pid"),
	}
	validator := newTestExecutableValidator([]string{trusted}, verifier)

	err := validator.ValidatePeer(peercred.Info{ExecutablePath: trusted, PID: 4321})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("expected ErrUntrustedClient, got %v", err)
	}
	if !strings.Contains(err.Error(), "verify peer process signature") {
		t.Fatalf("error = %q, want peer process signature context", err.Error())
	}
}

func TestExecutableValidatorSkipsMissingTrustedPath(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "agent-secret")
	validator := NewExecutableValidator([]string{missing})

	err := validator.ValidatePeer(peercred.Info{ExecutablePath: missing})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("expected ErrUntrustedClient for missing trusted path, got %v", err)
	}
}

func TestClientPathDiscoveryReportsExecutableError(t *testing.T) {
	executableErr := errors.New("executable unavailable")
	executable := func() (string, error) {
		return "", executableErr
	}

	if _, err := defaultClientPaths(executable); !errors.Is(err, executableErr) {
		t.Fatalf("defaultClientPaths error = %v, want %v", err, executableErr)
	}
	if _, err := currentExecutableClientPaths(executable); !errors.Is(err, executableErr) {
		t.Fatalf("currentExecutableClientPaths error = %v, want %v", err, executableErr)
	}
}

func TestDefaultClientPathsIncludeBundledCLIForDaemonHelper(t *testing.T) {
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

	got := clientPathsForExecutable(daemonExe)
	if !slices.Contains(got, wantCLI) {
		t.Fatalf("trusted paths = %v, want bundled CLI %q", got, wantCLI)
	}
}

func TestDefaultClientPathsDoNotIncludeUserLocalBin(t *testing.T) {
	t.Parallel()

	daemonExe := filepath.Join(t.TempDir(), "agent-secretd")
	got := clientPathsForExecutable(daemonExe)
	for _, path := range got {
		if strings.Contains(path, filepath.Join(".local", "bin", "agent-secret")) {
			t.Fatalf("trusted paths include mutable user command path: %v", got)
		}
	}
}
