package approval

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kovyrin/agent-secret/internal/daemon/trust"
	"github.com/kovyrin/agent-secret/internal/pathresolve"
	"github.com/kovyrin/agent-secret/internal/peercred"
)

func ValidateExpectedApprover(expected ExpectedApprover) error {
	if expected.PID <= 0 {
		return fmt.Errorf("%w: launcher returned invalid approver pid %d", ErrApproverLaunchFailed, expected.PID)
	}
	if strings.TrimSpace(expected.ExecutablePath) == "" {
		return fmt.Errorf("%w: launcher returned empty approver executable path", ErrApproverLaunchFailed)
	}
	return nil
}

func ValidateApproverPeer(expected ExpectedApprover, got peercred.Info) error {
	if expected.PID != 0 && got.PID != expected.PID {
		return fmt.Errorf("%w: pid %d != %d", ErrApproverPeerMismatch, got.PID, expected.PID)
	}
	expectedTeamID := strings.TrimSpace(expected.ExpectedTeamID)
	enforceTeamID := false
	if expected.VerifySignature {
		var err error
		expectedTeamID, enforceTeamID, err = trust.ExpectedTeamIDForSignatureValidation(
			expectedTeamID,
			ErrApproverPeerMismatch,
		)
		if err != nil {
			return err
		}
	}
	if expected.ExecutablePath == "" {
		if enforceTeamID {
			return fmt.Errorf("%w: executable path is unavailable for signature validation", ErrApproverPeerMismatch)
		}
		return nil
	}
	expectedPath, err := comparableApproverPath(expected.ExecutablePath, ErrApproverPeerMismatch)
	if err != nil {
		return err
	}
	gotPath, err := comparableApproverPath(got.ExecutablePath, ErrApproverPeerMismatch)
	if err != nil {
		return err
	}
	if gotPath != expectedPath {
		return fmt.Errorf("%w: executable %q != %q", ErrApproverPeerMismatch, gotPath, expectedPath)
	}
	if enforceTeamID {
		if err := trust.ValidatePeerSignature(
			got,
			expectedPath,
			expectedTeamID,
			expected.SignatureVerifier,
			ErrApproverPeerMismatch,
		); err != nil {
			return err
		}
	}
	return nil
}

func comparableApproverPath(path string, errKind error) (string, error) {
	resolved, err := pathresolve.Strict(path)
	if err != nil {
		if errKind == nil {
			errKind = ErrApproverIdentity
		}
		return "", fmt.Errorf("%w: normalize approver path %q: %w", errKind, path, err)
	}
	return resolved, nil
}

func defaultApproverPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("%w: get executable path: %w", ErrApproverLaunchFailed, err)
	}
	candidates := approverCandidatesForExecutable(exe)
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(
			home,
			"Applications",
			"Agent Secret.app",
			"Contents",
			"MacOS",
			"Agent Secret",
		))
	}
	for _, candidate := range candidates {
		if executableExists(candidate) {
			return candidate, nil
		}
	}
	return candidates[0], nil
}

func approverCandidatesForExecutable(executable string) []string {
	executables := []string{executable}
	if resolved := pathresolve.BestEffort(executable); resolved != executable {
		executables = append(executables, resolved)
	}

	candidates := make([]string, 0, len(executables)*2)
	seen := make(map[string]struct{})
	for _, candidate := range executables {
		for _, path := range []string{
			filepath.Clean(filepath.Join(filepath.Dir(candidate), "..", "..", "MacOS", "Agent Secret")),
			filepath.Clean(filepath.Join(
				filepath.Dir(candidate),
				"..",
				"..",
				"..",
				"..",
				"..",
				"MacOS",
				"Agent Secret",
			)),
		} {
			if _, ok := seen[path]; ok {
				continue
			}
			candidates = append(candidates, path)
			seen[path] = struct{}{}
		}
	}
	return candidates
}

func approverExecutablesInApp(appPath string) []string {
	return []string{
		filepath.Join(appPath, "Contents", "MacOS", "Agent Secret"),
	}
}

func executableExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}
