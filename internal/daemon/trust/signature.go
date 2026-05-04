package trust

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/kovyrin/agent-secret/internal/peercred"
)

const DevelopmentExpectedTeamID = "-"

//nolint:gochecknoglobals // Release builds set this with -ldflags to bind local helpers to the signing Team ID.
var defaultDeveloperIDTeamID string

type CodeSignatureVerifier interface {
	VerifyPath(path string) (string, error)
	VerifyProcess(pid int) (string, error)
}

type CodesignSignatureVerifier struct{}

type codesignCommandRunner func(context.Context, ...string) ([]byte, error)

func (CodesignSignatureVerifier) VerifyPath(path string) (string, error) {
	return VerifyCodeSignature(path)
}

func (CodesignSignatureVerifier) VerifyProcess(pid int) (string, error) {
	return VerifyProcessCodeSignature(pid)
}

func DefaultExpectedTeamID() string {
	return strings.TrimSpace(defaultDeveloperIDTeamID)
}

func ExpectedTeamIDForSignatureValidation(expectedTeamID string, errKind error) (string, bool, error) {
	expectedTeamID = strings.TrimSpace(expectedTeamID)
	if expectedTeamID == "" {
		return "", false, fmt.Errorf("%w: expected Developer ID Team ID is required for signature validation", errKind)
	}
	if expectedTeamID == DevelopmentExpectedTeamID {
		return expectedTeamID, false, nil
	}
	return expectedTeamID, true, nil
}

func ValidatePeerSignature(
	info peercred.Info,
	path string,
	expectedTeamID string,
	verifier CodeSignatureVerifier,
	errKind error,
) error {
	if verifier == nil {
		verifier = CodesignSignatureVerifier{}
	}
	if info.PID <= 0 {
		return fmt.Errorf("%w: peer pid is unavailable for signature validation", errKind)
	}
	teamID, err := verifier.VerifyPath(path)
	if err != nil {
		return fmt.Errorf("%w: verify trusted executable signature: %w", errKind, err)
	}
	if teamID != expectedTeamID {
		return fmt.Errorf("%w: trusted executable team id %q != %q", errKind, teamID, expectedTeamID)
	}
	teamID, err = verifier.VerifyProcess(info.PID)
	if err != nil {
		return fmt.Errorf("%w: verify peer process signature: %w", errKind, err)
	}
	if teamID != expectedTeamID {
		return fmt.Errorf("%w: peer process team id %q != %q", errKind, teamID, expectedTeamID)
	}
	return nil
}

func VerifyCodeSignature(bundlePath string) (string, error) {
	return verifyCodeSignatureTarget(bundlePath, "code signature for "+bundlePath)
}

func VerifyProcessCodeSignature(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("invalid process id %d", pid)
	}
	return verifyCodeSignatureTarget(fmt.Sprintf("+%d", pid), fmt.Sprintf("code signature for process %d", pid))
}

func verifyCodeSignatureTarget(target string, description string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return verifyCodeSignatureTargetWithRunner(ctx, target, description, runCodesign)
}

func verifyCodeSignatureTargetWithRunner(
	ctx context.Context,
	target string,
	description string,
	run codesignCommandRunner,
) (string, error) {
	if _, err := run(ctx, "--verify", "--strict", "--deep", target); err != nil {
		return "", fmt.Errorf("verify %s: %w", description, err)
	}
	output, err := run(ctx, "-dv", "--verbose=4", target)
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", description, err)
	}
	teamID, err := teamIDFromCodesignOutput(output)
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", description, err)
	}
	return teamID, nil
}

func runCodesign(ctx context.Context, args ...string) ([]byte, error) {
	//nolint:gosec // G204: codesign path is fixed; targets are canonicalized paths or codesign +PID selectors.
	cmd := exec.CommandContext(ctx, "/usr/bin/codesign", args...)
	return cmd.CombinedOutput()
}

func teamIDFromCodesignOutput(output []byte) (string, error) {
	for line := range strings.SplitSeq(string(output), "\n") {
		teamID, ok := strings.CutPrefix(strings.TrimSpace(line), "TeamIdentifier=")
		if ok {
			teamID = strings.TrimSpace(teamID)
			if teamID == "" {
				return "", errors.New("codesign output has empty TeamIdentifier")
			}
			return teamID, nil
		}
	}
	return "", errors.New("codesign output missing TeamIdentifier")
}
