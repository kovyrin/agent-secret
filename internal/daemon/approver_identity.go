package daemon

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	DefaultApproverBundleID   = "com.kovyrin.agent-secret"
	DefaultApproverExecutable = "Agent Secret"
	developmentExpectedTeamID = "-"
)

//nolint:gochecknoglobals // Release builds set this with -ldflags to bind local helpers to the signing Team ID.
var defaultDeveloperIDTeamID string

type BundleApproverIdentityPolicy struct {
	ExpectedBundleID   string
	ExpectedExecutable string
	ExpectedTeamID     string
	VerifySignature    bool
}

type codeSignatureVerifier interface {
	VerifyPath(path string) (string, error)
	VerifyProcess(pid int) (string, error)
}

type codesignSignatureVerifier struct{}

func (codesignSignatureVerifier) VerifyPath(path string) (string, error) {
	return verifyCodeSignature(path)
}

func (codesignSignatureVerifier) VerifyProcess(pid int) (string, error) {
	return verifyProcessCodeSignature(pid)
}

func DefaultApproverIdentityPolicy() BundleApproverIdentityPolicy {
	return BundleApproverIdentityPolicy{
		ExpectedBundleID:   DefaultApproverBundleID,
		ExpectedExecutable: DefaultApproverExecutable,
		ExpectedTeamID:     defaultExpectedTeamID(),
		VerifySignature:    runtime.GOOS == "darwin",
	}
}

func defaultExpectedTeamID() string {
	return strings.TrimSpace(defaultDeveloperIDTeamID)
}

func expectedTeamIDForSignatureValidation(expectedTeamID string, errKind error) (string, bool, error) {
	if errKind == nil {
		errKind = ErrApproverIdentity
	}
	expectedTeamID = strings.TrimSpace(expectedTeamID)
	if expectedTeamID == "" {
		return "", false, fmt.Errorf("%w: expected Developer ID Team ID is required for signature validation", errKind)
	}
	if expectedTeamID == developmentExpectedTeamID {
		return expectedTeamID, false, nil
	}
	return expectedTeamID, true, nil
}

func (p BundleApproverIdentityPolicy) ValidateApproverExecutable(path string) (ApproverIdentity, error) {
	path, err := comparableApproverPath(path)
	if err != nil {
		return ApproverIdentity{}, err
	}
	bundlePath, err := appBundleForExecutable(path)
	if err != nil {
		return ApproverIdentity{}, err
	}

	infoPath := filepath.Join(bundlePath, "Contents", "Info.plist")
	bundleID, err := plistString(infoPath, "CFBundleIdentifier")
	if err != nil {
		return ApproverIdentity{}, err
	}
	expectedBundleID := p.ExpectedBundleID
	if expectedBundleID == "" {
		expectedBundleID = DefaultApproverBundleID
	}
	if bundleID != expectedBundleID {
		return ApproverIdentity{}, fmt.Errorf("%w: bundle id %q != %q", ErrApproverIdentity, bundleID, expectedBundleID)
	}

	executableName, err := plistString(infoPath, "CFBundleExecutable")
	if err != nil {
		return ApproverIdentity{}, err
	}
	expectedExecutable := p.ExpectedExecutable
	if expectedExecutable == "" {
		expectedExecutable = DefaultApproverExecutable
	}
	if executableName != expectedExecutable {
		return ApproverIdentity{}, fmt.Errorf("%w: executable %q != %q", ErrApproverIdentity, executableName, expectedExecutable)
	}
	bundleExecutable := filepath.Join(bundlePath, "Contents", "MacOS", executableName)
	bundleExecutable, err = comparableApproverPath(bundleExecutable)
	if err != nil {
		return ApproverIdentity{}, err
	}
	if path != bundleExecutable {
		return ApproverIdentity{}, fmt.Errorf("%w: executable %q is outside expected bundle executable %q", ErrApproverIdentity, path, bundleExecutable)
	}

	teamID := ""
	expectedTeamID := strings.TrimSpace(p.ExpectedTeamID)
	if p.VerifySignature {
		var enforceTeamID bool
		expectedTeamID, enforceTeamID, err = expectedTeamIDForSignatureValidation(expectedTeamID, ErrApproverIdentity)
		if err != nil {
			return ApproverIdentity{}, err
		}
		teamID, err = verifyCodeSignature(bundlePath)
		if err != nil {
			return ApproverIdentity{}, err
		}
		if enforceTeamID && teamID != expectedTeamID {
			return ApproverIdentity{}, fmt.Errorf("%w: team id %q != %q", ErrApproverIdentity, teamID, expectedTeamID)
		}
	}

	return ApproverIdentity{
		ExecutablePath:  path,
		BundlePath:      bundlePath,
		BundleID:        bundleID,
		TeamID:          teamID,
		ExpectedTeamID:  expectedTeamID,
		VerifySignature: p.VerifySignature,
	}, nil
}

func appBundleForExecutable(path string) (string, error) {
	dir := filepath.Dir(path)
	for {
		if filepath.Ext(dir) == ".app" {
			bundlePath, err := comparableApproverPath(dir)
			if err != nil {
				return "", err
			}
			return bundlePath, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("%w: executable %q is not inside a .app bundle", ErrApproverIdentity, path)
		}
		dir = parent
	}
}

func plistString(path string, key string) (string, error) {
	//nolint:gosec // G304: path is the Info.plist inside the canonicalized .app bundle under validation.
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%w: read %s: %w", ErrApproverIdentity, path, err)
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var currentKey string
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "key":
			var value string
			if err := decoder.DecodeElement(&value, &start); err != nil {
				return "", fmt.Errorf("%w: parse %s key: %w", ErrApproverIdentity, path, err)
			}
			currentKey = value
		case "string":
			var value string
			if err := decoder.DecodeElement(&value, &start); err != nil {
				return "", fmt.Errorf("%w: parse %s string: %w", ErrApproverIdentity, path, err)
			}
			if currentKey == key {
				return value, nil
			}
			currentKey = ""
		}
	}
	return "", fmt.Errorf("%w: %s missing %s", ErrApproverIdentity, path, key)
}

func verifyCodeSignature(bundlePath string) (string, error) {
	return verifyCodeSignatureTarget(bundlePath, "code signature for "+bundlePath)
}

func verifyProcessCodeSignature(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("%w: invalid process id %d", ErrApproverIdentity, pid)
	}
	return verifyCodeSignatureTarget(fmt.Sprintf("+%d", pid), fmt.Sprintf("code signature for process %d", pid))
}

func verifyCodeSignatureTarget(target string, description string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	//nolint:gosec // G204: codesign path is fixed; targets are canonicalized paths or codesign +PID selectors.
	if err := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--strict", "--deep", target).Run(); err != nil {
		return "", fmt.Errorf("%w: verify %s: %w", ErrApproverIdentity, description, err)
	}
	//nolint:gosec // G204: codesign path is fixed; targets are canonicalized paths or codesign +PID selectors.
	output, err := exec.CommandContext(ctx, "/usr/bin/codesign", "-dv", "--verbose=4", target).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: inspect %s: %w", ErrApproverIdentity, description, err)
	}
	for line := range strings.SplitSeq(string(output), "\n") {
		teamID, ok := strings.CutPrefix(strings.TrimSpace(line), "TeamIdentifier=")
		if ok {
			return teamID, nil
		}
	}
	return "", nil
}
