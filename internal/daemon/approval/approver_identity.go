package approval

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kovyrin/agent-secret/internal/daemon/trust"
)

const (
	DefaultApproverBundleID   = "com.kovyrin.agent-secret"
	DefaultApproverExecutable = "Agent Secret"
)

type BundleApproverIdentityPolicy struct {
	ExpectedBundleID   string
	ExpectedExecutable string
	ExpectedTeamID     string
	VerifySignature    bool
}

func DefaultApproverIdentityPolicy() BundleApproverIdentityPolicy {
	return BundleApproverIdentityPolicy{
		ExpectedBundleID:   DefaultApproverBundleID,
		ExpectedExecutable: DefaultApproverExecutable,
		ExpectedTeamID:     trust.DefaultExpectedTeamID(),
		VerifySignature:    runtime.GOOS == "darwin",
	}
}

func expectedTeamIDForSignatureValidation(expectedTeamID string, errKind error) (string, bool, error) {
	if errKind == nil {
		errKind = ErrApproverIdentity
	}
	return trust.ExpectedTeamIDForSignatureValidation(expectedTeamID, errKind)
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
	bundleID, err := trust.PlistString(infoPath, "CFBundleIdentifier", ErrApproverIdentity)
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

	executableName, err := trust.PlistString(infoPath, "CFBundleExecutable", ErrApproverIdentity)
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
		teamID, err = trust.VerifyCodeSignature(bundlePath)
		if err != nil {
			return ApproverIdentity{}, fmt.Errorf("%w: %w", ErrApproverIdentity, err)
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

func verifyProcessCodeSignature(pid int) (string, error) {
	teamID, err := trust.VerifyProcessCodeSignature(pid)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrApproverIdentity, err)
	}
	return teamID, nil
}
