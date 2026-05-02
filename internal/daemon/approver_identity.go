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
	DefaultApproverBundleID   = "com.kovyrin.agent-secret.approver"
	DefaultApproverExecutable = "agent-secret-approver"
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
		VerifySignature:    runtime.GOOS == "darwin",
	}
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
	if p.VerifySignature {
		teamID, err = verifyCodeSignature(bundlePath)
		if err != nil {
			return ApproverIdentity{}, err
		}
	}
	if p.ExpectedTeamID != "" && teamID != p.ExpectedTeamID {
		return ApproverIdentity{}, fmt.Errorf("%w: team id %q != %q", ErrApproverIdentity, teamID, p.ExpectedTeamID)
	}

	return ApproverIdentity{
		ExecutablePath: path,
		BundlePath:     bundlePath,
		BundleID:       bundleID,
		TeamID:         teamID,
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--strict", "--deep", bundlePath).Run(); err != nil {
		return "", fmt.Errorf("%w: verify code signature for %s: %w", ErrApproverIdentity, bundlePath, err)
	}
	output, err := exec.CommandContext(ctx, "/usr/bin/codesign", "-dv", "--verbose=4", bundlePath).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: inspect code signature for %s: %w", ErrApproverIdentity, bundlePath, err)
	}
	for line := range strings.SplitSeq(string(output), "\n") {
		teamID, ok := strings.CutPrefix(strings.TrimSpace(line), "TeamIdentifier=")
		if ok {
			return teamID, nil
		}
	}
	return "", nil
}
