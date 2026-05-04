package approval

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kovyrin/agent-secret/internal/peercred"
)

func TestValidateExpectedApprover(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		expected ExpectedApprover
		wantErr  string
	}{
		{
			name:     "valid",
			expected: ExpectedApprover{PID: 1234, ExecutablePath: "/Applications/Agent Secret.app/Contents/MacOS/Agent Secret"},
		},
		{
			name:     "invalid pid",
			expected: ExpectedApprover{ExecutablePath: "/bin/echo"},
			wantErr:  "invalid approver pid",
		},
		{
			name:     "empty executable",
			expected: ExpectedApprover{PID: 1234, ExecutablePath: " \t\n"},
			wantErr:  "empty approver executable path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateExpectedApprover(tt.expected)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("ValidateExpectedApprover returned nil error")
				}
				if !errors.Is(err, ErrApproverLaunchFailed) {
					t.Fatalf("error = %v, want ErrApproverLaunchFailed", err)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateExpectedApprover returned error: %v", err)
			}
		})
	}
}

func TestValidateApproverPeer(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	other := writeApproverPeerTestExecutable(t)
	tests := []struct {
		name     string
		expected ExpectedApprover
		got      peercred.Info
		wantErr  string
	}{
		{
			name:     "matches pid and executable",
			expected: ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe},
			got:      peerInfoForTest(t, os.Getpid(), exe),
		},
		{
			name:     "allows missing expected executable without signature enforcement",
			expected: ExpectedApprover{PID: os.Getpid()},
			got:      peerInfoForTest(t, os.Getpid(), filepath.Join(t.TempDir(), "missing")),
		},
		{
			name:     "rejects pid mismatch",
			expected: ExpectedApprover{PID: os.Getpid() + 1, ExecutablePath: exe},
			got:      peerInfoForTest(t, os.Getpid(), exe),
			wantErr:  "pid",
		},
		{
			name:     "rejects executable mismatch",
			expected: ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe},
			got:      peerInfoForTest(t, os.Getpid(), other),
			wantErr:  "executable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateApproverPeer(tt.expected, tt.got)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("ValidateApproverPeer returned nil error")
				}
				if !errors.Is(err, ErrApproverPeerMismatch) {
					t.Fatalf("error = %v, want ErrApproverPeerMismatch", err)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateApproverPeer returned error: %v", err)
			}
		})
	}
}

func writeApproverPeerTestExecutable(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: approver peer tests need executable fixtures.
		t.Fatalf("write executable: %v", err)
	}
	return path
}

func TestValidateApproverPeerRejectsBrokenSymlinkEvenWhenPathsMatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	broken := filepath.Join(dir, "Agent Secret")
	if err := os.Symlink(filepath.Join(dir, "missing"), broken); err != nil {
		t.Fatalf("create broken symlink: %v", err)
	}

	err := ValidateApproverPeer(
		ExpectedApprover{PID: os.Getpid(), ExecutablePath: broken},
		peerInfoForTest(t, os.Getpid(), broken),
	)
	if !errors.Is(err, ErrApproverPeerMismatch) {
		t.Fatalf("ValidateApproverPeer error = %v, want ErrApproverPeerMismatch", err)
	}
	if !strings.Contains(err.Error(), "normalize approver path") {
		t.Fatalf("ValidateApproverPeer error = %q, want path normalization context", err.Error())
	}
}
