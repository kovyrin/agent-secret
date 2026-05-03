package daemon

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestExpectedTeamIDForSignatureValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		teamID      string
		wantTeamID  string
		wantEnforce bool
		wantErr     bool
	}{
		{
			name:    "missing team id",
			wantErr: true,
		},
		{
			name:       "development sentinel",
			teamID:     developmentExpectedTeamID,
			wantTeamID: developmentExpectedTeamID,
		},
		{
			name:        "developer id team",
			teamID:      "  ABC123XYZ9  ",
			wantTeamID:  "ABC123XYZ9",
			wantEnforce: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotTeamID, gotEnforce, err := expectedTeamIDForSignatureValidation(tt.teamID, ErrApproverIdentity)
			if tt.wantErr {
				if !errors.Is(err, ErrApproverIdentity) {
					t.Fatalf("error = %v, want ErrApproverIdentity", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expectedTeamIDForSignatureValidation returned error: %v", err)
			}
			if gotTeamID != tt.wantTeamID {
				t.Fatalf("team id = %q, want %q", gotTeamID, tt.wantTeamID)
			}
			if gotEnforce != tt.wantEnforce {
				t.Fatalf("enforce = %v, want %v", gotEnforce, tt.wantEnforce)
			}
		})
	}
}

func TestAppBundleForExecutableFindsContainingBundle(t *testing.T) {
	t.Parallel()

	executable := writeApproverBundle(t, t.TempDir(), DefaultApproverBundleID, DefaultApproverExecutable)
	bundlePath := filepath.Clean(filepath.Join(filepath.Dir(executable), "..", ".."))
	bundlePath, err := comparableApproverPath(bundlePath)
	if err != nil {
		t.Fatalf("canonicalize bundle path: %v", err)
	}

	got, err := appBundleForExecutable(executable)
	if err != nil {
		t.Fatalf("appBundleForExecutable returned error: %v", err)
	}
	if got != bundlePath {
		t.Fatalf("bundle path = %q, want %q", got, bundlePath)
	}
}

func TestAppBundleForExecutableRejectsNonBundlePath(t *testing.T) {
	t.Parallel()

	_, err := appBundleForExecutable(filepath.Join(t.TempDir(), "approver"))
	if !errors.Is(err, ErrApproverIdentity) {
		t.Fatalf("error = %v, want ErrApproverIdentity", err)
	}
}

func TestPlistStringReadsBundleMetadata(t *testing.T) {
	t.Parallel()

	executable := writeApproverBundle(t, t.TempDir(), DefaultApproverBundleID, DefaultApproverExecutable)
	infoPath := filepath.Join(filepath.Dir(executable), "..", "Info.plist")

	got, err := plistString(infoPath, "CFBundleIdentifier")
	if err != nil {
		t.Fatalf("plistString returned error: %v", err)
	}
	if got != DefaultApproverBundleID {
		t.Fatalf("bundle id = %q, want %q", got, DefaultApproverBundleID)
	}
}

func TestPlistStringRejectsMissingKey(t *testing.T) {
	t.Parallel()

	executable := writeApproverBundle(t, t.TempDir(), DefaultApproverBundleID, DefaultApproverExecutable)
	infoPath := filepath.Join(filepath.Dir(executable), "..", "Info.plist")

	_, err := plistString(infoPath, "MissingKey")
	if !errors.Is(err, ErrApproverIdentity) {
		t.Fatalf("error = %v, want ErrApproverIdentity", err)
	}
}

func TestVerifyProcessCodeSignatureRejectsInvalidPID(t *testing.T) {
	t.Parallel()

	_, err := verifyProcessCodeSignature(0)
	if !errors.Is(err, ErrApproverIdentity) {
		t.Fatalf("error = %v, want ErrApproverIdentity", err)
	}
}
