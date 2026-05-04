package approval

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kovyrin/agent-secret/internal/daemon/trust"
	"github.com/kovyrin/agent-secret/internal/testsupport/appbundle"
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
			teamID:     trust.DevelopmentExpectedTeamID,
			wantTeamID: trust.DevelopmentExpectedTeamID,
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

	executable := appbundle.WriteApproverBundle(t, t.TempDir(), DefaultApproverBundleID, DefaultApproverExecutable)
	bundlePath := filepath.Clean(filepath.Join(filepath.Dir(executable), "..", ".."))
	bundlePath, err := comparableApproverPath(bundlePath, ErrApproverIdentity)
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

	executable := appbundle.WriteApproverBundle(t, t.TempDir(), DefaultApproverBundleID, DefaultApproverExecutable)
	infoPath := filepath.Join(filepath.Dir(executable), "..", "Info.plist")

	got, err := trust.PlistString(infoPath, "CFBundleIdentifier", ErrApproverIdentity)
	if err != nil {
		t.Fatalf("plistString returned error: %v", err)
	}
	if got != DefaultApproverBundleID {
		t.Fatalf("bundle id = %q, want %q", got, DefaultApproverBundleID)
	}
}

func TestPlistStringRejectsMissingKey(t *testing.T) {
	t.Parallel()

	executable := appbundle.WriteApproverBundle(t, t.TempDir(), DefaultApproverBundleID, DefaultApproverExecutable)
	infoPath := filepath.Join(filepath.Dir(executable), "..", "Info.plist")

	_, err := trust.PlistString(infoPath, "MissingKey", ErrApproverIdentity)
	if !errors.Is(err, ErrApproverIdentity) {
		t.Fatalf("error = %v, want ErrApproverIdentity", err)
	}
}

func TestPlistStringReportsMalformedPlist(t *testing.T) {
	t.Parallel()

	infoPath := filepath.Join(t.TempDir(), "Info.plist")
	if err := os.WriteFile(infoPath, []byte("<plist><dict><key>CFBundleIdentifier</key>"), 0o600); err != nil {
		t.Fatalf("write Info.plist: %v", err)
	}

	_, err := trust.PlistString(infoPath, "CFBundleIdentifier", ErrApproverIdentity)
	if !errors.Is(err, ErrApproverIdentity) {
		t.Fatalf("error = %v, want ErrApproverIdentity", err)
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Fatalf("error = %q, want parse context", err.Error())
	}
	if strings.Contains(err.Error(), "missing CFBundleIdentifier") {
		t.Fatalf("error = %q, should not report parse failure as missing key", err.Error())
	}
}

func TestVerifyProcessCodeSignatureRejectsInvalidPID(t *testing.T) {
	t.Parallel()

	_, err := verifyProcessCodeSignature(0)
	if !errors.Is(err, ErrApproverIdentity) {
		t.Fatalf("error = %v, want ErrApproverIdentity", err)
	}
}
