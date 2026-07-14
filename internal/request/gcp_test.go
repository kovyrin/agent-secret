package request

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/fileidentity"
)

func TestNormalizeGCPAccessSortsDedupesAndRequiresScopes(t *testing.T) {
	t.Parallel()

	access, err := NormalizeGCPAccess(GCPAccess{
		GoogleAccount:  " work ",
		Project:        " fixture-beta ",
		ServiceAccount: " agent-beta@fixture-beta.iam.gserviceaccount.com ",
		Scopes: []string{
			" https://www.googleapis.com/auth/logging.read ",
			"https://www.googleapis.com/auth/cloud-platform",
			"https://www.googleapis.com/auth/logging.read",
		},
	})
	if err != nil {
		t.Fatalf("NormalizeGCPAccess returned error: %v", err)
	}
	if access.GoogleAccount != "work" || access.Project != "fixture-beta" ||
		access.ServiceAccount != "agent-beta@fixture-beta.iam.gserviceaccount.com" {
		t.Fatalf("access fields not normalized: %+v", access)
	}
	wantScopes := []string{
		"https://www.googleapis.com/auth/cloud-platform",
		"https://www.googleapis.com/auth/logging.read",
	}
	if len(access.Scopes) != len(wantScopes) || access.Scopes[0] != wantScopes[0] || access.Scopes[1] != wantScopes[1] {
		t.Fatalf("scopes = %v, want %v", access.Scopes, wantScopes)
	}

	_, err = NormalizeGCPAccess(GCPAccess{
		GoogleAccount:  "work",
		Project:        "fixture-beta",
		ServiceAccount: "agent-beta@fixture-beta.iam.gserviceaccount.com",
	})
	if !errors.Is(err, ErrInvalidGCPScope) {
		t.Fatalf("missing scopes error = %v, want ErrInvalidGCPScope", err)
	}
}

func TestGCPAuthRequestsNormalizeAndValidateForDaemon(t *testing.T) {
	t.Parallel()

	status, err := NewGCPAuthStatus(" personal ")
	if err != nil {
		t.Fatalf("NewGCPAuthStatus returned error: %v", err)
	}
	if status.GoogleAccount != "personal" {
		t.Fatalf("status account = %q", status.GoogleAccount)
	}
	if err := status.ValidateForDaemon(); err != nil {
		t.Fatalf("status ValidateForDaemon returned error: %v", err)
	}
	login, err := NewGCPAuthLogin(GCPAuthLoginOptions{
		GoogleAccount: " personal ",
		ExpectedEmail: " Oleksiy@Kovyrin.NET ",
	})
	if err != nil {
		t.Fatalf("NewGCPAuthLogin returned error: %v", err)
	}
	if login.GoogleAccount != "personal" || login.ExpectedEmail != "oleksiy@kovyrin.net" {
		t.Fatalf("login request = %+v", login)
	}
	if err := login.ValidateForDaemon(); err != nil {
		t.Fatalf("login ValidateForDaemon returned error: %v", err)
	}
	logout, err := NewGCPAuthLogout(" personal ")
	if err != nil {
		t.Fatalf("NewGCPAuthLogout returned error: %v", err)
	}
	if logout.GoogleAccount != "personal" {
		t.Fatalf("logout account = %q", logout.GoogleAccount)
	}
	if err := logout.ValidateForDaemon(); err != nil {
		t.Fatalf("logout ValidateForDaemon returned error: %v", err)
	}
}

func TestGCPAuthRequestsRejectInvalidAliasesAndEmails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "empty required login account",
			run: func() error {
				_, err := NewGCPAuthLogin(GCPAuthLoginOptions{})
				return err
			},
		},
		{
			name: "newline account",
			run: func() error {
				_, err := NewGCPAuthStatus("personal\nfixture")
				return err
			},
		},
		{
			name: "long account",
			run: func() error {
				_, err := NewGCPAuthLogout(strings.Repeat("a", 129))
				return err
			},
		},
		{
			name: "bad expected email",
			run: func() error {
				_, err := NewGCPAuthLogin(GCPAuthLoginOptions{
					GoogleAccount: "personal",
					ExpectedEmail: "oleksiy kovyrin.net",
				})
				return err
			},
		},
		{
			name: "daemon requires normalized status",
			run: func() error {
				return GCPAuthStatusRequest{GoogleAccount: " personal "}.ValidateForDaemon()
			},
		},
		{
			name: "daemon requires normalized login",
			run: func() error {
				return GCPAuthLoginRequest{GoogleAccount: "personal", ExpectedEmail: "Oleksiy@Kovyrin.NET"}.ValidateForDaemon()
			},
		},
		{
			name: "daemon requires normalized logout",
			run: func() error {
				return GCPAuthLogoutRequest{GoogleAccount: " personal "}.ValidateForDaemon()
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.run(); !errors.Is(err, ErrInvalidGCPAccount) {
				t.Fatalf("error = %v, want ErrInvalidGCPAccount", err)
			}
		})
	}
}

func TestNewGCPSessionCreateAllowsLongerSessionTTL(t *testing.T) {
	t.Parallel()

	req, err := NewGCPSessionCreate(GCPSessionCreateOptions{
		Reason: "Run benchmark",
		Access: GCPAccess{
			GoogleAccount:  "work",
			Project:        "fixture-bench",
			ServiceAccount: "agent-bench@fixture-bench.iam.gserviceaccount.com",
			Scopes:         []string{"https://www.googleapis.com/auth/cloud-platform"},
		},
		ProfileName:      "fixture-prod-benchmark-run",
		ConfigSourcePath: "/tmp/project/agent-secret.yml",
		ProjectRoot:      "/tmp/project",
		TTL:              45 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewGCPSessionCreate returned error: %v", err)
	}
	if req.TTL != 45*time.Minute {
		t.Fatalf("TTL = %s, want 45m", req.TTL)
	}
	if req.MaxCommandStarts != DefaultGCPSessionMaxCommandStarts {
		t.Fatalf("max command starts = %d", req.MaxCommandStarts)
	}
}

func TestGCPSessionRefreshMarginUsesTwentyPercentWithFloor(t *testing.T) {
	t.Parallel()

	if got := GCPSessionRemainingTokenRefreshMargin(10 * time.Minute); got != 2*time.Minute {
		t.Fatalf("10m margin = %s, want 2m", got)
	}
	if got := GCPSessionRemainingTokenRefreshMargin(2 * time.Minute); got != time.Minute {
		t.Fatalf("2m margin = %s, want 1m floor", got)
	}
}

func TestGCPExecValidateForDaemonRequiresPreNormalizedScopes(t *testing.T) {
	t.Parallel()

	exe, identity := testGCPExecutable(t)
	req, err := NewGCPExec(GCPExecOptions{
		Reason:                 "Inspect logs",
		Command:                []string{exe, "-test.run=none"},
		ResolvedExecutable:     exe,
		ExecutableIdentity:     identity,
		AllowMutableExecutable: true,
		CWD:                    "/tmp",
		EnvironmentFingerprint: EnvironmentFingerprint(os.Environ()),
		Access: GCPAccess{
			GoogleAccount:  "work",
			Project:        "fixture-beta",
			ServiceAccount: "agent-beta@fixture-beta.iam.gserviceaccount.com",
			Scopes: []string{
				"https://www.googleapis.com/auth/logging.read",
				"https://www.googleapis.com/auth/cloud-platform",
			},
		},
		ReceivedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("NewGCPExec returned error: %v", err)
	}
	req.Scopes = []string{
		"https://www.googleapis.com/auth/logging.read",
		"https://www.googleapis.com/auth/cloud-platform",
	}
	if err := req.ValidateForDaemon(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("ValidateForDaemon error = %v, want pre-normalization failure", err)
	}
}

func TestNewGCPExecBuildsDaemonValidatedSnapshot(t *testing.T) {
	t.Parallel()

	exe, identity := testGCPExecutable(t)
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	req, err := NewGCPExec(GCPExecOptions{
		Reason:                 "  Inspect beta logs  ",
		Command:                []string{exe, "-test.run=none"},
		ResolvedExecutable:     exe,
		ExecutableIdentity:     identity,
		AllowMutableExecutable: true,
		CWD:                    "/tmp",
		EnvironmentFingerprint: EnvironmentFingerprint([]string{"PATH=/tmp/bin", "CLOUDSDK_CONFIG=/ambient"}),
		Access: GCPAccess{
			GoogleAccount:  " work ",
			Project:        " fixture-beta ",
			ServiceAccount: " agent-beta@fixture-beta.iam.gserviceaccount.com ",
			Scopes: []string{
				"https://www.googleapis.com/auth/logging.read",
				"https://www.googleapis.com/auth/cloud-platform",
			},
		},
		ProfileName: " beta-logs ",
		ConfigRoot:  "/tmp",
		TTL:         2 * time.Minute,
		ReceivedAt:  now,
		ReuseOnly:   true,
	})
	if err != nil {
		t.Fatalf("NewGCPExec returned error: %v", err)
	}
	if req.Reason != "Inspect beta logs" || req.ProfileName != "beta-logs" || !req.ReuseOnly {
		t.Fatalf("unexpected request metadata: %+v", req)
	}
	if !req.AllowMutableExecutable {
		t.Fatal("AllowMutableExecutable = false, want true")
	}
	if req.DeliveryMode != GCPDeliveryModeTokenFile {
		t.Fatalf("delivery mode = %q", req.DeliveryMode)
	}
	if !req.ExpiresAt.Equal(now.Add(2*time.Minute)) || !req.Expired(req.ExpiresAt) {
		t.Fatalf("expiry = %s, expired=%t", req.ExpiresAt, req.Expired(req.ExpiresAt))
	}
	if err := req.ValidateForDaemon(); err != nil {
		t.Fatalf("ValidateForDaemon returned error: %v", err)
	}
	access := req.Access()
	access.Scopes[0] = "changed"
	if req.Scopes[0] == "changed" {
		t.Fatal("Access returned mutable scope slice")
	}
}

func TestGCPExecWithReceiptTimeRestampsDaemonClock(t *testing.T) {
	t.Parallel()

	exe, identity := testGCPExecutable(t)
	req, err := NewGCPExec(GCPExecOptions{
		Reason:                 "Inspect logs",
		Command:                []string{exe},
		ResolvedExecutable:     exe,
		ExecutableIdentity:     identity,
		AllowMutableExecutable: true,
		CWD:                    "/tmp",
		EnvironmentFingerprint: EnvironmentFingerprint([]string{"PATH=/tmp/bin"}),
		Access:                 testGCPAccess(),
		TTL:                    90 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewGCPExec returned error: %v", err)
	}
	now := time.Date(2026, 5, 21, 13, 0, 0, 0, time.UTC)
	stamped := req.WithReceiptTime(now)
	if !stamped.ReceivedAt.Equal(now) || !stamped.ExpiresAt.Equal(now.Add(90*time.Second)) {
		t.Fatalf("stamped times = received %s expires %s", stamped.ReceivedAt, stamped.ExpiresAt)
	}
	if err := stamped.ValidateForDaemon(); err != nil {
		t.Fatalf("ValidateForDaemon returned error: %v", err)
	}
}

func TestGCPCommandRequestsRejectMutableExecutableByDefault(t *testing.T) {
	t.Parallel()

	exe, identity := testGCPExecutable(t)
	execReq, err := NewGCPExec(GCPExecOptions{
		Reason:                 "Inspect logs",
		Command:                []string{exe},
		ResolvedExecutable:     exe,
		ExecutableIdentity:     identity,
		CWD:                    "/tmp",
		EnvironmentFingerprint: EnvironmentFingerprint([]string{"PATH=/tmp/bin"}),
		Access:                 testGCPAccess(),
		ReceivedAt:             time.Now(),
	})
	if err != nil {
		t.Fatalf("NewGCPExec returned error: %v", err)
	}
	if err := execReq.ValidateForDaemon(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GCP exec ValidateForDaemon error = %v, want ErrInvalidRequest", err)
	}

	useReq, err := NewGCPSessionUse(GCPSessionUseOptions{
		SessionHandle:          "asess_123",
		Command:                []string{exe},
		ResolvedExecutable:     exe,
		ExecutableIdentity:     identity,
		CWD:                    "/tmp",
		EnvironmentFingerprint: EnvironmentFingerprint([]string{"PATH=/tmp/bin"}),
	})
	if err != nil {
		t.Fatalf("NewGCPSessionUse returned error: %v", err)
	}
	if err := useReq.ValidateForDaemon(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GCP session use ValidateForDaemon error = %v, want ErrInvalidRequest", err)
	}
}

func TestNewGCPSessionCreateBuildsDaemonValidatedSnapshot(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	req, err := NewGCPSessionCreate(GCPSessionCreateOptions{
		Reason:           "  Run benchmark  ",
		Access:           testGCPAccess(),
		ProfileName:      " fixture-prod-benchmark-run ",
		ConfigSourcePath: "/tmp/project/agent-secret.yml",
		ProjectRoot:      "/tmp/project",
		TTL:              20 * time.Minute,
		MaxCommandStarts: 7,
		ReceivedAt:       now,
	})
	if err != nil {
		t.Fatalf("NewGCPSessionCreate returned error: %v", err)
	}
	if req.Reason != "Run benchmark" || req.ProfileName != "fixture-prod-benchmark-run" || req.MaxCommandStarts != 7 {
		t.Fatalf("unexpected request: %+v", req)
	}
	if !req.ExpiresAt.Equal(now.Add(20*time.Minute)) || !req.Expired(req.ExpiresAt) {
		t.Fatalf("expiry = %s, expired=%t", req.ExpiresAt, req.Expired(req.ExpiresAt))
	}
	if err := req.ValidateForDaemon(); err != nil {
		t.Fatalf("ValidateForDaemon returned error: %v", err)
	}
	access := req.Access()
	access.Scopes[0] = "changed"
	if req.Scopes[0] == "changed" {
		t.Fatal("Access returned mutable scope slice")
	}
}

func TestGCPSessionCreateWithReceiptTimeRestampsDaemonClock(t *testing.T) {
	t.Parallel()

	req, err := NewGCPSessionCreate(GCPSessionCreateOptions{
		Reason:           "Run benchmark",
		Access:           testGCPAccess(),
		ProfileName:      "benchmark",
		ConfigSourcePath: "/tmp/project/agent-secret.yml",
		ProjectRoot:      "/tmp/project",
		TTL:              12 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewGCPSessionCreate returned error: %v", err)
	}
	now := time.Date(2026, 5, 21, 14, 0, 0, 0, time.UTC)
	stamped := req.WithReceiptTime(now)
	if !stamped.ReceivedAt.Equal(now) || !stamped.ExpiresAt.Equal(now.Add(12*time.Minute)) {
		t.Fatalf("stamped times = received %s expires %s", stamped.ReceivedAt, stamped.ExpiresAt)
	}
	if err := stamped.ValidateForDaemon(); err != nil {
		t.Fatalf("ValidateForDaemon returned error: %v", err)
	}
}

func TestNewGCPSessionUseAndDestroyValidateForDaemon(t *testing.T) {
	t.Parallel()

	exe, identity := testGCPExecutable(t)
	useReq, err := NewGCPSessionUse(GCPSessionUseOptions{
		SessionHandle:          " asess_123 ",
		Command:                []string{exe, "-test.run=none"},
		ResolvedExecutable:     exe,
		ExecutableIdentity:     identity,
		AllowMutableExecutable: true,
		CWD:                    "/tmp",
		EnvironmentFingerprint: EnvironmentFingerprint([]string{"PATH=/tmp/bin"}),
	})
	if err != nil {
		t.Fatalf("NewGCPSessionUse returned error: %v", err)
	}
	if useReq.SessionHandle != "asess_123" {
		t.Fatalf("session handle = %q", useReq.SessionHandle)
	}
	if !useReq.AllowMutableExecutable {
		t.Fatal("AllowMutableExecutable = false, want true")
	}
	if err := useReq.ValidateForDaemon(); err != nil {
		t.Fatalf("use ValidateForDaemon returned error: %v", err)
	}

	destroyReq, err := NewGCPSessionDestroy(" asess_123 ", "/tmp")
	if err != nil {
		t.Fatalf("NewGCPSessionDestroy returned error: %v", err)
	}
	if destroyReq.SessionHandle != "asess_123" || destroyReq.CWD != "/tmp" {
		t.Fatalf("unexpected destroy request: %+v", destroyReq)
	}
	if err := destroyReq.ValidateForDaemon(); err != nil {
		t.Fatalf("destroy ValidateForDaemon returned error: %v", err)
	}
}

func TestGCPRequestRejectsInvalidFields(t *testing.T) {
	t.Parallel()

	exe, identity := testGCPExecutable(t)
	tests := []struct {
		name string
		err  error
		run  func() error
	}{
		{
			name: "non https scope",
			err:  ErrInvalidGCPScope,
			run: func() error {
				_, err := NormalizeGCPAccess(GCPAccess{
					GoogleAccount:  "work",
					Project:        "fixture-beta",
					ServiceAccount: "agent-beta@fixture-beta.iam.gserviceaccount.com",
					Scopes:         []string{"http://www.googleapis.com/auth/cloud-platform"},
				})
				return err
			},
		},
		{
			name: "service account email",
			err:  ErrInvalidGCPServiceAccount,
			run: func() error {
				_, err := NormalizeGCPAccess(GCPAccess{
					GoogleAccount:  "work",
					Project:        "fixture-beta",
					ServiceAccount: "agent-beta",
					Scopes:         []string{"https://www.googleapis.com/auth/cloud-platform"},
				})
				return err
			},
		},
		{
			name: "exec ttl",
			err:  ErrInvalidTTL,
			run: func() error {
				_, err := NewGCPExec(GCPExecOptions{
					Reason:                 "Inspect logs",
					Command:                []string{exe},
					ResolvedExecutable:     exe,
					ExecutableIdentity:     identity,
					AllowMutableExecutable: true,
					CWD:                    "/tmp",
					EnvironmentFingerprint: EnvironmentFingerprint([]string{"PATH=/tmp/bin"}),
					Access:                 testGCPAccess(),
					TTL:                    time.Hour,
				})
				return err
			},
		},
		{
			name: "relative config root",
			err:  ErrInvalidRequest,
			run: func() error {
				_, err := NewGCPExec(GCPExecOptions{
					Reason:                 "Inspect logs",
					Command:                []string{exe},
					ResolvedExecutable:     exe,
					ExecutableIdentity:     identity,
					AllowMutableExecutable: true,
					CWD:                    "/tmp",
					EnvironmentFingerprint: EnvironmentFingerprint([]string{"PATH=/tmp/bin"}),
					Access:                 testGCPAccess(),
					ConfigRoot:             "relative",
				})
				return err
			},
		},
		{
			name: "session max starts",
			err:  ErrInvalidGCPSessionMaxStarts,
			run: func() error {
				_, err := NewGCPSessionCreate(GCPSessionCreateOptions{
					Reason:           "Run benchmark",
					Access:           testGCPAccess(),
					ProfileName:      "benchmark",
					ConfigSourcePath: "/tmp/project/agent-secret.yml",
					ProjectRoot:      "/tmp/project",
					MaxCommandStarts: MaxGCPSessionMaxCommandStarts + 1,
				})
				return err
			},
		},
		{
			name: "session use handle",
			err:  ErrInvalidGCPSession,
			run: func() error {
				_, err := NewGCPSessionUse(GCPSessionUseOptions{})
				return err
			},
		},
		{
			name: "session destroy cwd",
			err:  ErrInvalidRequest,
			run: func() error {
				_, err := NewGCPSessionDestroy("asess_123", "relative")
				return err
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.run(); !errors.Is(err, tc.err) {
				t.Fatalf("error = %v, want %v", err, tc.err)
			}
		})
	}
}

func TestGCPSessionHandleAuditIDRedactsHandleWithStablePrefix(t *testing.T) {
	t.Parallel()

	got := GCPSessionHandleAuditID("  asess_1234567890_secret  ")
	if !strings.HasPrefix(got, "asess_1234:") {
		t.Fatalf("audit id = %q, want redacted handle prefix", got)
	}
	if len(got) != len("asess_1234:")+16 {
		t.Fatalf("audit id length = %d, want prefix plus 16 digest chars: %q", len(got), got)
	}
	if GCPSessionHandleAuditID("") != "" {
		t.Fatal("empty handle produced audit id")
	}
}

func testGCPAccess() GCPAccess {
	return GCPAccess{
		GoogleAccount:  "work",
		Project:        "fixture-beta",
		ServiceAccount: "agent-beta@fixture-beta.iam.gserviceaccount.com",
		Scopes:         []string{"https://www.googleapis.com/auth/cloud-platform"},
	}
}

func testGCPExecutable(t *testing.T) (string, fileidentity.Identity) {
	t.Helper()

	return testExecutable(t, t.TempDir(), "gcloud")
}
