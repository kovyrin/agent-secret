package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateCommandsRequireNativeApproval(t *testing.T) {
	parser := NewParser()
	for _, args := range [][]string{
		{"update", "install"}, {"update", "check", "--yes"}, {"update", "status", "--install"},
	} {
		if _, err := parser.Parse(args); !errors.Is(err, ErrInvalidArguments) {
			t.Fatalf("%v returned %v, want invalid arguments", args, err)
		}
	}
	command, err := parser.Parse([]string{"update", "status", "--json"})
	if err != nil || command.Kind != KindUpdateStatus || !command.OutputJSON {
		t.Fatalf("status command = %v, %v", command.Kind, err)
	}
	command, err = parser.Parse([]string{"update", "check"})
	if err != nil || command.Kind != KindUpdateCheck {
		t.Fatalf("check command = %v, %v", command.Kind, err)
	}
	command, err = parser.Parse([]string{"update", "--help"})
	if !errors.Is(err, ErrHelpRequested) || !strings.Contains(command.HelpText, "requires approval") {
		t.Fatalf("update help does not describe approval: %v, %v", command, err)
	}
}

func TestUpdateStatusShowsInstalledVersionAndRecovery(t *testing.T) {
	host := writeUpdateBundle(t)
	if err := os.WriteFile(filepath.Join(filepath.Dir(host), ".agent-secret-update"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	status := installedUpdateStatus(host)
	if status.Release != "0.0.35" || status.Build != "1.0.35" || !status.UpdaterConfigured || !status.TransactionPresent {
		t.Fatalf("unexpected installed status: %+v", status)
	}
	var output bytes.Buffer
	app := NewApp(nil, &output, &output)
	if code := app.writeUpdateStatus(status, false); code != 0 ||
		!strings.Contains(output.String(), "0.0.35 (build 1.0.35)") ||
		!strings.Contains(output.String(), "needs recovery") {
		t.Fatalf("unexpected text status: %d, %s", code, output.String())
	}
	output.Reset()
	if code := app.writeUpdateStatus(status, true); code != 0 ||
		!strings.Contains(output.String(), `"transaction_present":true`) ||
		strings.Contains(output.String(), "https://") {
		t.Fatalf("unexpected JSON status: %d, %s", code, output.String())
	}
	app.Stdout = failingWriter{err: errors.New("write failed")}
	if code := app.writeUpdateStatus(status, true); code != 1 {
		t.Fatalf("status write error returned %d", code)
	}
	output.Reset()
	app.Stdout = &output
	if code := app.Run(context.Background(), []string{"update", "status"}); code != 0 ||
		!strings.Contains(output.String(), "updates are unavailable") {
		t.Fatalf("standalone CLI status: %d, %s", code, output.String())
	}
}

func TestUpdateCheckOnlyOpensTheBundledUpdater(t *testing.T) {
	host := writeUpdateBundle(t)
	var output bytes.Buffer
	app := NewApp(nil, &output, &output)
	ctx := context.Background()
	wanted := filepath.Join(host, "Contents", "Library", "LoginItems", "AgentSecretUpdater.app")
	launch := func(_ context.Context, path string) error {
		if path != wanted {
			t.Fatalf("launcher path = %q, want %q", path, wanted)
		}
		return nil
	}
	if code := app.openUpdateCheck(ctx, host, launch); code != 0 {
		t.Fatalf("open update check returned %d", code)
	}
	failed := func(context.Context, string) error { return errors.New("synthetic launch error") }
	if code := app.openUpdateCheck(ctx, host, failed); code != 1 ||
		!strings.Contains(output.String(), "could not open Check for Updates") {
		t.Fatalf("failed update check: %d, %s", code, output.String())
	}
	if code := app.Run(ctx, []string{"update", "check"}); code != 1 {
		t.Fatalf("standalone CLI opened the updater: %d", code)
	}
}

func writeUpdateBundle(t *testing.T) string {
	t.Helper()
	host := filepath.Join(t.TempDir(), "Agent Secret.app")
	contents := filepath.Join(host, "Contents")
	if err := os.MkdirAll(contents, 0o700); err != nil {
		t.Fatal(err)
	}
	plist := `<plist><dict>
<key>CFBundleShortVersionString</key><string>0.0.35</string>
<key>CFBundleVersion</key><string>1.0.35</string>
<key>SUFeedURL</key><string>https://example.test/appcast.xml</string>
</dict></plist>`
	if err := os.WriteFile(filepath.Join(contents, "Info.plist"), []byte(plist), 0o600); err != nil {
		t.Fatal(err)
	}
	return host
}
