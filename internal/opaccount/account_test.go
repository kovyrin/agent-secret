package opaccount

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSelectDesktopAccountPrecedence(t *testing.T) {
	tests := []struct {
		name            string
		accountOverride string
		opAccount       string
		want            string
	}{
		{
			name:            "explicit override",
			accountOverride: " Fixture ",
			opAccount:       "FromEnv",
			want:            "Fixture",
		},
		{
			name:      "op account fallback",
			opAccount: " EnvAccount ",
			want:      "EnvAccount",
		},
		{
			name: "built in default",
			want: DefaultDesktopAccount,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SelectDesktopAccountWithDetector(tt.accountOverride, tt.opAccount, nil)
			if got != tt.want {
				t.Fatalf("account = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSelectDesktopAccountUsesProductionDetectorFallback(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	got := SelectDesktopAccount("", "")
	if got != DefaultDesktopAccount {
		t.Fatalf("account = %q, want default account", got)
	}
}

func TestSelectDesktopAccountDetectsSingleJSONAccount(t *testing.T) {
	got := SelectDesktopAccountWithDetector("", "", func() string {
		return singleCLIAccountFromJSON([]byte(`[{"url":"my.1password.ca","email":"testing-user1@example.test"}]`))
	})
	if got != "my.1password.ca" {
		t.Fatalf("account = %q, want detected account", got)
	}
}

func TestSelectDesktopAccountDetectsSingleTableAccount(t *testing.T) {
	got := SelectDesktopAccountWithDetector("", "", func() string {
		return singleCLIAccountFromTable([]byte(
			"URL                EMAIL                             USER ID\n" +
				"my.1password.ca    testing-user1@example.test       4POXGBG34RAQBMLPYCV42CSF4M\n",
		))
	})
	if got != "my.1password.ca" {
		t.Fatalf("account = %q, want detected account", got)
	}
}

func TestSelectDesktopAccountFallsBackWhenCLIDetectionIsAmbiguous(t *testing.T) {
	got := SelectDesktopAccountWithDetector("", "", func() string {
		return singleCLIAccountFromJSON([]byte(`[{"url":"my.1password.com"},{"url":"my.1password.ca"}]`))
	})
	if got != DefaultDesktopAccount {
		t.Fatalf("account = %q, want default account", got)
	}
}

func TestDetectSingleCLIAccountUsesJSONBeforeTable(t *testing.T) {
	writeFakeOP(t, `
if [ "$1" = "account" ] && [ "$2" = "list" ] && [ "$3" = "--format=json" ]; then
  printf '%s\n' '[{"url":"json.1password.example"}]'
  exit 0
fi
if [ "$1" = "account" ] && [ "$2" = "list" ]; then
  printf '%s\n' 'URL                EMAIL                             USER ID'
  printf '%s\n' 'table.1password.example testing-user1@example.test   USERID'
  exit 0
fi
exit 64
`)

	got := DetectSingleCLIAccount()
	if got != "json.1password.example" {
		t.Fatalf("account = %q, want JSON account", got)
	}
}

func TestDetectSingleCLIAccountFallsBackToTable(t *testing.T) {
	writeFakeOP(t, `
if [ "$1" = "account" ] && [ "$2" = "list" ] && [ "$3" = "--format=json" ]; then
  exit 64
fi
if [ "$1" = "account" ] && [ "$2" = "list" ]; then
  printf '%s\n' 'URL                EMAIL                             USER ID'
  printf '%s\n' 'table.1password.example testing-user1@example.test   USERID'
  exit 0
fi
exit 64
`)

	got := DetectSingleCLIAccount()
	if got != "table.1password.example" {
		t.Fatalf("account = %q, want table account", got)
	}
}

func writeFakeOP(t *testing.T, body string) {
	t.Helper()

	binDir := t.TempDir()
	t.Setenv("PATH", binDir)
	path := filepath.Join(binDir, "op")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil { //nolint:gosec // G306: account-selection tests need a runnable fake 1Password CLI.
		t.Fatalf("write fake op: %v", err)
	}
}
