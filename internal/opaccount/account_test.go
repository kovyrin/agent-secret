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
			t.Setenv("PATH", t.TempDir())

			got := SelectDesktopAccount(tt.accountOverride, tt.opAccount)
			if got != tt.want {
				t.Fatalf("account = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSelectDesktopAccountDetectsSingleJSONAccount(t *testing.T) {
	writeFakeOP(t, `
if [ "$1" = "account" ] && [ "$2" = "list" ] && [ "$3" = "--format=json" ]; then
  printf '%s\n' '[{"url":"my.1password.ca","email":"testing-user1@example.test"}]'
  exit 0
fi
exit 64
`)

	got := SelectDesktopAccount("", "")
	if got != "my.1password.ca" {
		t.Fatalf("account = %q, want detected account", got)
	}
}

func TestSelectDesktopAccountDetectsSingleTableAccount(t *testing.T) {
	writeFakeOP(t, `
if [ "$1" = "account" ] && [ "$2" = "list" ] && [ "$3" = "--format=json" ]; then
  exit 64
fi
if [ "$1" = "account" ] && [ "$2" = "list" ]; then
  printf '%s\n' 'URL                EMAIL                             USER ID'
  printf '%s\n' 'my.1password.ca    testing-user1@example.test       4POXGBG34RAQBMLPYCV42CSF4M'
  exit 0
fi
exit 64
`)

	got := SelectDesktopAccount("", "")
	if got != "my.1password.ca" {
		t.Fatalf("account = %q, want detected account", got)
	}
}

func TestSelectDesktopAccountFallsBackWhenCLIDetectionIsAmbiguous(t *testing.T) {
	writeFakeOP(t, `
if [ "$1" = "account" ] && [ "$2" = "list" ] && [ "$3" = "--format=json" ]; then
  printf '%s\n' '[{"url":"my.1password.com"},{"url":"my.1password.ca"}]'
  exit 0
fi
exit 64
`)

	got := SelectDesktopAccount("", "")
	if got != DefaultDesktopAccount {
		t.Fatalf("account = %q, want default account", got)
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
