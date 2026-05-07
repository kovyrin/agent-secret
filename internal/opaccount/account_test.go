package opaccount

import (
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
