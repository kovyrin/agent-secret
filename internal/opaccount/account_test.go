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
			name:      "OP_ACCOUNT fallback",
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
			got := SelectDesktopAccount(tt.accountOverride, tt.opAccount)
			if got != tt.want {
				t.Fatalf("account = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSelectDesktopAccountUsesDesktopDefaultWhenUnset(t *testing.T) {
	got := SelectDesktopAccount("", "")
	if got != DefaultDesktopAccount {
		t.Fatalf("account = %q, want default account", got)
	}
}

func TestSelectConcreteDesktopAccountBindsDefault(t *testing.T) {
	got := SelectConcreteDesktopAccount("", "", func() string {
		return " DetectedAccount "
	})
	if got != "DetectedAccount" {
		t.Fatalf("account = %q, want detected account", got)
	}
}

func TestSelectConcreteDesktopAccountPreservesExplicitFallbacks(t *testing.T) {
	got := SelectConcreteDesktopAccount(" OverrideAccount ", "EnvAccount", func() string {
		t.Fatal("detector should not run when explicit account is present")
		return ""
	})
	if got != "OverrideAccount" {
		t.Fatalf("account = %q, want override account", got)
	}
}

func TestSelectSingleAccount(t *testing.T) {
	tests := []struct {
		name     string
		accounts []string
		want     string
	}{
		{name: "none", accounts: nil, want: ""},
		{name: "blank", accounts: []string{" \t "}, want: ""},
		{name: "single", accounts: []string{" AccountUUID "}, want: "AccountUUID"},
		{name: "multiple", accounts: []string{"AccountA", "AccountB"}, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectSingleAccount(tt.accounts)
			if got != tt.want {
				t.Fatalf("account = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSelectDefaultDesktopAccountPrefersPersonalAccount(t *testing.T) {
	accounts := []DesktopAccount{
		{
			UUID:      "BusinessUUID",
			State:     "A",
			UserState: "A",
			Type:      "B",
			SignInURL: "https://fixture.1password.com/",
		},
		{
			UUID:      "PersonalUUID",
			State:     "A",
			UserState: "A",
			Type:      "F",
			SignInURL: "https://my.1password.com/",
		},
	}

	got := SelectDefaultDesktopAccount(accounts)
	if got != "PersonalUUID" {
		t.Fatalf("account = %q, want personal account", got)
	}
}

func TestSelectDefaultDesktopAccountFallsBackToSingleActiveAccount(t *testing.T) {
	accounts := []DesktopAccount{
		{
			UUID:      "BusinessUUID",
			State:     "A",
			UserState: "A",
			Type:      "B",
			SignInURL: "https://fixture.1password.com/",
		},
	}

	got := SelectDefaultDesktopAccount(accounts)
	if got != "BusinessUUID" {
		t.Fatalf("account = %q, want only active account", got)
	}
}

func TestSelectDefaultDesktopAccountRejectsAmbiguousBusinessAccounts(t *testing.T) {
	accounts := []DesktopAccount{
		{UUID: "BusinessOne", State: "A", UserState: "A", Type: "B"},
		{UUID: "BusinessTwo", State: "A", UserState: "A", Type: "B"},
	}

	got := SelectDefaultDesktopAccount(accounts)
	if got != "" {
		t.Fatalf("account = %q, want no default account", got)
	}
}

func TestSelectDefaultDesktopAccountIgnoresInactiveAccounts(t *testing.T) {
	accounts := []DesktopAccount{
		{
			UUID:      "InactivePersonal",
			State:     "S",
			UserState: "A",
			Type:      "F",
			SignInURL: "https://my.1password.com/",
		},
		{
			UUID:      "BusinessUUID",
			State:     "A",
			UserState: "A",
			Type:      "B",
			SignInURL: "https://fixture.1password.com/",
		},
	}

	got := SelectDefaultDesktopAccount(accounts)
	if got != "BusinessUUID" {
		t.Fatalf("account = %q, want only active account", got)
	}
}
