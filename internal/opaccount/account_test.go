package opaccount

import (
	"errors"
	"slices"
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
	var calls [][]string
	run := func(args ...string) ([]byte, error) {
		calls = append(calls, slices.Clone(args))
		if slices.Equal(args, []string{"--format=json"}) {
			return []byte(`[{"url":"json.1password.example"}]`), nil
		}
		return []byte(
			"URL                EMAIL                             USER ID\n" +
				"table.1password.example testing-user1@example.test   USERID\n",
		), nil
	}

	got := detectSingleCLIAccountWithRunner(run)
	if got != "json.1password.example" {
		t.Fatalf("account = %q, want JSON account", got)
	}
	if len(calls) != 1 || !slices.Equal(calls[0], []string{"--format=json"}) {
		t.Fatalf("calls = %#v, want only JSON account list", calls)
	}
}

func TestDetectSingleCLIAccountFallsBackToTable(t *testing.T) {
	var calls [][]string
	run := func(args ...string) ([]byte, error) {
		calls = append(calls, slices.Clone(args))
		if slices.Equal(args, []string{"--format=json"}) {
			return nil, errors.New("json format unavailable")
		}
		return []byte(
			"URL                EMAIL                             USER ID\n" +
				"table.1password.example testing-user1@example.test   USERID\n",
		), nil
	}

	got := detectSingleCLIAccountWithRunner(run)
	if got != "table.1password.example" {
		t.Fatalf("account = %q, want table account", got)
	}
	if len(calls) != 2 || !slices.Equal(calls[0], []string{"--format=json"}) || len(calls[1]) != 0 {
		t.Fatalf("calls = %#v, want JSON then table account list", calls)
	}
}
