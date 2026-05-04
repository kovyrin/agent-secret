package opaccount

import "testing"

func TestSelectDesktopAccountPrecedence(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

			got := SelectDesktopAccount(tt.accountOverride, tt.opAccount)
			if got != tt.want {
				t.Fatalf("account = %q, want %q", got, tt.want)
			}
		})
	}
}
