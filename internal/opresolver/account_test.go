package opresolver

import (
	"context"
	"testing"
)

func TestDesktopAccountWithPrecedence(t *testing.T) {
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
			name: "sdk default",
			want: DefaultDesktopAccount,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := desktopAccountWith(context.Background(), tt.accountOverride, tt.opAccount)
			if err != nil {
				t.Fatalf("desktopAccountWith returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("account = %q, want %q", got, tt.want)
			}
		})
	}
}
