package request

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestCodeLoadingEnvironmentEntries(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"NODE_OPTIONS=--require /tmp/old.js",
		"NODE_OPTIONS=--require /tmp/example.js",
		"BASH_ENV=/tmp/example.sh",
		"GIT_SSH_COMMAND=/tmp/example-ssh",
		"PYTHONSTARTUP=/tmp/example.py",
		"RUBYOPT=-r/tmp/example.rb",
		"GIT_CONFIG_KEY_0=core.sshCommand",
		"UNRELATED=value",
	}
	want := []string{
		"BASH_ENV=/tmp/example.sh",
		"GIT_CONFIG_KEY_0=core.sshCommand",
		"GIT_SSH_COMMAND=/tmp/example-ssh",
		"NODE_OPTIONS=--require /tmp/example.js",
		"PYTHONSTARTUP=/tmp/example.py",
		"RUBYOPT=-r/tmp/example.rb",
	}
	if got := CodeLoadingEnvironmentEntries(env); !reflect.DeepEqual(got, want) {
		t.Fatalf("code-loading entries = %v, want %v", got, want)
	}
	if err := validateCodeLoadingEnvironmentEntries(want); err != nil {
		t.Fatalf("valid entries rejected: %v", err)
	}
}

func TestCodeLoadingEnvironmentEntriesRejectUndisplayableValues(t *testing.T) {
	entries := CodeLoadingEnvironmentEntries([]string{"NODE_OPTIONS=" + strings.Repeat("x", maxCodeLoadingEnvironmentBytes)})
	if err := validateCodeLoadingEnvironmentEntries(entries); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversized code-loading environment = %v, want ErrInvalidRequest", err)
	}
}
