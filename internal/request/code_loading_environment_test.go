package request

import (
	"reflect"
	"testing"
)

func TestCodeLoadingEnvironmentNames(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"NODE_OPTIONS=--require /tmp/example.js",
		"BASH_ENV=/tmp/example.sh",
		"GIT_SSH_COMMAND=/tmp/example-ssh",
		"PYTHONSTARTUP=/tmp/example.py",
		"RUBYOPT=-r/tmp/example.rb",
		"GIT_CONFIG_KEY_0=core.sshCommand",
		"UNRELATED=value",
	}
	want := []string{"BASH_ENV", "GIT_CONFIG_KEY_0", "GIT_SSH_COMMAND", "NODE_OPTIONS", "PYTHONSTARTUP", "RUBYOPT"}
	if got := CodeLoadingEnvironmentNames(env); !reflect.DeepEqual(got, want) {
		t.Fatalf("code-loading names = %v, want %v", got, want)
	}
}
