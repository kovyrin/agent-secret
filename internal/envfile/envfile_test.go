package envfile

import (
	"errors"
	"strings"
	"testing"
)

func TestParseDotenvEntries(t *testing.T) {
	t.Parallel()

	entries, err := Parse("test.env", strings.NewReader(`
# comment
PLAIN=value
SPACED = value with spaces # comment
export EXPORTED=present
EMPTY=
SINGLE='literal # value'
DOUBLE="line\nnext\tTabbed"
URL=op://Example/Item/password
`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	got := make(map[string]string, len(entries))
	for _, entry := range entries {
		got[entry.Key] = entry.Value
	}
	for key, want := range map[string]string{
		"PLAIN":    "value",
		"SPACED":   "value with spaces",
		"EXPORTED": "present",
		"EMPTY":    "",
		"SINGLE":   "literal # value",
		"DOUBLE":   "line\nnext\tTabbed",
		"URL":      "op://Example/Item/password",
	} {
		if got[key] != want {
			t.Fatalf("%s = %q, want %q", key, got[key], want)
		}
	}
}

func TestParseRejectsMalformedLines(t *testing.T) {
	t.Parallel()

	tests := []string{
		"NO_EQUALS",
		"=missing-key",
		"BAD\x00KEY=value",
		"SINGLE='unterminated",
		"DOUBLE=\"unterminated",
		"QUOTED=\"value\" trailing",
	}
	for _, input := range tests {
		_, err := Parse("bad.env", strings.NewReader(input))
		if !errors.Is(err, ErrInvalidEnvFile) {
			t.Fatalf("Parse(%q) error = %v, want ErrInvalidEnvFile", input, err)
		}
	}
}
