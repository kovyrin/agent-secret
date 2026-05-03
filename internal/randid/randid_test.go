package randid

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestGenerateUsesReaderBytes(t *testing.T) {
	t.Parallel()

	id, err := Generate(strings.NewReader("abcdefghijklmnop"), "req")
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if id != "req_6162636465666768696a6b6c6d6e6f70" {
		t.Fatalf("id = %q, want deterministic hex id", id)
	}
}

func TestGenerateWrapsReaderError(t *testing.T) {
	t.Parallel()

	_, err := Generate(errorReader{}, "req")
	if !errors.Is(err, errReadFailed) {
		t.Fatalf("error = %v, want wrapped reader error", err)
	}
}

var errReadFailed = errors.New("read failed")

type errorReader struct{}

func (errorReader) Read(_ []byte) (int, error) {
	return 0, errReadFailed
}

func TestGenerateAcceptsNilReader(t *testing.T) {
	t.Parallel()

	id, err := Generate(nil, "nonce")
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if !strings.HasPrefix(id, "nonce_") {
		t.Fatalf("id = %q, want nonce prefix", id)
	}
	if len(id) != len("nonce_")+32 {
		t.Fatalf("id length = %d, want prefix plus 32 hex chars", len(id))
	}
}

var _ io.Reader = errorReader{}
