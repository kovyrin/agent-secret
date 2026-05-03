package protocol

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestHelpersRejectMalformedPayloads(t *testing.T) {
	t.Parallel()

	if _, err := NewEnvelope(TypeOK, "req_1", "nonce_1", make(chan int)); err == nil {
		t.Fatal("expected unmarshalable payload error")
	}

	var env Envelope
	if _, err := DecodePayload[StatusPayload](env); err != nil {
		t.Fatalf("empty payload decode returned error: %v", err)
	}
	env = Envelope{Version: ProtocolVersion, Type: TypeOK, Payload: json.RawMessage(`{`)}
	if _, err := DecodePayload[StatusPayload](env); !errors.Is(err, ErrMalformedEnvelope) {
		t.Fatalf("expected malformed payload error, got %v", err)
	}

	if err := ValidateEnvelope(Envelope{Version: 99, Type: TypeOK}); !errors.Is(err, ErrProtocolVersion) {
		t.Fatalf("expected protocol version error, got %v", err)
	}
	if err := ValidateEnvelope(Envelope{Version: ProtocolVersion}); !errors.Is(err, ErrMalformedEnvelope) {
		t.Fatalf("expected missing type error, got %v", err)
	}
}
