package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
)

func TestProtocolHelpersRejectMalformedPayloads(t *testing.T) {
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

	if err := validateEnvelope(Envelope{Version: 99, Type: TypeOK}); !errors.Is(err, ErrProtocolVersion) {
		t.Fatalf("expected protocol version error, got %v", err)
	}
	if err := validateEnvelope(Envelope{Version: ProtocolVersion}); !errors.Is(err, ErrMalformedEnvelope) {
		t.Fatalf("expected missing type error, got %v", err)
	}
}

func TestClientProtocolErrorsAndCloseNil(t *testing.T) {
	t.Parallel()

	protocolErr := &ProtocolError{Code: "bad_request", Message: "nope"}
	if protocolErr.Error() != "bad_request: nope" {
		t.Fatalf("protocol error string = %q", protocolErr.Error())
	}
	if !IsProtocolError(protocolErr, "bad_request") {
		t.Fatal("IsProtocolError did not match protocol error")
	}
	if IsProtocolError(errors.New("plain"), "bad_request") {
		t.Fatal("IsProtocolError matched plain error")
	}

	client := &Client{}
	if err := client.Close(); err != nil {
		t.Fatalf("nil client close returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := roundTrip[StatusPayload](ctx, client, TypeDaemonStatus, "", "", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled round trip, got %v", err)
	}
}

func TestSameUIDValidatorRejectsInspectFailure(t *testing.T) {
	t.Parallel()

	err := (SameUIDValidator{}).Validate(&net.UnixConn{})
	if err == nil {
		t.Fatal("expected invalid unix connection error")
	}
}
