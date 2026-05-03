package protocol

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestHelpersRejectMalformedPayloads(t *testing.T) {
	t.Parallel()

	if _, err := NewEnvelope(TypeOK, Correlation{RequestID: "req_1", Nonce: "nonce_1"}, make(chan int)); err == nil {
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

func TestReadEnvelopeFrame(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		maxBytes    int64
		readerSize  int
		wantType    MessageType
		wantRequest string
		wantErr     error
	}{
		{
			name:        "valid newline-delimited envelope with default limit",
			input:       `{"version":1,"type":"ok","request_id":"req_1"}` + "\n",
			wantType:    TypeOK,
			wantRequest: "req_1",
		},
		{
			name:    "empty frame",
			input:   "\n",
			wantErr: ErrMalformedEnvelope,
		},
		{
			name:    "clean eof",
			input:   "",
			wantErr: io.EOF,
		},
		{
			name:    "unterminated eof",
			input:   `{"version":1,"type":"ok"}`,
			wantErr: ErrMalformedEnvelope,
		},
		{
			name:    "malformed json",
			input:   "{\n",
			wantErr: ErrMalformedEnvelope,
		},
		{
			name:     "oversized complete frame",
			input:    `{"version":1,"type":"ok"}` + "\n",
			maxBytes: 8,
			wantErr:  ErrProtocolFrameSize,
		},
		{
			name:       "oversized buffered frame",
			input:      strings.Repeat("x", 64) + "\n",
			maxBytes:   8,
			readerSize: 16,
			wantErr:    ErrProtocolFrameSize,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tc.input))
			if tc.readerSize > 0 {
				reader = bufio.NewReaderSize(strings.NewReader(tc.input), tc.readerSize)
			}

			got, err := ReadEnvelopeFrame(reader, tc.maxBytes)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ReadEnvelopeFrame error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadEnvelopeFrame returned error: %v", err)
			}
			if got.Type != tc.wantType || got.RequestID != tc.wantRequest {
				t.Fatalf("ReadEnvelopeFrame = %+v, want type %q request %q", got, tc.wantType, tc.wantRequest)
			}
		})
	}
}
