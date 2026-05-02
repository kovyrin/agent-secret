package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/request"
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

func TestClientRoundTripHonorsContextCancellationWaitingForResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		wantType string
		prepare  func(*testing.T) func(context.Context, *Client) error
	}{
		{
			name:     "status",
			wantType: TypeDaemonStatus,
			prepare: func(_ *testing.T) func(context.Context, *Client) error {
				return func(ctx context.Context, client *Client) error {
					_, err := client.Status(ctx)
					return err
				}
			},
		},
		{
			name:     "stop",
			wantType: TypeDaemonStop,
			prepare: func(_ *testing.T) func(context.Context, *Client) error {
				return func(ctx context.Context, client *Client) error {
					_, err := client.Stop(ctx)
					return err
				}
			},
		},
		{
			name:     "fetch pending approval",
			wantType: TypeApprovalPending,
			prepare: func(_ *testing.T) func(context.Context, *Client) error {
				return func(ctx context.Context, client *Client) error {
					_, err := client.FetchPendingApproval(ctx)
					return err
				}
			},
		},
		{
			name:     "submit approval decision",
			wantType: TypeApprovalDecision,
			prepare: func(_ *testing.T) func(context.Context, *Client) error {
				return func(ctx context.Context, client *Client) error {
					return client.SubmitApprovalDecision(ctx, ApprovalDecisionPayload{
						RequestID: "req_1",
						Nonce:     "nonce_1",
						Decision:  "approve_once",
					})
				}
			},
		},
		{
			name:     "request exec",
			wantType: TypeRequestExec,
			prepare: func(t *testing.T) func(context.Context, *Client) error {
				t.Helper()

				req := testExecRequest(t, []request.SecretSpec{
					{Alias: "TOKEN", Ref: "op://Example/Item/token"},
				})
				return func(ctx context.Context, client *Client) error {
					_, err := client.RequestExec(ctx, "req_1", "nonce_1", req)
					return err
				}
			},
		},
		{
			name:     "report started",
			wantType: TypeCommandStarted,
			prepare: func(_ *testing.T) func(context.Context, *Client) error {
				return func(ctx context.Context, client *Client) error {
					return client.ReportStarted(ctx, "req_1", "nonce_1", 1234)
				}
			},
		},
		{
			name:     "report completed",
			wantType: TypeCommandCompleted,
			prepare: func(_ *testing.T) func(context.Context, *Client) error {
				return func(ctx context.Context, client *Client) error {
					return client.ReportCompleted(ctx, "req_1", "nonce_1", 0, "")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client, requests, cleanup := startStallingDaemonClient(t)
			defer cleanup()
			call := tc.prepare(t)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			errc := make(chan error, 1)
			go func() {
				errc <- call(ctx, client)
			}()

			env := receiveStalledRequest(t, requests)
			if env.Type != tc.wantType {
				t.Fatalf("request type = %s, want %s", env.Type, tc.wantType)
			}

			cancel()
			err := receiveRoundTripError(t, errc)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("expected context canceled error, got %v", err)
			}
		})
	}
}

func TestClientRoundTripHonorsContextDeadlineWaitingForResponse(t *testing.T) {
	t.Parallel()

	client, requests, cleanup := startStallingDaemonClient(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		_, err := client.Status(ctx)
		errc <- err
	}()

	env := receiveStalledRequest(t, requests)
	if env.Type != TypeDaemonStatus {
		t.Fatalf("request type = %s, want %s", env.Type, TypeDaemonStatus)
	}

	err := receiveRoundTripError(t, errc)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline exceeded error, got %v", err)
	}
}

func TestSameUIDValidatorRejectsInspectFailure(t *testing.T) {
	t.Parallel()

	err := (SameUIDValidator{}).Validate(&net.UnixConn{})
	if err == nil {
		t.Fatal("expected invalid unix connection error")
	}
}

func startStallingDaemonClient(t *testing.T) (*Client, <-chan Envelope, func()) {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "agent-secret-stall-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("secure socket test directory: %v", err)
	}
	path := filepath.Join(dir, "daemon.sock")
	listener, err := ListenUnix(path)
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("ListenUnix returned error: %v", err)
	}

	requests := make(chan Envelope, 1)
	release := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			serverDone <- err
			return
		}
		defer func() { _ = conn.Close() }()

		var env Envelope
		if err := json.NewDecoder(conn).Decode(&env); err != nil {
			serverDone <- err
			return
		}
		requests <- env
		<-release
		serverDone <- nil
	}()

	conn, err := Dial(context.Background(), path)
	if err != nil {
		_ = listener.Close()
		t.Fatalf("Dial returned error: %v", err)
	}
	client := NewClient(conn)

	return client, requests, func() {
		_ = client.Close()
		close(release)
		_ = listener.Close()
		defer func() { _ = os.RemoveAll(dir) }()
		select {
		case err := <-serverDone:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("stalling daemon returned error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("stalling daemon did not stop")
		}
	}
}

func receiveStalledRequest(t *testing.T, requests <-chan Envelope) Envelope {
	t.Helper()

	select {
	case env := <-requests:
		return env
	case <-time.After(time.Second):
		t.Fatal("daemon client did not write request")
	}
	return Envelope{}
}

func receiveRoundTripError(t *testing.T, errc <-chan error) error {
	t.Helper()

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected round trip error")
		}
		return err
	case <-time.After(time.Second):
		t.Fatal("daemon client did not return after context cancellation")
	}
	return nil
}
