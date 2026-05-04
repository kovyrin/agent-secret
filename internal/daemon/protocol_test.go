package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/request"
	"github.com/kovyrin/agent-secret/internal/testsupport/unixsocket"
)

func TestClientProtocolErrorsAndCloseNil(t *testing.T) {
	t.Parallel()

	protocolErr := &ProtocolError{Code: protocol.ErrorCodeBadRequest, Message: "nope"}
	if protocolErr.Error() != "bad_request: nope" {
		t.Fatalf("protocol error string = %q", protocolErr.Error())
	}
	if !IsProtocolError(protocolErr, protocol.ErrorCodeBadRequest) {
		t.Fatal("IsProtocolError did not match protocol error")
	}
	if IsProtocolError(errors.New("plain"), protocol.ErrorCodeBadRequest) {
		t.Fatal("IsProtocolError matched plain error")
	}

	client := &Client{}
	if err := client.Close(); err != nil {
		t.Fatalf("nil client close returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := roundTrip[protocol.StatusPayload](ctx, client, protocol.TypeDaemonStatus, protocol.Correlation{}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled round trip, got %v", err)
	}
}

func TestClientRoundTripHonorsContextCancellationWaitingForResponse(t *testing.T) {
	t.Parallel()

	client, requests, cleanup := startStallingDaemonClient(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		_, err := client.Status(ctx)
		errc <- err
	}()

	env := receiveStalledRequest(t, requests)
	if env.Type != protocol.TypeDaemonStatus {
		t.Fatalf("request type = %s, want %s", env.Type, protocol.TypeDaemonStatus)
	}

	cancel()
	err := receiveRoundTripError(t, errc)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
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
	if env.Type != protocol.TypeDaemonStatus {
		t.Fatalf("request type = %s, want %s", env.Type, protocol.TypeDaemonStatus)
	}

	err := receiveRoundTripError(t, errc)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline exceeded error, got %v", err)
	}
}

func TestClientRoundTripUsesDefaultDeadlineWithoutCallerDeadline(t *testing.T) {
	t.Parallel()

	client, requests, cleanup := startStallingDaemonClient(t)
	defer cleanup()
	client.DefaultTimeout = 25 * time.Millisecond

	errc := make(chan error, 1)
	go func() {
		_, err := client.Status(context.Background())
		errc <- err
	}()

	env := receiveStalledRequest(t, requests)
	if env.Type != protocol.TypeDaemonStatus {
		t.Fatalf("request type = %s, want %s", env.Type, protocol.TypeDaemonStatus)
	}

	err := receiveRoundTripError(t, errc)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected default deadline exceeded error, got %v", err)
	}
}

func TestClientRequestExecDefaultDeadlineAllowsApprovalWaitUntilRequestExpiry(t *testing.T) {
	t.Parallel()

	client, cleanup := startRespondingDaemonClient(t, func(env protocol.Envelope) []byte {
		time.Sleep(60 * time.Millisecond)
		return execResponseFrame(t, env, protocol.ExecResponsePayload{
			Env:           map[string]string{"TOKEN": "value"},
			SecretAliases: []string{"TOKEN"},
		})
	})
	defer cleanup()
	client.DefaultTimeout = 25 * time.Millisecond

	req := testExecRequestAt(t, time.Now(), []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token"}})
	got, err := client.RequestExec(context.Background(), testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("RequestExec returned error before request expiry: %v", err)
	}
	if got.Env["TOKEN"] != "value" {
		t.Fatalf("exec response env = %+v", got.Env)
	}
}

func TestClientRejectsMissingPayloadForPayloadOKResponses(t *testing.T) {
	t.Parallel()

	req := testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: "op://Example/Item/token", Account: "Work"},
	})
	client, cleanup := startRespondingDaemonClient(t, func(env protocol.Envelope) []byte {
		if env.Type != protocol.TypeRequestExec {
			t.Fatalf("request type = %s, want %s", env.Type, protocol.TypeRequestExec)
		}
		return emptyOKResponseFrame(t, env)
	})
	defer cleanup()

	_, err := client.RequestExec(context.Background(), testCorrelation("req_1", "nonce_1"), req)
	if !errors.Is(err, protocol.ErrMalformedEnvelope) {
		t.Fatalf("expected malformed empty OK response error, got %v", err)
	}
	if !strings.Contains(err.Error(), "missing payload") {
		t.Fatalf("error %q does not mention missing payload", err)
	}
}

func TestClientValidatesPayloadOKResponseShape(t *testing.T) {
	t.Parallel()

	execReq := testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: "op://Example/Item/token", Account: "Work"},
	})
	tests := []struct {
		name       string
		frame      func(t *testing.T, env protocol.Envelope) []byte
		call       func(context.Context, *Client) error
		wantErrMsg string
	}{
		{
			name: "status pid",
			frame: func(t *testing.T, env protocol.Envelope) []byte {
				t.Helper()

				return okResponseFrame(t, env, protocol.StatusPayload{})
			},
			call: func(ctx context.Context, client *Client) error {
				_, err := client.Status(ctx)
				return err
			},
			wantErrMsg: "invalid pid",
		},
		{
			name: "pending request id",
			frame: func(t *testing.T, env protocol.Envelope) []byte {
				t.Helper()

				return okResponseFrame(t, env, approval.ApprovalRequestPayload{
					Nonce:     "nonce_1",
					Command:   []string{"terraform", "plan"},
					ExpiresAt: time.Now().Add(time.Minute),
					Secrets: []approval.ApprovalRequestedSecret{
						{Alias: "TOKEN", Ref: "op://Example/Item/token", Account: "Work"},
					},
				})
			},
			call: func(ctx context.Context, client *Client) error {
				_, err := client.FetchPendingApproval(ctx)
				return err
			},
			wantErrMsg: "missing request id",
		},
		{
			name: "exec aliases",
			frame: func(t *testing.T, env protocol.Envelope) []byte {
				t.Helper()

				return execResponseFrame(t, env, protocol.ExecResponsePayload{
					Env:           map[string]string{"OTHER": "value"},
					SecretAliases: []string{"OTHER"},
				})
			},
			call: func(ctx context.Context, client *Client) error {
				_, err := client.RequestExec(ctx, testCorrelation("req_1", "nonce_1"), execReq)
				return err
			},
			wantErrMsg: "secret aliases do not match",
		},
		{
			name: "exec env",
			frame: func(t *testing.T, env protocol.Envelope) []byte {
				t.Helper()

				return execResponseFrame(t, env, protocol.ExecResponsePayload{
					Env:           map[string]string{"TOKEN": "value", "OTHER": "value"},
					SecretAliases: []string{"TOKEN"},
				})
			},
			call: func(ctx context.Context, client *Client) error {
				_, err := client.RequestExec(ctx, testCorrelation("req_1", "nonce_1"), execReq)
				return err
			},
			wantErrMsg: "env aliases do not match",
		},
		{
			name: "exec missing env",
			frame: func(t *testing.T, env protocol.Envelope) []byte {
				t.Helper()

				return execResponseFrame(t, env, protocol.ExecResponsePayload{
					SecretAliases: []string{"TOKEN"},
				})
			},
			call: func(ctx context.Context, client *Client) error {
				_, err := client.RequestExec(ctx, testCorrelation("req_1", "nonce_1"), execReq)
				return err
			},
			wantErrMsg: "missing env",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client, cleanup := startRespondingDaemonClient(t, func(env protocol.Envelope) []byte {
				return tc.frame(t, env)
			})
			defer cleanup()

			err := tc.call(context.Background(), client)
			if !errors.Is(err, protocol.ErrMalformedEnvelope) {
				t.Fatalf("expected malformed response error, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErrMsg) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErrMsg)
			}
		})
	}
}

func TestClientRejectsOversizedDaemonResponseFrame(t *testing.T) {
	t.Parallel()

	client, cleanup := startRespondingDaemonClient(t, func(protocol.Envelope) []byte {
		frame := bytes.Repeat([]byte("x"), int(protocol.DefaultMaxProtocolFrameBytes)+1)
		return append(frame, '\n')
	})
	defer cleanup()

	_, err := client.Status(context.Background())
	if !errors.Is(err, protocol.ErrProtocolFrameSize) {
		t.Fatalf("expected protocol frame size error, got %v", err)
	}
}

func TestClientRejectsMismatchedErrorResponseCorrelation(t *testing.T) {
	t.Parallel()

	execReq := testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: "op://Example/Item/token"},
	})
	tests := []struct {
		name       string
		frame      []byte
		call       func(context.Context, *Client) error
		wantErr    error
		wantErrMsg string
	}{
		{
			name:       "request exec request id",
			frame:      errorResponseFrame(t, "req_stale", "nonce_1"),
			wantErr:    protocol.ErrMalformedEnvelope,
			wantErrMsg: "response request id mismatch",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.RequestExec(
					ctx,
					testCorrelation("req_1", "nonce_1"),
					execReq,
				)
				return err
			},
		},
		{
			name:    "command started nonce",
			frame:   errorResponseFrame(t, "req_1", "nonce_stale"),
			wantErr: ErrInvalidNonce,
			call: func(ctx context.Context, client *Client) error {
				return client.ReportStarted(ctx, testCorrelation("req_1", "nonce_1"), 1234)
			},
		},
		{
			name:       "command completed request id",
			frame:      errorResponseFrame(t, "req_stale", "nonce_1"),
			wantErr:    protocol.ErrMalformedEnvelope,
			wantErrMsg: "response request id mismatch",
			call: func(ctx context.Context, client *Client) error {
				return client.ReportCompleted(ctx, testCorrelation("req_1", "nonce_1"), 0, "")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client, cleanup := startRespondingDaemonClient(t, func(protocol.Envelope) []byte { return tc.frame })
			defer cleanup()

			err := tc.call(context.Background(), client)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
			if tc.wantErrMsg != "" && !strings.Contains(err.Error(), tc.wantErrMsg) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErrMsg)
			}
		})
	}
}

func TestClientAllowsUncorrelatedStatusErrorResponse(t *testing.T) {
	t.Parallel()

	client, cleanup := startRespondingDaemonClient(t, func(protocol.Envelope) []byte {
		return errorResponseFrame(t, "req_other", "nonce_other")
	})
	defer cleanup()

	_, err := client.Status(context.Background())
	if !IsProtocolError(err, protocol.ErrorCodeBadRequest) {
		t.Fatalf("expected daemon protocol error, got %v", err)
	}
}

func errorResponseFrame(t *testing.T, requestID string, nonce string) []byte {
	t.Helper()

	env, err := protocol.NewEnvelope(protocol.TypeError, testCorrelation(requestID, nonce), protocol.ErrorPayload{
		Code:    "bad_request",
		Message: "bad request",
	})
	if err != nil {
		t.Fatalf("NewEnvelope returned error: %v", err)
	}
	frame, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal error response: %v", err)
	}
	return append(frame, '\n')
}

func emptyOKResponseFrame(t *testing.T, request protocol.Envelope) []byte {
	t.Helper()

	env := protocol.Envelope{
		Version:   protocol.ProtocolVersion,
		Type:      protocol.TypeOK,
		RequestID: request.RequestID,
		Nonce:     request.Nonce,
	}
	frame, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal empty OK response: %v", err)
	}
	return append(frame, '\n')
}

func okResponseFrame(t *testing.T, request protocol.Envelope, payload any) []byte {
	t.Helper()

	env, err := protocol.NewEnvelope(protocol.TypeOK, request.Correlation(), payload)
	if err != nil {
		t.Fatalf("NewEnvelope returned error: %v", err)
	}
	frame, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal OK response: %v", err)
	}
	return append(frame, '\n')
}

func execResponseFrame(t *testing.T, request protocol.Envelope, payload protocol.ExecResponsePayload) []byte {
	t.Helper()

	env, err := protocol.NewEnvelope(protocol.TypeOK, request.Correlation(), payload)
	if err != nil {
		t.Fatalf("NewEnvelope returned error: %v", err)
	}
	frame, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal exec response: %v", err)
	}
	return append(frame, '\n')
}

func TestSameUIDValidatorRejectsInspectFailure(t *testing.T) {
	t.Parallel()

	err := (SameUIDValidator{}).Validate(&net.UnixConn{})
	if err == nil {
		t.Fatal("expected invalid unix connection error")
	}
}

func startRespondingDaemonClient(t *testing.T, response func(protocol.Envelope) []byte) (*Client, func()) {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "agent-secret-response-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: socket tests need an owner-searchable private listener directory.
		_ = os.RemoveAll(dir)
		t.Fatalf("secure socket test directory: %v", err)
	}
	path := filepath.Join(dir, "daemon.sock")
	listener, err := ListenUnix(path)
	unixsocket.SkipIfBindUnavailable(t, err)
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("ListenUnix returned error: %v", err)
	}

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			serverDone <- err
			return
		}
		defer func() { _ = conn.Close() }()

		var env protocol.Envelope
		if err := json.NewDecoder(conn).Decode(&env); err != nil {
			serverDone <- err
			return
		}
		_, err = conn.Write(response(env))
		serverDone <- err
	}()

	conn, err := Dial(context.Background(), path)
	if err != nil {
		_ = listener.Close()
		t.Fatalf("Dial returned error: %v", err)
	}
	client := NewClient(conn)

	return client, func() {
		_ = client.Close()
		_ = listener.Close()
		defer func() { _ = os.RemoveAll(dir) }()
		select {
		case err := <-serverDone:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("responding daemon returned error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("responding daemon did not stop")
		}
	}
}

func startStallingDaemonClient(t *testing.T) (*Client, <-chan protocol.Envelope, func()) {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "agent-secret-stall-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: socket tests need an owner-searchable private listener directory.
		_ = os.RemoveAll(dir)
		t.Fatalf("secure socket test directory: %v", err)
	}
	path := filepath.Join(dir, "daemon.sock")
	listener, err := ListenUnix(path)
	unixsocket.SkipIfBindUnavailable(t, err)
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("ListenUnix returned error: %v", err)
	}

	requests := make(chan protocol.Envelope, 1)
	release := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			serverDone <- err
			return
		}
		defer func() { _ = conn.Close() }()

		var env protocol.Envelope
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

func receiveStalledRequest(t *testing.T, requests <-chan protocol.Envelope) protocol.Envelope {
	t.Helper()

	select {
	case env := <-requests:
		return env
	case <-time.After(time.Second):
		t.Fatal("daemon client did not write request")
	}
	return protocol.Envelope{}
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
