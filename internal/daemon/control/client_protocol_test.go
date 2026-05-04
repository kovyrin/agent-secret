package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/daemon"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/daemon/socket"
	"github.com/kovyrin/agent-secret/internal/fileidentity"
	"github.com/kovyrin/agent-secret/internal/request"
	"github.com/kovyrin/agent-secret/internal/testsupport/unixsocket"
)

func testCorrelation(requestID string, nonce string) protocol.Correlation {
	return protocol.Correlation{RequestID: requestID, Nonce: nonce}
}

func testExecRequest(t *testing.T, secrets []request.SecretSpec) request.ExecRequest {
	t.Helper()
	return testExecRequestAt(t, time.Now(), secrets)
}

func testExecRequestAt(t *testing.T, now time.Time, secrets []request.SecretSpec) request.ExecRequest {
	t.Helper()

	reqSecrets := make([]request.Secret, 0, len(secrets))
	for _, spec := range secrets {
		ref, err := request.ParseSecretRef(spec.Ref)
		if err != nil {
			t.Fatalf("ParseSecretRef returned error: %v", err)
		}
		reqSecrets = append(reqSecrets, request.Secret{Alias: spec.Alias, Ref: ref, Account: spec.Account})
	}

	return request.ExecRequest{
		Reason:             "Run Terraform plan",
		Command:            []string{"terraform", "plan"},
		ResolvedExecutable: "/opt/homebrew/bin/terraform",
		ExecutableIdentity: fileidentity.Identity{Device: 1, Inode: 1, Mode: 0o755},
		CWD:                "/tmp/project",
		Secrets:            reqSecrets,
		TTL:                request.DefaultExecTTL,
		ReceivedAt:         now,
		ExpiresAt:          now.Add(request.DefaultExecTTL),
	}
}

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
	if _, err := roundTripResponse[protocol.StatusPayload](
		ctx,
		client,
		protocol.TypeDaemonStatus,
		protocol.Correlation{},
		nil,
		false,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled round trip, got %v", err)
	}
}

func TestConnectReportsMissingSocketAfterDefaultTrustSetup(t *testing.T) {
	t.Parallel()

	_, err := Connect(context.Background(), filepath.Join(t.TempDir(), "missing.sock"))
	if !errors.Is(err, socket.ErrDaemonUnavailable) {
		t.Fatalf("Connect error = %v, want %v", err, socket.ErrDaemonUnavailable)
	}
}

func TestClientSetContextDeadlineHandlesInactiveContexts(t *testing.T) {
	t.Parallel()

	client := &Client{}
	called := false
	if err := client.setContextDeadline(context.Background(), func(time.Time) error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("setContextDeadline without deadline returned error: %v", err)
	}
	if called {
		t.Fatal("setContextDeadline called setter without a context deadline")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := client.setContextDeadline(ctx, func(time.Time) error {
		t.Fatal("setContextDeadline called setter after context cancellation")
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("setContextDeadline error = %v, want %v", err, context.Canceled)
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

	ctx := newManualDoneContext(context.DeadlineExceeded)
	errc := make(chan error, 1)
	go func() {
		_, err := client.Status(ctx)
		errc <- err
	}()

	env := receiveStalledRequest(t, requests)
	if env.Type != protocol.TypeDaemonStatus {
		t.Fatalf("request type = %s, want %s", env.Type, protocol.TypeDaemonStatus)
	}

	ctx.finish()
	err := receiveRoundTripError(t, errc)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline exceeded error, got %v", err)
	}
}

func TestClientContextWithDefaultDeadlineUsesDefaultTimeout(t *testing.T) {
	t.Parallel()

	client := &Client{DefaultTimeout: time.Minute}
	startedAt := time.Now()
	ctx, cancel := client.contextWithDefaultDeadline(context.Background(), protocol.TypeDaemonStatus, nil)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("contextWithDefaultDeadline did not set a deadline")
	}
	if deadline.Before(startedAt.Add(time.Minute)) || deadline.After(time.Now().Add(time.Minute+time.Second)) {
		t.Fatalf("default deadline = %s, want about one minute from now", deadline)
	}
}

func TestClientRequestExecDefaultDeadlineUsesRequestExpiry(t *testing.T) {
	t.Parallel()

	defaultTimeout := 25 * time.Millisecond
	client := &Client{DefaultTimeout: defaultTimeout}
	req := testExecRequestAt(t, time.Now(), []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token"}})
	ctx, cancel := client.contextWithDefaultDeadline(context.Background(), protocol.TypeRequestExec, req)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("RequestExec context did not receive a deadline")
	}
	want := req.ExpiresAt.Add(defaultTimeout)
	if !deadline.Equal(want) {
		t.Fatalf("RequestExec deadline = %s, want %s", deadline, want)
	}
}

func TestClientRequestExecDefaultDeadlineUsesRequestTTL(t *testing.T) {
	t.Parallel()

	defaultTimeout := 25 * time.Millisecond
	client := &Client{DefaultTimeout: defaultTimeout}
	req := testExecRequestAt(t, time.Now(), []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token"}})
	req.ExpiresAt = time.Time{}
	req.TTL = 2 * time.Minute
	before := time.Now()
	ctx, cancel := client.contextWithDefaultDeadline(context.Background(), protocol.TypeRequestExec, req)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("RequestExec context did not receive a deadline")
	}
	minDeadline := before.Add(req.TTL + defaultTimeout)
	maxDeadline := time.Now().Add(req.TTL + defaultTimeout)
	if deadline.Before(minDeadline) || deadline.After(maxDeadline) {
		t.Fatalf("RequestExec TTL deadline = %s, want between %s and %s", deadline, minDeadline, maxDeadline)
	}
}

func TestClientKeepsCallerDeadline(t *testing.T) {
	t.Parallel()

	client := &Client{DefaultTimeout: time.Hour}
	wantDeadline := time.Now().Add(50 * time.Millisecond)
	callerCtx, cancel := context.WithDeadline(context.Background(), wantDeadline)
	defer cancel()

	ctx, returnedCancel := client.contextWithDefaultDeadline(callerCtx, protocol.TypeDaemonStatus, nil)
	defer returnedCancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("caller deadline was dropped")
	}
	if !deadline.Equal(wantDeadline) {
		t.Fatalf("deadline = %s, want caller deadline %s", deadline, wantDeadline)
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
			wantErr: protocol.ErrInvalidNonce,
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

func TestClientCheckOnePasswordUsesDiagnosticsRequest(t *testing.T) {
	t.Parallel()

	requests := make(chan protocol.Envelope, 1)
	client, cleanup := startRespondingDaemonClient(t, func(env protocol.Envelope) []byte {
		requests <- env
		return emptyOKResponseFrame(t, env)
	})
	defer cleanup()

	if err := client.CheckOnePassword(context.Background()); err != nil {
		t.Fatalf("CheckOnePassword returned error: %v", err)
	}
	env := receiveStalledRequest(t, requests)
	if env.Type != protocol.TypeOnePasswordStatus {
		t.Fatalf("request type = %s, want %s", env.Type, protocol.TypeOnePasswordStatus)
	}
	if len(env.Payload) != 0 {
		t.Fatalf("onepassword status payload = %s, want empty", env.Payload)
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

	err := (daemon.SameUIDValidator{}).Validate(&net.UnixConn{})
	if err == nil {
		t.Fatal("expected invalid unix connection error")
	}
}

func startRespondingDaemonClient(t *testing.T, response func(protocol.Envelope) []byte) (*Client, func()) {
	t.Helper()

	serverConn, clientConn := unixsocket.Pair(t)
	serverDone := make(chan error, 1)
	go func() {
		defer func() { _ = serverConn.Close() }()

		var env protocol.Envelope
		if err := json.NewDecoder(serverConn).Decode(&env); err != nil {
			serverDone <- err
			return
		}
		_, err := serverConn.Write(response(env))
		serverDone <- err
	}()

	client := NewClient(clientConn)

	return client, func() {
		_ = client.Close()
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

	serverConn, clientConn := unixsocket.Pair(t)
	requests := make(chan protocol.Envelope, 1)
	release := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		defer func() { _ = serverConn.Close() }()

		var env protocol.Envelope
		if err := json.NewDecoder(serverConn).Decode(&env); err != nil {
			serverDone <- err
			return
		}
		requests <- env
		<-release
		serverDone <- nil
	}()

	client := NewClient(clientConn)

	return client, requests, func() {
		_ = client.Close()
		close(release)
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

type manualDoneContext struct {
	done     chan struct{}
	err      error
	deadline time.Time
}

func newManualDoneContext(err error) *manualDoneContext {
	return &manualDoneContext{
		done:     make(chan struct{}),
		err:      err,
		deadline: time.Now().Add(time.Hour),
	}
}

func (c *manualDoneContext) Done() <-chan struct{} {
	return c.done
}

func (c *manualDoneContext) Err() error {
	select {
	case <-c.done:
		return c.err
	default:
		return nil
	}
}

func (c *manualDoneContext) Deadline() (time.Time, bool) {
	return c.deadline, true
}

func (c *manualDoneContext) Value(any) any {
	return nil
}

func (c *manualDoneContext) finish() {
	close(c.done)
}
