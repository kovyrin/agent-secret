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
	"github.com/kovyrin/agent-secret/internal/itemmetadata"
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
		if spec.Account == "" {
			spec.Account = "Work"
		}
		ref, err := request.ParseSecretRef(spec.Ref)
		if err != nil {
			t.Fatalf("ParseSecretRef returned error: %v", err)
		}
		reqSecrets = append(reqSecrets, request.Secret{Alias: spec.Alias, Ref: ref, Account: spec.Account})
	}

	return request.ExecRequest{
		Reason:                 "Run Terraform plan",
		Command:                []string{"terraform", "plan"},
		ResolvedExecutable:     "/opt/homebrew/bin/terraform",
		ExecutableIdentity:     fileidentity.Identity{Device: 1, Inode: 1, Mode: 0o755},
		AllowMutableExecutable: true,
		CWD:                    "/tmp/project",
		Secrets:                reqSecrets,
		TTL:                    request.DefaultExecTTL,
		ReceivedAt:             now,
		ExpiresAt:              now.Add(request.DefaultExecTTL),
	}
}

func testItemDescribeRequestAt(now time.Time) request.ItemDescribeRequest {
	return request.ItemDescribeRequest{
		Reason:             "Inspect item metadata",
		Command:            []string{"agent-secret", "item", "describe", "op://Example/Item"},
		ResolvedExecutable: "/opt/homebrew/bin/agent-secret",
		CWD:                "/tmp/project",
		Ref: itemmetadata.Ref{
			Raw:   "op://Example/Item",
			Vault: "Example",
			Item:  "Item",
		},
		Account:    "Work",
		TTL:        request.DefaultItemDescribeTTL,
		ReceivedAt: now,
		ExpiresAt:  now.Add(request.DefaultItemDescribeTTL),
	}
}

func testSessionCreateRequestAt(t *testing.T, now time.Time) request.SessionCreateRequest {
	t.Helper()

	req, err := request.NewSessionCreate(request.SessionCreateOptions{
		Reason:             "Deploy workflow",
		Command:            []string{"agent-secret", "session", "create"},
		ResolvedExecutable: "/opt/homebrew/bin/agent-secret",
		ExecutableIdentity: fileidentity.Identity{Device: 1, Inode: 1, Mode: 0o755},
		CWD:                "/tmp/project",
		ReceivedAt:         now,
		MaxReads:           2,
		Secrets: []request.SecretSpec{
			{Alias: "TOKEN", Ref: "op://Example/Item/token", Account: "Work"},
		},
	})
	if err != nil {
		t.Fatalf("NewSessionCreate returned error: %v", err)
	}
	return req
}

func testSessionResolveRequest(t *testing.T) request.SessionResolveRequest {
	t.Helper()

	req, err := request.NewSessionResolve(
		"astok_abc123",
		[]string{"/opt/homebrew/bin/terraform", "plan"},
		"/opt/homebrew/bin/terraform",
		fileidentity.Identity{Device: 2, Inode: 2, Mode: 0o755},
		"/tmp/project",
		request.EnvironmentFingerprint([]string{"PATH=/opt/homebrew/bin"}),
	)
	if err != nil {
		t.Fatalf("NewSessionResolve returned error: %v", err)
	}
	return req
}

func testGCPExecRequestAt(now time.Time) request.GCPExecRequest {
	return request.GCPExecRequest{
		Reason:                 "Inspect logs",
		Command:                []string{"gcloud", "logging", "read", "severity>=ERROR"},
		ResolvedExecutable:     "/opt/homebrew/bin/gcloud",
		ExecutableIdentity:     fileidentity.Identity{Device: 1, Inode: 2, Mode: 0o755},
		CWD:                    "/tmp/project",
		EnvironmentFingerprint: request.EnvironmentFingerprint([]string{"PATH=/opt/homebrew/bin"}),
		GoogleAccount:          "work",
		Project:                "fixture-beta",
		ServiceAccount:         "agent-beta@fixture-beta.iam.gserviceaccount.com",
		Scopes:                 []string{"https://www.googleapis.com/auth/cloud-platform"},
		DeliveryMode:           request.GCPDeliveryModeTokenFile,
		TTL:                    2 * time.Minute,
		ReceivedAt:             now,
		ExpiresAt:              now.Add(2 * time.Minute),
	}
}

func testGCPSessionCreateRequestAt(now time.Time) request.GCPSessionCreateRequest {
	return request.GCPSessionCreateRequest{
		Reason:           "Run benchmark",
		GoogleAccount:    "work",
		Project:          "fixture-beta",
		ServiceAccount:   "agent-beta@fixture-beta.iam.gserviceaccount.com",
		Scopes:           []string{"https://www.googleapis.com/auth/cloud-platform"},
		ProfileName:      "beta-benchmark",
		ConfigSourcePath: "/tmp/project/agent-secret.yml",
		ProjectRoot:      "/tmp/project",
		DeliveryMode:     request.GCPDeliveryModeTokenFile,
		TTL:              30 * time.Minute,
		ReceivedAt:       now,
		ExpiresAt:        now.Add(30 * time.Minute),
		MaxCommandStarts: 12,
	}
}

func testGCPSessionUseRequest() request.GCPSessionUseRequest {
	return request.GCPSessionUseRequest{
		SessionHandle:          "asess_123",
		Command:                []string{"gcloud", "compute", "instances", "list"},
		ResolvedExecutable:     "/opt/homebrew/bin/gcloud",
		ExecutableIdentity:     fileidentity.Identity{Device: 1, Inode: 2, Mode: 0o755},
		CWD:                    "/tmp/project",
		EnvironmentFingerprint: request.EnvironmentFingerprint([]string{"PATH=/opt/homebrew/bin"}),
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

func TestClientRequestItemDescribeDefaultDeadlineUsesRequestExpiry(t *testing.T) {
	t.Parallel()

	defaultTimeout := 25 * time.Millisecond
	client := &Client{DefaultTimeout: defaultTimeout}
	req := testItemDescribeRequestAt(time.Now())
	ctx, cancel := client.contextWithDefaultDeadline(context.Background(), protocol.TypeItemDescribe, req)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("DescribeItem context did not receive a deadline")
	}
	want := req.ExpiresAt.Add(defaultTimeout)
	if !deadline.Equal(want) {
		t.Fatalf("DescribeItem deadline = %s, want %s", deadline, want)
	}
}

func TestClientGCPDefaultDeadlinesUseRequestExpiry(t *testing.T) {
	t.Parallel()

	defaultTimeout := 25 * time.Millisecond
	client := &Client{DefaultTimeout: defaultTimeout}
	now := time.Now()
	execReq := testGCPExecRequestAt(now)
	ctx, cancel := client.contextWithDefaultDeadline(context.Background(), protocol.TypeGCPExec, execReq)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("GCP exec context did not receive a deadline")
	}
	if want := execReq.ExpiresAt.Add(defaultTimeout); !deadline.Equal(want) {
		t.Fatalf("GCP exec deadline = %s, want %s", deadline, want)
	}

	sessionReq := testGCPSessionCreateRequestAt(now)
	ctx, cancel = client.contextWithDefaultDeadline(context.Background(), protocol.TypeGCPSessionCreate, gcpSessionCreateClientPayload{Request: sessionReq, Handle: "asess_123"})
	defer cancel()
	deadline, ok = ctx.Deadline()
	if !ok {
		t.Fatal("GCP session create context did not receive a deadline")
	}
	if want := sessionReq.ExpiresAt.Add(defaultTimeout); !deadline.Equal(want) {
		t.Fatalf("GCP session create deadline = %s, want %s", deadline, want)
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
	sessionCreateReq := testSessionCreateRequestAt(t, time.Now())
	sessionResolveReq := testSessionResolveRequest(t)
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
			name: "helper hello executable",
			frame: func(t *testing.T, env protocol.Envelope) []byte {
				t.Helper()

				return okResponseFrame(t, env, protocol.HelperHelloPayload{
					Protocol:   protocol.ProtocolVersion,
					AppVersion: "dev",
					PID:        1234,
				})
			},
			call: func(ctx context.Context, client *Client) error {
				_, err := client.Hello(ctx)
				return err
			},
			wantErrMsg: "missing executable",
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
		{
			name: "session create id",
			frame: func(t *testing.T, env protocol.Envelope) []byte {
				t.Helper()

				return okResponseFrame(t, env, protocol.SessionCreateResponsePayload{
					SessionID:      "bad",
					SessionToken:   "astok_abc123",
					SecretAliases:  []string{"TOKEN"},
					MaxReads:       sessionCreateReq.MaxReads,
					RemainingReads: sessionCreateReq.MaxReads,
				})
			},
			call: func(ctx context.Context, client *Client) error {
				_, err := client.CreateSession(ctx, testCorrelation("req_1", "nonce_1"), sessionCreateReq)
				return err
			},
			wantErrMsg: "invalid session id",
		},
		{
			name: "session create token",
			frame: func(t *testing.T, env protocol.Envelope) []byte {
				t.Helper()

				return okResponseFrame(t, env, protocol.SessionCreateResponsePayload{
					SessionID:      "asid_abc123",
					SessionToken:   "bad",
					SecretAliases:  []string{"TOKEN"},
					MaxReads:       sessionCreateReq.MaxReads,
					RemainingReads: sessionCreateReq.MaxReads,
				})
			},
			call: func(ctx context.Context, client *Client) error {
				_, err := client.CreateSession(ctx, testCorrelation("req_1", "nonce_1"), sessionCreateReq)
				return err
			},
			wantErrMsg: "invalid session token",
		},
		{
			name: "session create aliases",
			frame: func(t *testing.T, env protocol.Envelope) []byte {
				t.Helper()

				return okResponseFrame(t, env, protocol.SessionCreateResponsePayload{
					SessionID:      "asid_abc123",
					SessionToken:   "astok_abc123",
					SecretAliases:  []string{"OTHER"},
					MaxReads:       sessionCreateReq.MaxReads,
					RemainingReads: sessionCreateReq.MaxReads,
				})
			},
			call: func(ctx context.Context, client *Client) error {
				_, err := client.CreateSession(ctx, testCorrelation("req_1", "nonce_1"), sessionCreateReq)
				return err
			},
			wantErrMsg: "secret aliases do not match",
		},
		{
			name: "session create reads",
			frame: func(t *testing.T, env protocol.Envelope) []byte {
				t.Helper()

				return okResponseFrame(t, env, protocol.SessionCreateResponsePayload{
					SessionID:      "asid_abc123",
					SessionToken:   "astok_abc123",
					SecretAliases:  []string{"TOKEN"},
					MaxReads:       sessionCreateReq.MaxReads,
					RemainingReads: 1,
				})
			},
			call: func(ctx context.Context, client *Client) error {
				_, err := client.CreateSession(ctx, testCorrelation("req_1", "nonce_1"), sessionCreateReq)
				return err
			},
			wantErrMsg: "remaining reads",
		},
		{
			name: "session resolve env",
			frame: func(t *testing.T, env protocol.Envelope) []byte {
				t.Helper()

				return okResponseFrame(t, env, protocol.SessionResolveResponsePayload{
					Env:           map[string]string{"TOKEN": "value", "OTHER": "value"},
					SecretAliases: []string{"TOKEN"},
				})
			},
			call: func(ctx context.Context, client *Client) error {
				_, err := client.ResolveSession(ctx, testCorrelation("req_1", "nonce_1"), sessionResolveReq)
				return err
			},
			wantErrMsg: "env aliases",
		},
		{
			name: "session resolve missing env",
			frame: func(t *testing.T, env protocol.Envelope) []byte {
				t.Helper()

				return okResponseFrame(t, env, protocol.SessionResolveResponsePayload{
					SecretAliases: []string{"TOKEN"},
				})
			},
			call: func(ctx context.Context, client *Client) error {
				_, err := client.ResolveSession(ctx, testCorrelation("req_1", "nonce_1"), sessionResolveReq)
				return err
			},
			wantErrMsg: "missing env",
		},
		{
			name: "gcp missing token env",
			frame: func(t *testing.T, env protocol.Envelope) []byte {
				t.Helper()

				return okResponseFrame(t, env, protocol.GCPCommandResponsePayload{
					Env: map[string]string{
						"CLOUDSDK_CONFIG":       "/tmp/cloudsdk",
						"CLOUDSDK_CORE_PROJECT": "fixture-beta",
					},
					DeliveryMode: request.GCPDeliveryModeTokenFile,
					ExpiresAt:    time.Now().Add(time.Minute),
				})
			},
			call: func(ctx context.Context, client *Client) error {
				_, err := client.RequestGCPExec(ctx, testCorrelation("req_gcp", "nonce_gcp"), testGCPExecRequestAt(time.Now()))
				return err
			},
			wantErrMsg: "missing CLOUDSDK_AUTH_ACCESS_TOKEN_FILE",
		},
		{
			name: "gcp missing delivery mode",
			frame: func(t *testing.T, env protocol.Envelope) []byte {
				t.Helper()

				return okResponseFrame(t, env, protocol.GCPCommandResponsePayload{
					Env: map[string]string{
						"CLOUDSDK_CONFIG":                 "/tmp/cloudsdk",
						"CLOUDSDK_AUTH_ACCESS_TOKEN_FILE": "/tmp/token",
						"CLOUDSDK_CORE_PROJECT":           "fixture-beta",
					},
					ExpiresAt: time.Now().Add(time.Minute),
				})
			},
			call: func(ctx context.Context, client *Client) error {
				_, err := client.UseGCPSession(ctx, testCorrelation("req_gcp", "nonce_gcp"), testGCPSessionUseRequest())
				return err
			},
			wantErrMsg: "missing delivery mode",
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

func TestClientGCPRoundTripsPayloads(t *testing.T) {
	t.Parallel()

	now := time.Now()
	commandPayload := protocol.GCPCommandResponsePayload{
		Env: map[string]string{
			"CLOUDSDK_CONFIG":                 "/tmp/cloudsdk",
			"CLOUDSDK_AUTH_ACCESS_TOKEN_FILE": "/tmp/token",
			"CLOUDSDK_CORE_PROJECT":           "fixture-beta",
		},
		DeliveryMode: request.GCPDeliveryModeTokenFile,
		ExpiresAt:    now.Add(time.Minute),
	}
	tests := []struct {
		name string
		call func(context.Context, *Client) error
		want protocol.MessageType
	}{
		{
			name: "gcp exec",
			want: protocol.TypeGCPExec,
			call: func(ctx context.Context, client *Client) error {
				payload, err := client.RequestGCPExec(ctx, testCorrelation("req_gcp", "nonce_gcp"), testGCPExecRequestAt(now))
				if err != nil {
					return err
				}
				if payload.Env["CLOUDSDK_CORE_PROJECT"] != "fixture-beta" {
					return errors.New("missing project env")
				}
				return nil
			},
		},
		{
			name: "gcp session create",
			want: protocol.TypeGCPSessionCreate,
			call: func(ctx context.Context, client *Client) error {
				payload, err := client.CreateGCPSession(ctx, testCorrelation("req_create", "nonce_create"), testGCPSessionCreateRequestAt(now), "asess_123")
				if err != nil {
					return err
				}
				if payload.SessionHandle != "asess_123" {
					return errors.New("missing session handle")
				}
				return nil
			},
		},
		{
			name: "gcp session list",
			want: protocol.TypeGCPSessionList,
			call: func(ctx context.Context, client *Client) error {
				payload, err := client.ListGCPSessions(ctx, "/tmp/project")
				if err != nil {
					return err
				}
				if len(payload.Sessions) != 1 {
					return errors.New("missing session list")
				}
				return nil
			},
		},
		{
			name: "gcp session destroy",
			want: protocol.TypeGCPSessionDestroy,
			call: func(ctx context.Context, client *Client) error {
				payload, err := client.DestroyGCPSession(ctx, request.GCPSessionDestroyRequest{SessionHandle: "asess_123", CWD: "/tmp/project"})
				if err != nil {
					return err
				}
				if !payload.Destroyed {
					return errors.New("destroy response not marked destroyed")
				}
				return nil
			},
		},
		{
			name: "gcp with session",
			want: protocol.TypeGCPWithSession,
			call: func(ctx context.Context, client *Client) error {
				payload, err := client.UseGCPSession(ctx, testCorrelation("req_use", "nonce_use"), testGCPSessionUseRequest())
				if err != nil {
					return err
				}
				if payload.DeliveryMode != request.GCPDeliveryModeTokenFile {
					return errors.New("missing delivery mode")
				}
				return nil
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			requests := make(chan protocol.Envelope, 1)
			client, cleanup := startRespondingDaemonClient(t, func(env protocol.Envelope) []byte {
				requests <- env
				//nolint:exhaustive // This test table covers only GCP client request types.
				switch env.Type {
				case protocol.TypeGCPExec, protocol.TypeGCPWithSession:
					return okResponseFrame(t, env, commandPayload)
				case protocol.TypeGCPSessionCreate:
					return okResponseFrame(t, env, protocol.GCPSessionCreateResponsePayload{
						SessionHandle:          "asess_123",
						SessionAuditID:         "asess_123:deadbeef",
						ExpiresAt:              now.Add(30 * time.Minute),
						RemainingCommandStarts: 12,
					})
				case protocol.TypeGCPSessionList:
					return okResponseFrame(t, env, protocol.GCPSessionListResponsePayload{
						Sessions: []protocol.GCPSessionInfo{{SessionAuditID: "asess_123:deadbeef"}},
					})
				case protocol.TypeGCPSessionDestroy:
					return okResponseFrame(t, env, protocol.GCPSessionDestroyResponsePayload{
						Destroyed:      true,
						SessionAuditID: "asess_123:deadbeef",
					})
				default:
					t.Fatalf("unexpected request type %s", env.Type)
				}
				return nil
			})
			defer cleanup()

			if err := tc.call(context.Background(), client); err != nil {
				t.Fatalf("%s returned error: %v", tc.name, err)
			}
			env := receiveStalledRequest(t, requests)
			if env.Type != tc.want {
				t.Fatalf("request type = %s, want %s", env.Type, tc.want)
			}
		})
	}
}

func TestClientDescribeItemRoundTripsPayload(t *testing.T) {
	t.Parallel()

	req := testItemDescribeRequestAt(time.Now())
	requests := make(chan protocol.Envelope, 1)
	client, cleanup := startRespondingDaemonClient(t, func(env protocol.Envelope) []byte {
		requests <- env
		return okResponseFrame(t, env, protocol.ItemDescribeResponsePayload{
			Item: itemmetadata.Metadata{
				Account: "Work",
				Vault:   "Example",
				Item:    "Item",
				Fields: []itemmetadata.Field{
					{Label: "token", Ref: "op://Example/Item/token"},
				},
			},
		})
	})
	defer cleanup()

	payload, err := client.DescribeItem(context.Background(), testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("DescribeItem returned error: %v", err)
	}
	if payload.Item.Account != "Work" || payload.Item.Item != "Item" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	env := receiveStalledRequest(t, requests)
	if env.Type != protocol.TypeItemDescribe {
		t.Fatalf("request type = %s, want %s", env.Type, protocol.TypeItemDescribe)
	}
	got, err := protocol.DecodeRequiredPayload[request.ItemDescribeRequest](env)
	if err != nil {
		t.Fatalf("decode item describe request: %v", err)
	}
	if got.Ref.Raw != req.Ref.Raw || got.Account != req.Account {
		t.Fatalf("unexpected item describe request: %+v", got)
	}
}

func TestClientSessionCreateAndResolveRoundTripsPayloads(t *testing.T) {
	t.Parallel()

	t.Run("create", func(t *testing.T) {
		t.Parallel()

		req := testSessionCreateRequestAt(t, time.Now())
		requests := make(chan protocol.Envelope, 1)
		client, cleanup := startRespondingDaemonClient(t, func(env protocol.Envelope) []byte {
			requests <- env
			return okResponseFrame(t, env, protocol.SessionCreateResponsePayload{
				SessionID:      "asid_abc123",
				SessionToken:   "astok_abc123",
				SecretAliases:  []string{"TOKEN"},
				ExpiresAt:      req.ExpiresAt,
				MaxReads:       2,
				RemainingReads: 2,
			})
		})
		defer cleanup()

		payload, err := client.CreateSession(context.Background(), testCorrelation("req_1", "nonce_1"), req)
		if err != nil {
			t.Fatalf("CreateSession returned error: %v", err)
		}
		if payload.SessionID != "asid_abc123" || payload.SessionToken != "astok_abc123" || payload.RemainingReads != 2 {
			t.Fatalf("unexpected create payload: %+v", payload)
		}
		env := receiveStalledRequest(t, requests)
		if env.Type != protocol.TypeSessionCreate {
			t.Fatalf("request type = %s, want %s", env.Type, protocol.TypeSessionCreate)
		}
		got, err := protocol.DecodeRequiredPayload[request.SessionCreateRequest](env)
		if err != nil {
			t.Fatalf("decode session create request: %v", err)
		}
		if got.Reason != req.Reason || got.MaxReads != req.MaxReads {
			t.Fatalf("unexpected session create request: %+v", got)
		}
	})

	t.Run("resolve", func(t *testing.T) {
		t.Parallel()

		req := testSessionResolveRequest(t)
		req, err := req.WithRequestedAliases([]string{"TOKEN"})
		if err != nil {
			t.Fatalf("WithRequestedAliases returned error: %v", err)
		}
		requests := make(chan protocol.Envelope, 1)
		client, cleanup := startRespondingDaemonClient(t, func(env protocol.Envelope) []byte {
			requests <- env
			return okResponseFrame(t, env, protocol.SessionResolveResponsePayload{
				Env:           map[string]string{"TOKEN": "synthetic-secret-value"},
				SecretAliases: []string{"TOKEN"},
				OverrideEnv:   true,
			})
		})
		defer cleanup()

		payload, err := client.ResolveSession(context.Background(), testCorrelation("req_1", "nonce_1"), req)
		if err != nil {
			t.Fatalf("ResolveSession returned error: %v", err)
		}
		if payload.Env["TOKEN"] == "" || !payload.OverrideEnv {
			t.Fatalf("unexpected resolve payload: %+v", payload)
		}
		env := receiveStalledRequest(t, requests)
		if env.Type != protocol.TypeSessionResolve {
			t.Fatalf("request type = %s, want %s", env.Type, protocol.TypeSessionResolve)
		}
		got, err := protocol.DecodeRequiredPayload[request.SessionResolveRequest](env)
		if err != nil {
			t.Fatalf("decode session resolve request: %v", err)
		}
		if got.SessionToken != req.SessionToken || got.CWD != req.CWD {
			t.Fatalf("unexpected session resolve request: %+v", got)
		}
		if len(got.RequestedAliases) != 1 || got.RequestedAliases[0] != "TOKEN" {
			t.Fatalf("requested aliases = %v, want TOKEN", got.RequestedAliases)
		}
	})

	t.Run("resolve rejects wrong projected aliases", func(t *testing.T) {
		t.Parallel()

		req := testSessionResolveRequest(t)
		req, err := req.WithRequestedAliases([]string{"TOKEN"})
		if err != nil {
			t.Fatalf("WithRequestedAliases returned error: %v", err)
		}
		client, cleanup := startRespondingDaemonClient(t, func(env protocol.Envelope) []byte {
			return okResponseFrame(t, env, protocol.SessionResolveResponsePayload{
				Env:           map[string]string{"OTHER_TOKEN": "synthetic-secret-value"},
				SecretAliases: []string{"OTHER_TOKEN"},
			})
		})
		defer cleanup()

		if _, err := client.ResolveSession(context.Background(), testCorrelation("req_1", "nonce_1"), req); !errors.Is(err, protocol.ErrMalformedEnvelope) {
			t.Fatalf("ResolveSession error = %v, want ErrMalformedEnvelope", err)
		}
	})
}

func TestClientSessionManagementRoundTripsPayloads(t *testing.T) {
	t.Parallel()

	t.Run("destroy", func(t *testing.T) {
		t.Parallel()

		req := request.SessionDestroyRequest{SessionID: "asid_abc123"}
		requests := make(chan protocol.Envelope, 1)
		client, cleanup := startRespondingDaemonClient(t, func(env protocol.Envelope) []byte {
			requests <- env
			return okResponseFrame(t, env, protocol.SessionDestroyResponsePayload{
				SessionID: "asid_abc123",
				Destroyed: true,
			})
		})
		defer cleanup()

		payload, err := client.DestroySession(context.Background(), req)
		if err != nil {
			t.Fatalf("DestroySession returned error: %v", err)
		}
		if !payload.Destroyed {
			t.Fatalf("unexpected destroy payload: %+v", payload)
		}
		env := receiveStalledRequest(t, requests)
		if env.Type != protocol.TypeSessionDestroy {
			t.Fatalf("request type = %s, want %s", env.Type, protocol.TypeSessionDestroy)
		}
	})

	t.Run("destroy all", func(t *testing.T) {
		t.Parallel()

		req := request.NewSessionDestroyAll()
		requests := make(chan protocol.Envelope, 1)
		client, cleanup := startRespondingDaemonClient(t, func(env protocol.Envelope) []byte {
			requests <- env
			return okResponseFrame(t, env, protocol.SessionDestroyResponsePayload{
				Destroyed:      true,
				DestroyedCount: 2,
			})
		})
		defer cleanup()

		payload, err := client.DestroySession(context.Background(), req)
		if err != nil {
			t.Fatalf("DestroySession --all returned error: %v", err)
		}
		if !payload.Destroyed || payload.DestroyedCount != 2 {
			t.Fatalf("unexpected destroy all payload: %+v", payload)
		}
		env := receiveStalledRequest(t, requests)
		if env.Type != protocol.TypeSessionDestroy {
			t.Fatalf("request type = %s, want %s", env.Type, protocol.TypeSessionDestroy)
		}
	})

	t.Run("list", func(t *testing.T) {
		t.Parallel()

		requests := make(chan protocol.Envelope, 1)
		client, cleanup := startRespondingDaemonClient(t, func(env protocol.Envelope) []byte {
			requests <- env
			return okResponseFrame(t, env, protocol.SessionListResponsePayload{
				Sessions: []protocol.SessionInfoPayload{{
					SessionID:      "asid_abc123",
					Reason:         "Deploy workflow",
					CWD:            "/tmp/project",
					SecretAliases:  []string{"TOKEN"},
					ExpiresAt:      time.Now().Add(time.Minute),
					MaxReads:       2,
					RemainingReads: 1,
				}},
			})
		})
		defer cleanup()

		payload, err := client.ListSessions(context.Background())
		if err != nil {
			t.Fatalf("ListSessions returned error: %v", err)
		}
		if len(payload.Sessions) != 1 || payload.Sessions[0].RemainingReads != 1 {
			t.Fatalf("unexpected list payload: %+v", payload)
		}
		env := receiveStalledRequest(t, requests)
		if env.Type != protocol.TypeSessionList {
			t.Fatalf("request type = %s, want %s", env.Type, protocol.TypeSessionList)
		}
	})
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

	if err := client.CheckOnePassword(context.Background(), "my.1password.ca"); err != nil {
		t.Fatalf("CheckOnePassword returned error: %v", err)
	}
	env := receiveStalledRequest(t, requests)
	if env.Type != protocol.TypeOnePasswordStatus {
		t.Fatalf("request type = %s, want %s", env.Type, protocol.TypeOnePasswordStatus)
	}
	payload, err := protocol.DecodeRequiredPayload[protocol.OnePasswordStatusPayload](env)
	if err != nil {
		t.Fatalf("decode onepassword status payload: %v", err)
	}
	if payload.Account != "my.1password.ca" {
		t.Fatalf("onepassword status account = %q, want my.1password.ca", payload.Account)
	}
}

func TestClientRequestStopUsesDaemonStopRequest(t *testing.T) {
	t.Parallel()

	requests := make(chan protocol.Envelope, 1)
	client, cleanup := startRespondingDaemonClient(t, func(env protocol.Envelope) []byte {
		requests <- env
		return okResponseFrame(t, env, protocol.StatusPayload{PID: 4321})
	})
	defer cleanup()

	payload, err := client.RequestStop(context.Background())
	if err != nil {
		t.Fatalf("RequestStop returned error: %v", err)
	}
	if payload.PID != 4321 {
		t.Fatalf("RequestStop PID = %d, want 4321", payload.PID)
	}
	env := receiveStalledRequest(t, requests)
	if env.Type != protocol.TypeDaemonStop {
		t.Fatalf("request type = %s, want %s", env.Type, protocol.TypeDaemonStop)
	}
	if len(env.Payload) != 0 {
		t.Fatalf("daemon stop payload = %s, want empty", env.Payload)
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
