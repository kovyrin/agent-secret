package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/kovyrin/agent-secret/internal/daemon/peertrust"
	daemonprocess "github.com/kovyrin/agent-secret/internal/daemon/process"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/daemon/socket"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/request"
)

type ProtocolError struct {
	Code    protocol.ErrorCode
	Message string
}

func (e *ProtocolError) Error() string {
	return string(e.Code) + ": " + e.Message
}

type Client struct {
	conn           *net.UnixConn
	encoder        *json.Encoder
	reader         *bufio.Reader
	DefaultTimeout time.Duration
}

const DefaultClientProtocolTimeout = 30 * time.Second

func Connect(ctx context.Context, path string) (*Client, error) {
	trustedPaths, err := defaultTrustedDaemonPaths()
	if err != nil {
		return nil, err
	}
	return ConnectWithPeerValidator(ctx, path, peertrust.NewDaemonValidator(trustedPaths))
}

func ConnectWithPeerValidator(ctx context.Context, path string, validator peertrust.DaemonPeerValidator) (*Client, error) {
	conn, err := socket.Dial(ctx, path)
	if err != nil {
		return nil, err
	}
	if err := validateDaemonPeer(conn, validator); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return NewClient(conn), nil
}

func validateDaemonPeer(conn *net.UnixConn, validator peertrust.DaemonPeerValidator) error {
	if validator == nil {
		return nil
	}
	info, err := peercred.Inspect(conn)
	if err != nil {
		return fmt.Errorf("%w: inspect daemon peer: %w", peertrust.ErrUntrustedDaemon, err)
	}
	return validator.ValidateDaemonPeer(info)
}

func defaultTrustedDaemonPaths() ([]string, error) {
	daemonPath, err := daemonprocess.DefaultDaemonPath()
	if err != nil {
		return nil, err
	}
	return peertrust.DaemonPathsForPath(daemonPath)
}

func NewClient(conn *net.UnixConn) *Client {
	return &Client{
		conn:           conn,
		encoder:        json.NewEncoder(conn),
		reader:         bufio.NewReader(conn),
		DefaultTimeout: DefaultClientProtocolTimeout,
	}
}

func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *Client) Status(ctx context.Context) (protocol.StatusPayload, error) {
	payload, err := roundTripPayload[protocol.StatusPayload](ctx, c, protocol.TypeDaemonStatus, protocol.Correlation{}, nil)
	if err != nil {
		return protocol.StatusPayload{}, err
	}
	if err := validateStatusPayload(protocol.TypeDaemonStatus, payload); err != nil {
		return protocol.StatusPayload{}, err
	}
	return payload, nil
}

func (c *Client) Hello(ctx context.Context) (protocol.HelperHelloPayload, error) {
	payload, err := roundTripPayload[protocol.HelperHelloPayload](ctx, c, protocol.TypeHelperHello, protocol.Correlation{}, nil)
	if err != nil {
		return protocol.HelperHelloPayload{}, err
	}
	if err := validateHelperHelloPayload(payload); err != nil {
		return protocol.HelperHelloPayload{}, err
	}
	return payload, nil
}

func (c *Client) RequestStop(ctx context.Context) (protocol.StatusPayload, error) {
	payload, err := roundTripPayload[protocol.StatusPayload](ctx, c, protocol.TypeDaemonStop, protocol.Correlation{}, nil)
	if err != nil {
		return protocol.StatusPayload{}, err
	}
	if err := validateStatusPayload(protocol.TypeDaemonStop, payload); err != nil {
		return protocol.StatusPayload{}, err
	}
	return payload, nil
}

func (c *Client) CheckOnePassword(ctx context.Context, account string) error {
	payload := protocol.OnePasswordStatusPayload{Account: account}
	return roundTripAck(ctx, c, protocol.TypeOnePasswordStatus, protocol.Correlation{}, payload)
}

func (c *Client) RequestExec(
	ctx context.Context,
	correlation protocol.Correlation,
	req request.ExecRequest,
) (protocol.ExecResponsePayload, error) {
	payload, err := roundTripPayload[protocol.ExecResponsePayload](ctx, c, protocol.TypeRequestExec, correlation, req)
	if err != nil {
		return protocol.ExecResponsePayload{}, err
	}
	if err := validateExecResponsePayload(payload, req); err != nil {
		return protocol.ExecResponsePayload{}, err
	}
	return payload, nil
}

type gcpSessionCreateClientPayload struct {
	Request request.GCPSessionCreateRequest `json:"request"`
	Handle  string                          `json:"handle"`
}

type gcpSessionListClientPayload struct {
	CWD string `json:"cwd"`
}

func (c *Client) RequestGCPExec(
	ctx context.Context,
	correlation protocol.Correlation,
	req request.GCPExecRequest,
) (protocol.GCPCommandResponsePayload, error) {
	payload, err := roundTripPayload[protocol.GCPCommandResponsePayload](ctx, c, protocol.TypeGCPExec, correlation, req)
	if err != nil {
		return protocol.GCPCommandResponsePayload{}, err
	}
	if err := validateGCPCommandResponsePayload(payload); err != nil {
		return protocol.GCPCommandResponsePayload{}, err
	}
	return payload, nil
}

func (c *Client) CreateGCPSession(
	ctx context.Context,
	correlation protocol.Correlation,
	req request.GCPSessionCreateRequest,
	handle string,
) (protocol.GCPSessionCreateResponsePayload, error) {
	return roundTripPayload[protocol.GCPSessionCreateResponsePayload](
		ctx,
		c,
		protocol.TypeGCPSessionCreate,
		correlation,
		gcpSessionCreateClientPayload{Request: req, Handle: handle},
	)
}

func (c *Client) ListGCPSessions(ctx context.Context, cwd string) (protocol.GCPSessionListResponsePayload, error) {
	return roundTripPayload[protocol.GCPSessionListResponsePayload](
		ctx,
		c,
		protocol.TypeGCPSessionList,
		protocol.Correlation{},
		gcpSessionListClientPayload{CWD: cwd},
	)
}

func (c *Client) DestroyGCPSession(
	ctx context.Context,
	req request.GCPSessionDestroyRequest,
) (protocol.GCPSessionDestroyResponsePayload, error) {
	return roundTripPayload[protocol.GCPSessionDestroyResponsePayload](
		ctx,
		c,
		protocol.TypeGCPSessionDestroy,
		protocol.Correlation{},
		req,
	)
}

func (c *Client) UseGCPSession(
	ctx context.Context,
	correlation protocol.Correlation,
	req request.GCPSessionUseRequest,
) (protocol.GCPCommandResponsePayload, error) {
	payload, err := roundTripPayload[protocol.GCPCommandResponsePayload](ctx, c, protocol.TypeGCPWithSession, correlation, req)
	if err != nil {
		return protocol.GCPCommandResponsePayload{}, err
	}
	if err := validateGCPCommandResponsePayload(payload); err != nil {
		return protocol.GCPCommandResponsePayload{}, err
	}
	return payload, nil
}

func (c *Client) DescribeItem(
	ctx context.Context,
	correlation protocol.Correlation,
	req request.ItemDescribeRequest,
) (protocol.ItemDescribeResponsePayload, error) {
	payload, err := roundTripPayload[protocol.ItemDescribeResponsePayload](ctx, c, protocol.TypeItemDescribe, correlation, req)
	if err != nil {
		return protocol.ItemDescribeResponsePayload{}, err
	}
	if payload.Item.Item == "" || payload.Item.Vault == "" {
		return protocol.ItemDescribeResponsePayload{}, fmt.Errorf("%w: item.describe response missing item metadata", protocol.ErrMalformedEnvelope)
	}
	return payload, nil
}

func (c *Client) CreateSession(
	ctx context.Context,
	correlation protocol.Correlation,
	req request.SessionCreateRequest,
) (protocol.SessionCreateResponsePayload, error) {
	payload, err := roundTripPayload[protocol.SessionCreateResponsePayload](ctx, c, protocol.TypeSessionCreate, correlation, req)
	if err != nil {
		return protocol.SessionCreateResponsePayload{}, err
	}
	if err := validateSessionCreateResponsePayload(payload, req); err != nil {
		return protocol.SessionCreateResponsePayload{}, err
	}
	return payload, nil
}

func (c *Client) ResolveSession(
	ctx context.Context,
	correlation protocol.Correlation,
	req request.SessionResolveRequest,
) (protocol.SessionResolveResponsePayload, error) {
	payload, err := roundTripPayload[protocol.SessionResolveResponsePayload](ctx, c, protocol.TypeSessionResolve, correlation, req)
	if err != nil {
		return protocol.SessionResolveResponsePayload{}, err
	}
	if err := validateSessionResolveResponsePayload(payload, req); err != nil {
		return protocol.SessionResolveResponsePayload{}, err
	}
	return payload, nil
}

func (c *Client) DestroySession(ctx context.Context, req request.SessionDestroyRequest) (protocol.SessionDestroyResponsePayload, error) {
	payload, err := roundTripPayload[protocol.SessionDestroyResponsePayload](ctx, c, protocol.TypeSessionDestroy, protocol.Correlation{}, req)
	if err != nil {
		return protocol.SessionDestroyResponsePayload{}, err
	}
	if req.All {
		if !payload.Destroyed || payload.SessionID != "" {
			return protocol.SessionDestroyResponsePayload{}, fmt.Errorf("%w: session.destroy --all response does not match request", protocol.ErrMalformedEnvelope)
		}
		return payload, nil
	}
	if payload.SessionID != req.SessionID || !payload.Destroyed {
		return protocol.SessionDestroyResponsePayload{}, fmt.Errorf("%w: session.destroy response does not match request", protocol.ErrMalformedEnvelope)
	}
	return payload, nil
}

func (c *Client) ListSessions(ctx context.Context) (protocol.SessionListResponsePayload, error) {
	return roundTripPayload[protocol.SessionListResponsePayload](ctx, c, protocol.TypeSessionList, protocol.Correlation{}, nil)
}

func (c *Client) ReportStarted(ctx context.Context, correlation protocol.Correlation, childPID int) error {
	return roundTripAck(ctx, c, protocol.TypeCommandStarted, correlation, protocol.CommandStartedPayload{ChildPID: childPID})
}

func (c *Client) ReportCompleted(
	ctx context.Context,
	correlation protocol.Correlation,
	exitCode int,
	signal string,
) error {
	return roundTripAck(ctx, c, protocol.TypeCommandCompleted, correlation, protocol.CommandCompletedPayload{
		ExitCode: exitCode,
		Signal:   signal,
	})
}

func roundTripPayload[T any](
	ctx context.Context,
	c *Client,
	messageType protocol.MessageType,
	correlation protocol.Correlation,
	payload any,
) (T, error) {
	return roundTripResponse[T](ctx, c, messageType, correlation, payload, true)
}

func roundTripAck(
	ctx context.Context,
	c *Client,
	messageType protocol.MessageType,
	correlation protocol.Correlation,
	payload any,
) error {
	_, err := roundTripResponse[struct{}](ctx, c, messageType, correlation, payload, false)
	return err
}

func roundTripResponse[T any](
	ctx context.Context,
	c *Client,
	messageType protocol.MessageType,
	correlation protocol.Correlation,
	payload any,
	requirePayload bool,
) (T, error) {
	var zero T
	ctx, cancel := c.contextWithDefaultDeadline(ctx, messageType, payload)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("daemon request canceled: %w", err)
	}
	env, err := protocol.NewEnvelope(messageType, correlation, payload)
	if err != nil {
		return zero, err
	}
	stopCancelWatch := c.closeOnContextCancel(ctx)
	defer stopCancelWatch()
	defer c.clearDeadlines()

	if err := c.setWriteDeadline(ctx); err != nil {
		return zero, fmt.Errorf("set daemon write deadline %s: %w", messageType, err)
	}
	if err := c.encoder.Encode(env); err != nil {
		if ctxErr := contextErrorAfterIOError(ctx, err); ctxErr != nil {
			return zero, fmt.Errorf("daemon request canceled: %w", ctxErr)
		}
		return zero, fmt.Errorf("send daemon message %s: %w", messageType, err)
	}

	if err := c.setReadDeadline(ctx); err != nil {
		return zero, fmt.Errorf("set daemon read deadline %s: %w", messageType, err)
	}
	resp, err := c.readEnvelope()
	if err != nil {
		if ctxErr := contextErrorAfterIOError(ctx, err); ctxErr != nil {
			return zero, fmt.Errorf("daemon request canceled: %w", ctxErr)
		}
		return zero, fmt.Errorf("read daemon response %s: %w", messageType, err)
	}
	if err := protocol.ValidateEnvelope(resp); err != nil {
		return zero, fmt.Errorf("validate daemon response %s: %w", messageType, err)
	}
	if err := validateResponseCorrelation(resp, correlation); err != nil {
		return zero, err
	}
	if resp.Type == protocol.TypeError {
		payload, err := protocol.DecodeRequiredPayload[protocol.ErrorPayload](resp)
		if err != nil {
			return zero, fmt.Errorf("decode daemon error response %s: %w", messageType, err)
		}
		return zero, &ProtocolError{Code: payload.Code, Message: payload.Message}
	}
	if resp.Type != protocol.TypeOK {
		return zero, fmt.Errorf("%w: response type %s", protocol.ErrProtocolType, resp.Type)
	}
	if len(resp.Payload) == 0 {
		if requirePayload {
			return zero, fmt.Errorf("%w: %s response missing payload", protocol.ErrMalformedEnvelope, messageType)
		}
		return zero, nil
	}
	if requirePayload {
		out, err := protocol.DecodeRequiredPayload[T](resp)
		if err != nil {
			return zero, err
		}
		return out, nil
	}
	return protocol.DecodePayload[T](resp)
}

func validateStatusPayload(messageType protocol.MessageType, payload protocol.StatusPayload) error {
	if payload.PID <= 0 {
		return fmt.Errorf("%w: %s response has invalid pid", protocol.ErrMalformedEnvelope, messageType)
	}
	return nil
}

func validateHelperHelloPayload(payload protocol.HelperHelloPayload) error {
	if payload.Protocol != protocol.ProtocolVersion {
		return fmt.Errorf("%w: helper protocol %d", protocol.ErrProtocolVersion, payload.Protocol)
	}
	if payload.AppVersion == "" {
		return fmt.Errorf("%w: helper.hello response missing app_version", protocol.ErrMalformedEnvelope)
	}
	if payload.PID <= 0 {
		return fmt.Errorf("%w: helper.hello response has invalid pid", protocol.ErrMalformedEnvelope)
	}
	if payload.Executable == "" {
		return fmt.Errorf("%w: helper.hello response missing executable", protocol.ErrMalformedEnvelope)
	}
	return nil
}

func validateExecResponsePayload(payload protocol.ExecResponsePayload, req request.ExecRequest) error {
	expectedAliases := request.SecretAliases(req.Secrets)
	if !slices.Equal(payload.SecretAliases, expectedAliases) {
		return fmt.Errorf("%w: request.exec response secret aliases do not match request", protocol.ErrMalformedEnvelope)
	}
	if payload.Env == nil {
		return fmt.Errorf("%w: request.exec response missing env", protocol.ErrMalformedEnvelope)
	}
	if gotAliases := envAliases(payload.Env); !slices.Equal(gotAliases, expectedAliases) {
		return fmt.Errorf("%w: request.exec response env aliases do not match request", protocol.ErrMalformedEnvelope)
	}
	return nil
}

func validateSessionCreateResponsePayload(payload protocol.SessionCreateResponsePayload, req request.SessionCreateRequest) error {
	if err := request.ValidateSessionID(payload.SessionID); err != nil {
		return fmt.Errorf("%w: invalid session id in session.create response: %w", protocol.ErrMalformedEnvelope, err)
	}
	if err := request.ValidateSessionToken(payload.SessionToken); err != nil {
		return fmt.Errorf("%w: invalid session token in session.create response: %w", protocol.ErrMalformedEnvelope, err)
	}
	expectedAliases := request.SecretAliases(req.Secrets)
	if !slices.Equal(payload.SecretAliases, expectedAliases) {
		return fmt.Errorf("%w: session.create response secret aliases do not match request", protocol.ErrMalformedEnvelope)
	}
	if payload.MaxReads != req.MaxReads {
		return fmt.Errorf("%w: session.create response max reads does not match request", protocol.ErrMalformedEnvelope)
	}
	if payload.RemainingReads != req.MaxReads {
		return fmt.Errorf("%w: session.create response remaining reads does not match request", protocol.ErrMalformedEnvelope)
	}
	return nil
}

func validateSessionResolveResponsePayload(payload protocol.SessionResolveResponsePayload, req request.SessionResolveRequest) error {
	if payload.Env == nil {
		return fmt.Errorf("%w: session.resolve response missing env", protocol.ErrMalformedEnvelope)
	}
	if gotAliases := envAliases(payload.Env); !slices.Equal(gotAliases, payload.SecretAliases) {
		return fmt.Errorf("%w: session.resolve response env aliases do not match secret aliases", protocol.ErrMalformedEnvelope)
	}
	if len(req.RequestedAliases) > 0 && !slices.Equal(payload.SecretAliases, req.RequestedAliases) {
		return fmt.Errorf("%w: session.resolve response secret aliases do not match requested aliases", protocol.ErrMalformedEnvelope)
	}
	return nil
}

func validateGCPCommandResponsePayload(payload protocol.GCPCommandResponsePayload) error {
	if payload.Env == nil {
		return fmt.Errorf("%w: GCP command response missing env", protocol.ErrMalformedEnvelope)
	}
	for _, key := range []string{"CLOUDSDK_CONFIG", "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE", "CLOUDSDK_CORE_PROJECT"} {
		if payload.Env[key] == "" {
			return fmt.Errorf("%w: GCP command response missing %s", protocol.ErrMalformedEnvelope, key)
		}
	}
	if payload.DeliveryMode == "" {
		return fmt.Errorf("%w: GCP command response missing delivery mode", protocol.ErrMalformedEnvelope)
	}
	return nil
}

func envAliases(env map[string]string) []string {
	aliases := make([]string, 0, len(env))
	for alias := range env {
		aliases = append(aliases, alias)
	}
	slices.Sort(aliases)
	return aliases
}

func (c *Client) contextWithDefaultDeadline(
	ctx context.Context,
	messageType protocol.MessageType,
	payload any,
) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	timeout := c.defaultTimeout()
	now := time.Now()
	deadline := now.Add(timeout)
	if expiresAt, ttl, ok := protocolRequestTiming(messageType, payload); ok {
		deadline = protocolRequestDeadline(now, timeout, expiresAt, ttl)
	}
	return context.WithDeadline(ctx, deadline)
}

func protocolRequestTiming(messageType protocol.MessageType, payload any) (time.Time, time.Duration, bool) {
	//nolint:exhaustive // Only request types with approval TTLs extend client protocol deadlines.
	switch messageType {
	case protocol.TypeRequestExec:
		req, ok := payload.(request.ExecRequest)
		return req.ExpiresAt, req.TTL, ok
	case protocol.TypeGCPExec:
		req, ok := payload.(request.GCPExecRequest)
		return req.ExpiresAt, req.TTL, ok
	case protocol.TypeGCPSessionCreate:
		req, ok := payload.(gcpSessionCreateClientPayload)
		return req.Request.ExpiresAt, req.Request.TTL, ok
	case protocol.TypeItemDescribe:
		req, ok := payload.(request.ItemDescribeRequest)
		return req.ExpiresAt, req.TTL, ok
	case protocol.TypeSessionCreate:
		req, ok := payload.(request.SessionCreateRequest)
		return req.ExpiresAt, req.TTL, ok
	default:
		return time.Time{}, 0, false
	}
}

func protocolRequestDeadline(
	now time.Time,
	timeout time.Duration,
	expiresAt time.Time,
	ttl time.Duration,
) time.Time {
	if expiresAt.After(now) {
		return expiresAt.Add(timeout)
	}
	if expiresAt.IsZero() && ttl > 0 {
		return now.Add(ttl + timeout)
	}
	return now.Add(timeout)
}

func (c *Client) defaultTimeout() time.Duration {
	if c != nil && c.DefaultTimeout > 0 {
		return c.DefaultTimeout
	}
	return DefaultClientProtocolTimeout
}

func validateResponseCorrelation(resp protocol.Envelope, correlation protocol.Correlation) error {
	if correlation.RequestID != "" && resp.RequestID != correlation.RequestID {
		return fmt.Errorf("%w: response request id mismatch", protocol.ErrMalformedEnvelope)
	}
	if correlation.Nonce != "" && resp.Nonce != correlation.Nonce {
		return protocol.ErrInvalidNonce
	}
	return nil
}

func (c *Client) readEnvelope() (protocol.Envelope, error) {
	return protocol.ReadEnvelopeFrame(c.reader, protocol.DefaultMaxProtocolFrameBytes)
}

func (c *Client) closeOnContextCancel(ctx context.Context) func() {
	done := ctx.Done()
	if done == nil || c.conn == nil {
		return func() {}
	}
	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-done:
			_ = c.Close()
		case <-stop:
		}
	}()
	return func() {
		close(stop)
		<-stopped
	}
}

func (c *Client) setWriteDeadline(ctx context.Context) error {
	return c.setContextDeadline(ctx, c.conn.SetWriteDeadline)
}

func (c *Client) setReadDeadline(ctx context.Context) error {
	return c.setContextDeadline(ctx, c.conn.SetReadDeadline)
}

func (c *Client) setContextDeadline(ctx context.Context, set func(time.Time) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil
	}
	if err := set(deadline); err != nil {
		if ctxErr := contextErrorAfterIOError(ctx, err); ctxErr != nil {
			return ctxErr
		}
		return err
	}
	return nil
}

func (c *Client) clearDeadlines() {
	if c.conn == nil {
		return
	}
	_ = c.conn.SetDeadline(time.Time{})
}

func contextErrorAfterIOError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		deadline, ok := ctx.Deadline()
		if ok && !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
	}
	return nil
}

func IsProtocolError(err error, code protocol.ErrorCode) bool {
	var protocolErr *ProtocolError
	return errors.As(err, &protocolErr) && protocolErr.Code == code
}
