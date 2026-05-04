package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/daemon/control"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
)

const approvalSocketTestClientTimeout = time.Second

type approvalSocketTestClient struct {
	conn    *net.UnixConn
	encoder *json.Encoder
	reader  *bufio.Reader
}

func newApprovalSocketTestClient(conn *net.UnixConn) *approvalSocketTestClient {
	return &approvalSocketTestClient{
		conn:    conn,
		encoder: json.NewEncoder(conn),
		reader:  bufio.NewReader(conn),
	}
}

func (c *approvalSocketTestClient) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *approvalSocketTestClient) FetchPending(ctx context.Context) (approval.ApprovalRequestPayload, error) {
	payload, err := approvalSocketTestRoundTripPayload[approval.ApprovalRequestPayload](
		ctx,
		c,
		protocol.TypeApprovalPending,
		protocol.Correlation{},
		nil,
	)
	if err != nil {
		return approval.ApprovalRequestPayload{}, err
	}
	if err := validateApprovalRequestPayloadForServerTest(payload); err != nil {
		return approval.ApprovalRequestPayload{}, err
	}
	return payload, nil
}

func (c *approvalSocketTestClient) SubmitDecision(
	ctx context.Context,
	decision approval.ApprovalDecisionPayload,
) error {
	correlation := protocol.Correlation{RequestID: decision.RequestID, Nonce: decision.Nonce}
	return approvalSocketTestRoundTripAck(ctx, c, protocol.TypeApprovalDecision, correlation, decision)
}

func approvalSocketTestRoundTripPayload[T any](
	ctx context.Context,
	client *approvalSocketTestClient,
	messageType protocol.MessageType,
	correlation protocol.Correlation,
	payload any,
) (T, error) {
	return approvalSocketTestRoundTripResponse[T](ctx, client, messageType, correlation, payload, true)
}

func approvalSocketTestRoundTripAck(
	ctx context.Context,
	client *approvalSocketTestClient,
	messageType protocol.MessageType,
	correlation protocol.Correlation,
	payload any,
) error {
	_, err := approvalSocketTestRoundTripResponse[struct{}](ctx, client, messageType, correlation, payload, false)
	return err
}

func approvalSocketTestRoundTripResponse[T any](
	ctx context.Context,
	client *approvalSocketTestClient,
	messageType protocol.MessageType,
	correlation protocol.Correlation,
	payload any,
	requirePayload bool,
) (T, error) {
	var zero T
	ctx, cancel := approvalSocketTestContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("approval test request canceled: %w", err)
	}
	if err := setApprovalSocketTestDeadline(ctx, client.conn); err != nil {
		return zero, err
	}
	defer func() { _ = client.conn.SetDeadline(time.Time{}) }()

	env, err := protocol.NewEnvelope(messageType, correlation, payload)
	if err != nil {
		return zero, err
	}
	if err := client.encoder.Encode(env); err != nil {
		return zero, fmt.Errorf("send approval test message %s: %w", messageType, err)
	}
	resp, err := protocol.ReadEnvelopeFrame(client.reader, protocol.DefaultMaxProtocolFrameBytes)
	if err != nil {
		return zero, fmt.Errorf("read approval test response %s: %w", messageType, err)
	}
	if err := protocol.ValidateEnvelope(resp); err != nil {
		return zero, fmt.Errorf("validate approval test response %s: %w", messageType, err)
	}
	if err := validateApprovalSocketTestCorrelation(resp, correlation); err != nil {
		return zero, err
	}
	if resp.Type == protocol.TypeError {
		payload, err := protocol.DecodeRequiredPayload[protocol.ErrorPayload](resp)
		if err != nil {
			return zero, fmt.Errorf("decode approval test error response %s: %w", messageType, err)
		}
		return zero, &control.ProtocolError{Code: payload.Code, Message: payload.Message}
	}
	if resp.Type != protocol.TypeOK {
		return zero, fmt.Errorf("%w: response type %s", protocol.ErrProtocolType, resp.Type)
	}
	if requirePayload {
		return protocol.DecodeRequiredPayload[T](resp)
	}
	return zero, nil
}

func approvalSocketTestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, approvalSocketTestClientTimeout)
}

func setApprovalSocketTestDeadline(ctx context.Context, conn *net.UnixConn) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set approval test socket deadline: %w", err)
	}
	return nil
}

func validateApprovalSocketTestCorrelation(resp protocol.Envelope, correlation protocol.Correlation) error {
	if correlation.RequestID != "" && resp.RequestID != correlation.RequestID {
		return fmt.Errorf("%w: response request id mismatch", protocol.ErrMalformedEnvelope)
	}
	if correlation.Nonce != "" && resp.Nonce != correlation.Nonce {
		return protocol.ErrInvalidNonce
	}
	return nil
}

func validateApprovalRequestPayloadForServerTest(payload approval.ApprovalRequestPayload) error {
	if payload.RequestID == "" {
		return fmt.Errorf("%w: approval.pending response missing request id", protocol.ErrMalformedEnvelope)
	}
	if payload.Nonce == "" {
		return fmt.Errorf("%w: approval.pending response missing nonce", protocol.ErrMalformedEnvelope)
	}
	if len(payload.Command) == 0 {
		return fmt.Errorf("%w: approval.pending response missing command", protocol.ErrMalformedEnvelope)
	}
	if payload.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: approval.pending response missing expiry", protocol.ErrMalformedEnvelope)
	}
	if len(payload.Secrets) == 0 {
		return fmt.Errorf("%w: approval.pending response missing secrets", protocol.ErrMalformedEnvelope)
	}
	return nil
}
