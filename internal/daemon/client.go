package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/kovyrin/agent-secret/internal/request"
)

type ProtocolError struct {
	Code    string
	Message string
}

func (e *ProtocolError) Error() string {
	return e.Code + ": " + e.Message
}

type Client struct {
	conn    *net.UnixConn
	encoder *json.Encoder
	decoder *json.Decoder
}

func Connect(ctx context.Context, path string) (*Client, error) {
	conn, err := Dial(ctx, path)
	if err != nil {
		return nil, err
	}
	return NewClient(conn), nil
}

func NewClient(conn *net.UnixConn) *Client {
	return &Client{
		conn:    conn,
		encoder: json.NewEncoder(conn),
		decoder: json.NewDecoder(conn),
	}
}

func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *Client) Status(ctx context.Context) (StatusPayload, error) {
	return roundTrip[StatusPayload](ctx, c, TypeDaemonStatus, "", "", nil)
}

func (c *Client) Stop(ctx context.Context) (StatusPayload, error) {
	return roundTrip[StatusPayload](ctx, c, TypeDaemonStop, "", "", nil)
}

func (c *Client) FetchPendingApproval(ctx context.Context) (ApprovalRequestPayload, error) {
	return roundTrip[ApprovalRequestPayload](ctx, c, TypeApprovalPending, "", "", nil)
}

func (c *Client) SubmitApprovalDecision(ctx context.Context, decision ApprovalDecisionPayload) error {
	_, err := roundTrip[struct{}](ctx, c, TypeApprovalDecision, decision.RequestID, decision.Nonce, decision)
	return err
}

func (c *Client) RequestExec(ctx context.Context, requestID string, nonce string, req request.ExecRequest) (ExecResponsePayload, error) {
	return roundTrip[ExecResponsePayload](ctx, c, TypeRequestExec, requestID, nonce, req)
}

func (c *Client) ReportStarted(ctx context.Context, requestID string, nonce string, childPID int) error {
	_, err := roundTrip[struct{}](ctx, c, TypeCommandStarted, requestID, nonce, CommandStartedPayload{ChildPID: childPID})
	return err
}

func (c *Client) ReportCompleted(ctx context.Context, requestID string, nonce string, exitCode int, signal string) error {
	_, err := roundTrip[struct{}](ctx, c, TypeCommandCompleted, requestID, nonce, CommandCompletedPayload{
		ExitCode: exitCode,
		Signal:   signal,
	})
	return err
}

func roundTrip[T any](ctx context.Context, c *Client, messageType string, requestID string, nonce string, payload any) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("daemon request canceled: %w", err)
	}
	env, err := NewEnvelope(messageType, requestID, nonce, payload)
	if err != nil {
		return zero, err
	}
	if err := c.encoder.Encode(env); err != nil {
		return zero, fmt.Errorf("send daemon message %s: %w", messageType, err)
	}

	var resp Envelope
	if err := c.decoder.Decode(&resp); err != nil {
		return zero, fmt.Errorf("read daemon response %s: %w", messageType, err)
	}
	if err := validateEnvelope(resp); err != nil {
		return zero, fmt.Errorf("validate daemon response %s: %w", messageType, err)
	}
	if resp.Type == TypeError {
		payload, err := DecodePayload[ErrorPayload](resp)
		if err != nil {
			return zero, fmt.Errorf("decode daemon error response %s: %w", messageType, err)
		}
		return zero, &ProtocolError{Code: payload.Code, Message: payload.Message}
	}
	if resp.Type != TypeOK {
		return zero, fmt.Errorf("%w: response type %s", ErrProtocolType, resp.Type)
	}
	if requestID != "" && resp.RequestID != requestID {
		return zero, fmt.Errorf("%w: response request id mismatch", ErrMalformedEnvelope)
	}
	if nonce != "" && resp.Nonce != nonce {
		return zero, ErrInvalidNonce
	}
	if len(resp.Payload) == 0 {
		return zero, nil
	}
	var out T
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		return zero, fmt.Errorf("%w: %w", ErrMalformedEnvelope, err)
	}
	return out, nil
}

func IsProtocolError(err error, code string) bool {
	var protocolErr *ProtocolError
	return errors.As(err, &protocolErr) && protocolErr.Code == code
}
