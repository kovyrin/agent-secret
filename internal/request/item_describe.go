package request

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/kovyrin/agent-secret/internal/itemmetadata"
	"github.com/kovyrin/agent-secret/internal/pathresolve"
)

const DefaultItemDescribeTTL = 2 * time.Minute

type ItemDescribeOptions struct {
	Reason             string
	Command            []string
	CWD                string
	ResolvedExecutable string
	Ref                string
	Account            string
	TTL                time.Duration
	ReceivedAt         time.Time
}

type ItemDescribeRequest struct {
	Reason             string           `json:"reason"`
	Command            []string         `json:"command"`
	ResolvedExecutable string           `json:"resolved_executable"`
	CWD                string           `json:"cwd"`
	Ref                itemmetadata.Ref `json:"ref"`
	Account            string           `json:"account"`
	TTL                time.Duration    `json:"ttl"`
	ReceivedAt         time.Time        `json:"received_at"`
	ExpiresAt          time.Time        `json:"expires_at"`
}

func NewItemDescribe(opts ItemDescribeOptions) (ItemDescribeRequest, error) {
	reason, err := validateReason(opts.Reason)
	if err != nil {
		return ItemDescribeRequest{}, err
	}
	ref, err := itemmetadata.ParseRef(opts.Ref)
	if err != nil {
		return ItemDescribeRequest{}, fmt.Errorf("%w: %w", ErrInvalidReference, err)
	}
	account := strings.TrimSpace(opts.Account)
	if account == "" {
		return ItemDescribeRequest{}, fmt.Errorf("%w: item account is required", ErrInvalidReference)
	}
	ttl := opts.TTL
	if ttl == 0 {
		ttl = DefaultItemDescribeTTL
	}
	if ttl < MinExecTTL || ttl > MaxExecTTL {
		return ItemDescribeRequest{}, fmt.Errorf("%w: must be between %s and %s", ErrInvalidTTL, MinExecTTL, MaxExecTTL)
	}
	cwd, err := normalizeCWD(opts.CWD)
	if err != nil {
		return ItemDescribeRequest{}, err
	}
	resolvedExecutable := opts.ResolvedExecutable
	if resolvedExecutable == "" {
		resolvedExecutable, err = os.Executable()
		if err != nil {
			return ItemDescribeRequest{}, fmt.Errorf("resolve current executable: %w", err)
		}
		resolvedExecutable, err = pathresolve.Strict(resolvedExecutable)
		if err != nil {
			return ItemDescribeRequest{}, fmt.Errorf("%w: resolve current executable: %w", ErrInvalidCommand, err)
		}
	}
	command := slices.Clone(opts.Command)
	if len(command) == 0 {
		command = []string{"agent-secret", "item", "describe", opts.Ref}
	}
	receivedAt := opts.ReceivedAt
	expiresAt := time.Time{}
	if !receivedAt.IsZero() {
		expiresAt = receivedAt.Add(ttl)
	}
	return ItemDescribeRequest{
		Reason:             reason,
		Command:            command,
		ResolvedExecutable: resolvedExecutable,
		CWD:                cwd,
		Ref:                ref,
		Account:            account,
		TTL:                ttl,
		ReceivedAt:         receivedAt,
		ExpiresAt:          expiresAt,
	}, nil
}

func (r ItemDescribeRequest) WithReceiptTime(receivedAt time.Time) ItemDescribeRequest {
	r.ReceivedAt = receivedAt
	r.ExpiresAt = receivedAt.Add(r.TTL)
	return r
}

func (r ItemDescribeRequest) Expired(at time.Time) bool {
	return !at.Before(r.ExpiresAt)
}

func (r ItemDescribeRequest) ValidateForDaemon() error {
	reason, err := validateReason(r.Reason)
	if err != nil {
		return err
	}
	if reason != r.Reason {
		return fmt.Errorf("%w: reason must be pre-normalized", ErrInvalidReason)
	}
	if r.TTL < MinExecTTL || r.TTL > MaxExecTTL {
		return fmt.Errorf("%w: must be between %s and %s", ErrInvalidTTL, MinExecTTL, MaxExecTTL)
	}
	if r.ReceivedAt.IsZero() || r.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: request times are required", ErrInvalidRequest)
	}
	if !r.ExpiresAt.Equal(r.ReceivedAt.Add(r.TTL)) {
		return fmt.Errorf("%w: expires_at must equal received_at plus ttl", ErrInvalidTTL)
	}
	if err := validateDaemonPath("cwd", r.CWD, false); err != nil {
		return err
	}
	if err := validateDaemonPath("resolved executable", r.ResolvedExecutable, true); err != nil {
		return err
	}
	if len(r.Command) == 0 || r.Command[0] == "" {
		return fmt.Errorf("%w: argv is required", ErrInvalidCommand)
	}
	if _, err := itemmetadata.ParseRef(r.Ref.Raw); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidReference, err)
	}
	if strings.TrimSpace(r.Account) != r.Account || r.Account == "" {
		return fmt.Errorf("%w: item account is required", ErrInvalidReference)
	}
	return nil
}
