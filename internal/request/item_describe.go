package request

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/kovyrin/agent-secret/internal/itemmetadata"
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
	ttl := opts.TTL
	if ttl == 0 {
		ttl = DefaultItemDescribeTTL
	}
	if ttl < MinRequestTTL || ttl > MaxRequestTTL {
		return ItemDescribeRequest{}, fmt.Errorf("%w: must be between %s and %s", ErrInvalidTTL, MinRequestTTL, MaxRequestTTL)
	}
	if err := validatePreparedPath("cwd", opts.CWD, false); err != nil {
		return ItemDescribeRequest{}, err
	}
	if err := validatePreparedPath("resolved executable", opts.ResolvedExecutable, true); err != nil {
		return ItemDescribeRequest{}, err
	}
	command := slices.Clone(opts.Command)
	if len(command) == 0 || command[0] == "" {
		return ItemDescribeRequest{}, fmt.Errorf("%w: argv is required", ErrInvalidCommand)
	}
	receivedAt := opts.ReceivedAt
	expiresAt := time.Time{}
	if !receivedAt.IsZero() {
		expiresAt = receivedAt.Add(ttl)
	}
	return ItemDescribeRequest{
		Reason:             reason,
		Command:            command,
		ResolvedExecutable: opts.ResolvedExecutable,
		CWD:                opts.CWD,
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
	if err := validateDaemonLifecycle(daemonLifecycle{
		Reason:             r.Reason,
		Command:            r.Command,
		CWD:                r.CWD,
		ResolvedExecutable: r.ResolvedExecutable,
		TTL:                r.TTL,
		ReceivedAt:         r.ReceivedAt,
		ExpiresAt:          r.ExpiresAt,
	}); err != nil {
		return err
	}
	parsed, err := itemmetadata.ParseRef(r.Ref.Raw)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidReference, err)
	}
	if parsed != r.Ref {
		return fmt.Errorf("%w: item reference metadata must be pre-normalized", ErrInvalidReference)
	}
	if strings.TrimSpace(r.Account) != r.Account {
		return fmt.Errorf("%w: item account must be trimmed", ErrInvalidReference)
	}
	return nil
}
