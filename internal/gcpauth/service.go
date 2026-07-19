package gcpauth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/request"
)

type OAuthLoginRunner interface {
	Login(ctx context.Context, req OAuthLoginRequest) (OAuthToken, error)
}

type Service struct {
	store Store
	oauth OAuthLoginRunner
	now   func() time.Time
}

type ServiceOptions struct {
	Store Store
	OAuth OAuthLoginRunner
	Now   func() time.Time
}

func NewService(opts ServiceOptions) (*Service, error) {
	if opts.Store == nil {
		return nil, errors.New("GCP auth store is required")
	}
	if opts.OAuth == nil {
		return nil, errors.New("GCP OAuth login runner is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Service{store: opts.Store, oauth: opts.OAuth, now: now}, nil
}

func (s *Service) Status(ctx context.Context, req request.GCPAuthStatusRequest) (protocol.GCPAuthStatusResponsePayload, error) {
	if err := req.ValidateForDaemon(); err != nil {
		return protocol.GCPAuthStatusResponsePayload{}, err
	}
	if req.GoogleAccount != "" {
		credential, found, err := s.store.Get(ctx, req.GoogleAccount)
		if err != nil {
			return protocol.GCPAuthStatusResponsePayload{}, err
		}
		if !found {
			return protocol.GCPAuthStatusResponsePayload{}, nil
		}
		return protocol.GCPAuthStatusResponsePayload{Accounts: []protocol.GCPAuthAccountInfo{credentialInfo(credential)}}, nil
	}
	credentials, err := s.store.List(ctx)
	if err != nil {
		return protocol.GCPAuthStatusResponsePayload{}, err
	}
	accounts := make([]protocol.GCPAuthAccountInfo, 0, len(credentials))
	for _, credential := range credentials {
		accounts = append(accounts, credentialInfo(credential))
	}
	slices.SortFunc(accounts, func(a, b protocol.GCPAuthAccountInfo) int {
		return strings.Compare(a.GoogleAccount, b.GoogleAccount)
	})
	return protocol.GCPAuthStatusResponsePayload{Accounts: accounts}, nil
}

func (s *Service) Login(ctx context.Context, req request.GCPAuthLoginRequest) (protocol.GCPAuthLoginResponsePayload, error) {
	if err := req.ValidateForDaemon(); err != nil {
		return protocol.GCPAuthLoginResponsePayload{}, err
	}
	token, err := s.oauth.Login(ctx, OAuthLoginRequest{
		GoogleAccount: req.GoogleAccount,
		ExpectedEmail: req.ExpectedEmail,
	})
	if err != nil {
		return protocol.GCPAuthLoginResponsePayload{}, err
	}
	now := s.now().UTC()
	created := now
	if existing, found, err := s.store.Get(ctx, req.GoogleAccount); err != nil {
		return protocol.GCPAuthLoginResponsePayload{}, err
	} else if found && !existing.CreatedAt.IsZero() {
		created = existing.CreatedAt
	}
	credential := Credential{
		GoogleAccount: req.GoogleAccount,
		Email:         token.Email,
		RefreshToken:  token.RefreshToken,
		Scopes:        slices.Clone(token.Scopes),
		CreatedAt:     created,
		UpdatedAt:     now,
	}
	if err := s.store.Put(ctx, credential); err != nil {
		return protocol.GCPAuthLoginResponsePayload{}, err
	}
	return protocol.GCPAuthLoginResponsePayload{Account: credentialInfo(credential)}, nil
}

func (s *Service) Logout(ctx context.Context, req request.GCPAuthLogoutRequest) (protocol.GCPAuthLogoutResponsePayload, error) {
	if err := req.ValidateForDaemon(); err != nil {
		return protocol.GCPAuthLogoutResponsePayload{}, err
	}
	deleted, err := s.store.Delete(ctx, req.GoogleAccount)
	if err != nil {
		return protocol.GCPAuthLogoutResponsePayload{}, err
	}
	return protocol.GCPAuthLogoutResponsePayload{GoogleAccount: req.GoogleAccount, Deleted: deleted}, nil
}

func credentialInfo(credential Credential) protocol.GCPAuthAccountInfo {
	return protocol.GCPAuthAccountInfo{
		GoogleAccount: credential.GoogleAccount,
		Email:         credential.Email,
		Scopes:        slices.Clone(credential.Scopes),
		CreatedAt:     credential.CreatedAt,
		UpdatedAt:     credential.UpdatedAt,
	}
}
