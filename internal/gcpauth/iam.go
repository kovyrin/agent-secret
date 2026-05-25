package gcpauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kovyrin/agent-secret/internal/gcpcompat"
)

type MintRequest struct {
	GoogleAccount  string
	Project        string
	ServiceAccount string
	Scopes         []string
	Lifetime       time.Duration
	Reason         string
}

type IAMCredentialsMinter struct {
	store         Store
	clientID      string
	tokenEndpoint string
	iamEndpoint   string
	httpClient    *http.Client
}

type IAMCredentialsMinterOptions struct {
	Store         Store
	ClientID      string
	TokenEndpoint string
	IAMEndpoint   string
	HTTPClient    *http.Client
}

type refreshTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

type generateAccessTokenRequest struct {
	Scopes   []string `json:"scope"`
	Lifetime string   `json:"lifetime"`
}

type generateAccessTokenResponse struct {
	AccessToken string    `json:"accessToken"`
	ExpireTime  time.Time `json:"expireTime"`
}

func NewIAMCredentialsMinter(opts IAMCredentialsMinterOptions) (*IAMCredentialsMinter, error) {
	if opts.Store == nil {
		return nil, errors.New("GCP auth store is required")
	}
	clientID := strings.TrimSpace(opts.ClientID)
	if clientID == "" {
		return nil, ErrOAuthClientID
	}
	tokenEndpoint := opts.TokenEndpoint
	if tokenEndpoint == "" {
		tokenEndpoint = DefaultTokenEndpoint
	}
	iamEndpoint := strings.TrimRight(opts.IAMEndpoint, "/")
	if iamEndpoint == "" {
		iamEndpoint = DefaultIAMEndpoint
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &IAMCredentialsMinter{
		store:         opts.Store,
		clientID:      clientID,
		tokenEndpoint: tokenEndpoint,
		iamEndpoint:   iamEndpoint,
		httpClient:    httpClient,
	}, nil
}

func (m *IAMCredentialsMinter) MintAccessToken(ctx context.Context, req MintRequest) (gcpcompat.Token, error) {
	credential, found, err := m.store.Get(ctx, req.GoogleAccount)
	if err != nil {
		return gcpcompat.Token{}, err
	}
	if !found {
		return gcpcompat.Token{}, fmt.Errorf("%w: %s", ErrCredentialNotFound, req.GoogleAccount)
	}
	bootstrapToken, err := m.refreshBootstrapToken(ctx, credential.RefreshToken)
	if err != nil {
		return gcpcompat.Token{}, err
	}
	token, err := m.generateAccessToken(ctx, bootstrapToken, req)
	if err != nil {
		return gcpcompat.Token{}, err
	}
	return token, nil
}

func (m *IAMCredentialsMinter) refreshBootstrapToken(ctx context.Context, refreshToken string) (string, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return "", errors.New("stored GCP OAuth credential is missing refresh token")
	}
	form := url.Values{}
	form.Set("client_id", m.clientID)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, m.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create GCP OAuth refresh request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var response refreshTokenResponse
	if err := doJSON(m.httpClient, httpReq, &response); err != nil {
		return "", fmt.Errorf("refresh GCP OAuth bootstrap token: %w", err)
	}
	if response.Error != "" {
		return "", fmt.Errorf("refresh GCP OAuth bootstrap token: %s", response.Error)
	}
	if response.AccessToken == "" {
		return "", errors.New("refresh GCP OAuth bootstrap token: response missing access token")
	}
	return response.AccessToken, nil
}

func (m *IAMCredentialsMinter) generateAccessToken(ctx context.Context, bootstrapToken string, req MintRequest) (gcpcompat.Token, error) {
	body := generateAccessTokenRequest{
		Scopes:   slices.Clone(req.Scopes),
		Lifetime: iamLifetime(req.Lifetime),
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return gcpcompat.Token{}, fmt.Errorf("marshal IAMCredentials request: %w", err)
	}
	endpoint := m.iamEndpoint + "/v1/projects/-/serviceAccounts/" + url.PathEscape(req.ServiceAccount) + ":generateAccessToken"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return gcpcompat.Token{}, fmt.Errorf("create IAMCredentials request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+bootstrapToken)
	httpReq.Header.Set("Content-Type", "application/json")
	var response generateAccessTokenResponse
	if err := doJSON(m.httpClient, httpReq, &response); err != nil {
		return gcpcompat.Token{}, fmt.Errorf("call IAMCredentials generateAccessToken: %w", err)
	}
	if response.AccessToken == "" {
		return gcpcompat.Token{}, errors.New("IAMCredentials response missing access token")
	}
	if response.ExpireTime.IsZero() {
		return gcpcompat.Token{}, errors.New("IAMCredentials response missing expireTime")
	}
	return gcpcompat.Token{AccessToken: response.AccessToken, ExpiresAt: response.ExpireTime}, nil
}

func iamLifetime(lifetime time.Duration) string {
	seconds := int(math.Ceil(lifetime.Seconds()))
	seconds = max(seconds, 1)
	return fmt.Sprintf("%ds", seconds)
}
