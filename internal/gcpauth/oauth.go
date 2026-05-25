package gcpauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

type BrowserOpener func(context.Context, string) error

type OAuthFlow struct {
	clientID         string
	scopes           []string
	authEndpoint     string
	tokenEndpoint    string
	userInfoEndpoint string
	httpClient       *http.Client
	openBrowser      BrowserOpener
	randomReader     io.Reader
}

type OAuthFlowOptions struct {
	ClientID         string
	Scopes           []string
	AuthEndpoint     string
	TokenEndpoint    string
	UserInfoEndpoint string
	HTTPClient       *http.Client
	OpenBrowser      BrowserOpener
	RandomReader     io.Reader
}

type OAuthLoginRequest struct {
	GoogleAccount string
	ExpectedEmail string
}

type OAuthToken struct {
	AccessToken  string
	RefreshToken string
	Email        string
	Scopes       []string
}

type oauthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

type userInfoResponse struct {
	Email string `json:"email"`
}

func NewOAuthFlow(opts OAuthFlowOptions) *OAuthFlow {
	scopes := slices.Clone(opts.Scopes)
	if len(scopes) == 0 {
		scopes = defaultOAuthScopes()
	}
	authEndpoint := opts.AuthEndpoint
	if authEndpoint == "" {
		authEndpoint = DefaultAuthEndpoint
	}
	tokenEndpoint := opts.TokenEndpoint
	if tokenEndpoint == "" {
		tokenEndpoint = DefaultTokenEndpoint
	}
	userInfoEndpoint := opts.UserInfoEndpoint
	if userInfoEndpoint == "" {
		userInfoEndpoint = DefaultUserInfoEndpoint
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	randomReader := opts.RandomReader
	if randomReader == nil {
		randomReader = rand.Reader
	}
	return &OAuthFlow{
		clientID:         strings.TrimSpace(opts.ClientID),
		scopes:           scopes,
		authEndpoint:     authEndpoint,
		tokenEndpoint:    tokenEndpoint,
		userInfoEndpoint: userInfoEndpoint,
		httpClient:       httpClient,
		openBrowser:      opts.OpenBrowser,
		randomReader:     randomReader,
	}
}

func (f *OAuthFlow) Login(ctx context.Context, req OAuthLoginRequest) (OAuthToken, error) {
	if strings.TrimSpace(f.clientID) == "" {
		return OAuthToken{}, ErrOAuthClientID
	}
	openBrowser := f.openBrowser
	if openBrowser == nil {
		openBrowser = OpenBrowser
	}
	state, err := randomURLSafe(f.randomReader, 32)
	if err != nil {
		return OAuthToken{}, fmt.Errorf("generate OAuth state: %w", err)
	}
	verifier, err := randomURLSafe(f.randomReader, 64)
	if err != nil {
		return OAuthToken{}, fmt.Errorf("generate OAuth PKCE verifier: %w", err)
	}
	challenge := pkceChallenge(verifier)

	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return OAuthToken{}, fmt.Errorf("start OAuth callback listener: %w", err)
	}
	defer func() { _ = listener.Close() }()
	redirectURI := "http://" + listener.Addr().String() + "/callback"
	callbacks := make(chan oauthCallback, 1)
	server := &http.Server{
		Handler:           oauthCallbackHandler(state, callbacks),
		ReadHeaderTimeout: 10 * time.Second,
	}
	defer func() { _ = server.Close() }()
	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			callbacks <- oauthCallback{err: fmt.Errorf("serve OAuth callback: %w", err)}
		}
	}()

	authURL, err := f.authURL(redirectURI, state, challenge, req)
	if err != nil {
		return OAuthToken{}, err
	}
	if err := openBrowser(ctx, authURL); err != nil {
		return OAuthToken{}, fmt.Errorf("open browser for GCP OAuth login: %w", err)
	}

	var callback oauthCallback
	select {
	case <-ctx.Done():
		return OAuthToken{}, ctx.Err()
	case callback = <-callbacks:
		if callback.err != nil {
			return OAuthToken{}, callback.err
		}
	}

	token, err := f.exchangeCode(ctx, callback.code, redirectURI, verifier)
	if err != nil {
		return OAuthToken{}, err
	}
	if token.RefreshToken == "" {
		return OAuthToken{}, ErrOAuthNoRefresh
	}
	email, err := f.fetchEmail(ctx, token.AccessToken)
	if err != nil {
		return OAuthToken{}, err
	}
	expected := strings.TrimSpace(strings.ToLower(req.ExpectedEmail))
	if expected != "" && strings.ToLower(email) != expected {
		return OAuthToken{}, fmt.Errorf("%w: got %s, expected %s", ErrOAuthEmailMismatch, email, expected)
	}
	scopes := strings.Fields(token.Scope)
	if len(scopes) == 0 {
		scopes = slices.Clone(f.scopes)
	}
	return OAuthToken{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Email:        email,
		Scopes:       scopes,
	}, nil
}

func (f *OAuthFlow) authURL(redirectURI string, state string, challenge string, req OAuthLoginRequest) (string, error) {
	endpoint, err := url.Parse(f.authEndpoint)
	if err != nil {
		return "", fmt.Errorf("parse GCP OAuth auth endpoint: %w", err)
	}
	values := endpoint.Query()
	values.Set("client_id", f.clientID)
	values.Set("redirect_uri", redirectURI)
	values.Set("response_type", "code")
	values.Set("scope", strings.Join(f.scopes, " "))
	values.Set("state", state)
	values.Set("code_challenge", challenge)
	values.Set("code_challenge_method", "S256")
	values.Set("access_type", "offline")
	values.Set("prompt", "consent")
	if req.ExpectedEmail != "" {
		values.Set("login_hint", req.ExpectedEmail)
	} else if strings.Contains(req.GoogleAccount, "@") {
		values.Set("login_hint", req.GoogleAccount)
	}
	endpoint.RawQuery = values.Encode()
	return endpoint.String(), nil
}

func (f *OAuthFlow) exchangeCode(ctx context.Context, code string, redirectURI string, verifier string) (oauthTokenResponse, error) {
	form := url.Values{}
	form.Set("client_id", f.clientID)
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", redirectURI)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return oauthTokenResponse{}, fmt.Errorf("create GCP OAuth token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var token oauthTokenResponse
	if err := doJSON(f.httpClient, req, &token); err != nil {
		return oauthTokenResponse{}, fmt.Errorf("exchange GCP OAuth code: %w", err)
	}
	if token.Error != "" {
		return oauthTokenResponse{}, fmt.Errorf("exchange GCP OAuth code: %s", token.Error)
	}
	if token.AccessToken == "" {
		return oauthTokenResponse{}, errors.New("exchange GCP OAuth code: response missing access token")
	}
	return token, nil
}

func (f *OAuthFlow) fetchEmail(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.userInfoEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("create GCP OAuth userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	var user userInfoResponse
	if err := doJSON(f.httpClient, req, &user); err != nil {
		return "", fmt.Errorf("fetch GCP OAuth userinfo: %w", err)
	}
	email := strings.TrimSpace(strings.ToLower(user.Email))
	if email == "" {
		return "", errors.New("fetch GCP OAuth userinfo: response missing email")
	}
	return email, nil
}

type oauthCallback struct {
	code string
	err  error
}

func oauthCallbackHandler(expectedState string, callbacks chan<- oauthCallback) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if got := query.Get("state"); got != expectedState {
			http.Error(w, "Agent Secret GCP login failed: state mismatch.", http.StatusBadRequest)
			callbacks <- oauthCallback{err: ErrOAuthState}
			return
		}
		if errCode := query.Get("error"); errCode != "" {
			http.Error(w, "Agent Secret GCP login failed: "+html.EscapeString(errCode), http.StatusBadRequest)
			callbacks <- oauthCallback{err: fmt.Errorf("GCP OAuth returned %s", errCode)}
			return
		}
		code := query.Get("code")
		if code == "" {
			http.Error(w, "Agent Secret GCP login failed: missing authorization code.", http.StatusBadRequest)
			callbacks <- oauthCallback{err: errors.New("GCP OAuth callback missing authorization code")}
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><title>Agent Secret GCP Login</title><p>Agent Secret GCP login completed. You can close this window.</p>")
		callbacks <- oauthCallback{code: code}
	})
}

func randomURLSafe(reader io.Reader, bytesLen int) (string, error) {
	buf := make([]byte, bytesLen)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func doJSON(client *http.Client, req *http.Request, out any) error {
	resp, err := client.Do(req) //nolint:gosec // G704: callers supply fixed Google endpoints or test servers, not user input.
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	contentType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, req.URL.Host)
	}
	if contentType != "" && contentType != "application/json" {
		return fmt.Errorf("unexpected content type %q from %s", contentType, req.URL.Host)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode JSON from %s: %w", req.URL.Host, err)
	}
	return nil
}
