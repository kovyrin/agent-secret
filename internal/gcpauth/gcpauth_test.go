package gcpauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/request"
)

func TestOAuthFlowUsesPKCEAndOmitsUnsetClientSecretInTokenRequest(t *testing.T) {
	t.Parallel()

	var tokenForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm returned error: %v", err)
			}
			tokenForm = cloneValues(r.PostForm)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"access_token": "bootstrap-access",
				"refresh_token": "bootstrap-refresh",
				"scope": "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/iam",
				"token_type": "Bearer",
				"expires_in": 3600
			}`))
		case "/userinfo":
			if got := r.Header.Get("Authorization"); got != "Bearer bootstrap-access" {
				t.Fatalf("userinfo authorization = %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"email":"Oleksiy@Kovyrin.net"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	flow := NewOAuthFlow(OAuthFlowOptions{
		ClientID:         "desktop-client-id",
		AuthEndpoint:     "https://accounts.example.invalid/o/oauth2/v2/auth",
		TokenEndpoint:    server.URL + "/token",
		UserInfoEndpoint: server.URL + "/userinfo",
		OpenBrowser: func(ctx context.Context, authURL string) error {
			_ = ctx
			parsed, err := url.Parse(authURL)
			if err != nil {
				t.Fatalf("parse auth URL: %v", err)
			}
			query := parsed.Query()
			if query.Get("client_id") != "desktop-client-id" ||
				query.Get("code_challenge") == "" ||
				query.Get("code_challenge_method") != "S256" ||
				query.Get("access_type") != "offline" ||
				query.Get("prompt") != "consent" ||
				query.Get("scope") != "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/iam" ||
				query.Get("login_hint") != "oleksiy@kovyrin.net" {
				t.Fatalf("unexpected auth URL query: %s", parsed.RawQuery)
			}
			callback, err := url.Parse(query.Get("redirect_uri"))
			if err != nil {
				t.Fatalf("parse redirect_uri: %v", err)
			}
			values := callback.Query()
			values.Set("state", query.Get("state"))
			values.Set("code", "auth-code")
			callback.RawQuery = values.Encode()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, callback.String(), nil)
			if err != nil {
				return err
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("callback status = %d", resp.StatusCode)
			}
			return nil
		},
	})

	token, err := flow.Login(context.Background(), OAuthLoginRequest{
		GoogleAccount: "personal",
		ExpectedEmail: "oleksiy@kovyrin.net",
	})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if token.RefreshToken != "bootstrap-refresh" || token.Email != "oleksiy@kovyrin.net" {
		t.Fatalf("unexpected OAuth token metadata: %+v", token)
	}
	if tokenForm.Get("client_secret") != "" {
		t.Fatalf("token exchange unexpectedly sent client_secret")
	}
	if tokenForm.Get("code") != "auth-code" ||
		tokenForm.Get("code_verifier") == "" ||
		tokenForm.Get("grant_type") != "authorization_code" {
		t.Fatalf("unexpected token form: %v", tokenForm)
	}
}

func TestOAuthFlowIncludesConfiguredClientSecretInTokenRequest(t *testing.T) {
	t.Parallel()

	var tokenForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm returned error: %v", err)
		}
		tokenForm = cloneValues(r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"bootstrap-access","refresh_token":"bootstrap-refresh"}`))
	}))
	defer server.Close()

	flow := NewOAuthFlow(OAuthFlowOptions{
		ClientID:      "desktop-client-id",
		ClientSecret:  "desktop-client-secret",
		TokenEndpoint: server.URL,
	})
	_, err := flow.exchangeCode(context.Background(), "auth-code", "http://127.0.0.1/callback", "verifier")
	if err != nil {
		t.Fatalf("exchangeCode returned error: %v", err)
	}
	if tokenForm.Get("client_secret") != "desktop-client-secret" {
		t.Fatalf("client_secret = %q", tokenForm.Get("client_secret"))
	}
}

func TestOAuthFlowRejectsMissingGrantedScopes(t *testing.T) {
	t.Parallel()

	var userInfoCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"access_token": "bootstrap-access",
				"refresh_token": "bootstrap-refresh",
				"scope": "openid https://www.googleapis.com/auth/userinfo.email",
				"token_type": "Bearer",
				"expires_in": 3600
			}`))
		case "/userinfo":
			userInfoCalled = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"email":"oleksiy@kovyrin.net"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	flow := NewOAuthFlow(OAuthFlowOptions{
		ClientID:         "desktop-client-id",
		AuthEndpoint:     "https://accounts.example.invalid/o/oauth2/v2/auth",
		TokenEndpoint:    server.URL + "/token",
		UserInfoEndpoint: server.URL + "/userinfo",
		OpenBrowser: func(ctx context.Context, authURL string) error {
			parsed, err := url.Parse(authURL)
			if err != nil {
				t.Fatalf("parse auth URL: %v", err)
			}
			query := parsed.Query()
			callback, err := url.Parse(query.Get("redirect_uri"))
			if err != nil {
				t.Fatalf("parse redirect_uri: %v", err)
			}
			values := callback.Query()
			values.Set("state", query.Get("state"))
			values.Set("code", "auth-code")
			callback.RawQuery = values.Encode()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, callback.String(), nil)
			if err != nil {
				return err
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			return nil
		},
	})

	_, err := flow.Login(context.Background(), OAuthLoginRequest{
		GoogleAccount: "personal",
		ExpectedEmail: "oleksiy@kovyrin.net",
	})
	if !errors.Is(err, ErrOAuthScopeDenied) || !strings.Contains(err.Error(), BootstrapOAuthScopeIAM) {
		t.Fatalf("Login error = %v, want missing IAM scope", err)
	}
	if userInfoCalled {
		t.Fatal("userinfo endpoint was called after missing required scope")
	}
}

func TestServiceLoginStatusAndLogoutDoNotExposeRefreshToken(t *testing.T) {
	t.Parallel()

	store := newMemoryStore()
	service, err := NewService(ServiceOptions{
		Store: store,
		OAuth: staticOAuthRunner{token: OAuthToken{
			RefreshToken: "secret-refresh",
			Email:        "oleksiy@kovyrin.net",
			Scopes:       []string{BootstrapOAuthScopeIAM},
		}},
		Now: func() time.Time { return time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}

	login, err := service.Login(context.Background(), mustGCPAuthLogin(t, "personal", "oleksiy@kovyrin.net"))
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	encoded, err := json.Marshal(login)
	if err != nil {
		t.Fatalf("marshal login response: %v", err)
	}
	if strings.Contains(string(encoded), "secret-refresh") {
		t.Fatalf("login response leaked refresh token: %s", encoded)
	}

	status, err := service.Status(context.Background(), request.GCPAuthStatusRequest{})
	if err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	if len(status.Accounts) != 1 || status.Accounts[0].GoogleAccount != "personal" {
		t.Fatalf("unexpected status response: %+v", status)
	}

	logout, err := service.Logout(context.Background(), request.GCPAuthLogoutRequest{GoogleAccount: "personal"})
	if err != nil {
		t.Fatalf("Logout returned error: %v", err)
	}
	if !logout.Deleted {
		t.Fatalf("logout deleted = false")
	}
}

func TestServicePreservesCredentialCreationTimeOnRelogin(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	if err := store.Put(context.Background(), Credential{
		GoogleAccount: "personal",
		Email:         "old@example.com",
		RefreshToken:  "old-refresh",
		CreatedAt:     createdAt,
		UpdatedAt:     createdAt,
	}); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		Store: store,
		OAuth: staticOAuthRunner{token: OAuthToken{
			RefreshToken: "new-refresh",
			Email:        "oleksiy@kovyrin.net",
			Scopes:       []string{BootstrapOAuthScopeIAM},
		}},
		Now: func() time.Time { return updatedAt },
	})
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}

	login, err := service.Login(context.Background(), mustGCPAuthLogin(t, "personal", "oleksiy@kovyrin.net"))
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if !login.Account.CreatedAt.Equal(createdAt) || !login.Account.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("login times = created %s updated %s", login.Account.CreatedAt, login.Account.UpdatedAt)
	}
}

func TestServiceReturnsStoreAndOAuthErrors(t *testing.T) {
	t.Parallel()

	storeErr := errors.New("store unavailable")
	oauthErr := errors.New("oauth denied")
	service, err := NewService(ServiceOptions{
		Store: errStore{err: storeErr},
		OAuth: staticOAuthRunner{err: oauthErr},
	})
	if err != nil {
		t.Fatalf("NewService returned error: %v", err)
	}

	if _, err := service.Status(context.Background(), request.GCPAuthStatusRequest{}); !errors.Is(err, storeErr) {
		t.Fatalf("Status error = %v, want storeErr", err)
	}
	if _, err := service.Login(context.Background(), mustGCPAuthLogin(t, "personal", "")); !errors.Is(err, oauthErr) {
		t.Fatalf("Login error = %v, want oauthErr", err)
	}
	if _, err := service.Logout(context.Background(), request.GCPAuthLogoutRequest{GoogleAccount: "personal"}); !errors.Is(err, storeErr) {
		t.Fatalf("Logout error = %v, want storeErr", err)
	}
}

func TestKeychainStoreRoundTripUsesPrivateIndex(t *testing.T) {
	backend, store := newMemoryKeychainStore()
	ctx := context.Background()
	accounts := []string{"personal", "fixture"}

	for _, account := range accounts {
		err := store.Put(ctx, Credential{
			GoogleAccount: account,
			Email:         account + "@example.test",
			RefreshToken:  "synthetic-" + account,
			Scopes:        []string{BootstrapOAuthScopeIAM},
		})
		if err != nil {
			t.Fatalf("Put(%s) returned error: %v", account, err)
		}
	}
	if len(backend.items) != len(accounts)+1 {
		t.Fatalf("backend stored %d items, want credentials plus index", len(backend.items))
	}

	credential, found, err := store.Get(ctx, "personal")
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if !found || credential.RefreshToken != "synthetic-personal" {
		t.Fatalf("Get = %+v found=%t", credential, found)
	}
	credential.GoogleAccount = ""
	if err := store.Put(ctx, credential); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Put missing account error = %v, want ErrInvalidCredential", err)
	}

	credentials, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	gotAccounts := make([]string, 0, len(credentials))
	for _, credential := range credentials {
		gotAccounts = append(gotAccounts, credential.GoogleAccount)
	}
	wantAccounts := slices.Clone(accounts)
	slices.Sort(wantAccounts)
	if !slices.Equal(gotAccounts, wantAccounts) {
		t.Fatalf("listed accounts = %v, want %v", gotAccounts, wantAccounts)
	}

	deleted, err := store.Delete(ctx, "personal")
	if err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}
	if !deleted {
		t.Fatal("Delete returned false for existing credential")
	}
	_, found, err = store.Get(ctx, "personal")
	if err != nil {
		t.Fatalf("Get after delete returned error: %v", err)
	}
	if found {
		t.Fatal("deleted credential still found")
	}
	again, err := store.Delete(ctx, "personal")
	if err != nil {
		t.Fatalf("second Delete returned error: %v", err)
	}
	if again {
		t.Fatal("second Delete returned true")
	}
}

func TestKeychainStoreRepairsInaccessibleIndexOnPutAndDelete(t *testing.T) {
	backend, store := newMemoryKeychainStore()
	ctx := context.Background()
	indexKey := keychainTestKey(store.service, keychainIndexAccount)
	backend.items[indexKey] = []byte(`{"accounts":["stale"]}`)
	backend.getErrs[indexKey] = ErrKeychainAccess

	if err := store.Put(ctx, Credential{
		GoogleAccount: "personal",
		Email:         "personal@example.test",
		RefreshToken:  "synthetic-refresh",
	}); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	if _, ok := backend.getErrs[indexKey]; ok {
		t.Fatal("Put did not clear inaccessible index")
	}
	credentials, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List after Put returned error: %v", err)
	}
	if len(credentials) != 1 || credentials[0].GoogleAccount != "personal" {
		t.Fatalf("credentials after repaired Put = %+v", credentials)
	}

	backend.getErrs[indexKey] = ErrKeychainAccess
	deleted, err := store.Delete(ctx, "personal")
	if err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}
	if !deleted {
		t.Fatal("Delete returned false")
	}
	credentials, err = store.List(ctx)
	if err != nil {
		t.Fatalf("List after Delete returned error: %v", err)
	}
	if len(credentials) != 0 {
		t.Fatalf("credentials after repaired Delete = %+v, want empty", credentials)
	}
}

func TestIAMCredentialsMinterRefreshesBootstrapTokenAndCallsGenerateAccessToken(t *testing.T) {
	t.Parallel()

	store := newMemoryStore()
	syntheticRefresh := strings.Join([]string{"bootstrap", "refresh"}, "-")
	if err := store.Put(context.Background(), Credential{
		GoogleAccount: "personal",
		Email:         "oleksiy@kovyrin.net",
		RefreshToken:  syntheticRefresh,
	}); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	expireTime := time.Date(2026, 5, 25, 12, 10, 0, 0, time.UTC)
	var refreshForm url.Values
	var generateBody generateAccessTokenRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm returned error: %v", err)
			}
			refreshForm = cloneValues(r.PostForm)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"bootstrap-access","token_type":"Bearer","expires_in":3600}`))
		case "/v1/projects/-/serviceAccounts/agent-beta@fixture-beta.iam.gserviceaccount.com:generateAccessToken":
			if got := r.Header.Get("Authorization"); got != "Bearer bootstrap-access" {
				t.Fatalf("IAM authorization = %q", got)
			}
			if err := json.NewDecoder(r.Body).Decode(&generateBody); err != nil {
				t.Fatalf("decode generateAccessToken body: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"accessToken":"service-account-access","expireTime":"` + expireTime.Format(time.RFC3339Nano) + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	minter, err := NewIAMCredentialsMinter(IAMCredentialsMinterOptions{
		Store:         store,
		ClientID:      "desktop-client-id",
		ClientSecret:  "desktop-client-secret",
		TokenEndpoint: server.URL + "/token",
		IAMEndpoint:   server.URL,
	})
	if err != nil {
		t.Fatalf("NewIAMCredentialsMinter returned error: %v", err)
	}
	token, err := minter.MintAccessToken(context.Background(), MintRequest{
		GoogleAccount:  "personal",
		Project:        "fixture-beta",
		ServiceAccount: "agent-beta@fixture-beta.iam.gserviceaccount.com",
		Scopes:         []string{"https://www.googleapis.com/auth/cloud-platform"},
		Lifetime:       90 * time.Second,
	})
	if err != nil {
		t.Fatalf("MintAccessToken returned error: %v", err)
	}
	if token.AccessToken != "service-account-access" || !token.ExpiresAt.Equal(expireTime) {
		t.Fatalf("unexpected minted token metadata: %+v", token)
	}
	if refreshForm.Get("refresh_token") != syntheticRefresh ||
		refreshForm.Get("client_secret") != "desktop-client-secret" {
		t.Fatalf("unexpected refresh form: %v", refreshForm)
	}
	if generateBody.Lifetime != "90s" ||
		!slices.Equal(generateBody.Scopes, []string{"https://www.googleapis.com/auth/cloud-platform"}) {
		t.Fatalf("unexpected generateAccessToken body: %+v", generateBody)
	}
}

func TestIAMCredentialsMinterRejectsMissingAndIncompleteCredentials(t *testing.T) {
	t.Parallel()

	store := newMemoryStore()
	minter, err := NewIAMCredentialsMinter(IAMCredentialsMinterOptions{
		Store:    store,
		ClientID: "desktop-client-id",
	})
	if err != nil {
		t.Fatalf("NewIAMCredentialsMinter returned error: %v", err)
	}
	_, err = minter.MintAccessToken(context.Background(), MintRequest{GoogleAccount: "personal"})
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("missing credential error = %v, want ErrCredentialNotFound", err)
	}
	if err := store.Put(context.Background(), Credential{GoogleAccount: "personal"}); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	_, err = minter.MintAccessToken(context.Background(), MintRequest{GoogleAccount: "personal"})
	if err == nil || !strings.Contains(err.Error(), "missing refresh token") {
		t.Fatalf("missing refresh token error = %v", err)
	}
}

func TestOAuthHTTPErrorIncludesStructuredDescription(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"client_secret is missing"}`))
	}))
	defer server.Close()

	flow := NewOAuthFlow(OAuthFlowOptions{
		ClientID:      "desktop-client-id",
		TokenEndpoint: server.URL,
	})
	_, err := flow.exchangeCode(context.Background(), "auth-code", "http://127.0.0.1/callback", "verifier")
	if err == nil || !strings.Contains(err.Error(), "invalid_request: client_secret is missing") {
		t.Fatalf("exchangeCode error = %v", err)
	}
}

func TestHTTPErrorIncludesGoogleAPIMessage(t *testing.T) {
	t.Parallel()

	err := httpError("iamcredentials.googleapis.com", http.StatusForbidden, "application/json", []byte(`{
		"error": {
			"code": 403,
			"message": "The IAM Service Account Credentials API has not been used in project 123 before or it is disabled.",
			"status": "PERMISSION_DENIED"
		}
	}`))
	if err == nil ||
		!strings.Contains(err.Error(), "PERMISSION_DENIED") ||
		!strings.Contains(err.Error(), "has not been used in project 123") {
		t.Fatalf("httpError = %v, want nested Google API message", err)
	}
}

type staticOAuthRunner struct {
	token OAuthToken
	err   error
}

func (r staticOAuthRunner) Login(context.Context, OAuthLoginRequest) (OAuthToken, error) {
	return r.token, r.err
}

type memoryStore struct {
	mu         sync.Mutex
	credential map[string]Credential
}

func newMemoryStore() *memoryStore {
	return &memoryStore{credential: map[string]Credential{}}
}

func (s *memoryStore) Get(_ context.Context, account string) (Credential, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.credential[account]
	return credential, ok, nil
}

func (s *memoryStore) Put(_ context.Context, credential Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credential[credential.GoogleAccount] = credential
	return nil
}

func (s *memoryStore) Delete(_ context.Context, account string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.credential[account]
	delete(s.credential, account)
	return ok, nil
}

func (s *memoryStore) List(context.Context) ([]Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	credentials := make([]Credential, 0, len(s.credential))
	for _, credential := range s.credential {
		credentials = append(credentials, credential)
	}
	return credentials, nil
}

type errStore struct {
	err error
}

func (s errStore) Get(context.Context, string) (Credential, bool, error) {
	return Credential{}, false, s.err
}

func (s errStore) Put(context.Context, Credential) error {
	return s.err
}

func (s errStore) Delete(context.Context, string) (bool, error) {
	return false, s.err
}

func (s errStore) List(context.Context) ([]Credential, error) {
	return nil, s.err
}

type memoryKeychainBackend struct {
	mu      sync.Mutex
	items   map[string][]byte
	getErrs map[string]error
}

func newMemoryKeychainStore() (*memoryKeychainBackend, *KeychainStore) {
	backend := &memoryKeychainBackend{items: map[string][]byte{}, getErrs: map[string]error{}}
	store := &KeychainStore{
		service: "com.kovyrin.agent-secret.gcp.oauth.test",
		backend: keychainBackend{
			get:    backend.get,
			put:    backend.put,
			delete: backend.delete,
		},
	}
	return backend, store
}

func (b *memoryKeychainBackend) get(_ context.Context, service string, account string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := keychainTestKey(service, account)
	if err, ok := b.getErrs[key]; ok {
		return nil, err
	}
	raw, ok := b.items[key]
	if !ok {
		return nil, ErrCredentialNotFound
	}
	return slices.Clone(raw), nil
}

func (b *memoryKeychainBackend) put(_ context.Context, service string, account string, raw []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := keychainTestKey(service, account)
	delete(b.getErrs, key)
	b.items[key] = slices.Clone(raw)
	return nil
}

func (b *memoryKeychainBackend) delete(_ context.Context, service string, account string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := keychainTestKey(service, account)
	_, ok := b.items[key]
	delete(b.items, key)
	delete(b.getErrs, key)
	return ok, nil
}

func keychainTestKey(service string, account string) string {
	return service + "\x00" + account
}

func mustGCPAuthLogin(t *testing.T, googleAccount string, expectedEmail string) request.GCPAuthLoginRequest {
	t.Helper()
	req, err := request.NewGCPAuthLogin(request.GCPAuthLoginOptions{
		GoogleAccount: googleAccount,
		ExpectedEmail: expectedEmail,
	})
	if err != nil {
		t.Fatalf("NewGCPAuthLogin returned error: %v", err)
	}
	return req
}

func cloneValues(values url.Values) url.Values {
	out := make(url.Values, len(values))
	for key, list := range values {
		out[key] = slices.Clone(list)
	}
	return out
}
