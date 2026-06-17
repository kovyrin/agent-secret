package request

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/fileidentity"
	"github.com/kovyrin/agent-secret/internal/peercred"
)

func TestNewSessionCreateDefaultsAndDaemonValidation(t *testing.T) {
	t.Parallel()

	dir := testResolvedDir(t)
	bin, identity := testExecutable(t, dir, "agent-secret")
	receivedAt := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)

	req, err := NewSessionCreate(SessionCreateOptions{
		Reason:             "  Run deployment workflow  ",
		Command:            []string{"agent-secret", "session", "create"},
		ResolvedExecutable: bin,
		ExecutableIdentity: identity,
		CWD:                dir,
		ReceivedAt:         receivedAt,
		Secrets: []SecretSpec{
			{Alias: "TOKEN", Ref: "op://Example Vault/Deploy/token", Account: " Work "},
		},
		OverrideEnv: true,
	})
	if err != nil {
		t.Fatalf("NewSessionCreate returned error: %v", err)
	}

	if req.Reason != "Run deployment workflow" {
		t.Fatalf("reason = %q", req.Reason)
	}
	if req.TTL != DefaultSessionTTL {
		t.Fatalf("ttl = %s, want %s", req.TTL, DefaultSessionTTL)
	}
	if req.MaxReads != DefaultSessionMaxReads {
		t.Fatalf("max reads = %d, want %d", req.MaxReads, DefaultSessionMaxReads)
	}
	if req.Binding.Mode != SessionBindingModeAuto ||
		req.Binding.AncestorDepth != 0 ||
		req.Binding.AncestorName != "" ||
		len(req.Binding.AncestorNames) != 0 {
		t.Fatalf("binding = %+v, want auto", req.Binding)
	}
	if !req.ExpiresAt.Equal(receivedAt.Add(DefaultSessionTTL)) {
		t.Fatalf("expires_at = %s, want %s", req.ExpiresAt, receivedAt.Add(DefaultSessionTTL))
	}
	if !req.OverrideEnv {
		t.Fatal("override env was not preserved")
	}
	if len(req.Secrets) != 1 || req.Secrets[0].Account != "Work" {
		t.Fatalf("secrets not parsed and normalized: %+v", req.Secrets)
	}

	received := req.WithReceiptTime(receivedAt.Add(time.Minute))
	if !received.ExpiresAt.Equal(received.ReceivedAt.Add(DefaultSessionTTL)) {
		t.Fatalf("WithReceiptTime expires_at = %s received_at = %s", received.ExpiresAt, received.ReceivedAt)
	}
	if received.Expired(received.ExpiresAt.Add(-time.Nanosecond)) || !received.Expired(received.ExpiresAt) {
		t.Fatalf("Expired boundary mismatch for expires_at %s", received.ExpiresAt)
	}
	if err := received.ValidateForDaemon(); err != nil {
		t.Fatalf("ValidateForDaemon returned error: %v", err)
	}
}

func TestNewSessionCreateAcceptsMaximumReadLimit(t *testing.T) {
	t.Parallel()

	dir := testResolvedDir(t)
	bin, identity := testExecutable(t, dir, "agent-secret")

	req, err := NewSessionCreate(SessionCreateOptions{
		Reason:             "Run long workflow",
		Command:            []string{"agent-secret", "session", "create"},
		ResolvedExecutable: bin,
		ExecutableIdentity: identity,
		CWD:                dir,
		MaxReads:           MaxSessionReads,
		Secrets: []SecretSpec{
			{Alias: "TOKEN", Ref: "op://Example Vault/Deploy/token", Account: "Work"},
		},
	})
	if err != nil {
		t.Fatalf("NewSessionCreate returned error: %v", err)
	}
	if req.MaxReads != MaxSessionReads {
		t.Fatalf("max reads = %d, want %d", req.MaxReads, MaxSessionReads)
	}
}

func TestNewSessionCreateRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	dir := testResolvedDir(t)
	bin, identity := testExecutable(t, dir, "agent-secret")
	base := SessionCreateOptions{
		Reason:             "Deploy",
		Command:            []string{"agent-secret", "session", "create"},
		ResolvedExecutable: bin,
		ExecutableIdentity: identity,
		CWD:                dir,
		Secrets: []SecretSpec{
			{Alias: "TOKEN", Ref: "op://Example Vault/Deploy/token", Account: "Work"},
		},
	}

	tests := []struct {
		name   string
		mutate func(*SessionCreateOptions)
		want   error
	}{
		{name: "missing reason", mutate: func(o *SessionCreateOptions) { o.Reason = "" }, want: ErrInvalidReason},
		{name: "short ttl", mutate: func(o *SessionCreateOptions) { o.TTL = time.Second }, want: ErrInvalidTTL},
		{name: "too many reads", mutate: func(o *SessionCreateOptions) { o.MaxReads = MaxSessionReads + 1 }, want: ErrInvalidSessionRead},
		{name: "missing cwd", mutate: func(o *SessionCreateOptions) { o.CWD = "" }, want: ErrInvalidRequest},
		{name: "missing executable", mutate: func(o *SessionCreateOptions) { o.ResolvedExecutable = "" }, want: ErrInvalidRequest},
		{name: "missing executable identity", mutate: func(o *SessionCreateOptions) { o.ExecutableIdentity = fileidentity.Identity{} }, want: ErrInvalidRequest},
		{name: "missing command", mutate: func(o *SessionCreateOptions) { o.Command = nil }, want: ErrInvalidCommand},
		{name: "bad secret", mutate: func(o *SessionCreateOptions) { o.Secrets[0].Alias = "token" }, want: ErrInvalidAlias},
		{name: "bad bind depth", mutate: func(o *SessionCreateOptions) {
			o.Binding = SessionBindingPolicy{Mode: SessionBindingModeAncestor, AncestorDepth: MaxSessionBindAncestor + 1}
		}, want: ErrInvalidSessionBind},
		{name: "bad bind name", mutate: func(o *SessionCreateOptions) {
			o.Binding = SessionBindingPolicy{Mode: SessionBindingModeAncestorName, AncestorName: "/bin/zsh"}
		}, want: ErrInvalidSessionBind},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := base
			opts.Command = append([]string(nil), base.Command...)
			opts.Secrets = append([]SecretSpec(nil), base.Secrets...)
			tt.mutate(&opts)
			_, err := NewSessionCreate(opts)
			if !errors.Is(err, tt.want) {
				t.Fatalf("NewSessionCreate error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestSessionBindingPolicyValidation(t *testing.T) {
	t.Parallel()

	parent, err := NewSessionAncestorBinding(1)
	if err != nil {
		t.Fatalf("NewSessionAncestorBinding returned error: %v", err)
	}
	if parent.Mode != SessionBindingModeAncestor || parent.AncestorDepth != 1 {
		t.Fatalf("parent binding = %+v", parent)
	}
	named, err := NewSessionAncestorNameBinding(" Codex ")
	if err != nil {
		t.Fatalf("NewSessionAncestorNameBinding returned error: %v", err)
	}
	if named.Mode != SessionBindingModeAncestorName || named.AncestorName != "Codex" || named.AncestorDepth != 0 {
		t.Fatalf("named binding = %+v", named)
	}
	if !slices.Equal(named.AncestorNames, []string{"Codex"}) {
		t.Fatalf("named ancestor names = %v, want [Codex]", named.AncestorNames)
	}

	names, err := NewSessionAncestorNamesBinding([]string{" claude ", "Codex", "claude"})
	if err != nil {
		t.Fatalf("NewSessionAncestorNamesBinding returned error: %v", err)
	}
	if names.Mode != SessionBindingModeAncestorName ||
		names.AncestorName != "" ||
		!slices.Equal(names.AncestorNames, []string{"claude", "Codex"}) {
		t.Fatalf("names binding = %+v, want ordered deduplicated allowlist", names)
	}

	tests := []struct {
		name   string
		policy SessionBindingPolicy
	}{
		{name: "zero ancestor", policy: SessionBindingPolicy{Mode: SessionBindingModeAncestor}},
		{name: "too deep ancestor", policy: SessionBindingPolicy{Mode: SessionBindingModeAncestor, AncestorDepth: MaxSessionBindAncestor + 1}},
		{name: "auto with depth", policy: SessionBindingPolicy{Mode: SessionBindingModeAuto, AncestorDepth: 1}},
		{name: "auto with name", policy: SessionBindingPolicy{Mode: SessionBindingModeAuto, AncestorName: "Codex"}},
		{name: "auto with names", policy: SessionBindingPolicy{Mode: SessionBindingModeAuto, AncestorNames: []string{"Codex"}}},
		{name: "ancestor with name", policy: SessionBindingPolicy{Mode: SessionBindingModeAncestor, AncestorDepth: 1, AncestorName: "Codex"}},
		{name: "ancestor with names", policy: SessionBindingPolicy{Mode: SessionBindingModeAncestor, AncestorDepth: 1, AncestorNames: []string{"Codex"}}},
		{name: "ancestor name with depth", policy: SessionBindingPolicy{Mode: SessionBindingModeAncestorName, AncestorDepth: 1, AncestorName: "Codex"}},
		{name: "empty ancestor name", policy: SessionBindingPolicy{Mode: SessionBindingModeAncestorName}},
		{name: "path ancestor name", policy: SessionBindingPolicy{Mode: SessionBindingModeAncestorName, AncestorName: "/bin/zsh"}},
		{name: "path ancestor names entry", policy: SessionBindingPolicy{Mode: SessionBindingModeAncestorName, AncestorNames: []string{"zsh", "/bin/bash"}}},
		{name: "too many ancestor names", policy: SessionBindingPolicy{Mode: SessionBindingModeAncestorName, AncestorNames: repeatedStrings("zsh", MaxSessionBindNames+1)}},
		{name: "single name not in names", policy: SessionBindingPolicy{Mode: SessionBindingModeAncestorName, AncestorName: "zsh", AncestorNames: []string{"bash"}}},
		{name: "dot ancestor name", policy: SessionBindingPolicy{Mode: SessionBindingModeAncestorName, AncestorName: "."}},
		{name: "long ancestor name", policy: SessionBindingPolicy{Mode: SessionBindingModeAncestorName, AncestorName: strings.Repeat("a", MaxSessionBindNameLen+1)}},
		{name: "unknown mode", policy: SessionBindingPolicy{Mode: "pid", AncestorDepth: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := NormalizeSessionBindingPolicy(tt.policy); !errors.Is(err, ErrInvalidSessionBind) {
				t.Fatalf("NormalizeSessionBindingPolicy error = %v, want ErrInvalidSessionBind", err)
			}
		})
	}
}

func repeatedStrings(value string, count int) []string {
	values := make([]string, count)
	for i := range values {
		values[i] = value
	}
	return values
}

func TestSessionResolveValidation(t *testing.T) {
	t.Parallel()

	dir := testResolvedDir(t)
	bin, identity := testExecutable(t, dir, "terraform")
	env := []string{"PATH=" + filepath.Dir(bin), "TOKEN=existing"}

	req, err := NewSessionResolve(
		"astok_abc123",
		[]string{bin, "plan"},
		bin,
		identity,
		dir,
		EnvironmentFingerprint(env),
	)
	if err != nil {
		t.Fatalf("NewSessionResolve returned error: %v", err)
	}
	expected := peercred.Expected{
		UID:            501,
		GID:            20,
		PID:            12345,
		ExecutablePath: bin,
		CWD:            dir,
	}
	req = req.WithExpectedPeer(expected)
	req, err = req.WithRequestedAliases([]string{" B_TOKEN ", "A_TOKEN"})
	if err != nil {
		t.Fatalf("WithRequestedAliases returned error: %v", err)
	}
	if req.ExpectedPeer != expected {
		t.Fatalf("expected peer not applied: %+v", req.ExpectedPeer)
	}
	if !slices.Equal(req.RequestedAliases, []string{"A_TOKEN", "B_TOKEN"}) {
		t.Fatalf("requested aliases = %v, want sorted subset", req.RequestedAliases)
	}
	if err := req.ValidateForDaemon(); err != nil {
		t.Fatalf("ValidateForDaemon returned error: %v", err)
	}
}

func TestSessionResolveRejectsInvalidRequestedAliases(t *testing.T) {
	t.Parallel()

	dir := testResolvedDir(t)
	bin, identity := testExecutable(t, dir, "terraform")
	req, err := NewSessionResolve(
		"astok_abc123",
		[]string{bin, "plan"},
		bin,
		identity,
		dir,
		EnvironmentFingerprint([]string{"PATH=" + filepath.Dir(bin)}),
	)
	if err != nil {
		t.Fatalf("NewSessionResolve returned error: %v", err)
	}
	if _, err := req.WithRequestedAliases([]string{"TOKEN", "TOKEN"}); !errors.Is(err, ErrInvalidAlias) {
		t.Fatalf("WithRequestedAliases duplicate error = %v, want ErrInvalidAlias", err)
	}

	expected := peercred.Expected{
		UID:            501,
		GID:            20,
		PID:            12345,
		ExecutablePath: bin,
		CWD:            dir,
	}
	req = req.WithExpectedPeer(expected)
	req.RequestedAliases = []string{"B_TOKEN", "A_TOKEN"}
	if err := req.ValidateForDaemon(); !errors.Is(err, ErrInvalidAlias) {
		t.Fatalf("ValidateForDaemon unsorted aliases error = %v, want ErrInvalidAlias", err)
	}
}

func TestSessionResolveRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	dir := testResolvedDir(t)
	bin, identity := testExecutable(t, dir, "terraform")
	fingerprint := EnvironmentFingerprint([]string{"PATH=" + filepath.Dir(bin)})

	tests := []struct {
		name         string
		sessionToken string
		command      []string
		exe          string
		identity     fileidentity.Identity
		cwd          string
		env          string
		want         error
	}{
		{name: "bad session token", sessionToken: "session_abc", command: []string{bin}, exe: bin, identity: identity, cwd: dir, env: fingerprint, want: ErrInvalidSessionToken},
		{name: "session id is not a token", sessionToken: "asid_abc", command: []string{bin}, exe: bin, identity: identity, cwd: dir, env: fingerprint, want: ErrInvalidSessionToken},
		{name: "missing command", sessionToken: "astok_abc", command: nil, exe: bin, identity: identity, cwd: dir, env: fingerprint, want: ErrInvalidCommand},
		{name: "relative cwd", sessionToken: "astok_abc", command: []string{bin}, exe: bin, identity: identity, cwd: "deploy", env: fingerprint, want: ErrInvalidRequest},
		{name: "relative executable", sessionToken: "astok_abc", command: []string{bin}, exe: "terraform", identity: identity, cwd: dir, env: fingerprint, want: ErrInvalidRequest},
		{name: "missing identity", sessionToken: "astok_abc", command: []string{bin}, exe: bin, identity: fileidentity.Identity{}, cwd: dir, env: fingerprint, want: ErrInvalidRequest},
		{name: "bad env fingerprint", sessionToken: "astok_abc", command: []string{bin}, exe: bin, identity: identity, cwd: dir, env: "sha256:bad", want: ErrInvalidRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewSessionResolve(tt.sessionToken, tt.command, tt.exe, tt.identity, tt.cwd, tt.env)
			if !errors.Is(err, tt.want) {
				t.Fatalf("NewSessionResolve error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestSessionResolveDaemonValidationRejectsMissingPeerMetadata(t *testing.T) {
	t.Parallel()

	dir := testResolvedDir(t)
	bin, identity := testExecutable(t, dir, "terraform")
	req, err := NewSessionResolve(
		"astok_abc",
		[]string{bin},
		bin,
		identity,
		dir,
		EnvironmentFingerprint([]string{"PATH=" + filepath.Dir(bin)}),
	)
	if err != nil {
		t.Fatalf("NewSessionResolve returned error: %v", err)
	}
	err = req.ValidateForDaemon()
	if !errors.Is(err, ErrInvalidRequest) || !strings.Contains(err.Error(), "expected peer metadata") {
		t.Fatalf("ValidateForDaemon error = %v, want missing peer metadata", err)
	}
}

func TestSessionDestroyValidation(t *testing.T) {
	t.Parallel()

	req, err := NewSessionDestroy("asid_abc123")
	if err != nil {
		t.Fatalf("NewSessionDestroy returned error: %v", err)
	}
	if req.SessionID != "asid_abc123" {
		t.Fatalf("session id = %q", req.SessionID)
	}
	if err := req.ValidateForDaemon(); err != nil {
		t.Fatalf("ValidateForDaemon returned error: %v", err)
	}
	if err := ValidateSessionID("asid_abc-DEF_123"); err != nil {
		t.Fatalf("ValidateSessionID returned error: %v", err)
	}
	if err := ValidateSessionToken("astok_abc-DEF_123"); err != nil {
		t.Fatalf("ValidateSessionToken returned error: %v", err)
	}
	if err := ValidateSessionID("astok_abc-DEF_123"); !errors.Is(err, ErrInvalidSessionID) {
		t.Fatalf("ValidateSessionID with token error = %v, want ErrInvalidSessionID", err)
	}
	all := NewSessionDestroyAll()
	if !all.All || all.SessionID != "" {
		t.Fatalf("destroy all request = %+v", all)
	}
	if err := all.ValidateForDaemon(); err != nil {
		t.Fatalf("destroy all ValidateForDaemon returned error: %v", err)
	}
	if err := (SessionDestroyRequest{SessionID: "asid_abc123", All: true}).ValidateForDaemon(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("destroy all with id error = %v, want ErrInvalidRequest", err)
	}
	_, err = NewSessionDestroy("bad")
	if !errors.Is(err, ErrInvalidSessionID) {
		t.Fatalf("NewSessionDestroy error = %v, want ErrInvalidSessionID", err)
	}
}
