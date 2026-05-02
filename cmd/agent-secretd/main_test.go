package main

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/opresolver"
)

func TestParseDaemonConfigRejectsCallerSelectedTrustInputs(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"--approver", "/tmp/fake-approver.app"},
		{"--trusted-client", "/tmp/fake-agent-secret"},
	} {
		_, err := parseDaemonConfig(args)
		if err == nil {
			t.Fatalf("parseDaemonConfig(%v) returned nil error", args)
		}
		if !strings.Contains(err.Error(), "flag provided but not defined") {
			t.Fatalf("parseDaemonConfig(%v) error = %v, want unknown flag", args, err)
		}
	}
}

func TestParseDaemonConfigDoesNotReadApproverEnvironmentOverride(t *testing.T) {
	t.Setenv("AGENT_SECRET_APPROVER_PATH", "/tmp/fake-approver")

	if _, err := parseDaemonConfig([]string{}); err != nil {
		t.Fatalf("parseDaemonConfig returned error: %v", err)
	}
}

func TestNewResolverUsesDesktopResolverWithoutAccountOverride(t *testing.T) {
	t.Parallel()

	resolver := newResolver(" \t ")
	desktop, ok := resolver.(*desktopResolver)
	if !ok {
		t.Fatalf("resolver type = %T, want *desktopResolver", resolver)
	}
	if desktop.account != "" {
		t.Fatalf("account = %q, want resolver-level default account", desktop.account)
	}
}

func TestDesktopResolverEffectiveAccountUsesPerSecretOverride(t *testing.T) {
	t.Parallel()

	resolver, ok := newResolver("Fixture").(*desktopResolver)
	if !ok {
		t.Fatal("resolver is not a desktop resolver")
	}
	if account := resolver.effectiveAccount(" Preview "); account != "Preview" {
		t.Fatalf("account = %q, want Preview", account)
	}
	if account := resolver.effectiveAccount(" \t "); account != "Fixture" {
		t.Fatalf("account = %q, want Fixture", account)
	}
}

func TestDesktopResolverInitializesDifferentAccountsConcurrently(t *testing.T) {
	t.Parallel()

	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	slowDone := make(chan error, 1)
	fastResolver := testDesktopResolver(t)
	slowResolver := testDesktopResolver(t)
	resolver := testDesktopResolverWithFactory(func(ctx context.Context, opts opresolver.ClientOptions) (*opresolver.Resolver, error) {
		switch opts.Account {
		case "slow":
			close(slowStarted)
			select {
			case <-releaseSlow:
				return slowResolver, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		case "fast":
			return fastResolver, nil
		default:
			return nil, fmt.Errorf("unexpected account %q", opts.Account)
		}
	})

	go func() {
		_, err := resolver.client(context.Background(), "slow")
		slowDone <- err
	}()
	receiveSignal(t, slowStarted, "slow resolver initialization did not start")

	fastDone := make(chan error, 1)
	go func() {
		got, err := resolver.client(context.Background(), "fast")
		if err == nil && got != fastResolver {
			err = fmt.Errorf("fast resolver = %p, want %p", got, fastResolver)
		}
		fastDone <- err
	}()
	receiveNoError(t, fastDone, "fast account initialization was blocked by slow account")

	close(releaseSlow)
	receiveNoError(t, slowDone, "slow account initialization failed")
}

func TestDesktopResolverCoalescesConcurrentSameAccountInitialization(t *testing.T) {
	t.Parallel()

	sharedStarted := make(chan struct{})
	releaseShared := make(chan struct{})
	sharedResolver := testDesktopResolver(t)
	var calls atomic.Int32
	resolver := testDesktopResolverWithFactory(func(ctx context.Context, opts opresolver.ClientOptions) (*opresolver.Resolver, error) {
		if opts.Account != "shared" {
			return nil, fmt.Errorf("unexpected account %q", opts.Account)
		}
		if calls.Add(1) == 1 {
			close(sharedStarted)
		}
		select {
		case <-releaseShared:
			return sharedResolver, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	firstDone := make(chan clientResult, 1)
	go func() {
		got, err := resolver.client(context.Background(), "shared")
		firstDone <- clientResult{resolver: got, err: err}
	}()
	receiveSignal(t, sharedStarted, "shared resolver initialization did not start")

	secondDone := make(chan clientResult, 1)
	go func() {
		got, err := resolver.client(context.Background(), "shared")
		secondDone <- clientResult{resolver: got, err: err}
	}()

	select {
	case result := <-secondDone:
		t.Fatalf("second same-account initialization completed before first finished: %+v", result)
	case <-time.After(50 * time.Millisecond):
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("factory calls before release = %d, want 1", got)
	}

	close(releaseShared)
	first := receiveClientResult(t, firstDone, "first same-account initialization failed")
	second := receiveClientResult(t, secondDone, "second same-account initialization failed")
	if first != sharedResolver || second != sharedResolver {
		t.Fatalf("same-account resolvers = %p and %p, want %p", first, second, sharedResolver)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("factory calls = %d, want 1", got)
	}
}

type fakeSecretsAPI struct{}

func (fakeSecretsAPI) Resolve(_ context.Context, _ string) (string, error) {
	return "synthetic-secret-value", nil
}

type clientResult struct {
	resolver *opresolver.Resolver
	err      error
}

func testDesktopResolver(t *testing.T) *opresolver.Resolver {
	t.Helper()

	resolver, err := opresolver.NewResolver(fakeSecretsAPI{})
	if err != nil {
		t.Fatalf("NewResolver returned error: %v", err)
	}
	return resolver
}

func testDesktopResolverWithFactory(factory desktopResolverFactory) *desktopResolver {
	return &desktopResolver{
		clients:            make(map[string]*opresolver.Resolver),
		inits:              make(map[string]*desktopResolverInit),
		newDesktopResolver: factory,
	}
}

func receiveSignal(t *testing.T, ch <-chan struct{}, message string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}

func receiveNoError(t *testing.T, ch <-chan error, message string) {
	t.Helper()

	select {
	case err := <-ch:
		if err != nil {
			t.Fatalf("%s: %v", message, err)
		}
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}

func receiveClientResult(t *testing.T, ch <-chan clientResult, message string) *opresolver.Resolver {
	t.Helper()

	select {
	case result := <-ch:
		if result.err != nil {
			t.Fatalf("%s: %v", message, result.err)
		}
		return result.resolver
	case <-time.After(time.Second):
		t.Fatal(message)
	}
	return nil
}
