package opresolver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDesktopPoolResolveRequiresRequestAccount(t *testing.T) {
	t.Parallel()

	pool := NewDesktopPool()
	_, err := pool.Resolve(context.Background(), "op://Example Vault/Item/password", " \t ")
	if !errors.Is(err, ErrAccountRequired) {
		t.Fatalf("Resolve error = %v, want ErrAccountRequired", err)
	}
}

func TestDesktopPoolInitializesDifferentAccountsConcurrently(t *testing.T) {
	t.Parallel()

	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	slowDone := make(chan error, 1)
	fastResolver := testDesktopResolver(t)
	slowResolver := testDesktopResolver(t)
	pool := testDesktopPoolWithFactory(func(ctx context.Context, opts ClientOptions) (*Resolver, error) {
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
		_, err := pool.client(context.Background(), "slow")
		slowDone <- err
	}()
	receiveSignal(t, slowStarted, "slow resolver initialization did not start")

	fastDone := make(chan error, 1)
	go func() {
		got, err := pool.client(context.Background(), "fast")
		if err == nil && got != fastResolver {
			err = fmt.Errorf("fast resolver = %p, want %p", got, fastResolver)
		}
		fastDone <- err
	}()
	receiveNoError(t, fastDone, "fast account initialization was blocked by slow account")

	close(releaseSlow)
	receiveNoError(t, slowDone, "slow account initialization failed")
}

func TestDesktopPoolCoalescesConcurrentSameAccountInitialization(t *testing.T) {
	t.Parallel()

	sharedStarted := make(chan struct{})
	releaseShared := make(chan struct{})
	sharedResolver := testDesktopResolver(t)
	var calls atomic.Int32
	pool := testDesktopPoolWithFactory(func(ctx context.Context, opts ClientOptions) (*Resolver, error) {
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
		got, err := pool.client(context.Background(), "shared")
		firstDone <- clientResult{resolver: got, err: err}
	}()
	receiveSignal(t, sharedStarted, "shared resolver initialization did not start")

	secondDone := make(chan clientResult, 1)
	go func() {
		got, err := pool.client(context.Background(), "shared")
		secondDone <- clientResult{resolver: got, err: err}
	}()

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

func TestDesktopPoolResolveReturnsSecretValue(t *testing.T) {
	t.Parallel()

	fake := &fakeSecretsAPI{value: "synthetic-secret-value"}
	var gotOptions ClientOptions
	pool := NewDesktopPoolWithOptions(DesktopPoolOptions{
		IntegrationName:    "test integration",
		IntegrationVersion: "test version",
		Factory: func(_ context.Context, opts ClientOptions) (*Resolver, error) {
			gotOptions = opts
			return NewResolver(fake)
		},
	})

	value, err := pool.Resolve(context.Background(), "op://Example Vault/Item/password", "override-account")
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if value != "synthetic-secret-value" {
		t.Fatalf("value = %q, want synthetic-secret-value", value)
	}
	if fake.ref != "op://Example Vault/Item/password" {
		t.Fatalf("resolved ref = %q, want input ref", fake.ref)
	}
	if gotOptions.Account != "override-account" {
		t.Fatalf("account = %q, want override-account", gotOptions.Account)
	}
	if gotOptions.IntegrationName != "test integration" || gotOptions.IntegrationVersion != "test version" {
		t.Fatalf("integration options were not preserved: %+v", gotOptions)
	}
}

func TestDesktopPoolResolveWrapsWaiterCancellationOnce(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	resolver := testDesktopResolver(t)
	var calls atomic.Int32
	pool := testDesktopPoolWithFactory(func(ctx context.Context, opts ClientOptions) (*Resolver, error) {
		if opts.Account != "shared" {
			return nil, fmt.Errorf("unexpected account %q", opts.Account)
		}
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
			return resolver, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	ownerDone := make(chan error, 1)
	go func() {
		_, err := pool.Resolve(context.Background(), "op://Example Vault/Item/password", "shared")
		ownerDone <- err
	}()
	receiveSignal(t, started, "shared resolver initialization did not start")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := pool.Resolve(ctx, "op://Example Vault/Item/password", "shared")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Resolve error = %v, want context canceled", err)
	}
	if got := strings.Count(err.Error(), "create 1Password resolver"); got != 1 {
		t.Fatalf("resolver creation context count = %d in %q, want 1", got, err)
	}

	close(release)
	receiveNoError(t, ownerDone, "owner resolver initialization failed")
	if got := calls.Load(); got != 1 {
		t.Fatalf("factory calls = %d, want 1", got)
	}
}

func TestWaitForDesktopPoolInitReturnsCompletedResult(t *testing.T) {
	t.Parallel()

	want := testDesktopResolver(t)
	init := &desktopPoolInit{done: make(chan struct{}), resolver: want}
	close(init.done)

	got, err := waitForDesktopPoolInit(context.Background(), init)
	if err != nil {
		t.Fatalf("waitForDesktopPoolInit returned error: %v", err)
	}
	if got != want {
		t.Fatalf("resolver = %p, want %p", got, want)
	}
}

func TestWaitForDesktopPoolInitReturnsContextError(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	init := &desktopPoolInit{done: make(chan struct{})}

	if _, err := waitForDesktopPoolInit(ctx, init); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForDesktopPoolInit error = %v, want context canceled", err)
	}
}

type clientResult struct {
	resolver *Resolver
	err      error
}

func testDesktopResolver(t *testing.T) *Resolver {
	t.Helper()

	resolver, err := NewResolver(&fakeSecretsAPI{value: "synthetic-secret-value"})
	if err != nil {
		t.Fatalf("NewResolver returned error: %v", err)
	}
	return resolver
}

func testDesktopPoolWithFactory(factory DesktopResolverFactory) *DesktopPool {
	return NewDesktopPoolWithOptions(DesktopPoolOptions{Factory: factory})
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

func receiveClientResult(t *testing.T, ch <-chan clientResult, message string) *Resolver {
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
