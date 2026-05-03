package opresolver

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewDesktopPoolUsesDesktopResolverWithoutAccountOverride(t *testing.T) {
	t.Parallel()

	pool := NewDesktopPool(" \t ")
	if pool.account != "" {
		t.Fatalf("account = %q, want resolver-level default account", pool.account)
	}
}

func TestDesktopPoolEffectiveAccountUsesPerSecretOverride(t *testing.T) {
	t.Parallel()

	pool := NewDesktopPool("Fixture")
	if account := pool.effectiveAccount(" Preview "); account != "Preview" {
		t.Fatalf("account = %q, want Preview", account)
	}
	if account := pool.effectiveAccount(" \t "); account != "Fixture" {
		t.Fatalf("account = %q, want Fixture", account)
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
