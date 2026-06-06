package bwsm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestKeychainStorePutGetListDelete(t *testing.T) {
	t.Parallel()

	backend := newMemoryKeychainBackend()
	store := NewKeychainStore("test.service")
	store.backend = backend.backend()
	store.now = func() time.Time { return time.Date(2026, 6, 6, 1, 2, 3, 0, time.UTC) }

	ctx := context.Background()
	if err := store.Put(ctx, Token{Alias: "work", AccessToken: "synthetic-token"}); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	token, found, err := store.Get(ctx, "work")
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if !found {
		t.Fatal("Get found=false")
	}
	if token.Alias != "work" || token.AccessToken != "synthetic-token" {
		t.Fatalf("token = %#v", token)
	}
	aliases, err := ListAliases(ctx, store)
	if err != nil {
		t.Fatalf("ListAliases returned error: %v", err)
	}
	if len(aliases) != 1 || aliases[0] != "work" {
		t.Fatalf("aliases = %v", aliases)
	}
	deleted, err := store.Delete(ctx, "work")
	if err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}
	if !deleted {
		t.Fatal("Delete deleted=false")
	}
	if _, found, err := store.Get(ctx, "work"); err != nil || found {
		t.Fatalf("Get after delete found=%v err=%v", found, err)
	}
}

func TestKeychainStoreRejectsInvalidAliasAndEmptyToken(t *testing.T) {
	t.Parallel()

	store := NewKeychainStore("test.service")
	store.backend = newMemoryKeychainBackend().backend()
	ctx := context.Background()
	if err := store.Put(ctx, Token{Alias: "bad alias", AccessToken: "synthetic-token"}); !errors.Is(err, ErrInvalidTokenAlias) {
		t.Fatalf("invalid alias error = %v", err)
	}
	if err := store.Put(ctx, Token{Alias: "work", AccessToken: " \n "}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("empty token error = %v", err)
	}
}

func TestKeychainStoreDefaultsServiceAndPreservesCreatedAt(t *testing.T) {
	t.Parallel()

	backend := newMemoryKeychainBackend()
	store := NewKeychainStore(" \t ")
	store.backend = backend.backend()
	if store.service != DefaultKeychainService {
		t.Fatalf("service = %q, want default", store.service)
	}

	firstTime := time.Date(2026, 6, 6, 1, 2, 3, 0, time.UTC)
	secondTime := firstTime.Add(time.Hour)
	store.now = func() time.Time { return firstTime }
	if err := store.Put(context.Background(), Token{Alias: "work", AccessToken: "first"}); err != nil {
		t.Fatalf("first Put returned error: %v", err)
	}
	store.now = func() time.Time { return secondTime }
	if err := store.Put(context.Background(), Token{Alias: "work", AccessToken: "second"}); err != nil {
		t.Fatalf("second Put returned error: %v", err)
	}
	token, found, err := store.Get(context.Background(), "work")
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if !found {
		t.Fatal("Get found=false")
	}
	if !token.CreatedAt.Equal(firstTime) || !token.UpdatedAt.Equal(secondTime) {
		t.Fatalf("token times = created %s updated %s", token.CreatedAt, token.UpdatedAt)
	}
}

func TestKeychainStoreRepairsInaccessibleIndex(t *testing.T) {
	t.Parallel()

	backend := newMemoryKeychainBackend()
	store := NewKeychainStore("test.service")
	store.backend = backend.backend()
	deletedIndex := false
	store.backend.get = func(ctx context.Context, service string, account string) ([]byte, error) {
		if account == keychainIndexAccount {
			return nil, ErrKeychainAccess
		}
		return backend.get(ctx, service, account)
	}
	store.backend.delete = func(ctx context.Context, service string, account string) (bool, error) {
		if account == keychainIndexAccount {
			deletedIndex = true
			return true, nil
		}
		return backend.delete(ctx, service, account)
	}

	err := store.Put(context.Background(), Token{Alias: "work", AccessToken: "synthetic-token"})
	if err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	if !deletedIndex {
		t.Fatal("Put did not delete inaccessible index")
	}
}

func TestKeychainStorePutAllowingUserInteractionUsesInteractiveWrites(t *testing.T) {
	t.Parallel()

	backend := newMemoryKeychainBackend()
	store := NewKeychainStore("test.service")
	store.backend = backend.backend()
	var normalPuts []string
	var interactivePuts []string
	store.backend.put = func(ctx context.Context, service string, account string, value []byte) error {
		normalPuts = append(normalPuts, account)
		return backend.put(ctx, service, account, value)
	}
	store.backend.putInteractive = func(ctx context.Context, service string, account string, value []byte) error {
		interactivePuts = append(interactivePuts, account)
		return backend.put(ctx, service, account, value)
	}

	err := store.PutAllowingUserInteraction(context.Background(), Token{Alias: "work", AccessToken: "synthetic-token"})
	if err != nil {
		t.Fatalf("PutAllowingUserInteraction returned error: %v", err)
	}
	if len(normalPuts) != 0 {
		t.Fatalf("normal writes = %v, want none", normalPuts)
	}
	wantInteractive := []string{"work", keychainIndexAccount}
	if strings.Join(interactivePuts, ",") != strings.Join(wantInteractive, ",") {
		t.Fatalf("interactive writes = %v, want %v", interactivePuts, wantInteractive)
	}
}

func TestKeychainStorePutAllowingUserInteractionReplacesInaccessibleIndex(t *testing.T) {
	t.Parallel()

	backend := newMemoryKeychainBackend()
	store := NewKeychainStore("test.service")
	store.backend = backend.backend()
	store.backend.get = func(ctx context.Context, service string, account string) ([]byte, error) {
		if account == keychainIndexAccount {
			return nil, ErrKeychainAccess
		}
		return backend.get(ctx, service, account)
	}
	store.backend.delete = func(context.Context, string, string) (bool, error) {
		return false, errors.New("non-interactive delete should not be used")
	}

	err := store.PutAllowingUserInteraction(context.Background(), Token{Alias: "work", AccessToken: "synthetic-token"})
	if err != nil {
		t.Fatalf("PutAllowingUserInteraction returned error: %v", err)
	}
}

func TestKeychainStoreRepairsInaccessibleToken(t *testing.T) {
	t.Parallel()

	backend := newMemoryKeychainBackend()
	store := NewKeychainStore("test.service")
	store.backend = backend.backend()
	store.backend.get = func(ctx context.Context, service string, account string) ([]byte, error) {
		if account == "work" {
			return nil, ErrKeychainAccess
		}
		return backend.get(ctx, service, account)
	}

	err := store.Put(context.Background(), Token{Alias: "work", AccessToken: "synthetic-token"})
	if err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	raw, err := backend.get(context.Background(), store.service, "work")
	if err != nil {
		t.Fatalf("stored token not written: %v", err)
	}
	if !strings.Contains(string(raw), "synthetic-token") {
		t.Fatalf("stored token JSON = %s, want replacement token", raw)
	}
}

func TestKeychainStorePropagatesBackendAndDecodeErrors(t *testing.T) {
	t.Parallel()

	backend := newMemoryKeychainBackend()
	store := NewKeychainStore("test.service")
	store.backend = backend.backend()
	ctx := context.Background()
	if err := backend.put(ctx, store.service, "work", []byte("not-json")); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	if _, _, err := store.Get(ctx, "work"); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("Get invalid json error = %v", err)
	}
	if err := backend.put(ctx, store.service, keychainIndexAccount, []byte("not-json")); err != nil {
		t.Fatalf("seed index: %v", err)
	}
	if _, err := store.List(ctx); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("List invalid index error = %v", err)
	}

	backendErr := errors.New("backend unavailable")
	store.backend.get = func(context.Context, string, string) ([]byte, error) {
		return nil, backendErr
	}
	if _, _, err := store.Get(ctx, "work"); !errors.Is(err, backendErr) {
		t.Fatalf("Get backend error = %v, want %v", err, backendErr)
	}
}

func TestKeychainStatusErrors(t *testing.T) {
	t.Parallel()

	for _, status := range []int{
		keychainStatusUserCanceled,
		keychainStatusAuthFailed,
		keychainStatusInteractionNotAllowed,
		keychainStatusUserInteractionRequired,
	} {
		err := keychainStatusErrorFromStatus("read", status)
		if !errors.Is(err, ErrKeychainAccess) {
			t.Fatalf("status %d error = %v, want ErrKeychainAccess", status, err)
		}
		if !strings.Contains(err.Error(), "token install") {
			t.Fatalf("status %d repair guidance = %v", status, err)
		}
		if !isKeychainInteractionStatus(status) {
			t.Fatalf("status %d was not recognized as interactive", status)
		}
	}

	err := keychainStatusErrorFromStatus("read", -1)
	if errors.Is(err, ErrKeychainAccess) || !strings.Contains(err.Error(), "OSStatus -1") {
		t.Fatalf("non-interaction status error = %v", err)
	}
	if isKeychainInteractionStatus(-1) {
		t.Fatal("non-interaction status recognized as interactive")
	}
}

type memoryKeychainBackend struct {
	values map[string][]byte
}

func newMemoryKeychainBackend() *memoryKeychainBackend {
	return &memoryKeychainBackend{values: make(map[string][]byte)}
}

func (b *memoryKeychainBackend) backend() keychainBackend {
	return keychainBackend{
		get:            b.get,
		put:            b.put,
		putInteractive: b.put,
		delete:         b.delete,
	}
}

func (b *memoryKeychainBackend) get(_ context.Context, service string, account string) ([]byte, error) {
	value, ok := b.values[service+"\x00"+account]
	if !ok {
		return nil, ErrTokenNotFound
	}
	return append([]byte(nil), value...), nil
}

func (b *memoryKeychainBackend) put(_ context.Context, service string, account string, value []byte) error {
	b.values[service+"\x00"+account] = append([]byte(nil), value...)
	return nil
}

func (b *memoryKeychainBackend) delete(_ context.Context, service string, account string) (bool, error) {
	key := service + "\x00" + account
	if _, ok := b.values[key]; !ok {
		return false, nil
	}
	delete(b.values, key)
	return true, nil
}
