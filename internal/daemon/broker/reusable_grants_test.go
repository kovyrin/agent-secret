package broker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/policy"
	"github.com/kovyrin/agent-secret/internal/request"
	"github.com/kovyrin/agent-secret/internal/secretcache"
)

func TestBrokerReusableApprovalUsesCacheAndForceRefreshRefetches(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	approver := &mockApprover{decision: approval.Decision{Approved: true, Reusable: true, ReusableUses: 4}}
	resolver := &mockResolver{values: map[string]string{ref: "first"}}
	aud := &memoryAudit{}
	cache := secretcache.NewSecretCache()
	broker := newTestBroker(t, Options{Approver: approver, Resolver: resolver, Audit: aud, Cache: cache})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	req.ReusableUses = 4

	first, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("first deliverExec returned error: %v", err)
	}
	if first.approvalID == "" {
		t.Fatal("expected reusable approval id")
	}
	requireActiveRequest(t, broker, testCorrelation("req_1", "nonce_1"))

	resolver.values[ref] = "second"
	second, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_2", "nonce_2"), req)
	if err != nil {
		t.Fatalf("second deliverExec returned error: %v", err)
	}
	if second.Env["TOKEN"] != "first" {
		t.Fatalf("reusable approval did not use cached value: %+v", second.Env)
	}
	if len(resolver.Calls()) != 1 {
		t.Fatalf("cached reusable approval refetched without force-refresh: %v", resolver.Calls())
	}
	reuseEvent, ok := singleAuditEvent(aud.Events(), audit.EventApprovalReused)
	if !ok {
		t.Fatalf("expected one approval_reused audit event, got %+v", aud.Events())
	}
	if reuseEvent.ApprovalID != first.approvalID {
		t.Fatalf("approval_reused approval id = %q, want %q", reuseEvent.ApprovalID, first.approvalID)
	}
	if reuseEvent.RemainingUses == nil || *reuseEvent.RemainingUses != 3 {
		t.Fatalf("approval_reused remaining uses = %v, want 3", reuseEvent.RemainingUses)
	}
	requireActiveRequest(t, broker, testCorrelation("req_2", "nonce_2"))

	force := req
	force.ForceRefresh = true
	third, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_3", "nonce_3"), force)
	if err != nil {
		t.Fatalf("force-refresh deliverExec returned error: %v", err)
	}
	if third.Env["TOKEN"] != "second" {
		t.Fatalf("force refresh did not update cached value: %+v", third.Env)
	}
	if value, ok := cache.Get(secretcache.CacheKey{ScopeID: first.approvalID, Ref: ref}); !ok || value != "second" {
		t.Fatalf("force refresh cache value = %q, %v; want second, true", value, ok)
	}
	if len(resolver.Calls()) != 2 {
		t.Fatalf("force-refresh did not refetch once: %v", resolver.Calls())
	}
	events := aud.Events()
	if !containsAuditEvent(events, audit.EventApprovalRefreshed) {
		t.Fatalf("force-refresh did not emit refresh audit event: %+v", events)
	}
}

func TestBrokerReuseOnlyUsesExistingApprovalOrFailsWithoutPrompt(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	approver := &mockApprover{decision: approval.Decision{Approved: true, Reusable: true, ReusableUses: 3}}
	resolver := &mockResolver{values: map[string]string{ref: "first"}}
	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{Approver: approver, Resolver: resolver, Audit: aud})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	reuseOnly := req
	reuseOnly.ReuseOnly = true
	if _, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), reuseOnly); !errors.Is(err, ErrNoReusableApproval) {
		t.Fatalf("reuse-only without match error = %v, want ErrNoReusableApproval", err)
	}
	if approver.calls != 0 {
		t.Fatalf("reuse-only miss opened approval prompt; calls = %d", approver.calls)
	}
	if len(resolver.Calls()) != 0 {
		t.Fatalf("reuse-only miss resolved secrets: %v", resolver.Calls())
	}
	if !containsAuditEvent(aud.Events(), audit.EventApprovalReuseMissed) {
		t.Fatalf("reuse-only miss did not emit audit event: %+v", aud.Events())
	}

	first, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_2", "nonce_2"), req)
	if err != nil {
		t.Fatalf("normal reusable approval returned error: %v", err)
	}
	if first.approvalID == "" {
		t.Fatal("expected reusable approval id")
	}
	resolver.values[ref] = "second"
	second, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_3", "nonce_3"), reuseOnly)
	if err != nil {
		t.Fatalf("reuse-only match returned error: %v", err)
	}
	if second.Env["TOKEN"] != "first" {
		t.Fatalf("reuse-only did not use cached value: %+v", second.Env)
	}
	if approver.calls != 1 {
		t.Fatalf("reuse-only match opened another approval prompt; calls = %d", approver.calls)
	}
}

func TestBrokerReusableApprovalUsesApprovedUseLimit(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	approver := &mockApprover{decision: approval.Decision{Approved: true, Reusable: true, ReusableUses: 2}}
	resolver := &mockResolver{values: map[string]string{ref: "first"}}
	cache := secretcache.NewSecretCache()
	broker := newTestBroker(t, Options{
		Approver: approver,
		Resolver: resolver,
		Audit:    &memoryAudit{},
		Cache:    cache,
	})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	req.ReusableUses = 2

	first, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("first deliverExec returned error: %v", err)
	}
	if first.approvalID == "" {
		t.Fatal("expected reusable approval id")
	}
	requireActiveRequest(t, broker, testCorrelation("req_1", "nonce_1"))

	resolver.values[ref] = "second"
	second, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_2", "nonce_2"), req)
	if err != nil {
		t.Fatalf("second deliverExec returned error: %v", err)
	}
	if second.Env["TOKEN"] != "first" {
		t.Fatalf("second delivery did not reuse cached first value: %+v", second.Env)
	}
	requireActiveRequest(t, broker, testCorrelation("req_2", "nonce_2"))
	if _, ok := cache.Get(secretcache.CacheKey{ScopeID: first.approvalID, Ref: ref}); ok {
		t.Fatal("two-use approval cache scope remained after two deliveries")
	}

	third, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_3", "nonce_3"), req)
	if err != nil {
		t.Fatalf("third deliverExec returned error: %v", err)
	}
	if third.Env["TOKEN"] != "second" {
		t.Fatalf("fresh approval after exhaustion used stale value: %+v", third.Env)
	}
	if third.approvalID == first.approvalID {
		t.Fatalf("fresh approval reused exhausted approval id %q", first.approvalID)
	}
	if approver.calls != 2 {
		t.Fatalf("approver calls = %d, want fresh approval after two deliveries", approver.calls)
	}
}

func TestBrokerReservesReusableUseBeforePayloadDelivery(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	approver := &mockApprover{decision: approval.Decision{Approved: true, Reusable: true, ReusableUses: 2}}
	resolver := &mockResolver{values: map[string]string{ref: "first"}}
	broker := newTestBroker(t, Options{
		Approver: approver,
		Resolver: resolver,
		Audit:    &memoryAudit{},
		Cache:    secretcache.NewSecretCache(),
	})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	req.ReusableUses = 2

	first, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("first deliverExec returned error: %v", err)
	}
	requireActiveRequest(t, broker, testCorrelation("req_1", "nonce_1"))

	second, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_2", "nonce_2"), req)
	if err != nil {
		t.Fatalf("second deliverExec returned error: %v", err)
	}
	if second.approvalID != first.approvalID {
		t.Fatalf(
			"second approval id = %q, want reusable approval %q",
			second.approvalID,
			first.approvalID,
		)
	}
	if second.Env["TOKEN"] != "first" {
		t.Fatalf("second delivery did not reuse cached first value: %+v", second.Env)
	}

	approver.decision = approval.Decision{Approved: false}
	_, err = deliverExecForTest(context.Background(), broker, testCorrelation("req_3", "nonce_3"), req)
	if !errors.Is(err, approval.ErrApprovalDenied) {
		t.Fatalf("third deliverExec reused a reserved one-use approval; got %v", err)
	}
	if approver.calls != 2 {
		t.Fatalf("approver calls = %d, want fresh approval after reserved use exhausted cache availability", approver.calls)
	}

	requireActiveRequest(t, broker, testCorrelation("req_2", "nonce_2"))
}

func TestReusableGrantManagerPropagatesInvalidDeliveryResult(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	store := policy.NewStore(func() time.Time { return now })
	manager := newReusableGrantManager(
		func() time.Time { return now },
		store,
		secretcache.NewSecretCache(),
		nil,
	)
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token"}})
	approval, err := store.AddReusable(policy.ReusableApprovalSpec{
		Request:      req,
		ID:           "appr_1",
		Nonce:        "nonce_1",
		ReservedUses: 1,
	})
	if err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}

	err = manager.finishDelivery(approval.ID, policy.DeliveryResult("unknown"))
	if !errors.Is(err, policy.ErrInvalidDeliveryResult) {
		t.Fatalf("finishDelivery invalid result error = %v, want invalid delivery result", err)
	}
}

func TestBrokerClearsReusableCacheOnExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	ref := "op://Example/Item/token"
	cache := secretcache.NewSecretCache()
	resolver := &mockResolver{values: map[string]string{ref: "first"}}
	approver := &mockApprover{decision: approval.Decision{Approved: true, Reusable: true}}
	broker, err := New(Options{
		Now:      func() time.Time { return now },
		Cache:    cache,
		Approver: approver,
		Resolver: resolver,
		Audit:    &memoryAudit{},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	first, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("first deliverExec returned error: %v", err)
	}
	requireActiveRequest(t, broker, testCorrelation("req_1", "nonce_1"))
	if _, ok := cache.Get(secretcache.CacheKey{ScopeID: first.approvalID, Ref: ref}); !ok {
		t.Fatal("expected first reusable value in cache")
	}

	now = req.ExpiresAt.Add(time.Second)
	resolver.values[ref] = "second"
	next := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	second, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_2", "nonce_2"), next)
	if err != nil {
		t.Fatalf("second deliverExec returned error: %v", err)
	}
	if second.Env["TOKEN"] != "second" {
		t.Fatalf("fresh approval after expiry used stale value: %+v", second.Env)
	}
	if second.approvalID == first.approvalID {
		t.Fatalf("fresh approval reused expired approval id %q", second.approvalID)
	}
	if _, ok := cache.Get(secretcache.CacheKey{ScopeID: first.approvalID, Ref: ref}); ok {
		t.Fatal("expired reusable approval cache scope remained reachable")
	}
}

func TestBrokerRejectsReusableApprovalThatExpiresDuringForceRefresh(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	ref := "op://Example/Item/token"
	cache := secretcache.NewSecretCache()
	approver := &mockApprover{decision: approval.Decision{Approved: true, Reusable: true}}
	broker, err := New(Options{
		Now:      func() time.Time { return now },
		Cache:    cache,
		Approver: approver,
		Resolver: &mockResolver{values: map[string]string{ref: "first"}},
		Audit:    &memoryAudit{},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	first, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("first deliverExec returned error: %v", err)
	}
	requireActiveRequest(t, broker, testCorrelation("req_1", "nonce_1"))
	if _, ok := cache.Get(secretcache.CacheKey{ScopeID: first.approvalID, Ref: ref}); !ok {
		t.Fatal("expected reusable value in cache before force refresh")
	}

	now = req.ExpiresAt.Add(-time.Millisecond)
	broker.grants.resolver = &advancingResolver{
		value: "second",
		advance: func() {
			now = req.ExpiresAt.Add(time.Second)
		},
	}
	force := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	force.ForceRefresh = true

	_, err = deliverExecForTest(context.Background(), broker, testCorrelation("req_2", "nonce_2"), force)
	if !errors.Is(err, approval.ErrRequestExpired) {
		t.Fatalf("expected expired reusable approval during refresh, got %v", err)
	}
	if _, ok := cache.Get(secretcache.CacheKey{ScopeID: first.approvalID, Ref: ref}); ok {
		t.Fatal("expired reusable approval cache scope remained after force refresh")
	}
	if _, _, err := broker.grants.reusable.store.MatchReusable(req); !errors.Is(err, policy.ErrMismatch) {
		t.Fatalf("expired reusable approval remained in store: %v", err)
	}
}

func TestBrokerRejectsReusableApprovalThatExpiresBeforePayloadDelivery(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	ref := "op://Example/Item/token"
	cache := secretcache.NewSecretCache()
	broker, err := New(Options{
		Now:      func() time.Time { return now },
		Cache:    cache,
		Approver: &mockApprover{decision: approval.Decision{Approved: true, Reusable: true}},
		Resolver: &mockResolver{values: map[string]string{ref: "first"}},
		Audit:    &memoryAudit{},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	first, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("first deliverExec returned error: %v", err)
	}
	requireActiveRequest(t, broker, testCorrelation("req_1", "nonce_1"))

	now = req.ExpiresAt.Add(-time.Millisecond)
	reuse := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	_, err = deliverExecWithWriteForTest(
		context.Background(),
		broker,
		testCorrelation("req_2", "nonce_2"),
		reuse,
		func(delivery *ExecDelivery) error {
			now = req.ExpiresAt.Add(time.Second)
			return delivery.BeforeWrite()
		},
	)
	if !errors.Is(err, approval.ErrRequestExpired) {
		t.Fatalf("expected reusable approval expiry before payload delivery, got %v", err)
	}
	if _, ok := cache.Get(secretcache.CacheKey{ScopeID: first.approvalID, Ref: ref}); ok {
		t.Fatal("expired reusable approval cache scope remained before payload delivery")
	}
	requireNoActiveRequest(t, broker, testCorrelation("req_2", ""), ErrUnknownRequest)
}

func TestBrokerDoesNotReturnPostWriteReusableFinalizationError(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	ref := "op://Example/Item/token"
	cache := secretcache.NewSecretCache()
	broker, err := New(Options{
		Now:      func() time.Time { return now },
		Cache:    cache,
		Approver: &mockApprover{decision: approval.Decision{Approved: true, Reusable: true}},
		Resolver: &mockResolver{values: map[string]string{ref: "first"}},
		Audit:    &memoryAudit{},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	first, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("first deliverExec returned error: %v", err)
	}
	requireActiveRequest(t, broker, testCorrelation("req_1", "nonce_1"))

	now = req.ExpiresAt.Add(-time.Millisecond)
	reuse := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	wrotePayload := false
	second, err := deliverExecWithWriteForTest(
		context.Background(),
		broker,
		testCorrelation("req_2", "nonce_2"),
		reuse,
		func(delivery *ExecDelivery) error {
			if err := delivery.BeforeWrite(); err != nil {
				return err
			}
			payload := delivery.Payload()
			if payload.Env["TOKEN"] != "first" {
				t.Fatalf("reused payload env = %+v, want first value", payload.Env)
			}
			wrotePayload = true
			now = req.ExpiresAt.Add(time.Second)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("post-write finalization error escaped delivery: %v", err)
	}
	if !wrotePayload {
		t.Fatal("payload writer was not called")
	}
	if second.Env["TOKEN"] != "first" {
		t.Fatalf("returned grant env = %+v, want first value", second.Env)
	}
	if _, ok := cache.Get(secretcache.CacheKey{ScopeID: first.approvalID, Ref: ref}); ok {
		t.Fatal("expired reusable approval cache scope remained after post-write finalization")
	}
	requireActiveRequest(t, broker, testCorrelation("req_2", "nonce_2"))
}

func TestBrokerStopClearsReusableCache(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	cache := secretcache.NewSecretCache()
	broker := newTestBroker(t, Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true, Reusable: true}},
		Resolver: &mockResolver{values: map[string]string{ref: "value"}},
		Audit:    &memoryAudit{},
		Cache:    cache,
	})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	grant, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("deliverExec returned error: %v", err)
	}
	if _, ok := cache.Get(secretcache.CacheKey{ScopeID: grant.approvalID, Ref: ref}); !ok {
		t.Fatal("expected reusable value in cache")
	}
	broker.StopWithAuditEvent(context.Background(), audit.Event{})
	if _, ok := cache.Get(secretcache.CacheKey{ScopeID: grant.approvalID, Ref: ref}); ok {
		t.Fatal("daemon stop left reusable cache scope reachable")
	}
}
