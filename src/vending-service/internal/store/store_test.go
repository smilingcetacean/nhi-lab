package store

import (
	"context"
	"errors"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	// A fresh named in-memory database per test (not literal ":memory:", which
	// modernc.org/sqlite's DSN handling with cache=shared could otherwise
	// share across tests running in the same process). file::memory: with a
	// unique query param keeps each test isolated.
	s, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestCreateAndGetDelegation(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	rec := DelegationRecord{
		ChainID: "c_abc", ParentSpiffeID: "spiffe://lab.local/agent/parent/t1",
		ChildSpiffeID: "spiffe://lab.local/agent/parent/t1/child/c1",
		GrantedScopes: []string{"resource:read:datasetA"}, TaskContext: "demo",
		EntryID: "entry-1", PolicyID: "nhi_grants_c_abc",
		IssuedAt: 100, TTL: 300, ExpiresAt: 400,
	}
	if err := s.CreateDelegation(ctx, rec); err != nil {
		t.Fatalf("CreateDelegation: %v", err)
	}

	got, err := s.GetDelegation(ctx, "c_abc")
	if err != nil {
		t.Fatalf("GetDelegation: %v", err)
	}
	if got.ChildSpiffeID != rec.ChildSpiffeID || len(got.GrantedScopes) != 1 || got.GrantedScopes[0] != "resource:read:datasetA" {
		t.Fatalf("GetDelegation returned unexpected record: %+v", got)
	}
	if got.RevokedAt != nil {
		t.Fatalf("expected a fresh delegation to be unrevoked, got RevokedAt=%v", got.RevokedAt)
	}
}

func TestGetDelegationNotFound(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.GetDelegation(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestCreateDelegationDuplicateChainIDFails(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	rec := DelegationRecord{ChainID: "c_dup", ParentSpiffeID: "p", ChildSpiffeID: "p/child/c", EntryID: "e", PolicyID: "pol", IssuedAt: 1, TTL: 1, ExpiresAt: 2}
	if err := s.CreateDelegation(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateDelegation(ctx, rec); err == nil {
		t.Fatal("expected duplicate chain_id insert to fail")
	}
}

func TestMarkRevokedIsIdempotentAndPreservesFirstTimestamp(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	rec := DelegationRecord{ChainID: "c_rev", ParentSpiffeID: "p", ChildSpiffeID: "p/child/c", EntryID: "e", PolicyID: "pol", IssuedAt: 1, TTL: 1, ExpiresAt: 2}
	if err := s.CreateDelegation(ctx, rec); err != nil {
		t.Fatal(err)
	}

	if err := s.MarkRevoked(ctx, "c_rev", 1000, "revoked_on_demand"); err != nil {
		t.Fatal(err)
	}
	// A second, later revoke (e.g. the reaper racing a manual disposal) must
	// not overwrite the first revocation's timestamp/reason.
	if err := s.MarkRevoked(ctx, "c_rev", 2000, "ttl_expired"); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetDelegation(ctx, "c_rev")
	if err != nil {
		t.Fatal(err)
	}
	if got.RevokedAt == nil || *got.RevokedAt != 1000 {
		t.Fatalf("expected revoked_at to stay at the first revocation (1000), got %v", got.RevokedAt)
	}
	if got.RevocationReason != "revoked_on_demand" {
		t.Fatalf("expected revocation_reason to stay %q, got %q", "revoked_on_demand", got.RevocationReason)
	}
}

func TestMarkRevokedUnknownChainIsNotFound(t *testing.T) {
	s := openTestStore(t)
	if err := s.MarkRevoked(context.Background(), "nope", 1, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestListExpiredUnrevoked(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	mk := func(chainID string, expiresAt int64) DelegationRecord {
		return DelegationRecord{ChainID: chainID, ParentSpiffeID: "p", ChildSpiffeID: "p/child/" + chainID, EntryID: "e-" + chainID, PolicyID: "pol-" + chainID, IssuedAt: 1, TTL: 1, ExpiresAt: expiresAt}
	}
	if err := s.CreateDelegation(ctx, mk("expired", 100)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateDelegation(ctx, mk("live", 100000)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateDelegation(ctx, mk("expired_but_revoked", 100)); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkRevoked(ctx, "expired_but_revoked", 50, "revoked_on_demand"); err != nil {
		t.Fatal(err)
	}

	expired, err := s.ListExpiredUnrevoked(ctx, 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0].ChainID != "expired" {
		t.Fatalf("expected exactly [expired], got %+v", expired)
	}
}

func TestCheckAndRecordNonceRejectsReplay(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if err := s.CheckAndRecordNonce(ctx, "parent-a", "nonce-1", 0, 1000); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
	if err := s.CheckAndRecordNonce(ctx, "parent-a", "nonce-1", 0, 1000); !errors.Is(err, ErrNonceReused) {
		t.Fatalf("expected ErrNonceReused on replay, got %v", err)
	}
	// The same nonce from a DIFFERENT parent is a distinct key and must not
	// be refused — nonce uniqueness is scoped per parent, not global.
	if err := s.CheckAndRecordNonce(ctx, "parent-b", "nonce-1", 0, 1000); err != nil {
		t.Fatalf("same nonce, different parent, should succeed: %v", err)
	}
}

func TestPruneExpiredNonces(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if err := s.CheckAndRecordNonce(ctx, "p", "old", 0, 100); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckAndRecordNonce(ctx, "p", "new", 0, 100000); err != nil {
		t.Fatal(err)
	}
	n, err := s.PruneExpiredNonces(ctx, 500)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 pruned nonce, got %d", n)
	}
	// The pruned nonce should be usable again; the live one should still
	// refuse a replay.
	if err := s.CheckAndRecordNonce(ctx, "p", "old", 501, 100000); err != nil {
		t.Fatalf("expected pruned nonce to be reusable: %v", err)
	}
	if err := s.CheckAndRecordNonce(ctx, "p", "new", 501, 100000); !errors.Is(err, ErrNonceReused) {
		t.Fatalf("expected live nonce to still refuse replay, got %v", err)
	}
}

func mustCreate(t *testing.T, s *Store, chain, parent, child string, issuedAt, expiresAt int64) {
	t.Helper()
	if err := s.CreateDelegation(context.Background(), DelegationRecord{
		ChainID: chain, ParentSpiffeID: parent, ChildSpiffeID: child,
		GrantedScopes: []string{"resource:read:datasetA"}, EntryID: "e_" + chain, PolicyID: "nhi_grants_" + chain,
		IssuedAt: issuedAt, TTL: expiresAt - issuedAt, ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCountLiveChildrenCountsOnlyUnrevokedUnexpiredDirectChildren(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	p := "spiffe://lab.local/agent/parent/t1"
	mustCreate(t, s, "c_live1", p, p+"/child/a", 100, 500)
	mustCreate(t, s, "c_live2", p, p+"/child/b", 100, 500)
	mustCreate(t, s, "c_expired", p, p+"/child/c", 100, 199)
	mustCreate(t, s, "c_revoked", p, p+"/child/d", 100, 500)
	if err := s.MarkRevoked(ctx, "c_revoked", 150, "revoked_on_demand"); err != nil {
		t.Fatal(err)
	}
	// A grandchild and another parent's child are not direct children of p.
	mustCreate(t, s, "c_grand", p+"/child/a", p+"/child/a/child/x", 100, 500)
	mustCreate(t, s, "c_other", "spiffe://lab.local/agent/parent/t2", "spiffe://lab.local/agent/parent/t2/child/a", 100, 500)

	n, err := s.CountLiveChildren(ctx, p, 200)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("CountLiveChildren = %d, want 2", n)
	}
	// A child expiring exactly now is still live (the resource's rule is expires_at < now).
	if n, _ := s.CountLiveChildren(ctx, p, 500); n != 2 {
		t.Fatalf("CountLiveChildren at expires_at = %d, want 2", n)
	}
	if n, _ := s.CountLiveChildren(ctx, p, 501); n != 0 {
		t.Fatalf("CountLiveChildren after expiry = %d, want 0", n)
	}
}

func TestListLiveChildrenSkipsRevokedAndOtherParents(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	p := "spiffe://lab.local/agent/parent/t1"
	mustCreate(t, s, "c_b", p, p+"/child/b", 101, 500)
	mustCreate(t, s, "c_a", p, p+"/child/a", 100, 150) // expired but unrevoked: still listed
	mustCreate(t, s, "c_gone", p, p+"/child/gone", 100, 500)
	mustCreate(t, s, "c_other", p+"/child/a", p+"/child/a/child/x", 100, 500)
	if err := s.MarkRevoked(ctx, "c_gone", 150, "revoked_on_demand"); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListLiveChildren(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ChainID != "c_a" || got[1].ChainID != "c_b" {
		t.Fatalf("ListLiveChildren = %+v, want [c_a c_b]", got)
	}
	got, err = s.ListLiveChildren(ctx, p+"/child/a")
	if err != nil || len(got) != 1 || got[0].ChainID != "c_other" {
		t.Fatalf("ListLiveChildren(grandchild level) = %+v, %v", got, err)
	}
}
