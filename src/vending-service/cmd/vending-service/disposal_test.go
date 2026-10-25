package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"nhi-lab/vending-service/internal/audit"
	"nhi-lab/vending-service/internal/manifest"
	"nhi-lab/vending-service/internal/policyclient"
	"nhi-lab/vending-service/internal/spireentry"
	"nhi-lab/vending-service/internal/store"
)

const (
	rootID = "spiffe://lab.local/agent/parent/t1"
	cID    = rootID + "/child/c1"
	gID    = cID + "/child/g1"
	g2ID   = cID + "/child/g2"
	ggID   = gID + "/child/x1"
)

// seed inserts one live delegation row (expires well after the harness clock).
func (h *harness) seed(t *testing.T, chain, parent, child string) {
	t.Helper()
	if err := h.srv.store.CreateDelegation(context.Background(), store.DelegationRecord{
		ChainID: chain, ParentSpiffeID: parent, ChildSpiffeID: child,
		GrantedScopes: []string{"resource:read:datasetA"},
		EntryID:       "entry_" + chain, PolicyID: "nhi_grants_" + chain,
		IssuedAt: 1_800_000_000, TTL: 600, ExpiresAt: 1_800_000_600,
	}); err != nil {
		t.Fatal(err)
	}
}

// callLog records the order of the two external disposal calls.
type callLog struct {
	mu    sync.Mutex
	calls []string
}

func (l *callLog) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, s)
}

// wireDisposal points the stubs at a shared log. failGrant / failEntry name
// chain_ids whose grant removal / entry deletion should fail.
func (h *harness) wireDisposal(log *callLog, failGrant, failEntry map[string]bool) {
	h.srv.policyEngine = &stubPolicyEngine{disposeFn: func(_ context.Context, chainID string) error {
		log.add("grant:" + chainID)
		if failGrant[chainID] {
			return errors.New("opa unreachable")
		}
		return nil
	}}
	h.srv.entries = &stubEntryClient{deleteFn: func(_ context.Context, entryID string) error {
		log.add("entry:" + strings.TrimPrefix(entryID, "entry_"))
		if failEntry[strings.TrimPrefix(entryID, "entry_")] {
			return errors.New("spire unreachable")
		}
		return nil
	}}
}

func (h *harness) dispose(t *testing.T, callerID, chain string) *httptest.ResponseRecorder {
	t.Helper()
	token := mintJWTSVID(t, jwtKeyID, h.jwtKey, mustID(t, callerID), h.srv.cfg.audience, time.Unix(1_800_003_600, 0))
	r := httptest.NewRequest(http.MethodDelete, "/delegations/"+chain, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.SetPathValue("chain_id", chain)
	w := httptest.NewRecorder()
	h.srv.handleDispose(w, r)
	return w
}

func (h *harness) record(t *testing.T, chain string) store.DelegationRecord {
	t.Helper()
	rec, err := h.srv.store.GetDelegation(context.Background(), chain)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// disposeEvents returns the dispose-stage audit events in order.
func (h *harness) disposeEvents(t *testing.T) []audit.Event {
	t.Helper()
	var out []audit.Event
	for _, ln := range strings.Split(strings.TrimSpace(h.auditBuf.String()), "\n") {
		if ln == "" {
			continue
		}
		ev := mustDecodeEvent(t, ln)
		if ev.Stage == audit.StageDispose {
			out = append(out, ev)
		}
	}
	return out
}

// seedTree builds P -> C -> {G, G2} and G -> GG, plus an unrelated sibling
// subtree under the same root and an already revoked row under C.
func (h *harness) seedTree(t *testing.T) {
	t.Helper()
	h.seed(t, "c_c", rootID, cID)
	h.seed(t, "c_g", cID, gID)
	h.seed(t, "c_g2", cID, g2ID)
	h.seed(t, "c_gg", gID, ggID)
	h.seed(t, "c_sib", rootID, rootID+"/child/c2")
	h.seed(t, "c_sibg", rootID+"/child/c2", rootID+"/child/c2/child/g1")
	h.seed(t, "c_old", cID, cID+"/child/old")
	if err := h.srv.store.MarkRevoked(context.Background(), "c_old", 1_799_999_000, "revoked_on_demand"); err != nil {
		t.Fatal(err)
	}
}

// Revoking C disposes C, then its descendants breadth-first, and nothing else.
func TestDisposeCascadesToLiveDescendantsBreadthFirst(t *testing.T) {
	h := newHarness(t)
	h.seedTree(t)
	var log callLog
	h.wireDisposal(&log, nil, nil)

	w := h.dispose(t, rootID, "c_c")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}

	for _, chain := range []string{"c_c", "c_g", "c_g2", "c_gg"} {
		if h.record(t, chain).RevokedAt == nil {
			t.Errorf("%s was not revoked", chain)
		}
	}
	for _, chain := range []string{"c_sib", "c_sibg"} {
		if h.record(t, chain).RevokedAt != nil {
			t.Errorf("%s belongs to another subtree and must stay live", chain)
		}
	}
	// The row that was already revoked keeps its original timestamp and reason,
	// and is not disposed a second time.
	if old := h.record(t, "c_old"); old.RevokedAt == nil || *old.RevokedAt != 1_799_999_000 || old.RevocationReason != "revoked_on_demand" {
		t.Errorf("already-revoked row was touched: %+v", old)
	}

	// Breadth-first: C, then both of its children (in issue order, then chain
	// id), then the grandchild. Each chain is grant first, then entry.
	want := []string{
		"grant:c_c", "entry:c_c",
		"grant:c_g", "entry:c_g",
		"grant:c_g2", "entry:c_g2",
		"grant:c_gg", "entry:c_gg",
	}
	if fmt.Sprint(log.calls) != fmt.Sprint(want) {
		t.Errorf("disposal order = %v\nwant %v", log.calls, want)
	}

	// Descendants carry the target's chain_id in the reason and the revoking
	// parent as the actor; the target keeps the on-demand reason.
	if r := h.record(t, "c_c").RevocationReason; r != "revoked_on_demand" {
		t.Errorf("target reason = %q", r)
	}
	for _, chain := range []string{"c_g", "c_g2", "c_gg"} {
		if r := h.record(t, chain).RevocationReason; r != "ancestor_revoked: c_c" {
			t.Errorf("%s reason = %q, want ancestor_revoked: c_c", chain, r)
		}
	}
	events := h.disposeEvents(t)
	if len(events) != 4 {
		t.Fatalf("got %d dispose events, want 4: %+v", len(events), events)
	}
	for _, ev := range events {
		if ev.ActorSpiffeID != rootID || ev.Outcome != audit.OutcomeAllow {
			t.Errorf("event %+v: want actor %s, outcome allow", ev, rootID)
		}
		wantReason := "ancestor_revoked: c_c"
		if ev.ChainID == "c_c" {
			wantReason = "revoked_on_demand"
		}
		if ev.Detail.Reason != wantReason {
			t.Errorf("event for %s: reason = %q, want %q", ev.ChainID, ev.Detail.Reason, wantReason)
		}
	}
}

// Revoking a leaf walks nothing: there is nobody below it.
func TestDisposeOfALeafDisposesOnlyThatChain(t *testing.T) {
	h := newHarness(t)
	h.seedTree(t)
	var log callLog
	h.wireDisposal(&log, nil, nil)
	if w := h.dispose(t, cID, "c_gg"); w.Code != http.StatusForbidden {
		t.Fatalf("C is not GG's parent: status = %d, want 403", w.Code)
	}
	if w := h.dispose(t, gID, "c_gg"); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if fmt.Sprint(log.calls) != "[grant:c_gg entry:c_gg]" {
		t.Errorf("calls = %v", log.calls)
	}
}

// The grant is removed before the SPIRE entry, so a failure between the two
// leaves the child already denied rather than still authorised.
func TestDisposeChainRemovesGrantBeforeEntryBeforeRow(t *testing.T) {
	h := newHarness(t)
	h.seed(t, "c_c", rootID, cID)
	var log callLog
	h.wireDisposal(&log, nil, map[string]bool{"c_c": true}) // the entry deletion fails

	w := h.dispose(t, rootID, "c_c")
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Code)
	}
	if fmt.Sprint(log.calls) != "[grant:c_c entry:c_c]" {
		t.Fatalf("calls = %v, want the grant removed first", log.calls)
	}
	if h.record(t, "c_c").RevokedAt != nil {
		t.Error("the row must stay unrevoked when the entry deletion failed, so the reaper retries")
	}

}

// If the grant removal itself fails, nothing else is attempted.
func TestDisposeChainStopsWhenTheGrantCannotBeRemoved(t *testing.T) {
	h := newHarness(t)
	h.seed(t, "c_c", rootID, cID)
	var log callLog
	h.wireDisposal(&log, map[string]bool{"c_c": true}, nil)
	if w := h.dispose(t, rootID, "c_c"); w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Code)
	}
	if fmt.Sprint(log.calls) != "[grant:c_c]" {
		t.Fatalf("calls = %v, want only the failed grant removal", log.calls)
	}
	if h.record(t, "c_c").RevokedAt != nil {
		t.Error("the row must stay unrevoked")
	}
}

// If the target itself cannot be disposed, the walk does not start.
func TestDisposeDoesNotCascadeWhenTheTargetFails(t *testing.T) {
	h := newHarness(t)
	h.seedTree(t)
	var log callLog
	h.wireDisposal(&log, map[string]bool{"c_c": true}, nil)
	if w := h.dispose(t, rootID, "c_c"); w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d", w.Code)
	}
	if fmt.Sprint(log.calls) != "[grant:c_c]" {
		t.Fatalf("calls = %v", log.calls)
	}
	if h.record(t, "c_g").RevokedAt != nil {
		t.Error("descendants must not be touched when the target failed")
	}
}

// One failing descendant is named in the error, keeps its row unrevoked for
// the reaper, and does not stop the rest of the subtree from being cleaned up.
func TestDisposeCascadePartialFailureNamesTheDescendant(t *testing.T) {
	h := newHarness(t)
	h.seedTree(t)
	var log callLog
	h.wireDisposal(&log, map[string]bool{"c_g": true}, nil)

	w := h.dispose(t, rootID, "c_c")
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "c_g ") && !strings.Contains(w.Body.String(), "c_g (") {
		t.Errorf("response does not name the failed descendant c_g: %s", w.Body.String())
	}
	if h.record(t, "c_c").RevokedAt == nil {
		t.Error("the target itself was disposed and must be revoked")
	}
	if h.record(t, "c_g").RevokedAt != nil {
		t.Error("the failed descendant must stay unrevoked so the reaper picks it up")
	}
	for _, chain := range []string{"c_g2", "c_gg"} {
		if h.record(t, chain).RevokedAt == nil {
			t.Errorf("%s should still have been disposed", chain)
		}
	}
	// An error event for the failed descendant, attributed to the revoking
	// parent and carrying its own chain_id; plus the 502 event for the target.
	var found bool
	for _, ev := range h.disposeEvents(t) {
		if ev.ChainID == "c_g" && ev.Outcome == audit.OutcomeError &&
			strings.Contains(ev.Detail.Reason, "ancestor_revoked: c_c") && ev.ActorSpiffeID == rootID {
			found = true
		}
	}
	if !found {
		t.Errorf("no dispose/error event for c_g: %s", h.auditBuf.String())
	}

	// The reaper picks the stranded row up at its expiry, without cascading.
	h.srv.now = func() time.Time { return time.Unix(1_800_000_601, 0) }
	var log2 callLog
	h.wireDisposal(&log2, nil, nil)
	h.srv.reapOnce(context.Background())
	if h.record(t, "c_g").RevokedAt == nil || h.record(t, "c_g").RevocationReason != "ttl_expired" {
		t.Errorf("the reaper did not dispose the stranded descendant: %+v", h.record(t, "c_g"))
	}
	// c_sib and c_sibg expired too, so the reaper disposes those as well; but
	// no cascade means nothing is disposed with the ancestor_revoked reason.
	for _, chain := range []string{"c_sib", "c_sibg"} {
		if r := h.record(t, chain).RevocationReason; r != "ttl_expired" {
			t.Errorf("%s reason = %q, want ttl_expired", chain, r)
		}
	}
}

// The reaper never cascades: reaping C leaves C's live children alone.
func TestReaperDoesNotCascade(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.srv.store.CreateDelegation(ctx, store.DelegationRecord{
		ChainID: "c_c", ParentSpiffeID: rootID, ChildSpiffeID: cID, GrantedScopes: []string{"resource:read:datasetA"},
		EntryID: "entry_c_c", PolicyID: "p", IssuedAt: 1, TTL: 10, ExpiresAt: 11, // long expired
	}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, "c_g", cID, gID) // live
	var log callLog
	h.wireDisposal(&log, nil, nil)
	h.srv.reapOnce(ctx)
	if fmt.Sprint(log.calls) != "[grant:c_c entry:c_c]" {
		t.Fatalf("calls = %v", log.calls)
	}
	if h.record(t, "c_g").RevokedAt != nil {
		t.Error("the reaper must not cascade")
	}
}

// --- TTL attenuation -----------------------------------------------------------

// vendOnce runs a full vend from parent with the given requested TTL against a
// stub policy engine that returns synth, and reports what reached SPIRE.
func (h *harness) vendOnce(t *testing.T, parent, hint, nonce string, ttl int64, synth policyclient.SynthesizeResponse) (*httptest.ResponseRecorder, *int64, *int64) {
	t.Helper()
	parentID := mustID(t, parent)
	token := mintJWTSVID(t, jwtKeyID, h.jwtKey, parentID, h.srv.cfg.audience, time.Unix(1_800_003_600, 0))
	var gotTTL, gotExpires int64
	h.srv.policyEngine = &stubPolicyEngine{
		synthesizeFn: func(_ context.Context, req policyclient.SynthesizeRequest) (policyclient.SynthesizeResponse, error) {
			out := synth
			out.PolicyID = "nhi_grants_" + req.ChainID
			return out, nil
		},
		disposeFn: func(context.Context, string) error { return nil },
	}
	h.srv.entries = &stubEntryClient{
		lookupFn: defaultLookupSelectors,
		createFn: func(_ context.Context, _, _ string, _ []spireentry.Selector, x509TTL, expiresAt int64) (string, error) {
			gotTTL, gotExpires = x509TTL, expiresAt
			return "entry-" + nonce, nil
		},
	}
	m := manifest.SpawnManifest{
		ParentSpiffeID: parent, ChildPathHint: hint,
		RequestedScopes: []string{"resource:read:datasetA"},
		ChildSelectors:  map[string]string{"k8s:ns": "agents", "k8s:sa": "nhi-test-vend-child"},
		TTLSeconds:      ttl, Nonce: nonce,
	}
	m = signManifest(t, h.ca, parentID, m)
	return h.request(t, m, token), &gotTTL, &gotExpires
}

// The expiry the policy engine returns is what the SPIRE entry, the X.509-SVID
// TTL, the stored TTL and the 201 all carry; the vend event records the
// requested TTL.
func TestVendUsesTheShortenedExpiryEverywhere(t *testing.T) {
	h := newHarness(t) // now = 1_800_000_000
	w, x509TTL, entryExpires := h.vendOnce(t, cID, "child/g1", "n-short", 600, policyclient.SynthesizeResponse{
		ChildScopes: []string{"resource:read:datasetA"}, ExpiresAt: 1_800_000_090, TTLShortened: true,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if *entryExpires != 1_800_000_090 {
		t.Errorf("SPIRE entry expires_at = %d, want 1800000090", *entryExpires)
	}
	if *x509TTL != 90 {
		t.Errorf("X.509-SVID TTL = %d, want 90 (expires_at - now), not the requested 600", *x509TTL)
	}
	var resp delegationResponse
	mustUnmarshal(t, w.Body.Bytes(), &resp)
	if resp.ExpiresAt != 1_800_000_090 {
		t.Errorf("201 expires_at = %d", resp.ExpiresAt)
	}
	rec := h.record(t, resp.ChainID)
	if rec.TTL != 90 || rec.ExpiresAt != 1_800_000_090 {
		t.Errorf("stored ttl/expires_at = %d/%d, want 90/1800000090", rec.TTL, rec.ExpiresAt)
	}
	ev := lastAuditEvent(t, h.auditBuf)
	if ev.Stage != audit.StageVend || ev.Outcome != audit.OutcomeAllow ||
		ev.Detail.ExpiresAt == nil || *ev.Detail.ExpiresAt != 1_800_000_090 {
		t.Fatalf("vend event = %+v", ev)
	}
	if !strings.Contains(ev.Detail.Reason, "requested 600") {
		t.Errorf("vend reason = %q, want it to record the requested TTL", ev.Detail.Reason)
	}
}

func TestVendWithoutShorteningHasNoTTLReason(t *testing.T) {
	h := newHarness(t)
	w, x509TTL, _ := h.vendOnce(t, rootID, "child/c1", "n-plain", 300, policyclient.SynthesizeResponse{
		ChildScopes: []string{"resource:read:datasetA"}, ExpiresAt: 1_800_000_300,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if *x509TTL != 300 {
		t.Errorf("X.509-SVID TTL = %d, want 300", *x509TTL)
	}
	if ev := lastAuditEvent(t, h.auditBuf); ev.Detail.Reason != "" {
		t.Errorf("reason = %q, want empty", ev.Detail.Reason)
	}
}

// A parent about to expire still gets a child with a usable (>= 1 s) X.509 TTL.
func TestVendX509TTLIsAtLeastOneSecond(t *testing.T) {
	h := newHarness(t)
	w, x509TTL, _ := h.vendOnce(t, cID, "child/g1", "n-edge", 600, policyclient.SynthesizeResponse{
		ChildScopes: []string{"resource:read:datasetA"}, ExpiresAt: 1_800_000_000, TTLShortened: true,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if *x509TTL != 1 {
		t.Errorf("X.509-SVID TTL = %d, want 1", *x509TTL)
	}
}

// --- creation limits -----------------------------------------------------------

func (h *harness) eventsOf(t *testing.T, stage, outcome string) []audit.Event {
	t.Helper()
	var out []audit.Event
	for _, ln := range strings.Split(strings.TrimSpace(h.auditBuf.String()), "\n") {
		if ln == "" {
			continue
		}
		if ev := mustDecodeEvent(t, ln); ev.Stage == stage && ev.Outcome == outcome {
			out = append(out, ev)
		}
	}
	return out
}

var okSynth = policyclient.SynthesizeResponse{ChildScopes: []string{"resource:read:datasetA"}, ExpiresAt: 1_800_000_300}

// With the default limit of 2, G (depth 2) may not vend a depth-3 child. The
// refusal is a 403 and an audited vend deny, nothing is created, and the
// nonce is not recorded, so the same manifest succeeds once the limit is raised.
func TestVendRefusedAtDepthLimitLeavesNoState(t *testing.T) {
	h := newHarness(t)
	h.srv.policyEngine = &stubPolicyEngine{synthesizeFn: func(context.Context, policyclient.SynthesizeRequest) (policyclient.SynthesizeResponse, error) {
		t.Error("the policy engine must not be called for a depth refusal")
		return okSynth, nil
	}}
	created := false
	h.srv.entries = &stubEntryClient{lookupFn: defaultLookupSelectors, createFn: func(context.Context, string, string, []spireentry.Selector, int64, int64) (string, error) {
		created = true
		return "x", nil
	}}
	parentID := mustID(t, gID)
	token := mintJWTSVID(t, jwtKeyID, h.jwtKey, parentID, h.srv.cfg.audience, time.Unix(1_800_003_600, 0))
	m := signManifest(t, h.ca, parentID, manifest.SpawnManifest{
		ParentSpiffeID: gID, ChildPathHint: "child/x1", RequestedScopes: []string{"resource:read:datasetA"},
		ChildSelectors: map[string]string{"k8s:ns": "agents", "k8s:sa": "nhi-test-vend-child"},
		TTLSeconds:     300, Nonce: "depth-nonce",
	})

	w := h.request(t, m, token)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	denies := h.eventsOf(t, audit.StageVend, audit.OutcomeDeny)
	if len(denies) != 1 || !strings.Contains(denies[0].Detail.Reason, "MAX_DELEGATION_DEPTH is 2") ||
		denies[0].ActorSpiffeID != gID || denies[0].Detail.ChildSpiffeID != ggID {
		t.Fatalf("expected one vend deny naming the depth limit, got %+v", denies)
	}
	if created {
		t.Error("a SPIRE entry was created")
	}
	if n, _ := h.srv.store.CountLiveChildren(context.Background(), gID, 0); n != 0 {
		t.Errorf("a delegation row was created (%d)", n)
	}
	// The nonce was not recorded: replaying the identical manifest, with the
	// limit raised, is a fresh request (201), not a replay (409).
	h.srv.cfg.maxDelegationDepth = 3
	h.srv.policyEngine = &stubPolicyEngine{synthesizeFn: func(_ context.Context, req policyclient.SynthesizeRequest) (policyclient.SynthesizeResponse, error) {
		out := okSynth
		out.PolicyID = "nhi_grants_" + req.ChainID
		return out, nil
	}}
	h.srv.entries = &stubEntryClient{lookupFn: defaultLookupSelectors, createFn: func(context.Context, string, string, []spireentry.Selector, int64, int64) (string, error) {
		return "entry-ok", nil
	}}
	if w2 := h.request(t, m, token); w2.Code != http.StatusCreated {
		t.Fatalf("with MAX_DELEGATION_DEPTH=3 the same manifest got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestVendAtTheDepthLimitIsAllowed(t *testing.T) {
	h := newHarness(t)
	// C (depth 1) vending G (depth 2) is exactly at the default limit.
	w, _, _ := h.vendOnce(t, cID, "child/g1", "n-edge-depth", 300, okSynth)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
}

// Live children only: revoked and expired ones do not count against the cap.
func TestVendRefusedAtChildCapAndFreedByDisposal(t *testing.T) {
	h := newHarness(t)
	h.srv.cfg.maxLiveChildren = 2
	var log callLog

	for i := 1; i <= 2; i++ {
		w, _, _ := h.vendOnce(t, rootID, fmt.Sprintf("child/k%d", i), fmt.Sprintf("n-cap-%d", i), 300, okSynth)
		if w.Code != http.StatusCreated {
			t.Fatalf("child %d: status = %d, body=%s", i, w.Code, w.Body.String())
		}
	}
	w, _, _ := h.vendOnce(t, rootID, "child/k3", "n-cap-3", 300, okSynth)
	if w.Code != http.StatusForbidden {
		t.Fatalf("third child: status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	denies := h.eventsOf(t, audit.StageVend, audit.OutcomeDeny)
	if len(denies) != 1 || !strings.Contains(denies[0].Detail.Reason, "MAX_LIVE_CHILDREN is 2") {
		t.Fatalf("expected a vend deny naming the child cap, got %+v", denies)
	}

	// Dispose one child. The refused manifest (same nonce) then succeeds: it was
	// refused before its nonce was recorded, so this is not a replay.
	all, err := h.srv.store.ListLiveChildren(context.Background(), rootID)
	if err != nil || len(all) != 2 {
		t.Fatalf("live children = %v, %v", all, err)
	}
	h.wireDisposal(&log, nil, nil)
	if w := h.dispose(t, rootID, all[0].ChainID); w.Code != http.StatusOK {
		t.Fatalf("dispose: %d %s", w.Code, w.Body.String())
	}
	w, _, _ = h.vendOnce(t, rootID, "child/k3", "n-cap-3", 300, okSynth)
	if w.Code != http.StatusCreated {
		t.Fatalf("after disposal: status = %d, body=%s", w.Code, w.Body.String())
	}
}

// Ten concurrent vends by one parent yield exactly MAX_LIVE_CHILDREN children.
// The synthesis stub sleeps so that, without the per-parent lock, every request
// would pass the count before any row was inserted.
func TestConcurrentVendsByOneParentRespectTheCap(t *testing.T) {
	h := newHarness(t)
	h.srv.cfg.maxLiveChildren = 2
	parentID := mustID(t, rootID)
	token := mintJWTSVID(t, jwtKeyID, h.jwtKey, parentID, h.srv.cfg.audience, time.Unix(1_800_003_600, 0))
	h.srv.policyEngine = &stubPolicyEngine{
		synthesizeFn: func(_ context.Context, req policyclient.SynthesizeRequest) (policyclient.SynthesizeResponse, error) {
			time.Sleep(30 * time.Millisecond)
			out := okSynth
			out.PolicyID = "nhi_grants_" + req.ChainID
			return out, nil
		},
		disposeFn: func(context.Context, string) error { return nil },
	}
	var entryMu sync.Mutex
	entries := 0
	h.srv.entries = &stubEntryClient{
		lookupFn: defaultLookupSelectors,
		createFn: func(context.Context, string, string, []spireentry.Selector, int64, int64) (string, error) {
			entryMu.Lock()
			defer entryMu.Unlock()
			entries++
			return fmt.Sprintf("entry-%d", entries), nil
		},
	}

	const n = 10
	var manifests [n]manifest.SpawnManifest
	for i := range manifests {
		manifests[i] = signManifest(t, h.ca, parentID, manifest.SpawnManifest{
			ParentSpiffeID: rootID, ChildPathHint: fmt.Sprintf("child/p%d", i),
			RequestedScopes: []string{"resource:read:datasetA"},
			ChildSelectors:  map[string]string{"k8s:ns": "agents", "k8s:sa": "nhi-test-vend-child"},
			TTLSeconds:      300, Nonce: fmt.Sprintf("n-par-%d", i),
		})
	}
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = h.request(t, manifests[i], token).Code
		}()
	}
	wg.Wait()

	created, refused := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusCreated:
			created++
		case http.StatusForbidden:
			refused++
		default:
			t.Errorf("unexpected status %d", c)
		}
	}
	if created != 2 || refused != n-2 {
		t.Fatalf("created=%d refused=%d (codes %v), want 2 and %d", created, refused, codes, n-2)
	}
	if live, _ := h.srv.store.CountLiveChildren(context.Background(), rootID, 1_800_000_000); live != 2 {
		t.Errorf("live children in the store = %d, want 2", live)
	}
	if entries != 2 {
		t.Errorf("SPIRE entries created = %d, want 2", entries)
	}
}

// Different parents do not block each other, and the lock table empties.
func TestParentLocksAreIndependentAndReleased(t *testing.T) {
	var p parentLocks
	unlockA := p.lock("a")
	done := make(chan struct{})
	go func() {
		unlockB := p.lock("b") // must not wait for "a"
		unlockB()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a lock on one parent blocked another parent")
	}
	unlockA()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.locks) != 0 {
		t.Errorf("lock table not emptied: %d entries", len(p.locks))
	}
}

func TestEnvPositiveInt(t *testing.T) {
	t.Setenv("LIMIT_T", "")
	if n, err := envPositiveInt("LIMIT_T", 8); err != nil || n != 8 {
		t.Fatalf("default: %d, %v", n, err)
	}
	t.Setenv("LIMIT_T", "3")
	if n, err := envPositiveInt("LIMIT_T", 8); err != nil || n != 3 {
		t.Fatalf("set: %d, %v", n, err)
	}
	for _, bad := range []string{"0", "-1", "two", "2.5"} {
		t.Setenv("LIMIT_T", bad)
		if _, err := envPositiveInt("LIMIT_T", 8); err == nil {
			t.Errorf("%q must be an error, not a silent fallback", bad)
		}
	}
}
