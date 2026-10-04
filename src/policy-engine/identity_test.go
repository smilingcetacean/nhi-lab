package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- child_spiffe_id must be validated as a structural descendant of
// parent_spiffe_id. ----------------------------------------------------------

func TestValidateChildDescendantAcceptsLegitimateChild(t *testing.T) {
	err := validateChildDescendant(
		"spiffe://lab.local/agent/parent/t1",
		"spiffe://lab.local/agent/parent/t1/child/c1",
		nil,
	)
	if err != nil {
		t.Fatalf("legitimate child rejected: %v", err)
	}
}

// The concrete escalation the descendant check closes: parent=P1 holds {A},
// child=P2 is an UNRELATED identity (not a descendant of P1 at all — it could
// even be another root parent). Must be rejected outright, before it can ever
// become the spiffe_id of a written grant.
func TestValidateChildDescendantRejectsSiblingParent(t *testing.T) {
	err := validateChildDescendant(
		"spiffe://lab.local/agent/parent/p1",
		"spiffe://lab.local/agent/parent/p2", // a different, unrelated parent
		nil,
	)
	if err == nil {
		t.Fatal("expected an unrelated sibling parent to be rejected as child_spiffe_id")
	}
}

// A grandchild, or anything with more than one path segment past /child/, is
// also not "a direct child of this parent" under the SPIFFE ID scheme.
func TestValidateChildDescendantRejectsGrandchild(t *testing.T) {
	err := validateChildDescendant(
		"spiffe://lab.local/agent/parent/t1",
		"spiffe://lab.local/agent/parent/t1/child/c1/child/c2",
		nil,
	)
	if err == nil {
		t.Fatal("expected a grandchild-shaped id to be rejected")
	}
}

func TestValidateChildDescendantRejectsEmptySubtaskID(t *testing.T) {
	err := validateChildDescendant(
		"spiffe://lab.local/agent/parent/t1",
		"spiffe://lab.local/agent/parent/t1/child/",
		nil,
	)
	if err == nil {
		t.Fatal("expected an empty subtask-id to be rejected")
	}
}

// go-spiffe's own path parser refuses ".." dot segments (verified against
// v2.8.1 empirically), so this exercises that a malformed subtask-id using
// path traversal never reaches a "prefix matched" true.
func TestValidateChildDescendantRejectsDotSegmentTrickery(t *testing.T) {
	err := validateChildDescendant(
		"spiffe://lab.local/agent/parent/t1",
		"spiffe://lab.local/agent/parent/t1/child/../other",
		nil,
	)
	if err == nil {
		t.Fatal("expected a '..' segment in child_spiffe_id to be rejected")
	}
}

// A child_spiffe_id that is structurally a legitimate descendant (the prefix
// check alone would accept it) must still be rejected if it collides with an
// entry in the bootstrap root-parent table: a root parent is pre-provisioned,
// cluster-declared authority and cannot also be the target of a synthesized
// grant, however its path happens to be shaped.
func TestValidateChildDescendantRejectsBootstrapRootParentAsChild(t *testing.T) {
	bootstrap := map[string][]string{
		"spiffe://lab.local/agent/parent/t1/child/c1": {"resource:read:datasetA"},
	}
	err := validateChildDescendant(
		"spiffe://lab.local/agent/parent/t1",
		"spiffe://lab.local/agent/parent/t1/child/c1",
		bootstrap,
	)
	if err == nil {
		t.Fatal("expected a child_spiffe_id colliding with a bootstrap root parent to be rejected")
	}
}

func TestValidateChildDescendantRejectsCrossTrustDomain(t *testing.T) {
	err := validateChildDescendant(
		"spiffe://lab.local/agent/parent/t1",
		"spiffe://other.trust/agent/parent/t1/child/c1",
		nil,
	)
	if err == nil {
		t.Fatal("expected a cross-trust-domain child_spiffe_id to be rejected")
	}
}

func TestValidateChildDescendantRejectsMalformedSpiffeIDs(t *testing.T) {
	if err := validateChildDescendant("not-a-spiffe-id", "spiffe://lab.local/agent/parent/t1/child/c1", nil); err == nil {
		t.Fatal("expected malformed parent_spiffe_id to be rejected")
	}
	if err := validateChildDescendant("spiffe://lab.local/agent/parent/t1", "not-a-spiffe-id", nil); err == nil {
		t.Fatal("expected malformed child_spiffe_id to be rejected")
	}
}

// End-to-end: the same escalation, driven through the
// real handler. parent=P1 holds {A} (via bootstrap); child=P2 is an unrelated
// identity. Even though requested ⊆ Π(P1), the call must be rejected before
// any grant naming P2 is ever written — because P2 is not P1's child.
func TestHandleSynthesizeRejectsSiblingParentEscalation(t *testing.T) {
	var putCalled bool
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/policies":
			_ = json.NewEncoder(w).Encode(opaPolicyListResponse{Result: nil})
		case r.Method == http.MethodPut:
			putCalled = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected OPA call: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer opaSrv.Close()

	srv := &server{
		audit:       newAuditor(&bytes.Buffer{}),
		synthesizer: deterministicSynthesizer{},
		opa:         newOPAClient(opaSrv.Client(), opaSrv.URL),
		bootstrap: map[string][]string{
			"spiffe://lab.local/agent/parent/p1": {"resource:read:datasetA"},
		},
		now: func() time.Time { return time.Unix(1000, 0) },
	}

	body := []byte(`{
		"chain_id":"escalation_attempt",
		"parent_spiffe_id":"spiffe://lab.local/agent/parent/p1",
		"child_spiffe_id":"spiffe://lab.local/agent/parent/p2",
		"requested_scopes":["resource:read:datasetA"],
		"ttl_seconds":60
	}`)
	r := mustSpiffeCertRequest(t, "POST", "/synthesize", "spiffe://lab.local/svc/vending-service", body)
	w := httptest.NewRecorder()
	srv.handleSynthesize(w, r)

	if w.Code != 400 {
		t.Fatalf("status = %d, want 400 (sibling/unrelated child_spiffe_id must be rejected), body=%s", w.Code, w.Body.String())
	}
	// Assert WHY it was rejected, not merely that it was. handleSynthesize
	// validates chain_id before child_spiffe_id, so a fixture that trips the
	// earlier check produces an identical 400 with putCalled == false — and
	// this test would then pass with validateChildDescendant deleted
	// outright. That is not hypothetical: it is exactly what happened when
	// chainIDPattern was tightened and this fixture was not updated with the
	// others. Pinning the reason keeps the test bound to the escalation fix.
	if body := w.Body.String(); !strings.Contains(body, "child_spiffe_id") {
		t.Fatalf("rejected for the wrong reason: want a child_spiffe_id denial, got %s", body)
	}
	if putCalled {
		t.Fatal("a grant module was written to OPA despite the invalid child_spiffe_id — escalation not closed")
	}
}

// --- chain_id must be validated at the API boundary so slugify's
// lowercase+substitute transform is the IDENTITY function over every accepted
// input — genuinely injective, not merely "less likely to collide". ---------

func TestValidateChainIDAcceptsPlainShapes(t *testing.T) {
	for _, id := range []string{"chain_1", "chain2", "abc123", "a_b_c_d9", "chain_one", "chain_two"} {
		if err := validateChainID(id); err != nil {
			t.Errorf("validateChainID(%q) = %v, want accepted", id, err)
		}
	}
}

// Anything chainIDPattern would otherwise fold — uppercase, '-', or the wider
// junk chars a caller might send — must be rejected at the boundary, not
// silently folded into a collision with some other accepted chain_id. This is
// why the accepted set is not wider: a set like
// ([a-zA-Z0-9_-]) would still let "chain-1" and "chain_1" both through, and both
// collide after slugify. Restricting to [a-z0-9_] removes every
// character slugify would otherwise change, so nothing in this list is a
// "maybe" — every one of them must be refused.
func TestValidateChainIDRejectsAnythingSlugifyWouldChange(t *testing.T) {
	for _, id := range []string{
		"chain-1", // '-' would be folded to '_' by slugify
		"CHAIN-1", // uppercase would be lowercased AND '-' folded
		"Chain_1", // uppercase would be lowercased
		"chain.1", // '.' would be folded to '_'
		"chain 1", // space would be folded to '_'
		"chain/1", // '/' would be folded to '_'
		"chaîn-1", // non-ASCII, outside [a-z0-9_] entirely
		"",        // empty
		"châin_1", // non-ASCII
	} {
		if err := validateChainID(id); err == nil {
			t.Errorf("validateChainID(%q) = nil, want rejected (slugify would change this input)", id)
		}
	}
}

// The specific collision this guards against: "chain-1" and
// "CHAIN-1" — both accepted by a wider chainIDPattern and
// both folding onto the same policy_id as "chain_1" — must now be rejected
// outright by the API, not silently collided.
func TestValidateChainIDRejectsFormerlyCollidingShapes(t *testing.T) {
	for _, id := range []string{"chain-1", "CHAIN-1"} {
		if err := validateChainID(id); err == nil {
			t.Errorf("validateChainID(%q) = nil, want rejected", id)
		}
	}
}

// Two distinct rejected-shape chain_ids must both be refused before the
// renderer/slugify ever sees them — driven through the real handler so the
// boundary check, not just the standalone validator, is exercised.
func TestHandleSynthesizeRejectsInvalidChainIDBeforeRendering(t *testing.T) {
	for _, chainID := range []string{"chain.1", "chain 1", "chain/1", "chain-1", "CHAIN-1"} {
		t.Run(chainID, func(t *testing.T) {
			srv := &server{audit: newAuditor(&bytes.Buffer{}), now: time.Now}
			body, _ := json.Marshal(map[string]any{
				"chain_id":         chainID,
				"parent_spiffe_id": "spiffe://lab.local/agent/parent/t1",
				"child_spiffe_id":  "spiffe://lab.local/agent/parent/t1/child/c1",
				"requested_scopes": []string{"resource:read:datasetA"},
				"ttl_seconds":      60,
			})
			r := mustSpiffeCertRequest(t, "POST", "/synthesize", "spiffe://lab.local/svc/vending-service", body)
			w := httptest.NewRecorder()
			srv.handleSynthesize(w, r)
			if w.Code != 400 {
				t.Fatalf("status = %d, want 400 for chain_id %q", w.Code, chainID)
			}
		})
	}
}

// The injectivity property chainIDPattern exists for: every accepted
// chain_id that is a genuinely distinct STRING remains a distinct policy_id
// after slugification. With chainIDPattern restricted to [a-z0-9_] — the
// exact set slugify leaves untouched — this must now hold for ALL accepted
// pairs, not just some of them.
func TestAcceptedChainIDsRemainDistinctAfterSlugify(t *testing.T) {
	ids := []string{"chain_1", "chain_2", "other_chain", "abc123", "a_b_c"}
	seen := make(map[string]string) // policy_id -> chain_id that produced it
	for _, id := range ids {
		if err := validateChainID(id); err != nil {
			t.Fatalf("validateChainID(%q) unexpectedly rejected: %v", id, err)
		}
		pid := policyID(id)
		if prior, collided := seen[pid]; collided {
			t.Fatalf("chain_id %q and %q both produced policy_id %q — not injective", id, prior, pid)
		}
		seen[pid] = id
		// slugify must be the identity function (mod the nhi_grants_ prefix)
		// over anything validateChainID accepts: nothing in [a-z0-9_] is
		// touched by lowercasing or by the '-'->'_' substitution.
		if slugify(id) != id {
			t.Errorf("slugify(%q) = %q, want %q unchanged (chainIDPattern should only accept slugify-invariant input)",
				id, slugify(id), id)
		}
	}
}
