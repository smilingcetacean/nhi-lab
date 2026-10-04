// Package manifest defines the spawn manifest wire shape and its
// structural validation. It is shared between the vending service (verifier)
// and cmd/parentsim (signer/sender) so both sides construct the exact same
// canonical byte string for the detached-JWS signature — see
// internal/signature.
package manifest

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// SpawnManifest is the spawn manifest wire shape, submitted by a parent to
// POST /delegations.
type SpawnManifest struct {
	ParentSpiffeID  string            `json:"parent_spiffe_id"`
	ChildPathHint   string            `json:"child_path_hint"`
	RequestedScopes []string          `json:"requested_scopes"`
	TaskContext     string            `json:"task_context"`
	ChildSelectors  map[string]string `json:"child_selectors"`
	TTLSeconds      int64             `json:"ttl_seconds"`
	// Nonce is replay protection. The vending service
	// remembers every (parent_spiffe_id, nonce) pair it has accepted and
	// refuses a repeat — see internal/store.
	Nonce string `json:"nonce"`
	// Signature is a detached JWS (RFC 7515 Appendix F, compact
	// serialization with an empty payload segment) over CanonicalBytes(),
	// signed with the private key backing the parent's OWN X.509-SVID and
	// carrying that certificate chain in the `x5c` header. See
	// internal/signature for why this is a second, distinct
	// credential from the JWT-SVID bearer token used to authenticate the
	// HTTP call itself: a captured bearer token lets an attacker replay the
	// *connection*, but not sign a *new* manifest, because the X.509-SVID
	// private key never leaves the parent's Workload API boundary.
	Signature string `json:"signature"`
}

// canonicalForm is SpawnManifest minus Signature, with every field in a
// FIXED declaration order. encoding/json marshals struct fields in
// declaration order and map keys in sorted order, so two independent
// callers building the same SpawnManifest values always produce identical
// bytes here — that determinism is the entire point: the signer and the
// verifier must compute the same payload without exchanging it out of band.
type canonicalForm struct {
	ParentSpiffeID  string            `json:"parent_spiffe_id"`
	ChildPathHint   string            `json:"child_path_hint"`
	RequestedScopes []string          `json:"requested_scopes"`
	TaskContext     string            `json:"task_context"`
	ChildSelectors  map[string]string `json:"child_selectors"`
	TTLSeconds      int64             `json:"ttl_seconds"`
	Nonce           string            `json:"nonce"`
}

// CanonicalBytes returns the exact bytes the manifest's signature must cover.
func (m SpawnManifest) CanonicalBytes() ([]byte, error) {
	c := canonicalForm{
		ParentSpiffeID:  m.ParentSpiffeID,
		ChildPathHint:   m.ChildPathHint,
		RequestedScopes: m.RequestedScopes,
		TaskContext:     m.TaskContext,
		ChildSelectors:  m.ChildSelectors,
		TTLSeconds:      m.TTLSeconds,
		Nonce:           m.Nonce,
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("canonicalize manifest: %w", err)
	}
	return b, nil
}

// MaxTTLSeconds bounds ttl_seconds so a manifest cannot request a
// registration entry (and therefore an identity) that outlives any
// reasonable lab run. 24h is generous; nothing in the lab needs longer.
const MaxTTLSeconds = 24 * 60 * 60

// MaxNonceLen bounds an attacker-controlled string that ends up in both the
// SQLite replay table and the audit log.
const MaxNonceLen = 256

// distinguishingSelectorKeys is the allow-list of selector keys that,
// combined with k8s:ns, can identify exactly one pod. This is deliberately
// an allow-list rather than "anything but k8s:ns" (a key-count test, which
// k8s:node-name defeats) or a deny-list of known-bad keys: SPIRE's k8s workload attestor
// emits a wider set of selectors than just these three — including, per
// SPIRE's k8s workload attestor documentation, k8s:node-name, k8s:pod-owner,
// k8s:pod-owner-uid, k8s:pod-image(-count), k8s:pod-init-image(-count),
// k8s:pod-label, k8s:pod-annotation, k8s:container-name, and
// k8s:container-image — none of which distinguish one pod from its
// co-resident siblings (a node, an owning ReplicaSet, or an image can be
// shared by many pods at once). An allow-list fails closed on any of those,
// and on any selector key added to a future attestor version that neither
// this code has enumerated yet; a deny-list would fail open on
// exactly that case.
//
//   - k8s:pod-uid  — unique per pod object, never reused.
//   - k8s:pod-name — unique within a namespace at a point in time.
//   - k8s:sa       — not unique across pods sharing a service account, but
//     combined with k8s:ns this is a documented, accepted residual (a
//     same-namespace sibling with its OWN service account can still be
//     named) — not the "matches everything" defect this list closes.
var distinguishingSelectorKeys = map[string]bool{
	"k8s:pod-uid":  true,
	"k8s:pod-name": true,
	"k8s:sa":       true,
}

// Validate checks the manifest is structurally well-formed: valid SPIFFE ID,
// a properly shaped child_path_hint ("child/<subtask-id>",
// exactly one segment after "child/"), a bounded positive TTL, a non-empty
// nonce and at least one child selector. It does NOT check the signature
// (internal/signature), the authenticated caller (main.go), or Π(P) (the
// policy engine) — each of those is a
// distinct step with its own audit outcome, and collapsing them here would
// blur which check actually failed.
func (m SpawnManifest) Validate() error {
	parentID, err := spiffeid.FromString(m.ParentSpiffeID)
	if err != nil {
		return fmt.Errorf("parent_spiffe_id is not a valid SPIFFE ID: %w", err)
	}
	// Every legitimate parent lives under /agent/parent/ — a root parent at
	// /agent/parent/<task-id>, or a DYNAMIC parent (itself vended as a
	// child, now delegating further — the multi-hop case) at
	// /agent/parent/<task-id>/child/<subtask-id>[/child/<...>]*. Either
	// shape starts with this prefix; nothing else does. Without this check
	// any authenticated identity in the trust domain — an infrastructure
	// service (svc/*), a node alias, anything — could claim to be a parent
	// (svc/test-workload could mint a real, if scopeless, child entry).
	const parentPrefix = "/agent/parent/"
	if !strings.HasPrefix(parentID.Path(), parentPrefix) || parentID.Path() == parentPrefix {
		return fmt.Errorf("parent_spiffe_id %q is not shaped like a parent (must be under %q)",
			m.ParentSpiffeID, parentPrefix)
	}

	if len(m.RequestedScopes) == 0 {
		return fmt.Errorf("requested_scopes must not be empty")
	}

	const prefix = "child/"
	if !strings.HasPrefix(m.ChildPathHint, prefix) {
		return fmt.Errorf("child_path_hint %q must start with %q", m.ChildPathHint, prefix)
	}
	subtask := m.ChildPathHint[len(prefix):]
	if subtask == "" {
		return fmt.Errorf("child_path_hint %q has an empty subtask-id after %q", m.ChildPathHint, prefix)
	}
	if strings.Contains(subtask, "/") {
		return fmt.Errorf("child_path_hint %q has more than one path segment after %q", m.ChildPathHint, prefix)
	}
	if err := spiffeid.ValidatePathSegment(subtask); err != nil {
		return fmt.Errorf("child_path_hint %q has an invalid subtask-id segment %q: %w", m.ChildPathHint, subtask, err)
	}
	// ChildSpiffeID() must itself be constructible as a valid, in-trust-domain
	// descendant of parentID — this also catches a parent path so long/odd
	// that appending /child/<x> would not parse.
	childID, err := spiffeid.FromString(parentID.String() + "/" + m.ChildPathHint)
	if err != nil {
		return fmt.Errorf("computed child SPIFFE ID is invalid: %w", err)
	}
	_ = childID

	if m.TTLSeconds <= 0 {
		return fmt.Errorf("ttl_seconds must be positive")
	}
	if m.TTLSeconds > MaxTTLSeconds {
		return fmt.Errorf("ttl_seconds %d exceeds the maximum of %d", m.TTLSeconds, MaxTTLSeconds)
	}

	if m.Nonce == "" {
		return fmt.Errorf("nonce is required")
	}
	if len(m.Nonce) > MaxNonceLen {
		return fmt.Errorf("nonce exceeds %d characters", MaxNonceLen)
	}

	if len(m.ChildSelectors) == 0 {
		return fmt.Errorf("child_selectors must not be empty")
	}
	hasDistinguishingSelector := false
	for k, v := range m.ChildSelectors {
		if k == "" || v == "" {
			return fmt.Errorf("child_selectors must not contain empty keys or values")
		}
		if distinguishingSelectorKeys[k] {
			hasDistinguishingSelector = true
		}
	}
	// A plain "any key other than k8s:ns" check is a KEY-COUNT test, not
	// a distinguishing-power test. SPIRE's k8s workload attestor also emits
	// k8s:node-name and other node/owner-scoped selectors that identify a
	// whole node or owner, not one pod — {"k8s:ns": "agents",
	// "k8s:node-name": "nhi-lab-worker"} would satisfy it and get a
	// live 201 that matched every pod on that node (in the lab:
	// nhi-test-workload, vending-test-attacker, vending-test-parent are all
	// co-resident). That would allow:
	// chain_id hijack of the submitting parent's own pod, attribution loss
	// across the matched set, and a parent locked out of disposing its own
	// child (403) until the TTL reaper recovered it.
	//
	// The fix is an ALLOW-LIST, not a wider deny-list: only selector keys
	// SPIRE's k8s workload attestor can emit that name a single pod are
	// accepted as "distinguishing" — see distinguishingSelectorKeys below.
	// An allow-list fails closed on any selector this code has not
	// enumerated (e.g. a future attestor version), where a
	// deny-list would fail open on exactly that case.
	if !hasDistinguishingSelector {
		return fmt.Errorf("child_selectors must include at least one pod-distinguishing selector (k8s:pod-uid, k8s:pod-name, or k8s:sa) in addition to \"k8s:ns\" — selectors that identify a node, owner, or other non-pod-unique scope (e.g. \"k8s:node-name\", \"k8s:pod-owner\") do not satisfy this")
	}

	if m.Signature == "" {
		return fmt.Errorf("signature is required")
	}

	return nil
}

// ChildSpiffeID is parent_spiffe_id + "/" + child_path_hint, exactly the
// shape src/policy-engine/identity.go's validateChildDescendant requires and
// exactly what the SPIRE registration entry this service mints must use as
// its own spiffeID. Call only after Validate()
// has succeeded.
func (m SpawnManifest) ChildSpiffeID() string {
	return m.ParentSpiffeID + "/" + m.ChildPathHint
}
