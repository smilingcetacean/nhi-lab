package manifest

import "testing"

func validManifest() SpawnManifest {
	return SpawnManifest{
		ParentSpiffeID:  "spiffe://lab.local/agent/parent/t1",
		ChildPathHint:   "child/c1",
		RequestedScopes: []string{"resource:read:datasetA"},
		TaskContext:     "demo task",
		ChildSelectors:  map[string]string{"k8s:ns": "agents", "k8s:pod-uid": "abc"},
		TTLSeconds:      300,
		Nonce:           "nonce-1",
		Signature:       "sig",
	}
}

func TestValidateAcceptsWellFormedManifest(t *testing.T) {
	if err := validManifest().Validate(); err != nil {
		t.Fatalf("expected valid manifest to pass, got: %v", err)
	}
}

func TestValidateRejectsBadParentID(t *testing.T) {
	m := validManifest()
	m.ParentSpiffeID = "not-a-spiffe-id"
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for invalid parent_spiffe_id")
	}
}

// TestValidateRejectsNonParentShapedParentID is the regression test for
// parent-ID injection: an infrastructure service identity (or
// a node alias, or anything else not under /agent/parent/) must not be
// accepted as parent_spiffe_id, regardless of what JWT-SVID authenticated
// the caller — parents live only under /agent/parent/.
func TestValidateRejectsNonParentShapedParentID(t *testing.T) {
	cases := []string{
		"spiffe://lab.local/svc/test-workload",   // infrastructure service
		"spiffe://lab.local/svc/vending-service", // this service itself
		"spiffe://lab.local/node/nhi-lab",        // node alias
		"spiffe://lab.local/agent/parent/",       // prefix with empty remainder
	}
	for _, id := range cases {
		m := validManifest()
		m.ParentSpiffeID = id
		if err := m.Validate(); err == nil {
			t.Errorf("expected parent_spiffe_id %q (not shaped like a parent) to be rejected", id)
		}
	}
}

// A DYNAMIC parent — itself previously vended as a child, the multi-hop
// delegation case — must still be ACCEPTED: its own SPIFFE ID is
// a /agent/parent/.../child/... path, not a bare /agent/parent/<id>.
func TestValidateAcceptsDynamicParentShape(t *testing.T) {
	m := validManifest()
	m.ParentSpiffeID = "spiffe://lab.local/agent/parent/t1/child/c1"
	m.ChildPathHint = "child/grandchild1"
	if err := m.Validate(); err != nil {
		t.Fatalf("expected a dynamic (previously-vended-as-child) parent to be accepted, got: %v", err)
	}
}

func TestValidateRejectsEmptyRequestedScopes(t *testing.T) {
	m := validManifest()
	m.RequestedScopes = nil
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for empty requested_scopes")
	}
}

func TestValidateRejectsChildPathHintWithoutPrefix(t *testing.T) {
	m := validManifest()
	m.ChildPathHint = "c1"
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for child_path_hint missing 'child/' prefix")
	}
}

func TestValidateRejectsMultiSegmentChildPathHint(t *testing.T) {
	m := validManifest()
	m.ChildPathHint = "child/c1/extra"
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for multi-segment child_path_hint")
	}
}

func TestValidateRejectsEmptySubtask(t *testing.T) {
	m := validManifest()
	m.ChildPathHint = "child/"
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for empty subtask-id")
	}
}

func TestValidateRejectsNonPositiveTTL(t *testing.T) {
	for _, ttl := range []int64{0, -1} {
		m := validManifest()
		m.TTLSeconds = ttl
		if err := m.Validate(); err == nil {
			t.Fatalf("expected error for ttl_seconds=%d", ttl)
		}
	}
}

func TestValidateRejectsExcessiveTTL(t *testing.T) {
	m := validManifest()
	m.TTLSeconds = MaxTTLSeconds + 1
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for ttl_seconds beyond the maximum")
	}
}

func TestValidateRejectsEmptyNonce(t *testing.T) {
	m := validManifest()
	m.Nonce = ""
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for empty nonce")
	}
}

func TestValidateRejectsEmptySelectors(t *testing.T) {
	m := validManifest()
	m.ChildSelectors = nil
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for empty child_selectors")
	}
}

// TestValidateRejectsNamespaceOnlySelectors is a regression test:
// child_selectors carrying only "k8s:ns" (no k8s:sa, k8s:pod-uid, or any
// other pod-distinguishing selector) must be rejected. SPIRE matches an
// entry when its selector set is a SUBSET of the workload's attested
// selectors, so a namespace-only entry matches every pod in that namespace
// — not a plausible sibling, but literally any workload sharing it.
func TestValidateRejectsNamespaceOnlySelectors(t *testing.T) {
	m := validManifest()
	m.ChildSelectors = map[string]string{"k8s:ns": "agents"}
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for namespace-only child_selectors")
	}
}

// A selector set carrying k8s:sa in addition to k8s:ns (the shape this
// lab's own fixtures use — manifests/test/44-vending-test-parent.yaml,
// 45-vending-test-child.yaml) must still be ACCEPTED.
func TestValidateAcceptsNamespacePlusServiceAccountSelectors(t *testing.T) {
	m := validManifest()
	m.ChildSelectors = map[string]string{"k8s:ns": "agents", "k8s:sa": "nhi-test-vend-child"}
	if err := m.Validate(); err != nil {
		t.Fatalf("expected k8s:ns + k8s:sa to be accepted, got: %v", err)
	}
}

// TestValidateSelectorDistinguishingPower is the regression test showing that
// an "any key other than k8s:ns" check would be a key-COUNT test, not a
// distinguishing-POWER test. It would accept
// {"k8s:ns": ..., "k8s:node-name": ...} — a real selector pair SPIRE's k8s
// workload attestor emits, and one that matches every pod on that node, not
// one pod. This table exercises the full set of non-distinguishing keys the
// attestor can emit (so a future addition to this list has to be a
// deliberate edit, not an accidental gap) plus each allow-listed key in
// isolation.
func TestValidateSelectorDistinguishingPower(t *testing.T) {
	cases := []struct {
		name      string
		selectors map[string]string
		wantOK    bool
	}{
		// The defect: k8s:node-name satisfies a "!= k8s:ns" check but
		// identifies a whole node, not a pod.
		{"ns+node-name", map[string]string{"k8s:ns": "agents", "k8s:node-name": "nhi-lab-worker"}, false},
		{"ns+pod-owner", map[string]string{"k8s:ns": "agents", "k8s:pod-owner": "ReplicaSet:agents/foo-abc"}, false},
		{"ns+pod-owner-uid", map[string]string{"k8s:ns": "agents", "k8s:pod-owner-uid": "ReplicaSet:abc-123"}, false},
		{"ns+pod-image", map[string]string{"k8s:ns": "agents", "k8s:pod-image": "example/agent:latest"}, false},
		{"ns+pod-image-count", map[string]string{"k8s:ns": "agents", "k8s:pod-image-count": "1"}, false},
		{"ns+pod-init-image", map[string]string{"k8s:ns": "agents", "k8s:pod-init-image": "example/init:latest"}, false},
		{"ns+pod-init-image-count", map[string]string{"k8s:ns": "agents", "k8s:pod-init-image-count": "0"}, false},
		{"ns+pod-label", map[string]string{"k8s:ns": "agents", "k8s:pod-label": "app:agent"}, false},
		{"ns+pod-annotation", map[string]string{"k8s:ns": "agents", "k8s:pod-annotation": "foo:bar"}, false},
		{"ns+container-name", map[string]string{"k8s:ns": "agents", "k8s:container-name": "main"}, false},
		{"ns+container-image", map[string]string{"k8s:ns": "agents", "k8s:container-image": "example/agent:latest"}, false},
		{"ns+node-name+node-ip (both non-distinguishing)", map[string]string{"k8s:ns": "agents", "k8s:node-name": "nhi-lab-worker", "k8s:node-ip": "10.0.0.5"}, false},
		// Allow-listed keys, each accepted alone alongside k8s:ns.
		{"ns+pod-uid", map[string]string{"k8s:ns": "agents", "k8s:pod-uid": "abc-123"}, true},
		{"ns+pod-name", map[string]string{"k8s:ns": "agents", "k8s:pod-name": "vending-test-parent-0"}, true},
		{"ns+sa", map[string]string{"k8s:ns": "agents", "k8s:sa": "nhi-test-vend-child"}, true},
		// A non-distinguishing key alongside a distinguishing one must still
		// pass — the guard only requires AT LEAST ONE distinguishing key.
		{"ns+node-name+pod-uid", map[string]string{"k8s:ns": "agents", "k8s:node-name": "nhi-lab-worker", "k8s:pod-uid": "abc-123"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validManifest()
			m.ChildSelectors = tc.selectors
			err := m.Validate()
			if tc.wantOK && err != nil {
				t.Fatalf("expected selectors %v to be accepted, got: %v", tc.selectors, err)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("expected selectors %v to be rejected (no pod-distinguishing selector), but Validate() succeeded", tc.selectors)
			}
		})
	}
}

func TestValidateRejectsMissingSignature(t *testing.T) {
	m := validManifest()
	m.Signature = ""
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for missing signature")
	}
}

func TestChildSpiffeIDShape(t *testing.T) {
	m := validManifest()
	got := m.ChildSpiffeID()
	want := "spiffe://lab.local/agent/parent/t1/child/c1"
	if got != want {
		t.Fatalf("ChildSpiffeID() = %q, want %q", got, want)
	}
}

// TestCanonicalBytesDeterministic is the property the whole signature scheme
// depends on: two independently constructed SpawnManifest values with the
// same field values must marshal to byte-identical CanonicalBytes(), because
// the signer and the verifier compute this independently and never exchange
// it directly.
func TestCanonicalBytesDeterministic(t *testing.T) {
	a := validManifest()
	b := validManifest()
	ab, err := a.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	bb, err := b.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(ab) != string(bb) {
		t.Fatalf("CanonicalBytes differ for identical manifests:\n%s\n%s", ab, bb)
	}
}

// TestCanonicalBytesExcludesSignature: signing the canonical form must not
// depend on the signature field itself (which does not exist yet at sign
// time) — changing Signature must not change CanonicalBytes().
func TestCanonicalBytesExcludesSignature(t *testing.T) {
	a := validManifest()
	b := validManifest()
	b.Signature = "a-completely-different-signature"
	ab, _ := a.CanonicalBytes()
	bb, _ := b.CanonicalBytes()
	if string(ab) != string(bb) {
		t.Fatal("CanonicalBytes must not depend on the Signature field")
	}
}

// TestCanonicalBytesChangesWithContent: a tampered field (e.g. an escalated
// requested_scopes list) must produce different canonical bytes, or the
// signature would not actually protect the field that changed.
func TestCanonicalBytesChangesWithContent(t *testing.T) {
	a := validManifest()
	b := validManifest()
	b.RequestedScopes = []string{"resource:read:datasetA", "resource:read:datasetB"}
	ab, _ := a.CanonicalBytes()
	bb, _ := b.CanonicalBytes()
	if string(ab) == string(bb) {
		t.Fatal("CanonicalBytes must change when requested_scopes changes")
	}
}
