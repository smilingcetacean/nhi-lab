package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"nhi-lab/vending-service/internal/audit"
	"nhi-lab/vending-service/internal/manifest"
	"nhi-lab/vending-service/internal/policyclient"
	"nhi-lab/vending-service/internal/signature"
	"nhi-lab/vending-service/internal/spireentry"
	"nhi-lab/vending-service/internal/store"
)

// stubPolicyEngine and stubEntryClient stand in for the real mTLS clients in
// tests that need to reach past attestation (steps 1-3) without a live
// policy engine or SPIRE server. By default both simply refuse — an
// unconfigured stub failing loudly is safer than one that silently
// succeeds and lets a test believe a step ran when it did not.
type stubPolicyEngine struct {
	synthesizeFn func(ctx context.Context, req policyclient.SynthesizeRequest) (policyclient.SynthesizeResponse, error)
	disposeFn    func(ctx context.Context, chainID string) error
}

func (s *stubPolicyEngine) Synthesize(ctx context.Context, req policyclient.SynthesizeRequest) (policyclient.SynthesizeResponse, error) {
	if s.synthesizeFn != nil {
		return s.synthesizeFn(ctx, req)
	}
	return policyclient.SynthesizeResponse{}, errUnconfiguredStub
}

func (s *stubPolicyEngine) Dispose(ctx context.Context, chainID string) error {
	if s.disposeFn != nil {
		return s.disposeFn(ctx, chainID)
	}
	return errUnconfiguredStub
}

type stubEntryClient struct {
	createFn func(ctx context.Context, parentID, childSpiffeID string, selectors []spireentry.Selector, x509TTLSeconds, expiresAt int64) (string, error)
	deleteFn func(ctx context.Context, entryID string) error
	lookupFn func(ctx context.Context, spiffeID string) ([]spireentry.Selector, error)
}

func (s *stubEntryClient) CreateChildEntry(ctx context.Context, parentID, childSpiffeID string, selectors []spireentry.Selector, x509TTLSeconds, expiresAt int64) (string, error) {
	if s.createFn != nil {
		return s.createFn(ctx, parentID, childSpiffeID, selectors, x509TTLSeconds, expiresAt)
	}
	return "", errUnconfiguredStub
}

func (s *stubEntryClient) DeleteEntry(ctx context.Context, entryID string) error {
	if s.deleteFn != nil {
		return s.deleteFn(ctx, entryID)
	}
	return errUnconfiguredStub
}

func (s *stubEntryClient) LookupSelectors(ctx context.Context, spiffeID string) ([]spireentry.Selector, error) {
	if s.lookupFn != nil {
		return s.lookupFn(ctx, spiffeID)
	}
	return nil, errUnconfiguredStub
}

// defaultLookupSelectors is the selector-consistency check's default test fixture: the caller was
// attested in namespace "agents" — matching the k8s:ns=agents used
// throughout this file's test manifests, so tests that do not care about
// the selector-consistency check specifically do not have to configure it
// themselves.
func defaultLookupSelectors(context.Context, string) ([]spireentry.Selector, error) {
	return []spireentry.Selector{{Type: "k8s", Value: "ns:agents"}, {Type: "k8s", Value: "sa:nhi-test-vend-parent"}}, nil
}

var errUnconfiguredStub = errUnconfigured{}

type errUnconfigured struct{}

func (errUnconfigured) Error() string { return "test stub not configured for this call" }

// --- test fixtures: a fake CA + a fake dual bundle, standing in for the
// SPIRE trust bundle so these tests exercise the REAL cryptographic paths
// (JWT-SVID validation, x5c chain verification) without a live cluster. ---

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"test-ca"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

func (ca *testCA) leaf(t *testing.T, id spiffeid.ID) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(id.String())
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"test-leaf"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// fakeBundle implements the bundleSource interface (mtls.go) with a single
// fixed trust domain, backed by a real x509 CA and a real JWT signing key —
// so jwtsvid.ParseAndValidate and signature.Verify run their actual
// cryptographic checks in these tests, not a stub.
type fakeBundle struct {
	trustDomain spiffeid.TrustDomain
	x509        *x509bundle.Bundle
	jwt         *jwtbundle.Bundle
}

func (f *fakeBundle) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return f.x509, nil
}

func (f *fakeBundle) GetJWTBundleForTrustDomain(td spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	return f.jwt, nil
}

const testTrustDomain = "lab.local"

func newFakeBundle(t *testing.T, ca *testCA, jwtKeyID string, jwtKey *ecdsa.PrivateKey) *fakeBundle {
	t.Helper()
	td := spiffeid.RequireTrustDomainFromString(testTrustDomain)
	return &fakeBundle{
		trustDomain: td,
		x509:        x509bundle.FromX509Authorities(td, []*x509.Certificate{ca.cert}),
		jwt:         jwtbundle.FromJWTAuthorities(td, map[string]crypto.PublicKey{jwtKeyID: jwtKey.Public()}),
	}
}

// mintJWTSVID builds a real, validly-signed JWT-SVID for subject/audience,
// signed by jwtKey under jwtKeyID — exactly the shape jwtsvid.ParseAndValidate
// expects (kid header, sub/aud/exp claims).
func mintJWTSVID(t *testing.T, jwtKeyID string, jwtKey *ecdsa.PrivateKey, subject spiffeid.ID, audience string, expiry time.Time) string {
	t.Helper()
	opts := (&josejwt.SignerOptions{}).WithType("JWT").WithHeader(josejwt.HeaderKey("kid"), jwtKeyID)
	signer, err := josejwt.NewSigner(josejwt.SigningKey{Algorithm: josejwt.ES256, Key: jwtKey}, opts)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.Claims{
		Subject:  subject.String(),
		Audience: jwt.Audience{audience},
		Expiry:   jwt.NewNumericDate(expiry),
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func mustID(t *testing.T, s string) spiffeid.ID {
	t.Helper()
	id, err := spiffeid.FromString(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// signManifest signs m's canonical bytes as parentID's own X.509-SVID would
// would, returning m with Signature populated.
func signManifest(t *testing.T, ca *testCA, parentID spiffeid.ID, m manifest.SpawnManifest) manifest.SpawnManifest {
	t.Helper()
	leaf, key := ca.leaf(t, parentID)
	payload, err := m.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signature.Sign(payload, key, []*x509.Certificate{leaf})
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = sig
	return m
}

const jwtKeyID = "test-jwt-key-1"

// harness bundles everything a handleVend test needs: a CA, a JWT signing
// key, a fake bundle built from both, and a stub policy engine / SPIRE
// entry client / store — the same three externals handleVend's steps 4-7
// call out to.
type harness struct {
	ca       *testCA
	jwtKey   *ecdsa.PrivateKey
	bundle   *fakeBundle
	srv      *server
	auditBuf *bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ca := newTestCA(t)
	jwtKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle := newFakeBundle(t, ca, jwtKeyID, jwtKey)

	var buf bytes.Buffer
	srv := &server{
		cfg: config{
			audience:          "spiffe://lab.local/svc/vending-service",
			nodeAliasSpiffeID: "spiffe://lab.local/node/nhi-lab",
		},
		audit:        audit.New(&buf),
		bundles:      bundle,
		trustDomain:  bundle.trustDomain,
		now:          func() time.Time { return time.Unix(1_800_000_000, 0) },
		store:        newInMemoryTestStore(t),
		policyEngine: &stubPolicyEngine{},
		entries:      &stubEntryClient{lookupFn: defaultLookupSelectors},
	}
	return &harness{ca: ca, jwtKey: jwtKey, bundle: bundle, srv: srv, auditBuf: &buf}
}

func (h *harness) request(t *testing.T, m manifest.SpawnManifest, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/delegations", bytes.NewReader(body))
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h.srv.handleVend(w, r)
	return w
}

// --- tests -----------------------------------------------------------------

func TestHandleVendRejectsMissingAuth(t *testing.T) {
	h := newHarness(t)
	m := manifest.SpawnManifest{}
	w := h.request(t, m, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	assertAuditDeny(t, h.auditBuf, audit.StageAttest)
}

func TestHandleVendRejectsInvalidJWT(t *testing.T) {
	h := newHarness(t)
	m := manifest.SpawnManifest{}
	w := h.request(t, m, "not-a-real-jwt")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestHandleVendRejectsWrongAudience(t *testing.T) {
	h := newHarness(t)
	parentID := mustID(t, "spiffe://lab.local/agent/parent/t1")
	// Token minted for a DIFFERENT audience (e.g. the resource, not the
	// vending service) must be refused here even though it is a perfectly
	// valid token elsewhere in the trust domain.
	token := mintJWTSVID(t, jwtKeyID, h.jwtKey, parentID, "spiffe://lab.local/svc/resource", time.Unix(1_800_003_600, 0))
	m := manifest.SpawnManifest{}
	w := h.request(t, m, token)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

// TestHandleVendRejectsClaimedParentNotMatchingCaller is vending-flow step 3:
// the authenticated caller and the manifest's claimed parent_spiffe_id must
// be the same identity — an attacker holding a VALID JWT-SVID for its own
// identity must not be able to submit a manifest claiming to be someone
// else's parent.
func TestHandleVendRejectsClaimedParentNotMatchingCaller(t *testing.T) {
	h := newHarness(t)
	callerID := mustID(t, "spiffe://lab.local/agent/parent/attacker")
	claimedParentID := mustID(t, "spiffe://lab.local/agent/parent/victim")

	token := mintJWTSVID(t, jwtKeyID, h.jwtKey, callerID, h.srv.cfg.audience, time.Unix(1_800_003_600, 0))
	m := manifest.SpawnManifest{
		ParentSpiffeID: claimedParentID.String(), ChildPathHint: "child/c1",
		RequestedScopes: []string{"resource:read:datasetA"},
		ChildSelectors:  map[string]string{"k8s:ns": "agents", "k8s:sa": "some-child-sa"},
		TTLSeconds:      300, Nonce: "n1",
	}
	// Signed correctly by the CLAIMED parent's key, not the caller's — the
	// x5c check alone would pass; only cross-checking against the JWT-SVID
	// subject catches this.
	m = signManifest(t, h.ca, claimedParentID, m)

	w := h.request(t, m, token)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	ev := lastAuditEvent(t, h.auditBuf)
	if ev.Outcome != audit.OutcomeDeny {
		t.Fatalf("outcome = %q, want deny", ev.Outcome)
	}
	if ev.Detail.Reason == "" || !containsAll(ev.Detail.Reason, "does not match", "authenticated caller") {
		t.Fatalf("deny reason does not name the actual mismatch: %q", ev.Detail.Reason)
	}
}

// TestHandleVendRelayedManifestDoesNotBurnTheRealParentsNonce is a
// regression test. An attacker RELAYS a manifest genuinely signed
// by the real parent (so signature verification passes) but submits it over
// its own, different, authenticated connection. The relay must still be
// denied (403, caller/claim mismatch) — but critically, it must NOT consume
// the (parent, nonce) pair, or the real parent's own later legitimate
// submission of that exact manifest would be refused as a replay it never
// committed. This is why the parent/caller check must run before nonce
// recording, not after.
func TestHandleVendRelayedManifestDoesNotBurnTheRealParentsNonce(t *testing.T) {
	h := newHarness(t)
	realParentID := mustID(t, "spiffe://lab.local/agent/parent/t1")
	attackerID := mustID(t, "spiffe://lab.local/agent/parent/attacker")

	m := manifest.SpawnManifest{
		ParentSpiffeID: realParentID.String(), ChildPathHint: "child/c1",
		RequestedScopes: []string{"resource:read:datasetA"},
		ChildSelectors:  map[string]string{"k8s:ns": "agents", "k8s:sa": "some-child-sa"},
		TTLSeconds:      300, Nonce: "captured-nonce",
	}
	// Genuinely signed by the real parent's own key — not a forgery.
	m = signManifest(t, h.ca, realParentID, m)

	// The attacker relays it over ITS OWN authenticated connection.
	attackerToken := mintJWTSVID(t, jwtKeyID, h.jwtKey, attackerID, h.srv.cfg.audience, time.Unix(1_800_003_600, 0))
	w1 := h.request(t, m, attackerToken)
	if w1.Code != http.StatusForbidden {
		t.Fatalf("relay: status = %d, want 403; body=%s", w1.Code, w1.Body.String())
	}

	// The REAL parent now legitimately submits the SAME manifest (same
	// nonce — it is, after all, the same spawn intent). This must NOT be
	// refused as a replay: the attacker's denied relay must not have
	// consumed the nonce.
	h.srv.policyEngine = &stubPolicyEngine{
		synthesizeFn: func(_ context.Context, req policyclient.SynthesizeRequest) (policyclient.SynthesizeResponse, error) {
			return policyclient.SynthesizeResponse{ChildScopes: []string{"resource:read:datasetA"}, PolicyID: "nhi_grants_" + req.ChainID, ExpiresAt: 1_800_000_300}, nil
		},
	}
	h.srv.entries = &stubEntryClient{
		lookupFn: defaultLookupSelectors,
		createFn: func(context.Context, string, string, []spireentry.Selector, int64, int64) (string, error) {
			return "entry-1", nil
		},
	}
	realToken := mintJWTSVID(t, jwtKeyID, h.jwtKey, realParentID, h.srv.cfg.audience, time.Unix(1_800_003_600, 0))
	w2 := h.request(t, m, realToken)
	if w2.Code != http.StatusCreated {
		t.Fatalf("real parent's legitimate submission = %d, want 201 (must not be refused as a replay caused by the attacker's denied relay); body=%s",
			w2.Code, w2.Body.String())
	}
}

// TestHandleVendRejectsForgedSignature: a manifest signed by a key that does
// NOT belong to the claimed parent (e.g. an attacker's own X.509-SVID key)
// must be refused, and refused specifically for signature failure — not
// merely because some later step happens to fail too.
func TestHandleVendRejectsForgedSignature(t *testing.T) {
	h := newHarness(t)
	parentID := mustID(t, "spiffe://lab.local/agent/parent/t1")
	attackerID := mustID(t, "spiffe://lab.local/agent/parent/attacker")

	token := mintJWTSVID(t, jwtKeyID, h.jwtKey, parentID, h.srv.cfg.audience, time.Unix(1_800_003_600, 0))
	m := manifest.SpawnManifest{
		ParentSpiffeID: parentID.String(), ChildPathHint: "child/c1",
		RequestedScopes: []string{"resource:read:datasetA"},
		ChildSelectors:  map[string]string{"k8s:ns": "agents", "k8s:sa": "some-child-sa"},
		TTLSeconds:      300, Nonce: "n1",
	}
	// Signed by the ATTACKER's key/cert, but claiming parentID in the body.
	m = signManifest(t, h.ca, attackerID, m)

	w := h.request(t, m, token)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	ev := lastAuditEvent(t, h.auditBuf)
	if ev.Stage != audit.StageAttest || ev.Outcome != audit.OutcomeDeny {
		t.Fatalf("event = %+v, want attest/deny", ev)
	}
	if !containsAll(ev.Detail.Reason, "signature") {
		t.Fatalf("deny reason does not name signature failure: %q", ev.Detail.Reason)
	}
}

// TestHandleVendRejectsReplayedNonce proves replay protection is not
// vacuous: the FIRST submission of a given (parent, nonce) must reach past
// attestation (it will fail later, at the policy-engine step, because this
// harness has no policy engine configured — that is fine, the assertion
// here is specifically about the nonce check's own outcome on each attempt).
func TestHandleVendRejectsReplayedNonce(t *testing.T) {
	h := newHarness(t)
	parentID := mustID(t, "spiffe://lab.local/agent/parent/t1")
	token := mintJWTSVID(t, jwtKeyID, h.jwtKey, parentID, h.srv.cfg.audience, time.Unix(1_800_003_600, 0))

	buildManifest := func() manifest.SpawnManifest {
		m := manifest.SpawnManifest{
			ParentSpiffeID: parentID.String(), ChildPathHint: "child/c1",
			RequestedScopes: []string{"resource:read:datasetA"},
			ChildSelectors:  map[string]string{"k8s:ns": "agents", "k8s:sa": "some-child-sa"},
			TTLSeconds:      300, Nonce: "reused-nonce",
		}
		return signManifest(t, h.ca, parentID, m)
	}

	// First submission: must NOT be denied for nonce reuse (it will fail
	// later at the policy-engine call, which is nil here — a 500, not a
	// nonce-replay 409).
	w1 := h.request(t, buildManifest(), token)
	if w1.Code == http.StatusConflict {
		t.Fatalf("first submission must not be treated as a replay: %s", w1.Body.String())
	}

	// Second submission with the SAME nonce: must be refused specifically as
	// a replay (409), not merely fail some other way.
	w2 := h.request(t, buildManifest(), token)
	if w2.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (nonce replay refused); body=%s", w2.Code, w2.Body.String())
	}
	ev := lastAuditEvent(t, h.auditBuf)
	if !containsAll(ev.Detail.Reason, "already been used") {
		t.Fatalf("deny reason does not name nonce reuse: %q", ev.Detail.Reason)
	}
}

func TestHandleVendRejectsMalformedManifest(t *testing.T) {
	h := newHarness(t)
	parentID := mustID(t, "spiffe://lab.local/agent/parent/t1")
	token := mintJWTSVID(t, jwtKeyID, h.jwtKey, parentID, h.srv.cfg.audience, time.Unix(1_800_003_600, 0))

	m := manifest.SpawnManifest{
		ParentSpiffeID: parentID.String(),
		ChildPathHint:  "not-shaped-like-a-child", // fails Validate()
		TTLSeconds:     300, Nonce: "n1", Signature: "irrelevant",
	}
	w := h.request(t, m, token)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// TestHandleVendRejectsSelectorsOutsideCallersOwnNamespace is a regression
// test: a manifest naming child_selectors in a DIFFERENT k8s namespace than
// the one the caller was itself attested in must be refused. Without this,
// any authenticated parent could name the protected resource's own pod's
// selectors and have SPIRE hand that unrelated pod an SVID for a SPIFFE ID
// inside a delegation chain it was never forked into.
func TestHandleVendRejectsSelectorsOutsideCallersOwnNamespace(t *testing.T) {
	h := newHarness(t)
	parentID := mustID(t, "spiffe://lab.local/agent/parent/t1")
	token := mintJWTSVID(t, jwtKeyID, h.jwtKey, parentID, h.srv.cfg.audience, time.Unix(1_800_003_600, 0))

	// The caller (parentID) was itself attested in namespace "agents"
	// (defaultLookupSelectors), but the manifest names namespace "nhi" —
	// e.g. the protected resource's own namespace.
	m := manifest.SpawnManifest{
		ParentSpiffeID:  parentID.String(),
		ChildPathHint:   "child/c1",
		RequestedScopes: []string{"resource:read:datasetA"},
		ChildSelectors:  map[string]string{"k8s:ns": "nhi", "k8s:sa": "resource"},
		TTLSeconds:      300, Nonce: "n1",
	}
	m = signManifest(t, h.ca, parentID, m)

	entryCreated := false
	h.srv.entries = &stubEntryClient{
		lookupFn: defaultLookupSelectors, // caller's own ns is "agents"
		createFn: func(context.Context, string, string, []spireentry.Selector, int64, int64) (string, error) {
			entryCreated = true
			return "should-not-happen", nil
		},
	}

	w := h.request(t, m, token)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if entryCreated {
		t.Fatal("no SPIRE entry should have been created for cross-namespace selectors")
	}
	ev := lastAuditEvent(t, h.auditBuf)
	if ev.Outcome != audit.OutcomeDeny {
		t.Fatalf("outcome = %q, want deny", ev.Outcome)
	}
	if !containsAll(ev.Detail.Reason, "inconsistent", "attested selectors") {
		t.Fatalf("deny reason does not name the selector-consistency check: %q", ev.Detail.Reason)
	}
}

// TestHandleVendRejectsNamespaceOnlySelectors is a regression test: a
// manifest whose
// child_selectors carry ONLY k8s:ns (no k8s:sa, no k8s:pod-uid, nothing that
// distinguishes one pod from another) must be refused. Without this, SPIRE's
// subset-match semantics mean the resulting entry matches EVERY pod
// attested into that namespace — including the submitting parent's own pod
// and any unrelated pod that happens to share it — handing the child's
// chain_id to workloads that were never forked into the delegation at all.
// Without the check, exactly this shape got a 201. This is a
// manifest.Validate() failure (400), caught even before signature
// verification — structurally distinct from the cross-namespace check (403, requires a live selector lookup) — so the
// audit event fires at the same "invalid manifest" denial every other
// Validate() failure uses.
func TestHandleVendRejectsNamespaceOnlySelectors(t *testing.T) {
	h := newHarness(t)
	parentID := mustID(t, "spiffe://lab.local/agent/parent/t1")
	token := mintJWTSVID(t, jwtKeyID, h.jwtKey, parentID, h.srv.cfg.audience, time.Unix(1_800_003_600, 0))

	m := manifest.SpawnManifest{
		ParentSpiffeID:  parentID.String(),
		ChildPathHint:   "child/c1",
		RequestedScopes: []string{"resource:read:datasetA"},
		ChildSelectors:  map[string]string{"k8s:ns": "agents"}, // matches every pod in "agents"
		TTLSeconds:      300, Nonce: "n1",
	}
	m = signManifest(t, h.ca, parentID, m)

	entryCreated := false
	h.srv.entries = &stubEntryClient{
		lookupFn: defaultLookupSelectors,
		createFn: func(context.Context, string, string, []spireentry.Selector, int64, int64) (string, error) {
			entryCreated = true
			return "should-not-happen", nil
		},
	}

	w := h.request(t, m, token)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if entryCreated {
		t.Fatal("no SPIRE entry should have been created for a namespace-only selector set")
	}
	ev := lastAuditEvent(t, h.auditBuf)
	if ev.Stage != audit.StageAttest || ev.Outcome != audit.OutcomeDeny {
		t.Fatalf("event = %+v, want attest/deny", ev)
	}
	if !containsAll(ev.Detail.Reason, "pod-distinguishing selector") {
		t.Fatalf("deny reason does not name the missing pod-distinguishing selector: %q", ev.Detail.Reason)
	}
}

// TestHandleVendRejectsWhenCallerHasNoLookupableSelectors: LookupSelectors
// returning nothing (e.g. the caller's own entry carries no k8s:ns for some
// reason) must fail CLOSED, not be treated as "no constraint".
func TestHandleVendRejectsWhenCallerHasNoLookupableSelectors(t *testing.T) {
	h := newHarness(t)
	parentID := mustID(t, "spiffe://lab.local/agent/parent/t1")
	token := mintJWTSVID(t, jwtKeyID, h.jwtKey, parentID, h.srv.cfg.audience, time.Unix(1_800_003_600, 0))

	m := manifest.SpawnManifest{
		ParentSpiffeID:  parentID.String(),
		ChildPathHint:   "child/c1",
		RequestedScopes: []string{"resource:read:datasetA"},
		ChildSelectors:  map[string]string{"k8s:ns": "agents", "k8s:sa": "some-child-sa"},
		TTLSeconds:      300, Nonce: "n1",
	}
	m = signManifest(t, h.ca, parentID, m)

	h.srv.entries = &stubEntryClient{
		lookupFn: func(context.Context, string) ([]spireentry.Selector, error) { return nil, nil },
	}

	w := h.request(t, m, token)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (fail closed); body=%s", w.Code, w.Body.String())
	}
}

// --- test helpers ------------------------------------------------------

func assertAuditDeny(t *testing.T, buf *bytes.Buffer, wantStage string) {
	t.Helper()
	ev := lastAuditEvent(t, buf)
	if ev.Stage != wantStage {
		t.Errorf("stage = %q, want %q", ev.Stage, wantStage)
	}
	if ev.Outcome != audit.OutcomeDeny {
		t.Errorf("outcome = %q, want deny", ev.Outcome)
	}
}

func lastAuditEvent(t *testing.T, buf *bytes.Buffer) audit.Event {
	t.Helper()
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) == 0 || len(lines[0]) == 0 {
		t.Fatalf("no audit events emitted")
	}
	var ev audit.Event
	if err := json.Unmarshal(lines[len(lines)-1], &ev); err != nil {
		t.Fatalf("last audit line is not valid JSON: %v (%s)", err, lines[len(lines)-1])
	}
	return ev
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !bytes.Contains([]byte(s), []byte(sub)) {
			return false
		}
	}
	return true
}

// newInMemoryTestStore opens a throwaway SQLite-backed store for tests that
// need to get past the nonce-check step. See internal/store/store_test.go
// for the store package's own, more thorough unit tests.
func newInMemoryTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestHandleVendHappyPathPersistsAttenuatedDelegation drives the full
// success path (steps 1-7) with a stub policy engine that ATTENUATES the
// request — child_scopes is a strict subset of requested_scopes, exactly
// what the deterministic synthesizer does in production. This is the
// end-to-end shape verify-vending.sh exercises against the real cluster; here it
// runs in-process against fakes so it can assert on internal state (the
// persisted delegation record, the exact audit trail) that an HTTP-only
// integration test cannot see directly.
func TestHandleVendHappyPathPersistsAttenuatedDelegation(t *testing.T) {
	h := newHarness(t)
	parentID := mustID(t, "spiffe://lab.local/agent/parent/t1")
	token := mintJWTSVID(t, jwtKeyID, h.jwtKey, parentID, h.srv.cfg.audience, time.Unix(1_800_003_600, 0))

	var gotSynthReq policyclient.SynthesizeRequest
	h.srv.policyEngine = &stubPolicyEngine{
		synthesizeFn: func(_ context.Context, req policyclient.SynthesizeRequest) (policyclient.SynthesizeResponse, error) {
			gotSynthReq = req
			// Attenuation: caller asked for A and B, policy engine
			// (deriving Π(P) itself) only grants A.
			return policyclient.SynthesizeResponse{
				ChildScopes: []string{"resource:read:datasetA"},
				PolicyID:    "nhi_grants_" + req.ChainID,
				ExpiresAt:   1_800_000_300,
			}, nil
		},
	}
	var gotCreateSelectors []spireentry.Selector
	h.srv.entries = &stubEntryClient{
		lookupFn: defaultLookupSelectors,
		createFn: func(_ context.Context, parentAlias, childSpiffeID string, selectors []spireentry.Selector, ttl, expiresAt int64) (string, error) {
			gotCreateSelectors = selectors
			if parentAlias != h.srv.cfg.nodeAliasSpiffeID {
				t.Errorf("entry parent_id = %q, want the node alias %q", parentAlias, h.srv.cfg.nodeAliasSpiffeID)
			}
			return "entry-xyz", nil
		},
	}

	m := manifest.SpawnManifest{
		ParentSpiffeID:  parentID.String(),
		ChildPathHint:   "child/c1",
		RequestedScopes: []string{"resource:read:datasetA", "resource:read:datasetB"},
		TaskContext:     "demo",
		ChildSelectors:  map[string]string{"k8s:ns": "agents", "k8s:sa": "nhi-test-vend-child"},
		TTLSeconds:      300,
		Nonce:           "happy-path-nonce",
	}
	m = signManifest(t, h.ca, parentID, m)

	w := h.request(t, m, token)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}

	var resp delegationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.ChildScopes) != 1 || resp.ChildScopes[0] != "resource:read:datasetA" {
		t.Fatalf("child_scopes = %v, want exactly [resource:read:datasetA] (attenuated, not the requested superset)", resp.ChildScopes)
	}
	wantChildID := "spiffe://lab.local/agent/parent/t1/child/c1"
	if resp.ChildSpiffeID != wantChildID {
		t.Fatalf("child_spiffe_id = %q, want %q", resp.ChildSpiffeID, wantChildID)
	}
	if resp.ChainID == "" {
		t.Fatal("chain_id must not be empty")
	}
	// chain_id must already satisfy the policy engine's ^[a-z0-9_]+$
	// contract — this is what makes it safe to
	// send onward without any further transform.
	for _, r := range resp.ChainID {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_') {
			t.Fatalf("chain_id %q contains a character outside [a-z0-9_]", resp.ChainID)
		}
	}

	if gotSynthReq.ParentSpiffeID != parentID.String() || gotSynthReq.ChildSpiffeID != wantChildID {
		t.Fatalf("policy engine request = %+v", gotSynthReq)
	}
	// The request
	// to the policy engine must carry no parent-scopes field at all — this
	// is enforced structurally by policyclient.SynthesizeRequest simply
	// having no such field, asserted here by round-tripping through JSON
	// and checking no such key appears.
	raw, _ := json.Marshal(gotSynthReq)
	if bytes.Contains(raw, []byte("parent_scope")) {
		t.Fatalf("request to policy engine must not mention parent scopes: %s", raw)
	}

	if len(gotCreateSelectors) != 2 {
		t.Fatalf("selectors passed to SPIRE Entry API = %v, want 2", gotCreateSelectors)
	}

	// The delegation record must be persisted and match what was returned.
	rec, err := h.srv.store.GetDelegation(context.Background(), resp.ChainID)
	if err != nil {
		t.Fatalf("GetDelegation: %v", err)
	}
	if rec.EntryID != "entry-xyz" || len(rec.GrantedScopes) != 1 || rec.GrantedScopes[0] != "resource:read:datasetA" {
		t.Fatalf("persisted record = %+v", rec)
	}
	if rec.RevokedAt != nil {
		t.Fatalf("a freshly vended delegation must not be revoked")
	}

	// The vend audit event must show BOTH what was requested and what was
	// actually granted, so the attenuation gap is auditable after the fact
	// (attribution — the whole point of this lab).
	vendEvent := lastAuditEvent(t, h.auditBuf)
	if vendEvent.Stage != audit.StageVend || vendEvent.Outcome != audit.OutcomeAllow {
		t.Fatalf("last event = %+v, want vend/allow", vendEvent)
	}
	if len(vendEvent.Detail.RequestedScopes) != 2 || len(vendEvent.Detail.ChildScopes) != 1 {
		t.Fatalf("vend audit event does not show the attenuation gap: %+v", vendEvent.Detail)
	}
}

// TestHandleVendRejectsEmptyAttenuationResult is a regression test: a
// caller with NO overlap between what it
// requested and what it actually holds (Π(requested) ∩ Π(P) = ∅ — modelled
// here by a stub policy engine returning an empty ChildScopes, exactly what
// an unknown/no-authority parent gets) must be refused, not
// handed a 201 and a live, if scopeless, SPIRE identity. Also asserts the
// already-written (now-orphaned) grant module is cleaned up.
func TestHandleVendRejectsEmptyAttenuationResult(t *testing.T) {
	h := newHarness(t)
	parentID := mustID(t, "spiffe://lab.local/agent/parent/t1")
	token := mintJWTSVID(t, jwtKeyID, h.jwtKey, parentID, h.srv.cfg.audience, time.Unix(1_800_003_600, 0))

	var disposedChain string
	h.srv.policyEngine = &stubPolicyEngine{
		synthesizeFn: func(_ context.Context, req policyclient.SynthesizeRequest) (policyclient.SynthesizeResponse, error) {
			return policyclient.SynthesizeResponse{ChildScopes: nil, PolicyID: "nhi_grants_" + req.ChainID, ExpiresAt: 1_800_000_300}, nil
		},
		disposeFn: func(_ context.Context, chainID string) error { disposedChain = chainID; return nil },
	}
	entryCreated := false
	h.srv.entries = &stubEntryClient{
		lookupFn: defaultLookupSelectors,
		createFn: func(context.Context, string, string, []spireentry.Selector, int64, int64) (string, error) {
			entryCreated = true
			return "entry-should-not-happen", nil
		},
	}

	m := manifest.SpawnManifest{
		ParentSpiffeID:  parentID.String(),
		ChildPathHint:   "child/c1",
		RequestedScopes: []string{"resource:read:datasetA"},
		ChildSelectors:  map[string]string{"k8s:ns": "agents", "k8s:sa": "nhi-test-vend-child"},
		TTLSeconds:      300, Nonce: "empty-attenuation-nonce",
	}
	m = signManifest(t, h.ca, parentID, m)

	w := h.request(t, m, token)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if entryCreated {
		t.Fatal("no SPIRE entry should have been created for a zero-authority mint")
	}
	if disposedChain == "" {
		t.Fatal("the orphaned (scopeless) grant module the policy engine already wrote should have been cleaned up")
	}
	ev := lastAuditEvent(t, h.auditBuf)
	if ev.Stage != audit.StageVend || ev.Outcome != audit.OutcomeDeny {
		t.Fatalf("event = %+v, want vend/deny", ev)
	}
	if !containsAll(ev.Detail.Reason, "no scopes") {
		t.Fatalf("deny reason does not name the empty-attenuation refusal: %q", ev.Detail.Reason)
	}
}

// TestHandleDisposeRejectsNonParentCaller: only the delegation's OWN parent
// may revoke it. An authenticated caller that is not that parent (e.g. an
// unrelated agent, or even the child itself) must be refused — disposal is
// not "any authenticated identity may delete any delegation".
func TestHandleDisposeRejectsNonParentCaller(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if err := h.srv.store.CreateDelegation(ctx, store.DelegationRecord{
		ChainID: "c_test1", ParentSpiffeID: "spiffe://lab.local/agent/parent/t1",
		ChildSpiffeID: "spiffe://lab.local/agent/parent/t1/child/c1",
		GrantedScopes: []string{"resource:read:datasetA"},
		EntryID:       "entry-1", PolicyID: "nhi_grants_c_test1",
		IssuedAt: 1, TTL: 300, ExpiresAt: 400,
	}); err != nil {
		t.Fatal(err)
	}

	strangerID := mustID(t, "spiffe://lab.local/agent/parent/stranger")
	token := mintJWTSVID(t, jwtKeyID, h.jwtKey, strangerID, h.srv.cfg.audience, time.Unix(1_800_003_600, 0))

	r := httptest.NewRequest(http.MethodDelete, "/delegations/c_test1", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.SetPathValue("chain_id", "c_test1")
	w := httptest.NewRecorder()
	h.srv.handleDispose(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	rec, err := h.srv.store.GetDelegation(ctx, "c_test1")
	if err != nil {
		t.Fatal(err)
	}
	if rec.RevokedAt != nil {
		t.Fatal("a delegation must not be revoked by a non-parent caller")
	}
}

// TestHandleDisposeByParentRevokesAndDeletesEntry proves the parent CAN
// revoke its own delegation, and that disposal actually calls both external
// systems (SPIRE entry deletion, policy engine grant removal) rather than
// only updating local bookkeeping.
func TestHandleDisposeByParentRevokesAndDeletesEntry(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	parentID := mustID(t, "spiffe://lab.local/agent/parent/t1")

	if err := h.srv.store.CreateDelegation(ctx, store.DelegationRecord{
		ChainID: "c_test2", ParentSpiffeID: parentID.String(),
		ChildSpiffeID: parentID.String() + "/child/c1",
		GrantedScopes: []string{"resource:read:datasetA"},
		EntryID:       "entry-2", PolicyID: "nhi_grants_c_test2",
		IssuedAt: 1, TTL: 300, ExpiresAt: 400,
	}); err != nil {
		t.Fatal(err)
	}

	var deletedEntryID, disposedChainID string
	h.srv.entries = &stubEntryClient{
		deleteFn: func(_ context.Context, entryID string) error { deletedEntryID = entryID; return nil },
	}
	h.srv.policyEngine = &stubPolicyEngine{
		disposeFn: func(_ context.Context, chainID string) error { disposedChainID = chainID; return nil },
	}

	token := mintJWTSVID(t, jwtKeyID, h.jwtKey, parentID, h.srv.cfg.audience, time.Unix(1_800_003_600, 0))
	r := httptest.NewRequest(http.MethodDelete, "/delegations/c_test2", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.SetPathValue("chain_id", "c_test2")
	w := httptest.NewRecorder()
	h.srv.handleDispose(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if deletedEntryID != "entry-2" {
		t.Fatalf("SPIRE entry deletion was not called with the right entry_id: got %q", deletedEntryID)
	}
	if disposedChainID != "c_test2" {
		t.Fatalf("policy engine dispose was not called with the right chain_id: got %q", disposedChainID)
	}
	rec, err := h.srv.store.GetDelegation(ctx, "c_test2")
	if err != nil {
		t.Fatal(err)
	}
	if rec.RevokedAt == nil {
		t.Fatal("delegation must be marked revoked after disposal")
	}
	if rec.RevocationReason != "revoked_on_demand" {
		t.Fatalf("revocation_reason = %q, want revoked_on_demand", rec.RevocationReason)
	}
}

// TestReaperReapsExpiredDelegation is the "orphaned child" test: a
// delegation whose TTL has passed and which nobody disposed of must be
// caught and disposed of by the reaper, attributed to the service's own
// identity rather than a caller.
func TestReaperReapsExpiredDelegation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if err := h.srv.store.CreateDelegation(ctx, store.DelegationRecord{
		ChainID: "c_orphan", ParentSpiffeID: "spiffe://lab.local/agent/parent/dead-parent",
		ChildSpiffeID: "spiffe://lab.local/agent/parent/dead-parent/child/c1",
		GrantedScopes: []string{"resource:read:datasetA"},
		EntryID:       "entry-orphan", PolicyID: "nhi_grants_c_orphan",
		IssuedAt: 1, TTL: 300, ExpiresAt: 400, // now() below is well past this
	}); err != nil {
		t.Fatal(err)
	}

	var deleted, disposed bool
	h.srv.entries = &stubEntryClient{deleteFn: func(context.Context, string) error { deleted = true; return nil }}
	h.srv.policyEngine = &stubPolicyEngine{disposeFn: func(context.Context, string) error { disposed = true; return nil }}

	h.srv.reapOnce(ctx)

	if !deleted || !disposed {
		t.Fatalf("reaper did not dispose the orphaned child: deleted=%v disposed=%v", deleted, disposed)
	}
	rec, err := h.srv.store.GetDelegation(ctx, "c_orphan")
	if err != nil {
		t.Fatal(err)
	}
	if rec.RevokedAt == nil || rec.RevocationReason != "ttl_expired" {
		t.Fatalf("expected the orphan to be revoked with reason ttl_expired, got %+v", rec)
	}
	ev := lastAuditEvent(t, h.auditBuf)
	if ev.Stage != audit.StageDispose || ev.ChainID != "c_orphan" {
		t.Fatalf("reaper did not emit a dispose audit event for the orphan: %+v", ev)
	}
	if ev.ActorSpiffeID != h.srv.cfg.audience {
		t.Fatalf("reaper-initiated disposal must be attributed to this service's own identity, got %q", ev.ActorSpiffeID)
	}
}
