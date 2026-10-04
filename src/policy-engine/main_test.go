package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

// synthesizeRequest must have no field a "parent_scopes" JSON key could ever
// populate. This is the strongest enforceable version of the "Π(P) is never
// caller-supplied" rule — not "we don't read it in this code path today" but "there is no
// field to read it into, so unmarshal silently drops it, whatever the wire
// body contains". Mirrors TestOPAInputExcludesChainID in src/resource.
func TestSynthesizeRequestHasNoParentScopesField(t *testing.T) {
	typ := reflect.TypeOf(synthesizeRequest{})
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "parent_scopes" {
			t.Fatalf("synthesizeRequest must not carry a parent_scopes field: %s", typ.Field(i).Name)
		}
	}

	withParentScopes := []byte(`{"chain_id":"c1","parent_spiffe_id":"p","child_spiffe_id":"c",
		"requested_scopes":["a"],"ttl_seconds":60,
		"parent_scopes":["a","b","c","admin:everything"]}`)
	without := []byte(`{"chain_id":"c1","parent_spiffe_id":"p","child_spiffe_id":"c",
		"requested_scopes":["a"],"ttl_seconds":60}`)

	var withReq, withoutReq synthesizeRequest
	if err := json.Unmarshal(withParentScopes, &withReq); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(without, &withoutReq); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(withReq, withoutReq) {
		t.Fatalf("a caller-supplied parent_scopes key changed the decoded request:\n%+v\nvs\n%+v", withReq, withoutReq)
	}
}

func mustSpiffeCertRequest(t *testing.T, method, path, spiffeID string, body []byte) *http.Request {
	t.Helper()
	u, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{u}}},
	}
	return r
}

// End-to-end handler test: a caller claiming an inflated parent_scopes value
// must not get more than the intersection of what it actually REQUESTED and
// what Π(P) — derived by this service from OPA plus the bootstrap table —
// actually contains. This is the request-smuggling analogue of
// TestRequiredScopesIgnoreCallerInput in src/resource.
func TestHandleSynthesizeIgnoresCallerSuppliedParentScopes(t *testing.T) {
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/policies":
			_ = json.NewEncoder(w).Encode(opaPolicyListResponse{Result: nil})
		case r.Method == http.MethodPut:
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
			// The parent genuinely holds only datasetA.
			"spiffe://lab.local/agent/parent/t1": {"resource:read:datasetA"},
		},
		now: func() time.Time { return time.Unix(1000, 0) },
	}

	body := []byte(`{
		"chain_id":"chain_1",
		"parent_spiffe_id":"spiffe://lab.local/agent/parent/t1",
		"child_spiffe_id":"spiffe://lab.local/agent/parent/t1/child/c1",
		"requested_scopes":["resource:read:datasetA","resource:read:datasetB"],
		"ttl_seconds":60,
		"parent_scopes":["resource:read:datasetA","resource:read:datasetB","admin:everything"]
	}`)
	r := mustSpiffeCertRequest(t, http.MethodPost, "/synthesize", "spiffe://lab.local/svc/vending-service", body)
	w := httptest.NewRecorder()
	srv.handleSynthesize(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp synthesizeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	// Only datasetA: the caller's claimed parent_scopes (which included
	// datasetB and admin:everything) must have been completely ignored.
	if len(resp.ChildScopes) != 1 || resp.ChildScopes[0] != "resource:read:datasetA" {
		t.Fatalf("child_scopes = %v, want exactly [resource:read:datasetA] — a caller-asserted "+
			"parent_scopes value leaked into the grant", resp.ChildScopes)
	}
	if resp.ExpiresAt != 1060 {
		t.Errorf("expires_at = %d, want 1060 (now=1000 + ttl=60)", resp.ExpiresAt)
	}
	if resp.PolicyID != "nhi_grants_chain_1" {
		t.Errorf("policy_id = %q, want nhi_grants_chain_1", resp.PolicyID)
	}
}

// Unknown parent (absent from both OPA and bootstrap) must attenuate the
// whole request to the empty set, end to end through the handler.
func TestHandleSynthesizeUnknownParentYieldsEmptyGrant(t *testing.T) {
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(opaPolicyListResponse{})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer opaSrv.Close()

	srv := &server{
		audit:       newAuditor(&bytes.Buffer{}),
		synthesizer: deterministicSynthesizer{},
		opa:         newOPAClient(opaSrv.Client(), opaSrv.URL),
		bootstrap:   map[string][]string{},
		now:         func() time.Time { return time.Unix(1000, 0) },
	}

	body := []byte(`{"chain_id":"c2","parent_spiffe_id":"spiffe://lab.local/agent/parent/ghost",
		"child_spiffe_id":"spiffe://lab.local/agent/parent/ghost/child/c1",
		"requested_scopes":["resource:read:datasetA"],"ttl_seconds":30}`)
	r := mustSpiffeCertRequest(t, http.MethodPost, "/synthesize", "spiffe://lab.local/svc/vending-service", body)
	w := httptest.NewRecorder()
	srv.handleSynthesize(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp synthesizeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.ChildScopes) != 0 {
		t.Fatalf("child_scopes = %v, want empty for an unknown parent", resp.ChildScopes)
	}
}

func TestHandleSynthesizeRejectsMissingFields(t *testing.T) {
	srv := &server{audit: newAuditor(&bytes.Buffer{}), now: time.Now}
	r := mustSpiffeCertRequest(t, http.MethodPost, "/synthesize", "spiffe://lab.local/svc/vending-service",
		[]byte(`{"chain_id":"","parent_spiffe_id":"p","child_spiffe_id":"c","ttl_seconds":30}`))
	w := httptest.NewRecorder()
	srv.handleSynthesize(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandleSynthesizeRejectsNonPositiveTTL(t *testing.T) {
	srv := &server{audit: newAuditor(&bytes.Buffer{}), now: time.Now}
	r := mustSpiffeCertRequest(t, http.MethodPost, "/synthesize", "spiffe://lab.local/svc/vending-service",
		[]byte(`{"chain_id":"c1","parent_spiffe_id":"p","child_spiffe_id":"c","ttl_seconds":0}`))
	w := httptest.NewRecorder()
	srv.handleSynthesize(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

// Every rejection must still leave an audit record — the same discipline
// src/resource follows, and for the same reason (the negative tests need
// both the denial and the evidence of it).
func TestHandleSynthesizeMissingFieldsIsAudited(t *testing.T) {
	var buf bytes.Buffer
	srv := &server{audit: newAuditor(&buf), now: time.Now}
	r := mustSpiffeCertRequest(t, http.MethodPost, "/synthesize", "spiffe://lab.local/svc/vending-service",
		[]byte(`{"chain_id":"","parent_spiffe_id":"","child_spiffe_id":"","ttl_seconds":30}`))
	w := httptest.NewRecorder()
	srv.handleSynthesize(w, r)

	var ev auditEvent
	if err := json.Unmarshal(buf.Bytes(), &ev); err != nil {
		t.Fatalf("no audit event emitted: %v", err)
	}
	if ev.Outcome != "deny" {
		t.Errorf("outcome = %q, want deny", ev.Outcome)
	}
	if ev.ActorSpiffeID != "spiffe://lab.local/svc/vending-service" {
		t.Errorf("actor_spiffe_id = %q", ev.ActorSpiffeID)
	}
}

func TestHandleDisposeRemovesTheCorrectPolicyID(t *testing.T) {
	var gotPath, gotMethod string
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer opaSrv.Close()

	srv := &server{
		audit: newAuditor(&bytes.Buffer{}),
		opa:   newOPAClient(opaSrv.Client(), opaSrv.URL),
		now:   time.Now,
	}

	r := mustSpiffeCertRequest(t, http.MethodDelete, "/synthesize/chain_1", "spiffe://lab.local/svc/vending-service", nil)
	r.SetPathValue("chain_id", "chain_1")
	w := httptest.NewRecorder()
	srv.handleDispose(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("opa method = %q, want DELETE", gotMethod)
	}
	if gotPath != "/v1/policies/"+policyID("chain_1") {
		t.Errorf("opa path = %q, want /v1/policies/%s", gotPath, policyID("chain_1"))
	}
}

func TestActorFromRequestRequiresClientCertificate(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/synthesize", nil)
	if _, err := actorFromRequest(r); err == nil {
		t.Fatal("expected an error when no TLS client certificate is present")
	}
}
