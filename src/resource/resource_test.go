package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRequiredScopesAreServerDerived(t *testing.T) {
	cases := []struct {
		method, path string
		want         []string
		known        bool
	}{
		{http.MethodGet, "/datasets/A", []string{"resource:read:datasetA"}, true},
		{http.MethodGet, "/datasets/B", []string{"resource:read:datasetB"}, true},
		{http.MethodPost, "/jobs", []string{"resource:write:jobs"}, true},
		// Method is part of the identity of an endpoint: holding the read
		// scope for /jobs must not let a caller POST to it.
		{http.MethodGet, "/jobs", nil, false},
		{http.MethodGet, "/datasets/C", nil, false},
	}
	for _, c := range cases {
		rt, known := routeFor(c.method, c.path)
		got := rt.requiredScopes
		if known != c.known {
			t.Errorf("%s %s: known = %v, want %v", c.method, c.path, known, c.known)
			continue
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s %s: scopes = %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

// The core contract: scopes are derived from the
// request line and from nothing else. If a future change ever threaded a
// caller-supplied value into the required scopes, this is what should fail.
func TestRequiredScopesIgnoreCallerInput(t *testing.T) {
	ra, _ := routeFor(http.MethodGet, "/datasets/A")
	rb, _ := routeFor(http.MethodGet, "/datasets/A")
	a, b := ra.requiredScopes, rb.requiredScopes
	if strings.Join(a, ",") != strings.Join(b, ",") {
		t.Fatal("required scopes are not a pure function of method and path")
	}
	if len(a) != 1 || a[0] != "resource:read:datasetA" {
		t.Fatalf("unexpected required scopes for /datasets/A: %v", a)
	}
}

// The chain id is a correlation hint and must never influence
// an authorization decision. The strongest enforceable version of that rule is
// that it never reaches OPA at all.
func TestOPAInputExcludesChainID(t *testing.T) {
	in := opaInput{
		SpiffeID: "spiffe://lab.local/agent/parent/t1/child/c1",
		Method:   http.MethodGet,
		Path:     "/datasets/A",
		Scopes:   []string{"resource:read:datasetA"},
		Now:      time.Now().Unix(),
	}
	raw, err := json.Marshal(opaRequest{Input: in})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	input, ok := decoded["input"].(map[string]any)
	if !ok {
		t.Fatalf("no input object in %s", raw)
	}
	for _, forbidden := range []string{"chain_id", "chain_id_source", "authorization", "token"} {
		if _, present := input[forbidden]; present {
			t.Errorf("OPA input must not carry %q: %s", forbidden, raw)
		}
	}
	// And the fields the policy engine's generated Rego is written against must be present.
	for _, required := range []string{"spiffe_id", "method", "path", "scopes", "now"} {
		if _, present := input[required]; !present {
			t.Errorf("OPA input is missing the contract field %q: %s", required, raw)
		}
	}
}

func TestChainIDProvenance(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/datasets/A", nil)
		id, src := chainIDFrom(r)
		if id != "" || src != chainSourceAbsent {
			t.Fatalf("got (%q, %q)", id, src)
		}
	})
	t.Run("client asserted", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/datasets/A", nil)
		r.Header.Set("X-NHI-Chain-Id", "chain-abc")
		id, src := chainIDFrom(r)
		if id != "chain-abc" || src != chainSourceClientAsserted {
			t.Fatalf("got (%q, %q)", id, src)
		}
	})
	t.Run("bounded", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/datasets/A", nil)
		r.Header.Set("X-NHI-Chain-Id", strings.Repeat("x", 500))
		id, _ := chainIDFrom(r)
		if len(id) != 128 {
			t.Fatalf("chain id not bounded: len = %d", len(id))
		}
	})
}

// A freshly started OPA holding no policy returns `{}` — the queried path is
// undefined rather than false. Treating that as anything but a denial is the
// precise failure default-deny exists to prevent, so it gets its own test.
func TestUndefinedPolicyResultDenies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	a := newAuthorizer(srv.Client(), srv.URL, "/v1/data/nhi/resource/allow")
	allowed, _, err := a.decide(context.Background(), opaInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatal("undefined OPA result must deny")
	}
}

func TestAuthorizerDecisions(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		body        string
		wantAllow   bool
		wantErr     bool
		errFragment string
	}{
		{name: "allow", status: 200, body: `{"result":true}`, wantAllow: true},
		{name: "deny", status: 200, body: `{"result":false}`},
		{name: "undefined", status: 200, body: `{}`},
		// A 401 means OPA's system.authz refused *this service's* identity —
		// a policy-plane misconfiguration, not a policy denial. The error must say
		// so, because the two look identical from the caller's side.
		{name: "opa refuses our identity", status: 401, body: `{"code":"unauthorized"}`,
			wantErr: true, errFragment: "system.authz"},
		{name: "opa error", status: 500, body: `boom`, wantErr: true, errFragment: "HTTP 500"},
		{name: "unparseable", status: 200, body: `not json`, wantErr: true, errFragment: "decode"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()

			a := newAuthorizer(srv.Client(), srv.URL, "/v1/data/nhi/resource/allow")
			allowed, _, err := a.decide(context.Background(), opaInput{})
			if c.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				if c.errFragment != "" && !strings.Contains(err.Error(), c.errFragment) {
					t.Fatalf("error %q does not mention %q", err, c.errFragment)
				}
				// Whatever went wrong, the request must not be allowed.
				if allowed {
					t.Fatal("an error must never allow the request")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if allowed != c.wantAllow {
				t.Fatalf("allowed = %v, want %v", allowed, c.wantAllow)
			}
		})
	}
}

// The resource sends what the request DEMANDS. This asserts the wire format
// the policy engine renders Rego against.
func TestAuthorizerSendsRequiredScopes(t *testing.T) {
	var got opaRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"result":true}`))
	}))
	defer srv.Close()

	a := newAuthorizer(srv.Client(), srv.URL, "/v1/data/nhi/resource/allow")
	_, _, err := a.decide(context.Background(), opaInput{
		SpiffeID: "spiffe://lab.local/svc/test-workload",
		Method:   http.MethodGet,
		Path:     "/datasets/A",
		Scopes:   []string{"resource:read:datasetA"},
		Now:      1785012840,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Input.SpiffeID != "spiffe://lab.local/svc/test-workload" {
		t.Errorf("spiffe_id = %q", got.Input.SpiffeID)
	}
	if len(got.Input.Scopes) != 1 || got.Input.Scopes[0] != "resource:read:datasetA" {
		t.Errorf("scopes = %v", got.Input.Scopes)
	}
	if got.Input.Now != 1785012840 {
		t.Errorf("now = %d", got.Input.Now)
	}
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		header  string
		want    string
		wantErr bool
	}{
		{"Bearer abc.def.ghi", "abc.def.ghi", false},
		{"bearer abc.def.ghi", "abc.def.ghi", false}, // scheme is case-insensitive
		{"", "", true},
		{"abc.def.ghi", "", true},
		{"Basic dXNlcjpwYXNz", "", true},
		{"Bearer ", "", true},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/datasets/A", nil)
		if c.header != "" {
			r.Header.Set("Authorization", c.header)
		}
		got, err := bearerToken(r)
		if (err != nil) != c.wantErr {
			t.Errorf("header %q: err = %v, wantErr %v", c.header, err, c.wantErr)
			continue
		}
		if got != c.want {
			t.Errorf("header %q: token = %q, want %q", c.header, got, c.want)
		}
	}
}

// The audit schema is shared lab-wide. Field names are what the
// experiment scripts parse, so a rename must break a test rather than a report.
func TestAuditEventSchema(t *testing.T) {
	var buf bytes.Buffer
	a := newAuditor(&buf)
	decision := true
	latency := 1.5
	a.emit(auditEvent{
		ChainID:       "chain-1",
		ActorSpiffeID: "spiffe://lab.local/agent/parent/t1/child/c1",
		Outcome:       "allow",
		Detail: detail{
			Method:            http.MethodGet,
			Path:              "/datasets/A",
			RequiredScopes:    []string{"resource:read:datasetA"},
			ChainIDSource:     chainSourceClientAsserted,
			PolicyDecision:    &decision,
			DecisionLatencyMs: &latency,
		},
	})

	var ev map[string]any
	if err := json.Unmarshal(buf.Bytes(), &ev); err != nil {
		t.Fatalf("audit event is not valid JSON: %v (%s)", err, buf.String())
	}
	for _, field := range []string{"timestamp", "stage", "chain_id", "actor_spiffe_id", "outcome", "detail"} {
		if _, ok := ev[field]; !ok {
			t.Errorf("audit event missing normative field %q: %s", field, buf.String())
		}
	}
	if ev["stage"] != stageOperate {
		t.Errorf("stage = %v, want %q", ev["stage"], stageOperate)
	}
	d := ev["detail"].(map[string]any)
	if d["chain_id_source"] != chainSourceClientAsserted {
		t.Errorf("chain_id_source = %v", d["chain_id_source"])
	}
	// One event per line: the log is JSON Lines, and the experiments read it that way.
	if strings.Count(strings.TrimSpace(buf.String()), "\n") != 0 {
		t.Errorf("audit event spans multiple lines: %q", buf.String())
	}
}

// Every rejection must leave a record — the negative tests assert the denial
// AND the audit event, so a silent refusal path would be a hole in the
// evidence rather than merely untidy.
func TestUnauthenticatedRequestIsDeniedAndAudited(t *testing.T) {
	var buf bytes.Buffer
	s := &server{
		cfg:   config{audience: "spiffe://lab.local/svc/resource"},
		audit: newAuditor(&buf),
		now:   func() time.Time { return time.Unix(1785012840, 0) },
	}

	r := httptest.NewRequest(http.MethodGet, "/datasets/A", nil)
	r.Header.Set("X-NHI-Chain-Id", "chain-9")
	w := httptest.NewRecorder()
	s.handleProtected(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	var ev auditEvent
	if err := json.Unmarshal(buf.Bytes(), &ev); err != nil {
		t.Fatalf("no audit event emitted: %v", err)
	}
	if ev.Outcome != "deny" {
		t.Errorf("outcome = %q, want deny", ev.Outcome)
	}
	// Unauthenticated, so there is no actor to attribute to. The field must be
	// empty rather than carrying anything the caller claimed.
	if ev.ActorSpiffeID != "" {
		t.Errorf("actor_spiffe_id = %q, want empty for an unauthenticated caller", ev.ActorSpiffeID)
	}
	// The chain id is still recorded for correlation, with its provenance.
	if ev.ChainID != "chain-9" || ev.Detail.ChainIDSource != chainSourceClientAsserted {
		t.Errorf("chain id = %q (%q)", ev.ChainID, ev.Detail.ChainIDSource)
	}
	// Nothing reached OPA, so there is no decision to report.
	if ev.Detail.PolicyDecision != nil {
		t.Error("policy_decision must be absent when OPA was never consulted")
	}
}
