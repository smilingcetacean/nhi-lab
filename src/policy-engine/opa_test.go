package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDeriveParentScopesUnionsBootstrapAndOPA(t *testing.T) {
	now := time.Unix(1000, 0)
	grants := map[string]grantModule{
		"nhi_grants_a": {SpiffeID: "spiffe://lab.local/agent/parent/t1", Scopes: []string{"resource:read:datasetB"}, ExpiresAt: 2000},
		// A different parent's grant must not leak in.
		"nhi_grants_b": {SpiffeID: "spiffe://lab.local/agent/parent/other", Scopes: []string{"admin:everything"}, ExpiresAt: 2000},
		// Expired grant for the SAME parent must be excluded.
		"nhi_grants_c": {SpiffeID: "spiffe://lab.local/agent/parent/t1", Scopes: []string{"resource:write:jobs"}, ExpiresAt: 500},
	}
	bootstrap := map[string][]string{
		"spiffe://lab.local/agent/parent/t1": {"resource:read:datasetA"},
	}

	got := deriveParentScopes(grants, bootstrap, "spiffe://lab.local/agent/parent/t1", now)
	want := map[string]bool{"resource:read:datasetA": true, "resource:read:datasetB": true}
	if len(got) != len(want) {
		t.Fatalf("Π(P) = %v, want exactly %v", got, want)
	}
	for _, s := range got {
		if !want[s] {
			t.Errorf("unexpected scope %q leaked into Π(P): %v", s, got)
		}
	}
}

// The core fail-closed case: a parent absent from both OPA and the bootstrap
// table has Π(P) = ∅, not an error and not a default grant.
func TestDeriveParentScopesUnknownParentIsEmpty(t *testing.T) {
	got := deriveParentScopes(nil, nil, "spiffe://lab.local/agent/parent/nobody", time.Unix(1000, 0))
	if len(got) != 0 {
		t.Fatalf("unknown parent yielded %v, want empty", got)
	}
}

func TestListGrantModulesFiltersToNhiGrantsPrefix(t *testing.T) {
	grantRego, err := renderGrantModule("c1", "spiffe://lab.local/svc/test-workload", []string{"resource:read:datasetA"}, 99999999999)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/policies" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		resp := opaPolicyListResponse{Result: []opaPolicyListItem{
			{ID: "system/authz", Raw: "package system.authz\n\ndefault allow := false\n"},
			{ID: "nhi/resource.rego", Raw: "package nhi.resource\n\ndefault allow := false\n"},
			{ID: policyID("c1"), Raw: grantRego},
		}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := newOPAClient(srv.Client(), srv.URL)
	got, err := client.listGrantModules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 nhi_grants_* module, got %d: %v", len(got), got)
	}
	gm, ok := got[policyID("c1")]
	if !ok {
		t.Fatalf("expected %q in result, got %v", policyID("c1"), got)
	}
	if gm.SpiffeID != "spiffe://lab.local/svc/test-workload" {
		t.Errorf("spiffe_id = %q", gm.SpiffeID)
	}
}

// If OPA ever held a module named nhi_grants_* that does not parse under our
// own strict grammar, that is a bug worth failing loudly on rather than
// silently excluding the module from Π(P) (which would look identical to
// "this parent has no grant" and mask the corruption).
func TestListGrantModulesRejectsUnparseableGrantContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := opaPolicyListResponse{Result: []opaPolicyListItem{
			{ID: "nhi_grants_corrupted", Raw: "package nhi.grants.corrupted\n\nallow := true\n"},
		}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := newOPAClient(srv.Client(), srv.URL)
	if _, err := client.listGrantModules(context.Background()); err == nil {
		t.Fatal("expected an error for an unparseable nhi_grants_* module")
	}
}

func TestListGrantModulesReportsOPAAuthzRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"unauthorized"}`))
	}))
	defer srv.Close()

	client := newOPAClient(srv.Client(), srv.URL)
	_, err := client.listGrantModules(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestDeriveParentExpiryTakesTheEarliestLiveGrant(t *testing.T) {
	now := time.Unix(1000, 0)
	parent := "spiffe://lab.local/agent/parent/t1/child/c1"
	grants := map[string]grantModule{
		"nhi_grants_a": {SpiffeID: parent, ExpiresAt: 5000},
		"nhi_grants_b": {SpiffeID: parent, ExpiresAt: 1800},
		"nhi_grants_c": {SpiffeID: parent, ExpiresAt: 3000},
		// Expired: must not drag the minimum below now.
		"nhi_grants_d": {SpiffeID: parent, ExpiresAt: 500},
		// Another identity's earlier grant must not count.
		"nhi_grants_e": {SpiffeID: "spiffe://lab.local/agent/parent/other", ExpiresAt: 1100},
	}
	got, ok := deriveParentExpiry(grants, parent, now)
	if !ok || got != 1800 {
		t.Fatalf("deriveParentExpiry = (%d, %v), want (1800, true)", got, ok)
	}
}

// A bootstrap-only root holds no grant module, so there is nothing to clamp to.
func TestDeriveParentExpiryRootHasNone(t *testing.T) {
	grants := map[string]grantModule{
		"nhi_grants_a": {SpiffeID: "spiffe://lab.local/agent/parent/t1/child/c1", ExpiresAt: 5000},
	}
	if got, ok := deriveParentExpiry(grants, "spiffe://lab.local/agent/parent/t1", time.Unix(1000, 0)); ok {
		t.Fatalf("root parent got an expiry bound %d", got)
	}
	if _, ok := deriveParentExpiry(nil, "spiffe://lab.local/agent/parent/t1", time.Unix(1000, 0)); ok {
		t.Fatal("no grants at all must yield no bound")
	}
}

func TestAttenuateExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	cases := []struct {
		name         string
		ttl          int64
		parentExpiry int64
		hasParent    bool
		want         int64
		wantShort    bool
	}{
		{"root, no clamp", 600, 0, false, 1600, false},
		{"parent outlives the request", 600, 5000, true, 1600, false},
		{"parent expires first", 600, 1200, true, 1200, true},
		{"parent expires exactly at the requested expiry", 600, 1600, true, 1600, false},
	}
	for _, tc := range cases {
		got, short := attenuateExpiry(now, tc.ttl, tc.parentExpiry, tc.hasParent)
		if got != tc.want || short != tc.wantShort {
			t.Errorf("%s: attenuateExpiry = (%d, %v), want (%d, %v)", tc.name, got, short, tc.want, tc.wantShort)
		}
	}
}

// OPA answers 404 for a DELETE of a policy id it does not hold. Disposal must
// treat that as done (a retry after a partial failure finds the grant already
// gone), while any other failure still surfaces.
func TestDeleteGrantModuleIsIdempotent(t *testing.T) {
	for _, tc := range []struct {
		status  int
		wantErr bool
	}{
		{http.StatusOK, false},
		{http.StatusNotFound, false},
		{http.StatusInternalServerError, true},
		{http.StatusUnauthorized, true},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete || r.URL.Path != "/v1/policies/nhi_grants_c1" {
				t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(tc.status)
		}))
		err := newOPAClient(srv.Client(), srv.URL).deleteGrantModule(context.Background(), "nhi_grants_c1")
		srv.Close()
		if (err != nil) != tc.wantErr {
			t.Errorf("OPA status %d: err = %v, wantErr = %v", tc.status, err, tc.wantErr)
		}
	}
}

// Only DELETE gets that leniency: a PUT that comes back 404 is still a failure.
func TestPutGrantModuleStillFailsOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if err := newOPAClient(srv.Client(), srv.URL).putGrantModule(context.Background(), "nhi_grants_c1", "package x\n"); err == nil {
		t.Fatal("expected an error for a 404 on PUT")
	}
}
