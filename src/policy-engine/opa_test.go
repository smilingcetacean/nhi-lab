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
