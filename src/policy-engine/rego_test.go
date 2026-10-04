package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSlugify(t *testing.T) {
	cases := []struct{ in, want string }{
		{"chain-abc", "chain_abc"},
		{"chain_abc_123", "chain_abc_123"},
		{"CHAIN-ABC", "chain_abc"},
		{"t1/child/c1", "t1_child_c1"},
		{"weird!!chars??here", "weird__chars__here"},
		{"", ""},
		{"spiffe://lab.local/agent/parent/t1/child/c1", "spiffe___lab_local_agent_parent_t1_child_c1"},
	}
	for _, c := range cases {
		if got := slugify(c.in); got != c.want {
			t.Errorf("slugify(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// policyID and packageName use the SAME slug but DIFFERENT
// separators. Getting this wrong means disposal (which only has chain_id)
// targets the wrong OPA policy ID, or the rendered package does not live
// where nhi/resource.rego expects it (data.nhi.grants.<slug>).
func TestPolicyIDAndPackageNameShareSlugButDifferInSeparator(t *testing.T) {
	chainID := "t1/child-c1"
	slug := slugify(chainID)

	id := policyID(chainID)
	pkg := packageName(chainID)

	if id != "nhi_grants_"+slug {
		t.Errorf("policyID(%q) = %q, want %q", chainID, id, "nhi_grants_"+slug)
	}
	if pkg != "nhi.grants."+slug {
		t.Errorf("packageName(%q) = %q, want %q", chainID, pkg, "nhi.grants."+slug)
	}
	// The confinement system.authz enforces: the policy ID must
	// start with "nhi_grants_" exactly, underscore-separated throughout.
	if !strings.HasPrefix(id, "nhi_grants_") {
		t.Errorf("policy ID %q does not start with nhi_grants_", id)
	}
	if strings.Contains(id, ".") {
		t.Errorf("policy ID %q must not contain '.' — system.authz matches it as a flat path segment", id)
	}
	// The package must be dot-separated so data.nhi.grants.<slug> resolves.
	if !strings.HasPrefix(pkg, "nhi.grants.") {
		t.Errorf("package %q does not start with nhi.grants.", pkg)
	}
}

func TestRenderGrantModuleRoundTripsThroughParseGrantModule(t *testing.T) {
	rego, err := renderGrantModule("chain-1", "spiffe://lab.local/agent/parent/t1/child/c1",
		[]string{"resource:read:datasetA", "resource:read:datasetB"}, 1785012840)
	if err != nil {
		t.Fatal(err)
	}
	gm, err := parseGrantModule(rego)
	if err != nil {
		t.Fatalf("rendered module did not parse: %v\n---\n%s", err, rego)
	}
	if gm.SpiffeID != "spiffe://lab.local/agent/parent/t1/child/c1" {
		t.Errorf("spiffe_id = %q", gm.SpiffeID)
	}
	if len(gm.Scopes) != 2 || gm.Scopes[0] != "resource:read:datasetA" || gm.Scopes[1] != "resource:read:datasetB" {
		t.Errorf("scopes = %v", gm.Scopes)
	}
	if gm.ExpiresAt != 1785012840 {
		t.Errorf("expires_at = %d", gm.ExpiresAt)
	}
}

// expires_at must ALWAYS be present in the rendered module. Rendering with an empty scopes slice (a fully
// attenuated child) must still produce a valid, parseable module rather than
// omitting fields.
func TestRenderGrantModuleAlwaysSetsExpiry(t *testing.T) {
	rego, err := renderGrantModule("chain-empty", "spiffe://lab.local/svc/test-workload", nil, 42)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rego, "expires_at := 42") {
		t.Fatalf("rendered module has no expires_at: %s", rego)
	}
	gm, err := parseGrantModule(rego)
	if err != nil {
		t.Fatalf("empty-scopes module did not parse: %v\n---\n%s", err, rego)
	}
	if len(gm.Scopes) != 0 {
		t.Errorf("scopes = %v, want empty", gm.Scopes)
	}
}

// The strict parser must REJECT anything not matching the exact shape this
// service writes — not guess at it. Each case below is a plausible way a
// hand-edited or corrupted module could deviate.
func TestParseGrantModuleRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"wrong package prefix", "package nhi.resource\n\nspiffe_id := \"x\"\n\nscopes := []\n\nexpires_at := 1\n"},
		{"missing expires_at", "package nhi.grants.c1\n\nspiffe_id := \"x\"\n\nscopes := []\n"},
		{"extra injected rule", "package nhi.grants.c1\n\nspiffe_id := \"x\"\n\nscopes := []\n\nexpires_at := 1\n\nallow := true\n"},
		{"unquoted spiffe_id", "package nhi.grants.c1\n\nspiffe_id := x\n\nscopes := []\n\nexpires_at := 1\n"},
		{"scopes not an array", "package nhi.grants.c1\n\nspiffe_id := \"x\"\n\nscopes := \"not-a-list\"\n\nexpires_at := 1\n"},
		{"expires_at not numeric", "package nhi.grants.c1\n\nspiffe_id := \"x\"\n\nscopes := []\n\nexpires_at := \"soon\"\n"},
		{"empty", ""},
		{"uppercase package segment", "package NHI.grants.c1\n\nspiffe_id := \"x\"\n\nscopes := []\n\nexpires_at := 1\n"},
		{"trailing garbage", "package nhi.grants.c1\n\nspiffe_id := \"x\"\n\nscopes := []\n\nexpires_at := 1\nextra garbage here"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := parseGrantModule(c.raw); err == nil {
				t.Fatalf("expected parseGrantModule to reject:\n%s", c.raw)
			}
		})
	}
}

// The rendered module must be valid Rego, checked with the real `opa` binary
// (v1.18.2, on PATH in this environment) rather than merely "the Go code that
// produced it compiled". This is the only test in the package that shells
// out; it is skipped if opa is not on PATH so the rest of the suite still
// runs in an environment without it.
func TestRenderedModuleIsValidRego(t *testing.T) {
	opaPath, err := exec.LookPath("opa")
	if err != nil {
		t.Skip("opa not on PATH; skipping opa check/eval validation")
	}

	rego, err := renderGrantModule("policy-verify", "spiffe://lab.local/svc/test-workload",
		[]string{"resource:read:datasetA"}, 1785012840)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	file := filepath.Join(dir, "grant.rego")
	if err := os.WriteFile(file, []byte(rego), 0o600); err != nil {
		t.Fatal(err)
	}

	checkCmd := exec.Command(opaPath, "check", file)
	if out, err := checkCmd.CombinedOutput(); err != nil {
		t.Fatalf("opa check failed: %v\n%s\n---\n%s", err, out, rego)
	}

	evalCmd := exec.Command(opaPath, "eval",
		"-d", file, "data.nhi.grants.policy_verify.scopes", "--format", "json")
	out, err := evalCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("opa eval failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "resource:read:datasetA") {
		t.Fatalf("opa eval did not surface the expected scope: %s", out)
	}
}
