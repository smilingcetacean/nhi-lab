package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// slugify turns a chain_id into the character set OPA policy IDs and Rego
// package name segments both accept: [a-z0-9_]. Every character outside that
// set becomes '_'. This transform is a fixed contract; get it wrong and
// disposal (which recomputes the same slug from the same chain_id) silently
// targets the wrong module.
func slugify(chainID string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(chainID) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

// policyID is the OPA policy ID this chain_id's grant is stored under —
// the last path segment of PUT/DELETE /v1/policies/<id>. It is what
// system.authz's startswith(input.path[2], "nhi_grants_") check matches
// against.
func policyID(chainID string) string {
	return "nhi_grants_" + slugify(chainID)
}

// packageName is the Rego package this chain_id's grant module declares.
// Note the separator differs from policyID: OPA's policy ID is an opaque
// filename-like string (underscore throughout), while a Rego package path is
// dot-separated, which is what makes it addressable at data.nhi.grants.<slug>
// for the containment rule in nhi/resource.rego. Same slug, two different
// renderings — that difference is the easiest part of the naming contract to
// get wrong, so it is factored into one function each way.
func packageName(chainID string) string {
	return "nhi.grants." + slugify(chainID)
}

// renderGrantModule produces exactly the grant shape nhi/resource.rego reads:
//
//	package nhi.grants.<slug>
//
//	spiffe_id := "..."
//
//	scopes := [...]
//
//	expires_at := <unix>
//
// expires_at is always set (never omitted): a grant with no expires_at would never expire under
// nhi/resource.rego's `expired()` rule, which treats an absent field as "not
// expired" rather than erroring.
func renderGrantModule(chainID, childSpiffeID string, scopes []string, expiresAt int64) (string, error) {
	if scopes == nil {
		scopes = []string{}
	}
	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		return "", fmt.Errorf("marshal scopes: %w", err)
	}
	spiffeIDJSON, err := json.Marshal(childSpiffeID)
	if err != nil {
		return "", fmt.Errorf("marshal spiffe_id: %w", err)
	}
	module := fmt.Sprintf(
		"package %s\n\nspiffe_id := %s\n\nscopes := %s\n\nexpires_at := %d\n",
		packageName(chainID), spiffeIDJSON, scopesJSON, expiresAt,
	)
	return module, nil
}

// grantModule is the strictly parsed content of one nhi_grants_* policy, as
// returned by OPA in GET /v1/policies.
type grantModule struct {
	SpiffeID  string
	Scopes    []string
	ExpiresAt int64
}

// grantModulePattern matches EXACTLY the shape renderGrantModule produces:
// this service is the only writer of these modules, so parsing does not need
// to tolerate hand-edited variations — it needs to refuse them. Anything that
// does not match this pattern is rejected rather than best-effort-guessed,
// by design: a strict, narrow parser over Rego semantics we control.
var grantModulePattern = regexp.MustCompile(
	`(?s)\Apackage nhi\.grants\.([a-z0-9_]+)\n+` +
		`spiffe_id := ("(?:[^"\\]|\\.)*")\n+` +
		`scopes := (\[[^\]]*\])\n+` +
		`expires_at := (-?[0-9]+)\n*\z`,
)

// parseGrantModule strictly parses one grant module's raw Rego source.
// Returns an error — never a best-effort partial result — for anything that
// does not match grantModulePattern exactly: a hand-edited module, a stray
// extra rule, an unterminated string, or a scopes array containing something
// other than JSON strings.
func parseGrantModule(raw string) (grantModule, error) {
	m := grantModulePattern.FindStringSubmatch(raw)
	if m == nil {
		return grantModule{}, fmt.Errorf("does not match the expected nhi.grants.<slug> shape")
	}
	var spiffeID string
	if err := json.Unmarshal([]byte(m[2]), &spiffeID); err != nil {
		return grantModule{}, fmt.Errorf("spiffe_id is not a valid JSON string: %w", err)
	}
	var scopes []string
	if err := json.Unmarshal([]byte(m[3]), &scopes); err != nil {
		return grantModule{}, fmt.Errorf("scopes is not a valid JSON array of strings: %w", err)
	}
	expiresAt, err := strconv.ParseInt(m[4], 10, 64)
	if err != nil {
		return grantModule{}, fmt.Errorf("expires_at is not a valid integer: %w", err)
	}
	return grantModule{SpiffeID: spiffeID, Scopes: scopes, ExpiresAt: expiresAt}, nil
}
