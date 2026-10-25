package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

// opaClient is the policy engine's egress leg: mTLS to OPA with this
// service's own X509-SVID, exercising the three operations OPA's
// system.authz confines it to — list, write and delete under the nhi_grants_* prefix.
type opaClient struct {
	http    *http.Client
	baseURL string
}

func newOPAClient(client *http.Client, baseURL string) *opaClient {
	return &opaClient{http: client, baseURL: strings.TrimRight(baseURL, "/")}
}

// opaPolicyListItem is one element of GET /v1/policies. OPA's response
// includes more fields (ast, path) than this; only `id` and `raw` are read —
// the AST is not parsed by this service, see rego.go's parseGrantModule for
// why a narrow parser over the raw source is preferred instead.
type opaPolicyListItem struct {
	ID  string `json:"id"`
	Raw string `json:"raw"`
}

type opaPolicyListResponse struct {
	Result []opaPolicyListItem `json:"result"`
}

// listGrantModules returns every nhi_grants_* module currently loaded in OPA,
// strictly parsed. A module that fails to parse is an error for the whole
// call rather than silently skipped: if this service's own writer produced
// something parseGrantModule rejects, that is a bug worth surfacing loudly,
// not a grant worth guessing at.
func (c *opaClient) listGrantModules(ctx context.Context) (map[string]grantModule, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/policies", nil)
	if err != nil {
		return nil, fmt.Errorf("build list request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call opa: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read opa response: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf(
			"opa refused this service's identity (HTTP 401) — check system.authz for svc/policy-engine: %s",
			bytes.TrimSpace(raw))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("opa GET /v1/policies returned HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
	}

	var out opaPolicyListResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode opa policy list: %w", err)
	}

	modules := make(map[string]grantModule)
	for _, item := range out.Result {
		if !strings.HasPrefix(item.ID, "nhi_grants_") {
			continue
		}
		gm, err := parseGrantModule(item.Raw)
		if err != nil {
			return nil, fmt.Errorf("policy %q does not parse as a grant module: %w", item.ID, err)
		}
		modules[item.ID] = gm
	}
	return modules, nil
}

// putGrantModule loads (or replaces) one grant module. id must already be
// policyID(chainID) — that confinement is what OPA's system.authz enforces,
// not something this client double-checks.
func (c *opaClient) putGrantModule(ctx context.Context, id, rego string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/v1/policies/"+id, strings.NewReader(rego))
	if err != nil {
		return fmt.Errorf("build put request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	return c.do(req, "PUT /v1/policies/"+id)
}

// deleteGrantModule removes one grant module. OPA answers 404 for an id that
// does not exist; that is treated as success here, so disposal is idempotent.
// It has to be: the vending service removes the grant first and the SPIRE
// entry second, so a retry after a failure in between (from the API or from
// the reaper) finds the module already gone, and so can a revoke racing the
// reaper for the same chain_id.
func (c *opaClient) deleteGrantModule(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/v1/policies/"+id, nil)
	if err != nil {
		return fmt.Errorf("build delete request: %w", err)
	}
	return c.do(req, "DELETE /v1/policies/"+id, http.StatusNotFound)
}

// do sends req and requires HTTP 200, or one of the extra statuses in
// alsoOK, which the caller has decided mean the same thing as success.
func (c *opaClient) do(req *http.Request, label string, alsoOK ...int) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("call opa (%s): %w", label, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("opa refused this service's identity (HTTP 401) on %s — check system.authz for svc/policy-engine: %s",
			label, bytes.TrimSpace(raw))
	}
	if resp.StatusCode != http.StatusOK && !slices.Contains(alsoOK, resp.StatusCode) {
		return fmt.Errorf("opa %s returned HTTP %d: %s", label, resp.StatusCode, bytes.TrimSpace(raw))
	}
	return nil
}

// deriveParentScopes embodies the central rule: Π(P) is read
// back from OPA's own state, unioned with the static root-parent bootstrap
// table, and NEVER accepted from the caller. A parent that appears in
// neither source has Π(P) = ∅ — fail closed, not an error.
//
// now is the engine's own clock (injectable for tests), used to exclude
// expired grants from the union — an expired grant confers no authority to
// delegate, just as it confers none to act (nhi/resource.rego's `expired`).
func deriveParentScopes(grants map[string]grantModule, bootstrap map[string][]string, parentSpiffeID string, now time.Time) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(scopes []string) {
		for _, s := range scopes {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	if scopes, ok := bootstrap[parentSpiffeID]; ok {
		add(scopes)
	}
	nowUnix := now.Unix()
	for _, gm := range grants {
		if gm.SpiffeID != parentSpiffeID {
			continue
		}
		if gm.ExpiresAt < nowUnix {
			continue
		}
		add(gm.Scopes)
	}
	return out
}

// attenuateExpiry is the time analogue of Π(C) = requested ∩ Π(P): the child's
// expiry is the earlier of now + ttl and the earliest expires_at among the
// parent's live grants, so no child outlives any grant that contributed to the
// authority it was derived from. The request is shortened, never refused.
//
// A parent with no live grant (parentExpiry ok == false) is a root parent from
// the bootstrap table: static entries have no expiry of their own, so only the
// requested TTL applies. shortened reports whether the parent's expiry bound
// the result.
func attenuateExpiry(now time.Time, ttlSeconds int64, parentExpiry int64, hasParentExpiry bool) (expiresAt int64, shortened bool) {
	expiresAt = now.Unix() + ttlSeconds
	if hasParentExpiry && parentExpiry < expiresAt {
		return parentExpiry, true
	}
	return expiresAt, false
}

// deriveParentExpiry returns the earliest expires_at among the parent's live
// grants, read from the same OPA state as deriveParentScopes and with the same
// notion of "live". ok is false when the parent holds no live grant, which is
// the case for a bootstrap-only root (and for an unknown parent, whose empty
// Π(P) the vending service refuses anyway).
func deriveParentExpiry(grants map[string]grantModule, parentSpiffeID string, now time.Time) (earliest int64, ok bool) {
	nowUnix := now.Unix()
	for _, gm := range grants {
		if gm.SpiffeID != parentSpiffeID || gm.ExpiresAt < nowUnix {
			continue
		}
		if !ok || gm.ExpiresAt < earliest {
			earliest, ok = gm.ExpiresAt, true
		}
	}
	return earliest, ok
}
