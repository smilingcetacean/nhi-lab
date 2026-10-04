package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// opaInput is exactly what the resource sends to OPA. The field set is a
// contract: the policy engine's generated Rego is written against it, so
// adding or renaming a field here is a design change, not a refactor.
//
// Note what is NOT here: chain_id. The X-NHI-Chain-Id header is an untrusted hint used only for correlation in audit
// events. Passing it into the authorization input would let a caller influence
// its own decision with an unverified string. TestOPAInputExcludesChainID
// enforces this.
type opaInput struct {
	// SpiffeID is the authenticated subject of the caller's JWT-SVID.
	SpiffeID string `json:"spiffe_id"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	// Scopes are the scopes this request REQUIRES, derived server-side from
	// method and path. Never caller-supplied. See routeFor.
	Scopes []string `json:"scopes"`
	// Now is the resource's clock, in Unix seconds, so that TTL conditions in
	// generated policy are evaluated against a value the test harness can
	// control. Rego's own time.now_ns() would make the expiry experiments
	// depend on wall-clock timing.
	Now int64 `json:"now"`
}

type opaRequest struct {
	Input opaInput `json:"input"`
}

// opaResponse is OPA's document response. `result` is absent, not false, when
// the queried path is undefined — which is what an OPA holding no policy at all
// returns. Modelling it as *bool keeps those two cases distinguishable.
type opaResponse struct {
	Result *bool `json:"result"`
}

// authorizer asks OPA whether a request may proceed.
type authorizer struct {
	client   *http.Client
	queryURL string
}

func newAuthorizer(client *http.Client, opaURL, decisionPath string) *authorizer {
	return &authorizer{
		client:   client,
		queryURL: opaURL + decisionPath,
	}
}

// decide returns the allow/deny answer, the latency of the round trip, and an
// error if OPA could not be consulted at all.
//
// The distinction between (false, nil) and (false, err) matters and is kept
// deliberately: the first is OPA saying no, the second is the resource being
// unable to ask. Both deny the request — that is the default-deny requirement —
// but they are different audit records and different operational problems.
func (a *authorizer) decide(ctx context.Context, in opaInput) (allowed bool, latency time.Duration, err error) {
	body, err := json.Marshal(opaRequest{Input: in})
	if err != nil {
		return false, 0, fmt.Errorf("marshal opa input: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.queryURL, bytes.NewReader(body))
	if err != nil {
		return false, 0, fmt.Errorf("build opa request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := a.client.Do(req)
	latency = time.Since(start)
	if err != nil {
		return false, latency, fmt.Errorf("call opa: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, latency, fmt.Errorf("read opa response: %w", err)
	}

	// A 401 here is worth calling out explicitly rather than folding into a
	// generic status error: it means OPA's system.authz policy refused this
	// service's own SPIFFE ID, i.e. the policy plane is misconfigured
	// or this pod is not running under the identity it thinks it is.
	if resp.StatusCode == http.StatusUnauthorized {
		return false, latency, fmt.Errorf(
			"opa refused this service's identity (HTTP 401) — check OPA's system.authz rule for svc/resource: %s",
			bytes.TrimSpace(raw))
	}
	if resp.StatusCode != http.StatusOK {
		return false, latency, fmt.Errorf("opa returned HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
	}

	var out opaResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return false, latency, fmt.Errorf("decode opa response %q: %w", raw, err)
	}

	// Undefined result: the decision path does not exist. That is the state of
	// a freshly started OPA with no base policy loaded, and it must deny —
	// silently treating "no policy" as "no restriction" is the exact failure
	// mode default-deny exists to prevent.
	if out.Result == nil {
		return false, latency, nil
	}
	return *out.Result, latency, nil
}
