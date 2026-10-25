// Package policyclient is the vending service's client for the policy
// engine's wire contract: HTTP/JSON over mTLS on :8443,
// POST /synthesize and DELETE /synthesize/{chain_id}.
//
// Per the policy-engine README: send only chain_id, parent_spiffe_id, child_spiffe_id, requested_scopes,
// task_context, ttl_seconds. There is no field here for parent scopes —
// deliberately, mirroring the policy engine's own synthesizeRequest shape,
// so the vending service (already holding unscoped SPIRE admin)
// cannot even accidentally assert Π(P).
package policyclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Client struct {
	http    *http.Client
	baseURL string
}

func New(httpClient *http.Client, baseURL string) *Client {
	return &Client{http: httpClient, baseURL: baseURL}
}

type SynthesizeRequest struct {
	ChainID         string   `json:"chain_id"`
	ParentSpiffeID  string   `json:"parent_spiffe_id"`
	ChildSpiffeID   string   `json:"child_spiffe_id"`
	RequestedScopes []string `json:"requested_scopes"`
	TaskContext     string   `json:"task_context"`
	TTLSeconds      int64    `json:"ttl_seconds"`
}

type SynthesizeResponse struct {
	ChildScopes []string `json:"child_scopes"`
	PolicyID    string   `json:"policy_id"`
	ExpiresAt   int64    `json:"expires_at"`
	// TTLShortened is set by the policy engine when ExpiresAt is earlier than
	// the requested ttl_seconds allowed, because the parent's own grant ends
	// first.
	TTLShortened bool `json:"ttl_shortened,omitempty"`
}

// Synthesize calls POST /synthesize. Errors carry the response body so a
// non-2xx (e.g. this service's SVID not authorized by CLIENT_SPIFFE_ID) is
// diagnosable from the vending service's own audit log without cross
// referencing the policy engine's.
func (c *Client) Synthesize(ctx context.Context, req SynthesizeRequest) (SynthesizeResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return SynthesizeResponse{}, fmt.Errorf("marshal synthesize request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/synthesize", bytes.NewReader(body))
	if err != nil {
		return SynthesizeResponse{}, fmt.Errorf("build synthesize request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return SynthesizeResponse{}, fmt.Errorf("call policy engine: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return SynthesizeResponse{}, fmt.Errorf("read policy engine response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return SynthesizeResponse{}, fmt.Errorf("policy engine POST /synthesize returned HTTP %d: %s",
			resp.StatusCode, bytes.TrimSpace(raw))
	}

	var out SynthesizeResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return SynthesizeResponse{}, fmt.Errorf("decode policy engine response: %w", err)
	}
	return out, nil
}

// Dispose calls DELETE /synthesize/{chain_id}. Idempotent on the policy
// engine's side, so this is safe to call from both
// handleDispose and the reaper without coordination.
func (c *Client) Dispose(ctx context.Context, chainID string) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/synthesize/"+chainID, nil)
	if err != nil {
		return fmt.Errorf("build dispose request: %w", err)
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("call policy engine: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read policy engine response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("policy engine DELETE /synthesize/%s returned HTTP %d: %s",
			chainID, resp.StatusCode, bytes.TrimSpace(raw))
	}
	return nil
}
