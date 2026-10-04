// Package spireentry wraps the SPIRE Entry API (spire-api-sdk) the vending
// service uses to create and delete child registration entries — the
// mechanism by which identities are minted at runtime.
//
// This client authenticates with the service's own X.509-SVID over
// mTLS, matched against server.conf's admin_ids. A JWT-SVID does not
// authorize here. This package holds no opinion on WHAT may be minted —
// SPIRE's admin API is all-or-nothing — the caller (main.go) is
// where every constraint on selectors, TTL and SPIFFE ID shape is enforced.
package spireentry

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
)

type Client struct {
	conn  *grpc.ClientConn
	entry entryv1.EntryClient
}

// Dial opens a gRPC connection to the SPIRE server's admin endpoint over
// mTLS using tlsCfg (built by the caller with tlsconfig.MTLSClientConfig, so
// this package stays agnostic of go-spiffe's X509Source plumbing).
func Dial(ctx context.Context, target string, tlsCfg *tls.Config) (*Client, error) {
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, fmt.Errorf("dial spire-server admin endpoint %s: %w", target, err)
	}
	return &Client{conn: conn, entry: entryv1.NewEntryClient(conn)}, nil
}

func (c *Client) Close() error { return c.conn.Close() }

// Selector is a type:value pair, e.g. {Type: "k8s", Value: "ns:agents"}.
type Selector struct {
	Type  string
	Value string
}

// ParseChildSelectors converts the spawn manifest's child_selectors map
// (for example {"k8s:ns": "agents", "k8s:pod-uid": "<uid>"}) into
// SPIRE selectors. The map KEY is "<selector-type>:<subtype>" (matching the
// shape scripts/register-entries.sh's `-selector` flags use, e.g.
// "k8s:ns:agents" == type "k8s", value "ns:agents") and the map VALUE is the
// subtype's value; the two are joined back into one SPIRE selector per
// entry. A key with no ':' is rejected rather than guessed at.
//
// This function only checks syntax and non-emptiness. It does NOT enforce
// that the resulting selector set is narrow enough to identify one pod —
// that is manifest.Validate()'s job, which main.go's handleVend
// always calls before ParseChildSelectors is ever reached. A caller that
// invokes this function without having first run Validate() gets no
// protection against a namespace-only selector set matching every pod in a
// namespace.
func ParseChildSelectors(childSelectors map[string]string) ([]Selector, error) {
	if len(childSelectors) == 0 {
		return nil, fmt.Errorf("child_selectors must not be empty")
	}
	out := make([]Selector, 0, len(childSelectors))
	for k, v := range childSelectors {
		selType, subtype, found := strings.Cut(k, ":")
		if !found || selType == "" || subtype == "" {
			return nil, fmt.Errorf("child_selectors key %q must be of the form <type>:<subtype> (e.g. \"k8s:ns\")", k)
		}
		out = append(out, Selector{Type: selType, Value: subtype + ":" + v})
	}
	return out, nil
}

// LookupSelectors returns the selectors of the registration entry (or
// entries — ordinarily exactly one) for spiffeID. Used by main.go's
// namespace-consistency check: a manifest's child_selectors must be a consistent
// extension of the CALLER's own attested selectors (specifically, the same
// k8s namespace), which requires knowing what the caller was actually
// attested against — not merely what SPIFFE ID its JWT-SVID names.
func (c *Client) LookupSelectors(ctx context.Context, spiffeID string) ([]Selector, error) {
	id, err := parseSPIFFEID(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("spiffe_id: %w", err)
	}
	resp, err := c.entry.ListEntries(ctx, &entryv1.ListEntriesRequest{
		Filter: &entryv1.ListEntriesRequest_Filter{BySpiffeId: id},
		OutputMask: &types.EntryMask{
			SpiffeId:  true,
			Selectors: true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("ListEntries(spiffe_id=%s): %w", spiffeID, err)
	}
	var out []Selector
	for _, e := range resp.Entries {
		for _, s := range e.Selectors {
			out = append(out, Selector{Type: s.Type, Value: s.Value})
		}
	}
	return out, nil
}

// CreateChildEntry creates (or, if an identical entry already exists,
// idempotently reuses) a SPIRE registration entry for childSpiffeID,
// parented to parentID (the node alias, never an individual
// agent), with the given selectors and TTL. expiresAt additionally bounds
// the ENTRY itself (SPIRE's own entry.expires_at, distinct from the X.509
// SVID TTL): past that time SPIRE refuses to issue or renew any SVID under
// this entry even if this service never calls Dispose — the mechanism that
// makes the TTL reaper's job "clean up bookkeeping and the OPA grant" rather
// than "the only thing standing between an orphaned child and a live SVID".
func (c *Client) CreateChildEntry(ctx context.Context, parentID, childSpiffeID string, selectors []Selector, x509TTLSeconds, expiresAt int64) (entryID string, err error) {
	parentSPIFFEID, err := parseSPIFFEID(parentID)
	if err != nil {
		return "", fmt.Errorf("parent_id: %w", err)
	}
	childSPIFFEID, err := parseSPIFFEID(childSpiffeID)
	if err != nil {
		return "", fmt.Errorf("child spiffe_id: %w", err)
	}

	pbSelectors := make([]*types.Selector, len(selectors))
	for i, s := range selectors {
		pbSelectors[i] = &types.Selector{Type: s.Type, Value: s.Value}
	}

	resp, err := c.entry.BatchCreateEntry(ctx, &entryv1.BatchCreateEntryRequest{
		Entries: []*types.Entry{
			{
				SpiffeId:    childSPIFFEID,
				ParentId:    parentSPIFFEID,
				Selectors:   pbSelectors,
				X509SvidTtl: int32(x509TTLSeconds),
				ExpiresAt:   expiresAt,
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("BatchCreateEntry: %w", err)
	}
	if len(resp.Results) != 1 {
		return "", fmt.Errorf("BatchCreateEntry: expected 1 result, got %d", len(resp.Results))
	}
	result := resp.Results[0]
	code := codes.Code(result.Status.GetCode())
	switch code {
	case codes.OK, codes.AlreadyExists:
		if result.Entry == nil {
			return "", fmt.Errorf("BatchCreateEntry: status %s but no entry returned", code)
		}
		return result.Entry.Id, nil
	default:
		return "", fmt.Errorf("BatchCreateEntry: %s: %s", code, result.Status.GetMessage())
	}
}

// DeleteEntry removes a registration entry by ID. Deleting an entry that
// does not exist is treated as success (mirrors the policy engine's
// deleteGrantModule, opa.go) — disposal must be safe to retry and safe to
// race against the reaper.
func (c *Client) DeleteEntry(ctx context.Context, entryID string) error {
	if entryID == "" {
		return nil
	}
	resp, err := c.entry.BatchDeleteEntry(ctx, &entryv1.BatchDeleteEntryRequest{Ids: []string{entryID}})
	if err != nil {
		return fmt.Errorf("BatchDeleteEntry: %w", err)
	}
	if len(resp.Results) != 1 {
		return fmt.Errorf("BatchDeleteEntry: expected 1 result, got %d", len(resp.Results))
	}
	code := codes.Code(resp.Results[0].Status.GetCode())
	switch code {
	case codes.OK, codes.NotFound:
		return nil
	default:
		return fmt.Errorf("BatchDeleteEntry: %s: %s", code, resp.Results[0].Status.GetMessage())
	}
}

func parseSPIFFEID(s string) (*types.SPIFFEID, error) {
	const scheme = "spiffe://"
	if !strings.HasPrefix(s, scheme) {
		return nil, fmt.Errorf("%q is not a spiffe:// URI", s)
	}
	rest := s[len(scheme):]
	td, path, _ := strings.Cut(rest, "/")
	if td == "" {
		return nil, fmt.Errorf("%q has no trust domain", s)
	}
	if path != "" {
		path = "/" + path
	}
	return &types.SPIFFEID{TrustDomain: td, Path: path}, nil
}
