// Command parentsim is a minimal Go parent, independent of the Python agent
// harness (src/agents/parent.py). It drives src/deploy/scripts/verify-vending.sh,
// the experiment suites and the identity-uniqueness demo against a live
// cluster, so "a test parent with a static entry submits a manifest" can be
// exercised in-cluster with no human action.
//
// It fetches its OWN X.509-SVID and a JWT-SVID (audience = the vending
// service) from the Workload API — exactly what a real parent agent will do
// — builds a spawn manifest, signs it (detached JWS, x5c-bound to its
// X.509-SVID), and either vends or
// disposes a delegation. Every knob a negative test needs (a corrupted
// signature, a fixed nonce for replay, a claimed parent that does not match
// the caller) is a flag, not a code change, so verify-vending.sh can drive every
// scenario from one binary.
//
// This is explicitly a scripted test harness — the seam where a real agent
// framework (and later an LLM-driven fork decision) would attach is
// parent.py, not this binary.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"nhi-lab/vending-service/internal/manifest"
	"nhi-lab/vending-service/internal/signature"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "parentsim:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: parentsim <vend|sign|dispose|get|whoami|call|fetch-jwt|bearer-call|x509-check|idle> [flags]")
	}
	mode := os.Args[1]

	// idle: block forever. This distroless image has no /bin/sleep (no
	// shell, no coreutils at all — deliberately, to keep this harness
	// minimal), so the test-fixture pods
	// (manifests/test/44-vending-test-parent.yaml,
	// 45-vending-test-child.yaml) run `["/parentsim", "idle"]` as their
	// container command instead of `["sleep", "infinity"]`, and
	// verify-vending.sh drives everything else via `kubectl exec ... parentsim
	// <mode>` against the already-running process's container.
	if mode == "idle" {
		// NOT select{} — with a single goroutine and no other channels in
		// play, the Go runtime's deadlock detector correctly identifies
		// that as unrecoverable and exits with "all goroutines are asleep
		// - deadlock!". A sleep loop blocks just as effectively without
		// tripping it.
		for {
			time.Sleep(time.Hour)
		}
	}
	fs := flag.NewFlagSet(mode, flag.ExitOnError)

	vendingURL := fs.String("vending-url", envOr("VENDING_SERVICE_URL", "http://vending-service.nhi.svc.cluster.local:8090"), "vending service base URL")
	audience := fs.String("audience", envOr("VENDING_AUDIENCE", "spiffe://lab.local/svc/vending-service"), "JWT-SVID audience for the vending service")
	socketPath := fs.String("socket", envOr("SPIFFE_ENDPOINT_SOCKET", "unix:///run/spire/sockets/agent.sock"), "Workload API socket")

	childPathHint := fs.String("child-path-hint", "child/c1", "manifest child_path_hint")
	scopes := fs.String("scopes", "resource:read:datasetA", "comma-separated requested_scopes")
	taskContext := fs.String("task-context", "parentsim demo task", "manifest task_context")
	selectors := fs.String("selectors", "k8s:ns=agents,k8s:sa=nhi-test-vend-child", "comma-separated key=value child_selectors")
	ttl := fs.Int64("ttl", 300, "manifest ttl_seconds")
	nonce := fs.String("nonce", "", "manifest nonce (random if empty) — set explicitly to test replay")
	claimParent := fs.String("claim-parent", "", "override parent_spiffe_id claimed in the manifest body (default: this workload's own SPIFFE ID) — used to test caller/claim mismatch")
	corruptSignature := fs.Bool("corrupt-signature", false, "flip a character in the manifest signature after signing — used to test forged-signature rejection")
	chainID := fs.String("chain-id", "", "chain_id (dispose/get modes only)")
	rawManifest := fs.String("raw-manifest", "", "in -mode=vend, submit this exact JSON manifest (built by -mode=sign) instead of building a new one — used to test a relayed/stolen manifest")

	// "call" mode: fetch a JWT-SVID for -call-audience and issue one HTTP
	// request to -call-url. Used by verify-vending.sh from the CHILD pod to
	// prove "the child obtains its own SVID via the Workload API with no
	// human action" and then exercises the resource with it — the same
	// binary plays parent (vend/dispose) and child (call) roles, since both
	// just need Workload API + HTTP.
	callAudience := fs.String("call-audience", "spiffe://lab.local/svc/resource", "JWT-SVID audience for -mode=call and -mode=fetch-jwt")
	callURL := fs.String("call-url", "", "URL to request in -mode=call and -mode=bearer-call")
	callMethod := fs.String("call-method", http.MethodGet, "HTTP method for -mode=call and -mode=bearer-call")
	bearerToken := fs.String("bearer-token", "", "token to present verbatim in -mode=bearer-call (see -mode=fetch-jwt)")

	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	httpClient := &http.Client{Timeout: 15 * time.Second}
	base := strings.TrimRight(*vendingURL, "/")

	// bearer-call issues exactly one HTTP request using a CALLER-SUPPLIED
	// token (-bearer-token), fetching nothing from the Workload API at all.
	// Deliberately checked FIRST, before any X.509/JWT fetch below: it is
	// used by verify-vending.sh to replay a token captured (via -mode=fetch-jwt)
	// BEFORE disposal, after the child's SPIRE registration entry has been
	// deleted — at which point a fresh Workload API fetch would itself fail
	// or hang, which is not what this check is testing. This specifically
	// proves resource access is denied even with a credential that is still
	// cryptographically valid (has not hit its own `exp`): the denial comes
	// from the OPA grant being removed, not merely from the child being
	// unable to obtain a new token.
	if mode == "bearer-call" {
		if *callURL == "" {
			return fmt.Errorf("bearer-call requires -call-url")
		}
		if *bearerToken == "" {
			return fmt.Errorf("bearer-call requires -bearer-token")
		}
		return postJSON(httpClient, *callMethod, *callURL, *bearerToken, nil)
	}

	// x509-check does not need a JWT-SVID either: it is a ONE-SHOT
	// (non-cached, non-streaming) fetch straight to the Workload API, used
	// to prove the negative half of the vending lifecycle — after disposal,
	// this must fail (or time out), because the SPIRE registration entry is
	// gone and the agent can no longer attest this pod against it.
	if mode == "x509-check" {
		svid, err := workloadapi.FetchX509SVID(ctx, workloadapi.WithAddr(*socketPath))
		if err != nil {
			fmt.Fprintln(os.Stderr, "HTTP N/A (workload API fetch failed, as expected once the entry is gone)")
			fmt.Printf(`{"error":%q}`+"\n", err.Error())
			os.Exit(2)
		}
		fmt.Printf(`{"spiffe_id":%q,"not_after":%q}`+"\n", svid.ID.String(), svid.Certificates[0].NotAfter.Format(time.RFC3339))
		return nil
	}

	// call and fetch-jwt need only a JWT-SVID (audience -call-audience), not
	// this workload's own X.509-SVID — kept separate from the vend/dispose/
	// get path below, which needs the X.509-SVID to sign a manifest.
	if mode == "call" || mode == "fetch-jwt" {
		callJWT, err := workloadapi.FetchJWTSVID(ctx, jwtsvid.Params{Audience: *callAudience}, workloadapi.WithAddr(*socketPath))
		if err != nil {
			return fmt.Errorf("fetch JWT-SVID (aud=%s): %w", *callAudience, err)
		}
		if mode == "fetch-jwt" {
			// Printed with no trailing newline and nothing else on stdout,
			// so `$(kubectl exec ... parentsim fetch-jwt)` captures exactly
			// the token and nothing else.
			fmt.Print(callJWT.Marshal())
			return nil
		}
		if *callURL == "" {
			return fmt.Errorf("call requires -call-url")
		}
		return postJSON(httpClient, *callMethod, *callURL, callJWT.Marshal(), nil)
	}

	clientOpt := workloadapi.WithClientOptions(workloadapi.WithAddr(*socketPath))
	x509Src, err := workloadapi.NewX509Source(ctx, clientOpt)
	if err != nil {
		return fmt.Errorf("fetch X509-SVID: %w", err)
	}
	defer x509Src.Close()
	svid, err := x509Src.GetX509SVID()
	if err != nil {
		return fmt.Errorf("get X509-SVID: %w", err)
	}
	ownID := svid.ID

	if mode == "whoami" {
		fmt.Printf(`{"spiffe_id":%q}`+"\n", ownID.String())
		return nil
	}

	jwtSVID, err := workloadapi.FetchJWTSVID(ctx, jwtsvid.Params{Audience: *audience}, workloadapi.WithAddr(*socketPath))
	if err != nil {
		return fmt.Errorf("fetch JWT-SVID (aud=%s): %w", *audience, err)
	}

	switch mode {
	case "sign":
		// Build and sign a manifest EXACTLY as "vend" does, but only print
		// it — no HTTP call. Used by verify-vending.sh to model a manifest the
		// real parent legitimately produced (correct signature, correct
		// x5c identity) being captured and later relayed by a DIFFERENT,
		// unrelated caller (-mode=vend -raw-manifest=<this output>) — the
		// wrong-caller-identity negative test needs a manifest that is
		// genuinely, correctly signed by the claimed parent, or it would be
		// indistinguishable from the forged-signature test (which fails at
		// signature verification instead of at the caller/claim check).
		m, err := buildAndSignManifest(*childPathHint, *scopes, *taskContext, *selectors, *ttl, *nonce, *claimParent, ownID, svid, *corruptSignature)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(m)
		if err != nil {
			return fmt.Errorf("marshal signed manifest: %w", err)
		}
		fmt.Print(string(raw))
		return nil

	case "vend":
		if *rawManifest != "" {
			// Relay a manifest built (and signed) elsewhere, submitted with
			// THIS caller's own JWT-SVID as the bearer token. See "sign"
			// above for why this exists.
			var m manifest.SpawnManifest
			if err := json.Unmarshal([]byte(*rawManifest), &m); err != nil {
				return fmt.Errorf("parse -raw-manifest: %w", err)
			}
			return postJSON(httpClient, http.MethodPost, base+"/delegations", jwtSVID.Marshal(), m)
		}
		m, err := buildAndSignManifest(*childPathHint, *scopes, *taskContext, *selectors, *ttl, *nonce, *claimParent, ownID, svid, *corruptSignature)
		if err != nil {
			return err
		}
		return postJSON(httpClient, http.MethodPost, base+"/delegations", jwtSVID.Marshal(), m)

	case "dispose":
		if *chainID == "" {
			return fmt.Errorf("dispose requires -chain-id")
		}
		return postJSON(httpClient, http.MethodDelete, base+"/delegations/"+*chainID, jwtSVID.Marshal(), nil)

	case "get":
		if *chainID == "" {
			return fmt.Errorf("get requires -chain-id")
		}
		return postJSON(httpClient, http.MethodGet, base+"/delegations/"+*chainID, jwtSVID.Marshal(), nil)

	default:
		return fmt.Errorf("unknown mode %q (want vend, sign, dispose, get, whoami, call, fetch-jwt, bearer-call, x509-check)", mode)
	}
}

func postJSON(client *http.Client, method, url, bearer string, body any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("call vending service: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	// Print the HTTP status on stderr (for a human watching the log) and the
	// exact response body on stdout (for the caller — verify-vending.sh — to
	// parse with jq). Exit non-zero on a non-2xx so `set -e`-style scripts
	// can detect failure without parsing JSON first.
	fmt.Fprintf(os.Stderr, "HTTP %d\n", resp.StatusCode)
	fmt.Println(string(raw))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		os.Exit(2)
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitNonEmpty(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseSelectors(s string) map[string]string {
	out := map[string]string{}
	for _, pair := range splitNonEmpty(s, ",") {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		out[k] = v
	}
	return out
}

func randomNonce() string {
	return fmt.Sprintf("n_%d", time.Now().UnixNano())
}

// buildAndSignManifest is the common construction shared by -mode=vend
// (without -raw-manifest) and -mode=sign: build the SpawnManifest, sign its
// canonical bytes with this workload's own X.509-SVID key, and
// optionally corrupt the resulting signature for the forged-signature
// negative test.
func buildAndSignManifest(childPathHint, scopes, taskContext, selectors string, ttl int64, nonce, claimParent string, ownID spiffeid.ID, svid *x509svid.SVID, corruptSig bool) (manifest.SpawnManifest, error) {
	claimed := ownID.String()
	if claimParent != "" {
		claimed = claimParent
	}
	n := nonce
	if n == "" {
		n = randomNonce()
	}
	m := manifest.SpawnManifest{
		ParentSpiffeID:  claimed,
		ChildPathHint:   childPathHint,
		RequestedScopes: splitNonEmpty(scopes, ","),
		TaskContext:     taskContext,
		ChildSelectors:  parseSelectors(selectors),
		TTLSeconds:      ttl,
		Nonce:           n,
	}
	payload, err := m.CanonicalBytes()
	if err != nil {
		return manifest.SpawnManifest{}, fmt.Errorf("canonicalize manifest: %w", err)
	}
	sig, err := signature.Sign(payload, svid.PrivateKey, svid.Certificates)
	if err != nil {
		return manifest.SpawnManifest{}, fmt.Errorf("sign manifest: %w", err)
	}
	if corruptSig {
		sig = corrupt(sig)
	}
	m.Signature = sig
	return m, nil
}

// corrupt flips one character within the JWS SIGNATURE segment (the part
// after the last '.'), producing something that still parses structurally
// (same number of '.'-separated segments) but fails signature verification.
//
// Deliberately NOT the literal last character of the whole string. A
// base64url-encoded ECDSA P-256 signature is 64 raw bytes = 512 bits, which
// is not a multiple of 6, so the FINAL base64 character encodes 2 meaningful
// bits plus 4 unused padding bits that a lenient decoder (Go's
// base64.RawURLEncoding, which this service's dependency go-jose uses)
// does not validate as zero. Flipping only that last character sometimes
// changes only a padding bit the decoder discards, silently producing the
// SAME decoded signature bytes — an intermittent no-op "corruption" that
// depends on which base64 character the true last byte happens to encode
// to for a given (randomized, ECDSA) signature. Observed directly: the same
// -corrupt-signature flag correctly triggered a 401 on one run of
// verify-vending.sh and silently produced a VALID signature (502 from a
// downstream timeout, having sailed through signature verification) on the
// very next run against the same code. Flipping the FIRST character of the
// signature segment instead is always within the segment's most
// significant, always-meaningful bits, so it always changes the decoded
// signature value.
func corrupt(s string) string {
	lastDot := strings.LastIndexByte(s, '.')
	if lastDot < 0 || lastDot == len(s)-1 {
		// No signature segment to target (e.g. an empty/malformed input);
		// fall back to guaranteeing SOME difference from the original.
		return s + "x"
	}
	b := []byte(s)
	i := lastDot + 1
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}
