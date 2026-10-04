// Command resource is the lab's protected HTTP API — the "operate" stage of the
// NHI lifecycle.
//
// Two credentials meet here and must not be confused:
//
//   - INGRESS: callers authenticate with a JWT-SVID bearer token, validated
//     against the SPIRE trust bundle with an audience of this service's own
//     SPIFFE ID.
//   - EGRESS: this service authenticates to OPA with its own X509-SVID over
//     mTLS. It may ask OPA for decisions and may not write policy.
//
// Every request is default deny: it is refused unless OPA affirmatively
// returns true.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type config struct {
	listenAddr   string
	opaURL       string
	decisionPath string
	// audience is what a caller's JWT-SVID must be addressed to. Defaults to
	// this service's own SPIFFE ID so that a token minted for some other
	// service — a vending-service token, say — is rejected here even though it
	// is perfectly valid elsewhere in the trust domain.
	audience    string
	opaSpiffeID string
	socketPath  string
}

func loadConfig() config {
	return config{
		listenAddr:   env("LISTEN_ADDR", ":8080"),
		opaURL:       env("OPA_URL", "https://opa.opa.svc.cluster.local:8181"),
		decisionPath: env("OPA_DECISION_PATH", "/v1/data/nhi/resource/allow"),
		audience:     env("RESOURCE_AUDIENCE", "spiffe://lab.local/svc/resource"),
		opaSpiffeID:  env("OPA_SPIFFE_ID", "spiffe://lab.local/svc/opa"),
		socketPath:   env("SPIFFE_ENDPOINT_SOCKET", "unix:///run/spire/sockets/agent.sock"),
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("resource: %v", err)
	}
}

func run() error {
	cfg := loadConfig()
	audit := newAuditor(os.Stdout)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Ingress credential source: the trust bundle used to validate callers'
	// JWT-SVIDs. This never holds a caller's key — only the public bundle.
	clientOpt := workloadapi.WithClientOptions(workloadapi.WithAddr(cfg.socketPath))

	bundleSource, err := workloadapi.NewBundleSource(ctx, clientOpt)
	if err != nil {
		return fmt.Errorf("create trust bundle source (is the Workload API socket mounted at %s?): %w", cfg.socketPath, err)
	}
	defer bundleSource.Close()

	// Egress credential source: this service's own X509-SVID, presented to OPA.
	x509Src, err := workloadapi.NewX509Source(ctx, clientOpt)
	if err != nil {
		return fmt.Errorf("create X509 source: %w", err)
	}
	defer x509Src.Close()

	opaID, err := spiffeid.FromString(cfg.opaSpiffeID)
	if err != nil {
		return fmt.Errorf("parse OPA SPIFFE ID %q: %w", cfg.opaSpiffeID, err)
	}

	// Authorize OPA by its SPIFFE ID, not by hostname. The svc/opa entry has DNS SANs
	// to the svc/opa entry so that generic clients like curl can verify it at
	// all, but a SPIFFE-aware client should use the stronger check — it stays
	// correct even if DNS is subverted.
	opaClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: mtlsClientConfig(x509Src, opaID),
		},
	}

	srv := &server{
		cfg:        cfg,
		audit:      audit,
		bundles:    bundleSource,
		authorizer: newAuthorizer(opaClient, cfg.opaURL, cfg.decisionPath),
		now:        func() time.Time { return time.Now() },
	}

	mux := http.NewServeMux()
	// Unauthenticated, and deliberately so: this is the kubelet's probe
	// endpoint. It reveals only that the process is up. Contrast OPA, where
	// mTLS made HTTP probes impossible altogether — the resource's
	// ingress is JWT-bearer, not mTLS, so it has no such problem.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/", srv.handleProtected)

	httpSrv := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	log.Printf("resource listening on %s; audience=%s; opa=%s%s (authorized as %s)",
		cfg.listenAddr, cfg.audience, cfg.opaURL, cfg.decisionPath, cfg.opaSpiffeID)

	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type server struct {
	cfg   config
	audit *auditor
	// bundles is the SPIRE trust bundle used to validate callers' JWT-SVIDs.
	// It holds only public keys — never a caller's credential.
	bundles    jwtbundle.Source
	authorizer *authorizer
	// now is injectable so the TTL behaviour in generated policy can be tested
	// without sleeping.
	now func() time.Time
}

// handleProtected is the single path every protected request takes. The order
// of the steps is the security argument, so it is worth reading top to bottom:
// authenticate, then derive what the endpoint demands, then ask OPA, then and
// only then serve data.
func (s *server) handleProtected(w http.ResponseWriter, r *http.Request) {
	// The chain id is read first purely so that it can be attached to audit
	// events for correlation — including the events for requests that are
	// rejected before authentication. It is never consulted for a decision.
	chainID, chainSource := chainIDFrom(r)

	// --- authenticate -------------------------------------------------------
	token, err := bearerToken(r)
	if err != nil {
		s.deny(w, r, http.StatusUnauthorized, auditEvent{
			ChainID:       chainID,
			ActorSpiffeID: "",
			Outcome:       "deny",
			Detail: detail{
				Method:        r.Method,
				Path:          r.URL.Path,
				ChainIDSource: chainSource,
				Reason:        "missing or malformed Authorization header: " + err.Error(),
			},
		})
		return
	}

	svid, err := jwtsvid.ParseAndValidate(token, s.bundles, []string{s.cfg.audience})
	if err != nil {
		// Covers an expired token, a bad signature, a token from another trust
		// domain, and — importantly for the negative tests — a valid token minted for a
		// different audience.
		s.deny(w, r, http.StatusUnauthorized, auditEvent{
			ChainID:       chainID,
			ActorSpiffeID: "",
			Outcome:       "deny",
			Detail: detail{
				Method:        r.Method,
				Path:          r.URL.Path,
				ChainIDSource: chainSource,
				Reason:        "JWT-SVID validation failed: " + err.Error(),
			},
		})
		return
	}
	actor := svid.ID.String()

	// --- what does this endpoint demand? ------------------------------------
	rt, known := routeFor(r.Method, r.URL.Path)
	if !known {
		// A 404 is still audited. An authenticated caller probing for
		// endpoints is exactly the kind of thing the attribution claim in
		// should be able to reconstruct after the fact.
		s.deny(w, r, http.StatusNotFound, auditEvent{
			ChainID:       chainID,
			ActorSpiffeID: actor,
			Outcome:       "deny",
			Detail: detail{
				Method:        r.Method,
				Path:          r.URL.Path,
				ChainIDSource: chainSource,
				Reason:        "no such endpoint",
			},
		})
		return
	}

	// --- ask OPA ------------------------------------------------------------
	in := opaInput{
		SpiffeID: actor,
		Method:   r.Method,
		Path:     r.URL.Path,
		Scopes:   rt.requiredScopes,
		Now:      s.now().Unix(),
	}

	allowed, latency, err := s.authorizer.decide(r.Context(), in)
	latencyMs := float64(latency.Nanoseconds()) / 1e6

	if err != nil {
		// Could not consult OPA. Deny — an authorization service that cannot
		// be reached must not become an authorization bypass — but record it
		// as a distinct outcome so an operator can tell a policy denial from a
		// broken policy plane.
		s.deny(w, r, http.StatusServiceUnavailable, auditEvent{
			ChainID:       chainID,
			ActorSpiffeID: actor,
			Outcome:       "error",
			Detail: detail{
				Method:            r.Method,
				Path:              r.URL.Path,
				RequiredScopes:    rt.requiredScopes,
				ChainIDSource:     chainSource,
				Reason:            "policy decision unavailable: " + err.Error(),
				DecisionLatencyMs: &latencyMs,
			},
		})
		return
	}

	if !allowed {
		s.deny(w, r, http.StatusForbidden, auditEvent{
			ChainID:       chainID,
			ActorSpiffeID: actor,
			Outcome:       "deny",
			Detail: detail{
				Method:            r.Method,
				Path:              r.URL.Path,
				RequiredScopes:    rt.requiredScopes,
				ChainIDSource:     chainSource,
				Reason:            "policy denied",
				PolicyDecision:    &allowed,
				DecisionLatencyMs: &latencyMs,
			},
		})
		return
	}

	// --- serve --------------------------------------------------------------
	s.audit.emit(auditEvent{
		ChainID:       chainID,
		ActorSpiffeID: actor,
		Outcome:       "allow",
		Detail: detail{
			Method:            r.Method,
			Path:              r.URL.Path,
			RequiredScopes:    rt.requiredScopes,
			ChainIDSource:     chainSource,
			PolicyDecision:    &allowed,
			DecisionLatencyMs: &latencyMs,
		},
	})

	body := rt.dataset
	if body == nil {
		body = map[string]any{"accepted": true, "actor": actor}
	}
	writeJSON(w, http.StatusOK, body)
}

// deny emits the audit event and writes the response. Every rejection in this
// service goes through here, so there is no path that refuses a request without
// leaving a record — which is what the negative tests assert.
func (s *server) deny(w http.ResponseWriter, _ *http.Request, status int, ev auditEvent) {
	s.audit.emit(ev)
	writeJSON(w, status, map[string]any{
		"error":  http.StatusText(status),
		"reason": ev.Detail.Reason,
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func bearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", errors.New("no Authorization header")
	}
	scheme, token, found := strings.Cut(h, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", errors.New(`expected "Authorization: Bearer <jwt-svid>"`)
	}
	if token == "" {
		return "", errors.New("empty bearer token")
	}
	return token, nil
}

// chainIDFrom reads the delegation chain hint.
//
// This header is UNTRUSTED. Anyone can send
// any value. It is recorded for correlation and is never an input to a
// decision, which is why it is returned alongside its provenance rather than
// on its own — an auditor must not be able to read a chain_id without also
// seeing how much it is worth.
//
// The authenticated actor_spiffe_id is always the real attribution anchor.
func chainIDFrom(r *http.Request) (chainID, source string) {
	v := strings.TrimSpace(r.Header.Get("X-NHI-Chain-Id"))
	if v == "" {
		return "", chainSourceAbsent
	}
	// Bound it: this string is written to the audit log, and an unbounded
	// attacker-controlled field in the evidence trail is its own problem.
	const maxChainIDLen = 128
	if len(v) > maxChainIDLen {
		v = v[:maxChainIDLen]
	}
	return v, chainSourceClientAsserted
}
