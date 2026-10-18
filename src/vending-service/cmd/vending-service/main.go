// Command vending-service is the external vending controller — the core
// contribution of this lab. It creates child SPIRE
// registration entries via the Entry API against a stock SPIRE server, so
// the root of trust stays consolidated at the server while the policy
// decision sits outside it.
//
// Three credentials meet here and must not be confused:
//
//   - INGRESS: parents present a JWT-SVID bearer token, audience =
//     this service's own SPIFFE ID (mirrors src/resource's ingress).
//   - EGRESS to the policy engine: this service's own X509-SVID over mTLS.
//     It may only ask for synthesis; it does not, and
//     structurally cannot, write policy — see internal/policyclient.
//   - EGRESS to the SPIRE server's admin API: this service's own X509-SVID
//     over mTLS, matched against server.conf's admin_ids. This is
//     the one credential in the whole lab that grants unscoped SPIRE admin,
//     and this service is therefore in the TCB for every identity in the
//     trust domain, not only the children it mints.
//
// The vending flow (ordered, and the order is part of the security argument):
//  1. authenticate the caller by its JWT-SVID
//  2. verify the manifest signature and nonce (replay protection)
//  3. verify the claimed parent_spiffe_id matches the authenticated caller
//  4. call the policy engine, sending ONLY parent_spiffe_id (never Π(P))
//  5. the policy engine synthesizes child scopes and pushes Rego to OPA —
//     this service never writes policy itself (separation of duties)
//  6. create the child registration entry via the SPIRE Entry API
//  7. persist the delegation record; audit every step
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"nhi-lab/vending-service/internal/audit"
	"nhi-lab/vending-service/internal/manifest"
	"nhi-lab/vending-service/internal/policyclient"
	"nhi-lab/vending-service/internal/signature"
	"nhi-lab/vending-service/internal/spireentry"
	"nhi-lab/vending-service/internal/store"
)

type config struct {
	listenAddr string
	// audience is what a caller's JWT-SVID must be addressed to. Defaults to
	// this service's own SPIFFE ID.
	audience string
	// trustDomain is used to select the right bundle for JWT/X.509
	// verification and to build the node alias default below.
	trustDomain string

	policyEngineURL      string
	policyEngineSpiffeID string
	spireServerAddr      string
	spireServerSpiffeID  string
	nodeAliasSpiffeID    string // parent_id of every child entry
	dbPath               string
	auditLogPath         string // also append every audit event here; "" = stdout only
	socketPath           string
	reaperInterval       time.Duration
	// nonceRetentionMargin extends how long a consumed nonce is remembered
	// past the manifest's own ttl_seconds, so a replay cannot succeed simply
	// by outliving the nonce record while the underlying grant is still live.
	nonceRetentionMargin time.Duration
}

func loadConfig() config {
	return config{
		listenAddr:           env("LISTEN_ADDR", ":8090"),
		audience:             env("VENDING_AUDIENCE", "spiffe://lab.local/svc/vending-service"),
		trustDomain:          env("TRUST_DOMAIN", "lab.local"),
		policyEngineURL:      env("POLICY_ENGINE_URL", "https://policy-engine.nhi.svc.cluster.local:8443"),
		policyEngineSpiffeID: env("POLICY_ENGINE_SPIFFE_ID", "spiffe://lab.local/svc/policy-engine"),
		spireServerAddr:      env("SPIRE_SERVER_ADDR", "spire-server.spire.svc.cluster.local:8081"),
		spireServerSpiffeID:  env("SPIRE_SERVER_SPIFFE_ID", "spiffe://lab.local/spire/server"),
		nodeAliasSpiffeID:    env("NODE_ALIAS_SPIFFE_ID", "spiffe://lab.local/node/nhi-lab"),
		dbPath:               env("DB_PATH", "/var/lib/vending-service/vending.db"),
		auditLogPath:         env("AUDIT_LOG_PATH", ""),
		socketPath:           env("SPIFFE_ENDPOINT_SOCKET", "unix:///run/spire/sockets/agent.sock"),
		reaperInterval:       envDuration("REAPER_INTERVAL", 30*time.Second),
		nonceRetentionMargin: envDuration("NONCE_RETENTION_MARGIN", 24*time.Hour),
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("vending-service: %v", err)
	}
}

func run() error {
	cfg := loadConfig()
	auditor := audit.New(os.Stdout)
	if cfg.auditLogPath != "" {
		// Opened before anything else so a service that is meant to persist
		// its audit trail but cannot refuses to start, rather than running
		// with only the (ephemeral) stdout copy.
		auditFile, err := audit.OpenFile(cfg.auditLogPath)
		if err != nil {
			return fmt.Errorf("open audit log %s (AUDIT_LOG_PATH): %w", cfg.auditLogPath, err)
		}
		defer auditFile.Close()
		auditor = audit.NewWithFile(os.Stdout, auditFile, os.Stderr)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	clientOpt := workloadapi.WithClientOptions(workloadapi.WithAddr(cfg.socketPath))

	// Ingress credential source: the trust bundle used to validate parents'
	// JWT-SVIDs AND (the same bundle, different half) the x5c chain on a
	// manifest signature. One BundleSource serves both.
	wlBundles, err := workloadapi.NewBundleSource(ctx, clientOpt)
	if err != nil {
		return fmt.Errorf("create trust bundle source (is the Workload API socket mounted at %s?): %w", cfg.socketPath, err)
	}
	defer wlBundles.Close()

	// Egress credential: this service's own X509-SVID, presented to the
	// policy engine and to the SPIRE server's admin API.
	x509Src, err := workloadapi.NewX509Source(ctx, clientOpt)
	if err != nil {
		return fmt.Errorf("create X509 source: %w", err)
	}
	defer x509Src.Close()

	trustDomain, err := spiffeid.TrustDomainFromString(cfg.trustDomain)
	if err != nil {
		return fmt.Errorf("parse trust domain %q: %w", cfg.trustDomain, err)
	}

	policyEngineID, err := spiffeid.FromString(cfg.policyEngineSpiffeID)
	if err != nil {
		return fmt.Errorf("parse policy engine SPIFFE ID: %w", err)
	}
	policyHTTP := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: mtlsClientConfig(x509Src, policyEngineID)},
	}
	policyEngine := policyclient.New(policyHTTP, strings.TrimRight(cfg.policyEngineURL, "/"))

	spireServerID, err := spiffeid.FromString(cfg.spireServerSpiffeID)
	if err != nil {
		return fmt.Errorf("parse spire server SPIFFE ID: %w", err)
	}
	entryClient, err := spireentry.Dial(ctx, cfg.spireServerAddr, mtlsClientConfig(x509Src, spireServerID))
	if err != nil {
		return fmt.Errorf("dial spire server admin endpoint: %w", err)
	}
	defer entryClient.Close()

	db, err := store.Open(ctx, cfg.dbPath)
	if err != nil {
		return fmt.Errorf("open delegation store: %w", err)
	}
	defer db.Close()

	srv := &server{
		cfg:          cfg,
		audit:        auditor,
		bundles:      wlBundles,
		policyEngine: policyEngine,
		entries:      entryClient,
		store:        db,
		trustDomain:  trustDomain,
		now:          time.Now,
	}

	go srv.runReaper(ctx)

	mux := http.NewServeMux()
	// Unauthenticated liveness probe, mirroring src/resource.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("POST /delegations", srv.handleVend)
	mux.HandleFunc("GET /delegations/{chain_id}", srv.handleGet)
	mux.HandleFunc("DELETE /delegations/{chain_id}", srv.handleDispose)

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

	log.Printf("vending-service listening on %s; audience=%s; policy-engine=%s; spire-server=%s; node-alias=%s",
		cfg.listenAddr, cfg.audience, cfg.policyEngineURL, cfg.spireServerAddr, cfg.nodeAliasSpiffeID)

	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// policyEngineClient is the subset of *policyclient.Client this package
// calls, named separately so tests can substitute a stub instead of a live
// mTLS connection to the policy engine.
type policyEngineClient interface {
	Synthesize(ctx context.Context, req policyclient.SynthesizeRequest) (policyclient.SynthesizeResponse, error)
	Dispose(ctx context.Context, chainID string) error
}

// entryAPIClient is the subset of *spireentry.Client this package calls,
// named separately for the same reason: tests substitute a stub instead of
// a live mTLS connection to the SPIRE server's admin API.
type entryAPIClient interface {
	CreateChildEntry(ctx context.Context, parentID, childSpiffeID string, selectors []spireentry.Selector, x509TTLSeconds, expiresAt int64) (string, error)
	DeleteEntry(ctx context.Context, entryID string) error
	LookupSelectors(ctx context.Context, spiffeID string) ([]spireentry.Selector, error)
}

type server struct {
	cfg          config
	audit        *audit.Auditor
	bundles      bundleSource
	policyEngine policyEngineClient
	entries      entryAPIClient
	store        *store.Store
	trustDomain  spiffeid.TrustDomain
	// now is injectable so expiry math is deterministic in tests.
	now func() time.Time
}

const maxBodyBytes = 64 << 10

// handleVend is POST /delegations — the vending flow steps 1-7 in order. The
// ordering is the security argument:
// authenticate, verify signature+nonce, verify parent==caller, synthesize
// (policy engine derives Π(P) itself), mint the entry, persist, audit.
func (s *server) handleVend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// --- step 1: authenticate the caller by its JWT-SVID ---------------------
	token, err := bearerToken(r)
	if err != nil {
		s.deny(w, http.StatusUnauthorized, audit.Event{
			Stage: audit.StageAttest, Outcome: audit.OutcomeDeny,
			Detail: audit.Detail{Reason: "missing or malformed Authorization header: " + err.Error()},
		})
		return
	}
	callerSVID, err := jwtsvid.ParseAndValidate(token, s.bundles, []string{s.cfg.audience})
	if err != nil {
		s.deny(w, http.StatusUnauthorized, audit.Event{
			Stage: audit.StageAttest, Outcome: audit.OutcomeDeny,
			Detail: audit.Detail{Reason: "JWT-SVID validation failed: " + err.Error()},
		})
		return
	}
	actor := callerSVID.ID

	var m manifest.SpawnManifest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&m); err != nil {
		s.deny(w, http.StatusBadRequest, audit.Event{
			Stage: audit.StageAttest, ActorSpiffeID: actor.String(), Outcome: audit.OutcomeDeny,
			Detail: audit.Detail{Reason: "malformed request body: " + err.Error()},
		})
		return
	}
	if err := m.Validate(); err != nil {
		s.deny(w, http.StatusBadRequest, audit.Event{
			Stage: audit.StageAttest, ActorSpiffeID: actor.String(), Outcome: audit.OutcomeDeny,
			Detail: audit.Detail{
				ParentSpiffeID: m.ParentSpiffeID, Reason: "invalid manifest: " + err.Error(),
			},
		})
		return
	}

	// --- step 2a: verify the manifest signature -------------------------------
	// The signer must be the SAME identity the manifest claims as its parent
	// — checked here as part of signature verification, and again
	// below (step 3) against the JWT-SVID's authenticated subject. Two
	// independent credentials, both required to agree with the claim.
	parentID, err := spiffeid.FromString(m.ParentSpiffeID)
	if err != nil {
		// manifest.Validate() already checked this parses; unreachable in
		// practice, kept for defence in depth.
		s.deny(w, http.StatusBadRequest, audit.Event{
			Stage: audit.StageAttest, ActorSpiffeID: actor.String(), Outcome: audit.OutcomeDeny,
			Detail: audit.Detail{ParentSpiffeID: m.ParentSpiffeID, Reason: "invalid parent_spiffe_id: " + err.Error()},
		})
		return
	}
	x509Bundle, err := s.bundles.GetX509BundleForTrustDomain(s.trustDomain)
	if err != nil {
		s.deny(w, http.StatusServiceUnavailable, audit.Event{
			Stage: audit.StageAttest, ActorSpiffeID: actor.String(), Outcome: audit.OutcomeError,
			Detail: audit.Detail{ParentSpiffeID: m.ParentSpiffeID, Reason: "could not load X.509 trust bundle: " + err.Error()},
		})
		return
	}
	payload, err := m.CanonicalBytes()
	if err != nil {
		s.deny(w, http.StatusInternalServerError, audit.Event{
			Stage: audit.StageAttest, ActorSpiffeID: actor.String(), Outcome: audit.OutcomeError,
			Detail: audit.Detail{ParentSpiffeID: m.ParentSpiffeID, Reason: "could not canonicalize manifest: " + err.Error()},
		})
		return
	}
	if err := signature.Verify(m.Signature, payload, x509Bundle.X509Authorities(), parentID); err != nil {
		s.deny(w, http.StatusUnauthorized, audit.Event{
			Stage: audit.StageAttest, ActorSpiffeID: actor.String(), Outcome: audit.OutcomeDeny,
			Detail: audit.Detail{
				ParentSpiffeID: m.ParentSpiffeID,
				Reason:         "manifest signature verification failed: " + err.Error(),
			},
		})
		return
	}

	// --- step 3: the claimed parent must equal the authenticated caller ------
	//
	// Deliberately checked BEFORE nonce recording below, even though the
	// flow lists "verify signature and nonce" as step 2 and "verify claimed
	// parent" as step 3: recording the nonce is a STATE MUTATION, and doing
	// it before this check would let an attacker who merely RELAYS a
	// manifest it captured but did not create — genuinely signed by the
	// real parent, so it clears step 2a's signature check — burn that
	// (parent, nonce) pair through its own, unrelated, ultimately-denied
	// request. The real parent's own later, legitimate submission of that
	// same manifest would then be refused as "already used", a denial of
	// service against a spawn the attacker itself never got to complete.
	// Reordering costs nothing: signature verification (2a) still runs
	// first and is what actually establishes the manifest is genuine.
	if actor != parentID {
		s.deny(w, http.StatusForbidden, audit.Event{
			Stage: audit.StageAttest, ActorSpiffeID: actor.String(), Outcome: audit.OutcomeDeny,
			Detail: audit.Detail{
				ParentSpiffeID: m.ParentSpiffeID,
				Reason: fmt.Sprintf(
					"claimed parent_spiffe_id %q does not match the authenticated caller %q",
					m.ParentSpiffeID, actor.String()),
			},
		})
		return
	}

	childSpiffeID := m.ChildSpiffeID()

	// --- child_selectors must be a consistent extension of the
	// CALLER's own attested selectors (same k8s namespace) --------------------
	// Checked here — after the parent is confirmed to be the authenticated
	// caller, but BEFORE the nonce is recorded, so a request refused here
	// leaves no state behind for the caller to have to work around with a
	// fresh nonce. Without this, any authenticated parent could name ANY
	// selectors at all — e.g. the protected resource's own pod's selectors,
	// which — because SPIRE issues an SVID to every
	// workload whose attested selectors match SOME entry — would have made
	// that unrelated pod hold an SVID for a SPIFFE ID inside a delegation
	// chain it was never forked into. Looked up via the same admin Entry
	// API connection already used to create/delete entries: a READ, not a
	// new grant of authority, so it does not widen this service's admin scope.
	parentSelectors, err := s.entries.LookupSelectors(ctx, actor.String())
	if err != nil {
		s.deny(w, http.StatusServiceUnavailable, audit.Event{
			Stage: audit.StageAttest, ActorSpiffeID: actor.String(), Outcome: audit.OutcomeError,
			Detail: audit.Detail{ParentSpiffeID: m.ParentSpiffeID, Reason: "could not look up the caller's own selectors: " + err.Error()},
		})
		return
	}
	if err := validateChildSelectorsConsistentWithParent(parentSelectors, m.ChildSelectors); err != nil {
		s.deny(w, http.StatusForbidden, audit.Event{
			Stage: audit.StageAttest, ActorSpiffeID: actor.String(), Outcome: audit.OutcomeDeny,
			Detail: audit.Detail{
				ParentSpiffeID: m.ParentSpiffeID, ChildSpiffeID: childSpiffeID,
				Reason: "child_selectors inconsistent with the caller's own attested selectors: " + err.Error(),
			},
		})
		return
	}

	// --- step 2b: nonce replay protection -------------------------------------
	nowUnix := s.now().Unix()
	nonceExpiresAt := s.now().Add(time.Duration(m.TTLSeconds)*time.Second + s.cfg.nonceRetentionMargin).Unix()
	if err := s.store.CheckAndRecordNonce(ctx, m.ParentSpiffeID, m.Nonce, nowUnix, nonceExpiresAt); err != nil {
		reason := "could not record nonce: " + err.Error()
		status := http.StatusInternalServerError
		outcome := audit.OutcomeError
		if errors.Is(err, store.ErrNonceReused) {
			reason = "nonce has already been used for this parent (replay refused)"
			status = http.StatusConflict
			outcome = audit.OutcomeDeny
		}
		s.deny(w, status, audit.Event{
			Stage: audit.StageAttest, ActorSpiffeID: actor.String(), Outcome: outcome,
			Detail: audit.Detail{ParentSpiffeID: m.ParentSpiffeID, Reason: reason},
		})
		return
	}

	s.audit.Emit(audit.Event{
		Stage: audit.StageAttest, ActorSpiffeID: actor.String(), Outcome: audit.OutcomeAllow,
		Detail: audit.Detail{ParentSpiffeID: m.ParentSpiffeID, Reason: "JWT-SVID, manifest signature, nonce and child_selectors all verified"},
	})

	chainID, err := newChainID()
	if err != nil {
		s.deny(w, http.StatusInternalServerError, audit.Event{
			Stage: audit.StageVend, ActorSpiffeID: actor.String(), Outcome: audit.OutcomeError,
			Detail: audit.Detail{ParentSpiffeID: m.ParentSpiffeID, ChildSpiffeID: childSpiffeID, Reason: "could not generate chain_id: " + err.Error()},
		})
		return
	}

	// --- step 4/5: policy engine derives Π(P) itself and pushes Rego --------
	synth, err := s.policyEngine.Synthesize(ctx, policyclient.SynthesizeRequest{
		ChainID:         chainID,
		ParentSpiffeID:  m.ParentSpiffeID,
		ChildSpiffeID:   childSpiffeID,
		RequestedScopes: m.RequestedScopes,
		TaskContext:     m.TaskContext,
		TTLSeconds:      m.TTLSeconds,
	})
	if err != nil {
		s.deny(w, http.StatusBadGateway, audit.Event{
			Stage: audit.StageVend, ActorSpiffeID: actor.String(), ChainID: chainID, Outcome: audit.OutcomeError,
			Detail: audit.Detail{
				ParentSpiffeID: m.ParentSpiffeID, ChildSpiffeID: childSpiffeID,
				RequestedScopes: m.RequestedScopes,
				Reason:          "policy engine synthesis failed: " + err.Error(),
			},
		})
		return
	}

	// An empty child_scopes result means Π(requested) ∩ Π(P) = ∅ —
	// either the caller has no authority at all (Π(P) = ∅: unknown to both
	// OPA and the bootstrap table) or none of it overlaps what was
	// requested. Either way there is nothing to mint an identity FOR, and
	// minting one anyway would create a live SPIFFE ID with no actual
	// access — a needless identity in the trust domain, and a signal that
	// the caller may not be a legitimate parent at all (e.g. an
	// infrastructure service identity with no delegated authority could
	// otherwise still get a 201 and a real, if scopeless, child entry).
	// requested_scopes is guaranteed non-empty by manifest.Validate(), so
	// this is never triggered merely because the parent asked for nothing.
	if len(synth.ChildScopes) == 0 {
		s.deny(w, http.StatusForbidden, audit.Event{
			Stage: audit.StageVend, ActorSpiffeID: actor.String(), ChainID: chainID, Outcome: audit.OutcomeDeny,
			Detail: audit.Detail{
				ParentSpiffeID: m.ParentSpiffeID, ChildSpiffeID: childSpiffeID,
				RequestedScopes: m.RequestedScopes, PolicyID: synth.PolicyID,
				Reason: "policy engine granted no scopes (Π(requested) ∩ Π(parent) = ∅) — refusing to mint an identity with no authority",
			},
		})
		// The policy engine already wrote a (scopeless, inert) grant module
		// for this chain_id before returning — clean it up rather than
		// leaving a stray module behind, mirroring the entry-creation
		// failure path below.
		_ = s.policyEngine.Dispose(ctx, chainID)
		return
	}

	// --- step 6: create the child registration entry -------------------------
	selectors, err := spireentry.ParseChildSelectors(m.ChildSelectors)
	if err != nil {
		s.deny(w, http.StatusBadRequest, audit.Event{
			Stage: audit.StageVend, ActorSpiffeID: actor.String(), ChainID: chainID, Outcome: audit.OutcomeDeny,
			Detail: audit.Detail{
				ParentSpiffeID: m.ParentSpiffeID, ChildSpiffeID: childSpiffeID,
				Reason: "invalid child_selectors: " + err.Error(),
			},
		})
		return
	}
	entryID, err := s.entries.CreateChildEntry(ctx, s.cfg.nodeAliasSpiffeID, childSpiffeID, selectors, m.TTLSeconds, synth.ExpiresAt)
	if err != nil {
		s.deny(w, http.StatusBadGateway, audit.Event{
			Stage: audit.StageVend, ActorSpiffeID: actor.String(), ChainID: chainID, Outcome: audit.OutcomeError,
			Detail: audit.Detail{
				ParentSpiffeID: m.ParentSpiffeID, ChildSpiffeID: childSpiffeID,
				ChildScopes: synth.ChildScopes, PolicyID: synth.PolicyID,
				Reason: "could not create SPIRE registration entry: " + err.Error(),
			},
		})
		// Best-effort cleanup: the grant module was already written. Leaving
		// it behind names a child that will never exist as a SPIRE identity,
		// which is inert but untidy — remove it so a retry with a fresh
		// chain_id does not have to reason about a stray module.
		_ = s.policyEngine.Dispose(ctx, chainID)
		return
	}

	// --- step 7: persist the delegation record --------------------------------
	issuedAt := s.now().Unix()
	rec := store.DelegationRecord{
		ChainID:        chainID,
		ParentSpiffeID: m.ParentSpiffeID,
		ChildSpiffeID:  childSpiffeID,
		GrantedScopes:  synth.ChildScopes,
		TaskContext:    m.TaskContext,
		EntryID:        entryID,
		PolicyID:       synth.PolicyID,
		IssuedAt:       issuedAt,
		TTL:            m.TTLSeconds,
		ExpiresAt:      synth.ExpiresAt,
	}
	if err := s.store.CreateDelegation(ctx, rec); err != nil {
		s.deny(w, http.StatusInternalServerError, audit.Event{
			Stage: audit.StageVend, ActorSpiffeID: actor.String(), ChainID: chainID, Outcome: audit.OutcomeError,
			Detail: audit.Detail{
				ParentSpiffeID: m.ParentSpiffeID, ChildSpiffeID: childSpiffeID,
				EntryID: entryID, PolicyID: synth.PolicyID,
				Reason: "could not persist delegation record: " + err.Error(),
			},
		})
		// The entry and grant already exist; do not leave the caller thinking
		// nothing happened, but also do not silently claim success. A 500
		// here with entry_id/policy_id in the log lets an operator finish the
		// job by hand or by retrying disposal directly against those IDs.
		return
	}

	expiresAt := synth.ExpiresAt
	s.audit.Emit(audit.Event{
		Stage: audit.StageVend, ActorSpiffeID: actor.String(), ChainID: chainID, Outcome: audit.OutcomeAllow,
		Detail: audit.Detail{
			ParentSpiffeID: m.ParentSpiffeID, ChildSpiffeID: childSpiffeID,
			RequestedScopes: m.RequestedScopes, ChildScopes: synth.ChildScopes,
			PolicyID: synth.PolicyID, EntryID: entryID, ExpiresAt: &expiresAt,
			TaskContext: m.TaskContext,
		},
	})

	writeJSON(w, http.StatusCreated, delegationResponse{
		ChainID:        chainID,
		ParentSpiffeID: m.ParentSpiffeID,
		ChildSpiffeID:  childSpiffeID,
		ChildScopes:    synth.ChildScopes,
		EntryID:        entryID,
		PolicyID:       synth.PolicyID,
		IssuedAt:       issuedAt,
		ExpiresAt:      expiresAt,
	})
}

type delegationResponse struct {
	ChainID        string   `json:"chain_id"`
	ParentSpiffeID string   `json:"parent_spiffe_id"`
	ChildSpiffeID  string   `json:"child_spiffe_id"`
	ChildScopes    []string `json:"child_scopes"`
	EntryID        string   `json:"entry_id"`
	PolicyID       string   `json:"policy_id"`
	IssuedAt       int64    `json:"issued_at"`
	ExpiresAt      int64    `json:"expires_at"`
	RevokedAt      *int64   `json:"revoked_at,omitempty"`
	Revocation     string   `json:"revocation_reason,omitempty"`
}

// handleGet is GET /delegations/{chain_id}, for auditors and for
// verify-vending.sh to read back state without touching SQLite directly.
// Authenticated the same way as every other endpoint; any authenticated
// identity may read (this is a lab-wide audit surface, not a per-parent
// secret — the delegation record itself carries no credential material).
func (s *server) handleGet(w http.ResponseWriter, r *http.Request) {
	actor, err := s.authenticate(r)
	if err != nil {
		s.deny(w, http.StatusUnauthorized, audit.Event{
			Stage: audit.StageVend, Outcome: audit.OutcomeDeny,
			Detail: audit.Detail{Reason: err.Error()},
		})
		return
	}
	chainID := r.PathValue("chain_id")
	rec, err := s.store.GetDelegation(r.Context(), chainID)
	if errors.Is(err, store.ErrNotFound) {
		s.deny(w, http.StatusNotFound, audit.Event{
			Stage: audit.StageVend, ActorSpiffeID: actor.String(), ChainID: chainID, Outcome: audit.OutcomeDeny,
			Detail: audit.Detail{Reason: "no such delegation"},
		})
		return
	}
	if err != nil {
		s.deny(w, http.StatusInternalServerError, audit.Event{
			Stage: audit.StageVend, ActorSpiffeID: actor.String(), ChainID: chainID, Outcome: audit.OutcomeError,
			Detail: audit.Detail{Reason: err.Error()},
		})
		return
	}
	writeJSON(w, http.StatusOK, delegationResponse{
		ChainID: rec.ChainID, ParentSpiffeID: rec.ParentSpiffeID, ChildSpiffeID: rec.ChildSpiffeID,
		ChildScopes: rec.GrantedScopes, EntryID: rec.EntryID, PolicyID: rec.PolicyID,
		IssuedAt: rec.IssuedAt, ExpiresAt: rec.ExpiresAt, RevokedAt: rec.RevokedAt, Revocation: rec.RevocationReason,
	})
}

// handleDispose is DELETE /delegations/{chain_id} — disposal:
// delete the SPIRE entry, remove the Rego module, mark the record revoked.
// Parent-initiated revoke: only the delegation's own parent (or
// this service's own reaper, which calls disposeChain directly rather than
// through this handler) may revoke it.
func (s *server) handleDispose(w http.ResponseWriter, r *http.Request) {
	actor, err := s.authenticate(r)
	if err != nil {
		s.deny(w, http.StatusUnauthorized, audit.Event{
			Stage: audit.StageDispose, Outcome: audit.OutcomeDeny,
			Detail: audit.Detail{Reason: err.Error()},
		})
		return
	}
	chainID := r.PathValue("chain_id")
	rec, err := s.store.GetDelegation(r.Context(), chainID)
	if errors.Is(err, store.ErrNotFound) {
		s.deny(w, http.StatusNotFound, audit.Event{
			Stage: audit.StageDispose, ActorSpiffeID: actor.String(), ChainID: chainID, Outcome: audit.OutcomeDeny,
			Detail: audit.Detail{Reason: "no such delegation"},
		})
		return
	}
	if err != nil {
		s.deny(w, http.StatusInternalServerError, audit.Event{
			Stage: audit.StageDispose, ActorSpiffeID: actor.String(), ChainID: chainID, Outcome: audit.OutcomeError,
			Detail: audit.Detail{Reason: err.Error()},
		})
		return
	}
	if actor.String() != rec.ParentSpiffeID {
		s.deny(w, http.StatusForbidden, audit.Event{
			Stage: audit.StageDispose, ActorSpiffeID: actor.String(), ChainID: chainID, Outcome: audit.OutcomeDeny,
			Detail: audit.Detail{
				ParentSpiffeID: rec.ParentSpiffeID, ChildSpiffeID: rec.ChildSpiffeID,
				Reason: "only the delegation's own parent may revoke it",
			},
		})
		return
	}

	if err := s.disposeChain(r.Context(), rec, actor.String(), "revoked_on_demand"); err != nil {
		s.deny(w, http.StatusBadGateway, audit.Event{
			Stage: audit.StageDispose, ActorSpiffeID: actor.String(), ChainID: chainID, Outcome: audit.OutcomeError,
			Detail: audit.Detail{
				ParentSpiffeID: rec.ParentSpiffeID, ChildSpiffeID: rec.ChildSpiffeID,
				EntryID: rec.EntryID, PolicyID: rec.PolicyID, Reason: err.Error(),
			},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"chain_id": chainID, "revoked": true})
}

// disposeChain does the actual work of disposal — SPIRE entry deletion, OPA
// grant removal, record revocation — shared between handleDispose (parent
// initiated) and the reaper (TTL initiated). actor is who to attribute the
// audit event to: the parent for an on-demand call, this service's own
// identity for the reaper.
func (s *server) disposeChain(ctx context.Context, rec store.DelegationRecord, actor, reason string) error {
	if err := s.entries.DeleteEntry(ctx, rec.EntryID); err != nil {
		return fmt.Errorf("could not delete SPIRE registration entry: %w", err)
	}
	if err := s.policyEngine.Dispose(ctx, rec.ChainID); err != nil {
		return fmt.Errorf("could not remove grant module: %w", err)
	}
	revokedAt := s.now().Unix()
	if err := s.store.MarkRevoked(ctx, rec.ChainID, revokedAt, reason); err != nil {
		return fmt.Errorf("could not mark delegation revoked: %w", err)
	}
	s.audit.Emit(audit.Event{
		Stage: audit.StageDispose, ActorSpiffeID: actor, ChainID: rec.ChainID, Outcome: audit.OutcomeAllow,
		Detail: audit.Detail{
			ParentSpiffeID: rec.ParentSpiffeID, ChildSpiffeID: rec.ChildSpiffeID,
			EntryID: rec.EntryID, PolicyID: rec.PolicyID, Reason: reason,
		},
	})
	return nil
}

// authenticate is the shared ingress check for GET/DELETE /delegations/*.
func (s *server) authenticate(r *http.Request) (spiffeid.ID, error) {
	token, err := bearerToken(r)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("missing or malformed Authorization header: %w", err)
	}
	svid, err := jwtsvid.ParseAndValidate(token, s.bundles, []string{s.cfg.audience})
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("JWT-SVID validation failed: %w", err)
	}
	return svid.ID, nil
}

func (s *server) deny(w http.ResponseWriter, status int, ev audit.Event) {
	s.audit.Emit(ev)
	writeJSON(w, status, map[string]any{"error": http.StatusText(status), "reason": ev.Detail.Reason})
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

// newChainID mints a fresh, unpredictable chain_id already in the shape the
// policy engine requires (^[a-z0-9_]+$):
// hex digits are already lowercase alphanumeric, and the "c_" prefix keeps
// grep/log output distinguishable from an entry ID or SPIFFE ID at a glance.
// chain_id is minted HERE, not accepted from the manifest — the spawn
// manifest has no chain_id field; it is the vending service's own act
// of attribution, carried through every audit event from this point on.
func newChainID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "c_" + hex.EncodeToString(b[:]), nil
}

// validateChildSelectorsConsistentWithParent requires the
// manifest's child_selectors to name the SAME k8s namespace as the one the
// caller was itself attested against — the minimal, mechanically checkable
// form of "the child is a plausible extension of the parent", given that
// selectors are the only provenance signal SPIRE's k8s workload attestor
// hands this service (the agent's `skip_kubelet_verification` limitation
// already bounds how far that signal can be trusted; this check does not
// change that bound, it just stops a parent from naming a namespace it has
// no attested relationship to at all).
//
// parentSelectors is the caller's OWN entry, looked up live via the Entry
// API (main.go); childSelectors is the manifest's caller-asserted map
// (e.g. {"k8s:ns": "agents", ...}). Fails CLOSED: if
// either side has no k8s:ns selector at all, consistency cannot be
// established, so the request is refused rather than allowed through on an
// absent signal.
func validateChildSelectorsConsistentWithParent(parentSelectors []spireentry.Selector, childSelectors map[string]string) error {
	parentNS, ok := k8sSelectorValue(parentSelectors, "ns")
	if !ok {
		return fmt.Errorf("the caller's own registration entry carries no k8s:ns selector — cannot establish a namespace relationship")
	}
	childNS, ok := childSelectors["k8s:ns"]
	if !ok || childNS == "" {
		return fmt.Errorf("child_selectors carries no k8s:ns — cannot establish a namespace relationship")
	}
	if childNS != parentNS {
		return fmt.Errorf("child_selectors names namespace %q, but the caller was itself attested in namespace %q", childNS, parentNS)
	}
	return nil
}

// k8sSelectorValue finds a SPIRE selector {Type: "k8s", Value: "<subtype>:<value>"}
// and returns <value> for the given subtype (e.g. "ns", "sa").
func k8sSelectorValue(selectors []spireentry.Selector, subtype string) (string, bool) {
	prefix := subtype + ":"
	for _, s := range selectors {
		if s.Type != "k8s" {
			continue
		}
		if v, ok := strings.CutPrefix(s.Value, prefix); ok {
			return v, true
		}
	}
	return "", false
}
