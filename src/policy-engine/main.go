// Command policy-engine is the lab's policy synthesis service — the
// synthesis half of the "vend" stage and the policy-removal half of
// "dispose".
//
// Two credentials meet here, in the same directions as src/resource, but
// both mTLS rather than one JWT-SVID and one mTLS:
//
//   - INGRESS: callers present an X.509-SVID over mTLS and are authorized by
//     SPIFFE ID, confined to exactly one identity —
//     spiffe://lab.local/svc/vending-service by default.
//   - EGRESS: this service authenticates to OPA with its own X509-SVID over
//     mTLS. It is the ONLY identity OPA's system.authz permits to
//     write policy, confined further to the nhi_grants_* ID prefix.
//
// This service holds no local state: policy_id is a pure function of
// chain_id, Π(P) is read back from OPA plus a read-only bootstrap ConfigMap,
// and the delegation record itself belongs to the vending service.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type config struct {
	listenAddr string
	opaURL     string
	// clientSpiffeID is the ONLY identity this service's mTLS listener
	// authorizes. Defaults to the vending service. Overridable so a probe
	// pod can exercise /synthesize directly — see `make verify-policy`.
	clientSpiffeID string
	opaSpiffeID    string
	socketPath     string
	// bootstrapPath points at the read-only ConfigMap listing root parents:
	// spiffe_id -> scopes. Root parents have no grant module in OPA because
	// they were never vended as a child.
	bootstrapPath string
}

func loadConfig() config {
	return config{
		listenAddr:     env("LISTEN_ADDR", ":8443"),
		opaURL:         env("OPA_URL", "https://opa.opa.svc.cluster.local:8181"),
		clientSpiffeID: env("CLIENT_SPIFFE_ID", "spiffe://lab.local/svc/vending-service"),
		opaSpiffeID:    env("OPA_SPIFFE_ID", "spiffe://lab.local/svc/opa"),
		socketPath:     env("SPIFFE_ENDPOINT_SOCKET", "unix:///run/spire/sockets/agent.sock"),
		bootstrapPath:  env("BOOTSTRAP_PARENTS_PATH", "/etc/policy-engine/parents.json"),
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
		log.Fatalf("policy-engine: %v", err)
	}
}

func run() error {
	cfg := loadConfig()
	audit := newAuditor(os.Stdout)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	clientOpt := workloadapi.WithClientOptions(workloadapi.WithAddr(cfg.socketPath))

	// This service is SPIFFE-aware (it is a Go binary using go-spiffe), so
	// unlike OPA it needs no spiffe-helper sidecar — one
	// X509Source serves both its own listening identity and its egress
	// credential to OPA.
	x509Src, err := workloadapi.NewX509Source(ctx, clientOpt)
	if err != nil {
		return fmt.Errorf("create X509 source (is the Workload API socket mounted at %s?): %w", cfg.socketPath, err)
	}
	defer x509Src.Close()

	opaID, err := spiffeid.FromString(cfg.opaSpiffeID)
	if err != nil {
		return fmt.Errorf("parse OPA SPIFFE ID %q: %w", cfg.opaSpiffeID, err)
	}
	clientID, err := spiffeid.FromString(cfg.clientSpiffeID)
	if err != nil {
		return fmt.Errorf("parse accepted client SPIFFE ID %q: %w", cfg.clientSpiffeID, err)
	}

	opaHTTP := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: mtlsClientConfig(x509Src, opaID),
		},
	}

	bootstrap, err := loadBootstrapParents(cfg.bootstrapPath)
	if err != nil {
		return fmt.Errorf("load bootstrap parents: %w", err)
	}
	log.Printf("policy-engine: loaded %d root parent(s) from %s", len(bootstrap), cfg.bootstrapPath)

	srv := &server{
		audit:       audit,
		synthesizer: deterministicSynthesizer{},
		opa:         newOPAClient(opaHTTP, cfg.opaURL),
		bootstrap:   bootstrap,
		now:         time.Now,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /synthesize", srv.handleSynthesize)
	mux.HandleFunc("DELETE /synthesize/{chain_id}", srv.handleDispose)

	httpSrv := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           mux,
		TLSConfig:         mtlsServerConfig(x509Src, clientID),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	log.Printf("policy-engine listening on %s (mTLS); accepted client=%s; opa=%s (authorized as %s)",
		cfg.listenAddr, cfg.clientSpiffeID, cfg.opaURL, cfg.opaSpiffeID)

	// Empty cert/key file arguments: the certificate comes from TLSConfig's
	// GetCertificate callback (populated by mtlsServerConfig via go-spiffe),
	// not from files on disk. This is the standard go-spiffe http.Server
	// pattern.
	if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type server struct {
	audit       *auditor
	synthesizer Synthesizer
	opa         *opaClient
	// bootstrap is the static root-parent table, loaded once at startup. It
	// is cluster-provisioned (a ConfigMap), not runtime-writable, so caching
	// it in memory does not reintroduce mutable local state.
	bootstrap map[string][]string
	// now is injectable so expiry math is deterministic in tests, mirroring
	// src/resource's server.now.
	now func() time.Time
}

// synthesizeRequest is the /synthesize wire shape. Note what is
// deliberately NOT a field: parent scopes. If a caller includes a
// "parent_scopes" key in the JSON body it is silently dropped by
// json.Unmarshal, because no field in this struct claims it — the strongest
// enforceable form of "the caller cannot assert Π(P)". See
// TestSynthesizeIgnoresCallerSuppliedParentScopes.
type synthesizeRequest struct {
	ChainID         string   `json:"chain_id"`
	ParentSpiffeID  string   `json:"parent_spiffe_id"`
	ChildSpiffeID   string   `json:"child_spiffe_id"`
	RequestedScopes []string `json:"requested_scopes"`
	TaskContext     string   `json:"task_context"`
	TTLSeconds      int64    `json:"ttl_seconds"`
}

type synthesizeResponse struct {
	ChildScopes []string `json:"child_scopes"`
	PolicyID    string   `json:"policy_id"`
	ExpiresAt   int64    `json:"expires_at"`
}

const maxBodyBytes = 64 << 10

// handleSynthesize is POST /synthesize. The order of steps is the security
// argument, same discipline as src/resource/main.go:handleProtected —
// authenticate (already done by the TLS layer before this handler runs),
// derive Π(P) from state only this service can write, synthesize, render,
// push, THEN respond.
func (s *server) handleSynthesize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	actor, err := actorFromRequest(r)
	if err != nil {
		// The mTLS listener already refused any connection without an
		// authorized client certificate, so reaching here without one would
		// mean this handler was invoked outside that listener (e.g. a unit
		// test) rather than a real gap in the authorization path.
		s.deny(w, http.StatusUnauthorized, auditEvent{
			Stage: stageVend, Outcome: "deny",
			Detail: detail{Reason: "no authorized client certificate: " + err.Error()},
		})
		return
	}

	var req synthesizeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&req); err != nil {
		s.deny(w, http.StatusBadRequest, auditEvent{
			Stage: stageVend, ActorSpiffeID: actor, Outcome: "deny",
			Detail: detail{Reason: "malformed request body: " + err.Error()},
		})
		return
	}

	if req.ChainID == "" || req.ParentSpiffeID == "" || req.ChildSpiffeID == "" {
		s.deny(w, http.StatusBadRequest, auditEvent{
			Stage: stageVend, ActorSpiffeID: actor, ChainID: req.ChainID, Outcome: "deny",
			Detail: detail{
				ParentSpiffeID: req.ParentSpiffeID, ChildSpiffeID: req.ChildSpiffeID,
				Reason: "chain_id, parent_spiffe_id and child_spiffe_id are all required",
			},
		})
		return
	}
	if req.TTLSeconds <= 0 {
		s.deny(w, http.StatusBadRequest, auditEvent{
			Stage: stageVend, ActorSpiffeID: actor, ChainID: req.ChainID, Outcome: "deny",
			Detail: detail{
				ParentSpiffeID: req.ParentSpiffeID, ChildSpiffeID: req.ChildSpiffeID,
				Reason: "ttl_seconds must be positive",
			},
		})
		return
	}
	if err := validateChainID(req.ChainID); err != nil {
		s.deny(w, http.StatusBadRequest, auditEvent{
			Stage: stageVend, ActorSpiffeID: actor, ChainID: req.ChainID, Outcome: "deny",
			Detail: detail{
				ParentSpiffeID: req.ParentSpiffeID, ChildSpiffeID: req.ChildSpiffeID,
				Reason: "invalid chain_id: " + err.Error(),
			},
		})
		return
	}
	// child_spiffe_id is caller asserted and must be
	// validated as a structural descendant of parent_spiffe_id BEFORE it is
	// ever allowed to become the spiffe_id of a written grant module — see
	// identity.go's doc comment for the escalation this closes.
	if err := validateChildDescendant(req.ParentSpiffeID, req.ChildSpiffeID, s.bootstrap); err != nil {
		s.deny(w, http.StatusBadRequest, auditEvent{
			Stage: stageVend, ActorSpiffeID: actor, ChainID: req.ChainID, Outcome: "deny",
			Detail: detail{
				ParentSpiffeID: req.ParentSpiffeID, ChildSpiffeID: req.ChildSpiffeID,
				Reason: "invalid child_spiffe_id: " + err.Error(),
			},
		})
		return
	}

	// --- derive Π(P): OPA read-back unioned with the bootstrap table --------
	// NEVER from req — synthesizeRequest has no field to hold it. This is
	// the central rule of the policy engine.
	grants, err := s.opa.listGrantModules(ctx)
	if err != nil {
		s.deny(w, http.StatusServiceUnavailable, auditEvent{
			Stage: stageVend, ActorSpiffeID: actor, ChainID: req.ChainID, Outcome: "error",
			Detail: detail{
				ParentSpiffeID: req.ParentSpiffeID, ChildSpiffeID: req.ChildSpiffeID,
				Reason: "could not read back Π(P) from OPA: " + err.Error(),
			},
		})
		return
	}
	parentScopes := deriveParentScopes(grants, s.bootstrap, req.ParentSpiffeID, s.now())

	result, err := s.synthesizer.Synthesize(ctx, SynthesisRequest{
		ChainID:         req.ChainID,
		ParentSpiffeID:  req.ParentSpiffeID,
		ChildSpiffeID:   req.ChildSpiffeID,
		ParentScopes:    parentScopes,
		RequestedScopes: req.RequestedScopes,
		TaskContext:     req.TaskContext,
		TTLSeconds:      req.TTLSeconds,
	})
	if err != nil {
		s.deny(w, http.StatusInternalServerError, auditEvent{
			Stage: stageVend, ActorSpiffeID: actor, ChainID: req.ChainID, Outcome: "error",
			Detail: detail{
				ParentSpiffeID: req.ParentSpiffeID, ChildSpiffeID: req.ChildSpiffeID,
				ParentScopes: parentScopes, RequestedScopes: req.RequestedScopes,
				Reason: "synthesis failed: " + err.Error(),
			},
		})
		return
	}

	expiresAt := s.now().Unix() + req.TTLSeconds
	rego, err := renderGrantModule(req.ChainID, req.ChildSpiffeID, result.ChildScopes, expiresAt)
	if err != nil {
		s.deny(w, http.StatusInternalServerError, auditEvent{
			Stage: stageVend, ActorSpiffeID: actor, ChainID: req.ChainID, Outcome: "error",
			Detail: detail{Reason: "could not render grant module: " + err.Error()},
		})
		return
	}

	id := policyID(req.ChainID)
	if err := s.opa.putGrantModule(ctx, id, rego); err != nil {
		s.deny(w, http.StatusBadGateway, auditEvent{
			Stage: stageVend, ActorSpiffeID: actor, ChainID: req.ChainID, Outcome: "error",
			Detail: detail{
				ParentSpiffeID: req.ParentSpiffeID, ChildSpiffeID: req.ChildSpiffeID,
				ChildScopes: result.ChildScopes, PolicyID: id,
				Reason: "could not push grant to opa: " + err.Error(),
			},
		})
		return
	}

	s.audit.emit(auditEvent{
		Stage: stageVend, ActorSpiffeID: actor, ChainID: req.ChainID, Outcome: "allow",
		Detail: detail{
			ParentSpiffeID: req.ParentSpiffeID, ChildSpiffeID: req.ChildSpiffeID,
			RequestedScopes: req.RequestedScopes, ChildScopes: result.ChildScopes,
			ParentScopes: parentScopes, PolicyID: id, ExpiresAt: &expiresAt,
			TaskContext: req.TaskContext,
		},
	})

	writeJSON(w, http.StatusOK, synthesizeResponse{
		ChildScopes: result.ChildScopes,
		PolicyID:    id,
		ExpiresAt:   expiresAt,
	})
}

// handleDispose is DELETE /synthesize/{chain_id}: the policy engine's half of
// disposal. policy_id is recomputed from chain_id alone (there is no local
// state to look it up in), so this call is safe to retry and safe to race
// against itself.
func (s *server) handleDispose(w http.ResponseWriter, r *http.Request) {
	actor, err := actorFromRequest(r)
	if err != nil {
		s.deny(w, http.StatusUnauthorized, auditEvent{
			Stage: stageDispose, Outcome: "deny",
			Detail: detail{Reason: "no authorized client certificate: " + err.Error()},
		})
		return
	}

	chainID := r.PathValue("chain_id")
	if chainID == "" {
		s.deny(w, http.StatusBadRequest, auditEvent{
			Stage: stageDispose, ActorSpiffeID: actor, Outcome: "deny",
			Detail: detail{Reason: "chain_id is required"},
		})
		return
	}
	if err := validateChainID(chainID); err != nil {
		s.deny(w, http.StatusBadRequest, auditEvent{
			Stage: stageDispose, ActorSpiffeID: actor, ChainID: chainID, Outcome: "deny",
			Detail: detail{Reason: "invalid chain_id: " + err.Error()},
		})
		return
	}

	id := policyID(chainID)
	if err := s.opa.deleteGrantModule(r.Context(), id); err != nil {
		s.deny(w, http.StatusBadGateway, auditEvent{
			Stage: stageDispose, ActorSpiffeID: actor, ChainID: chainID, Outcome: "error",
			Detail: detail{PolicyID: id, Reason: "could not remove grant from opa: " + err.Error()},
		})
		return
	}

	s.audit.emit(auditEvent{
		Stage: stageDispose, ActorSpiffeID: actor, ChainID: chainID, Outcome: "allow",
		Detail: detail{PolicyID: id, Reason: "grant module removed"},
	})
	writeJSON(w, http.StatusOK, map[string]any{"chain_id": chainID, "policy_id": id, "removed": true})
}

func (s *server) deny(w http.ResponseWriter, status int, ev auditEvent) {
	s.audit.emit(ev)
	writeJSON(w, status, map[string]any{"error": http.StatusText(status), "reason": ev.Detail.Reason})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// actorFromRequest reads the authenticated caller's SPIFFE ID from its client
// certificate's URI SAN. This is defense in depth, not the primary control:
// the TLS layer (mtlsServerConfig / tlsconfig.AuthorizeID) already refused
// any connection whose client certificate is not authorized as
// cfg.clientSpiffeID, so by the time a handler runs, r.TLS.PeerCertificates[0]
// is guaranteed to carry that one identity. Reading it back here means the
// audit trail's actor_spiffe_id reflects what was actually verified rather
// than a value copied from config.
func actorFromRequest(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", errors.New("no client certificate presented")
	}
	cert := r.TLS.PeerCertificates[0]
	if len(cert.URIs) == 0 {
		return "", errors.New("client certificate carries no URI SAN")
	}
	id, err := spiffeid.FromURI(cert.URIs[0])
	if err != nil {
		return "", fmt.Errorf("parse SPIFFE ID from client certificate: %w", err)
	}
	return id.String(), nil
}
