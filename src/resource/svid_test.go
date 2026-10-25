package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// These tests pin down that the resource verifies the caller's JWT-SVID itself,
// on every request, before it derives scopes or asks OPA: a missing, expired,
// wrongly signed, other-trust-domain or wrong-audience token is a 401 with an
// audit event, and OPA is never consulted. Verification proves who is calling;
// the grant (OPA) decides what they may do, so neither result is cached.

const (
	svidTestAudience = "spiffe://lab.local/svc/resource"
	svidTestKeyID    = "test-key-1"
	svidTestSubject  = "spiffe://lab.local/agent/parent/t1/child/c1"
)

type svidHarness struct {
	key      *ecdsa.PrivateKey
	srv      *server
	auditBuf *bytes.Buffer
	// opaCalls counts requests that reached the stub OPA; opaAnswer is what it
	// returns.
	opaCalls  atomic.Int64
	opaAnswer atomic.Bool
}

func newSVIDHarness(t *testing.T) *svidHarness {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &svidHarness{key: key, auditBuf: &bytes.Buffer{}}
	h.opaAnswer.Store(true)

	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h.opaCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"result": h.opaAnswer.Load()})
	}))
	t.Cleanup(opa.Close)

	td := spiffeid.RequireTrustDomainFromString("lab.local")
	bundle := jwtbundle.FromJWTAuthorities(td, map[string]crypto.PublicKey{svidTestKeyID: key.Public()})
	h.srv = &server{
		cfg:        config{audience: svidTestAudience},
		audit:      newAuditor(h.auditBuf),
		bundles:    bundle,
		authorizer: newAuthorizer(opa.Client(), opa.URL, "/v1/data/nhi/resource/allow"),
		now:        time.Now,
	}
	return h
}

// token signs a JWT-SVID with signer under kid, for subject and audience,
// expiring at expiry.
func svidToken(t *testing.T, signer *ecdsa.PrivateKey, kid, subject, audience string, expiry time.Time) string {
	t.Helper()
	opts := (&josejwt.SignerOptions{}).WithType("JWT").WithHeader(josejwt.HeaderKey("kid"), kid)
	s, err := josejwt.NewSigner(josejwt.SigningKey{Algorithm: josejwt.ES256, Key: signer}, opts)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Signed(s).Claims(jwt.Claims{
		Subject: subject, Audience: jwt.Audience{audience}, Expiry: jwt.NewNumericDate(expiry),
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (h *svidHarness) get(token string) (*httptest.ResponseRecorder, auditEvent) {
	r := httptest.NewRequest(http.MethodGet, "/datasets/A", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	h.auditBuf.Reset()
	w := httptest.NewRecorder()
	h.srv.handleProtected(w, r)
	var ev auditEvent
	if line := strings.TrimSpace(h.auditBuf.String()); line != "" {
		_ = json.Unmarshal([]byte(line), &ev)
	}
	return w, ev
}

func TestUnverifiableSVIDsAreRefusedBeforeOPA(t *testing.T) {
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	cases := []struct {
		name  string
		token func(h *svidHarness) string
	}{
		{"missing token", func(*svidHarness) string { return "" }},
		{"expired token", func(h *svidHarness) string {
			return svidToken(t, h.key, svidTestKeyID, svidTestSubject, svidTestAudience, time.Now().Add(-time.Hour))
		}},
		{"wrongly signed token", func(*svidHarness) string {
			// Right key id and claims, but signed by a key the bundle does not hold.
			return svidToken(t, otherKey, svidTestKeyID, svidTestSubject, svidTestAudience, future)
		}},
		{"wrong-audience token", func(h *svidHarness) string {
			return svidToken(t, h.key, svidTestKeyID, svidTestSubject, "spiffe://lab.local/svc/vending-service", future)
		}},
		{"other-trust-domain token", func(h *svidHarness) string {
			return svidToken(t, h.key, svidTestKeyID, "spiffe://elsewhere.example/agent/parent/t1", svidTestAudience, future)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSVIDHarness(t) // OPA would say yes: only verification can stop these.
			w, ev := h.get(tc.token(h))

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
			}
			if n := h.opaCalls.Load(); n != 0 {
				t.Fatalf("OPA was consulted %d time(s) for an unverified caller", n)
			}
			if ev.Outcome != "deny" || ev.Stage != stageOperate {
				t.Fatalf("audit event = %+v, want an operate/deny event", ev)
			}
			if ev.ActorSpiffeID != "" {
				t.Errorf("actor_spiffe_id = %q: nothing was verified, so nothing may be attributed", ev.ActorSpiffeID)
			}
			if ev.Detail.Reason == "" || ev.Detail.PolicyDecision != nil {
				t.Errorf("detail = %+v, want a reason and no policy decision", ev.Detail)
			}
		})
	}
}

// The positive control for the table above, and the no-cache requirement: the
// same valid token is verified and sent to OPA on every request, so a grant
// removed between two requests changes the second answer, and the 403 comes
// from OPA (the token still verifies).
func TestVerificationAndDecisionAreNotCached(t *testing.T) {
	h := newSVIDHarness(t)
	token := svidToken(t, h.key, svidTestKeyID, svidTestSubject, svidTestAudience, time.Now().Add(time.Hour))

	w, ev := h.get(token)
	if w.Code != http.StatusOK || ev.Outcome != "allow" || ev.ActorSpiffeID != svidTestSubject {
		t.Fatalf("first request: %d %+v", w.Code, ev)
	}
	if n := h.opaCalls.Load(); n != 1 {
		t.Fatalf("OPA calls after the first request = %d, want 1", n)
	}

	h.opaAnswer.Store(false) // the grant is revoked; the token is unchanged and still valid
	w, ev = h.get(token)
	if w.Code != http.StatusForbidden {
		t.Fatalf("second request: status = %d, want 403 from OPA", w.Code)
	}
	if n := h.opaCalls.Load(); n != 2 {
		t.Fatalf("OPA calls after the second request = %d, want 2 (no cached decision)", n)
	}
	if ev.Outcome != "deny" || ev.Detail.PolicyDecision == nil || *ev.Detail.PolicyDecision || ev.ActorSpiffeID != svidTestSubject {
		t.Fatalf("audit event = %+v, want an attributed deny carrying OPA's decision", ev)
	}
}
