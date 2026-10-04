package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// testCA is a minimal self-signed CA plus a helper to mint leaf certs with a
// SPIFFE URI SAN, standing in for the SPIRE server's own CA in these tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"test-ca"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

// leaf mints a leaf certificate for id, signed by the CA, with a private key
// the test can sign a JWS with.
func (ca *testCA) leaf(t *testing.T, id spiffeid.ID) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(id.String())
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"test-leaf"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func mustID(t *testing.T, s string) spiffeid.ID {
	t.Helper()
	id, err := spiffeid.FromString(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestSignVerifyRoundTrip(t *testing.T) {
	ca := newTestCA(t)
	parentID := mustID(t, "spiffe://lab.local/agent/parent/t1")
	leaf, key := ca.leaf(t, parentID)

	payload := []byte(`{"hello":"world"}`)
	compact, err := Sign(payload, key, []*x509.Certificate{leaf})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := Verify(compact, payload, []*x509.Certificate{ca.cert}, parentID); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	ca := newTestCA(t)
	parentID := mustID(t, "spiffe://lab.local/agent/parent/t1")
	leaf, key := ca.leaf(t, parentID)

	payload := []byte(`{"hello":"world"}`)
	compact, err := Sign(payload, key, []*x509.Certificate{leaf})
	if err != nil {
		t.Fatal(err)
	}

	tampered := []byte(`{"hello":"mallory"}`)
	if err := Verify(compact, tampered, []*x509.Certificate{ca.cert}, parentID); err == nil {
		t.Fatal("expected verification of a tampered payload to fail")
	}
}

// TestVerifyRejectsWrongSignerIdentity is the escalation this scheme exists
// to close: a valid signature from a DIFFERENT identity's key (also chained
// to the same trust root) must not verify as if it came from expectedSigner.
func TestVerifyRejectsWrongSignerIdentity(t *testing.T) {
	ca := newTestCA(t)
	attackerID := mustID(t, "spiffe://lab.local/agent/parent/attacker")
	leaf, key := ca.leaf(t, attackerID)

	payload := []byte(`{"hello":"world"}`)
	compact, err := Sign(payload, key, []*x509.Certificate{leaf})
	if err != nil {
		t.Fatal(err)
	}

	claimedID := mustID(t, "spiffe://lab.local/agent/parent/t1")
	if err := Verify(compact, payload, []*x509.Certificate{ca.cert}, claimedID); err == nil {
		t.Fatal("expected verification to fail: signer identity does not match the claimed parent")
	}
}

// TestVerifyRejectsUntrustedRoot: a leaf signed by a CA that is not in the
// verifier's trust bundle must not verify, even with a structurally correct
// signature and matching SPIFFE ID.
func TestVerifyRejectsUntrustedRoot(t *testing.T) {
	realCA := newTestCA(t)
	rogueCA := newTestCA(t)
	parentID := mustID(t, "spiffe://lab.local/agent/parent/t1")
	leaf, key := rogueCA.leaf(t, parentID)

	payload := []byte(`{"hello":"world"}`)
	compact, err := Sign(payload, key, []*x509.Certificate{leaf})
	if err != nil {
		t.Fatal(err)
	}

	if err := Verify(compact, payload, []*x509.Certificate{realCA.cert}, parentID); err == nil {
		t.Fatal("expected verification to fail: leaf is not chained to the trusted root")
	}
}

func TestVerifyRejectsEmptySignature(t *testing.T) {
	if err := Verify("", []byte("x"), nil, spiffeid.ID{}); err == nil {
		t.Fatal("expected error for empty signature")
	}
}
