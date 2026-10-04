// Package signature implements the manifest-signing scheme: a
// detached JWS (RFC 7515 Appendix F) over the manifest's canonical bytes,
// signed with the private key backing the signer's own X.509-SVID, carrying
// that certificate's chain in the `x5c` header so the verifier can check it
// against the SPIRE trust bundle without a separate lookup.
package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	josejwt "github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// x5cHeader is the RFC 7515 §4.1.6 header parameter name.
const x5cHeader = josejwt.HeaderKey("x5c")

// acceptedAlgorithms bounds what Verify accepts. SPIRE's default key type is
// EC P-256, so ES256 covers the lab; PS256 is accepted too so a
// differently-configured SPIRE (RSA key type) is not silently unsupported.
var acceptedAlgorithms = []josejwt.SignatureAlgorithm{josejwt.ES256, josejwt.PS256}

// Sign produces a detached-JWS compact serialization over payload, signed
// with key (the private key backing leafAndChain[0], the signer's own
// X.509-SVID) and carrying leafAndChain in the x5c header. Used by
// cmd/parentsim to sign a spawn manifest; not used by the vending service
// itself, which only verifies.
func Sign(payload []byte, key crypto.Signer, leafAndChain []*x509.Certificate) (string, error) {
	if len(leafAndChain) == 0 {
		return "", errors.New("at least one certificate (the leaf) is required")
	}
	alg, err := algorithmFor(key.Public())
	if err != nil {
		return "", err
	}

	x5c := make([]string, len(leafAndChain))
	for i, c := range leafAndChain {
		x5c[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}

	opts := (&josejwt.SignerOptions{}).WithHeader(x5cHeader, x5c)
	signer, err := josejwt.NewSigner(josejwt.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		return "", fmt.Errorf("construct signer: %w", err)
	}

	obj, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("sign manifest: %w", err)
	}
	compact, err := obj.DetachedCompactSerialize()
	if err != nil {
		return "", fmt.Errorf("serialize detached JWS: %w", err)
	}
	return compact, nil
}

// Verify checks that compactJWS is a valid detached-JWS signature over
// payload, whose x5c header chains to one of roots, and whose leaf
// certificate's SPIFFE ID (URI SAN) equals expectedSigner. It returns the
// verified leaf certificate's SPIFFE ID on success — which is always
// expectedSigner, returned so callers can log what was actually checked
// rather than what was merely asked for.
//
// Chain verification uses x509.ExtKeyUsageAny: SPIRE X.509-SVIDs are typically
// issued with both server- and client-auth EKUs, and this check's purpose is
// "does this certificate chain to our trust root", not "is this specifically
// a TLS server/client cert" — that distinction belongs to the TLS layer, not
// here.
func Verify(compactJWS string, payload []byte, roots []*x509.Certificate, expectedSigner spiffeid.ID) error {
	if compactJWS == "" {
		return errors.New("empty signature")
	}
	obj, err := josejwt.ParseDetached(compactJWS, payload, acceptedAlgorithms)
	if err != nil {
		return fmt.Errorf("parse detached JWS: %w", err)
	}
	if len(obj.Signatures) != 1 {
		return fmt.Errorf("expected exactly one JWS signature, got %d", len(obj.Signatures))
	}

	pool := x509.NewCertPool()
	for _, c := range roots {
		pool.AddCert(c)
	}
	chains, err := obj.Signatures[0].Protected.Certificates(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("x5c certificate chain does not verify against the trust bundle: %w", err)
	}
	if len(chains) == 0 || len(chains[0]) == 0 {
		return errors.New("x5c verification produced no chain")
	}
	leaf := chains[0][0]

	if err := obj.DetachedVerify(payload, leaf.PublicKey); err != nil {
		return fmt.Errorf("signature does not verify against the x5c leaf certificate's key: %w", err)
	}

	if len(leaf.URIs) == 0 {
		return errors.New("x5c leaf certificate carries no URI SAN")
	}
	leafID, err := spiffeid.FromURI(leaf.URIs[0])
	if err != nil {
		return fmt.Errorf("parse SPIFFE ID from x5c leaf certificate: %w", err)
	}
	if leafID != expectedSigner {
		return fmt.Errorf("x5c leaf certificate identity %q does not match expected signer %q", leafID, expectedSigner)
	}
	return nil
}

func algorithmFor(pub crypto.PublicKey) (josejwt.SignatureAlgorithm, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return josejwt.ES256, nil
	case *rsa.PublicKey:
		return josejwt.PS256, nil
	default:
		return "", fmt.Errorf("unsupported public key type %T", pub)
	}
}
