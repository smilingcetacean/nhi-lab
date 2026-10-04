package main

import (
	"crypto/tls"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// x509Source is the subset of workloadapi.X509Source this package needs,
// named separately (mirroring src/resource/mtls.go) so the TLS wiring can be
// exercised without a live Workload API in tests.
type x509Source interface {
	x509svid.Source
	x509bundle.Source
}

// mtlsServerConfig builds the TLS config this service serves /synthesize
// over. Unlike the resource (JWT-SVID ingress), the policy engine's
// ingress is mTLS: the caller must present an X.509-SVID
// and is authorized by SPIFFE ID, confined to exactly one identity — by
// default spiffe://lab.local/svc/vending-service, overridable by
// CLIENT_SPIFFE_ID so a probe can exercise this path directly (see
// `make verify-policy`).
func mtlsServerConfig(src x509Source, acceptedClient spiffeid.ID) *tls.Config {
	return tlsconfig.MTLSServerConfig(src, src, tlsconfig.AuthorizeID(acceptedClient))
}

// mtlsClientConfig builds the TLS config this service uses to reach OPA,
// authorizing OPA by its SPIFFE ID rather than by hostname/DNS — the same
// choice src/resource/mtls.go makes and for the same reason.
func mtlsClientConfig(src x509Source, opaID spiffeid.ID) *tls.Config {
	return tlsconfig.MTLSClientConfig(src, src, tlsconfig.AuthorizeID(opaID))
}
