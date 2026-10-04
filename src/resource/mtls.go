package main

import (
	"crypto/tls"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// x509Source is the subset of workloadapi.X509Source this package needs. Named
// separately so the mTLS wiring can be exercised without a Workload API.
type x509Source interface {
	x509svid.Source
	x509bundle.Source
}

// mtlsClientConfig builds the TLS config the resource uses to reach OPA.
//
// AuthorizeID pins OPA's SPIFFE ID. DNS SANs exist on the svc/opa entry so that non-SPIFFE-aware
// clients can verify it, but a go-spiffe client should authorize on identity
// instead, which does not depend on DNS being trustworthy.
func mtlsClientConfig(src x509Source, opaID spiffeid.ID) *tls.Config {
	return tlsconfig.MTLSClientConfig(src, src, tlsconfig.AuthorizeID(opaID))
}
