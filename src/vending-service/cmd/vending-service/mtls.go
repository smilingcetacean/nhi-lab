package main

import (
	"crypto/tls"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// x509Source is the subset of workloadapi.X509Source this package needs,
// mirroring src/resource/mtls.go and src/policy-engine/mtls.go.
type x509Source interface {
	x509svid.Source
	x509bundle.Source
}

// bundleSource is the ingress credential source: it validates parents' JWT-
// SVIDs (jwtbundle.Source, as src/resource uses) AND, the same bundle's
// other half, the x5c chain on a manifest signature (x509bundle.Source).
// Typed as an interface — not the concrete *workloadapi.BundleSource —
// so tests can substitute a fake bundle without a live Workload API,
// mirroring src/resource/main.go's `bundles jwtbundle.Source` field.
type bundleSource interface {
	jwtbundle.Source
	x509bundle.Source
}

// mtlsClientConfig builds the TLS config used for BOTH egress legs this
// service has: to the policy engine and to the SPIRE server's
// admin API. Both are authorized by SPIFFE ID, not hostname —
// consistent with src/resource and src/policy-engine.
func mtlsClientConfig(src x509Source, peer spiffeid.ID) *tls.Config {
	return tlsconfig.MTLSClientConfig(src, src, tlsconfig.AuthorizeID(peer))
}
