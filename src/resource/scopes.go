package main

import "net/http"

// route is one protected endpoint and the scopes a caller must hold to use it.
type route struct {
	method string
	path   string
	// requiredScopes is what this endpoint DEMANDS. It is a property of the
	// endpoint, fixed at compile time — never anything the caller sends.
	requiredScopes []string
	// dataset is the payload returned on an allow. Nil for non-GET routes.
	dataset map[string]any
}

// routes is the whole protected surface. Two datasets plus a write are the minimum that can distinguish "allowed to
// read A" from "allowed to read anything" from "allowed to write", which is
// what the verification and attenuation tests need to tell apart.
var routes = []route{
	{
		method:         http.MethodGet,
		path:           "/datasets/A",
		requiredScopes: []string{"resource:read:datasetA"},
		dataset: map[string]any{
			"dataset": "A",
			"records": []map[string]any{
				{"id": 1, "value": "alpha"},
				{"id": 2, "value": "beta"},
			},
		},
	},
	{
		method:         http.MethodGet,
		path:           "/datasets/B",
		requiredScopes: []string{"resource:read:datasetB"},
		dataset: map[string]any{
			"dataset": "B",
			"records": []map[string]any{
				{"id": 1, "value": "gamma"},
			},
		},
	},
	{
		method:         http.MethodPost,
		path:           "/jobs",
		requiredScopes: []string{"resource:write:jobs"},
	},
}

// requiredScopesFor returns the scopes an endpoint demands, and whether the
// endpoint exists at all.
//
// It is worth being explicit about why this function looks like this.
//
// `scopes` in the OPA input means REQUIRED scopes, derived here from the method
// and path. It never means scopes asserted by the caller. The reason is that a
// SPIRE JWT-SVID carries no custom claims — there is nowhere for SPIRE to put a
// verified scope list — so any scope list arriving from the caller would be
// unauthenticated, and honouring it would be a self-grant: a child could
// request `resource:read:datasetB`, assert it held that scope, and be believed.
//
// The split of responsibility is therefore:
//
//	the resource states what the request DEMANDS  (this function)
//	OPA holds what the subject has been GRANTED   (data.nhi.grants, from the policy engine)
//
// and the decision is containment of the first in the second. Neither side can
// widen the other.
func requiredScopesFor(method, path string) ([]string, bool) {
	for _, r := range routes {
		if r.method == method && r.path == path {
			return r.requiredScopes, true
		}
	}
	return nil, false
}

func routeFor(method, path string) (route, bool) {
	for _, r := range routes {
		if r.method == method && r.path == path {
			return r, true
		}
	}
	return route{}, false
}
