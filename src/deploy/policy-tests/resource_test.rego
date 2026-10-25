package nhi.resource_test

# Tests for nhi/resource.rego, the base containment policy. The shipped policy
# is cut out of the opa-authz ConfigMap by run.sh, so these tests exercise the
# text that actually runs in the cluster.
#
# Lineage used throughout:
#
#     P  spiffe://lab.local/agent/parent/t1                      (root, no grant)
#     C  spiffe://lab.local/agent/parent/t1/child/c1
#     G  spiffe://lab.local/agent/parent/t1/child/c1/child/g1

import rego.v1

p := "spiffe://lab.local/agent/parent/t1"

c := "spiffe://lab.local/agent/parent/t1/child/c1"

g := "spiffe://lab.local/agent/parent/t1/child/c1/child/g1"

now := 1000

read_a := ["resource:read:datasetA"]

grant(id, expires_at) := {
	"spiffe_id": id,
	"scopes": read_a,
	"expires_at": expires_at,
}

req(id) := {
	"spiffe_id": id,
	"method": "GET",
	"path": "/datasets/A",
	"scopes": read_a,
	"now": now,
}

# --- the lineage rule -------------------------------------------------------

test_g_allowed_when_c_and_g_grants_live if {
	grants := {"c": grant(c, 2000), "g": grant(g, 2000)}
	data.nhi.resource.allow with input as req(g) with data.nhi.grants as grants
}

# The logical cascade on its own: C's grant is gone, G's is still present.
test_g_denied_when_c_grant_removed if {
	grants := {"g": grant(g, 2000)}
	not data.nhi.resource.allow with input as req(g) with data.nhi.grants as grants
}

test_c_allowed_with_only_the_root_above_it if {
	grants := {"c": grant(c, 2000)}
	data.nhi.resource.allow with input as req(c) with data.nhi.grants as grants
}

test_g_denied_when_c_grant_expired if {
	grants := {"c": grant(c, 999), "g": grant(g, 2000)}
	not data.nhi.resource.allow with input as req(g) with data.nhi.grants as grants
}

test_c_denied_when_its_own_grant_expired if {
	grants := {"c": grant(c, 999)}
	not data.nhi.resource.allow with input as req(c) with data.nhi.grants as grants
}

# Another chain's grant for the same ancestor still counts as "some grant
# naming that ancestor", and a grant for a different identity does not.
test_a_grant_for_a_different_child_is_not_an_ancestor_grant if {
	other := "spiffe://lab.local/agent/parent/t1/child/other"
	grants := {"o": grant(other, 2000), "g": grant(g, 2000)}
	not data.nhi.resource.allow with input as req(g) with data.nhi.grants as grants
}

test_two_grants_for_the_ancestor_one_expired_still_live if {
	grants := {
		"c_old": grant(c, 999),
		"c_new": grant(c, 2000),
		"g": grant(g, 2000),
	}
	data.nhi.resource.allow with input as req(g) with data.nhi.grants as grants
}

# A third level: every non-root ancestor must be live, not only the parent.
test_depth_three_needs_the_whole_chain if {
	gg := concat("/", [g, "child", "x1"])
	all_live := {"c": grant(c, 2000), "g": grant(g, 2000), "x": grant(gg, 2000)}
	missing_c := {"g": grant(g, 2000), "x": grant(gg, 2000)}
	missing_g := {"c": grant(c, 2000), "x": grant(gg, 2000)}
	data.nhi.resource.allow with input as req(gg) with data.nhi.grants as all_live
	not data.nhi.resource.allow with input as req(gg) with data.nhi.grants as missing_c
	not data.nhi.resource.allow with input as req(gg) with data.nhi.grants as missing_g
}

# --- the unchanged base behaviour -------------------------------------------

test_no_grants_denies if {
	not data.nhi.resource.allow with input as req(c) with data.nhi.grants as {}
}

test_scope_not_granted_denies if {
	grants := {"c": grant(c, 2000)}
	inp := object.union(req(c), {"scopes": ["resource:write:jobs"]})
	not data.nhi.resource.allow with input as inp with data.nhi.grants as grants
}

test_root_has_no_ancestors if {
	count(data.nhi.resource.ancestors) == 0 with input as req(p)
}

test_ancestors_of_g_are_c_only if {
	data.nhi.resource.ancestors == {c} with input as req(g)
}
