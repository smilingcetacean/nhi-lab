#!/usr/bin/env bash
# Create the static SPIRE registration entries the lab baseline needs.
#
# Idempotent: existing entries are left alone, so this can be re-run freely.
#
# Two entries are created:
#
#  1. A NODE ALIAS, spiffe://lab.local/node/nhi-lab, matching every agent that
#     attested with k8s_psat against cluster "nhi-lab". Workload entries are
#     parented to this alias rather than to an individual agent's SPIFFE ID,
#     because the agent ID embeds the node UID and therefore changes every time
#     the cluster is recreated. The vending service uses the same alias as
#     the parent ID of the child entries it mints.
#
#  2. The static test workload, spiffe://lab.local/svc/test-workload,
#     selected by namespace + service account.
#
#  2a. A DIFFERENT test pod's identity,
#      spiffe://lab.local/agent/parent/policy-verify/child/policy-verify-child —
#      a properly shaped CHILD of the policy-verify bootstrap root parent
#      (see manifests/policy-engine/36-policy-engine-bootstrap.yaml).
#      verify-policy.sh needs a real descendant identity to synthesize a
#      grant for and then present a JWT-SVID as, because /synthesize
#      validates that child_spiffe_id is a structural descendant of
#      parent_spiffe_id rather than accepting any non-empty string. This is
#      selected by a DEDICATED service account (k8s:sa:nhi-test-child,
#      manifests/test/43-child-workload.yaml) rather than reusing
#      k8s:sa:nhi-test: verify.sh asserts the nhi-test-workload pod resolves
#      to EXACTLY ONE X.509-SVID and one JWT-SVID subject, so adding a second
#      entry against the SAME selectors as svc/test-workload would break that
#      invariant for every pod under that service account, including the
#      resource-client.
#
#  3. The policy plane: svc/opa, svc/policy-engine and svc/resource, plus the
#     ephemeral svc/policy-probe used by verify.sh. These are declared here
#     rather than alongside the code for each component, because the policy
#     plane is *pre-declared*: the resource and the policy engine inherit an
#     identity and an authority they did not choose for themselves.
#
#  4. svc/vending-service, and the vend-verify test parent identity that
#     verify-vending.sh drives real spawn manifests through.
#
# Naming: a service pod in namespace `nhi` running under service account
# <name> is spiffe://lab.local/svc/<name>. OPA is the exception — it predates
# that namespace and stays in `opa` with its own service account.
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-nhi-lab}"
KUBECTX="${KUBECTX:-kind-${CLUSTER_NAME}}"
TRUST_DOMAIN="${TRUST_DOMAIN:-lab.local}"
NODE_ALIAS_ID="spiffe://${TRUST_DOMAIN}/node/${CLUSTER_NAME}"
TEST_WORKLOAD_ID="spiffe://${TRUST_DOMAIN}/svc/test-workload"
TEST_CHILD_ID="spiffe://${TRUST_DOMAIN}/agent/parent/policy-verify/child/policy-verify-child"

KUBECTL=(kubectl --context "${KUBECTX}")
SPIRE_SERVER=("${KUBECTL[@]}" exec -n spire spire-server-0 -c spire-server --
              /opt/spire/bin/spire-server)

entry_exists() {
  local spiffe_id="$1"
  "${SPIRE_SERVER[@]}" entry show -spiffeID "${spiffe_id}" 2>/dev/null \
    | grep -q "^Entry ID"
}

ensure_entry() {
  local description="$1"; shift
  local spiffe_id="$1"; shift
  if entry_exists "${spiffe_id}"; then
    echo "  = ${description}: ${spiffe_id} (already registered)"
    return 0
  fi
  echo "  + ${description}: ${spiffe_id}"
  "${SPIRE_SERVER[@]}" entry create "$@" >/dev/null
}

echo "Registering static SPIRE entries in trust domain ${TRUST_DOMAIN}"

ensure_entry "node alias" "${NODE_ALIAS_ID}" \
  -node \
  -spiffeID "${NODE_ALIAS_ID}" \
  -selector "k8s_psat:cluster:${CLUSTER_NAME}"

ensure_entry "static test workload" "${TEST_WORKLOAD_ID}" \
  -parentID "${NODE_ALIAS_ID}" \
  -spiffeID "${TEST_WORKLOAD_ID}" \
  -selector "k8s:ns:agents" \
  -selector "k8s:sa:nhi-test"

ensure_entry "properly-shaped child test identity (verify-policy only)" "${TEST_CHILD_ID}" \
  -parentID "${NODE_ALIAS_ID}" \
  -spiffeID "${TEST_CHILD_ID}" \
  -selector "k8s:ns:agents" \
  -selector "k8s:sa:nhi-test-child"

# --- Policy plane -----------------------------------------------------------
#
# OPA's own serving identity. Its SVID is delivered by a spiffe-helper sidecar
# because OPA cannot speak the Workload API; the entry is otherwise
# ordinary. Note that this identity has no privileges in OPA's own system.authz
# policy — it is what OPA *presents*, not what OPA *accepts*.
#
# The -dnsName flags matter and are not cosmetic. A SPIRE X509-SVID carries the
# SPIFFE ID in the URI SAN and, by default, NO DNS SAN at all. A SPIFFE-aware
# client (go-spiffe, as the resource uses) authenticates the peer by its
# SPIFFE ID and does not care. A generic TLS client — curl in verify.sh, or any
# off-the-shelf tool — performs hostname verification and would reject the
# connection outright. Adding the service DNS names lets both kinds of client
# talk to OPA without anyone resorting to --insecure, which would silently
# discard the server authentication half of mTLS.
ensure_entry "OPA server" "spiffe://${TRUST_DOMAIN}/svc/opa" \
  -parentID "${NODE_ALIAS_ID}" \
  -spiffeID "spiffe://${TRUST_DOMAIN}/svc/opa" \
  -selector "k8s:ns:opa" \
  -selector "k8s:sa:opa" \
  -dns "opa.opa.svc.cluster.local" \
  -dns "opa.opa.svc" \
  -dns "opa"

# The only identity OPA authorizes to write Rego. The image behind this
# identity is built separately; the identity itself is fixed here.
#
# -dns flags for the same reason as svc/opa above: the policy engine is
# SPIFFE-aware itself (go-spiffe, authorizes on URI SAN) and does not need
# them, but verify-policy.sh drives it with plain curl over mTLS, which
# performs ordinary hostname verification and would otherwise need
# --insecure — discarding the server-authentication half of mTLS for the sake
# of a verification script.
ensure_entry "policy engine" "spiffe://${TRUST_DOMAIN}/svc/policy-engine" \
  -parentID "${NODE_ALIAS_ID}" \
  -spiffeID "spiffe://${TRUST_DOMAIN}/svc/policy-engine" \
  -selector "k8s:ns:nhi" \
  -selector "k8s:sa:policy-engine" \
  -dns "policy-engine.nhi.svc.cluster.local" \
  -dns "policy-engine.nhi.svc" \
  -dns "policy-engine"

# The protected resource. Two distinct credentials meet at this service
# and they must not be confused: this X509-SVID is what it presents *to OPA* as
# a client. The JWT-SVIDs it validates on ingress are its callers' — issued to
# agents, with audience spiffe://lab.local/svc/resource.
ensure_entry "protected resource" "spiffe://${TRUST_DOMAIN}/svc/resource" \
  -parentID "${NODE_ALIAS_ID}" \
  -spiffeID "spiffe://${TRUST_DOMAIN}/svc/resource" \
  -selector "k8s:ns:nhi" \
  -selector "k8s:sa:resource"

# The vending service. This identity is named in the SPIRE server's
# admin_ids, so any pod scheduled under this service account holds unscoped
# SPIRE admin over the Entry API. It is the most privileged identity in the
# lab; keep the service account's use confined to the vending service.
ensure_entry "vending service" "spiffe://${TRUST_DOMAIN}/svc/vending-service" \
  -parentID "${NODE_ALIAS_ID}" \
  -spiffeID "spiffe://${TRUST_DOMAIN}/svc/vending-service" \
  -selector "k8s:ns:nhi" \
  -selector "k8s:sa:vending-service"

# Vending-service verification fixture, same pattern as policy-verify above: a REAL running
# pod (manifests/test/44-vending-test-parent.yaml) authenticates as this
# SPIFFE ID and submits real spawn manifests to the vending service.
# Root-parent scopes: manifests/policy-engine/36-policy-engine-bootstrap.yaml.
VEND_PARENT_ID="spiffe://${TRUST_DOMAIN}/agent/parent/vend-verify"
ensure_entry "vend-verify parent (verify-vending only)" "${VEND_PARENT_ID}" \
  -parentID "${NODE_ALIAS_ID}" \
  -spiffeID "${VEND_PARENT_ID}" \
  -selector "k8s:ns:agents" \
  -selector "k8s:sa:nhi-test-vend-parent"

# Deliberately absent: any entry for nhi-test-vend-child. The whole point
# of the vending service is that it creates exactly this entry
# in-band, from the spawn manifest — see verify-vending.sh.

# The demo parent (`make demo`, src/agents/parent.py,
# manifests/agents/71-demo-parent-pod.yaml). Same static-root-parent pattern
# as vend-verify above, but this is the identity a REAL parent.py runs as,
# not a temporary Go verification harness. Root-parent scopes:
# manifests/policy-engine/36-policy-engine-bootstrap.yaml.
DEMO_PARENT_ID="spiffe://${TRUST_DOMAIN}/agent/parent/demo"
ensure_entry "demo parent" "${DEMO_PARENT_ID}" \
  -parentID "${NODE_ALIAS_ID}" \
  -spiffeID "${DEMO_PARENT_ID}" \
  -selector "k8s:ns:agents" \
  -selector "k8s:sa:nhi-demo-parent"

# Deliberately absent: any entry for the demo child. Exactly like
# nhi-test-vend-child above, this is what src/agents/parent.py's spawn
# manifest creates dynamically — the child pod does not exist, let alone
# have an entry, until the vending service has minted one from the manifest.

# The experiments root parent (src/experiments/, manifests/experiments/).
# Same static-root-parent pattern as vend-verify/demo above, but this identity
# is deliberately granted ALL THREE scopes in the bootstrap ConfigMap so the
# functional/multi-hop/performance suites have more than a singleton scope
# set to randomize over. See manifests/policy-engine/36-policy-engine-bootstrap.yaml.
EXP_PARENT_ID="spiffe://${TRUST_DOMAIN}/agent/parent/exp-root"
ensure_entry "experiments root parent" "${EXP_PARENT_ID}" \
  -parentID "${NODE_ALIAS_ID}" \
  -spiffeID "${EXP_PARENT_ID}" \
  -selector "k8s:ns:agents" \
  -selector "k8s:sa:nhi-exp-parent"

# Deliberately absent: any entry for the experiments child or grandchild.
# Exactly like nhi-test-vend-child/the demo child above, these are what the
# vending service creates dynamically once a manifest names their selectors
# — the multi-hop suite's whole point is that the CHILD pod, once
# vended, can itself play parent for a grandchild with no pre-registration.

# Verification-only identity for verify.sh's policy-plane checks. It appears in
# no system.authz rule, which is the entire point: it is the "valid SVID for an
# identity that is not the policy engine" case that verify.sh must exercise.
ensure_entry "policy probe (verify only)" "spiffe://${TRUST_DOMAIN}/svc/policy-probe" \
  -parentID "${NODE_ALIAS_ID}" \
  -spiffeID "spiffe://${TRUST_DOMAIN}/svc/policy-probe" \
  -selector "k8s:ns:nhi" \
  -selector "k8s:sa:policy-probe"

echo
"${SPIRE_SERVER[@]}" entry show
