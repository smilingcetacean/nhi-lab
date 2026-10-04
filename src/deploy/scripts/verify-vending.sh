#!/usr/bin/env bash
# Vending-service verification for `make verify-vending`.
#
#   In-cluster integration test: a test parent with a static entry submits
#   a manifest; the child pod subsequently obtains its own SVID via the
#   Workload API without any human action; the child can access exactly its
#   granted scopes on the resource; after disposal the child's SVID stops
#   being renewable and resource access is denied.
#
# This script drives the FULL vending flow end to end against the real
# vending service, the real SPIRE Entry API, and the real policy engine —
# no mocks, no overrides of ingress identity (contrast verify-policy.sh, which
# overrides the policy engine's CLIENT_SPIFFE_ID to call it directly).
#
# Roles are played by real, running pods, each with its own SPIRE-attested
# identity — never a human typing a curl command by hand:
#   vending-test-parent   spiffe://lab.local/agent/parent/vend-verify (registered,
#                          bootstrap scopes: resource:read:datasetA only)
#   vending-test-attacker reuses svc/test-workload — a real, unrelated,
#                          authenticated identity, for the wrong-caller test
#   vending-test-child    UNREGISTERED at apply time — the vending service
#                          creates its entry dynamically, mid-script
set -uo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-nhi-lab}"
KUBECTX="${KUBECTX:-kind-${CLUSTER_NAME}}"
TRUST_DOMAIN="${TRUST_DOMAIN:-lab.local}"

RESOURCE_URL="http://resource.nhi.svc.cluster.local:8080"

PARENT_ID="spiffe://${TRUST_DOMAIN}/agent/parent/vend-verify"
CHILD_PATH_HINT="child/vend-verify-c1"
CHILD_ID="${PARENT_ID}/${CHILD_PATH_HINT}"
RESOURCE_AUD="spiffe://${TRUST_DOMAIN}/svc/resource"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS="${SCRIPT_DIR}/../manifests"

KUBECTL=(kubectl --context "${KUBECTX}")

FAILURES=0
CHECK_NO=0

step() {
  CHECK_NO=$((CHECK_NO + 1))
  printf '\n\033[1m[%d] %s\033[0m\n' "${CHECK_NO}" "$1"
}
pass() { printf '    \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '    \033[31mFAIL\033[0m %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
indent() { sed 's/^/    | /'; }

cleanup() {
  "${KUBECTL[@]}" delete -f "${MANIFESTS}/test/44-vending-test-parent.yaml" \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${KUBECTL[@]}" delete -f "${MANIFESTS}/test/45-vending-test-child.yaml" \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The vending service's delegation/nonce store is a SQLite file on an
# emptyDir (deliberately not persisted across pod restarts).
# That is exactly what makes a restart here the cheap way to guarantee a
# clean nonce table: this script uses FIXED nonces (e.g.
# "vend_verify_vend_nonce") so the replay check is meaningful, but that means
# a second consecutive run against a pod that survived the first run would
# see its own first run's nonces as already used and fail with a confusing
# 409 that has nothing to do with the replay check under test. Mirrors
# verify-policy.sh's "clear the grant namespace so this run starts from genuine
# default deny" step for the same reason: idempotent re-runnability is part
# of what a verification script has to guarantee, not an incidental nicety.
step "Restarting the vending service so this run starts from an empty nonce/delegation store"
"${KUBECTL[@]}" rollout restart deployment/vending-service -n nhi >/dev/null 2>&1
if "${KUBECTL[@]}" rollout status deployment/vending-service -n nhi --timeout=120s >/dev/null 2>&1; then
  pass "vending service restarted; SQLite store (emptyDir) is fresh"
else
  fail "vending service did not roll out"
fi

step "Deploying the vending service's test fixtures (parent, attacker, child)"
"${KUBECTL[@]}" apply -f "${MANIFESTS}/test/44-vending-test-parent.yaml" 2>&1 | indent
"${KUBECTL[@]}" apply -f "${MANIFESTS}/test/45-vending-test-child.yaml" 2>&1 | indent

READY=1
wait_ready() {
  local ns="$1" deploy="$2"
  if ! "${KUBECTL[@]}" rollout status "deployment/${deploy}" -n "${ns}" \
       --timeout=150s >/dev/null 2>&1; then
    fail "not Ready: ${ns}/${deploy}"
    "${KUBECTL[@]}" get pods -n "${ns}" -o wide 2>&1 | indent
    READY=0
  fi
}
wait_ready nhi    vending-service
wait_ready agents vending-test-parent
wait_ready agents vending-test-attacker
wait_ready agents vending-test-child
if [ "${READY}" -eq 1 ]; then
  pass "vending service and all three test fixtures Ready"
else
  printf '\n\033[31m================ VENDING VERIFY: FAIL ================\033[0m\n'
  exit 1
fi

running_pod() {
  local ns="$1" selector="$2"
  "${KUBECTL[@]}" get pods -n "${ns}" -l "${selector}" --field-selector=status.phase=Running \
    --sort-by=.metadata.creationTimestamp -o jsonpath='{.items}' \
    | jq -r 'if length > 0 then .[-1].metadata.name else empty end'
}
PARENT_POD=$(running_pod agents app=vending-test-parent)
ATTACKER_POD=$(running_pod agents app=vending-test-attacker)
CHILD_POD=$(running_pod agents app=vending-test-child)
VENDING_POD=$(running_pod nhi app=vending-service)
echo "    | parent=${PARENT_POD}  attacker=${ATTACKER_POD}  child=${CHILD_POD}  vending-service=${VENDING_POD}"

# ---------------------------------------------------------------------------
# Bootstrap ConfigMap loads once at policy-engine startup (see the policy
# engine's bootstrap.go). Restart so the running pod is guaranteed to have the
# vend-verify parent, mirroring verify-policy.sh's
# treatment of its own CLIENT_SPIFFE_ID override.
step "Rolling the policy engine so it picks up the vend-verify bootstrap parent"
"${KUBECTL[@]}" apply -f "${MANIFESTS}/policy-engine/" >/dev/null 2>&1
"${KUBECTL[@]}" rollout restart deployment/policy-engine -n nhi >/dev/null 2>&1
if "${KUBECTL[@]}" rollout status deployment/policy-engine -n nhi --timeout=120s >/dev/null 2>&1; then
  pass "policy engine restarted"
else
  fail "policy engine did not roll out"
fi

exec_p() { "${KUBECTL[@]}" exec -n agents "${PARENT_POD}" -c parentsim -- "$@" 2>&1; }
exec_a() { "${KUBECTL[@]}" exec -n agents "${ATTACKER_POD}" -c parentsim -- "$@" 2>&1; }
exec_c() { "${KUBECTL[@]}" exec -n agents "${CHILD_POD}" -c parentsim -- "$@" 2>&1; }

# split_status_body <combined output from parentsim> -> "<http-code>|<json body>"
# parentsim prints "HTTP <code>" to stderr and the JSON body to stdout;
# `kubectl exec ... 2>&1` interleaves them onto one stream, so pull the
# HTTP code out with a pattern match rather than relying on stream order.
split_status_body() {
  local out="$1" code body
  code=$(printf '%s\n' "${out}" | grep -o 'HTTP [0-9]*' | tail -1 | awk '{print $2}')
  body=$(printf '%s\n' "${out}" | grep -v '^HTTP ' | tr '\n' ' ')
  echo "${code:-000}|${body}"
}

# vend_retrying <exec-fn-name> <nonce-prefix> [parentsim vend flags, no -nonce]
#
# Retries ONLY on the specific transient symptom this host has shown
# repeatedly across this repo's other verify scripts (verify-policy.sh's
# curl-exit-7/28 retry on a fresh pod IP's first connection): HTTP 502 whose
# body names a policy-engine call that itself hit
# "context deadline exceeded" — i.e. THIS service's egress connection to a
# freshly-restarted policy-engine pod stalling on first connect, not a
# genuine denial. A completed HTTP response of any other shape is never
# retried.
#
# A plain retry with the SAME nonce would be wrong: nonce recording happens
# BEFORE the policy-engine call (see the step ordering in the vending
# service's main.go), so a failed attempt has already burned its nonce even though nothing
# was minted. Each retry therefore uses a fresh nonce, and the caller reads
# back LAST_VEND_NONCE — never a nonce the CALLER should assume in advance —
# to know which one actually succeeded (needed by the replay check right
# after, which must resubmit the EXACT manifest that succeeded).
vend_retrying() {
  local exec_fn="$1" nonce_prefix="$2"; shift 2
  local attempt nonce
  for attempt in 1 2 3; do
    nonce="${nonce_prefix}"
    [ "${attempt}" -gt 1 ] && nonce="${nonce_prefix}_retry${attempt}"
    LAST_VEND_OUT=$("${exec_fn}" /parentsim vend -nonce="${nonce}" "$@")
    if echo "${LAST_VEND_OUT}" | grep -q 'HTTP 502' && echo "${LAST_VEND_OUT}" | grep -qi 'context deadline exceeded'; then
      echo "    | (attempt ${attempt}: transient policy-engine connect delay to a fresh pod IP, retrying with a fresh nonce)" >&2
      sleep 2
      continue
    fi
    break
  done
  LAST_VEND_NONCE="${nonce}"
}

show_audit() {
  local n="${1:-1}"
  echo "    | audit event(s):"
  "${KUBECTL[@]}" logs -n nhi "${VENDING_POD}" -c vending-service --tail=60 2>/dev/null \
    | grep '^{' | tail -n "${n}" | jq -c . 2>/dev/null | sed 's/^/    |   /'
}

# ---------------------------------------------------------------------------
step "The child is UNREGISTERED before any manifest is submitted (x509-check fails)"
OUT=$(exec_c /parentsim x509-check)
echo "${OUT}" | indent
if echo "${OUT}" | grep -qi '"error"'; then
  pass "no SPIRE registration entry matches the child's selectors yet"
else
  fail "expected x509-check to fail before any entry exists, got: ${OUT}"
fi

# ---------------------------------------------------------------------------
step "NEGATIVE — wrong caller identity: attacker relays a manifest genuinely signed by the real parent"
# The REAL parent (vending-test-parent) builds and correctly signs a
# manifest with its OWN key (-mode=sign: the x5c check would pass —
# this is not a forged signature). The attacker then submits that exact,
# unmodified manifest using ITS OWN authenticated connection (its own valid
# JWT-SVID, svc/test-workload). This models a captured/relayed manifest —
# the meaningful case: signature verification alone cannot catch it, because
# the signature genuinely is the real parent's. Only the caller-binding check
# (claimed parent_spiffe_id must equal the AUTHENTICATED caller) closes this.
SIGNED_MANIFEST=$(exec_p /parentsim sign \
  -child-path-hint="child/vend-verify-attacker-c1" \
  -scopes=resource:read:datasetA -selectors="k8s:ns=agents,k8s:sa=nhi-test-vend-child" \
  -nonce=vend_verify_attacker_nonce)
echo "    | captured manifest (genuinely signed by ${PARENT_ID}):"
echo "${SIGNED_MANIFEST}" | indent
OUT=$(exec_a /parentsim vend -raw-manifest="${SIGNED_MANIFEST}")
echo "${OUT}" | indent
R=$(split_status_body "${OUT}")
CODE="${R%%|*}"; BODY="${R#*|}"
if [ "${CODE}" = "403" ]; then
  pass "wrong caller identity refused with HTTP 403"
else
  fail "expected 403 for a caller claiming someone else's parent identity, got '${CODE}': ${BODY}"
fi
AUDIT_LINE=$("${KUBECTL[@]}" logs -n nhi "${VENDING_POD}" -c vending-service --tail=5 2>/dev/null | grep '^{' | tail -1)
echo "    | audit event: ${AUDIT_LINE}"
if echo "${AUDIT_LINE}" | jq -e '.outcome == "deny" and (.detail.reason | test("does not match"))' >/dev/null 2>&1; then
  pass "deny audit event names the actual mismatch, not just a generic refusal"
else
  fail "expected a deny audit event citing the caller/claim mismatch, got: ${AUDIT_LINE}"
fi

# ---------------------------------------------------------------------------
step "NEGATIVE — forged manifest: a structurally valid but tampered signature is refused"
OUT=$(exec_p /parentsim vend -corrupt-signature \
  -child-path-hint="child/vend-verify-forged-c1" \
  -scopes=resource:read:datasetA -selectors="k8s:ns=agents,k8s:sa=nhi-test-vend-child" \
  -nonce=vend_verify_forged_nonce)
echo "${OUT}" | indent
R=$(split_status_body "${OUT}")
CODE="${R%%|*}"; BODY="${R#*|}"
if [ "${CODE}" = "401" ]; then
  pass "forged/corrupted signature refused with HTTP 401"
else
  fail "expected 401 for a corrupted signature, got '${CODE}': ${BODY}"
fi
AUDIT_LINE=$("${KUBECTL[@]}" logs -n nhi "${VENDING_POD}" -c vending-service --tail=5 2>/dev/null | grep '^{' | tail -1)
echo "    | audit event: ${AUDIT_LINE}"
if echo "${AUDIT_LINE}" | jq -e '.outcome == "deny" and (.detail.reason | test("signature"))' >/dev/null 2>&1; then
  pass "deny audit event names signature verification specifically, not a generic 401"
else
  fail "expected a deny audit event citing signature verification, got: ${AUDIT_LINE}"
fi
NO_ENTRY=$("${KUBECTL[@]}" exec -n spire spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server entry show -spiffeID "${PARENT_ID}/child/vend-verify-forged-c1" 2>/dev/null | grep -c '^Entry ID' || true)
if [ "${NO_ENTRY}" = "0" ]; then
  pass "no SPIRE entry was created for the rejected forged manifest"
else
  fail "a SPIRE entry exists for a manifest that should have been rejected at signature verification"
fi

# ---------------------------------------------------------------------------
step "CHECK A — a real spawn manifest is submitted (with a scope-escalation attempt)"
# Bootstrap table grants vend-verify ONLY resource:read:datasetA. Requesting
# datasetB too proves the vending service passes the escalation through to
# the policy engine rather than pre-filtering it, and that what comes back
# is attenuated (Π(C) ⊆ Π(P)), not the requested superset.
vend_retrying exec_p vend_verify_vend_nonce \
  -child-path-hint="${CHILD_PATH_HINT}" \
  -scopes=resource:read:datasetA,resource:read:datasetB \
  -task-context="vending verify — full lifecycle" \
  -selectors="k8s:ns=agents,k8s:sa=nhi-test-vend-child" \
  -ttl=600
OUT="${LAST_VEND_OUT}"
VEND_NONCE="${LAST_VEND_NONCE}"
echo "${OUT}" | indent
R=$(split_status_body "${OUT}")
CODE="${R%%|*}"; BODY="${R#*|}"
if [ "${CODE}" = "201" ]; then
  pass "manifest accepted, delegation created (HTTP 201)"
else
  fail "expected 201 from POST /delegations, got '${CODE}': ${BODY}"
  printf '\n\033[31m================ VENDING VERIFY: FAIL ================\033[0m\n'
  exit 1
fi
CHAIN_ID=$(echo "${BODY}" | grep -o '"chain_id":"[^"]*"' | head -1 | cut -d'"' -f4)
RESPONSE_CHILD_ID=$(echo "${BODY}" | grep -o '"child_spiffe_id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "    | chain_id=${CHAIN_ID}  child_spiffe_id=${RESPONSE_CHILD_ID}"
if [ -n "${CHAIN_ID}" ] && [ "${RESPONSE_CHILD_ID}" = "${CHILD_ID}" ]; then
  pass "child_spiffe_id matches the expected shape (parent + /child/ + subtask-id)"
else
  fail "child_spiffe_id = '${RESPONSE_CHILD_ID}', expected '${CHILD_ID}'"
fi
if echo "${BODY}" | grep -q 'resource:read:datasetA' && ! echo "${BODY}" | grep -q 'resource:read:datasetB'; then
  pass "child_scopes = [resource:read:datasetA] only — the datasetB escalation attempt was attenuated away"
else
  fail "expected child_scopes to contain exactly resource:read:datasetA, got: ${BODY}"
fi
show_audit 1

# ---------------------------------------------------------------------------
step "NEGATIVE — replay: resubmitting the SAME manifest (same nonce) is refused"
# Reuses VEND_NONCE — whichever nonce ACTUALLY succeeded above (vend_retrying
# may have had to move off the initial "vend_verify_vend_nonce" if a transient
# policy-engine connect delay forced a retry with a fresh one). Replaying a
# nonce this run never actually used would prove nothing.
OUT=$(exec_p /parentsim vend \
  -child-path-hint="${CHILD_PATH_HINT}" \
  -scopes=resource:read:datasetA,resource:read:datasetB \
  -task-context="vending verify — full lifecycle" \
  -selectors="k8s:ns=agents,k8s:sa=nhi-test-vend-child" \
  -ttl=600 -nonce="${VEND_NONCE}")
echo "${OUT}" | indent
R=$(split_status_body "${OUT}")
CODE="${R%%|*}"; BODY="${R#*|}"
if [ "${CODE}" = "409" ]; then
  pass "replayed nonce refused with HTTP 409"
else
  fail "expected 409 for a replayed nonce, got '${CODE}': ${BODY}"
fi
AUDIT_LINE=$("${KUBECTL[@]}" logs -n nhi "${VENDING_POD}" -c vending-service --tail=5 2>/dev/null | grep '^{' | tail -1)
echo "    | audit event: ${AUDIT_LINE}"
if echo "${AUDIT_LINE}" | jq -e '.outcome == "deny" and (.detail.reason | test("already been used"))' >/dev/null 2>&1; then
  pass "deny audit event names replay specifically"
else
  fail "expected a deny audit event citing nonce reuse, got: ${AUDIT_LINE}"
fi

# ---------------------------------------------------------------------------
step "CHECK B — the child pod obtains its own SVID via the Workload API, no human action"
# No kubectl, no manual entry creation from here on — the child pod's own
# SPIRE agent picks up the entry the vending service created above and
# starts issuing the new identity, purely because the pod's own attested
# selectors (k8s:ns:agents, k8s:sa:nhi-test-vend-child) now match it.
GOT=""
for attempt in $(seq 1 15); do
  OUT=$(exec_c /parentsim x509-check)
  GOT=$(echo "${OUT}" | grep -o '"spiffe_id":"[^"]*"' | head -1 | cut -d'"' -f4)
  [ "${GOT}" = "${CHILD_ID}" ] && break
  sleep 2
done
echo "    | child x509-check -> spiffe_id=${GOT:-<none>} (after up to 30s for the agent to notice the new entry)"
if [ "${GOT}" = "${CHILD_ID}" ]; then
  pass "child pod holds an X.509-SVID for ${CHILD_ID}, obtained with no human action"
else
  fail "child pod never obtained an SVID for ${CHILD_ID}; last output: ${OUT}"
fi

# ---------------------------------------------------------------------------
step "CHECK C — the child accesses EXACTLY its granted scope, nothing more"
OUT=$(exec_c /parentsim call -call-audience="${RESOURCE_AUD}" -call-url="${RESOURCE_URL}/datasets/A")
echo "${OUT}" | indent
R=$(split_status_body "${OUT}")
if [ "${R%%|*}" = "200" ]; then
  pass "child reads datasetA (its granted scope): 200"
else
  fail "expected 200 on datasetA, got '${R%%|*}': ${R#*|}"
fi

OUT=$(exec_c /parentsim call -call-audience="${RESOURCE_AUD}" -call-url="${RESOURCE_URL}/datasets/B")
echo "${OUT}" | indent
R=$(split_status_body "${OUT}")
if [ "${R%%|*}" = "403" ]; then
  pass "child is denied datasetB (requested by the parent, attenuated away, never granted): 403"
else
  fail "expected 403 on datasetB, got '${R%%|*}': ${R#*|}"
fi

# Capture a still-valid JWT-SVID now, BEFORE disposal, to replay after —
# proves the post-disposal denial below is a POLICY decision (grant
# removed), not merely "the child could not get a token."
CAPTURED_JWT=$(exec_c /parentsim fetch-jwt -call-audience="${RESOURCE_AUD}")
# A real JWT-SVID is three base64url segments joined by '.'; parentsim's own
# error path prints "parentsim: ..." on failure, which does not match.
if printf '%s' "${CAPTURED_JWT}" | grep -qE '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'; then
  pass "captured a JWT-SVID for the resource, to be replayed after disposal"
else
  fail "could not capture a JWT-SVID before disposal: ${CAPTURED_JWT}"
fi

# ---------------------------------------------------------------------------
step "CHECK D — disposal: DELETE /delegations/{chain_id}"
OUT=$(exec_p /parentsim dispose -chain-id="${CHAIN_ID}")
echo "${OUT}" | indent
R=$(split_status_body "${OUT}")
if [ "${R%%|*}" = "200" ]; then
  pass "disposal accepted"
else
  fail "expected 200 from DELETE /delegations/${CHAIN_ID}, got '${R%%|*}': ${R#*|}"
fi
show_audit 1

ENTRY_GONE=$("${KUBECTL[@]}" exec -n spire spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server entry show -spiffeID "${CHILD_ID}" 2>/dev/null | grep -c '^Entry ID' || true)
if [ "${ENTRY_GONE}" = "0" ]; then
  pass "the SPIRE registration entry for ${CHILD_ID} no longer exists"
else
  fail "a SPIRE entry for ${CHILD_ID} still exists after disposal"
fi

# ---------------------------------------------------------------------------
step "CHECK E — after disposal, the child's SVID stops being renewable"
FINAL=""
for attempt in $(seq 1 10); do
  OUT=$(exec_c /parentsim x509-check)
  if echo "${OUT}" | grep -qi '"error"'; then
    FINAL="gone"
    break
  fi
  GOT_NOW=$(echo "${OUT}" | grep -o '"spiffe_id":"[^"]*"' | head -1 | cut -d'"' -f4)
  # If the agent still reports SOME SVID it must not be the disposed child's.
  if [ "${GOT_NOW}" != "${CHILD_ID}" ]; then
    FINAL="different"
    break
  fi
  sleep 2
done
echo "    | final x509-check output: ${OUT}"
if [ -n "${FINAL}" ]; then
  pass "child can no longer obtain/renew an SVID for ${CHILD_ID} (${FINAL})"
else
  fail "child still holds a renewable SVID for ${CHILD_ID} after disposal"
fi

# ---------------------------------------------------------------------------
step "CHECK F — resource access is denied after disposal, even replaying the pre-disposal token"
OUT=$(exec_c /parentsim bearer-call -call-url="${RESOURCE_URL}/datasets/A" -bearer-token="${CAPTURED_JWT}")
echo "${OUT}" | indent
R=$(split_status_body "${OUT}")
if [ "${R%%|*}" = "403" ]; then
  pass "the captured (still cryptographically valid) JWT-SVID is now denied — the OPA grant, not the token's own expiry, is what changed"
else
  fail "expected 403 replaying the pre-disposal token after disposal, got '${R%%|*}': ${R#*|}"
fi

# ---------------------------------------------------------------------------
step "The reaper independently catches an orphaned child (parent never disposes)"
# A second delegation, vended and then abandoned (no DELETE call) with a
# very short TTL. The reaper (REAPER_INTERVAL=15s on this deployment) must
# revoke it on its own within a bounded time — this is the
# orphaned-child case: a parent that dies before calling disposal.
vend_retrying exec_p vend_verify_orphan_nonce \
  -child-path-hint="child/vend-verify-orphan-c1" \
  -scopes=resource:read:datasetA \
  -task-context="vending verify — orphaned child" \
  -selectors="k8s:ns=agents,k8s:sa=nhi-test-vend-child" \
  -ttl=5
OUT="${LAST_VEND_OUT}"
echo "${OUT}" | indent
R=$(split_status_body "${OUT}")
ORPHAN_CODE="${R%%|*}"; ORPHAN_BODY="${R#*|}"
if [ "${ORPHAN_CODE}" = "201" ]; then
  ORPHAN_CHAIN=$(echo "${ORPHAN_BODY}" | grep -o '"chain_id":"[^"]*"' | head -1 | cut -d'"' -f4)
  pass "orphan delegation created: ${ORPHAN_CHAIN} (ttl=5s)"
else
  fail "could not create the orphan delegation to test the reaper against: ${ORPHAN_CODE} ${ORPHAN_BODY}"
  ORPHAN_CHAIN=""
fi

if [ -n "${ORPHAN_CHAIN:-}" ]; then
  # Distinguish "exec succeeded, zero entries" (real evidence the reaper
  # ran) from "exec failed" (a transient kubectl/pod hiccup). This script
  # runs `set -uo pipefail` WITHOUT `-e`, so a failed `kubectl exec`
  # previously produced empty stdout, `grep -c` on empty input returned "0"
  # via `|| true`, and REAPED was set to "yes" from a check that never
  # actually ran — check 13 passed vacuously even when the exec itself
  # failed. A failed exec must retry, never be read as "reaped".
  REAPED=""
  EXEC_EVER_OK=""
  for attempt in $(seq 1 15); do
    ORPHAN_RAW=$("${KUBECTL[@]}" exec -n spire spire-server-0 -c spire-server -- \
      /opt/spire/bin/spire-server entry show -spiffeID "${PARENT_ID}/child/vend-verify-orphan-c1" 2>&1)
    EXEC_STATUS=$?
    if [ "${EXEC_STATUS}" -ne 0 ]; then
      echo "    | (attempt ${attempt}) spire-server entry show exec failed (status ${EXEC_STATUS}), retrying: ${ORPHAN_RAW}" >&2
      sleep 2
      continue
    fi
    EXEC_EVER_OK="yes"
    ORPHAN_ENTRY=$(printf '%s\n' "${ORPHAN_RAW}" | grep -c '^Entry ID')
    if [ "${ORPHAN_ENTRY}" = "0" ]; then
      REAPED="yes"
      break
    fi
    sleep 2
  done
  if [ "${REAPED}" = "yes" ]; then
    pass "the reaper deleted the orphaned child's SPIRE entry with no DELETE call from the parent"
  elif [ -z "${EXEC_EVER_OK}" ]; then
    fail "could not confirm reaper status: every 'spire-server entry show' exec attempt failed (last status ${EXEC_STATUS})"
  else
    fail "the orphaned child's SPIRE entry still exists after 30s; the reaper did not catch it"
  fi
  # Known limitation, not fixed here (see src/vending-service/README.md
  # Known Limitations): disposeChain deletes the SPIRE entry before
  # emitting the dispose audit event, so this single read right after
  # REAPED="yes" is not guaranteed atomic with the audit write.
  AUDIT_LINE=$("${KUBECTL[@]}" logs -n nhi "${VENDING_POD}" -c vending-service --tail=30 2>/dev/null \
    | grep '^{' | jq -c "select(.chain_id==\"${ORPHAN_CHAIN}\" and .stage==\"dispose\")" 2>/dev/null | tail -1)
  echo "    | reaper audit event: ${AUDIT_LINE}"
  if echo "${AUDIT_LINE}" | jq -e '.detail.reason == "ttl_expired"' >/dev/null 2>&1; then
    pass "reaper's dispose audit event is attributed with reason ttl_expired, distinguishing it from an on-demand revoke"
  else
    fail "expected a dispose audit event with reason ttl_expired for the orphan, got: ${AUDIT_LINE}"
  fi
fi

printf '\n'
if [ "${FAILURES}" -eq 0 ]; then
  printf '\033[32m================ VENDING VERIFY: PASS (%d checks) ================\033[0m\n' "${CHECK_NO}"
  printf 'One full spawn -> attest -> vend -> operate -> dispose cycle, driven end to end:\n'
  printf '  unregistered child          -> no SVID obtainable\n'
  printf '  wrong caller / forged sig   -> refused, with a specific audit reason each\n'
  printf '  requested A+B, Pi(P)=A      -> child_scopes=[A] (escalation attenuated)\n'
  printf '  replayed nonce              -> refused (409)\n'
  printf '  entry created               -> child obtains its own SVID, no human action\n'
  printf '  operate                     -> 200 on A, 403 on B\n'
  printf '  disposed                    -> entry gone, SVID not renewable, captured token now denied\n'
  printf '  orphaned child               -> reaped by TTL with no DELETE call\n'
  exit 0
else
  printf '\033[31m================ VENDING VERIFY: FAIL (%d failed) ================\033[0m\n' "${FAILURES}"
  exit 1
fi
