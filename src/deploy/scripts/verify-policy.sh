#!/usr/bin/env bash
# Policy-engine verification for `make verify-policy`.
#
#   go test ./... passes; a generated Rego module loaded into OPA produces
#   the expected allow/deny matrix against the live protected resource.
#
# This script drives the FULL synthesis path end to end: a client calls
# POST /synthesize on the policy engine over mTLS, the engine derives Π(P)
# from the bootstrap ConfigMap (not from anything the caller sent),
# intersects it with an ESCALATION ATTEMPT (the caller asks for a scope the
# parent does not hold), renders and pushes the resulting Rego to OPA, and
# only THEN is the resource's allow/deny matrix checked — with the same JWT-
# SVID reused throughout, exactly as verify-resource.sh does, so the only variable
# between outcomes is the policy the engine actually wrote.
#
# So that this script does not depend on the vending service, the one identity
# /synthesize authorizes (svc/vending-service) is overridden for the duration
# of this run to svc/policy-probe — an existing verification-only identity —
# and restored afterwards. That override, and its restoration, is itself
# asserted.
set -uo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-nhi-lab}"
KUBECTX="${KUBECTX:-kind-${CLUSTER_NAME}}"
TRUST_DOMAIN="${TRUST_DOMAIN:-lab.local}"

RESOURCE_AUDIENCE="spiffe://${TRUST_DOMAIN}/svc/resource"
RESOURCE_URL="http://resource.nhi.svc.cluster.local:8080"
OPA_URL="https://opa.opa.svc.cluster.local:8181"
POLICY_ENGINE_URL="https://policy-engine.nhi.svc.cluster.local:8443"

PARENT_ID="spiffe://${TRUST_DOMAIN}/agent/parent/policy-verify"          # bootstrap: resource:read:datasetA only
# CHILD_ID is a properly shaped descendant of PARENT_ID
# (PARENT_ID + "/child/" + <subtask-id>). /synthesize validates this
# structurally, so this cannot be an
# arbitrary caller-chosen identity. register-entries.sh registers this exact
# SPIFFE ID against a DEDICATED service account (k8s:sa:nhi-test-child,
# manifests/test/43-child-workload.yaml) rather than reusing k8s:sa:nhi-test —
# see that manifest's header comment for why (it would otherwise break the
# "exactly one SVID" invariant verify.sh asserts for nhi-test-workload).
CHILD_ID="spiffe://${TRUST_DOMAIN}/agent/parent/policy-verify/child/policy-verify-child"
CALLER_ID="${CHILD_ID}"                                               # the identity whose JWT-SVID we fetch and spend
# The escalation the descendant check closes: an UNRELATED identity — a sibling of
# PARENT_ID's namespace, not one of its descendants — must be refused as
# child_spiffe_id even when requested_scopes ⊆ Π(PARENT_ID). Reusing the
# plain svc/test-workload identity (not shaped as anyone's child) as that
# unrelated identity.
UNRELATED_CHILD_ID="spiffe://${TRUST_DOMAIN}/svc/test-workload"
CHAIN_ID="policy_verify_chain"
PROBE_CLIENT_ID="spiffe://${TRUST_DOMAIN}/svc/policy-probe"           # override target for CLIENT_SPIFFE_ID
WRONG_CLIENT_ID="spiffe://${TRUST_DOMAIN}/svc/policy-engine"          # the OTHER probe identity — must be refused

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

# ---------------------------------------------------------------------------
cleanup() {
  # Restore the policy engine's accepted client identity to its real default
  # before tearing anything else down, so a failed run does not leave the
  # override in place for whoever runs the cluster next.
  "${KUBECTL[@]}" apply -f "${MANIFESTS}/policy-engine/" >/dev/null 2>&1 || true
  "${KUBECTL[@]}" rollout status deployment/policy-engine -n nhi --timeout=120s >/dev/null 2>&1 || true
  "${KUBECTL[@]}" delete -f "${MANIFESTS}/test/43-child-workload.yaml" \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${KUBECTL[@]}" delete -f "${MANIFESTS}/test/42-resource-client.yaml" \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${KUBECTL[@]}" delete -f "${MANIFESTS}/test/41-policy-probe.yaml" \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

step "Deploying the resource, the test caller, the child identity and the mTLS probes"
"${KUBECTL[@]}" apply -f "${MANIFESTS}/resource/50-resource.yaml" 2>&1 | indent
"${KUBECTL[@]}" apply -f "${MANIFESTS}/test/42-resource-client.yaml" 2>&1 | indent
"${KUBECTL[@]}" apply -f "${MANIFESTS}/test/43-child-workload.yaml" 2>&1 | indent
"${KUBECTL[@]}" apply -f "${MANIFESTS}/test/41-policy-probe.yaml" 2>&1 | indent

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
wait_ready nhi    resource
wait_ready nhi    policy-engine
wait_ready agents resource-client
wait_ready agents child-workload
wait_ready nhi    policy-probe-unauthorized
wait_ready nhi    policy-probe-authorized
if [ "${READY}" -eq 1 ]; then
  pass "resource, policy engine, test caller, child identity and both probes all Ready"
else
  printf '\n\033[31m================ POLICY VERIFY: FAIL ================\033[0m\n'
  exit 1
fi

# running_pod <ns> <selector> — the newest Running pod matching the selector.
#
# NOT `.items[0]`: this script (like verify-resource.sh, which it runs right
# after in the canonical sequence) recreates Deployments that share a label
# with whatever a PRIOR run's `--wait=false` cleanup left mid-Terminating —
# observed on this host taking 30-40s to fully disappear. `.items[0]` from an
# unsorted list can pick that dying pod instead of the fresh Ready one,
# producing a `NotFound` moments later. Filtering to Running and sorting by
# creation time picks the pod `wait_ready` actually just confirmed.
running_pod() {
  local ns="$1" selector="$2"
  "${KUBECTL[@]}" get pods -n "${ns}" -l "${selector}" --field-selector=status.phase=Running \
    --sort-by=.metadata.creationTimestamp -o jsonpath='{.items}' \
    | jq -r 'if length > 0 then .[-1].metadata.name else empty end'
}

CLIENT_POD=$(running_pod agents app=resource-client)
CHILD_POD=$(running_pod agents app=child-workload)
UNAUTH_PROBE_POD=$(running_pod nhi probe=unauthorized)
AUTH_PROBE_POD=$(running_pod nhi probe=authorized)
RESOURCE_POD=$(running_pod nhi app=resource)
echo "    | caller(spend)=${CLIENT_POD}  caller(fetch,${CHILD_ID})=${CHILD_POD}  synth-probe(policy-probe)=${UNAUTH_PROBE_POD}  synth-probe(policy-engine)=${AUTH_PROBE_POD}  resource=${RESOURCE_POD}"

# ---------------------------------------------------------------------------
step "Overriding CLIENT_SPIFFE_ID so a probe pod can exercise /synthesize directly"
"${KUBECTL[@]}" -n nhi set env deployment/policy-engine "CLIENT_SPIFFE_ID=${PROBE_CLIENT_ID}" 2>&1 | indent
if "${KUBECTL[@]}" rollout status deployment/policy-engine -n nhi --timeout=120s >/dev/null 2>&1; then
  pass "policy engine now accepts ${PROBE_CLIENT_ID} on /synthesize (default remains svc/vending-service — see README)"
else
  fail "policy engine did not roll out after the CLIENT_SPIFFE_ID override"
  "${KUBECTL[@]}" get pods -n nhi -l app=policy-engine -o wide 2>&1 | indent
fi
POLICY_ENGINE_POD=$(running_pod nhi app=policy-engine)

# ---------------------------------------------------------------------------
# call <method> <path> [extra curl args...] on the RESOURCE, using the caller pod.
call() {
  local method="$1" path="$2"; shift 2
  local out code body
  out=$("${KUBECTL[@]}" exec -n agents "${CLIENT_POD}" -c client -- \
    curl -sS --max-time 15 -X "${method}" \
    -H "Authorization: Bearer ${JWT}" \
    -w '\nNHI_HTTP_CODE:%{http_code}' \
    "$@" "${RESOURCE_URL}${path}" 2>&1)
  code=$(printf '%s' "${out}" | grep -o 'NHI_HTTP_CODE:[0-9]*' | tail -1 | cut -d: -f2)
  body=$(printf '%s' "${out}" | grep -v 'NHI_HTTP_CODE:' | tr '\n' ' ' | head -c 300)
  echo "${code:-000}|${body}"
}

# opa_write <method> <policy-id> [data] — as svc/policy-engine, the only
# identity OPA's system.authz lets write Rego. Used only to clear stale state.
opa_write() {
  local method="$1" id="$2" data="${3:-}"
  local args=(-sS --max-time 15 -o /dev/null -w '%{http_code}'
    --cacert /run/spiffe/bundle.pem
    --cert /run/spiffe/svid.pem --key /run/spiffe/svid_key.pem
    -X "${method}" "${OPA_URL}/v1/policies/${id}")
  if [ -n "${data}" ]; then
    args+=(--data-binary "${data}")
  fi
  "${KUBECTL[@]}" exec -n nhi "${AUTH_PROBE_POD}" -c probe -- curl "${args[@]}" 2>&1 | tr -d '\n'
}

# synth <pod> <method> <path> [body] -> "<status>|<body>", against the POLICY
# ENGINE over mTLS, using whichever probe pod's own SVID.
#
# Retries on a bare TCP connect timeout (curl exit 28/7), and ONLY on that —
# never on a completed TLS handshake or HTTP response, which are the actual
# things under test. Observed repeatedly on this host: the very first
# connection between a just-created probe pod and a just-rolled
# policy-engine pod (both fresh pod IPs — the CLIENT_SPIFFE_ID override in
# step 2 forces a new policy-engine rollout every run) can time out at the
# bare TCP connect stage with no TLS bytes exchanged at all, while a retry
# moments later succeeds immediately. That is a new-pod-IP conntrack/CNI
# characteristic of this sandboxed host, not the policy engine: the
# long-lived resource/OPA pods verify.sh and verify-resource.sh talk to never
# show it. Retrying a bare connect timeout does not paper over anything this
# script cares about — a refusal that reaches the TLS layer
# (the wrong-identity check right above) returns a definite alert well
# under a second and is never retried.
synth() {
  local pod="$1" method="$2" path="$3" body="${4:-}"
  local args=(-sS --max-time 20
    --cacert /run/spiffe/bundle.pem
    --cert /run/spiffe/svid.pem --key /run/spiffe/svid_key.pem
    -w '\nNHI_HTTP_CODE:%{http_code}'
    -X "${method}" -H 'Content-Type: application/json')
  if [ -n "${body}" ]; then
    args+=(--data-binary "${body}")
  fi
  local out code respbody attempt
  for attempt in 1 2 3; do
    out=$("${KUBECTL[@]}" exec -n nhi "${pod}" -c probe -- \
      curl "${args[@]}" "${POLICY_ENGINE_URL}${path}" 2>&1)
    if ! echo "${out}" | grep -qE 'curl: \(7\)|curl: \(28\)'; then
      break
    fi
    echo "    | (attempt ${attempt}: bare TCP connect timeout to a fresh pod IP, retrying) ${out}" >&2
    sleep 2
  done
  code=$(printf '%s' "${out}" | grep -o 'NHI_HTTP_CODE:[0-9]*' | tail -1 | cut -d: -f2)
  respbody=$(printf '%s' "${out}" | grep -v 'NHI_HTTP_CODE:' | tr '\n' ' ' | head -c 500)
  echo "${code:-000}|${respbody}"
}

show_audit() {
  local n="${1:-1}" pod="${2:-${POLICY_ENGINE_POD}}" container="${3:-policy-engine}"
  echo "    | audit event(s):"
  "${KUBECTL[@]}" logs -n nhi "${pod}" -c "${container}" --tail=40 2>/dev/null \
    | grep '^{' | tail -n "${n}" | jq -c . 2>/dev/null | sed 's/^/    |   /'
}

# ---------------------------------------------------------------------------
step "Clearing the grant namespace so this run starts from genuine default deny"
EXISTING=$("${KUBECTL[@]}" exec -n nhi "${AUTH_PROBE_POD}" -c probe -- \
  curl -sS --max-time 15 \
  --cacert /run/spiffe/bundle.pem \
  --cert /run/spiffe/svid.pem --key /run/spiffe/svid_key.pem \
  "${OPA_URL}/v1/policies" 2>/dev/null \
  | jq -r '.result[]?.id // empty' 2>/dev/null | grep '^nhi_grants_' || true)
if [ -z "${EXISTING}" ]; then
  echo "    | no pre-existing grant modules"
else
  echo "${EXISTING}" | sed 's/^/    | removing: /'
  while read -r id; do
    [ -n "${id}" ] && opa_write DELETE "${id}" >/dev/null 2>&1
  done <<< "${EXISTING}"
fi
REMAINING=$("${KUBECTL[@]}" exec -n nhi "${AUTH_PROBE_POD}" -c probe -- \
  curl -sS --max-time 15 \
  --cacert /run/spiffe/bundle.pem \
  --cert /run/spiffe/svid.pem --key /run/spiffe/svid_key.pem \
  "${OPA_URL}/v1/policies" 2>/dev/null \
  | jq -r '.result[]?.id // empty' 2>/dev/null | grep -c '^nhi_grants_' || true)
if [ "${REMAINING}" = "0" ]; then
  pass "grant namespace is empty"
else
  fail "${REMAINING} grant module(s) still loaded; the checks below would be meaningless"
fi

# ---------------------------------------------------------------------------
step "Child identity obtains a JWT-SVID for the resource"
# Fetched from CHILD_POD (manifests/test/43-child-workload.yaml), whose SOLE
# registered identity is CHILD_ID — -spiffeID is passed anyway as an explicit
# assertion of intent, not because it is needed to disambiguate here.
JWT_JSON=$("${KUBECTL[@]}" exec -n agents "${CHILD_POD}" -c svid -- \
  /opt/spire/bin/spire-agent api fetch jwt \
  -audience "${RESOURCE_AUDIENCE}" -spiffeID "${CALLER_ID}" -socketPath /run/spire/sockets/agent.sock \
  -output json 2>&1)
JWT=$(echo "${JWT_JSON}" | jq -r '..|.svid? // empty' 2>/dev/null | head -1)
JWT_SUB=$(echo "${JWT_JSON}" | jq -r '..|.spiffe_id? // empty' 2>/dev/null | head -1)
if [ -z "${JWT}" ]; then
  echo "${JWT_JSON}" | indent
  fail "could not obtain a JWT-SVID for audience ${RESOURCE_AUDIENCE}"
  printf '\n\033[31m================ POLICY VERIFY: FAIL ================\033[0m\n'
  exit 1
fi
echo "    | subject: ${JWT_SUB}"
if [ "${JWT_SUB}" = "${CALLER_ID}" ]; then
  pass "caller holds a valid JWT-SVID for ${CALLER_ID} (reused as the 'child' below)"
else
  fail "JWT-SVID subject is '${JWT_SUB}', expected '${CALLER_ID}'"
fi

# ---------------------------------------------------------------------------
step "CHECK A — before synthesis, the resource denies (default deny)"
R=$(call GET /datasets/A)
echo "    | GET /datasets/A -> ${R}"
if [ "${R%%|*}" = "403" ]; then
  pass "no grant yet: denied"
else
  fail "expected 403 before any grant exists, got '${R%%|*}'"
fi

# ---------------------------------------------------------------------------
step "A caller using the WRONG probe identity is refused by the policy engine's mTLS listener"
# CLIENT_SPIFFE_ID was just overridden to svc/policy-probe. The OTHER
# ephemeral probe identity (svc/policy-engine) must be refused — the engine
# confines /synthesize to exactly one SPIFFE ID, mirroring the confinement
# OPA itself applies to policy writes.
#
# A bare "curl produced no 3-digit HTTP code" is not
# proof of a TLS rejection — the same class of flake documented elsewhere in
# this script for curl exit 7/28 (bare TCP connect timeout to a fresh pod IP)
# would ALSO produce no HTTP code and pass this check for the wrong reason.
# -v is used instead so stderr can be inspected for the actual TLS-alert
# signature, and a connect-timeout is treated as inconclusive (retried, then
# failed explicitly) rather than silently counted as a pass.
WRONG_OUT=""
for attempt in 1 2 3; do
  WRONG_OUT=$("${KUBECTL[@]}" exec -n nhi "${AUTH_PROBE_POD}" -c probe -- \
    curl -sS -v --max-time 30 -o /dev/null -w 'NHI_HTTP_CODE:%{http_code} NHI_EXIT:%{exitcode}' \
    --cacert /run/spiffe/bundle.pem \
    --cert /run/spiffe/svid.pem --key /run/spiffe/svid_key.pem \
    -X POST -H 'Content-Type: application/json' --data-binary '{}' \
    "${POLICY_ENGINE_URL}/synthesize" 2>&1)
  if echo "${WRONG_OUT}" | grep -qE 'curl: \(7\)|curl: \(28\)|NHI_EXIT:(7|28)'; then
    echo "    | (attempt ${attempt}: bare TCP connect timeout to a fresh pod IP, retrying)" >&2
    sleep 2
    continue
  fi
  break
done
CODE_LINE=$(echo "${WRONG_OUT}" | grep -o 'NHI_HTTP_CODE:[0-9]*' | tail -1)
EXIT_LINE=$(echo "${WRONG_OUT}" | grep -o 'NHI_EXIT:[0-9]*' | tail -1)
echo "    | POST /synthesize as ${WRONG_CLIENT_ID} (accepted identity is ${PROBE_CLIENT_ID}) -> ${CODE_LINE:-no HTTP code} ${EXIT_LINE:-}"
if echo "${WRONG_OUT}" | grep -qE 'curl: \(7\)|curl: \(28\)'; then
  fail "curl could not even connect (exit 7/28) after retries — this is a network/scheduling flake, NOT evidence of a TLS rejection; re-run"
elif echo "${WRONG_OUT}" | grep -qiE '(alert|certificate)' && echo "${WRONG_OUT}" | grep -qE 'curl: \(35\)|curl: \(56\)'; then
  pass "wrong client identity refused at the TLS layer (curl exit 35/56, alert/certificate signature in curl -v output)"
elif [ "${CODE_LINE}" = "NHI_HTTP_CODE:000" ] && echo "${WRONG_OUT}" | grep -qiE 'ssl|tls|handshake|certificate|alert'; then
  pass "wrong client identity refused before any HTTP response, with a TLS-shaped curl error"
else
  fail "expected a TLS-alert signature (exit 35/56, alert/certificate in curl -v) refusing ${WRONG_CLIENT_ID}, got: ${CODE_LINE:-none} ${EXIT_LINE:-}"
fi

# ---------------------------------------------------------------------------
step "An UNRELATED child_spiffe_id is rejected (400 + deny audit), closing the escalation"
# The escalation: without a descendant check, synthesize(parent=P1, child=P2,
# requested⊆Π(P1)) would succeed and write a grant naming P2, even though
# P2 is not P1's child at all — a subsequent synthesize(parent=P2, ...) would
# read that grant back as P2's OWN authority via deriveParentScopes.
# UNRELATED_CHILD_ID (svc/test-workload) is not shaped as any descendant of
# PARENT_ID, so this call must be refused before anything is written.
ESCALATION_BODY=$(cat <<EOF
{"chain_id":"${CHAIN_ID}_escalation","parent_spiffe_id":"${PARENT_ID}","child_spiffe_id":"${UNRELATED_CHILD_ID}",
 "requested_scopes":["resource:read:datasetA"],
 "task_context":"policy verify — sibling/unrelated child_spiffe_id escalation attempt","ttl_seconds":600}
EOF
)
echo "${ESCALATION_BODY}" | indent
R=$(synth "${UNAUTH_PROBE_POD}" POST /synthesize "${ESCALATION_BODY}")
echo "    | POST /synthesize (unrelated child) -> ${R}"
if [ "${R%%|*}" = "400" ]; then
  pass "unrelated child_spiffe_id (${UNRELATED_CHILD_ID}) refused with HTTP 400 — not a descendant of ${PARENT_ID}"
else
  fail "expected 400 for an unrelated child_spiffe_id, got '${R%%|*}': ${R#*|}"
fi
AUDIT_LINE=$("${KUBECTL[@]}" logs -n nhi "${POLICY_ENGINE_POD}" -c policy-engine --tail=5 2>/dev/null | grep '^{' | tail -1)
echo "    | audit event: ${AUDIT_LINE}"
if echo "${AUDIT_LINE}" | jq -e '.outcome == "deny" and (.detail.reason | test("descendant"))' >/dev/null 2>&1; then
  pass "deny audit event recorded, citing the descendant check"
else
  fail "expected a deny audit event citing the descendant check, got: ${AUDIT_LINE}"
fi
# Confirm nothing was written: the grant namespace is still empty, so a
# subsequent legitimate synthesis below cannot be mistaken for evidence that
# this rejected call actually landed something.
LEFTOVER=$("${KUBECTL[@]}" exec -n nhi "${AUTH_PROBE_POD}" -c probe -- \
  curl -sS --max-time 15 \
  --cacert /run/spiffe/bundle.pem \
  --cert /run/spiffe/svid.pem --key /run/spiffe/svid_key.pem \
  "${OPA_URL}/v1/policies" 2>/dev/null \
  | jq -r '.result[]?.id // empty' 2>/dev/null | grep -c '^nhi_grants_' || true)
if [ "${LEFTOVER}" = "0" ]; then
  pass "no grant module was written for the rejected escalation attempt"
else
  fail "${LEFTOVER} grant module(s) exist after a rejected escalation attempt — it wrote something"
fi

# ---------------------------------------------------------------------------
step "Synthesizing a grant: requested exceeds Π(P) — an escalation attempt"
# Bootstrap table (36-policy-engine-bootstrap.yaml) grants
# spiffe://lab.local/agent/parent/policy-verify ONLY resource:read:datasetA.
# Requesting datasetB too proves the engine attenuates rather than trusting
# the request: Π(C) = requested ∩ Π(P), never requested verbatim.
BODY=$(cat <<EOF
{"chain_id":"${CHAIN_ID}","parent_spiffe_id":"${PARENT_ID}","child_spiffe_id":"${CHILD_ID}",
 "requested_scopes":["resource:read:datasetA","resource:read:datasetB"],
 "task_context":"policy verify — escalation attempt","ttl_seconds":600}
EOF
)
echo "${BODY}" | indent
R=$(synth "${UNAUTH_PROBE_POD}" POST /synthesize "${BODY}")
echo "    | POST /synthesize -> ${R}"
CODE="${R%%|*}"
RESP_BODY="${R#*|}"
if [ "${CODE}" = "200" ]; then
  pass "synthesis accepted from the authorized probe identity (HTTP 200)"
else
  fail "expected 200 from POST /synthesize, got '${CODE}': ${RESP_BODY}"
fi
if echo "${RESP_BODY}" | grep -q 'resource:read:datasetA' && ! echo "${RESP_BODY}" | grep -q 'resource:read:datasetB'; then
  pass "child_scopes = [resource:read:datasetA] only — the datasetB escalation attempt was attenuated away"
else
  fail "expected child_scopes to contain exactly resource:read:datasetA, got: ${RESP_BODY}"
fi
show_audit 1

# ---------------------------------------------------------------------------
step "CHECK B — the SAME pod, SAME token, can now read dataset A"
R=$(call GET /datasets/A)
echo "    | GET /datasets/A -> ${R}"
if [ "${R%%|*}" = "200" ] && echo "${R}" | grep -q '"dataset"'; then
  pass "the policy engine's generated Rego grants exactly the synthesized scope"
else
  fail "expected 200 with a dataset payload, got '${R}'"
fi

step "CHECK C — but dataset B stays denied (attenuation, not escalation)"
R=$(call GET /datasets/B)
echo "    | GET /datasets/B -> ${R}"
if [ "${R%%|*}" = "403" ]; then
  pass "ungranted (and unheld-by-the-parent) scope denied"
else
  fail "expected 403 for datasetB, got '${R%%|*}'"
fi

# ---------------------------------------------------------------------------
step "Re-synthesizing the SAME chain_id is idempotent on the OPA side (same policy_id)"
R2=$(synth "${UNAUTH_PROBE_POD}" POST /synthesize "${BODY}")
CODE2="${R2%%|*}"
echo "    | POST /synthesize (again) -> ${R2}"
if [ "${CODE2}" = "200" ] && echo "${R2}" | grep -q "nhi_grants_policy_verify_chain"; then
  pass "policy_id is a pure function of chain_id : nhi_grants_policy_verify_chain both times"
else
  fail "expected the same policy_id on re-synthesis, got: ${R2}"
fi

# ---------------------------------------------------------------------------
step "CHECK D — disposal: DELETE /synthesize/{chain_id} removes the grant"
DEL=$(synth "${UNAUTH_PROBE_POD}" DELETE "/synthesize/${CHAIN_ID}")
echo "    | DELETE /synthesize/${CHAIN_ID} -> ${DEL}"
if [ "${DEL%%|*}" = "200" ]; then
  pass "disposal accepted"
else
  fail "expected 200 from DELETE /synthesize/${CHAIN_ID}, got '${DEL%%|*}': ${DEL#*|}"
fi
show_audit 1

step "After disposal, the SAME token is denied again — the credential alone confers nothing"
R=$(call GET /datasets/A)
echo "    | GET /datasets/A -> ${R}"
if [ "${R%%|*}" = "403" ]; then
  pass "default deny restored"
else
  fail "expected 403 after disposal, got '${R%%|*}'"
fi

# ---------------------------------------------------------------------------
step "Unknown parent (absent from OPA and the bootstrap table) attenuates to the empty set"
# child_spiffe_id must still be a properly-shaped descendant of THIS parent —
# the descendant check runs before Π(P) is even derived, so an unrelated
# child_spiffe_id would be rejected with 400 regardless of whether the parent
# is known. The case under test here is specifically "known-shape child,
# unknown parent", not "malformed child".
UNKNOWN_BODY='{"chain_id":"policy_verify_unknown","parent_spiffe_id":"spiffe://lab.local/agent/parent/nobody",
 "child_spiffe_id":"spiffe://lab.local/agent/parent/nobody/child/policy-verify-unknown-child",
 "requested_scopes":["resource:read:datasetA","resource:read:datasetB"],
 "task_context":"policy verify — unknown parent","ttl_seconds":60}'
R=$(synth "${UNAUTH_PROBE_POD}" POST /synthesize "${UNKNOWN_BODY}")
echo "    | POST /synthesize (unknown parent) -> ${R}"
if [ "${R%%|*}" = "200" ] && echo "${R#*|}" | jq -e '.child_scopes | length == 0' >/dev/null 2>&1; then
  pass "unknown parent -> child_scopes = [] (fail closed, not an error)"
else
  fail "expected an empty child_scopes array for an unknown parent, got: ${R}"
fi
synth "${UNAUTH_PROBE_POD}" DELETE "/synthesize/policy_verify_unknown" >/dev/null

# ---------------------------------------------------------------------------
# The header claims the override "and its restoration" is asserted. The
# restoration previously happened only in the cleanup() trap, whose failures
# are swallowed by `|| true` — so the claim was not earned. Assert it here,
# while a failure can still be reported. Leaving the override in place would
# mean the policy engine accepts a verification-only identity as the sole
# authorized /synthesize caller for whoever uses the cluster next.
step "The CLIENT_SPIFFE_ID override is restored to the real default"
"${KUBECTL[@]}" apply -f "${MANIFESTS}/policy-engine/" >/dev/null 2>&1 || true
"${KUBECTL[@]}" rollout status deployment/policy-engine -n nhi --timeout=120s >/dev/null 2>&1 || true
RESTORED=$("${KUBECTL[@]}" get deployment/policy-engine -n nhi \
  -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="CLIENT_SPIFFE_ID")].value}' 2>/dev/null)
echo "    | CLIENT_SPIFFE_ID = ${RESTORED:-<unset>}"
if [ "${RESTORED}" = "spiffe://${TRUST_DOMAIN}/svc/vending-service" ]; then
  pass "override restored; the probe identity is no longer authorized to /synthesize"
else
  fail "CLIENT_SPIFFE_ID left at '${RESTORED:-<unset>}', expected spiffe://${TRUST_DOMAIN}/svc/vending-service"
fi

printf '\n'
if [ "${FAILURES}" -eq 0 ]; then
  printf '\033[32m================ POLICY VERIFY: PASS (%d checks) ================\033[0m\n' "${CHECK_NO}"
  printf 'One synthesized grant, driven end to end through the policy engine:\n'
  printf '  before synthesis        -> 403 on /datasets/A\n'
  printf '  requested A+B, Π(P)=A   -> child_scopes=[A] (escalation attenuated)\n'
  printf '  grant active            -> 200 on /datasets/A, 403 on /datasets/B\n'
  printf '  disposed                -> 403 on /datasets/A again\n'
  exit 0
else
  printf '\033[31m================ POLICY VERIFY: FAIL (%d failed) ================\033[0m\n' "${FAILURES}"
  exit 1
fi
