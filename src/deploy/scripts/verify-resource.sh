#!/usr/bin/env bash
# Protected-resource verification for `make verify-resource`.
#
#   A pod with a valid SVID but no policy is denied (default deny); after
#   loading a hand-written Rego rule granting resource:read:datasetA to a test
#   SPIFFE ID, the same pod can read dataset A but not B.
#
# The same pod, the same credential, the same endpoint — the only thing that
# changes between the denial and the allow is the policy in OPA. That is the
# point of the test, so the script goes out of its way not to vary anything
# else: one JWT-SVID is fetched at the start and reused throughout.
#
# As with verify.sh, nothing is inferred. Each check prints the real HTTP status
# and body, and every denial is shown together with the audit event the resource
# emitted for it — a negative result must evidence both.
set -uo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-nhi-lab}"
KUBECTX="${KUBECTX:-kind-${CLUSTER_NAME}}"
TRUST_DOMAIN="${TRUST_DOMAIN:-lab.local}"

CALLER_ID="spiffe://${TRUST_DOMAIN}/svc/test-workload"
AUDIENCE="spiffe://${TRUST_DOMAIN}/svc/resource"
RESOURCE_URL="http://resource.nhi.svc.cluster.local:8080"
OPA_URL="https://opa.opa.svc.cluster.local:8181"
GRANT_POLICY_ID="nhi_grants_resource_verify"

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
# Ephemeral helpers: the caller pod, and the policy-engine-identity probe that
# writes the hand-written grant. Both are torn down on exit — see
# 41-policy-probe.yaml for why the authorized probe must not outlive the run.
cleanup() {
  "${KUBECTL[@]}" delete -f "${MANIFESTS}/test/42-resource-client.yaml" \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${KUBECTL[@]}" delete -f "${MANIFESTS}/test/41-policy-probe.yaml" \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

step "Deploying the resource, the test caller and the policy writer"
"${KUBECTL[@]}" apply -f "${MANIFESTS}/resource/50-resource.yaml" 2>&1 | indent
"${KUBECTL[@]}" apply -f "${MANIFESTS}/test/42-resource-client.yaml" 2>&1 | indent
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
wait_ready agents resource-client
wait_ready nhi    policy-probe-authorized
if [ "${READY}" -eq 1 ]; then
  pass "resource, test caller and policy writer all Ready"
else
  printf '\n\033[31m================ RESOURCE VERIFY: FAIL ================\033[0m\n'
  exit 1
fi

CLIENT_POD=$("${KUBECTL[@]}" get pods -n agents -l app=resource-client \
  -o jsonpath='{.items[0].metadata.name}')
WRITER_POD=$("${KUBECTL[@]}" get pods -n nhi -l probe=authorized \
  -o jsonpath='{.items[0].metadata.name}')
RESOURCE_POD=$("${KUBECTL[@]}" get pods -n nhi -l app=resource \
  -o jsonpath='{.items[0].metadata.name}')
echo "    | caller=${CLIENT_POD}  writer=${WRITER_POD}  resource=${RESOURCE_POD}"

# ---------------------------------------------------------------------------
step "Test caller obtains a JWT-SVID addressed to the resource"
JWT_JSON=$("${KUBECTL[@]}" exec -n agents "${CLIENT_POD}" -c svid -- \
  /opt/spire/bin/spire-agent api fetch jwt \
  -audience "${AUDIENCE}" -socketPath /run/spire/sockets/agent.sock \
  -output json 2>&1)
JWT=$(echo "${JWT_JSON}" | jq -r '..|.svid? // empty' 2>/dev/null | head -1)
JWT_SUB=$(echo "${JWT_JSON}" | jq -r '..|.spiffe_id? // empty' 2>/dev/null | head -1)
if [ -z "${JWT}" ]; then
  echo "${JWT_JSON}" | indent
  fail "could not obtain a JWT-SVID for audience ${AUDIENCE}"
  printf '\n\033[31m================ RESOURCE VERIFY: FAIL ================\033[0m\n'
  exit 1
fi
echo "    | subject  : ${JWT_SUB}"
echo "    | audience : ${AUDIENCE}"
echo "    | claims   : $(echo "${JWT}" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq -c . 2>/dev/null)"
if [ "${JWT_SUB}" = "${CALLER_ID}" ]; then
  pass "caller holds a valid JWT-SVID for ${CALLER_ID}"
else
  fail "JWT-SVID subject is '${JWT_SUB}', expected '${CALLER_ID}'"
fi

# call <method> <path> [extra curl args...] -> "<status>|<body>"
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
# identity OPA's system.authz lets write Rego.
opa_write() {
  local method="$1" id="$2" data="${3:-}"
  local args=(-sS --max-time 15 -o /dev/null -w '%{http_code}'
    --cacert /run/spiffe/bundle.pem
    --cert /run/spiffe/svid.pem --key /run/spiffe/svid_key.pem
    -X "${method}" "${OPA_URL}/v1/policies/${id}")
  if [ -n "${data}" ]; then
    args+=(--data-binary "${data}")
  fi
  "${KUBECTL[@]}" exec -n nhi "${WRITER_POD}" -c probe -- curl "${args[@]}" 2>&1 | tr -d '\n'
}

# Show the resource's audit events for the request just made: a negative
# result must evidence the denial AND the audit event.
show_audit() {
  local n="${1:-1}"
  echo "    | audit event(s):"
  "${KUBECTL[@]}" logs -n nhi "${RESOURCE_POD}" -c resource --tail=40 2>/dev/null \
    | grep '^{' | tail -n "${n}" | jq -c . 2>/dev/null | sed 's/^/    |   /'
}

# ---------------------------------------------------------------------------
# Clear the ENTIRE grant namespace, not just this script's own policy ID.
#
# This is not defensive boilerplate — it is load-bearing. "Default deny" is a
# claim about a state, and the assertion is only meaningful if that state
# actually holds. A grant left behind by an earlier run, a manual experiment or
# an interrupted verify-policy run would make the first check pass or fail for reasons
# having nothing to do with the code under test. That happened during
# development: a leftover grant made /datasets/A return 200 with no policy
# loaded, which looks exactly like a broken default-deny.
#
# Only ids under nhi_grants_* are touched. The base containment rule and
# system.authz are not addressable by this identity at all.
step "Clearing the grant namespace so 'no policy' genuinely means no policy"
EXISTING=$("${KUBECTL[@]}" exec -n nhi "${WRITER_POD}" -c probe -- \
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
REMAINING=$("${KUBECTL[@]}" exec -n nhi "${WRITER_POD}" -c probe -- \
  curl -sS --max-time 15 \
  --cacert /run/spiffe/bundle.pem \
  --cert /run/spiffe/svid.pem --key /run/spiffe/svid_key.pem \
  "${OPA_URL}/v1/policies" 2>/dev/null \
  | jq -r '.result[]?.id // empty' 2>/dev/null | grep -c '^nhi_grants_' || true)
if [ "${REMAINING}" = "0" ]; then
  pass "grant namespace is empty — the next check tests default deny, not stale state"
else
  fail "${REMAINING} grant module(s) still loaded; the default-deny check would be meaningless"
fi

step "CHECK A — valid SVID, no policy: request is DENIED (default deny)"
R=$(call GET /datasets/A)
echo "    | GET /datasets/A -> ${R}"
if [ "${R%%|*}" = "403" ]; then
  pass "authenticated caller with no grant is denied (HTTP 403)"
else
  fail "expected 403 for an authenticated caller with no policy, got '${R%%|*}'"
fi
show_audit 1

# ---------------------------------------------------------------------------
step "Loading a hand-written Rego grant for ${CALLER_ID} (dataset A only)"
# Written by hand here, deliberately: the policy engine generates exactly this
# shape, so this test pins the contract independently of the generator.
GRANT="package nhi.grants.resource_verify

spiffe_id := \"${CALLER_ID}\"

# Dataset A only. B is left ungranted on purpose — that asymmetry is what the
# checks below measure.
scopes := [\"resource:read:datasetA\"]

# Far future: this test is about scope containment, not expiry. The experiments test the
# TTL path by moving input.now instead.
expires_at := 99999999999
"
echo "${GRANT}" | indent
CODE=$(opa_write PUT "${GRANT_POLICY_ID}" "${GRANT}")
echo "    | PUT /v1/policies/${GRANT_POLICY_ID} -> HTTP ${CODE}"
if [ "${CODE}" = "200" ]; then
  pass "grant loaded by svc/policy-engine over mTLS"
else
  fail "could not load the grant (HTTP ${CODE})"
fi

# ---------------------------------------------------------------------------
step "CHECK B — the SAME pod with the SAME token can now read dataset A"
R=$(call GET /datasets/A)
echo "    | GET /datasets/A -> ${R}"
if [ "${R%%|*}" = "200" ] && echo "${R}" | grep -q '"dataset"'; then
  pass "granted scope allows the read (HTTP 200, dataset payload returned)"
else
  fail "expected 200 with a dataset payload, got '${R}'"
fi
show_audit 1

# ---------------------------------------------------------------------------
step "CHECK C — but is still denied dataset B"
R=$(call GET /datasets/B)
echo "    | GET /datasets/B -> ${R}"
if [ "${R%%|*}" = "403" ]; then
  pass "ungranted scope is denied (HTTP 403) — the grant attenuates, it does not open"
else
  fail "expected 403 for the ungranted dataset B, got '${R%%|*}'"
fi
show_audit 1

# ---------------------------------------------------------------------------
# Cheap and directly load-bearing for the vending service and experiments, so
# asserted here rather than discovered downstream.
step "Write scope is independent of read scope (POST /jobs still denied)"
R=$(call POST /jobs -H 'Content-Type: application/json' --data-binary '{}')
echo "    | POST /jobs -> ${R}"
if [ "${R%%|*}" = "403" ]; then
  pass "resource:write:jobs is not implied by resource:read:datasetA"
else
  fail "expected 403 for POST /jobs, got '${R%%|*}'"
fi

step "Unauthenticated request is refused before any policy is consulted"
UNAUTH=$("${KUBECTL[@]}" exec -n agents "${CLIENT_POD}" -c client -- \
  curl -sS --max-time 15 -o /dev/null -w '%{http_code}' \
  "${RESOURCE_URL}/datasets/A" 2>&1 | tr -d '\n')
echo "    | GET /datasets/A with no Authorization header -> HTTP ${UNAUTH}"
if [ "${UNAUTH}" = "401" ]; then
  pass "no credential is a 401, distinct from the 403 a valid credential without a grant gets"
else
  fail "expected 401 for an unauthenticated request, got '${UNAUTH}'"
fi

step "A JWT-SVID minted for a different audience is refused"
WRONG_JWT=$("${KUBECTL[@]}" exec -n agents "${CLIENT_POD}" -c svid -- \
  /opt/spire/bin/spire-agent api fetch jwt \
  -audience "spiffe://${TRUST_DOMAIN}/svc/vending-service" \
  -socketPath /run/spire/sockets/agent.sock -output json 2>&1 \
  | jq -r '..|.svid? // empty' 2>/dev/null | head -1)
WRONG=$("${KUBECTL[@]}" exec -n agents "${CLIENT_POD}" -c client -- \
  curl -sS --max-time 15 -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer ${WRONG_JWT}" \
  "${RESOURCE_URL}/datasets/A" 2>&1 | tr -d '\n')
echo "    | same identity, audience=svc/vending-service -> HTTP ${WRONG}"
if [ "${WRONG}" = "401" ]; then
  pass "audience binding holds: a token valid elsewhere in the trust domain is refused here"
else
  fail "expected 401 for a wrong-audience token, got '${WRONG}'"
fi
show_audit 1

# ---------------------------------------------------------------------------
step "Removing the grant restores the default deny (the policy engine's disposal path)"
CODE=$(opa_write DELETE "${GRANT_POLICY_ID}")
echo "    | DELETE /v1/policies/${GRANT_POLICY_ID} -> HTTP ${CODE}"
R=$(call GET /datasets/A)
echo "    | GET /datasets/A -> ${R}"
if [ "${R%%|*}" = "403" ]; then
  pass "access ends when the grant is removed — the credential alone confers nothing"
else
  fail "expected 403 after removing the grant, got '${R%%|*}'"
fi

# ---------------------------------------------------------------------------
printf '\n'
if [ "${FAILURES}" -eq 0 ]; then
  printf '\033[32m================ RESOURCE VERIFY: PASS (%d checks) ================\033[0m\n' "${CHECK_NO}"
  printf 'One pod, one JWT-SVID, three outcomes decided entirely by policy:\n'
  printf '  no grant      -> 403 on /datasets/A\n'
  printf '  grant loaded  -> 200 on /datasets/A, 403 on /datasets/B\n'
  printf '  grant removed -> 403 on /datasets/A again\n'
  exit 0
else
  printf '\033[31m================ RESOURCE VERIFY: FAIL (%d failed) ================\033[0m\n' "${FAILURES}"
  exit 1
fi
