#!/usr/bin/env bash
# Consistent-disposal verification for `make verify-disposal`.
#
#   Revocation, TTL and creation-limit rules, proved on a live cluster against
#   the real vending service, policy engine, OPA, SPIRE and resource:
#
#     cascade        P revokes C: G (C's child) is denied on its next request,
#                    and when the DELETE returns G's SPIRE entry and grant are
#                    gone and G's row is revoked with the ancestor named. Run
#                    three times.
#     lineage rule   With ONLY C's grant removed from OPA (by the policy
#                    engine's own identity, straight to OPA), G's grant is still
#                    there and G is still denied.
#     TTL            G asked for longer than C has left: it gets C's expiry, its
#                    SPIRE entry and X.509-SVID do not outlive it, and the vend
#                    event says so. With no DELETE, G is denied once C expires,
#                    and the reaper disposes both. ttl_seconds=21601 is a 400.
#     depth limit    G may not vend (403, audited, no state, nonce unspent);
#                    with MAX_DELEGATION_DEPTH=3 the same manifest succeeds.
#     child cap      With MAX_LIVE_CHILDREN=2 a third child is refused, a
#                    disposal frees a slot, and ten concurrent vends by one
#                    parent produce exactly two children.
#     crashed parent A parent that is force-killed after vending never runs any
#                    cleanup: its child keeps working until expires_at, is then
#                    denied, and is later reaped.
#     OPA reach      A pod labelled app=vending-service cannot open a TCP
#                    connection to OPA.
#     verification   A JWT-SVID for another audience is a 401 at the resource,
#                    audited. A revoked G whose JWT-SVID still verifies gets a
#                    403 from OPA (the grant decides, not the token).
#
# The chain P -> C -> G is played by the experiment fixtures (cmd/parentsim in
# three pods): experiments-parent is the root parent exp-root, experiments-child
# plays C, experiments-grandchild plays G. Nothing is mocked. Every nonce and
# child path carries a per-run id, because the vending service remembers them.
#
# The script restarts the vending service to change MAX_DELEGATION_DEPTH and
# MAX_LIVE_CHILDREN, and puts the shipped values back on exit (also on failure).
set -uo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-nhi-lab}"
KUBECTX="${KUBECTX:-kind-${CLUSTER_NAME}}"
TRUST_DOMAIN="${TRUST_DOMAIN:-lab.local}"

RESOURCE_URL="http://resource.nhi.svc.cluster.local:8080"
RESOURCE_AUD="spiffe://${TRUST_DOMAIN}/svc/resource"
VENDING_AUD="spiffe://${TRUST_DOMAIN}/svc/vending-service"
OPA_URL="https://opa.opa.svc.cluster.local:8181"

PARENT_ID="spiffe://${TRUST_DOMAIN}/agent/parent/exp-root"

# The limits the vending-service manifest ships with.
DEFAULT_DEPTH=2
DEFAULT_CHILDREN=8

RUN_ID="$(date -u +%Y%m%d%H%M%S)"
CASCADE_RUNS=3

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS="${SCRIPT_DIR}/../manifests"
REPO_SRC="$(cd "${SCRIPT_DIR}/../.." && pwd)"

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
die() {
  printf '\n\033[31m================ DISPOSAL VERIFY: FAIL ================\033[0m\n'
  exit 1
}

# check <description> <command...> : pass when the command succeeds.
check() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "${desc}"; else fail "${desc}"; fi
}

WORKDIR="$(mktemp -d)"
LIMITS_CHANGED=0

restore_limits() {
  [ "${LIMITS_CHANGED}" -eq 1 ] || return 0
  echo ">> restoring MAX_DELEGATION_DEPTH=${DEFAULT_DEPTH} MAX_LIVE_CHILDREN=${DEFAULT_CHILDREN}"
  "${KUBECTL[@]}" -n nhi set env deployment/vending-service \
    "MAX_DELEGATION_DEPTH=${DEFAULT_DEPTH}" "MAX_LIVE_CHILDREN=${DEFAULT_CHILDREN}" >/dev/null 2>&1 || true
  "${KUBECTL[@]}" rollout status deployment/vending-service -n nhi --timeout=120s >/dev/null 2>&1 || true
  LIMITS_CHANGED=0
}

# The probe carries the vending service's label, so until it is gone it also
# matches `kubectl logs -l app=vending-service` (which then fails for the other
# pods' container name). Delete it and wait, rather than leave it terminating.
drop_vs_probe() {
  "${KUBECTL[@]}" delete pod -n nhi disposal-vs-probe --ignore-not-found --grace-period=0 --force --wait=true >/dev/null 2>&1 || true
}

cleanup() {
  restore_limits
  drop_vs_probe
  "${KUBECTL[@]}" delete -f "${MANIFESTS}/test/41-policy-probe.yaml" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

# --- generic helpers (the same ones the other verify scripts use) ------------

running_pod() {
  local ns="$1" selector="$2"
  "${KUBECTL[@]}" get pods -n "${ns}" -l "${selector}" --field-selector=status.phase=Running \
    --sort-by=.metadata.creationTimestamp -o jsonpath='{.items}' \
    | jq -r '[.[] | select(.metadata.deletionTimestamp == null)] | if length > 0 then .[-1].metadata.name else empty end'
}

# split_status_body <combined output from parentsim> -> "<http-code>|<json body>"
split_status_body() {
  local out="$1" code body
  code=$(printf '%s\n' "${out}" | grep -o 'HTTP [0-9]*' | tail -1 | awk '{print $2}')
  body=$(printf '%s\n' "${out}" | grep -v '^HTTP ' | tr '\n' ' ')
  echo "${code:-000}|${body}"
}

# json_line <combined output> -> the first line that is a JSON object
json_line() { printf '%s\n' "$1" | grep '^{' | head -1; }

spire_entry_count() {
  local out status
  out=$("${KUBECTL[@]}" exec -n spire spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server entry show -spiffeID "$1" 2>&1)
  status=$?
  if [ "${status}" -ne 0 ]; then echo "ERR"; return; fi
  printf '%s\n' "${out}" | grep -c '^Entry ID' || true
}

# spire_entry_field <spiffe-id> <label> -> the value after "<label> :" of the entry
spire_entry_field() {
  "${KUBECTL[@]}" exec -n spire spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server entry show -spiffeID "$1" 2>/dev/null \
    | awk -F' : ' -v want="$2" '{ k=$1; gsub(/[ \t]+$/, "", k); if (k == want) { print $2; exit } }'
}

# --- pods and parentsim ---------------------------------------------------------

P_POD=""; C_POD=""; G_POD=""
resolve_pods() {
  P_POD=$(running_pod agents app=experiments-parent)
  C_POD=$(running_pod agents app=experiments-child)
  G_POD=$(running_pod agents app=experiments-grandchild)
}

# psim <pod> <parentsim args...> : stdout+stderr of the parentsim run in that pod
psim() {
  local pod="$1"; shift
  "${KUBECTL[@]}" exec -n agents "${pod}" -c parentsim -- /parentsim "$@" 2>&1
}

# vend <pod> <hint> <nonce> <selector-sa> <ttl> <scopes> -> sets V_OUT V_CODE V_BODY
vend() {
  local pod="$1" hint="$2" nonce="$3" sa="$4" ttl="$5" scopes="$6"
  V_OUT=$(psim "${pod}" vend -child-path-hint="${hint}" -nonce="${nonce}" \
    -scopes="${scopes}" -task-context="disposal verify" \
    -selectors="k8s:ns=agents,k8s:sa=${sa}" -ttl="${ttl}")
  local r; r=$(split_status_body "${V_OUT}")
  V_CODE="${r%%|*}"; V_BODY=$(json_line "${V_OUT}")
}

# vend_ok: as vend, but retries a transient policy-engine connect delay (HTTP 502
# + "context deadline exceeded" after a pod restart) on a fresh nonce, because the
# nonce is recorded before the policy engine is called.
vend_ok() {
  local pod="$1" hint="$2" nonce="$3" attempt n
  shift 3
  for attempt in 1 2 3 4; do
    n="${nonce}"; [ "${attempt}" -gt 1 ] && n="${nonce}_r${attempt}"
    vend "${pod}" "${hint}" "${n}" "$@"
    if [ "${V_CODE}" = "502" ] && printf '%s' "${V_OUT}" | grep -qi 'context deadline exceeded'; then
      sleep 3; continue
    fi
    break
  done
  LAST_NONCE="${n}"
}

x509_id() { psim "$1" x509-check | grep -o '"spiffe_id":"[^"]*"' | head -1 | cut -d'"' -f4; }

# wait_svid <pod> <spiffe-id> : the pod holds an X.509-SVID for exactly that ID
wait_svid() {
  local pod="$1" want="$2" got
  for _ in $(seq 1 30); do
    got=$(x509_id "${pod}")
    [ "${got}" = "${want}" ] && return 0
    sleep 2
  done
  return 1
}

# wait_no_identity <pod> : the agent no longer issues the pod any identity, so the
# next run starts with the pod holding exactly one SVID.
wait_no_identity() {
  local pod="$1"
  for _ in $(seq 1 45); do
    psim "${pod}" x509-check | grep -q '"error"' && return 0
    sleep 2
  done
  return 1
}

fetch_jwt() { psim "$1" fetch-jwt -call-audience="$2"; }

# bearer_code <pod> <path> <token> [method] -> HTTP status of the resource call
bearer_code() {
  local out; out=$(psim "$1" bearer-call -call-url="${RESOURCE_URL}$2" -bearer-token="$3" ${4:+-call-method="$4"})
  split_status_body "${out}" | cut -d'|' -f1
}

# --- audit readers -----------------------------------------------------------------

vending_pod() {
  "${KUBECTL[@]}" get pods -n nhi -l app=vending-service -o json \
    | jq -r '[.items[]
        | select(.metadata.deletionTimestamp == null)
        | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))
        | .metadata.name][0] // empty'
}

# audit_of <component> : every JSON audit line the component's pod has written
audit_of() {
  case "$1" in
    vending)  "${KUBECTL[@]}" logs -n nhi "$(vending_pod)" -c vending-service --tail=-1 2>/dev/null | grep '^{' ;;
    policy)   "${KUBECTL[@]}" logs -n nhi -l app=policy-engine -c policy-engine --tail=-1 2>/dev/null | grep '^{' ;;
    resource) "${KUBECTL[@]}" logs -n nhi -l app=resource -c resource --tail=-1 2>/dev/null | grep '^{' ;;
  esac
}

# ev <component> <jq select expression> -> matching events, one per line (compact)
ev() { audit_of "$1" | jq -c "select($2)" 2>/dev/null; }

# wait_ev <component> <jq select expression> -> first match, polling up to 90 s
wait_ev() {
  local line
  for _ in $(seq 1 45); do
    line=$(ev "$1" "$2" | head -1)
    if [ -n "${line}" ]; then printf '%s\n' "${line}"; return 0; fi
    sleep 2
  done
  return 1
}

get_delegation() { # <chain_id> -> JSON body of GET /delegations/{id}, as the root parent
  json_line "$(psim "${P_POD}" get -chain-id="$1")"
}

# --- limits ----------------------------------------------------------------------------

set_limits() { # <depth> <children>
  LIMITS_CHANGED=1
  "${KUBECTL[@]}" -n nhi set env deployment/vending-service \
    "MAX_DELEGATION_DEPTH=$1" "MAX_LIVE_CHILDREN=$2" >/dev/null 2>&1
  "${KUBECTL[@]}" rollout status deployment/vending-service -n nhi --timeout=150s >/dev/null 2>&1
}

live_limits() {
  "${KUBECTL[@]}" get deployment vending-service -n nhi -o json \
    | jq -r '.spec.template.spec.containers[0].env
             | map(select(.name == "MAX_DELEGATION_DEPTH" or .name == "MAX_LIVE_CHILDREN") | "\(.name)=\(.value)")
             | sort | join(" ")'
}

# --- chain construction ----------------------------------------------------------------

# make_chain <tag> [c_ttl] -> sets C_CHAIN C_ID C_EXP G_CHAIN G_ID G_EXP G_ISSUED
# P vends C onto the child pod, then C vends G onto the grandchild pod.
make_chain() {
  local tag="$1" c_ttl="${2:-600}"
  C_ID="${PARENT_ID}/child/dsp-c-${RUN_ID}-${tag}"
  G_ID="${C_ID}/child/dsp-g-${RUN_ID}-${tag}"
  vend_ok "${P_POD}" "child/dsp-c-${RUN_ID}-${tag}" "dsp_c_${RUN_ID}_${tag}" nhi-exp-child "${c_ttl}" \
    "resource:read:datasetA,resource:read:datasetB"
  if [ "${V_CODE}" != "201" ]; then echo "C vend failed: ${V_CODE} ${V_OUT}" >&2; return 1; fi
  C_CHAIN=$(jq -r .chain_id <<<"${V_BODY}"); C_EXP=$(jq -r .expires_at <<<"${V_BODY}")
  wait_svid "${C_POD}" "${C_ID}" || { echo "C pod never obtained ${C_ID}" >&2; return 1; }
  vend_ok "${C_POD}" "child/dsp-g-${RUN_ID}-${tag}" "dsp_g_${RUN_ID}_${tag}" nhi-exp-grandchild 600 \
    "resource:read:datasetA"
  if [ "${V_CODE}" != "201" ]; then echo "G vend failed: ${V_CODE} ${V_OUT}" >&2; return 1; fi
  G_CHAIN=$(jq -r .chain_id <<<"${V_BODY}"); G_EXP=$(jq -r .expires_at <<<"${V_BODY}")
  G_ISSUED=$(jq -r .issued_at <<<"${V_BODY}")
  wait_svid "${G_POD}" "${G_ID}" || { echo "G pod never obtained ${G_ID}" >&2; return 1; }
}

# drain_chain: dispose C (the cascade takes G) if still live, then wait until both
# fixtures pods hold no identity, ready for the next chain.
drain_chain() {
  psim "${P_POD}" dispose -chain-id="${C_CHAIN}" >/dev/null 2>&1 || true
  wait_no_identity "${C_POD}"; wait_no_identity "${G_POD}"
}

# ===============================================================================
step "Preconditions — fixtures, shipped limits and the lineage rule in the opa-authz ConfigMap"
resolve_pods
if [ -z "${P_POD}" ] || [ -z "${C_POD}" ] || [ -z "${G_POD}" ] || [ -z "$(vending_pod)" ]; then
  fail "fixtures not Ready (parent='${P_POD}' child='${C_POD}' grandchild='${G_POD}' vending='$(vending_pod)')"
  die
fi
echo "    | P=${P_POD}  C=${C_POD}  G=${G_POD}  vending-service=$(vending_pod)  run id ${RUN_ID}"
LIMITS="$(live_limits)"
if [ "${LIMITS}" = "MAX_DELEGATION_DEPTH=${DEFAULT_DEPTH} MAX_LIVE_CHILDREN=${DEFAULT_CHILDREN}" ]; then
  pass "the vending service runs the shipped limits (${LIMITS})"
else
  fail "unexpected limits at start: ${LIMITS}"
  die
fi
# A stale OPA would silently run the old containment rule and fail every check
# below for a confusing reason; say so up front.
if "${KUBECTL[@]}" get configmap opa-authz -n opa -o jsonpath='{.data.resource\.rego}' | grep -q 'ancestors_live'; then
  pass "the opa-authz ConfigMap carries the lineage-aware grant rule"
else
  fail "the opa-authz ConfigMap has no lineage rule: re-run 'make opa-up' and restart OPA"
  die
fi

step "Deploying the policy probes (the policy-engine probe writes to OPA directly; the other is an L3-admitted client)"
"${KUBECTL[@]}" apply -f "${MANIFESTS}/test/41-policy-probe.yaml" 2>&1 | indent
READY=1
for d in policy-probe-authorized policy-probe-unauthorized; do
  "${KUBECTL[@]}" rollout status "deployment/${d}" -n nhi --timeout=150s >/dev/null 2>&1 || { fail "not Ready: nhi/${d}"; READY=0; }
done
[ "${READY}" -eq 1 ] || die
AUTH_PROBE=$(running_pod nhi probe=authorized)
UNAUTH_PROBE=$(running_pod nhi probe=unauthorized)
pass "probes Ready (${AUTH_PROBE}, ${UNAUTH_PROBE})"

# opa_as_policy_engine <method> <policy-id> -> HTTP status
opa_as_policy_engine() {
  "${KUBECTL[@]}" exec -n nhi "${AUTH_PROBE}" -c probe -- curl -sS --max-time 15 -o /dev/null -w '%{http_code}' \
    --cacert /run/spiffe/bundle.pem --cert /run/spiffe/svid.pem --key /run/spiffe/svid_key.pem \
    -X "$1" "${OPA_URL}/v1/policies/$2" 2>&1 | tr -d '\n'
}

# ===============================================================================
# The cascade, three times
for run in $(seq 1 "${CASCADE_RUNS}"); do
  step "CASCADE ${run}/${CASCADE_RUNS} — P revokes C; G is denied, and its entry, grant and row are gone when the DELETE returns"
  if ! make_chain "k${run}"; then fail "could not build P -> C -> G"; die; fi
  echo "    | C=${C_ID} (${C_CHAIN})"
  echo "    | G=${G_ID} (${G_CHAIN})"

  OUT=$(psim "${G_POD}" call -call-audience="${RESOURCE_AUD}" -call-url="${RESOURCE_URL}/datasets/A")
  CODE=$(split_status_body "${OUT}" | cut -d'|' -f1)
  if [ "${CODE}" = "200" ]; then pass "before the revoke, G reads datasetA: 200"; else fail "G got '${CODE}' before the revoke"; fi
  G_JWT=$(fetch_jwt "${G_POD}" "${RESOURCE_AUD}")
  if printf '%s' "${G_JWT}" | grep -qE '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'; then
    pass "captured G's JWT-SVID (replayed after the revoke, so the denial cannot be 'G could not get a token')"
  else
    fail "could not capture G's JWT-SVID: ${G_JWT}"
  fi

  OUT=$(psim "${P_POD}" dispose -chain-id="${C_CHAIN}")
  CODE=$(split_status_body "${OUT}" | cut -d'|' -f1)
  if [ "${CODE}" = "200" ]; then pass "P: DELETE /delegations/${C_CHAIN} -> 200"; else fail "DELETE returned '${CODE}': ${OUT}"; fi

  # State at the moment the DELETE returned: read immediately, no waiting.
  check "C's SPIRE entry is gone" test "$(spire_entry_count "${C_ID}")" = "0"
  check "G's SPIRE entry is gone" test "$(spire_entry_count "${G_ID}")" = "0"
  REC=$(get_delegation "${G_CHAIN}")
  echo "    | G's row: ${REC}"
  if jq -e --arg r "ancestor_revoked: ${C_CHAIN}" '.revoked_at != null and .revocation_reason == $r' <<<"${REC}" >/dev/null 2>&1; then
    pass "G's row is revoked, reason 'ancestor_revoked: ${C_CHAIN}'"
  else
    fail "G's row is not revoked by the cascade"
  fi
  PE=$(ev policy ".stage==\"dispose\" and .chain_id==\"${G_CHAIN}\" and .outcome==\"allow\"" | head -1)
  if [ -n "${PE}" ]; then pass "the policy engine removed G's grant module (dispose/allow for ${G_CHAIN})"; else fail "no policy-engine dispose event for G"; fi
  GP=$(opa_as_policy_engine GET "nhi_grants_${G_CHAIN}")
  if [ "${GP}" = "404" ]; then pass "OPA no longer holds G's grant module (GET -> 404)"; else fail "OPA still answers '${GP}' for G's grant module"; fi

  # G's next request.
  CODE=$(bearer_code "${G_POD}" /datasets/A "${G_JWT}")
  if [ "${CODE}" = "403" ]; then pass "G's next request is denied: 403 (its JWT-SVID has not expired)"; else fail "expected 403 for G, got '${CODE}'"; fi
  RD=$(wait_ev resource ".stage==\"operate\" and .outcome==\"deny\" and .actor_spiffe_id==\"${G_ID}\" and .detail.path==\"/datasets/A\"" )
  echo "    | resource audit event: ${RD}"
  if jq -e '.detail.reason == "policy denied" and .detail.policy_decision == false' <<<"${RD}" >/dev/null 2>&1; then
    pass "the resource audited G's deny: 'policy denied', policy_decision=false (the token verified; OPA said no)"
  else
    fail "no resource deny audit event for G"
  fi

  # G's dispose event names C's chain and is attributed to the revoking parent.
  VD=$(wait_ev vending ".stage==\"dispose\" and .chain_id==\"${G_CHAIN}\" and .outcome==\"allow\"")
  echo "    | vending audit event: ${VD}"
  if jq -e --arg r "ancestor_revoked: ${C_CHAIN}" --arg a "${PARENT_ID}" '.detail.reason == $r and .actor_spiffe_id == $a' <<<"${VD}" >/dev/null 2>&1; then
    pass "G's dispose event names C's chain_id and is attributed to P"
  else
    fail "G's dispose event does not carry 'ancestor_revoked: ${C_CHAIN}' / actor ${PARENT_ID}"
  fi
  wait_no_identity "${C_POD}"; wait_no_identity "${G_POD}"
done

# ===============================================================================
step "LINEAGE RULE ON ITS OWN — only C's grant module is removed from OPA; G's is still there and G is denied"
if ! make_chain "lin"; then fail "could not build P -> C -> G"; die; fi
G_JWT=$(fetch_jwt "${G_POD}" "${RESOURCE_AUD}")
CODE=$(bearer_code "${G_POD}" /datasets/A "${G_JWT}")
if [ "${CODE}" = "200" ]; then pass "G reads datasetA while both grants are live: 200"; else fail "expected 200, got '${CODE}'"; fi
R=$(opa_as_policy_engine DELETE "nhi_grants_${C_CHAIN}")
if [ "${R}" = "200" ]; then pass "removed ONLY C's grant module straight from OPA (DELETE nhi_grants_${C_CHAIN} -> 200)"; else fail "OPA DELETE returned '${R}'"; fi
R=$(opa_as_policy_engine GET "nhi_grants_${G_CHAIN}")
if [ "${R}" = "200" ]; then pass "G's grant module is still in OPA (GET -> 200)"; else fail "G's grant module is not in OPA ('${R}')"; fi
R=$(opa_as_policy_engine GET "nhi_grants_${C_CHAIN}")
if [ "${R}" = "404" ]; then pass "C's grant module is gone (GET -> 404)"; else fail "C's grant module is still in OPA ('${R}')"; fi
CODE=$(bearer_code "${G_POD}" /datasets/A "${G_JWT}")
if [ "${CODE}" = "403" ]; then pass "G is denied (403) although its own grant is live: the lineage is broken"; else fail "expected 403, got '${CODE}'"; fi
if [ -n "$(ev resource ".outcome==\"deny\" and .actor_spiffe_id==\"${G_ID}\" and .detail.reason==\"policy denied\"" | head -1)" ]; then
  pass "the resource audited the deny for G"
else
  fail "no resource deny event for G"
fi
drain_chain

# ===============================================================================
step "TTL ATTENUATION — G asks for 600 s from a C that has under 80 s left"
C_TTL=80
if ! make_chain "ttl" "${C_TTL}"; then fail "could not build P -> C -> G"; die; fi
echo "    | C expires_at=${C_EXP}  G expires_at=${G_EXP}  G issued_at=${G_ISSUED}"
if [ "${V_CODE}" = "201" ]; then pass "G's vend (ttl_seconds=600) succeeded: 201"; else fail "vend returned ${V_CODE}"; fi
if [ "${G_EXP}" = "${C_EXP}" ]; then pass "G's expires_at equals C's (${C_EXP})"; else fail "G expires_at ${G_EXP} != C expires_at ${C_EXP}"; fi

EXP_TEXT=$(spire_entry_field "${G_ID}" "Expiration time")
EXP_EPOCH=""
[ -n "${EXP_TEXT}" ] && EXP_EPOCH=$(date -u -d "$(sed 's/ +0000 UTC$//; s/ UTC$//' <<<"${EXP_TEXT}")" +%s 2>/dev/null || echo "")
X509_TTL=$(spire_entry_field "${G_ID}" "X509-SVID TTL")
echo "    | G's SPIRE entry: expiry='${EXP_TEXT}' (${EXP_EPOCH}) X509-SVID TTL='${X509_TTL}'"
if [ -n "${EXP_EPOCH}" ] && [ "${EXP_EPOCH}" -le "${C_EXP}" ]; then pass "G's SPIRE entry expiry (${EXP_EPOCH}) does not exceed C's (${C_EXP})"; else fail "G's entry expiry '${EXP_TEXT}' exceeds C's"; fi
if [ -n "${X509_TTL}" ] && [ "${X509_TTL}" -le $((C_EXP - G_ISSUED)) ]; then
  pass "G's X.509-SVID TTL (${X509_TTL} s) does not exceed expires_at - issued_at ($((C_EXP - G_ISSUED)) s), far below the requested 600"
else
  fail "G's X.509-SVID TTL '${X509_TTL}' is not <= $((C_EXP - G_ISSUED))"
fi
VE=$(ev vending ".stage==\"vend\" and .chain_id==\"${G_CHAIN}\" and .outcome==\"allow\"" | head -1)
echo "    | vend event: ${VE}"
if jq -e --argjson e "${C_EXP}" '(.detail.reason | test("requested 600")) and .detail.expires_at == $e' <<<"${VE}" >/dev/null 2>&1; then
  pass "the vend event records the requested 600 s in detail.reason and the effective expires_at"
else
  fail "the vend event does not record the shortening"
fi
PE=$(ev policy ".stage==\"vend\" and .chain_id==\"${G_CHAIN}\" and .outcome==\"allow\"" | head -1)
if jq -e '.detail.reason | test("requested 600")' <<<"${PE}" >/dev/null 2>&1; then
  pass "the policy engine's own vend event says the TTL was shortened"
else
  fail "the policy engine's vend event does not record the shortening: ${PE}"
fi

G_JWT=$(fetch_jwt "${G_POD}" "${RESOURCE_AUD}")
CODE=$(bearer_code "${G_POD}" /datasets/A "${G_JWT}")
if [ "${CODE}" = "200" ]; then pass "G reads datasetA before C expires: 200"; else fail "expected 200 before expiry, got '${CODE}'"; fi

NOW=$(date +%s)
WAIT=$((C_EXP - NOW + 2))
[ "${WAIT}" -gt 0 ] && { echo "    | no DELETE is sent; waiting ${WAIT}s for C's expires_at to pass"; sleep "${WAIT}"; }
CODE=$(bearer_code "${G_POD}" /datasets/A "${G_JWT}")
if [ "${CODE}" = "403" ]; then pass "G is denied (403) once C's expiry has passed, with no DELETE"; else fail "expected 403 after expiry, got '${CODE}'"; fi
if [ -n "$(ev resource ".outcome==\"deny\" and .actor_spiffe_id==\"${G_ID}\" and .detail.reason==\"policy denied\"" | head -1)" ]; then
  pass "the resource audited the post-expiry deny for G"
else
  fail "no resource deny event for G after expiry"
fi
for who in "C:${C_CHAIN}" "G:${G_CHAIN}"; do
  RV=$(wait_ev vending ".stage==\"dispose\" and .chain_id==\"${who#*:}\" and .outcome==\"allow\" and .detail.reason==\"ttl_expired\"")
  if jq -e --arg a "${VENDING_AUD}" '.actor_spiffe_id == $a' <<<"${RV}" >/dev/null 2>&1; then
    pass "the reaper disposed ${who%%:*} (ttl_expired, attributed to the vending service)"
  else
    fail "the reaper did not dispose ${who%%:*} (${who#*:})"
  fi
done
wait_no_identity "${C_POD}"; wait_no_identity "${G_POD}"

OUT=$(psim "${P_POD}" vend -child-path-hint="child/dsp-toolong-${RUN_ID}" -nonce="dsp_toolong_${RUN_ID}" \
  -scopes=resource:read:datasetA -selectors="k8s:ns=agents,k8s:sa=nhi-dsp-nopod" -ttl=21601)
R=$(split_status_body "${OUT}")
if [ "${R%%|*}" = "400" ]; then pass "ttl_seconds=21601 is refused: 400"; else fail "expected 400 for ttl_seconds=21601, got '${R%%|*}'"; fi
if wait_ev vending ".stage==\"attest\" and .outcome==\"deny\" and (.detail.reason|test(\"ttl_seconds 21601 exceeds the maximum of 21600\"))" >/dev/null; then
  pass "the refusal is audited (attest/deny: ttl_seconds 21601 exceeds the maximum of 21600)"
else
  fail "no audit event for the 21601 refusal"
fi

# ===============================================================================
step "DEPTH LIMIT (default ${DEFAULT_DEPTH}) — G may not vend"
if ! make_chain "dep"; then fail "could not build P -> C -> G"; die; fi
GG_ID="${G_ID}/child/dsp-x-${RUN_ID}"
GG_HINT="child/dsp-x-${RUN_ID}"
GG_NONCE="dsp_x_${RUN_ID}"
vend "${G_POD}" "${GG_HINT}" "${GG_NONCE}" nhi-dsp-nopod 300 resource:read:datasetA
echo "${V_OUT}" | indent
if [ "${V_CODE}" = "403" ]; then pass "G's vend is refused: 403"; else fail "expected 403, got '${V_CODE}'"; fi
DENY=$(wait_ev vending ".stage==\"vend\" and .outcome==\"deny\" and .actor_spiffe_id==\"${G_ID}\" and (.detail.reason|test(\"MAX_DELEGATION_DEPTH is ${DEFAULT_DEPTH}\"))")
if [ -n "${DENY}" ]; then pass "audited vend/deny naming the limit: $(jq -r .detail.reason <<<"${DENY}")"; else fail "no vend deny event naming MAX_DELEGATION_DEPTH"; fi
check "no SPIRE entry was created for the depth-3 child" test "$(spire_entry_count "${GG_ID}")" = "0"
if [ -z "$(ev vending ".stage==\"vend\" and .outcome==\"allow\" and .detail.child_spiffe_id==\"${GG_ID}\"" | head -1)" ]; then
  pass "no vend/allow event, so no grant and no row exist for it"
else
  fail "a vend/allow event exists for ${GG_ID}"
fi

step "DEPTH LIMIT variant — MAX_DELEGATION_DEPTH=3: the very same manifest (same nonce) now succeeds"
if set_limits 3 "${DEFAULT_CHILDREN}"; then pass "vending service restarted with MAX_DELEGATION_DEPTH=3"; else fail "rollout failed"; die; fi
resolve_pods
vend_ok "${G_POD}" "${GG_HINT}" "${GG_NONCE}" nhi-dsp-nopod 300 resource:read:datasetA
echo "${V_OUT}" | indent
if [ "${V_CODE}" = "201" ] && [ "${LAST_NONCE}" = "${GG_NONCE}" ]; then
  pass "201 with the nonce that the refused vend carried: it was never recorded"
else
  fail "expected 201 with the original nonce, got '${V_CODE}' (nonce ${LAST_NONCE})"
fi
GG_CHAIN=$(jq -r .chain_id <<<"${V_BODY}")
check "a SPIRE entry now exists for the depth-3 child" test "$(spire_entry_count "${GG_ID}")" = "1"
# The cascade is not limited to one level: revoking C takes G and the depth-3 child.
OUT=$(psim "${P_POD}" dispose -chain-id="${C_CHAIN}")
if [ "$(split_status_body "${OUT}" | cut -d'|' -f1)" = "200" ]; then pass "P revokes C"; else fail "DELETE of C failed: ${OUT}"; fi
REC=$(get_delegation "${GG_CHAIN}")
if jq -e --arg r "ancestor_revoked: ${C_CHAIN}" '.revoked_at != null and .revocation_reason == $r' <<<"${REC}" >/dev/null 2>&1; then
  pass "the depth-3 child was revoked by the cascade, three levels below C's parent"
else
  fail "the depth-3 child was not revoked: ${REC}"
fi
check "its SPIRE entry is gone" test "$(spire_entry_count "${GG_ID}")" = "0"
wait_no_identity "${C_POD}"; wait_no_identity "${G_POD}"

# ===============================================================================
step "CHILD CAP — MAX_LIVE_CHILDREN=2 (depth back to ${DEFAULT_DEPTH})"
if set_limits "${DEFAULT_DEPTH}" 2; then pass "vending service restarted: $(live_limits)"; else fail "rollout failed"; die; fi
resolve_pods
KIDS=()
for i in 1 2; do
  vend_ok "${P_POD}" "child/dsp-k${i}-${RUN_ID}" "dsp_k${i}_${RUN_ID}" nhi-dsp-nopod 600 resource:read:datasetA
  if [ "${V_CODE}" = "201" ]; then KIDS+=("$(jq -r .chain_id <<<"${V_BODY}")"); pass "child ${i} vended: 201"; else fail "child ${i}: ${V_CODE} ${V_OUT}"; fi
done
THIRD_ID="${PARENT_ID}/child/dsp-k3-${RUN_ID}"
vend "${P_POD}" "child/dsp-k3-${RUN_ID}" "dsp_k3_${RUN_ID}" nhi-dsp-nopod 600 resource:read:datasetA
echo "${V_OUT}" | indent
if [ "${V_CODE}" = "403" ]; then pass "P's third live child is refused: 403"; else fail "expected 403, got '${V_CODE}'"; fi
DENY=$(wait_ev vending ".stage==\"vend\" and .outcome==\"deny\" and .actor_spiffe_id==\"${PARENT_ID}\" and (.detail.reason|test(\"MAX_LIVE_CHILDREN is 2\"))")
if [ -n "${DENY}" ]; then pass "audited vend/deny naming the limit: $(jq -r .detail.reason <<<"${DENY}")"; else fail "no vend deny event naming MAX_LIVE_CHILDREN"; fi
check "no SPIRE entry exists for the refused child" test "$(spire_entry_count "${THIRD_ID}")" = "0"

OUT=$(psim "${P_POD}" dispose -chain-id="${KIDS[0]}")
if [ "$(split_status_body "${OUT}" | cut -d'|' -f1)" = "200" ]; then pass "P disposes one child"; else fail "dispose failed: ${OUT}"; fi
vend "${P_POD}" "child/dsp-k3-${RUN_ID}" "dsp_k3_${RUN_ID}" nhi-dsp-nopod 600 resource:read:datasetA
if [ "${V_CODE}" = "201" ]; then
  pass "the refused manifest (same nonce) now succeeds: 201, so the refusal left no nonce behind"
  KIDS+=("$(jq -r .chain_id <<<"${V_BODY}")")
else
  fail "after a disposal the vend returned '${V_CODE}': ${V_OUT}"
fi
for k in "${KIDS[@]:1}"; do psim "${P_POD}" dispose -chain-id="${k}" >/dev/null 2>&1; done

step "CHILD CAP — ten concurrent vends by one parent yield exactly two children"
mkdir -p "${WORKDIR}/conc"
for i in $(seq 1 10); do
  ( psim "${P_POD}" vend -child-path-hint="child/dsp-par${i}-${RUN_ID}" -nonce="dsp_par${i}_${RUN_ID}" \
      -scopes=resource:read:datasetA -task-context="disposal verify concurrent" \
      -selectors="k8s:ns=agents,k8s:sa=nhi-dsp-nopod" -ttl=600 >"${WORKDIR}/conc/${i}.out" ) &
done
wait
CREATED=0; REFUSED=0; OTHER=0; PAR_CHAINS=()
for i in $(seq 1 10); do
  CODE=$(split_status_body "$(cat "${WORKDIR}/conc/${i}.out")" | cut -d'|' -f1)
  case "${CODE}" in
    201) CREATED=$((CREATED + 1)); PAR_CHAINS+=("$(jq -r .chain_id <<<"$(json_line "$(cat "${WORKDIR}/conc/${i}.out")")")") ;;
    403) REFUSED=$((REFUSED + 1)) ;;
    *)   OTHER=$((OTHER + 1)); echo "    | unexpected: $(cat "${WORKDIR}/conc/${i}.out")" ;;
  esac
done
echo "    | 201: ${CREATED}  403: ${REFUSED}  other: ${OTHER}"
if [ "${CREATED}" = "2" ] && [ "${REFUSED}" = "8" ] && [ "${OTHER}" = "0" ]; then
  pass "exactly 2 children created, 8 refused with 403"
else
  fail "expected 2 created and 8 refused"
fi
N=0
for i in $(seq 1 10); do
  N=$((N + $(spire_entry_count "${PARENT_ID}/child/dsp-par${i}-${RUN_ID}")))
done
if [ "${N}" = "2" ]; then pass "exactly 2 SPIRE entries exist for the ten children"; else fail "${N} SPIRE entries exist for the ten children"; fi
for k in "${PAR_CHAINS[@]}"; do psim "${P_POD}" dispose -chain-id="${k}" >/dev/null 2>&1; done

step "Restoring the shipped limits"
restore_limits
LIMITS="$(live_limits)"
if [ "${LIMITS}" = "MAX_DELEGATION_DEPTH=${DEFAULT_DEPTH} MAX_LIVE_CHILDREN=${DEFAULT_CHILDREN}" ]; then
  pass "limits are back to ${LIMITS}"
else
  fail "limits not restored: ${LIMITS}"
fi
resolve_pods

# ===============================================================================
step "CRASHED PARENT — P is force-killed after vending, so no cleanup ever runs; its child is denied at expires_at and then reaped"
X_TTL=50
X_ID="${PARENT_ID}/child/dsp-crash-${RUN_ID}"
vend_ok "${P_POD}" "child/dsp-crash-${RUN_ID}" "dsp_crash_${RUN_ID}" nhi-exp-child "${X_TTL}" resource:read:datasetA
if [ "${V_CODE}" = "201" ]; then
  X_CHAIN=$(jq -r .chain_id <<<"${V_BODY}"); X_EXP=$(jq -r .expires_at <<<"${V_BODY}")
  pass "P vends a ${X_TTL} s child: ${X_CHAIN}, expires_at=${X_EXP}"
else
  fail "vend failed: ${V_CODE} ${V_OUT}"; die
fi
wait_svid "${C_POD}" "${X_ID}" || fail "the child pod never obtained ${X_ID}"
X_JWT=$(fetch_jwt "${C_POD}" "${RESOURCE_AUD}")
OLD_P="${P_POD}"
"${KUBECTL[@]}" delete pod -n agents "${OLD_P}" --grace-period=0 --force 2>&1 | indent
# A replacement pod must exist, differ from the dead one and hold its own
# registration before the next step can use P again.
for _ in $(seq 1 60); do
  resolve_pods
  [ -n "${P_POD}" ] && [ "${P_POD}" != "${OLD_P}" ] && break
  sleep 2
done
"${KUBECTL[@]}" rollout status deployment/experiments-parent -n agents --timeout=150s >/dev/null 2>&1
if [ -n "${P_POD}" ] && [ "${P_POD}" != "${OLD_P}" ]; then pass "P was force-deleted with no grace period, so no hook or handler ran (pod ${OLD_P}); ${P_POD} replaced it"; else fail "P was not replaced"; fi
CODE=$(bearer_code "${C_POD}" /datasets/A "${X_JWT}")
if [ "${CODE}" = "200" ]; then pass "with its parent dead, the child still works before expires_at: 200 (nothing was cleaned up)"; else fail "expected 200 before expiry, got '${CODE}'"; fi
check "the child's row is still unrevoked" jq -e '.revoked_at == null' <<<"$(get_delegation "${X_CHAIN}")"
WAIT=$(( X_EXP - $(date +%s) + 2 ))
[ "${WAIT}" -gt 0 ] && { echo "    | waiting ${WAIT}s for expires_at"; sleep "${WAIT}"; }
CODE=$(bearer_code "${C_POD}" /datasets/A "${X_JWT}")
if [ "${CODE}" = "403" ]; then pass "denied at expires_at: 403"; else fail "expected 403 after expires_at, got '${CODE}'"; fi
RV=$(wait_ev vending ".stage==\"dispose\" and .chain_id==\"${X_CHAIN}\" and .outcome==\"allow\" and .detail.reason==\"ttl_expired\"")
if jq -e --arg a "${VENDING_AUD}" '.actor_spiffe_id == $a' <<<"${RV}" >/dev/null 2>&1; then
  pass "later reaped: dispose / ttl_expired, attributed to the vending service"
else
  fail "the reaper never disposed ${X_CHAIN}"
fi
check "its SPIRE entry is gone" test "$(spire_entry_count "${X_ID}")" = "0"
check "its row is revoked" jq -e '.revoked_at != null and .revocation_reason == "ttl_expired"' <<<"$(get_delegation "${X_CHAIN}")"
wait_no_identity "${C_POD}"

# ===============================================================================
step "OPA REACH — a pod labelled app=vending-service cannot open a TCP connection to OPA"
# Not Ready on purpose (the always-failing readiness probe), so the vending-service
# Service never routes real traffic to it.
"${KUBECTL[@]}" apply -f - <<'EOF' >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: disposal-vs-probe
  namespace: nhi
  labels:
    app: vending-service
    disposal-probe: "true"
spec:
  containers:
    - name: probe
      image: curlimages/curl:8.18.0
      imagePullPolicy: IfNotPresent
      command: ["sleep", "infinity"]
      readinessProbe:
        exec:
          command: ["false"]
      securityContext:
        runAsUser: 101
        runAsGroup: 102
        runAsNonRoot: true
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
EOF
for _ in $(seq 1 45); do
  [ "$("${KUBECTL[@]}" get pod -n nhi disposal-vs-probe -o jsonpath='{.status.phase}' 2>/dev/null)" = "Running" ] && break
  sleep 2
done
if [ "$("${KUBECTL[@]}" get pod -n nhi disposal-vs-probe -o jsonpath='{.status.phase}' 2>/dev/null)" = "Running" ]; then
  pass "probe pod disposal-vs-probe (app=vending-service) is Running"
else
  fail "probe pod did not start"
fi
# curl exit codes: 28 = connect timed out (packets dropped), 7 = refused,
# 35/56 = TCP connected and the TLS handshake then failed (no client certificate).
"${KUBECTL[@]}" exec -n nhi disposal-vs-probe -c probe -- curl -sk --connect-timeout 6 -o /dev/null "${OPA_URL}/health" >/dev/null 2>&1
RC=$?
if [ "${RC}" = "28" ]; then pass "app=vending-service -> OPA:8181: connection timed out (curl exit 28), the NetworkPolicy drops it"; else fail "curl exit ${RC}: expected 28 (connect timeout)"; fi
UNAUTH_PROBE=$(running_pod nhi probe=unauthorized)
"${KUBECTL[@]}" exec -n nhi "${UNAUTH_PROBE}" -c probe -- curl -sk --connect-timeout 6 -o /dev/null "${OPA_URL}/health" >/dev/null 2>&1
RC=$?
if [ "${RC}" = "35" ] || [ "${RC}" = "56" ] || [ "${RC}" = "0" ]; then
  pass "control: app=policy-probe -> OPA:8181 connects (curl exit ${RC}; the TLS handshake is what stops it), so the timeout above is the NetworkPolicy"
else
  fail "control probe: curl exit ${RC}, expected the TCP connection to succeed"
fi
drop_vs_probe
if ! grep -q '_ = childID' "${REPO_SRC}/vending-service/internal/manifest/manifest.go"; then
  pass "the '_ = childID' line is gone from manifest.go"
else
  fail "'_ = childID' is still in manifest.go"
fi

# ===============================================================================
step "SVID VERIFICATION AT THE RESOURCE — a JWT-SVID for another audience is a 401, audited"
if ! make_chain "aud"; then fail "could not build P -> C -> G"; die; fi
T0=$(date -u -d '2 seconds ago' +%Y-%m-%dT%H:%M:%S)
OUT=$(psim "${G_POD}" call -call-audience="${VENDING_AUD}" -call-url="${RESOURCE_URL}/datasets/A")
R=$(split_status_body "${OUT}")
if [ "${R%%|*}" = "401" ]; then pass "a JWT-SVID minted for the vending service's audience: 401 at the resource"; else fail "expected 401, got '${R%%|*}'"; fi
RD=$(wait_ev resource ".outcome==\"deny\" and .actor_spiffe_id==\"\" and .timestamp>=\"${T0}\" and (.detail.reason|test(\"JWT-SVID validation failed\"))")
echo "    | resource audit event: ${RD}"
if jq -e '.detail.policy_decision == null' <<<"${RD}" >/dev/null 2>&1 && [ -n "${RD}" ]; then
  pass "audited deny with no policy decision (OPA was not consulted)"
else
  fail "no 401 audit event"
fi
G_JWT=$(fetch_jwt "${G_POD}" "${RESOURCE_AUD}")
psim "${P_POD}" dispose -chain-id="${C_CHAIN}" >/dev/null 2>&1
CODE=$(bearer_code "${G_POD}" /datasets/A "${G_JWT}")
if [ "${CODE}" = "403" ]; then pass "revoked G, still holding a JWT-SVID that verifies: 403 from OPA, not 401"; else fail "expected 403, got '${CODE}'"; fi
wait_no_identity "${C_POD}"; wait_no_identity "${G_POD}"

# ===============================================================================
printf '\n'
if [ "${FAILURES}" -eq 0 ]; then
  printf '\033[32m================ DISPOSAL VERIFY: PASS (%d steps) ================\033[0m\n' "${CHECK_NO}"
  printf '  cascade        -> revoking C denied G, removed its entry and grant, revoked its row (%d runs)\n' "${CASCADE_RUNS}"
  printf '  lineage rule   -> removing only C'"'"'s grant denied G with its own grant still in OPA\n'
  printf '  TTL            -> G got C'"'"'s expiry; denied at it with no DELETE; reaped; 21601 -> 400\n'
  printf '  depth          -> G'"'"'s vend refused (403, no state, nonce unspent); allowed with MAX_DELEGATION_DEPTH=3\n'
  printf '  child cap      -> 3rd child refused; slot freed by disposal; 10 concurrent vends -> exactly 2\n'
  printf '  crashed parent -> child denied at expires_at, then reaped\n'
  printf '  OPA reach      -> app=vending-service cannot connect to OPA\n'
  printf '  verification   -> wrong audience 401; revoked G with a valid token 403\n'
  exit 0
else
  printf '\033[31m================ DISPOSAL VERIFY: FAIL (%d failed) ================\033[0m\n' "${FAILURES}"
  exit 1
fi
