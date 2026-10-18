#!/usr/bin/env bash
# Durability verification for `make verify-persistence`.
#
#   The vending service keeps its delegation records and replay nonces in a
#   SQLite file, and a second copy of its audit events in audit.jsonl, both on
#   the `vending-data` PersistentVolumeClaim. This script proves, on a live
#   cluster, that a pod restart loses none of it:
#
#     1. delegation survives:   a child C vended before the restart can still be
#                               read (GET) and disposed (DELETE) by its parent
#                               afterwards; its SPIRE entry and OPA grant go,
#                               and C's next request to the resource is denied
#                               (403) with a matching resource audit event.
#     2. the reaper survives:   a second child S with a 40 s TTL, vended before
#                               the restart, is reaped by the NEW pod once it
#                               expires (dispose / ttl_expired, original chain_id).
#     3. the audit trail        `make vending-audit` shows the pre-restart vend
#        survives:              events and the post-restart dispose events for
#                               both chain_ids, every line valid JSON with
#                               exactly the audit schema's top-level keys.
#     4. replay protection      a nonce used before the restart is refused
#        survives:              (409) after it.
#
# Same shape as verify-vending.sh: real pods with real SPIRE identities play
# the roles (fixtures from manifests/test/), parentsim is driven through
# `kubectl exec`, and nothing is mocked. The only addition is the restart
# itself, `kubectl delete pod -l app=vending-service`. Every nonce and child
# path carries a per-run id, so the script can be run repeatedly against the
# same cluster: the store it tests is exactly the kind that remembers.
#
# Roles:
#   vending-test-parent  spiffe://lab.local/agent/parent/vend-verify (registered;
#                        bootstrap scopes: resource:read:datasetA only)
#   vending-test-child   UNREGISTERED at apply time; becomes C when the vending
#                        service creates C's entry (selector sa=nhi-test-vend-child)
#   S                    is given a selector set that matches no pod, so the child
#                        pod never holds two SVIDs and its identity stays C's.
set -uo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-nhi-lab}"
KUBECTX="${KUBECTX:-kind-${CLUSTER_NAME}}"
TRUST_DOMAIN="${TRUST_DOMAIN:-lab.local}"

RESOURCE_URL="http://resource.nhi.svc.cluster.local:8080"
RESOURCE_AUD="spiffe://${TRUST_DOMAIN}/svc/resource"
VENDING_ID="spiffe://${TRUST_DOMAIN}/svc/vending-service"

PARENT_ID="spiffe://${TRUST_DOMAIN}/agent/parent/vend-verify"

# Computed once, at script start. The nonce table is durable, so nonces (and
# child paths) from an earlier run are still remembered; the suffix keeps this
# run's inputs new. The replay check resubmits a nonce THIS run used.
RUN_ID="$(date -u +%Y%m%d%H%M%S)"
LONG_PATH_HINT="child/persist-long-${RUN_ID}"
SHORT_PATH_HINT="child/persist-short-${RUN_ID}"
LONG_CHILD_ID="${PARENT_ID}/${LONG_PATH_HINT}"
SHORT_CHILD_ID="${PARENT_ID}/${SHORT_PATH_HINT}"
LONG_TTL=600
# S must still be live when the pod is deleted, so the old pod's reaper cannot
# reap it: the TTL has to outlast the pre-restart steps (about half a minute on
# a slow run) plus up to one reaper interval (15s). The wait below covers the TTL
# plus one more reaper interval for the NEW pod, with ample margin.
SHORT_TTL=40
SHORT_WAIT_SECONDS=120

# The audit schema's top-level keys, sorted (jq's `keys` sorts).
AUDIT_KEYS='["actor_spiffe_id","chain_id","detail","outcome","stage","timestamp"]'

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
die() {
  printf '\n\033[31m================ PERSISTENCE VERIFY: FAIL ================\033[0m\n'
  exit 1
}

cleanup() {
  "${KUBECTL[@]}" delete -f "${MANIFESTS}/test/44-vending-test-parent.yaml" \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "${KUBECTL[@]}" delete -f "${MANIFESTS}/test/45-vending-test-child.yaml" \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

running_pod() {
  local ns="$1" selector="$2"
  "${KUBECTL[@]}" get pods -n "${ns}" -l "${selector}" --field-selector=status.phase=Running \
    --sort-by=.metadata.creationTimestamp -o jsonpath='{.items}' \
    | jq -r 'if length > 0 then .[-1].metadata.name else empty end'
}

# split_status_body <combined output from parentsim> -> "<http-code>|<json body>"
# (see verify-vending.sh: parentsim prints "HTTP <code>" on stderr and the body on stdout)
split_status_body() {
  local out="$1" code body
  code=$(printf '%s\n' "${out}" | grep -o 'HTTP [0-9]*' | tail -1 | awk '{print $2}')
  body=$(printf '%s\n' "${out}" | grep -v '^HTTP ' | tr '\n' ' ')
  echo "${code:-000}|${body}"
}

# spire_entry_count <spiffe-id> -> number of registration entries, or ERR if the
# exec itself failed (a failed exec must never be read as "zero entries").
spire_entry_count() {
  local out status
  out=$("${KUBECTL[@]}" exec -n spire spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server entry show -spiffeID "$1" 2>&1)
  status=$?
  if [ "${status}" -ne 0 ]; then
    echo "ERR"
    return
  fi
  printf '%s\n' "${out}" | grep -c '^Entry ID' || true
}

# ready_vending_pod -> name of a Ready vending-service pod that is not terminating
ready_vending_pod() {
  "${KUBECTL[@]}" get pods -n nhi -l app=vending-service -o json \
    | jq -r '[.items[]
        | select(.metadata.deletionTimestamp == null)
        | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))
        | .metadata.name][0] // empty'
}

# vend_retrying <exec-fn-name> <nonce-prefix> [parentsim vend flags, no -nonce]
# Same transient-only retry as verify-vending.sh (HTTP 502 + "context deadline
# exceeded" from a freshly rolled policy-engine pod), each retry on a fresh
# nonce because the nonce is recorded before the policy engine is called.
# LAST_VEND_NONCE is the nonce that actually succeeded (needed for the replay).
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

# raw_events <log text> <chain_id> <stage> -> the event lines, byte for byte
raw_events() {
  printf '%s\n' "$1" | grep '^{' | grep -F "\"chain_id\":\"$2\"" | grep -F "\"stage\":\"$3\"" || true
}

# ---------------------------------------------------------------------------
step "Deploying the test fixtures (parent, attacker, child)"
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
wait_ready agents vending-test-child
if [ "${READY}" -eq 1 ]; then
  pass "vending service, test parent and test child Ready (run id ${RUN_ID})"
else
  die
fi

PARENT_POD=$(running_pod agents app=vending-test-parent)
CHILD_POD=$(running_pod agents app=vending-test-child)
OLD_POD=$(ready_vending_pod)
echo "    | parent=${PARENT_POD}  child=${CHILD_POD}  vending-service=${OLD_POD}"

# The bootstrap ConfigMap loads once at policy-engine startup; roll it so the
# running pod is guaranteed to know the vend-verify parent (as verify-vending.sh does).
step "Rolling the policy engine so it picks up the vend-verify bootstrap parent"
"${KUBECTL[@]}" apply -f "${MANIFESTS}/policy-engine/" >/dev/null 2>&1
"${KUBECTL[@]}" rollout restart deployment/policy-engine -n nhi >/dev/null 2>&1
if "${KUBECTL[@]}" rollout status deployment/policy-engine -n nhi --timeout=120s >/dev/null 2>&1; then
  pass "policy engine restarted"
else
  fail "policy engine did not roll out"
fi

exec_p() { "${KUBECTL[@]}" exec -n agents "${PARENT_POD}" -c parentsim -- "$@" 2>&1; }
exec_c() { "${KUBECTL[@]}" exec -n agents "${CHILD_POD}" -c parentsim -- "$@" 2>&1; }

# ---------------------------------------------------------------------------
step "BEFORE THE RESTART — the parent vends a long-TTL child C (${LONG_TTL}s) and a short-TTL child S (${SHORT_TTL}s)"
vend_retrying exec_p "persist_long_nonce_${RUN_ID}" \
  -child-path-hint="${LONG_PATH_HINT}" \
  -scopes=resource:read:datasetA \
  -task-context="persistence verify — long-TTL child C" \
  -selectors="k8s:ns=agents,k8s:sa=nhi-test-vend-child" \
  -ttl="${LONG_TTL}"
OUT="${LAST_VEND_OUT}"
LONG_NONCE="${LAST_VEND_NONCE}"
echo "${OUT}" | indent
R=$(split_status_body "${OUT}")
CODE="${R%%|*}"; BODY="${R#*|}"
if [ "${CODE}" = "201" ]; then
  C_CHAIN=$(echo "${BODY}" | jq -r '.chain_id')
  pass "C vended: chain_id=${C_CHAIN} child=${LONG_CHILD_ID} (HTTP 201)"
else
  fail "expected 201 for C, got '${CODE}': ${BODY}"
  die
fi

# Distinct selectors (no pod has this service account): the child pod must hold
# exactly one SVID, C's, so the JWT it fetches later is unambiguously C's.
vend_retrying exec_p "persist_short_nonce_${RUN_ID}" \
  -child-path-hint="${SHORT_PATH_HINT}" \
  -scopes=resource:read:datasetA \
  -task-context="persistence verify — short-TTL child S" \
  -selectors="k8s:ns=agents,k8s:sa=nhi-test-persist-short" \
  -ttl="${SHORT_TTL}"
OUT="${LAST_VEND_OUT}"
echo "${OUT}" | indent
R=$(split_status_body "${OUT}")
CODE="${R%%|*}"; BODY="${R#*|}"
if [ "${CODE}" = "201" ]; then
  S_CHAIN=$(echo "${BODY}" | jq -r '.chain_id')
  pass "S vended: chain_id=${S_CHAIN} child=${SHORT_CHILD_ID} (HTTP 201, expires in ${SHORT_TTL}s)"
else
  fail "expected 201 for S, got '${CODE}': ${BODY}"
  die
fi
SHORT_VENDED_AT=$(date +%s)

# ---------------------------------------------------------------------------
step "BEFORE THE RESTART — C is on record, has its SPIRE entry, and works"
OUT=$(exec_p /parentsim get -chain-id="${C_CHAIN}")
echo "${OUT}" | indent
R=$(split_status_body "${OUT}")
CODE="${R%%|*}"; PRE_BODY="${R#*|}"
if [ "${CODE}" = "200" ]; then
  pass "GET /delegations/${C_CHAIN} -> 200 on the original pod"
else
  fail "expected 200 from GET before the restart, got '${CODE}': ${PRE_BODY}"
  die
fi
PRE_RECORD=$(echo "${PRE_BODY}" | jq -cS .)

for who in "C:${LONG_CHILD_ID}" "S:${SHORT_CHILD_ID}"; do
  N=$(spire_entry_count "${who#*:}")
  if [ "${N}" = "1" ]; then
    pass "${who%%:*} has a SPIRE registration entry"
  else
    fail "expected one SPIRE entry for ${who%%:*} (${who#*:}), got '${N}'"
  fi
done

GOT=""
for attempt in $(seq 1 15); do
  OUT=$(exec_c /parentsim x509-check)
  GOT=$(echo "${OUT}" | grep -o '"spiffe_id":"[^"]*"' | head -1 | cut -d'"' -f4)
  [ "${GOT}" = "${LONG_CHILD_ID}" ] && break
  sleep 2
done
if [ "${GOT}" = "${LONG_CHILD_ID}" ]; then
  pass "the child pod holds an X.509-SVID for C (${LONG_CHILD_ID})"
else
  fail "the child pod never obtained an SVID for C; last output: ${OUT}"
fi
OUT=$(exec_c /parentsim call -call-audience="${RESOURCE_AUD}" -call-url="${RESOURCE_URL}/datasets/A")
R=$(split_status_body "${OUT}")
if [ "${R%%|*}" = "200" ]; then
  pass "C reads datasetA before the restart: 200"
else
  fail "expected 200 for C on datasetA before the restart, got '${R%%|*}': ${R#*|}"
fi

# What the original pod wrote to stdout for C's and S's vend. After the restart
# these lines exist nowhere but the audit file; they are compared against it later.
OLD_LOG=$("${KUBECTL[@]}" logs -n nhi "${OLD_POD}" -c vending-service 2>/dev/null)
C_VEND_LINE=$(raw_events "${OLD_LOG}" "${C_CHAIN}" vend | grep -F '"outcome":"allow"' | head -1)
S_VEND_LINE=$(raw_events "${OLD_LOG}" "${S_CHAIN}" vend | grep -F '"outcome":"allow"' | head -1)
if [ -n "${C_VEND_LINE}" ] && [ -n "${S_VEND_LINE}" ]; then
  pass "the original pod's stdout carries the vend events for C and S"
  echo "${C_VEND_LINE}" | indent
  echo "${S_VEND_LINE}" | indent
else
  fail "could not find both vend events in ${OLD_POD}'s stdout"
fi

# ---------------------------------------------------------------------------
step "THE RESTART — kubectl delete pod -l app=vending-service, then wait for the new pod to be Ready"
RESTART_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "    | deleting ${OLD_POD} at ${RESTART_AT}"
"${KUBECTL[@]}" delete pod -n nhi -l app=vending-service --wait=true --timeout=120s 2>&1 | indent
NEW_POD=""
for attempt in $(seq 1 60); do
  CAND=$(ready_vending_pod)
  if [ -n "${CAND}" ] && [ "${CAND}" != "${OLD_POD}" ]; then
    NEW_POD="${CAND}"
    break
  fi
  sleep 2
done
if [ -n "${NEW_POD}" ]; then
  RESTARTED_AFTER=$(( $(date +%s) - SHORT_VENDED_AT ))
  pass "new pod ${NEW_POD} is Ready (the old pod ${OLD_POD} is gone); ${RESTARTED_AFTER}s after S was vended"
else
  fail "no new Ready vending-service pod within 120s"
  "${KUBECTL[@]}" get pods -n nhi -l app=vending-service -o wide 2>&1 | indent
  die
fi
if ! "${KUBECTL[@]}" get pod -n nhi "${OLD_POD}" >/dev/null 2>&1; then
  pass "${OLD_POD} no longer exists, so everything below is answered by ${NEW_POD}"
else
  fail "${OLD_POD} still exists"
fi

# ---------------------------------------------------------------------------
step "DELEGATION SURVIVES — GET /delegations/{C} on the new pod returns the pre-restart record"
OUT=$(exec_p /parentsim get -chain-id="${C_CHAIN}")
echo "${OUT}" | indent
R=$(split_status_body "${OUT}")
CODE="${R%%|*}"; POST_BODY="${R#*|}"
if [ "${CODE}" = "200" ]; then
  pass "GET -> 200 (before persistence this was 404 for every pre-restart delegation)"
else
  fail "expected 200 from GET after the restart, got '${CODE}': ${POST_BODY}"
fi
POST_RECORD=$(echo "${POST_BODY}" | jq -cS . 2>/dev/null)
if [ -n "${POST_RECORD}" ] && [ "${POST_RECORD}" = "${PRE_RECORD}" ]; then
  pass "the record is identical to the one read before the restart"
  echo "    | ${POST_RECORD}"
else
  fail "record changed across the restart
    | before: ${PRE_RECORD}
    | after:  ${POST_RECORD}"
fi

# ---------------------------------------------------------------------------
step "REPLAY PROTECTION SURVIVES — resubmitting C's pre-restart nonce is refused"
OUT=$(exec_p /parentsim vend \
  -child-path-hint="${LONG_PATH_HINT}" \
  -scopes=resource:read:datasetA \
  -task-context="persistence verify — long-TTL child C" \
  -selectors="k8s:ns=agents,k8s:sa=nhi-test-vend-child" \
  -ttl="${LONG_TTL}" -nonce="${LONG_NONCE}")
echo "${OUT}" | indent
R=$(split_status_body "${OUT}")
CODE="${R%%|*}"; BODY="${R#*|}"
if [ "${CODE}" = "409" ]; then
  pass "replayed pre-restart nonce refused with HTTP 409"
else
  fail "expected 409 for a nonce used before the restart, got '${CODE}': ${BODY}"
fi
# kubectl appends "command terminated with exit code 2" after parentsim's
# non-2xx exit, so read the reason from the JSON line alone.
REASON=$(printf '%s\n' "${OUT}" | grep '^{' | jq -r '.reason' 2>/dev/null)
if [ "${REASON}" = "nonce has already been used for this parent (replay refused)" ]; then
  pass "response reason is: ${REASON}"
else
  fail "expected the reason 'nonce has already been used for this parent (replay refused)', got: ${REASON:-${BODY}}"
fi
AUDIT_LINE=$("${KUBECTL[@]}" logs -n nhi "${NEW_POD}" -c vending-service --tail=5 2>/dev/null | grep '^{' | tail -1)
echo "    | audit event: ${AUDIT_LINE}"
if echo "${AUDIT_LINE}" | jq -e '.stage == "attest" and .outcome == "deny" and (.detail.reason == "nonce has already been used for this parent (replay refused)")' >/dev/null 2>&1; then
  pass "deny audit event names the replay"
else
  fail "expected a deny audit event citing nonce reuse, got: ${AUDIT_LINE}"
fi

# ---------------------------------------------------------------------------
step "DISPOSAL WORKS — C still has access, then its parent DELETEs it through the new pod"
N=$(spire_entry_count "${LONG_CHILD_ID}")
if [ "${N}" = "1" ]; then
  pass "C's SPIRE entry survived the restart"
else
  fail "expected one SPIRE entry for C after the restart, got '${N}'"
fi
OUT=$(exec_c /parentsim call -call-audience="${RESOURCE_AUD}" -call-url="${RESOURCE_URL}/datasets/A")
R=$(split_status_body "${OUT}")
if [ "${R%%|*}" = "200" ]; then
  pass "C reads datasetA after the restart: 200 (its OPA grant survived too)"
else
  fail "expected 200 for C on datasetA after the restart, got '${R%%|*}': ${R#*|}"
fi
# Captured now so the denial after disposal is provably a policy decision (the
# grant is gone), not "C could not obtain a token".
CAPTURED_JWT=$(exec_c /parentsim fetch-jwt -call-audience="${RESOURCE_AUD}")
if printf '%s' "${CAPTURED_JWT}" | grep -qE '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'; then
  pass "captured a JWT-SVID for C, to be replayed after disposal"
else
  fail "could not capture a JWT-SVID for C: ${CAPTURED_JWT}"
fi

OUT=$(exec_p /parentsim dispose -chain-id="${C_CHAIN}")
echo "${OUT}" | indent
R=$(split_status_body "${OUT}")
if [ "${R%%|*}" = "200" ]; then
  pass "DELETE /delegations/${C_CHAIN} by the parent -> 200"
else
  fail "expected 200 from DELETE after the restart, got '${R%%|*}': ${R#*|}"
fi
N=$(spire_entry_count "${LONG_CHILD_ID}")
if [ "${N}" = "0" ]; then
  pass "C's SPIRE registration entry is gone"
else
  fail "C's SPIRE entry still exists after disposal (count '${N}')"
fi
PE_LINE=$("${KUBECTL[@]}" logs -n nhi -l app=policy-engine -c policy-engine --tail=100 2>/dev/null \
  | grep '^{' | jq -c "select(.chain_id==\"${C_CHAIN}\" and .stage==\"dispose\")" 2>/dev/null | tail -1)
echo "    | policy engine audit event: ${PE_LINE}"
if echo "${PE_LINE}" | jq -e '.outcome == "allow"' >/dev/null 2>&1; then
  pass "the policy engine removed C's OPA grant module (dispose / allow for its chain_id)"
else
  fail "no allowed dispose event from the policy engine for ${C_CHAIN}"
fi

OUT=$(exec_c /parentsim bearer-call -call-url="${RESOURCE_URL}/datasets/A" -bearer-token="${CAPTURED_JWT}")
echo "${OUT}" | indent
R=$(split_status_body "${OUT}")
if [ "${R%%|*}" = "403" ]; then
  pass "C's request to the resource is denied: 403"
else
  fail "expected 403 for C after disposal, got '${R%%|*}': ${R#*|}"
fi
RES_LINE=$("${KUBECTL[@]}" logs -n nhi -l app=resource -c resource --tail=100 2>/dev/null \
  | grep '^{' | jq -c "select(.actor_spiffe_id==\"${LONG_CHILD_ID}\" and .stage==\"operate\" and .outcome==\"deny\")" 2>/dev/null | tail -1)
echo "    | resource audit event: ${RES_LINE}"
if echo "${RES_LINE}" | jq -e '.detail.reason == "policy denied" and .detail.path == "/datasets/A"' >/dev/null 2>&1; then
  pass "the resource's deny audit event names C (policy denied on /datasets/A)"
else
  fail "no resource deny audit event for C on /datasets/A"
fi

# ---------------------------------------------------------------------------
step "THE REAPER SURVIVES — the new pod reaps S (ttl ${SHORT_TTL}s) once it expires, with S's original chain_id"
S_DISPOSE_LINE=""
for attempt in $(seq 1 $((SHORT_WAIT_SECONDS / 2))); do
  NEW_LOG=$("${KUBECTL[@]}" logs -n nhi "${NEW_POD}" -c vending-service 2>/dev/null)
  S_DISPOSE_LINE=$(raw_events "${NEW_LOG}" "${S_CHAIN}" dispose | grep -F '"outcome":"allow"' | head -1)
  [ -n "${S_DISPOSE_LINE}" ] && break
  sleep 2
done
echo "    | ${NEW_POD} audit event: ${S_DISPOSE_LINE:-<none within ${SHORT_WAIT_SECONDS}s>}"
if echo "${S_DISPOSE_LINE}" | jq -e ".stage == \"dispose\" and .chain_id == \"${S_CHAIN}\" and .detail.reason == \"ttl_expired\" and .actor_spiffe_id == \"${VENDING_ID}\"" >/dev/null 2>&1; then
  pass "the new pod emitted dispose / ttl_expired for S (${S_CHAIN}), attributed to the vending service itself"
else
  fail "no dispose / ttl_expired event for S from ${NEW_POD} within ${SHORT_WAIT_SECONDS}s"
fi
N=$(spire_entry_count "${SHORT_CHILD_ID}")
if [ "${N}" = "0" ]; then
  pass "S's SPIRE registration entry is gone"
else
  fail "S's SPIRE entry still exists after the reaper reported it (count '${N}')"
fi

# ---------------------------------------------------------------------------
step "THE AUDIT TRAIL SURVIVES — read audit.jsonl through the same reader as 'make vending-audit'"
TRAIL_FILE=$(mktemp)
if CLUSTER_NAME="${CLUSTER_NAME}" KUBECTX="${KUBECTX}" bash "${SCRIPT_DIR}/vending-audit.sh" >"${TRAIL_FILE}" 2>"${TRAIL_FILE}.err"; then
  TRAIL=$(cat "${TRAIL_FILE}")
  pass "reader pod printed the audit file ($(grep -c '' "${TRAIL_FILE}") lines), then was deleted"
else
  fail "vending-audit.sh failed: $(cat "${TRAIL_FILE}.err")"
  rm -f "${TRAIL_FILE}" "${TRAIL_FILE}.err"
  die
fi
rm -f "${TRAIL_FILE}" "${TRAIL_FILE}.err"
if "${KUBECTL[@]}" get pod -n nhi vending-audit-reader >/dev/null 2>&1; then
  fail "the reader pod still exists after the read"
else
  pass "no reader pod left behind"
fi

TOTAL=$(printf '%s\n' "${TRAIL}" | grep -c '')
VALID=$(printf '%s\n' "${TRAIL}" | jq -Rn --argjson want "${AUDIT_KEYS}" \
  '[inputs | try (fromjson | select(type == "object" and (keys == $want)) | 1) catch empty] | length')
if [ "${TOTAL}" -gt 0 ] && [ "${TOTAL}" = "${VALID}" ]; then
  pass "all ${TOTAL} lines parse as JSON with exactly the audit keys ${AUDIT_KEYS}"
else
  fail "${VALID:-0} of ${TOTAL} lines are JSON objects with exactly the audit keys"
fi

# Position of the first event matching chain/stage[/reason] in the file.
trail_idx() {
  printf '%s\n' "${TRAIL}" | jq -Rrn --arg c "$1" --arg s "$2" --arg r "${3:-}" \
    '[inputs | fromjson?] | to_entries
     | map(select(.value.chain_id == $c and .value.stage == $s and .value.outcome == "allow"
                  and ($r == "" or .value.detail.reason == $r)))
     | .[0].key // empty'
}

# check_trail <name> <chain_id> <dispose reason> <vend line the original pod wrote to stdout>
check_trail() {
  local name="$1" chain="$2" reason="$3" vend_line="$4" v d dispose_line new_log
  v=$(trail_idx "${chain}" vend)
  d=$(trail_idx "${chain}" dispose "${reason}")
  if [ -n "${v}" ] && [ -n "${d}" ] && [ "${v}" -lt "${d}" ]; then
    pass "${name} (${chain}): vend event (line $((v + 1))) precedes dispose / ${reason} (line $((d + 1)))"
  else
    fail "${name} (${chain}): expected a vend event followed by dispose / ${reason}; vend line '${v}', dispose line '${d}'"
  fi
  # The vend event was written by the ORIGINAL pod, which no longer exists: the
  # file is the only place it can still come from, and it must be the same line.
  if [ -n "${vend_line}" ] && printf '%s\n' "${TRAIL}" | grep -Fxq -- "${vend_line}"; then
    pass "${name}: the pre-restart vend event is in the file, byte-identical to what the original pod wrote to stdout"
  else
    fail "${name}: the original pod's vend line is missing from the audit file"
  fi
  new_log=$("${KUBECTL[@]}" logs -n nhi "${NEW_POD}" -c vending-service 2>/dev/null)
  if [ -z "$(raw_events "${new_log}" "${chain}" vend)" ]; then
    pass "${name}: the new pod's stdout has no vend event for it, so the file is the only surviving copy"
  else
    fail "${name}: the new pod's stdout unexpectedly holds a vend event for ${chain}"
  fi
  dispose_line=$(raw_events "${new_log}" "${chain}" dispose | grep -F '"outcome":"allow"' | head -1)
  if [ -n "${dispose_line}" ] && printf '%s\n' "${TRAIL}" | grep -Fxq -- "${dispose_line}"; then
    pass "${name}: the post-restart dispose event is in the file, byte-identical to the new pod's stdout"
  else
    fail "${name}: the new pod's dispose line is missing from the audit file"
  fi
}
check_trail C "${C_CHAIN}" revoked_on_demand "${C_VEND_LINE}"
check_trail S "${S_CHAIN}" ttl_expired "${S_VEND_LINE}"

# ---------------------------------------------------------------------------
printf '\n'
if [ "${FAILURES}" -eq 0 ]; then
  printf '\033[32m================ PERSISTENCE VERIFY: PASS (%d steps) ================\033[0m\n' "${CHECK_NO}"
  printf 'vending-service pod %s deleted and replaced by %s:\n' "${OLD_POD}" "${NEW_POD}"
  printf '  delegation        -> GET returns the same record; parent DELETE removes entry + grant; C then gets 403\n'
  printf '  reaper            -> the new pod disposed S with ttl_expired and its original chain_id\n'
  printf '  audit trail       -> vend (before) and dispose (after) for both chain_ids, valid JSON, exact schema\n'
  printf '  replay protection -> a pre-restart nonce is still refused (409)\n'
  exit 0
else
  printf '\033[31m================ PERSISTENCE VERIFY: FAIL (%d failed) ================\033[0m\n' "${FAILURES}"
  exit 1
fi
