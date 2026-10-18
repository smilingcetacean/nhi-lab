#!/usr/bin/env bash
# `make verify-present`: deterministic checks of the OpenCode parent pod. No LLM
# call is made and no API key is needed: the checks drive the pod's one tool
# exactly as OpenCode would, with fixed arguments, and assert on the identity,
# audit and refusal behaviour behind it.
#
# The tool is run THROUGH OpenCode, not around it:
#
#   opencode debug agent build --tool delegate_to_child --params '<json>'
#
# runs the real delegate_to_child.ts `execute` (the same code path a model's tool
# call takes, minus the model) and prints one JSON document on stdout whose
# `.result.output` is the tool's output, i.e. the one result line `parent.py tool`
# prints. That parses reliably (stdout is that single document, nothing else is
# on it), so no fallback to calling `python3 /app/parent.py tool` directly is
# needed. Two things the command does NOT do: it does not validate the arguments
# against the tool's schema (so the arguments here are written to be valid), and
# OpenCode puts no timeout on a custom tool (parent.py's own limits bound a
# cycle; `timeout` below bounds the script).
#
#   1. bring-up         OpenCode 1.19.3; delegate_to_child is the only enabled tool
#   2. dataset A        one full cycle: ok, records, mTLS callback from the vended
#                       child, disposed; the child's SPIRE entry and OPA grant
#                       are gone afterwards; one chain_id across vend / operate
#                       (resource, child, parent) / dispose; the spawn event
#   3. impostor         a pod with a valid SVID that is not the vended child dials
#                       the callback listener mid-cycle: refused and audited, and
#                       the legitimate cycle still ends ok
#   4. attenuation      dataset B is refused at vend time: no child, no entry, no grant
#
# Audit collection is bounded to this run's own time window (see demo.sh for
# why) and written to src/deploy/present-audit.jsonl (gitignored).
set -uo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-nhi-lab}"
KUBECTX="${KUBECTX:-kind-${CLUSTER_NAME}}"
TRUST_DOMAIN="${TRUST_DOMAIN:-lab.local}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS="${SCRIPT_DIR}/../manifests"
OUT_FILE="$(cd "${SCRIPT_DIR}/.." && pwd)/present-audit.jsonl"

KUBECTL=(kubectl --context "${KUBECTX}")
NS=agents
PARENT_POD=nhi-opencode-parent
PARENT_ID="spiffe://${TRUST_DOMAIN}/agent/parent/opencode"
IMPOSTOR_ID="spiffe://${TRUST_DOMAIN}/agent/parent/demo"
OPA_URL="https://opa.opa.svc.cluster.local:8181"
WANT_VERSION="1.19.3"
CALLBACK_PORT=8443

# A couple of seconds of slack before "now" (kubectl logs --since-time is a
# second-granularity cutoff); the checks below add no audit events before this run.
START_TIME="$(date -u -d '2 seconds ago' +%Y-%m-%dT%H:%M:%SZ)"
echo ">> verify-present window starts at ${START_TIME} (UTC)"

FAILURES=0
CHECK_NO=0
step() {
  CHECK_NO=$((CHECK_NO + 1))
  printf '\n\033[1m[%d] %s\033[0m\n' "${CHECK_NO}" "$1"
}
pass() { printf '    \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '    \033[31mFAIL\033[0m %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
indent() { sed 's/^/    | /'; }

WORK="$(mktemp -d)"
cleanup() {
  "${KUBECTL[@]}" delete pod callback-impostor -n "${NS}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  # The probe pods hold the policy engine's identity; they exist only for this run.
  "${KUBECTL[@]}" delete -f "${MANIFESTS}/test/41-policy-probe.yaml" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  rm -rf "${WORK}"
}
trap cleanup EXIT

# --- helpers ----------------------------------------------------------------

running_pod() {
  local ns="$1" selector="$2"
  "${KUBECTL[@]}" get pods -n "${ns}" -l "${selector}" --field-selector=status.phase=Running \
    --sort-by=.metadata.creationTimestamp -o jsonpath='{.items}' \
    | jq -r 'if length > 0 then .[-1].metadata.name else empty end'
}

in_parent() { "${KUBECTL[@]}" exec -n "${NS}" "${PARENT_POD}" -c parent -- "$@"; }

# run_tool <A|B> <task> <result file>
# Runs delegate_to_child through OpenCode and leaves the tool's result JSON (one
# line) in <result file>; the file is empty if OpenCode printed nothing parsable.
run_tool() {
  local dataset="$1" task="$2" out="$3" params
  params="$(jq -nc --arg t "${task}" --arg d "${dataset}" '{task: $t, dataset: $d}')"
  : > "${out}"
  timeout 300 "${KUBECTL[@]}" exec -n "${NS}" "${PARENT_POD}" -c parent -- \
    sh -c 'cd /workspace && exec opencode debug agent build --tool delegate_to_child --params "$1"' sh "${params}" \
    > "${out}.raw" 2> "${out}.err" || true
  jq -ce '.result.output | fromjson' "${out}.raw" > "${out}" 2>/dev/null || : > "${out}"
}

# jf <result file> <jq filter>: one field of a result.
jf() { jq -r "$2" "$1" 2>/dev/null; }

# spire_entries <spiffe id> -> number of registration entries for it, or "?"
spire_entries() {
  local raw n
  for _ in 1 2 3; do
    raw="$("${KUBECTL[@]}" exec -n spire spire-server-0 -c spire-server -- \
      /opt/spire/bin/spire-server entry show -spiffeID "$1" 2>/dev/null)" || raw=""
    n="$(printf '%s\n' "${raw}" | sed -n 's/^Found \([0-9]*\) entr.*/\1/p')"
    if [ -n "${n}" ]; then echo "${n}"; return 0; fi
    sleep 1
  done
  echo '?'
}

# opa_policy_ids -> every policy module id OPA holds, one per line; non-zero if
# OPA could not be listed. Read through the probe pod that holds the policy
# engine's identity, the only client besides the resource that OPA answers.
opa_policy_ids() {
  local raw
  for _ in 1 2 3; do
    raw="$("${KUBECTL[@]}" exec -n nhi "${PROBE_POD}" -c probe -- curl -sS --max-time 15 \
      --cacert /run/spiffe/bundle.pem --cert /run/spiffe/svid.pem --key /run/spiffe/svid_key.pem \
      "${OPA_URL}/v1/policies" 2>/dev/null)" || raw=""
    if printf '%s' "${raw}" | jq -e '.result' >/dev/null 2>&1; then
      printf '%s' "${raw}" | jq -r '.result[].id'
      return 0
    fi
    sleep 2
  done
  return 1
}

# grant_present <chain_id> -> 1 / 0 (or "?" if OPA cannot be listed)
grant_present() {
  local ids
  ids="$(opa_policy_ids)" || { echo '?'; return; }
  if printf '%s\n' "${ids}" | grep -qx "nhi_grants_$1"; then echo 1; else echo 0; fi
}

# check_disposed <label> <chain_id> <child spiffe id>: the child's SPIRE entry and OPA
# grant are gone (polled briefly: disposal is synchronous, the read is not).
check_disposed() {
  local label="$1" chain="$2" child="$3" e g
  for _ in 1 2 3 4 5 6; do
    e="$(spire_entries "${child}")"; g="$(grant_present "${chain}")"
    [ "${e}" = 0 ] && [ "${g}" = 0 ] && break
    sleep 2
  done
  echo "    | ${label}: SPIRE entries for the child=${e}, OPA grant modules for the chain=${g}"
  if [ "${e}" = 0 ]; then pass "${label}: the child's SPIRE entry is gone"; else fail "${label}: child SPIRE entry count is ${e}, want 0"; fi
  if [ "${g}" = 0 ]; then pass "${label}: the chain's OPA grant is gone"; else fail "${label}: OPA grant count is ${g}, want 0"; fi
}

# ev <file> <chain_id> <stage> <outcome> [extra jq condition] -> number of matching events
ev() {
  jq -c --arg c "$2" --arg s "$3" --arg o "$4" \
    "select(.chain_id == \$c and .stage == \$s and .outcome == \$o and (${5:-true}))" "$1" 2>/dev/null | wc -l | tr -d ' '
}
want_ev() { # <description> <file> <chain_id> <stage> <outcome> [extra jq condition]
  local n
  n="$(ev "$2" "$3" "$4" "$5" "${6:-true}")"
  if [ "${n}" -ge 1 ]; then pass "$1"; else fail "$1 (found ${n})"; fi
}

# ---------------------------------------------------------------------------
step "Preflight: the OpenCode parent pod and the policy probe are Ready"
if ! "${KUBECTL[@]}" wait --for=condition=Ready "pod/${PARENT_POD}" -n "${NS}" --timeout=60s >/dev/null 2>&1; then
  fail "pod ${NS}/${PARENT_POD} is not Ready; run 'make present-up'"
  exit 1
fi
"${KUBECTL[@]}" delete pod callback-impostor -n "${NS}" --ignore-not-found --wait=true >/dev/null 2>&1 || true
"${KUBECTL[@]}" apply -f "${MANIFESTS}/test/41-policy-probe.yaml" >/dev/null
if "${KUBECTL[@]}" rollout status deployment/policy-probe-authorized -n nhi --timeout=150s >/dev/null 2>&1; then
  PROBE_POD="$(running_pod nhi probe=authorized)"
  pass "parent pod Ready; OPA read-through probe ${PROBE_POD} Ready"
else
  fail "policy-probe-authorized did not become Ready (needed to read OPA's grant modules)"
  exit 1
fi
PARENT_IP="$("${KUBECTL[@]}" get pod "${PARENT_POD}" -n "${NS}" -o jsonpath='{.status.podIP}')"
echo "    | parent pod IP ${PARENT_IP}"
if [ "$(opa_policy_ids | wc -l | tr -d ' ')" -ge 1 ]; then
  pass "OPA can be listed through the probe (the grant checks below can see modules)"
else
  fail "OPA could not be listed through the probe; grant checks would be vacuous"
  exit 1
fi

# ---------------------------------------------------------------------------
step "Bring-up: OpenCode ${WANT_VERSION}, and delegate_to_child is the only enabled tool"
VERSION="$(in_parent opencode --version 2>/dev/null | tail -1 | tr -d '\r')"
echo "    | opencode --version: ${VERSION}"
if [ "${VERSION}" = "${WANT_VERSION}" ]; then pass "OpenCode is ${WANT_VERSION}"; else fail "OpenCode version is '${VERSION}', want ${WANT_VERSION}"; fi
ENABLED="$(in_parent sh -c 'cd /workspace && opencode debug agent build' 2>/dev/null \
  | jq -c '[.tools | to_entries[] | select(.value == true) | .key]' 2>/dev/null)"
echo "    | enabled tools: ${ENABLED:-<unreadable>}"
if [ "${ENABLED}" = '["delegate_to_child"]' ]; then
  pass "the only tool offered to the model is delegate_to_child"
else
  fail "enabled tools are ${ENABLED:-<unreadable>}, want [\"delegate_to_child\"]"
fi

# ---------------------------------------------------------------------------
step "Dataset A through the real OpenCode tool: one full delegation cycle"
RA="${WORK}/cycle-a.json"
echo "    | running: opencode debug agent build --tool delegate_to_child (dataset A); takes ~10-15 s"
run_tool A "verify-present: fetch the records in dataset A" "${RA}"
if [ ! -s "${RA}" ]; then
  fail "no parsable tool result; stdout was: $(head -c 300 "${RA}.raw")"
  indent < "${RA}.err" | head -5
  exit 1
fi
jq . "${RA}" | indent
CHAIN_A="$(jf "${RA}" '.chain_id // empty')"
CHILD_A="$(jf "${RA}" '.child_spiffe_id // empty')"
[ "$(jf "${RA}" '.ok')" = "true" ] && pass "ok:true" || fail "ok is not true (error: $(jf "${RA}" '.error'))"
[ "$(jf "${RA}" '[.data.records[]?.value] | sort | join(",")')" = "alpha,beta" ] \
  && pass "data carries dataset A's records (alpha, beta)" || fail "data does not hold exactly alpha and beta"
[ "$(jf "${RA}" '.returned_via')" = "mtls-callback" ] \
  && pass "returned_via mtls-callback" || fail "returned_via is $(jf "${RA}" '.returned_via'), want mtls-callback"
if [ -n "${CHILD_A}" ] && [ "$(jf "${RA}" '.peer_spiffe_id')" = "${CHILD_A}" ]; then
  pass "the callback peer is the vended child (${CHILD_A##*/})"
else
  fail "peer_spiffe_id '$(jf "${RA}" '.peer_spiffe_id')' is not the vended child '${CHILD_A}'"
fi
[ "$(jf "${RA}" '.child_scopes | join(",")')" = "resource:read:datasetA" ] \
  && pass "child scopes are exactly resource:read:datasetA" || fail "child scopes are $(jf "${RA}" '.child_scopes | join(",")')"
[ "$(jf "${RA}" '.disposed')" = "true" ] && pass "disposed:true" || fail "disposed is not true"
if [ -n "${CHAIN_A}" ] && [ -n "${CHILD_A}" ]; then
  check_disposed "after dataset A" "${CHAIN_A}" "${CHILD_A}"
else
  fail "no chain_id / child_spiffe_id in the result; disposal cannot be checked"
fi

# ---------------------------------------------------------------------------
step "An impostor holding a valid SVID that is not the vended child is refused"
sed "s|__TARGET__|${PARENT_IP}:${CALLBACK_PORT}|" "${MANIFESTS}/test/47-callback-impostor.yaml" \
  | "${KUBECTL[@]}" apply -f - >/dev/null
for _ in $(seq 1 45); do
  "${KUBECTL[@]}" logs -n "${NS}" callback-impostor 2>/dev/null | grep -q '^impostor identity:' && break
  sleep 1
done
if "${KUBECTL[@]}" logs -n "${NS}" callback-impostor 2>/dev/null | grep -q "^impostor identity: ${IMPOSTOR_ID}\$"; then
  pass "the impostor pod holds a valid SVID: ${IMPOSTOR_ID}, and is redialling ${PARENT_IP}:${CALLBACK_PORT}"
else
  fail "the impostor pod did not obtain the expected SVID"
  "${KUBECTL[@]}" logs -n "${NS}" callback-impostor 2>&1 | indent
fi

# Children that exist before the cycle, to recognise the new one.
PODS_BEFORE="$("${KUBECTL[@]}" get pods -n "${NS}" -l app=nhi-demo-child -o name | sort)"
RB="${WORK}/cycle-impostor.json"
run_tool A "verify-present: fetch dataset A while an impostor dials the callback" "${RB}" &
TOOL_PID=$!
# While the cycle runs: the child's entry and grant exist (a positive control for
# the absence checks), and the cycle is the one the impostor is racing.
CHAIN_B=""; CHILD_B=""
for _ in $(seq 1 60); do
  NEW="$("${KUBECTL[@]}" get pods -n "${NS}" -l app=nhi-demo-child -o json \
    | jq -r --arg before "${PODS_BEFORE}" '.items[] | select(("pod/" + .metadata.name) as $n | ($before | split("\n") | index($n)) | not) | [.metadata.name, .metadata.labels["nhi.chain-id"]] | @tsv' | head -1)"
  if [ -n "${NEW}" ]; then
    CHILD_B="${PARENT_ID}/child/$(printf '%s' "${NEW}" | cut -f1)"; CHAIN_B="$(printf '%s' "${NEW}" | cut -f2)"; break
  fi
  sleep 0.5
done
if [ -n "${CHAIN_B}" ]; then
  E="$(spire_entries "${CHILD_B}")"; G="$(grant_present "${CHAIN_B}")"
  echo "    | mid-cycle: SPIRE entries for the child=${E}, OPA grant modules for the chain=${G}"
  if [ "${E}" = 1 ] && [ "${G}" = 1 ]; then
    pass "mid-cycle the child's entry and grant exist, so their absence afterwards is meaningful"
  else
    fail "mid-cycle entry/grant counts are ${E}/${G}, want 1/1 (the absence checks would be vacuous)"
  fi
else
  fail "no new child pod appeared during the impostor cycle"
fi
wait "${TOOL_PID}"
if [ ! -s "${RB}" ]; then fail "no parsable tool result for the impostor cycle; stdout: $(head -c 300 "${RB}.raw")"; exit 1; fi
jq -c . "${RB}" | indent
[ "$(jf "${RB}" '.ok')" = "true" ] \
  && pass "the legitimate cycle still ended ok:true" || fail "the legitimate cycle did not end ok (error: $(jf "${RB}" '.error'))"
[ "$(jf "${RB}" '.peer_spiffe_id')" = "$(jf "${RB}" '.child_spiffe_id')" ] \
  && pass "its result came from the vended child, not the impostor" || fail "peer_spiffe_id differs from child_spiffe_id"
[ "$(jf "${RB}" '.chain_id')" = "${CHAIN_B}" ] || echo "    | note: chain seen mid-cycle (${CHAIN_B}) differs from the result's ($(jf "${RB}" '.chain_id'))"
CHAIN_B="$(jf "${RB}" '.chain_id // empty')"; CHILD_B="$(jf "${RB}" '.child_spiffe_id // empty')"
for _ in $(seq 1 20); do
  "${KUBECTL[@]}" logs -n "${NS}" callback-impostor 2>/dev/null | grep -q '^dial OK' && break
  sleep 1
done
"${KUBECTL[@]}" logs -n "${NS}" callback-impostor 2>&1 | indent
if "${KUBECTL[@]}" logs -n "${NS}" callback-impostor 2>/dev/null | grep -q '^dial OK'; then
  pass "the impostor reached the listener (so the refusal below is the listener's decision)"
else
  fail "the impostor never reached the listener"
fi
if [ -n "${CHAIN_B}" ] && [ -n "${CHILD_B}" ]; then check_disposed "after the impostor cycle" "${CHAIN_B}" "${CHILD_B}"; fi
"${KUBECTL[@]}" delete pod callback-impostor -n "${NS}" --ignore-not-found --wait=true >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
step "Attenuation: dataset B is refused at vend time, and nothing is minted"
PODS_N0="$("${KUBECTL[@]}" get pods -n "${NS}" -l app=nhi-demo-child -o name | wc -l | tr -d ' ')"
GRANTS0="$(opa_policy_ids | grep -c '^nhi_grants_' || true)"
RD="${WORK}/cycle-b.json"
run_tool B "verify-present: fetch the records in dataset B" "${RD}"
if [ ! -s "${RD}" ]; then fail "no parsable tool result for dataset B; stdout: $(head -c 300 "${RD}.raw")"; exit 1; fi
jq -c . "${RD}" | indent
[ "$(jf "${RD}" '.ok')" = "false" ] && pass "ok:false" || fail "ok is not false"
jf "${RD}" '.error' | grep -q '403' \
  && pass "error names the vend refusal (HTTP 403)" || fail "error does not mention 403: $(jf "${RD}" '.error')"
[ "$(jf "${RD}" '.chain_id')" = "null" ] && pass "chain_id is null (no chain is reported for a refusal)" || fail "chain_id is not null"
[ "$(jf "${RD}" '.child_scopes | length')" = "0" ] && pass "child_scopes is []" || fail "child_scopes is not empty"
[ "$(jf "${RD}" '.disposed')" = "false" ] && [ "$(jf "${RD}" '.data')" = "null" ] \
  && pass "nothing was disposed or returned" || fail "disposed/data are not false/null"
PODS_N1="$("${KUBECTL[@]}" get pods -n "${NS}" -l app=nhi-demo-child -o name | wc -l | tr -d ' ')"
GRANTS1="$(opa_policy_ids | grep -c '^nhi_grants_' || true)"
echo "    | child pods ${PODS_N0} -> ${PODS_N1}; OPA grant modules ${GRANTS0} -> ${GRANTS1}"
[ "${PODS_N0}" = "${PODS_N1}" ] && pass "no new child pod" || fail "child pod count changed ${PODS_N0} -> ${PODS_N1}"
[ "${GRANTS0}" = "${GRANTS1}" ] && [ "${GRANTS1}" = 0 ] \
  && pass "no OPA grant exists for the refused request" || fail "OPA grant modules ${GRANTS0} -> ${GRANTS1}, want 0 -> 0"

# ---------------------------------------------------------------------------
step "Collecting every component's audit events for this run"
# The parent's events come from the pod's own container log: PID 1 is `sleep`,
# so this proves NHI_AUDIT_SINK carries events written by an exec'd process.
# Children are found by their nhi.chain-id label.
F_PARENT="${WORK}/parent.jsonl"; F_CHILD="${WORK}/child.jsonl"; F_VEND="${WORK}/vending.jsonl"
F_PE="${WORK}/policy.jsonl"; F_RES="${WORK}/resource.jsonl"
sleep 1
"${KUBECTL[@]}" logs -n "${NS}" "${PARENT_POD}" -c parent --since-time="${START_TIME}" --tail=2000 2>/dev/null | grep '^{' > "${F_PARENT}" || true
: > "${F_CHILD}"
for chain in ${CHAIN_A} ${CHAIN_B}; do
  "${KUBECTL[@]}" logs -n "${NS}" -l "nhi.chain-id=${chain}" -c child --since-time="${START_TIME}" --tail=500 2>/dev/null | grep '^{' >> "${F_CHILD}" || true
done
collect() { "${KUBECTL[@]}" logs -n nhi -l "app=$1" -c "$1" --since-time="${START_TIME}" --tail=2000 --prefix=false 2>/dev/null | grep '^{' > "$2" || true; }
collect vending-service "${F_VEND}"; collect policy-engine "${F_PE}"; collect resource "${F_RES}"
cat "${F_PARENT}" "${F_CHILD}" "${F_VEND}" "${F_PE}" "${F_RES}" | jq -s -c 'sort_by(.timestamp)[]' > "${OUT_FILE}" 2>/dev/null
LINES="$(wc -l < "${OUT_FILE}" | tr -d ' ')"
echo "    | collected ${LINES} audit event(s) -> ${OUT_FILE}"
echo "    | parent=$(wc -l < "${F_PARENT}") child=$(wc -l < "${F_CHILD}") vending-service=$(wc -l < "${F_VEND}") policy-engine=$(wc -l < "${F_PE}") resource=$(wc -l < "${F_RES}")"
if [ "${LINES}" -gt 0 ] && ! jq -e 'select((.timestamp and .stage and (.chain_id != null) and .actor_spiffe_id and .outcome and .detail) | not)' "${OUT_FILE}" >/dev/null 2>&1; then
  pass "every collected line is audit-schema JSON"
else
  fail "no events, or a line is not audit-schema JSON"
fi

# ---------------------------------------------------------------------------
step "Attribution for the dataset A cycle (chain ${CHAIN_A:-<none>}): one chain_id from vend to dispose"
if [ -n "${CHAIN_A}" ]; then
  want_ev "vending service: vend (allow)" "${F_VEND}" "${CHAIN_A}" vend allow
  want_ev "policy engine: vend (allow)" "${F_PE}" "${CHAIN_A}" vend allow
  want_ev "resource: operate by the child (allow)" "${F_RES}" "${CHAIN_A}" operate allow ".actor_spiffe_id == \"${CHILD_A}\""
  want_ev "child pod: operate (allow)" "${F_CHILD}" "${CHAIN_A}" operate allow ".actor_spiffe_id == \"${CHILD_A}\""
  want_ev "parent pod log: operate/result_returned from the vended child (allow)" "${F_PARENT}" "${CHAIN_A}" operate allow \
    ".detail.kind == \"result_returned\" and .detail.peer == \"${CHILD_A}\""
  want_ev "vending service: dispose (allow)" "${F_VEND}" "${CHAIN_A}" dispose allow
  want_ev "policy engine: dispose (allow)" "${F_PE}" "${CHAIN_A}" dispose allow
  NOT_ALLOW="$(jq -c --arg c "${CHAIN_A}" 'select(.chain_id == $c and .outcome != "allow")' "${OUT_FILE}" | wc -l | tr -d ' ')"
  [ "${NOT_ALLOW}" = 0 ] && pass "every event on this chain is an allow" || fail "${NOT_ALLOW} non-allow event(s) on the dataset A chain"
  SPAWN="$(jq -c --arg id "${CHILD_A}" 'select(.stage == "spawn" and .chain_id == "" and .actor_spiffe_id == "'"${PARENT_ID}"'" and .detail.child_spiffe_id == $id)' "${F_PARENT}" | wc -l | tr -d ' ')"
  [ "${SPAWN}" = 1 ] && pass "the parent's spawn event for this child is present (chain_id \"\" by design)" || fail "expected one spawn event for ${CHILD_A}, found ${SPAWN}"
else
  fail "no chain_id from the dataset A cycle"
fi

step "Attribution for the impostor cycle (chain ${CHAIN_B:-<none>}): the refusal is audited"
if [ -n "${CHAIN_B}" ]; then
  want_ev "parent pod log: operate/callback_refused (deny) naming the impostor as peer" "${F_PARENT}" "${CHAIN_B}" operate deny \
    ".detail.kind == \"callback_refused\" and .detail.peer == \"${IMPOSTOR_ID}\""
  want_ev "parent pod log: operate/result_returned from the vended child (allow)" "${F_PARENT}" "${CHAIN_B}" operate allow \
    ".detail.kind == \"result_returned\" and .detail.peer == \"${CHILD_B}\""
  FORGED="$(jq -c --arg c "${CHAIN_B}" 'select(.chain_id == $c and .detail.kind == "result_returned" and .detail.peer != null)' "${F_PARENT}" \
    | jq -r --arg imp "${IMPOSTOR_ID}" 'select(.detail.peer == $imp)' | wc -l | tr -d ' ')"
  [ "${FORGED}" = 0 ] && pass "no result was ever accepted from the impostor" || fail "a result from the impostor was accepted"
  want_ev "vending service: dispose (allow)" "${F_VEND}" "${CHAIN_B}" dispose allow
else
  fail "no chain_id from the impostor cycle"
fi

step "Attribution for the refused dataset B request: vend deny, and the parent's spawn decision"
want_ev "vending service: vend (deny) for the parent, naming the empty intersection" "${F_VEND}" "$(jq -r 'select(.stage == "vend" and .outcome == "deny") | .chain_id' "${F_VEND}" | tail -1)" vend deny \
  ".actor_spiffe_id == \"${PARENT_ID}\" and (.detail.requested_scopes | index(\"resource:read:datasetB\")) != null"
DENIED_CHILD="$(jq -r 'select(.stage == "vend" and .outcome == "deny") | .detail.child_spiffe_id' "${F_VEND}" | tail -1)"
if [ -n "${DENIED_CHILD}" ] && [ "$(spire_entries "${DENIED_CHILD}")" = 0 ]; then
  pass "the refused child (${DENIED_CHILD##*/}) has no SPIRE entry"
else
  fail "the refused child '${DENIED_CHILD}' is unknown or has a SPIRE entry"
fi
SPAWN_B="$(jq -c 'select(.stage == "spawn" and (.detail.requested_scopes | index("resource:read:datasetB")) != null)' "${F_PARENT}" | wc -l | tr -d ' ')"
[ "${SPAWN_B}" = 1 ] && pass "the parent's spawn event for dataset B is present" || fail "expected one dataset B spawn event, found ${SPAWN_B}"

# ---------------------------------------------------------------------------
printf '\n'
if [ "${FAILURES}" -eq 0 ]; then
  printf '\033[32m================ VERIFY-PRESENT: PASS (%d steps) ================\033[0m\n' "${CHECK_NO}"
  printf 'The OpenCode parent, driven through its one tool with no LLM:\n'
  printf '  dataset A: vended child, mTLS result callback, disposal, one chain_id end to end\n'
  printf '  impostor with a valid SVID: refused and audited, legitimate cycle unaffected\n'
  printf '  dataset B: refused at vend time, nothing minted\n'
  printf '  audit events: %s\n' "${OUT_FILE}"
  exit 0
else
  printf '\033[31m================ VERIFY-PRESENT: FAIL (%d failed check(s)) ================\033[0m\n' "${FAILURES}"
  exit 1
fi
