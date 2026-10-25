#!/usr/bin/env bash
# `make verify-exit-hooks`: a parent that is deleted mid-cycle still disposes
# its delegation, and its child pod goes with it. No LLM and no API key.
#
#   (a) demo parent    parent.py is PID 1 of nhi-demo-parent and handles SIGTERM.
#                      The pod is deleted as soon as its delegation exists and
#                      the child pod is still running. The delegation is then
#                      revoked (GET shows revoked_at), a `dispose` event for the
#                      chain_id from the parent appears, and the child's SPIRE
#                      entry and OPA grant are gone.
#   (b) OpenCode       PID 1 of nhi-opencode-parent is `sleep infinity`; the tool
#       parent         (`parent.py tool`, started under `kubectl exec`) is not
#                      PID 1. The pod's preStop hook (`parent.py stop-tools`)
#                      signals it. Same checks as (a), with the pod deleted
#                      mid-cycle.
#   (c) ownerReference each child pod carries an ownerReference to its parent
#                      pod (the parent's name and UID, no blockOwnerDeletion),
#                      and deleting the parent pod makes the garbage collector
#                      delete the child pod: it is NotFound within a bounded wait.
#
# "Mid-cycle" is caught, not simulated: the script waits for the parent's
# "delegation created" line, which is written before the child pod exists, then
# reads the child pod's phase and deletes the parent pod. If the child had
# already finished (a terminal phase) the attempt proves nothing about the hook
# and is repeated (at most MAX_ATTEMPTS times). A `dispose` event only counts if
# it is stamped at or after the moment the delete was issued.
#
# Pods this script deletes are recreated: nhi-opencode-parent is applied again
# and waited on until Ready (also on failure, from the exit trap), and
# nhi-demo-parent is applied again and waited on until its cycle has Succeeded,
# which also shows the normal path still completes with the signal handler in
# place. Every chain_id is new, so the script can be run repeatedly.
set -uo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-nhi-lab}"
KUBECTX="${KUBECTX:-kind-${CLUSTER_NAME}}"
TRUST_DOMAIN="${TRUST_DOMAIN:-lab.local}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS="${SCRIPT_DIR}/../manifests"

KUBECTL=(kubectl --context "${KUBECTX}")
NS=agents
DEMO_POD=nhi-demo-parent
OC_POD=nhi-opencode-parent
DEMO_ID="spiffe://${TRUST_DOMAIN}/agent/parent/demo"
OC_ID="spiffe://${TRUST_DOMAIN}/agent/parent/opencode"
OPA_URL="https://opa.opa.svc.cluster.local:8181"
MAX_ATTEMPTS=3
# The garbage collector deletes the child pod at once, but the child's container
# (child.py as PID 1) ignores SIGTERM, so the kubelet waits out the 30 s default
# grace period before the pod object is gone. The OpenCode parent pod takes the
# same 30 s to go (`sleep infinity` as PID 1 ignores SIGTERM too), and its child
# is only collected once that pod object is gone.
GC_WAIT_SECONDS=120

# A couple of seconds of slack before "now" (kubectl logs --since-time is a
# second-granularity cutoff).
START_TIME="$(date -u -d '2 seconds ago' +%Y-%m-%dT%H:%M:%SZ)"
echo ">> verify-exit-hooks window starts at ${START_TIME} (UTC)"

FAILURES=0
CHECK_NO=0
step() {
  CHECK_NO=$((CHECK_NO + 1))
  printf '\n\033[1m[%d] %s\033[0m\n' "${CHECK_NO}" "$1"
}
pass() { printf '    \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '    \033[31mFAIL\033[0m %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
note() { printf '    | %s\n' "$1"; }
indent() { sed 's/^/    | /'; }

WORK="$(mktemp -d)"

# ensure_opencode_pod: the OpenCode parent pod exists and is Ready (applied from
# its manifest if it is missing, e.g. right after this script deleted it).
ensure_opencode_pod() {
  if ! "${KUBECTL[@]}" get pod "${OC_POD}" -n "${NS}" >/dev/null 2>&1; then
    "${KUBECTL[@]}" apply -f "${MANIFESTS}/agents/72-opencode-parent-pod.yaml" >/dev/null 2>&1
  fi
  "${KUBECTL[@]}" wait --for=condition=Ready "pod/${OC_POD}" -n "${NS}" --timeout=120s >/dev/null 2>&1
}

cleanup() {
  ensure_opencode_pod || echo "!! ${OC_POD} is not Ready after the run; re-run 'make present-up'" >&2
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
  if grep -qx "nhi_grants_$1" <<<"${ids}"; then echo 1; else echo 0; fi
}

# vending_get <chain_id> -> "<http code> <json body>", read as the OpenCode parent
# (any authenticated identity may read GET /delegations/{chain_id}).
vending_get() {
  "${KUBECTL[@]}" exec -n "${NS}" "${OC_POD}" -c parent -- python3 -c '
import sys
sys.path.insert(0, "/app")
import common
wl = common.new_workload_client()
tok = common.fetch_jwt_svid_retrying(wl, "spiffe://lab.local/svc/vending-service").token
r = common.http_session().get("http://vending-service.nhi.svc.cluster.local:8090/delegations/" + sys.argv[1],
                              headers=common.bearer_headers(tok))
print(r.status_code, r.text)' "$1" 2>/dev/null
}

# child_pod_of <chain_id> -> name of the child pod labelled with that chain, if any
child_pod_of() {
  "${KUBECTL[@]}" get pods -n "${NS}" -l "nhi.chain-id=$1" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# await_chain <log source...>: reads `kubectl logs` of the given pod every 0.3 s
# (or a file) until the parent logs "delegation created"; sets CHAIN and CHILD_ID.
CHAIN=""; CHILD_ID=""
await_chain() {
  local src="$1" line i
  CHAIN=""; CHILD_ID=""
  for i in $(seq 1 300); do
    if [ -f "${src}" ]; then line="$(grep -m1 'delegation created, chain_id=' "${src}" 2>/dev/null || true)"
    else line="$("${KUBECTL[@]}" logs -n "${NS}" "${src}" -c parent 2>/dev/null | grep -m1 'delegation created, chain_id=' || true)"; fi
    if [ -n "${line}" ]; then
      CHAIN="$(printf '%s' "${line}" | sed -n 's/.*chain_id=\([^ ]*\) child_spiffe_id=.*/\1/p')"
      CHILD_ID="$(printf '%s' "${line}" | sed -n 's/.*child_spiffe_id=\([^ ]*\) .*/\1/p')"
      return 0
    fi
    sleep 0.3
  done
  return 1
}

# catch_midcycle <parent pod> <parent uid>: with CHAIN set, finds the child pod, records
# its phase and ownerReferences. Sets CHILD_POD, CHILD_PHASE, CHILD_OWNERS; returns 0 if
# the child is still running (the delete will land mid-cycle), 1 if it already finished.
CHILD_POD=""; CHILD_PHASE=""; CHILD_OWNERS=""
catch_midcycle() {
  local i
  CHILD_POD=""; CHILD_PHASE=""; CHILD_OWNERS=""
  for i in $(seq 1 50); do
    CHILD_POD="$(child_pod_of "${CHAIN}")"
    [ -n "${CHILD_POD}" ] && break
    sleep 0.2
  done
  [ -n "${CHILD_POD}" ] || return 1
  local json
  json="$("${KUBECTL[@]}" get pod "${CHILD_POD}" -n "${NS}" -o json 2>/dev/null)" || return 1
  CHILD_PHASE="$(printf '%s' "${json}" | jq -r '.status.phase')"
  CHILD_OWNERS="$(printf '%s' "${json}" | jq -c '.metadata.ownerReferences // []')"
  case "${CHILD_PHASE}" in Succeeded|Failed) return 1 ;; esac
  return 0
}

# disposal_checks <label> <parent id> <t_delete epoch>: after the parent pod was deleted
# mid-cycle, the delegation is revoked, its `dispose` event exists and is not older than
# the delete, and the child's SPIRE entry and OPA grant are gone.
disposal_checks() {
  local label="$1" parent_id="$2" t_delete="$3" code body rec e g n i
  rec=""
  for i in $(seq 1 15); do
    rec="$(vending_get "${CHAIN}")"
    code="${rec%% *}"; body="${rec#* }"
    [ "${code}" = 200 ] && [ "$(printf '%s' "${body}" | jq -r '.revoked_at // empty' 2>/dev/null)" != "" ] && break
    sleep 2
  done
  note "${label}: GET /delegations/${CHAIN} -> ${code:-?} ${body:-}"
  if [ "${code}" = 200 ] && [ -n "$(printf '%s' "${body}" | jq -r '.revoked_at // empty' 2>/dev/null)" ]; then
    pass "${label}: the delegation is revoked (revoked_at is set, reason '$(printf '%s' "${body}" | jq -r '.revocation_reason')')"
  else
    fail "${label}: the delegation is not revoked after the parent pod was deleted"
  fi

  "${KUBECTL[@]}" logs -n nhi -l app=vending-service -c vending-service --since-time="${START_TIME}" \
    --tail=5000 --prefix=false 2>/dev/null | grep '^{' > "${WORK}/vending.jsonl" || true
  "${KUBECTL[@]}" logs -n nhi -l app=policy-engine -c policy-engine --since-time="${START_TIME}" \
    --tail=5000 --prefix=false 2>/dev/null | grep '^{' > "${WORK}/policy.jsonl" || true
  for src in vending policy; do
    n="$(jq -c --arg c "${CHAIN}" --arg a "${parent_id}" --argjson t "${t_delete}" \
      'select(.chain_id == $c and .stage == "dispose" and .outcome == "allow"
              and ((.actor_spiffe_id == $a) or (.actor_spiffe_id | endswith("/svc/vending-service")))
              and ((.timestamp | sub("\\.[0-9]+Z$"; "Z") | fromdate) >= $t))' "${WORK}/${src}.jsonl" | wc -l | tr -d ' ')"
    if [ "${n}" -ge 1 ]; then
      pass "${label}: ${src} service audit has a dispose (allow) event for ${CHAIN}, stamped at or after the delete"
      jq -c --arg c "${CHAIN}" 'select(.chain_id == $c and .stage == "dispose")' "${WORK}/${src}.jsonl" | indent
    else
      fail "${label}: no ${src} dispose (allow) event for ${CHAIN} at or after the delete (found ${n})"
    fi
  done
  n="$(jq -c --arg c "${CHAIN}" --arg a "${parent_id}" \
    'select(.chain_id == $c and .stage == "dispose" and .actor_spiffe_id == $a)' "${WORK}/vending.jsonl" | wc -l | tr -d ' ')"
  if [ "${n}" -ge 1 ]; then pass "${label}: the dispose event names the parent (${parent_id##*/parent/}) as actor"
  else fail "${label}: no dispose event with actor ${parent_id}"; fi

  for i in 1 2 3 4 5 6; do
    e="$(spire_entries "${CHILD_ID}")"; g="$(grant_present "${CHAIN}")"
    [ "${e}" = 0 ] && [ "${g}" = 0 ] && break
    sleep 2
  done
  note "${label}: SPIRE entries for the child=${e}, OPA grant modules for the chain=${g}"
  if [ "${e}" = 0 ]; then pass "${label}: the child's SPIRE entry is gone"; else fail "${label}: child SPIRE entry count is ${e}, want 0"; fi
  if [ "${g}" = 0 ]; then pass "${label}: the chain's OPA grant is gone"; else fail "${label}: OPA grant count is ${g}, want 0"; fi
}

# owner_checks <label> <parent pod> <parent uid> <t_delete epoch>: the child pod carried the
# right ownerReference, and is NotFound within GC_WAIT_SECONDS of the delete being issued.
owner_checks() {
  local label="$1" parent_pod="$2" parent_uid="$3" t0="$4" out gone=0
  note "${label}: child pod ${CHILD_POD} (phase when the parent was deleted: ${CHILD_PHASE}) ownerReferences: ${CHILD_OWNERS}"
  if printf '%s' "${CHILD_OWNERS}" | jq -e --arg n "${parent_pod}" --arg u "${parent_uid}" \
      'length == 1 and .[0].apiVersion == "v1" and .[0].kind == "Pod" and .[0].name == $n and .[0].uid == $u
       and (.[0] | has("blockOwnerDeletion") | not)' >/dev/null 2>&1; then
    pass "${label}: the child pod has exactly one ownerReference, to ${parent_pod} (uid ${parent_uid}), without blockOwnerDeletion"
  else
    fail "${label}: the child pod's ownerReferences are not the parent pod's"
  fi
  while [ $(($(date +%s) - t0)) -lt "${GC_WAIT_SECONDS}" ]; do
    out="$("${KUBECTL[@]}" get pod "${CHILD_POD}" -n "${NS}" 2>&1)"
    case "${out}" in *NotFound*) gone=1; break ;; esac
    sleep 1
  done
  if [ "${gone}" = 1 ]; then pass "${label}: child pod ${CHILD_POD} is NotFound $(($(date +%s) - t0))s after the delete was issued"
  else fail "${label}: child pod ${CHILD_POD} still exists ${GC_WAIT_SECONDS}s after the delete was issued"; fi
}

# ---------------------------------------------------------------------------
step "Preflight: the OpenCode parent pod and the OPA read-through probe are Ready"
if ! ensure_opencode_pod; then
  fail "pod ${NS}/${OC_POD} is not Ready; run 'make present-up'"
  exit 1
fi
"${KUBECTL[@]}" apply -f "${MANIFESTS}/test/41-policy-probe.yaml" >/dev/null
if "${KUBECTL[@]}" rollout status deployment/policy-probe-authorized -n nhi --timeout=150s >/dev/null 2>&1; then
  PROBE_POD="$(running_pod nhi probe=authorized)"
  pass "${OC_POD} Ready; OPA read-through probe ${PROBE_POD} Ready"
else
  fail "policy-probe-authorized did not become Ready (needed to read OPA's grant modules)"
  exit 1
fi
if [ "$(spire_entries "${DEMO_ID}")" = 1 ] && [ "$(spire_entries "${OC_ID}")" = 1 ]; then
  pass "both parents are registered with SPIRE"
else
  fail "the demo or OpenCode parent has no SPIRE entry; run 'make present-up'"
  exit 1
fi
if "${KUBECTL[@]}" get pod "${OC_POD}" -n "${NS}" -o json \
    | jq -e '.spec.terminationGracePeriodSeconds == 30 and (.spec.containers[0].lifecycle.preStop.exec.command | index("stop-tools")) != null' >/dev/null; then
  pass "${OC_POD} has the stop-tools preStop hook and a 30 s grace period"
else
  fail "${OC_POD} lacks the preStop hook or the 30 s grace period; run 'make present-up'"
fi

# ---------------------------------------------------------------------------
step "(a) Demo parent: delete the pod while its delegation is live"
DONE_A=0
for ATTEMPT in $(seq 1 "${MAX_ATTEMPTS}"); do
  note "attempt ${ATTEMPT}/${MAX_ATTEMPTS}"
  "${KUBECTL[@]}" apply -f "${MANIFESTS}/agents/70-demo-parent-rbac.yaml" >/dev/null
  "${KUBECTL[@]}" delete -f "${MANIFESTS}/agents/71-demo-parent-pod.yaml" --ignore-not-found --wait=true >/dev/null 2>&1 || true
  "${KUBECTL[@]}" delete pod -n "${NS}" -l app=nhi-demo-child --ignore-not-found --wait=true >/dev/null 2>&1 || true
  "${KUBECTL[@]}" apply -f "${MANIFESTS}/agents/71-demo-parent-pod.yaml" >/dev/null
  if ! await_chain "${DEMO_POD}"; then
    fail "(a) the demo parent never logged 'delegation created'"
    "${KUBECTL[@]}" logs -n "${NS}" "${DEMO_POD}" -c parent --tail=20 2>&1 | indent
    break
  fi
  PARENT_UID="$("${KUBECTL[@]}" get pod "${DEMO_POD}" -n "${NS}" -o jsonpath='{.metadata.uid}')"
  if ! catch_midcycle; then
    note "the child (${CHILD_POD:-none}) was already ${CHILD_PHASE:-missing}; this attempt would not exercise the hook, trying again"
    "${KUBECTL[@]}" wait --for=jsonpath='{.status.phase}'=Succeeded "pod/${DEMO_POD}" -n "${NS}" --timeout=60s >/dev/null 2>&1 || true
    continue
  fi
  note "chain_id=${CHAIN} child=${CHILD_ID}; child pod ${CHILD_POD} is ${CHILD_PHASE}; deleting ${DEMO_POD} (uid ${PARENT_UID}) now"
  T_DELETE="$(date +%s)"
  "${KUBECTL[@]}" delete pod "${DEMO_POD}" -n "${NS}" --wait=true --timeout=90s 2>&1 | indent
  DONE_A=1
  disposal_checks "(a) demo parent" "${DEMO_ID}" "${T_DELETE}"
  owner_checks "(c) demo parent's child" "${DEMO_POD}" "${PARENT_UID}" "${T_DELETE}"
  break
done
if [ "${DONE_A}" != 1 ]; then fail "(a) no attempt caught the demo parent mid-cycle with a running child"; fi

# Leave the demo parent as `make demo` does: applied, and its normal cycle done.
"${KUBECTL[@]}" delete pod -n "${NS}" -l app=nhi-demo-child --ignore-not-found --wait=true >/dev/null 2>&1 || true
"${KUBECTL[@]}" apply -f "${MANIFESTS}/agents/71-demo-parent-pod.yaml" >/dev/null
if "${KUBECTL[@]}" wait --for=jsonpath='{.status.phase}'=Succeeded "pod/${DEMO_POD}" -n "${NS}" --timeout=120s >/dev/null 2>&1; then
  pass "(a) the recreated demo parent completes its normal cycle (pod phase Succeeded)"
else
  fail "(a) the recreated demo parent did not reach Succeeded"
fi

# ---------------------------------------------------------------------------
step "(b) OpenCode parent: delete the pod while 'parent.py tool' runs under kubectl exec"
DONE_B=0
for ATTEMPT in $(seq 1 "${MAX_ATTEMPTS}"); do
  note "attempt ${ATTEMPT}/${MAX_ATTEMPTS}"
  ensure_opencode_pod || { fail "(b) ${OC_POD} is not Ready"; break; }
  OUT="${WORK}/tool-${ATTEMPT}.out"; ERR="${WORK}/tool-${ATTEMPT}.err"
  : > "${OUT}"; : > "${ERR}"
  timeout 120 "${KUBECTL[@]}" exec -n "${NS}" "${OC_POD}" -c parent -- \
    python3 /app/parent.py tool '{"task":"verify-exit-hooks: read dataset A","dataset":"A"}' > "${OUT}" 2> "${ERR}" &
  EXEC_PID=$!
  if ! await_chain "${ERR}"; then
    fail "(b) the tool never logged 'delegation created'"
    indent < "${ERR}" | tail -20
    kill "${EXEC_PID}" 2>/dev/null; wait "${EXEC_PID}" 2>/dev/null
    break
  fi
  PARENT_UID="$("${KUBECTL[@]}" get pod "${OC_POD}" -n "${NS}" -o jsonpath='{.metadata.uid}')"
  if ! catch_midcycle; then
    note "the child (${CHILD_POD:-none}) was already ${CHILD_PHASE:-missing}; this attempt would not exercise the hook, trying again"
    wait "${EXEC_PID}" 2>/dev/null
    continue
  fi
  note "chain_id=${CHAIN} child=${CHILD_ID}; child pod ${CHILD_POD} is ${CHILD_PHASE}; deleting ${OC_POD} (uid ${PARENT_UID}) now"
  T_DELETE="$(date +%s)"
  "${KUBECTL[@]}" delete pod "${OC_POD}" -n "${NS}" --wait=true --timeout=90s 2>&1 | indent
  wait "${EXEC_PID}" 2>/dev/null
  DONE_B=1
  note "the tool's stderr as it ended:"
  grep -E 'disposing delegation|dispose responded|tool (cycle|error)|cycle error' "${ERR}" | indent
  if [ -s "${OUT}" ]; then note "the tool's stdout result line: $(head -c 400 "${OUT}")"; else note "the tool printed no result line (its exec session ended with the pod)"; fi
  # The disposal checks read through the OpenCode pod, so it comes back first.
  ensure_opencode_pod || fail "(b) ${OC_POD} did not come back Ready after the deletion"
  disposal_checks "(b) OpenCode parent" "${OC_ID}" "${T_DELETE}"
  owner_checks "(c) OpenCode parent's child" "${OC_POD}" "${PARENT_UID}" "${T_DELETE}"
  break
done
if [ "${DONE_B}" != 1 ]; then fail "(b) no attempt caught the tool mid-cycle with a running child"; fi

ensure_opencode_pod \
  && pass "(b) ${OC_POD} was recreated and is Ready" \
  || fail "(b) ${OC_POD} is not Ready after the run"

# ---------------------------------------------------------------------------
printf '\n'
if [ "${FAILURES}" -eq 0 ]; then
  printf '\033[32m================ VERIFY-EXIT-HOOKS: PASS (%d steps) ================\033[0m\n' "${CHECK_NO}"
  printf 'A parent deleted mid-cycle disposes its delegation before it goes:\n'
  printf '  demo parent (PID 1 SIGTERM handler): dispose event, revoked record, no entry, no grant\n'
  printf '  OpenCode parent (preStop -> stop-tools -> tool handler): same\n'
  printf '  each child pod carried an ownerReference to its parent pod and was garbage-collected\n'
  exit 0
else
  printf '\033[31m================ VERIFY-EXIT-HOOKS: FAIL (%d failed check(s)) ================\033[0m\n' "${FAILURES}"
  exit 1
fi
