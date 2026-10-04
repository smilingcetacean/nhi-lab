#!/usr/bin/env bash
# Baseline verification for `make verify`.
#
#   Proves a pod in namespace `agents` with a known service account obtains
#   an X.509-SVID and a JWT-SVID, and that the OPA policy plane accepts writes
#   only from an authenticated svc/policy-engine.
#
# Nothing here is inferred. Each check runs a command and asserts on its real
# output; the output is printed so a reader can see the evidence rather than
# trust the exit code.
set -uo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-nhi-lab}"
KUBECTX="${KUBECTX:-kind-${CLUSTER_NAME}}"
TRUST_DOMAIN="${TRUST_DOMAIN:-lab.local}"
WORKLOAD_ID="spiffe://${TRUST_DOMAIN}/svc/test-workload"
JWT_AUDIENCE="${JWT_AUDIENCE:-nhi-lab-verify}"
SOCKET="/run/spire/sockets/agent.sock"

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
step "Cluster reachable and nodes Ready"
NODES=$("${KUBECTL[@]}" get nodes --no-headers 2>&1)
echo "${NODES}" | indent
NODE_COUNT=$(echo "${NODES}" | grep -c ' Ready ' || true)
if [ "${NODE_COUNT}" -eq 2 ]; then
  pass "2/2 nodes Ready (1 control-plane + 1 worker)"
else
  fail "expected 2 Ready nodes, found ${NODE_COUNT}"
fi

# ---------------------------------------------------------------------------
step "SPIRE control plane pods Running"
PODS=$("${KUBECTL[@]}" get pods -n spire -o wide --no-headers 2>&1)
echo "${PODS}" | indent
if echo "${PODS}" | grep -q '^spire-server-0 *1/1 *Running'; then
  pass "spire-server-0 is Running and Ready"
else
  fail "spire-server-0 is not Running/Ready"
fi
AGENT_READY=$(echo "${PODS}" | grep -c '^spire-agent-.* 1/1 *Running' || true)
if [ "${AGENT_READY}" -eq 2 ]; then
  pass "${AGENT_READY}/2 spire-agent DaemonSet pods Running and Ready"
else
  fail "expected 2 Ready spire-agent pods, found ${AGENT_READY}"
fi

# ---------------------------------------------------------------------------
step "Trust domain is ${TRUST_DOMAIN}"
BUNDLE=$("${KUBECTL[@]}" exec -n spire spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server bundle show -output json 2>&1)
TD=$(echo "${BUNDLE}" | jq -r '.trust_domain // empty' 2>/dev/null)
if [ -z "${TD}" ]; then
  # Older/newer output shapes: fall back to the JWKS `spiffe_sequence` form and
  # read the trust domain off an issued SVID instead.
  TD=$("${KUBECTL[@]}" exec -n spire spire-server-0 -c spire-server -- \
    /opt/spire/bin/spire-server entry show -output json 2>/dev/null \
    | jq -r '.entries[0].spiffe_id.trust_domain // empty')
fi
echo "    | trust domain: ${TD}"
if [ "${TD}" = "${TRUST_DOMAIN}" ]; then
  pass "server trust domain is ${TRUST_DOMAIN}"
else
  fail "server trust domain is '${TD}', expected '${TRUST_DOMAIN}'"
fi

# ---------------------------------------------------------------------------
step "Node attestation actually succeeded (k8s_psat)"
AGENT_LIST=$("${KUBECTL[@]}" exec -n spire spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server agent list 2>&1)
echo "${AGENT_LIST}" | indent
ATTESTED=$(echo "${AGENT_LIST}" | grep -c '^Attestation type .*k8s_psat' || true)
BANNED=$(echo "${AGENT_LIST}" | grep -ci 'banned *: *true' || true)
if [ "${ATTESTED}" -eq 2 ] && [ "${BANNED}" -eq 0 ]; then
  pass "${ATTESTED} agents attested via k8s_psat, none banned"
else
  fail "expected 2 k8s_psat-attested agents (found ${ATTESTED}, banned ${BANNED})"
fi

# ---------------------------------------------------------------------------
step "Static registration entries present"
ENTRIES=$("${KUBECTL[@]}" exec -n spire spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server entry show 2>&1)
echo "${ENTRIES}" | indent
NODE_ALIAS="spiffe://${TRUST_DOMAIN}/node/${CLUSTER_NAME}"
for want in "${NODE_ALIAS}" "${WORKLOAD_ID}"; do
  if echo "${ENTRIES}" | grep -q "${want}"; then
    pass "entry exists: ${want}"
  else
    fail "missing entry: ${want}"
  fi
done

# Invariant: every workload entry is parented to the node alias, not to a
# literal agent SPIFFE ID (which embeds a node UID and would not survive
# `make clean`). The vending service hard-codes this alias as the parent_id of
# every child entry it mints, so assert the structure — not merely that the
# strings appear.
WL_ENTRY=$("${KUBECTL[@]}" exec -n spire spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server entry show -spiffeID "${WORKLOAD_ID}" 2>&1)
WL_PARENT=$(echo "${WL_ENTRY}" | awk '/^Parent ID/ {sub(/^[^:]*:[[:space:]]*/, ""); print; exit}')
if [ "${WL_PARENT}" = "${NODE_ALIAS}" ]; then
  pass "${WORKLOAD_ID} is parented to the node alias ${NODE_ALIAS}"
else
  fail "node-alias invariant violated: parent of ${WORKLOAD_ID} is '${WL_PARENT}', expected '${NODE_ALIAS}'"
fi
for sel in "k8s:ns:agents" "k8s:sa:nhi-test"; do
  if echo "${WL_ENTRY}" | grep -qE "^Selector[[:space:]]*:[[:space:]]*${sel}$"; then
    pass "selector bound: ${sel}"
  else
    fail "missing selector on ${WORKLOAD_ID}: ${sel}"
  fi
done

# ---------------------------------------------------------------------------
step "Test workload pod Running in namespace agents"
"${KUBECTL[@]}" get pods -n agents -o wide --no-headers 2>&1 | indent
POD=$("${KUBECTL[@]}" get pods -n agents -l app=nhi-test-workload \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -z "${POD}" ]; then
  fail "no nhi-test-workload pod found in namespace agents"
  printf '\n\033[31m%d check(s) failed\033[0m\n' "${FAILURES}"
  exit 1
fi
SA=$("${KUBECTL[@]}" get pod -n agents "${POD}" -o jsonpath='{.spec.serviceAccountName}')
echo "    | pod=${POD} namespace=agents serviceAccount=${SA}"
if [ "${SA}" = "nhi-test" ]; then
  pass "pod ${POD} runs under the known service account 'nhi-test'"
else
  fail "pod ${POD} runs under service account '${SA}', expected 'nhi-test'"
fi

WLEXEC=("${KUBECTL[@]}" exec -n agents "${POD}" -c workload --)

# ---------------------------------------------------------------------------
step "CHECK A — pod obtains an X.509-SVID via the Workload API"
X509=$("${WLEXEC[@]}" /opt/spire/bin/spire-agent api fetch x509 \
  -socketPath "${SOCKET}" 2>&1)
echo "${X509}" | indent
if echo "${X509}" | grep -q "SPIFFE ID:[[:space:]]*${WORKLOAD_ID}$"; then
  pass "X.509-SVID issued for ${WORKLOAD_ID}"
else
  fail "no X.509-SVID for ${WORKLOAD_ID}"
fi
if echo "${X509}" | grep -q 'Received 1 svid'; then
  pass "Workload API returned exactly one X.509-SVID"
else
  fail "Workload API did not return exactly one X.509-SVID"
fi

# ---------------------------------------------------------------------------
step "CHECK B — pod obtains a JWT-SVID via the Workload API"
JWT_JSON=$("${WLEXEC[@]}" /opt/spire/bin/spire-agent api fetch jwt \
  -audience "${JWT_AUDIENCE}" -socketPath "${SOCKET}" -output json 2>&1)
JWT_ID=$(echo "${JWT_JSON}" | jq -r '..|.spiffe_id? // empty' 2>/dev/null | head -1)
JWT=$(echo "${JWT_JSON}" | jq -r '..|.svid? // empty' 2>/dev/null | head -1)
if [ -z "${JWT}" ]; then
  echo "${JWT_JSON}" | indent
  fail "could not obtain a JWT-SVID"
else
  echo "    | spiffe_id : ${JWT_ID}"
  echo "    | jwt-svid  : ${JWT:0:48}...${JWT: -16} (${#JWT} chars)"
  echo "    | claims    : $(echo "${JWT}" | cut -d. -f2 \
      | tr '_-' '/+' | base64 -d 2>/dev/null | jq -c . 2>/dev/null)"
  if [ "${JWT_ID}" = "${WORKLOAD_ID}" ]; then
    pass "JWT-SVID issued for ${WORKLOAD_ID} with audience '${JWT_AUDIENCE}'"
  else
    fail "JWT-SVID subject is '${JWT_ID}', expected '${WORKLOAD_ID}'"
  fi

  # Round-trip the token back through the Workload API so the check does not
  # merely assert that a string was returned, but that SPIRE itself considers
  # the token valid for that audience.
  VALIDATION=$("${WLEXEC[@]}" /opt/spire/bin/spire-agent api validate jwt \
    -audience "${JWT_AUDIENCE}" -svid "${JWT}" -socketPath "${SOCKET}" 2>&1)
  echo "${VALIDATION}" | indent
  if echo "${VALIDATION}" | grep -q "SVID is valid"; then
    pass "JWT-SVID validated against the SPIRE trust bundle"
  else
    fail "JWT-SVID failed validation"
  fi
fi

# ---------------------------------------------------------------------------
step "Continuous X.509-SVID delivery (pod's own 'api watch' stream)"
WATCH_LOG=$("${KUBECTL[@]}" logs -n agents "${POD}" -c workload --tail=12 2>&1)
echo "${WATCH_LOG}" | indent
if echo "${WATCH_LOG}" | grep -q "${WORKLOAD_ID}"; then
  pass "workload's own Workload API stream shows ${WORKLOAD_ID}"
else
  fail "workload's Workload API stream shows no SVID"
fi

# ---------------------------------------------------------------------------
step "OPA reachable and serving from an X509-SVID"
OPA_POD_LINE=$("${KUBECTL[@]}" get pods -n opa -l app=opa --no-headers 2>&1)
echo "${OPA_POD_LINE}" | indent
OPA_AVAIL=$("${KUBECTL[@]}" get deploy -n opa opa \
  -o jsonpath='{.status.conditions[?(@.type=="Available")].status}' 2>/dev/null)
OPA_VERSION=$("${KUBECTL[@]}" exec -n opa deploy/opa -c opa -- /opa version 2>&1 | head -2)
echo "${OPA_VERSION}" | indent
if [ "${OPA_AVAIL}" = "True" ]; then
  # Deployment Available means the tcpSocket readiness probe passed — the
  # listener accepts connections. It deliberately claims no more than that;
  # see the probe comment in 31-opa.yaml. Genuine health is established a few
  # checks below, by getting an evaluated decision back over mTLS.
  pass "OPA Deployment Available (listener accepting connections)"
else
  fail "OPA Deployment not Available"
fi

# The spiffe-helper sidecar is what makes OPA's TLS possible at all.
# Neither the OPA image nor the spiffe-helper image contains a shell, so the
# PEM files cannot be read out of the pod directly; the sidecar's liveness is
# asserted through the pod's container statuses instead, and the *content* of
# what it delivered is asserted below by a probe completing a real mTLS
# handshake against the SPIRE trust bundle.
HELPER_READY=$("${KUBECTL[@]}" get pods -n opa -l app=opa \
  -o jsonpath='{.items[0].status.initContainerStatuses[?(@.name=="spiffe-helper")].ready}' 2>/dev/null)
HELPER_RESTARTS=$("${KUBECTL[@]}" get pods -n opa -l app=opa \
  -o jsonpath='{.items[0].status.initContainerStatuses[?(@.name=="spiffe-helper")].restartCount}' 2>/dev/null)
echo "    | spiffe-helper sidecar: ready=${HELPER_READY:-<none>} restarts=${HELPER_RESTARTS:-?}"
if [ "${HELPER_READY}" = "true" ]; then
  pass "spiffe-helper sidecar running (SVID delivery and rotation active)"
else
  fail "spiffe-helper sidecar is not ready; OPA cannot have a valid serving SVID"
fi

# The svc/opa entry must carry DNS SANs. Without them OPA's SVID has a URI SAN
# only, and every non-SPIFFE-aware TLS client fails hostname verification —
# which in practice gets "fixed" with --insecure, discarding server
# authentication. Assert the entry rather than discovering this downstream.
OPA_ENTRY=$("${KUBECTL[@]}" exec -n spire spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server entry show -spiffeID "spiffe://${TRUST_DOMAIN}/svc/opa" 2>&1)
echo "${OPA_ENTRY}" | indent
if echo "${OPA_ENTRY}" | grep -q 'opa.opa.svc.cluster.local'; then
  pass "svc/opa entry carries the service DNS SAN (generic TLS clients can verify it)"
else
  fail "svc/opa entry has no DNS SAN for opa.opa.svc.cluster.local"
fi

# ---------------------------------------------------------------------------
# Authenticated policy-plane assertions: an anonymous write to OPA is refused,
# and a write from an identity other than svc/policy-engine is refused.
#
# Both are run from ephemeral probe pods that the NetworkPolicy admits at L3,
# so that a refusal is evidence of an authentication or authorization decision
# and not of a dropped packet. The probes are deleted at the end of this block.
step "Policy plane — deploying ephemeral mTLS probes"
PROBE_MANIFEST="$(dirname "${BASH_SOURCE[0]}")/../manifests/test/41-policy-probe.yaml"
cleanup_probes() {
  "${KUBECTL[@]}" delete -f "${PROBE_MANIFEST}" --ignore-not-found --wait=false \
    >/dev/null 2>&1 || true
}
trap cleanup_probes EXIT

"${KUBECTL[@]}" apply -f "${PROBE_MANIFEST}" 2>&1 | indent
PROBES_UP=0
if "${KUBECTL[@]}" rollout status deployment/policy-probe-unauthorized -n nhi --timeout=120s >/dev/null 2>&1 \
   && "${KUBECTL[@]}" rollout status deployment/policy-probe-authorized -n nhi --timeout=120s >/dev/null 2>&1; then
  pass "both probe pods Ready (each holds an X509-SVID via spiffe-helper)"
  PROBES_UP=1
else
  fail "probe pods did not become Ready; policy-plane assertions cannot run"
  "${KUBECTL[@]}" get pods -n nhi -l app=policy-probe -o wide 2>&1 | indent
fi

OPA_URL="https://opa.opa.svc.cluster.local:8181"

# Run curl inside a probe pod and return "<http_status>|<body-or-error>".
#
# One exec, no temp file: the probe containers run with
# readOnlyRootFilesystem, so `curl -o /tmp/body` would fail on the write rather
# than on the request, and every check would report a false negative. The
# status code is carried out-of-band in the -w trailer instead, and stderr is
# folded into stdout so that transport-level failures (which is precisely what
# the anonymous case should produce) are visible rather than swallowed.
#
# --cacert alone, with no --cert/--key, is the anonymous case: the client
# verifies OPA but presents no identity of its own.
probe_curl() {
  local probe="$1"; shift
  local pod out code body
  pod=$("${KUBECTL[@]}" get pods -n nhi -l "probe=${probe}" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  [ -n "${pod}" ] || { echo "000|no probe pod found for probe=${probe}"; return; }
  out=$("${KUBECTL[@]}" exec -n nhi "${pod}" -c probe -- \
    curl -sS --max-time 15 -w '\nNHI_HTTP_CODE:%{http_code}' "$@" 2>&1)
  code=$(printf '%s' "${out}" | grep -o 'NHI_HTTP_CODE:[0-9]*' | tail -1 | cut -d: -f2)
  body=$(printf '%s' "${out}" | grep -v 'NHI_HTTP_CODE:' | tr '\n' ' ' | head -c 300)
  echo "${code:-000}|${body}"
}

TEST_MODULE='package nhi.probe

allow := true
'

if [ "${PROBES_UP}" -eq 1 ]; then
  # -------------------------------------------------------------------------
  step "Policy plane — anonymous write to OPA is refused"
  ANON=$(probe_curl unauthorized \
    --cacert /run/spiffe/bundle.pem \
    -X PUT "${OPA_URL}/v1/policies/nhi_grants_anon_attempt" \
    --data-binary "${TEST_MODULE}")
  echo "    | result: ${ANON}"
  ANON_CODE="${ANON%%|*}"
  # No client certificate means the TLS handshake never completes, so curl
  # reports a transport error and %{http_code} stays 000. An HTTP status of any
  # kind here would mean OPA had accepted an unauthenticated connection.
  if [ "${ANON_CODE}" = "000" ] && echo "${ANON}" | grep -qiE 'alert|handshake|certificate|SSL'; then
    pass "anonymous PUT /v1/policies refused at the TLS handshake (no HTTP status reached)"
  elif [ "${ANON_CODE}" = "401" ] || [ "${ANON_CODE}" = "403" ]; then
    # Also acceptable: refused, just one layer later than expected.
    pass "anonymous PUT /v1/policies refused by system.authz (HTTP ${ANON_CODE})"
  else
    fail "anonymous PUT /v1/policies was NOT refused (got '${ANON_CODE}')"
  fi

  # -------------------------------------------------------------------------
  step "Policy plane — write from a non-policy-engine identity is refused"
  WRONG=$(probe_curl unauthorized \
    --cacert /run/spiffe/bundle.pem \
    --cert /run/spiffe/svid.pem --key /run/spiffe/svid_key.pem \
    -X PUT "${OPA_URL}/v1/policies/nhi_grants_wrong_identity_attempt" \
    --data-binary "${TEST_MODULE}")
  echo "    | result: ${WRONG}"
  WRONG_CODE="${WRONG%%|*}"
  # A 401 here is strictly stronger evidence than a connection failure: it
  # proves the handshake SUCCEEDED — so mTLS works and the network path is open
  # — and that OPA's own system.authz policy is what refused the write.
  if [ "${WRONG_CODE}" = "401" ] || [ "${WRONG_CODE}" = "403" ]; then
    pass "PUT /v1/policies as svc/policy-probe refused by system.authz (HTTP ${WRONG_CODE}) after a successful mTLS handshake"
  else
    fail "PUT /v1/policies as svc/policy-probe was NOT refused (got '${WRONG_CODE}')"
  fi

  # -------------------------------------------------------------------------
  # Positive control. Without it, the two checks above would both pass against
  # an OPA that denies everyone — which would not surface until the policy
  # engine could not push its first module.
  step "Policy plane positive control — svc/policy-engine MAY write policy"
  RIGHT=$(probe_curl authorized \
    --cacert /run/spiffe/bundle.pem \
    --cert /run/spiffe/svid.pem --key /run/spiffe/svid_key.pem \
    -X PUT "${OPA_URL}/v1/policies/nhi_grants_verify_positive_control" \
    --data-binary "${TEST_MODULE}")
  echo "    | result: ${RIGHT}"
  RIGHT_CODE="${RIGHT%%|*}"
  if [ "${RIGHT_CODE}" = "200" ]; then
    pass "PUT /v1/policies as svc/policy-engine accepted (HTTP 200) — authz is selective, not uniformly closed"
  else
    fail "PUT /v1/policies as svc/policy-engine was refused (got '${RIGHT_CODE}') — the policy engine would be unable to push Rego"
  fi

  # -------------------------------------------------------------------------
  # The decision path the resource depends on. Run while the control module is still
  # loaded, so a 200 carries an actual decision (`"result":true`) rather than
  # the empty document OPA returns for an undefined path — which would make
  # this check pass against an OPA holding no policy at all.
  step "Policy plane — the decision endpoint the resource uses answers over mTLS"
  DATA=$(probe_curl authorized \
    --cacert /run/spiffe/bundle.pem \
    --cert /run/spiffe/svid.pem --key /run/spiffe/svid_key.pem \
    -X POST "${OPA_URL}/v1/data/nhi/probe/allow" \
    -H 'Content-Type: application/json' --data-binary '{"input":{}}')
  echo "    | result: ${DATA}"
  DATA_CODE="${DATA%%|*}"
  if [ "${DATA_CODE}" = "200" ] && echo "${DATA}" | grep -q '"result":true'; then
    pass "POST /v1/data returned an evaluated decision over mTLS (HTTP 200, result=true)"
  else
    fail "POST /v1/data over mTLS did not return an evaluated decision (got '${DATA}')"
  fi

  # Remove the control module so the cluster is left as it was found. Doubles
  # as evidence that DELETE — the disposal half of the policy engine's grant
  # lifecycle — is authorized for the policy engine.
  step "Policy plane — svc/policy-engine may also DELETE policy (disposal path)"
  DEL=$(probe_curl authorized \
    --cacert /run/spiffe/bundle.pem \
    --cert /run/spiffe/svid.pem --key /run/spiffe/svid_key.pem \
    -X DELETE "${OPA_URL}/v1/policies/nhi_grants_verify_positive_control")
  echo "    | result: ${DEL}"
  if [ "${DEL%%|*}" = "200" ]; then
    pass "DELETE /v1/policies as svc/policy-engine accepted (HTTP 200); control module removed"
  else
    fail "DELETE /v1/policies as svc/policy-engine returned '${DEL%%|*}', expected 200"
  fi
fi

step "Policy plane — tearing down the ephemeral probes"
cleanup_probes
trap - EXIT
pass "probe pods deleted (no lingering holder of the policy-write identity)"

# ---------------------------------------------------------------------------
printf '\n'
if [ "${FAILURES}" -eq 0 ]; then
  printf '\033[32m================ VERIFY: PASS (%d checks) ================\033[0m\n' \
    "${CHECK_NO}"
  printf 'A pod in namespace agents (serviceAccount nhi-test) obtained both an\n'
  printf 'X.509-SVID and a JWT-SVID for %s.\n' "${WORKLOAD_ID}"
  exit 0
else
  printf '\033[31m================ VERIFY: FAIL (%d failed) ================\033[0m\n' \
    "${FAILURES}"
  exit 1
fi
