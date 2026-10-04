# Live walkthrough: identity vending and uniqueness (manual, copy-paste)

Companion to `src/deploy/scripts/demo-identity-uniqueness.sh` (the automated,
asserting version — run `make -C src/deploy demo-identity-uniqueness` for
that one). This file is for a HUMAN presenter typing commands live, one block
at a time, so an audience sees each artifact appear individually rather than
a script printing a wall of PASS lines.

Everything below drives the REAL, live stack: the vending service, the SPIRE
Entry API, and the policy engine. Nothing here is a mock. The "parent" is the
`experiments-parent` fixture
pod, which already holds a real SPIRE identity
(`spiffe://lab.local/agent/parent/exp-root`) with all three resource scopes
(`manifests/policy-engine/36-policy-engine-bootstrap.yaml`) — no new
manifests or SPIRE entries are needed to run this.

## 0. Prerequisites (once)

```bash
make -C src/deploy cluster-up
make -C src/deploy spire-up
make -C src/deploy vending-service-up
make -C src/deploy resource-up
make -C src/deploy experiments-fixtures-up
```

## 1. Set up your shell

```bash
export CLUSTER_NAME=nhi-lab
export KUBECTX=kind-${CLUSTER_NAME}
export PARENT_ID="spiffe://lab.local/agent/parent/exp-root"

# The pod playing the parent role — a real, running workload with its own
# SPIRE-attested identity, not a human-typed credential.
PARENT_POD=$(kubectl --context "$KUBECTX" get pods -n agents \
  -l app=experiments-parent --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}')
echo "parent pod: $PARENT_POD"

# Shorthand: every command below runs the SAME binary (cmd/parentsim)
# inside that pod, exactly the way a real parent agent would call
# out to the vending service — kubectl exec here stands in for "the parent
# process itself is making this call from inside its own pod."
exec_p() { kubectl --context "$KUBECTX" exec -n agents "$PARENT_POD" -c parentsim -- "$@"; }
```

## 2. Show the parent's own identity

```bash
exec_p /parentsim whoami
```
Expect: `{"spiffe_id":"spiffe://lab.local/agent/parent/exp-root"}`

**Narration:** this is the ONE identity every child below will be vended
from. Nothing forges or assumes an identity — this came from SPIRE's own
Workload API, inside the pod, via PSAT node attestation + the k8s workload
attestor.

## 3. Vend the first child ("alpha")

```bash
exec_p /parentsim vend \
  -child-path-hint=child/demo-alpha \
  -scopes=resource:read:datasetA \
  -task-context="live demo: child alpha" \
  -selectors="k8s:ns=agents,k8s:sa=demo-child-alpha" \
  -ttl=300
```

Expect `HTTP 201` (on stderr) and a JSON body on stdout shaped like:
```json
{"chain_id":"c_xxxxxxxx...","parent_spiffe_id":"spiffe://lab.local/agent/parent/exp-root","child_spiffe_id":"spiffe://lab.local/agent/parent/exp-root/child/demo-alpha","child_scopes":["resource:read:datasetA"],"entry_id":"...","policy_id":"nhi_grants_c_xxxxxxxx...","issued_at":...,"expires_at":...}
```

**Narration:** point at `chain_id`, `child_spiffe_id`, and `policy_id` —
three identifiers minted fresh, right now, by this one request.

```bash
# Capture the three identifiers for later steps.
ALPHA_CHAIN=<paste chain_id here>
ALPHA_CHILD="spiffe://lab.local/agent/parent/exp-root/child/demo-alpha"
```

## 4. Vend a SECOND child ("beta") from the exact same parent pod

```bash
exec_p /parentsim vend \
  -child-path-hint=child/demo-beta \
  -scopes=resource:read:datasetB \
  -task-context="live demo: child beta" \
  -selectors="k8s:ns=agents,k8s:sa=demo-child-beta" \
  -ttl=300
```

```bash
BETA_CHAIN=<paste chain_id here>
BETA_CHILD="spiffe://lab.local/agent/parent/exp-root/child/demo-beta"
```

**Narration:** same parent pod, same command, one flag changed
(`child-path-hint`/`scopes`) — and every identifier that came back is
different from alpha's. This is the point: uniqueness isn't something the
parent has to construct or promise, it falls out of a fresh delegation every
time.

## 5. Prove uniqueness against three independent sources of truth

**5a. The vending service's own bookkeeping** — each chain_id is its own
independently addressable record:
```bash
exec_p /parentsim get -chain-id="$ALPHA_CHAIN"
exec_p /parentsim get -chain-id="$BETA_CHAIN"
```
Compare the two JSON bodies side by side — different `child_spiffe_id`,
different `policy_id`, different `entry_id`.

**5b. SPIRE's own registration entries** — one per child, each with its own
Entry ID:
```bash
kubectl --context "$KUBECTX" exec -n spire spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server entry show -spiffeID "$ALPHA_CHILD"

kubectl --context "$KUBECTX" exec -n spire spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server entry show -spiffeID "$BETA_CHILD"
```
Point out: different `Entry ID`, different `SPIFFE ID`, SAME `Parent ID`
(the node alias, `spiffe://lab.local/node/nhi-lab`) — the node
alias is shared infrastructure; the child identity is not.

**5c. The audit trail** — every vend is its own event, attributable to this
one chain_id:
```bash
kubectl --context "$KUBECTX" logs -n nhi -l app=vending-service -c vending-service --tail=20 \
  | grep '^{' | jq -c 'select(.stage=="vend")'
```
Point out the two most recent lines: same `actor_spiffe_id` (the vending
service itself, since it's the one recording the event) but different
`chain_id` and `detail`.

## 6. Dispose one child, show the other is untouched

```bash
exec_p /parentsim dispose -chain-id="$ALPHA_CHAIN"

# alpha is gone:
kubectl --context "$KUBECTX" exec -n spire spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server entry show -spiffeID "$ALPHA_CHILD"
#   -> no entry

# beta is still fully live:
kubectl --context "$KUBECTX" exec -n spire spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server entry show -spiffeID "$BETA_CHILD"
#   -> entry still present
exec_p /parentsim get -chain-id="$BETA_CHAIN"
#   -> record still readable, not revoked
```

**Narration:** disposal is scoped to exactly one delegation — the
`chain_id`/`policy_id` pairing is precise enough that removing one child's
identity and grant leaves every sibling delegation, from the very same
parent, completely unaffected.

## 7. Clean up

```bash
exec_p /parentsim dispose -chain-id="$BETA_CHAIN"
```

---

For a scripted, asserting version of exactly this flow (safe to re-run any
number of times, uses random nonces, exits non-zero on any mismatch), see
`make -C src/deploy demo-identity-uniqueness`
(`src/deploy/scripts/demo-identity-uniqueness.sh`).
