#!/usr/bin/env python3
"""Parent agent.

Runs in a pod in namespace `agents`, authenticated by a REAL SPIRE
registration entry — spiffe://lab.local/agent/parent/demo for `make demo`,
spiffe://lab.local/agent/parent/opencode for the OpenCode parent pod that
calls the `tool` subcommand (see src/deploy/scripts/register-entries.sh and
manifests/policy-engine/36-policy-engine-bootstrap.yaml for their bootstrap
Π(P)) — exactly like the vending-test-parent fixture and cmd/parentsim.
Unlike verify-vending.sh (which pre-creates its child pod as a scripting
shortcut), the child pod here is created ONLY
AFTER the vending service has minted its SPIRE registration entry, so "the
child obtains its own identity with no human action" describes the child's
own spawn, not merely its identity issuance into a pod that already existed.

One full cycle, no negative-test branches (those live in src/experiments,
not this harness):

  1. fetch this pod's own X.509-SVID and a JWT-SVID (aud=vending service)
     from the Workload API — no pre-shared secret, no human action.
  2. decide_to_fork(): the SCRIPTED fork decision. This is the labeled seam
     where a real agent framework — an LLM given the parent's
     task context and asked whether/how to delegate — plugs in. The `tool`
     subcommand (below) is that plug-in: it supplies the decision instead.
     Nothing below this function changes for that: run_cycle() consumes
     exactly the shape decide_to_fork() returns.
  3. build + sign the spawn manifest (manifest.py), POST it to the
     vending service.
  4. create the child pod via the k8s API, using the EXACT selectors
     promised in the manifest (k8s:ns, k8s:pod-name — the pod does not exist
     until this step).
  5. wait for the child to finish its task.
  6. trigger disposal (DELETE /delegations/{chain_id}).

When the environment variable POD_IP is set, step 4 is preceded by opening an
mTLS listener on POD_IP:CALLBACK_PORT that accepts exactly the vended child's
SPIFFE ID, and the child sends its result straight back over it (see
common.CallbackListener). Without POD_IP the callback is off, which is how
`make demo` runs.

Two entry points:

  python3 parent.py                 the scripted demo cycle (`make demo`)
  python3 parent.py tool '<json>'   one cycle for a task the caller chose:
                                    {"task": "<free text>", "dataset": "A"|"B"}
                                    prints exactly one result JSON line on
                                    stdout; narration and (absent
                                    NHI_AUDIT_SINK) audit events go to stderr.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config

import common
import manifest as manifest_mod


def env(key: str, default: str) -> str:
    return os.environ.get(key, default)


def decide_to_fork(own_spiffe_id: str) -> dict:
    """THE SEAM: the parent's decision to spawn a child and what to ask for
    on its behalf. Scripted here — a fixed task, a fixed scope request, a
    fixed TTL — because LLM-driven forking is deliberately deferred (the
    stub policy engine has the same shape of deferral on the authorization
    side). A real agent framework would replace only this
    function's BODY: given the parent's own task/context, decide whether to
    fork at all, what sub-task to hand the child, and what scopes that
    sub-task plausibly needs. Everything downstream — signing, vending,
    child-pod creation, disposal — is mechanism, not policy, and does not
    change.

    Returns a plain dict, not a manifest.SpawnManifest, deliberately: this
    is the boundary an agent framework would call across, so its return
    shape should be framework-agnostic (JSON-able), not tied to this
    harness's internal signing types.

    The `tool` subcommand (tool_main) is where an LLM-driven agent now supplies
    the decision: it chooses only the free-text task and the dataset, and the
    harness builds the rest of this same dict (pod name, selectors, TTL, the
    requested scope derived from the dataset). This scripted body remains what
    `make demo` runs.
    """
    child_pod_name = manifest_mod.new_child_pod_name()
    return {
        "child_path_hint": f"child/{child_pod_name}",
        "child_pod_name": child_pod_name,
        "requested_scopes": env("REQUESTED_SCOPES", "resource:read:datasetA").split(","),
        "task_context": env("TASK_CONTEXT", "demo: read datasetA on the parent's behalf"),
        "ttl_seconds": int(env("TTL_SECONDS", "300")),
        "child_selectors": {"k8s:ns": env("CHILD_NAMESPACE", "agents"), "k8s:pod-name": child_pod_name},
        "dataset_path": env("DATASET_PATH", "/datasets/A"),
        "reason": "scripted fork decision (decide_to_fork seam)",
    }


def build_and_sign_manifest(decision: dict, own_id: str, svid) -> manifest_mod.SpawnManifest:
    m = manifest_mod.SpawnManifest(
        parent_spiffe_id=own_id,
        child_path_hint=decision["child_path_hint"],
        requested_scopes=decision["requested_scopes"],
        task_context=decision["task_context"],
        child_selectors=decision["child_selectors"],
        ttl_seconds=decision["ttl_seconds"],
    )
    m.signature = manifest_mod.sign_manifest(m, svid.private_key, svid.cert_chain)
    return m


def create_child_pod(
    v1: k8s_client.CoreV1Api,
    *,
    namespace: str,
    pod_name: str,
    chain_id: str,
    dataset_path: str,
    callback_addr: str | None = None,
) -> None:
    child_env = [
        k8s_client.V1EnvVar(name="RESOURCE_URL", value=env("RESOURCE_URL", "http://resource.nhi.svc.cluster.local:8080")),
        k8s_client.V1EnvVar(name="RESOURCE_AUDIENCE", value=env("RESOURCE_AUDIENCE", "spiffe://lab.local/svc/resource")),
        k8s_client.V1EnvVar(name="DATASET_PATH", value=dataset_path),
        k8s_client.V1EnvVar(name="CHAIN_ID", value=chain_id),
        k8s_client.V1EnvVar(name="SPIFFE_ENDPOINT_SOCKET", value=common.socket_path()),
    ]
    if callback_addr:
        child_env.append(k8s_client.V1EnvVar(name="PARENT_CALLBACK_ADDR", value=callback_addr))
    container = k8s_client.V1Container(
        name="child",
        image=env("AGENTS_IMAGE", "nhi-lab/agents:dev"),
        image_pull_policy="Never",
        command=["python3", "/app/child.py"],
        env=child_env,
        volume_mounts=[k8s_client.V1VolumeMount(name="spire-agent-socket", mount_path="/run/spire/sockets")],
    )
    pod = k8s_client.V1Pod(
        metadata=k8s_client.V1ObjectMeta(
            name=pod_name,
            namespace=namespace,
            labels={"app": "nhi-demo-child", "nhi.chain-id": chain_id},
        ),
        spec=k8s_client.V1PodSpec(
            restart_policy="Never",
            containers=[container],
            volumes=[
                k8s_client.V1Volume(
                    name="spire-agent-socket",
                    host_path=k8s_client.V1HostPathVolumeSource(path="/run/spire/sockets", type="DirectoryOrCreate"),
                )
            ],
        ),
    )
    v1.create_namespaced_pod(namespace=namespace, body=pod)


def wait_for_pod_completion(v1: k8s_client.CoreV1Api, *, namespace: str, pod_name: str, timeout_seconds: int = 120) -> str:
    """Polls until the child pod's phase is Succeeded or Failed (or the
    timeout elapses). Returns the final phase observed."""
    deadline = time.monotonic() + timeout_seconds
    phase = "Unknown"
    while time.monotonic() < deadline:
        # read_namespaced_pod (the pod object itself, .status included), not
        # read_namespaced_pod_status (the pods/status SUBRESOURCE) — the
        # latter needs a separate RBAC grant
        # (manifests/agents/70-demo-parent-rbac.yaml only grants "pods", not
        # "pods/status"), and there is no reason to ask for that extra
        # permission when the same information is on the object this
        # ServiceAccount can already read.
        pod = v1.read_namespaced_pod(name=pod_name, namespace=namespace)
        phase = pod.status.phase or "Unknown"
        if phase in ("Succeeded", "Failed"):
            return phase
        time.sleep(2)
    return phase


CALLBACK_TIMEOUT_SECONDS = 120
TOOL_TASK_MAX_CHARS = 500
TOOL_DATASETS = ("A", "B")
TERMINAL_PHASES = ("Succeeded", "Failed")


def callback_address() -> str | None:
    """POD_IP:CALLBACK_PORT when the mTLS result callback is on (only a parent
    pod that sets POD_IP turns it on), else None."""
    pod_ip = os.environ.get("POD_IP")
    if not pod_ip:
        return None
    return f"{pod_ip}:{env('CALLBACK_PORT', '8443')}"


def new_result(decision: dict) -> dict:
    """The tool-mode result shape; every key is always present."""
    return {
        "ok": False,
        "chain_id": None,
        "child_spiffe_id": None,
        "child_scopes": [],
        "requested_scopes": list(decision["requested_scopes"]),
        "status": None,
        "data": None,
        "returned_via": None,
        "peer_spiffe_id": None,
        "child_pod_phase": None,
        "disposed": False,
        "error": None,
    }


def _callback_event(own_id: str, chain_id: str, outcome: str, kind: str, peer: str | None, reason: str) -> None:
    common.emit_audit_event(
        stage=common.STAGE_OPERATE,
        chain_id=chain_id,
        actor_spiffe_id=own_id,
        outcome=outcome,
        detail={"kind": kind, "peer": peer, "reason": reason},
    )


def wait_for_callback(
    listener: common.CallbackListener,
    v1: k8s_client.CoreV1Api,
    *,
    namespace: str,
    pod_name: str,
    chain_id: str,
    own_id: str,
    timeout_seconds: float,
) -> tuple[dict | None, str | None]:
    """Accepts connections until the authorized child delivers a valid result
    line or the timeout passes. A connection that fails the handshake or
    authorization, or sends garbage, is logged and audited as refused and does
    not end the wait. Returns (result, None) on success, else (None, reason).
    The result is {"status": int, "body": str, "peer": str}."""
    deadline = time.monotonic() + timeout_seconds
    finished_phase: str | None = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            reason = f"no result from the child within {timeout_seconds:.0f}s"
            break
        out = listener.accept_one(min(remaining, 2.0))
        if out["kind"] == "idle":
            if finished_phase is not None:
                # The child had already finished at the previous idle poll, so
                # anything it sent was queued by now and was just drained.
                reason = f"child pod finished (phase={finished_phase}) without delivering a result"
                break
            try:
                phase = v1.read_namespaced_pod(name=pod_name, namespace=namespace).status.phase or "Unknown"
            except Exception as err:  # noqa: BLE001 - a failed poll only costs the early exit
                common.log(f"parent: polling child pod phase failed: {err!r}")
                continue
            if phase in TERMINAL_PHASES:
                finished_phase = phase
            continue
        if out["kind"] == "refused":
            common.log(f"parent: callback refused (peer={out['peer']}): {out['reason']}")
            _callback_event(own_id, chain_id, common.OUTCOME_DENY, "callback_refused", out["peer"], out["reason"])
            continue
        peer = out["peer"]
        try:
            payload = json.loads(out["line"])
            if (
                not isinstance(payload, dict)
                or not isinstance(payload.get("chain_id"), str)
                or not isinstance(payload.get("status"), int)
                or isinstance(payload.get("status"), bool)
                or not isinstance(payload.get("body"), str)
            ):
                raise ValueError("expected {chain_id: str, status: int, body: str}")
        except ValueError as err:
            common.log(f"parent: callback payload from {peer} malformed: {err}")
            _callback_event(own_id, chain_id, common.OUTCOME_DENY, "callback_refused", peer, f"malformed payload: {err}")
            continue
        if payload["chain_id"] != chain_id:
            reason = f"result carries chain_id {payload['chain_id']!r}, expected {chain_id!r}"
            common.log(f"parent: result rejected: {reason}")
            _callback_event(own_id, chain_id, common.OUTCOME_DENY, "result_rejected", peer, reason)
            return None, f"result rejected: {reason}"
        _callback_event(
            own_id, chain_id, common.OUTCOME_ALLOW, "result_returned", peer,
            f"authenticated child returned its result over mTLS (status {payload['status']})",
        )
        return {"status": payload["status"], "body": payload["body"], "peer": peer}, None
    common.log(f"parent: {reason}")
    _callback_event(own_id, chain_id, common.OUTCOME_ERROR, "callback_missing", None, reason)
    return None, reason


def _refusal_reason(resp) -> str:
    """The vending service's stated reason for a refusal, shortened for the
    result line."""
    try:
        body = resp.json()
        text = body.get("reason") or body.get("error") or resp.text
    except (ValueError, AttributeError):
        text = resp.text
    text = str(text).strip()
    return text if len(text) <= 300 else text[:300] + "..."


def run_cycle(decision: dict, *, wl, svid, own_id: str) -> dict:
    """Everything after the fork decision: build and sign the manifest, vend,
    (with POD_IP set) open the mTLS callback listener, create the child pod,
    collect the result, wait for the pod, and dispose. Disposal is attempted
    whenever a delegation exists, however the rest went. Returns the result
    dict (new_result); never raises."""
    res = new_result(decision)
    vending_url = env("VENDING_SERVICE_URL", "http://vending-service.nhi.svc.cluster.local:8090").rstrip("/")
    vending_audience = env("VENDING_AUDIENCE", "spiffe://lab.local/svc/vending-service")
    namespace = env("CHILD_NAMESPACE", "agents")
    session = common.http_session()
    listener: common.CallbackListener | None = None
    try:
        vending_jwt = common.fetch_jwt_svid_retrying(wl, vending_audience)
        m = build_and_sign_manifest(decision, own_id, svid)
        prospective_child_id = m.child_spiffe_id()

        # "spawn" is emitted here, before the vending service has minted a
        # chain_id (chain_id="" — consistent with how the vending service
        # itself represents a pre-vend event; see internal/audit's doc
        # comment) — this IS the parent's fork decision, the one stage no
        # other component emits.
        common.emit_audit_event(
            stage=common.STAGE_SPAWN,
            chain_id="",
            actor_spiffe_id=own_id,
            outcome=common.OUTCOME_ALLOW,
            detail={
                "child_spiffe_id": prospective_child_id,
                "requested_scopes": decision["requested_scopes"],
                "task_context": decision["task_context"],
                "reason": decision.get("reason", "scripted fork decision (decide_to_fork seam)"),
            },
        )

        common.log(f"parent: submitting spawn manifest for prospective child {prospective_child_id}")
        resp = session.post(
            f"{vending_url}/delegations",
            json=m.to_wire(),
            headers=common.bearer_headers(vending_jwt.token),
        )
        common.log(f"parent: vending service responded {resp.status_code}: {resp.text}")
        if resp.status_code != 201:
            common.log("parent: vend failed, aborting — the vending service's own audit event records why")
            res["error"] = f"vend refused: HTTP {resp.status_code}: {_refusal_reason(resp)}"
            return res
        vend = resp.json()
        chain_id = vend["chain_id"]
        child_spiffe_id = vend["child_spiffe_id"]
        res["chain_id"] = chain_id
        res["child_spiffe_id"] = child_spiffe_id
        res["child_scopes"] = list(vend.get("child_scopes") or [])
        common.log(f"parent: delegation created, chain_id={chain_id} child_spiffe_id={child_spiffe_id} child_scopes={vend.get('child_scopes')}")

        # The listener comes up before the pod exists, authorizing exactly the
        # identity just vended.
        callback_addr = callback_address()
        if callback_addr:
            listener = common.CallbackListener(callback_addr, child_spiffe_id)
            common.log(f"parent: mTLS callback listening on {callback_addr}, authorizing only {child_spiffe_id}")

        # --- create the child pod, only now that its identity already exists ---
        k8s_config.load_incluster_config()
        v1 = k8s_client.CoreV1Api()
        pod_name = decision["child_pod_name"]
        common.log(f"parent: creating child pod {namespace}/{pod_name}")
        create_child_pod(
            v1,
            namespace=namespace,
            pod_name=pod_name,
            chain_id=chain_id,
            dataset_path=decision["dataset_path"],
            callback_addr=callback_addr,
        )

        if listener is not None:
            got, why = wait_for_callback(
                listener,
                v1,
                namespace=namespace,
                pod_name=pod_name,
                chain_id=chain_id,
                own_id=own_id,
                timeout_seconds=float(env("CALLBACK_TIMEOUT_SECONDS", str(CALLBACK_TIMEOUT_SECONDS))),
            )
            if got is not None:
                res["returned_via"] = "mtls-callback"
                res["peer_spiffe_id"] = got["peer"]
                res["status"] = got["status"]
                try:
                    res["data"] = json.loads(got["body"])
                except ValueError:
                    res["data"] = got["body"]
            else:
                res["error"] = why

        phase = wait_for_pod_completion(v1, namespace=namespace, pod_name=pod_name)
        res["child_pod_phase"] = phase
        common.log(f"parent: child pod {pod_name} finished with phase={phase}")
    except Exception as err:  # noqa: BLE001 - reported in the result; disposal below still runs
        common.log(f"parent: cycle error: {err!r}")
        res["error"] = res["error"] or f"{type(err).__name__}: {err}"
    finally:
        if listener is not None:
            listener.close()
        if res["chain_id"]:
            # --- disposal ------------------------------------------------------
            # Fetch a fresh JWT-SVID rather than reusing the earlier one — the
            # child's own run may have taken a while, and this mirrors what a
            # real long-lived parent would do rather than assuming its first
            # token is still fresh.
            try:
                dispose_jwt = common.fetch_jwt_svid_retrying(wl, vending_audience)
                common.log(f"parent: disposing delegation {res['chain_id']}")
                dispose_resp = session.delete(
                    f"{vending_url}/delegations/{res['chain_id']}",
                    headers=common.bearer_headers(dispose_jwt.token),
                )
                common.log(f"parent: dispose responded {dispose_resp.status_code}: {dispose_resp.text}")
                res["disposed"] = dispose_resp.status_code == 200
                if not res["disposed"]:
                    res["error"] = res["error"] or f"dispose refused: HTTP {dispose_resp.status_code}"
            except Exception as err:  # noqa: BLE001
                common.log(f"parent: dispose failed: {err!r}")
                res["error"] = res["error"] or f"dispose failed: {type(err).__name__}: {err}"
    return res


def start() -> tuple:
    common.log("parent: fetching own credentials from the Workload API")
    wl = common.new_workload_client()
    svid = common.fetch_x509_svid_retrying(wl)
    own_id = str(svid.spiffe_id)
    common.log(f"parent: own SPIFFE ID = {own_id}")
    return wl, svid, own_id


def main() -> int:
    wl, svid, own_id = start()
    decision = decide_to_fork(own_id)
    res = run_cycle(decision, wl=wl, svid=svid, own_id=own_id)
    ok = res["child_pod_phase"] == "Succeeded" and res["disposed"] and res["error"] is None
    common.log(f"parent: cycle {'COMPLETE' if ok else 'FAILED'}")
    return 0 if ok else 1


# --- tool mode -----------------------------------------------------------------


def parse_tool_args(raw: str) -> tuple[dict | None, str | None]:
    """Strictly validates the tool arguments. Returns (decision inputs, None)
    or (None, why not)."""
    try:
        args = json.loads(raw)
    except ValueError as err:
        return None, f"arguments are not valid JSON: {err}"
    if not isinstance(args, dict):
        return None, "arguments must be a JSON object"
    extra = sorted(set(args) - {"task", "dataset"})
    if extra:
        return None, f"unexpected argument(s): {', '.join(extra)}"
    task, dataset = args.get("task"), args.get("dataset")
    if not isinstance(task, str) or not task.strip():
        return None, "task must be a non-empty string"
    if len(task) > TOOL_TASK_MAX_CHARS:
        return None, f"task must be at most {TOOL_TASK_MAX_CHARS} characters"
    if not isinstance(dataset, str) or dataset not in TOOL_DATASETS:
        return None, "dataset must be exactly \"A\" or \"B\""
    return {"task": task, "dataset": dataset}, None


def decision_from_tool(args: dict, own_spiffe_id: str) -> dict:
    """The tool-mode counterpart of decide_to_fork(): the caller supplies only
    the task and the dataset; the pod name, selectors, TTL and the requested
    scope (derived from the dataset, never taken from the caller) are the
    harness's."""
    child_pod_name = manifest_mod.new_child_pod_name()
    dataset = args["dataset"]
    return {
        "child_path_hint": f"child/{child_pod_name}",
        "child_pod_name": child_pod_name,
        "requested_scopes": [f"resource:read:dataset{dataset}"],
        "task_context": args["task"],
        "ttl_seconds": int(env("TTL_SECONDS", "300")),
        "child_selectors": {"k8s:ns": env("CHILD_NAMESPACE", "agents"), "k8s:pod-name": child_pod_name},
        "dataset_path": f"/datasets/{dataset}",
        "reason": "fork decision supplied by the agent tool (task and dataset chosen by the caller; scopes derived by the harness)",
    }


def _terminated(signum, _frame):
    raise SystemExit(128 + signum)


def tool_main(argv: list[str]) -> int:
    """`parent.py tool '<json>'`: one full cycle for a caller-chosen task.
    stdout carries exactly one line, the result JSON; everything else
    (narration, and audit events unless NHI_AUDIT_SINK is set) goes to
    stderr. Exit 0 if ok, 1 if the cycle ran but was not ok, 2 for bad
    arguments (nothing is vended)."""
    real_stdout = sys.stdout
    sys.stdout = sys.stderr  # nothing but the final result line may reach stdout

    def finish(res: dict, code: int) -> int:
        real_stdout.write(json.dumps(res) + "\n")
        real_stdout.flush()
        return code

    args, why = parse_tool_args(argv[0]) if len(argv) == 1 else (None, "usage: parent.py tool '<json: {task, dataset}>'")
    if args is None:
        res = new_result({"requested_scopes": []})
        res["error"] = why
        return finish(res, 2)

    # If the caller goes away mid-cycle, still dispose the delegation.
    signal.signal(signal.SIGTERM, _terminated)
    signal.signal(signal.SIGHUP, _terminated)
    res = new_result({"requested_scopes": [f"resource:read:dataset{args['dataset']}"]})
    try:
        wl, svid, own_id = start()
        decision = decision_from_tool(args, own_id)
        res = run_cycle(decision, wl=wl, svid=svid, own_id=own_id)
    except Exception as err:  # noqa: BLE001
        common.log(f"parent: tool error: {err!r}")
        res["error"] = res["error"] or f"{type(err).__name__}: {err}"

    res["ok"] = res["status"] == 200 and res["returned_via"] == "mtls-callback" and res["disposed"] and res["error"] is None
    if not res["ok"] and res["error"] is None:
        if callback_address() is None:
            res["error"] = "mTLS callback is off (POD_IP unset): the parent has no channel to receive the child's result"
        elif res["status"] != 200:
            res["error"] = f"the child's resource call returned HTTP {res['status']}"
        else:
            res["error"] = "cycle did not complete"
    common.log(f"parent: tool cycle {'COMPLETE' if res['ok'] else 'FAILED'}")
    return finish(res, 0 if res["ok"] else 1)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "tool":
        sys.exit(tool_main(sys.argv[2:]))
    if len(sys.argv) == 1:
        sys.exit(main())
    print("usage: parent.py [tool '<json>']", file=sys.stderr)
    sys.exit(2)
