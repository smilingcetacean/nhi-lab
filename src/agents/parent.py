#!/usr/bin/env python3
"""Parent agent.

Runs as a Kubernetes Job in namespace `agents`, authenticated by a REAL
SPIRE registration entry (spiffe://lab.local/agent/parent/demo — see
src/deploy/scripts/register-entries.sh and
manifests/policy-engine/36-policy-engine-bootstrap.yaml for its bootstrap
Π(P)), exactly like the vending-test-parent fixture and cmd/parentsim.
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
     task context and asked whether/how to delegate — would plug in later.
     Nothing below this function needs to change for that to happen: it
     already returns exactly the shape build_manifest() below consumes.
  3. build + sign the spawn manifest (manifest.py), POST it to the
     vending service.
  4. create the child pod via the k8s API, using the EXACT selectors
     promised in the manifest (k8s:ns, k8s:pod-name — the pod does not exist
     until this step).
  5. wait for the child to finish its task.
  6. trigger disposal (DELETE /delegations/{chain_id}).
"""

from __future__ import annotations

import os
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
    """
    child_pod_name = manifest_mod.new_child_pod_name()
    return {
        "child_path_hint": f"child/{child_pod_name}",
        "child_pod_name": child_pod_name,
        "requested_scopes": env("REQUESTED_SCOPES", "resource:read:datasetA").split(","),
        "task_context": env("TASK_CONTEXT", "demo: read datasetA on the parent's behalf"),
        "ttl_seconds": int(env("TTL_SECONDS", "300")),
        "child_selectors": {"k8s:ns": env("CHILD_NAMESPACE", "agents"), "k8s:pod-name": child_pod_name},
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


def create_child_pod(v1: k8s_client.CoreV1Api, *, namespace: str, pod_name: str, chain_id: str) -> None:
    container = k8s_client.V1Container(
        name="child",
        image=env("AGENTS_IMAGE", "nhi-lab/agents:dev"),
        image_pull_policy="Never",
        command=["python3", "/app/child.py"],
        env=[
            k8s_client.V1EnvVar(name="RESOURCE_URL", value=env("RESOURCE_URL", "http://resource.nhi.svc.cluster.local:8080")),
            k8s_client.V1EnvVar(name="RESOURCE_AUDIENCE", value=env("RESOURCE_AUDIENCE", "spiffe://lab.local/svc/resource")),
            k8s_client.V1EnvVar(name="DATASET_PATH", value=env("DATASET_PATH", "/datasets/A")),
            k8s_client.V1EnvVar(name="CHAIN_ID", value=chain_id),
            k8s_client.V1EnvVar(name="SPIFFE_ENDPOINT_SOCKET", value=common.socket_path()),
        ],
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


def main() -> int:
    common.log("parent: fetching own credentials from the Workload API")
    wl = common.new_workload_client()
    svid = common.fetch_x509_svid_retrying(wl)
    own_id = str(svid.spiffe_id)
    common.log(f"parent: own SPIFFE ID = {own_id}")

    vending_url = env("VENDING_SERVICE_URL", "http://vending-service.nhi.svc.cluster.local:8090").rstrip("/")
    vending_audience = env("VENDING_AUDIENCE", "spiffe://lab.local/svc/vending-service")
    namespace = env("CHILD_NAMESPACE", "agents")

    vending_jwt = common.fetch_jwt_svid_retrying(wl, vending_audience)

    decision = decide_to_fork(own_id)
    m = build_and_sign_manifest(decision, own_id, svid)
    prospective_child_id = m.child_spiffe_id()

    # "spawn" is emitted here, before the vending service has minted a
    # chain_id (chain_id="" — consistent with how the vending service itself
    # represents a pre-vend event; see internal/audit's doc comment) — this
    # IS the parent's fork decision, the one stage no other component emits.
    common.emit_audit_event(
        stage=common.STAGE_SPAWN,
        chain_id="",
        actor_spiffe_id=own_id,
        outcome=common.OUTCOME_ALLOW,
        detail={
            "child_spiffe_id": prospective_child_id,
            "requested_scopes": decision["requested_scopes"],
            "task_context": decision["task_context"],
            "reason": "scripted fork decision (decide_to_fork seam)",
        },
    )

    common.log(f"parent: submitting spawn manifest for prospective child {prospective_child_id}")
    session = common.http_session()
    resp = session.post(
        f"{vending_url}/delegations",
        json=m.to_wire(),
        headers=common.bearer_headers(vending_jwt.token),
    )
    common.log(f"parent: vending service responded {resp.status_code}: {resp.text}")
    if resp.status_code != 201:
        common.log("parent: vend failed, aborting — the vending service's own audit event records why")
        return 1
    vend = resp.json()
    chain_id = vend["chain_id"]
    child_spiffe_id = vend["child_spiffe_id"]
    common.log(f"parent: delegation created, chain_id={chain_id} child_spiffe_id={child_spiffe_id} child_scopes={vend.get('child_scopes')}")

    # --- create the child pod, only now that its identity already exists ---
    k8s_config.load_incluster_config()
    v1 = k8s_client.CoreV1Api()
    pod_name = decision["child_pod_name"]
    common.log(f"parent: creating child pod {namespace}/{pod_name}")
    create_child_pod(v1, namespace=namespace, pod_name=pod_name, chain_id=chain_id)

    phase = wait_for_pod_completion(v1, namespace=namespace, pod_name=pod_name)
    common.log(f"parent: child pod {pod_name} finished with phase={phase}")

    # --- disposal ------------------------------------------------------------
    # Fetch a fresh JWT-SVID rather than reusing the one from step 1 — the
    # child's own run may have taken a while, and this mirrors what a real
    # long-lived parent would do rather than assuming its first token is
    # still fresh.
    dispose_jwt = common.fetch_jwt_svid_retrying(wl, vending_audience)
    common.log(f"parent: disposing delegation {chain_id}")
    dispose_resp = session.delete(
        f"{vending_url}/delegations/{chain_id}",
        headers=common.bearer_headers(dispose_jwt.token),
    )
    common.log(f"parent: dispose responded {dispose_resp.status_code}: {dispose_resp.text}")

    ok = phase == "Succeeded" and dispose_resp.status_code == 200
    common.log(f"parent: cycle {'COMPLETE' if ok else 'FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
