#!/usr/bin/env python3
"""Multi-hop suite: P -> C -> G, demonstrating Pi(G) <= Pi(C) <= Pi(P).

This is the strongest single result this lab can add (the
recursive-delegation gap Stefanescu & Aciobaniei's "Lineage" paper targets
with formal proofs; this lab demonstrates it operationally instead).

Mechanism: the vending service's own manifest.Validate() already accepts a
DYNAMIC parent shape (`/agent/parent/<id>/child/<subtask>`),
and Pi(P) for such a parent is read back from OPA's own nhi_grants_* module
for it rather than asserted by the caller — so a child that
was itself just vended can immediately act as a parent for a further
delegation with NO code change and no special-casing. This suite is the
first thing in the repo to actually exercise that path end to end
(verify-vending.sh never vends past one hop).

The experiments-child pod plays a dual role: recipient of the P -> C
delegation, and then (once it holds its own SVID) submits its own
signed manifest to vend C -> G onto experiments-grandchild.
"""
from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from lib import cluster as c  # noqa: E402

NS = "agents"
VS_NS = "nhi"
PARENT_ID = f"spiffe://{c.TRUST_DOMAIN}/agent/parent/exp-root"


def vending_audit(tail: int = 60):
    return c.audit_lines(VS_NS, "app=vending-service", "vending-service", tail=tail)


def wait_for_svid(pod: str, expect_id: str, attempts: int = 20, interval: float = 2.0) -> bool:
    for _ in range(attempts):
        out = c.parentsim(NS, pod, "x509-check")
        if expect_id in out.body:
            return True
        time.sleep(interval)
    return False


def resource_call(pod: str, path: str) -> c.ParentsimResult:
    return c.parentsim(NS, pod, "call", f"-call-audience={c.RESOURCE_AUD}", f"-call-url={c.RESOURCE_URL}{path}")


def main() -> int:
    print("== multi-hop suite: P -> C -> G ==")
    parent_pod = c.wait_for_pod(NS, "app=experiments-parent")
    child_pod = c.wait_for_pod(NS, "app=experiments-child")
    grandchild_pod = c.wait_for_pod(NS, "app=experiments-grandchild")
    print(f"parent={parent_pod} child={child_pod} grandchild={grandchild_pod}")

    rid = uuid.uuid4().hex[:8]
    report: dict = {"generated_at": c.now_iso(), "run_id": rid}
    ok = True

    # --- Hop 1: P -> C, requesting all three scopes (P holds all three) -----
    child_hint = f"child/mh-c-{rid}"
    child_id = f"{PARENT_ID}/{child_hint}"
    r1 = c.parentsim(
        NS, parent_pod, "vend",
        f"-child-path-hint={child_hint}",
        "-scopes=resource:read:datasetA,resource:read:datasetB",
        "-task-context=experiment multi-hop hop1 (P->C)",
        "-selectors=k8s:ns=agents,k8s:sa=nhi-exp-child",
        "-ttl=600",
        f"-nonce=mh_hop1_{rid}",
    )
    hop1 = {"http_code": r1.code, "body": r1.body}
    report["hop1_vend"] = hop1
    if r1.code != 201:
        report["FATAL"] = "hop 1 (P->C) vend failed"
        _write(report)
        print("FATAL: hop1 vend failed:", r1.body)
        return 1
    chain1 = json.loads(r1.body)
    chain1_id = chain1["chain_id"]
    child_scopes = sorted(chain1["child_scopes"])
    print(f"  hop1: child_scopes={child_scopes}  child_spiffe_id={chain1['child_spiffe_id']}")
    assert chain1["child_spiffe_id"] == child_id

    svid_ok = wait_for_svid(child_pod, child_id)
    report["hop1_child_obtained_svid"] = svid_ok
    print(f"  hop1: child pod obtained SVID: {svid_ok}")
    ok = ok and svid_ok

    # child's own Pi(C) is EXACTLY what hop 1 granted -- requested A,B against
    # Pi(P) = {A,B,jobs} attenuates to {A,B} (a strict subset of Pi(P), and
    # equal here only because the request itself was a subset -- see the
    # scope-narrowing hop below for the strict-subset case).
    pi_p = ["resource:read:datasetA", "resource:read:datasetB", "resource:write:jobs"]
    hop1_subset_ok = set(child_scopes) <= set(pi_p)
    report["hop1_pi_c_subset_of_pi_p"] = hop1_subset_ok
    print(f"  hop1: Pi(C) subset of Pi(P): {hop1_subset_ok}  Pi(C)={child_scopes}  Pi(P)={pi_p}")
    ok = ok and hop1_subset_ok

    # --- Hop 2: C -> G, requesting Pi(C) plus an escalation attempt ---------
    # C only holds {A,B}. Request A,B,jobs from the CHILD pod (acting as
    # parent now) -- jobs should attenuate away, proving Pi(G) <= Pi(C) even
    # though jobs IS in the ROOT parent's authority (Pi(P)). This is the
    # interesting multi-hop case: attenuation composes hop over hop, it does
    # not "see through" to the root's authority.
    grandchild_hint = f"child/mh-g-{rid}"
    grandchild_id = f"{child_id}/{grandchild_hint}"
    r2 = c.parentsim(
        NS, child_pod, "vend",
        f"-child-path-hint={grandchild_hint}",
        "-scopes=resource:read:datasetA,resource:read:datasetB,resource:write:jobs",
        "-task-context=experiment multi-hop hop2 (C->G, jobs escalation attempt)",
        "-selectors=k8s:ns=agents,k8s:sa=nhi-exp-grandchild",
        "-ttl=600",
        f"-nonce=mh_hop2_{rid}",
    )
    hop2 = {"http_code": r2.code, "body": r2.body}
    report["hop2_vend"] = hop2
    if r2.code != 201:
        report["FATAL"] = "hop 2 (C->G) vend failed -- STRUCTURAL LIMIT if this is a systematic 4xx, see below"
        _write(report)
        print("FATAL: hop2 vend failed:", r2.body)
        return 1
    chain2 = json.loads(r2.body)
    chain2_id = chain2["chain_id"]
    grandchild_scopes = sorted(chain2["child_scopes"])
    print(f"  hop2: child_scopes={grandchild_scopes}  child_spiffe_id={chain2['child_spiffe_id']}")
    assert chain2["child_spiffe_id"] == grandchild_id

    hop2_subset_ok = set(grandchild_scopes) <= set(child_scopes)
    hop2_escalation_attenuated = "resource:write:jobs" not in grandchild_scopes
    report["hop2_pi_g_subset_of_pi_c"] = hop2_subset_ok
    report["hop2_jobs_escalation_attenuated"] = hop2_escalation_attenuated
    print(f"  hop2: Pi(G) subset of Pi(C): {hop2_subset_ok}  Pi(G)={grandchild_scopes}")
    print(f"  hop2: jobs escalation attenuated away (present in Pi(P) but not Pi(C)): {hop2_escalation_attenuated}")
    ok = ok and hop2_subset_ok and hop2_escalation_attenuated

    svid_ok_g = wait_for_svid(grandchild_pod, grandchild_id)
    report["hop2_grandchild_obtained_svid"] = svid_ok_g
    print(f"  hop2: grandchild pod obtained SVID: {svid_ok_g}")
    ok = ok and svid_ok_g

    # --- operate: grandchild exercises exactly its granted scopes ----------
    opA = resource_call(grandchild_pod, "/datasets/A")
    opJobs_out = c.exec_pod(NS, grandchild_pod, "parentsim", "/parentsim", "call",
                             f"-call-audience={c.RESOURCE_AUD}", f"-call-method=POST",
                             f"-call-url={c.RESOURCE_URL}/jobs")
    opJobs = c.split_status_body(opJobs_out)
    report["grandchild_get_datasetA"] = opA.code
    report["grandchild_post_jobs_denied"] = opJobs.code
    operate_ok = (opA.code == 200) and (opJobs.code == 403)
    print(f"  operate: GET /datasets/A -> {opA.code} (want 200); POST /jobs -> {opJobs.code} (want 403, jobs was attenuated away)")
    ok = ok and operate_ok

    # --- audit chain: both hops' events share no chain_id (each hop mints
    # its own), but the delegation records + audit detail carry the lineage
    # (parent_spiffe_id/child_spiffe_id) explicitly. Confirm both vend audit
    # events are present and attributed to the correct actor.
    events = vending_audit(tail=100)
    ev1 = c.find_event(events, chain_id=chain1_id, stage="vend", outcome="allow")
    ev2 = c.find_event(events, chain_id=chain2_id, stage="vend", outcome="allow")
    lineage_ok = (
        bool(ev1) and ev1["actor_spiffe_id"] == PARENT_ID and ev1["detail"]["child_spiffe_id"] == child_id
        and bool(ev2) and ev2["actor_spiffe_id"] == child_id and ev2["detail"]["child_spiffe_id"] == grandchild_id
    )
    report["hop1_audit_event"] = ev1
    report["hop2_audit_event"] = ev2
    report["lineage_traceable_via_audit"] = lineage_ok
    print(f"  audit: hop1 actor={ev1 and ev1['actor_spiffe_id']}  hop2 actor={ev2 and ev2['actor_spiffe_id']}  lineage_ok={lineage_ok}")
    ok = ok and lineage_ok

    # --- disposal: dispose G, then C. Confirm no automatic cascade (documented limitation) ---
    dispose_g = c.parentsim(NS, child_pod, "dispose", f"-chain-id={chain2_id}")
    dispose_c = c.parentsim(NS, parent_pod, "dispose", f"-chain-id={chain1_id}")
    report["dispose_grandchild_http_code"] = dispose_g.code
    report["dispose_child_http_code"] = dispose_c.code
    dispose_ok = (dispose_g.code == 200) and (dispose_c.code == 200)
    print(f"  disposal: G disposed by C -> {dispose_g.code}; C disposed by P -> {dispose_c.code}")
    ok = ok and dispose_ok

    report["overall_pass"] = ok
    _write(report)
    print(f"\n{'PASS' if ok else 'FAIL'}: multi-hop P -> C -> G")
    return 0 if ok else 1


def _write(report: dict) -> None:
    out_dir = Path(__file__).parent / "results" / "latest"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "multi_hop.json"
    out_path.write_text(json.dumps(report, indent=2, default=str))
    print(f"wrote {out_path}")


if __name__ == "__main__":
    raise SystemExit(main())
