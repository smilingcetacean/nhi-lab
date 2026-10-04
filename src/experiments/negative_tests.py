#!/usr/bin/env python3
"""Negative test suite.

Five scenarios (forged signature, scope escalation, replay, credential use
after revocation, orphaned child), each driven
against the REAL, live vending service / policy engine / resource (no mocks
— same discipline as verify-vending.sh) via `kubectl exec ... parentsim`, using
the dedicated `src/deploy/manifests/experiments/60-experiments-fixtures.yaml`
pods so a run never collides with a concurrent `make verify-vending`/`make demo`.

Every assertion pins BOTH the HTTP status AND the specific denial reason
carried in the matching audit event's `detail.reason` — a test that checked
only the status code would be satisfied by any earlier rejection on the same
code path (this happened in this lab: a tightened chain_id regex made an
escalation-guard test pass for the wrong reason after the guard it existed to
exercise was deleted). Each test also records which audit event it matched,
by chain_id where one exists, so the evidence is independently re-derivable
from the collected JSON.

Falsification of each guard (removing it on a scratch copy and confirming a
red run) is done separately at the Go unit-test level — see
results/falsification.md for the before/after evidence;
doing it here against the live cluster would mean rebuilding and
redeploying the vending-service image five times against shared cluster
state, which is neither necessary (the guards already have dedicated Go
unit tests) nor safe for a shared, non-isolated cluster.
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


def run_id() -> str:
    return uuid.uuid4().hex[:10]


def vending_audit(tail: int = 40):
    return c.audit_lines(VS_NS, "app=vending-service", "vending-service", tail=tail)


def resource_audit(tail: int = 60):
    return c.audit_lines(VS_NS, "app=resource", "resource", tail=tail)


def check(results: list, name: str, ok: bool, evidence: dict):
    results.append({"test": name, "pass": ok, **evidence})
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {name}")
    for k, v in evidence.items():
        print(f"      {k}: {v}")


def test_forged_signature(results, parent_pod):
    rid = run_id()
    r = c.parentsim(
        NS, parent_pod, "vend", "-corrupt-signature",
        f"-child-path-hint=child/negtest-forged-{rid}",
        "-scopes=resource:read:datasetA",
        "-selectors=k8s:ns=agents,k8s:sa=nhi-exp-child",
        f"-nonce=negtest_forged_{rid}",
    )
    ev = c.find_event(vending_audit(), stage="attest", outcome="deny")
    reason_ok = bool(ev) and "signature verification failed" in ev.get("detail", {}).get("reason", "")
    ok = (r.code == 401) and reason_ok
    entry_gone = not c.entry_exists(f"{PARENT_ID}/child/negtest-forged-{rid}")
    check(results, "forged_parent_signature", ok and entry_gone, {
        "http_code": r.code, "expected_http_code": 401,
        "audit_event": ev, "no_entry_created": entry_gone,
        "response_body": r.body,
    })


def test_scope_escalation(results, parent_pod):
    """exp-root holds all three scopes the resource defines (bootstrap
    ConfigMap), so a genuinely disjoint escalation attempt has to name a
    scope string the resource never grants at all — this proves the deny
    path (Pi(requested) ^ Pi(parent) = empty) independently of
    which scopes happen to be pre-provisioned, without reusing the
    single-scope vend-verify fixture verify-vending.sh already exercises."""
    rid = run_id()
    r = c.parentsim(
        NS, parent_pod, "vend",
        f"-child-path-hint=child/negtest-escalate-{rid}",
        "-scopes=resource:admin:everything",
        "-selectors=k8s:ns=agents,k8s:sa=nhi-exp-child",
        f"-nonce=negtest_escalate_{rid}",
    )
    ev = c.find_event(vending_audit(), stage="vend", outcome="deny")
    reason_ok = bool(ev) and "granted no scopes" in ev.get("detail", {}).get("reason", "")
    ok = (r.code == 403) and reason_ok
    entry_gone = not c.entry_exists(f"{PARENT_ID}/child/negtest-escalate-{rid}")
    check(results, "scope_escalation_manifest", ok and entry_gone, {
        "http_code": r.code, "expected_http_code": 403,
        "audit_event": ev, "no_entry_created": entry_gone,
        "response_body": r.body,
    })


def test_replay(results, parent_pod):
    rid = run_id()
    nonce = f"negtest_replay_{rid}"
    common = [
        f"-child-path-hint=child/negtest-replay-{rid}",
        "-scopes=resource:read:datasetA",
        "-selectors=k8s:ns=agents,k8s:sa=nhi-exp-child",
        f"-nonce={nonce}",
    ]
    first = c.parentsim(NS, parent_pod, "vend", *common)
    second = c.parentsim(NS, parent_pod, "vend", *common)
    ev = c.find_event(vending_audit(), stage="attest", outcome="deny")
    reason_ok = bool(ev) and "already been used" in ev.get("detail", {}).get("reason", "")
    ok = (first.code == 201) and (second.code == 409) and reason_ok
    check(results, "replay_captured_manifest", ok, {
        "first_http_code": first.code, "second_http_code": second.code,
        "expected": "201 then 409",
        "audit_event": ev,
    })
    # cleanup: dispose the first (successful) delegation so it doesn't dangle
    body = json.loads(first.body) if first.code == 201 else {}
    chain_id = body.get("chain_id")
    if chain_id:
        c.parentsim(NS, parent_pod, "dispose", f"-chain-id={chain_id}")


def test_credential_after_revocation(results, parent_pod, child_pod):
    rid = run_id()
    child_id = f"{PARENT_ID}/child/negtest-revoke-{rid}"
    r = c.parentsim(
        NS, parent_pod, "vend",
        f"-child-path-hint=child/negtest-revoke-{rid}",
        "-scopes=resource:read:datasetA",
        "-selectors=k8s:ns=agents,k8s:sa=nhi-exp-child",
        f"-nonce=negtest_revoke_{rid}",
    )
    if r.code != 201:
        check(results, "credential_use_after_revocation", False, {
            "setup_failed": True, "vend_http_code": r.code, "vend_body": r.body,
        })
        return
    chain_id = json.loads(r.body)["chain_id"]

    # wait for the child pod's SPIRE agent to pick up the new entry
    got = None
    for _ in range(15):
        out = c.parentsim(NS, child_pod, "x509-check")
        if '"spiffe_id"' in out.body and child_id in out.body:
            got = out.body
            break
        time.sleep(2)

    captured = c.exec_pod(NS, child_pod, "parentsim", "/parentsim", "fetch-jwt",
                           f"-call-audience={c.RESOURCE_AUD}").strip()
    captured_valid = bool(captured) and captured.count(".") == 2 and "parentsim:" not in captured

    dispose = c.parentsim(NS, parent_pod, "dispose", f"-chain-id={chain_id}")

    replay = c.parentsim(
        NS, child_pod, "bearer-call",
        f"-call-url={c.RESOURCE_URL}/datasets/A",
        f"-bearer-token={captured}",
    )
    # resource events don't carry this delegation's chain_id reliably (the
    # bearer-call here sends no X-NHI-Chain-Id header), so match on actor + outcome
    events = resource_audit()
    ev = None
    for e in reversed(events):
        if e.get("actor_spiffe_id") == child_id and e.get("outcome") == "deny":
            ev = e
            break
    reason_ok = bool(ev) and ev.get("detail", {}).get("reason") == "policy denied"
    ok = (got is not None) and captured_valid and (dispose.code == 200) and (replay.code == 403) and reason_ok
    check(results, "credential_use_after_revocation", ok, {
        "child_obtained_svid": got is not None,
        "captured_jwt_before_disposal": captured_valid,
        "dispose_http_code": dispose.code,
        "replay_http_code_after_disposal": replay.code, "expected": 403,
        "audit_event": ev,
    })


def test_orphaned_child(results, parent_pod):
    rid = run_id()
    child_id = f"{PARENT_ID}/child/negtest-orphan-{rid}"
    r = c.parentsim(
        NS, parent_pod, "vend",
        f"-child-path-hint=child/negtest-orphan-{rid}",
        "-scopes=resource:read:datasetA",
        "-selectors=k8s:ns=agents,k8s:sa=nhi-exp-child",
        f"-nonce=negtest_orphan_{rid}", "-ttl=5",
    )
    if r.code != 201:
        check(results, "orphaned_child_reaper", False, {
            "setup_failed": True, "vend_http_code": r.code, "vend_body": r.body,
        })
        return
    chain_id = json.loads(r.body)["chain_id"]

    reaped = False
    for _ in range(20):
        if not c.entry_exists(child_id):
            reaped = True
            break
        time.sleep(2)

    ev = None
    for e in reversed(vending_audit(tail=80)):
        if e.get("chain_id") == chain_id and e.get("stage") == "dispose":
            ev = e
            break
    reason_ok = bool(ev) and ev.get("detail", {}).get("reason") == "ttl_expired"
    ok = reaped and reason_ok
    check(results, "orphaned_child_reaper", ok, {
        "entry_reaped": reaped, "audit_event": ev, "chain_id": chain_id,
    })


def main():
    print("== negative test suite ==")
    parent_pod = c.wait_for_pod(NS, "app=experiments-parent")
    attacker_pod = c.wait_for_pod(NS, "app=experiments-attacker")
    child_pod = c.wait_for_pod(NS, "app=experiments-child")
    print(f"parent={parent_pod} attacker={attacker_pod} child={child_pod}")

    results: list[dict] = []
    test_forged_signature(results, parent_pod)
    test_scope_escalation(results, parent_pod)
    test_replay(results, parent_pod)
    test_credential_after_revocation(results, parent_pod, child_pod)
    test_orphaned_child(results, parent_pod)

    out_dir = Path(__file__).parent / "results" / "latest"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "negative_tests.json"
    out_path.write_text(json.dumps({
        "generated_at": c.now_iso(),
        "results": results,
    }, indent=2, default=str))
    print(f"\nwrote {out_path}")

    failed = [x for x in results if not x["pass"]]
    if failed:
        print(f"\n{len(failed)}/{len(results)} negative tests FAILED")
        return 1
    print(f"\nall {len(results)} negative tests PASSED (denial + audit event both confirmed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
