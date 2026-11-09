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
exercise was deleted). The matched event must also belong to the test's own
request, or a stale event from an earlier test or run could satisfy the
check just as vacuously:
  - forged signature and replay: their deny events carry no chain_id or
    child id, so the vending-service audit log is snapshotted immediately
    before the request under test and again after it, and exactly one NEW
    event from exp-root with the expected stage and outcome is required;
  - scope escalation: matched by its own `detail.child_spiffe_id`;
  - orphaned child: matched by its own chain_id;
  - credential use after revocation: matched on the resource side by its
    own child SPIFFE ID as the actor.
Each test records the event it matched (and, where relevant, how many
candidates there were), so the evidence is independently re-derivable from
the collected JSON.

Only the credential-after-revocation test needs an SVID actually delivered to
the experiments-child pod; every other test vends for a service account no
pod runs as (NOPOD_SA), so a guard that wrongly mints an identity cannot hand
that pod a second SVID and skew a later test.

results/falsification.md records the falsification of each guard at two
levels: the Go unit test that exercises it, and this suite run live against
a vending-service image that carries the mutation on an isolated throwaway
cluster, with the clean image restored afterwards.
"""
from __future__ import annotations

import base64
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

# Service account of the experiments-child pod. Only the credential-after-
# revocation test vends with it, because only that test needs the SVID to be
# delivered to a running workload.
CHILD_SA = "nhi-exp-child"
# Service account that NO pod runs as (checked at suite start). Every other
# test vends with it: the vending service checks only that k8s:ns matches the
# caller's own namespace, not that the service account exists, so the entry is
# created as usual but its SVID reaches no workload. A guard that wrongly
# mints an identity therefore cannot give the experiments-child pod a second
# SVID and change what a later test fetches.
NOPOD_SA = "nhi-exp-negtest-nopod"
NOPOD_SELECTORS = f"-selectors=k8s:ns={NS},k8s:sa={NOPOD_SA}"
CHILD_SELECTORS = f"-selectors=k8s:ns={NS},k8s:sa={CHILD_SA}"

# Large enough that every event a single request emits is still inside the
# tail when the "after" snapshot is taken.
SNAPSHOT_TAIL = 200


def run_id() -> str:
    return uuid.uuid4().hex[:10]


def vending_audit(tail: int = 40):
    return c.audit_lines(VS_NS, "app=vending-service", "vending-service", tail=tail)


def resource_audit(tail: int = 60):
    return c.audit_lines(VS_NS, "app=resource", "resource", tail=tail)


def _event_key(ev: dict) -> str:
    # Each event carries an RFC 3339 nanosecond timestamp, so its canonical
    # serialisation identifies one line of the log.
    return json.dumps(ev, sort_keys=True)


def audit_snapshot() -> set[str]:
    """The vending-service audit lines visible right now, taken immediately
    before a request so that only events emitted after it are considered."""
    return {_event_key(ev) for ev in vending_audit(tail=SNAPSHOT_TAIL)}


def new_events_from_parent(before: set[str]) -> list[dict]:
    return [ev for ev in vending_audit(tail=SNAPSHOT_TAIL)
            if _event_key(ev) not in before and ev.get("actor_spiffe_id") == PARENT_ID]


def match_new_event(before: set[str], stage: str, outcome: str, wait_s: float = 5.0) -> dict:
    """Events emitted after `before` by exp-root with the given stage and
    outcome. The service emits the event before it writes the response, so
    it is normally present on the first read; the short poll only covers log
    propagation. Exactly one candidate is required for a match."""
    deadline = time.time() + wait_s
    while True:
        new = new_events_from_parent(before)
        cands = [ev for ev in new if ev.get("stage") == stage and ev.get("outcome") == outcome]
        if cands or time.time() >= deadline:
            break
        time.sleep(0.5)
    return {
        "matched": cands[0] if len(cands) == 1 else None,
        "candidate_count": len(cands),
        "new_parent_events": new,
    }


def dispose_unexpected(parent_pod, r) -> dict | None:
    """A test that expects a refusal but got 201 disposes the delegation it
    was wrongly given (it still FAILs): left alone, it would count against
    the per-parent live-children cap until its TTL ran out."""
    if r.code != 201:
        return None
    try:
        chain_id = json.loads(r.body).get("chain_id")
    except (json.JSONDecodeError, AttributeError):
        chain_id = None
    if not chain_id:
        return {"chain_id": None, "dispose_http_code": None}
    d = c.parentsim(NS, parent_pod, "dispose", f"-chain-id={chain_id}")
    return {"chain_id": chain_id, "dispose_http_code": d.code}


def jwt_subject(token: str) -> str | None:
    """The `sub` claim of a compact JWS, read without verifying the
    signature (the resource verifies it when the token is presented)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, json.JSONDecodeError):
        return None
    sub = claims.get("sub") if isinstance(claims, dict) else None
    return sub if isinstance(sub, str) else None


def check_nopod_precondition() -> tuple[bool, str]:
    res = c.kubectl("get", "pods", "-n", NS, "-o", "json")
    pods = json.loads(res.stdout).get("items", [])
    offenders = [p["metadata"]["name"] for p in pods
                 if p.get("spec", {}).get("serviceAccountName") == NOPOD_SA]
    if offenders:
        return False, f"pod(s) in {NS} run as {NOPOD_SA}: {', '.join(offenders)}"
    return True, f"no pod in {NS} runs as {NOPOD_SA} ({len(pods)} pods checked)"


def check(results: list, name: str, ok: bool, evidence: dict):
    results.append({"test": name, "pass": ok, **evidence})
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {name}")
    for k, v in evidence.items():
        print(f"      {k}: {v}")


def test_forged_signature(results, parent_pod):
    rid = run_id()
    before = audit_snapshot()
    r = c.parentsim(
        NS, parent_pod, "vend", "-corrupt-signature",
        f"-child-path-hint=child/negtest-forged-{rid}",
        "-scopes=resource:read:datasetA",
        NOPOD_SELECTORS,
        f"-nonce=negtest_forged_{rid}",
    )
    m = match_new_event(before, stage="attest", outcome="deny")
    ev = m["matched"]
    reason_ok = bool(ev) and "signature verification failed" in ev.get("detail", {}).get("reason", "")
    ok = (r.code == 401) and reason_ok
    entry_gone = not c.entry_exists(f"{PARENT_ID}/child/negtest-forged-{rid}")
    unexpected = dispose_unexpected(parent_pod, r)
    check(results, "forged_parent_signature", ok and entry_gone, {
        "http_code": r.code, "expected_http_code": 401,
        "audit_event": ev, "audit_candidate_count": m["candidate_count"],
        "new_parent_events": m["new_parent_events"],
        "no_entry_created": entry_gone,
        "unexpected_delegation_disposed": unexpected,
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
    child_id = f"{PARENT_ID}/child/negtest-escalate-{rid}"
    r = c.parentsim(
        NS, parent_pod, "vend",
        f"-child-path-hint=child/negtest-escalate-{rid}",
        "-scopes=resource:admin:everything",
        NOPOD_SELECTORS,
        f"-nonce=negtest_escalate_{rid}",
    )
    # The empty-attenuation deny names the child, so match on this test's own
    # child SPIFFE ID rather than on whichever vend/deny is newest.
    cands = [e for e in vending_audit(tail=SNAPSHOT_TAIL)
             if e.get("detail", {}).get("child_spiffe_id") == child_id
             and e.get("stage") == "vend" and e.get("outcome") == "deny"]
    ev = cands[0] if len(cands) == 1 else None
    reason_ok = bool(ev) and "granted no scopes" in ev.get("detail", {}).get("reason", "")
    ok = (r.code == 403) and reason_ok
    entry_gone = not c.entry_exists(child_id)
    unexpected = dispose_unexpected(parent_pod, r)
    check(results, "scope_escalation_manifest", ok and entry_gone, {
        "http_code": r.code, "expected_http_code": 403,
        "audit_event": ev, "audit_candidate_count": len(cands),
        "no_entry_created": entry_gone,
        "unexpected_delegation_disposed": unexpected,
        "response_body": r.body,
    })


def test_replay(results, parent_pod):
    rid = run_id()
    nonce = f"negtest_replay_{rid}"
    common = [
        f"-child-path-hint=child/negtest-replay-{rid}",
        "-scopes=resource:read:datasetA",
        NOPOD_SELECTORS,
        f"-nonce={nonce}",
    ]
    first = c.parentsim(NS, parent_pod, "vend", *common)
    # snapshot between the two vends: only the replayed request's events count
    before = audit_snapshot()
    second = c.parentsim(NS, parent_pod, "vend", *common)
    m = match_new_event(before, stage="attest", outcome="deny")
    ev = m["matched"]
    reason_ok = bool(ev) and "already been used" in ev.get("detail", {}).get("reason", "")
    ok = (first.code == 201) and (second.code == 409) and reason_ok
    unexpected = dispose_unexpected(parent_pod, second)
    check(results, "replay_captured_manifest", ok, {
        "first_http_code": first.code, "second_http_code": second.code,
        "expected": "201 then 409",
        "audit_event": ev, "audit_candidate_count": m["candidate_count"],
        "new_parent_events": m["new_parent_events"],
        "unexpected_delegation_disposed": unexpected,
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
        CHILD_SELECTORS,
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
    # fetch-jwt asks the Workload API for a JWT-SVID without naming a subject,
    # so the agent returns whichever identity it lists first. If the pod held
    # another SVID, the test would be exercising that identity, not this one.
    captured_subject = jwt_subject(captured) if captured_valid else None
    subject_ok = captured_subject == child_id

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
    ok = ((got is not None) and captured_valid and subject_ok and (dispose.code == 200)
          and (replay.code == 403) and reason_ok)
    evidence = {
        "child_obtained_svid": got is not None,
        "captured_jwt_before_disposal": captured_valid,
        "captured_jwt_subject": captured_subject,
        "expected_jwt_subject": child_id,
        "dispose_http_code": dispose.code,
        "replay_http_code_after_disposal": replay.code, "expected": 403,
        "audit_event": ev,
    }
    if captured_valid and not subject_ok:
        evidence["captured_jwt_subject_mismatch"] = (
            f"captured JWT-SVID belongs to {captured_subject}, not to this test's child {child_id}")
    check(results, "credential_use_after_revocation", ok, evidence)


def test_orphaned_child(results, parent_pod):
    rid = run_id()
    child_id = f"{PARENT_ID}/child/negtest-orphan-{rid}"
    r = c.parentsim(
        NS, parent_pod, "vend",
        f"-child-path-hint=child/negtest-orphan-{rid}",
        "-scopes=resource:read:datasetA",
        NOPOD_SELECTORS,
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

    out_dir = Path(__file__).parent / "results" / "latest"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "negative_tests.json"

    pre_ok, pre_msg = check_nopod_precondition()
    if not pre_ok:
        print(f"\nPRECONDITION FAILED: {pre_msg}")
        print(f"  the tests vend for {NOPOD_SA} on the assumption that no workload receives its SVIDs")
        out_path.write_text(json.dumps({
            "generated_at": c.now_iso(),
            "precondition": {"pass": False, "detail": pre_msg},
            "results": [],
        }, indent=2, default=str))
        print(f"\nwrote {out_path}")
        return 1
    print(f"precondition: {pre_msg}")

    results: list[dict] = []
    test_forged_signature(results, parent_pod)
    test_scope_escalation(results, parent_pod)
    test_replay(results, parent_pod)
    test_credential_after_revocation(results, parent_pod, child_pod)
    test_orphaned_child(results, parent_pod)

    out_path.write_text(json.dumps({
        "generated_at": c.now_iso(),
        "precondition": {"pass": True, "detail": pre_msg},
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
