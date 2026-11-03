#!/usr/bin/env python3
"""Revoke to deny: how long after a parent revokes a child does the child get refused, and lose its identity?

`make revoke-to-deny` is the entry point. Not part of `make experiments`.

Each trial has the experiments parent P vend a fresh child SPIFFE ID for the
experiments child pod C (chain P -> C only), lets C run a request loop against
the protected resource, then has P revoke C with `DELETE /delegations/{chain_id}`.
The reference instant (t0) is the wall clock P's pod stamps just before it writes
the DELETE (`parentsim dispose-timed`).

C's side is `parentsim revoke-wait`, running in C's pod. Every `--interval-ms`
(default 20 ms) it fetches a fresh JWT-SVID from its SPIRE agent (audience the
resource) through one long-lived Workload API client, as a go-spiffe JWT source
does on each call, and in the same tick sends `GET /datasets/A` with it. It
reports "ready" at its first 200; the harness then waits a seeded random
0..`--jitter-s` seconds plus `--settle-s`, so the DELETE lands at a random point of
the agent's sync cycle, and sends the DELETE.

The vending service verifies the request, walks the chain, removes C's OPA grant
and deletes C's SPIRE entry. Two end marks follow:

  headline   revoke_to_deny_ms: t0 -> C's first 403 received. C's agent still
             hands out a valid JWT-SVID until it has synced, so the resource
             accepts the token and OPA denies it: 403.
  secondary  revoke_to_identity_gone_ms: t0 -> C's first failed token fetch
             received. Once the agent has synced, it no longer issues C an
             identity ("no identity issued"). C stops there and does not call the
             resource without a token.

A 401 is not expected and is not produced. A revoked child's JWT-SVID stays
cryptographically valid until it expires, so the resource sends 401 only for a
missing, malformed, expired or otherwise invalid token; the 403 is the denial the
revocation produces.

Clocks. Every stamp is CLOCK_REALTIME in Unix nanoseconds. The kind nodes are
containers on one host and share its kernel clock, so stamps from P's pod, C's pod
and the components' logs are directly comparable (the same assumption as
revocation_speed.py and poll.go). It would not hold on a cluster whose nodes are
separate machines.

Cross-checks, each its own column and reported separately from `ok`:
  * the resource's own first `deny` audit event for C's ID: its time, whether it
    falls inside the first-403 request, and its reason;
  * the policy engine's `dispose` event for C's chain (the grant removed), and the
    vending service's `dispose` event for it, each in ms after t0;
  * the SPIRE server's API audit log: the BatchDeleteEntry call for C's entry, and
    C's node agent's SyncAuthorizedEntries calls (the last before t0, and the last
    before the failed fetch, which most likely dropped the entry; needs the server
    audit log);
  * C's node agent's first log line naming C's ID after t0;
  * `c_entry_gone`, and `order_ok`: t0 < first 403 received <= failed fetch
    received, with the resource's deny event inside the 403 request.

`ok` means: the DELETE was answered 200, C was answered 200 before it, the first
refusal after it was a 403, and a failed fetch followed within the timeout.

Output (`results/<run-id>/`)
----------------------------
  revoke_to_deny.csv            one row per trial
  revoke_to_deny_summary.json   statistics, cross-check counts, host inventory
  revoke_to_deny_raw.json       the raw loop / DELETE / audit / agent-log records
  logs/{vending-service,spire-server,resource,policy-engine,spire-agent,parent}/trial-NN.log
                                each component's log lines for one trial, prefixed
                                with the container runtime's timestamp. The windows
                                are contiguous, so every line of the run is in
                                exactly one trial file. spire-agent is C's node
                                agent; parent holds P's command output, each line
                                prefixed with the time this host received it.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import statistics
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from lib import cluster as c  # noqa: E402
from revocation_speed import (  # noqa: E402  - shared timing helpers
    NS, PARENT_ID, ParentsimStream, host_inventory, json_line, ms, parse_rfc3339_ns, vend, wait_for_svid, wait_no_identity,
)
from vend_to_svid import (  # noqa: E402  - the vend-to-SVID benchmark's parts
    AUDIT_FIELDS, CLOCK_SLACK_NS, agent_first_line, agent_ids_by_node, agent_pod_for, column, component_logs,
    ns_to_rfc3339, spire_server_audit_enabled, stats,
)
from vend_to_access import stamp_lines  # noqa: E402

CHILD_SA = "nhi-exp-child"
SCOPES = "resource:read:datasetA"
DATASET_URL = f"{c.RESOURCE_URL}/datasets/A"  # needs resource:read:datasetA

CSV_FIELDS = [
    "trial", "ok", "error", "child_spiffe_id", "chain_id", "entry_id", "vend_status",
    "ready_jitter_ms",                 # the seeded random wait between C's ready and the DELETE (settle not included)
    # t0 (P's pod)
    "delete_send_ns", "delete_recv_ns", "delete_status", "delete_round_trip_ms",
    # C's pod: the last 200 before the revoke, the first denial, the end of the identity
    "ready_recv_ns", "ready_before_delete_ms",
    "first_denial_status", "first_403_send_ns", "first_403_recv_ns",
    "first_403_jwt_send_ns", "first_403_jwt_recv_ns",
    "last_200_send_ns", "last_200_recv_ns",
    "last_fetch_ok_send_ns", "last_fetch_ok_recv_ns",
    "failed_fetch_send_ns", "failed_fetch_recv_ns", "failed_fetch_error",
    "revoke_to_deny_ms",               # first 403 received - DELETE sent: the headline
    "revoke_to_deny_send_basis_ms",    # first 403 request sent - DELETE sent
    "revoke_to_identity_gone_ms",      # failed fetch received - DELETE sent: the secondary metric
    "revoke_to_identity_gone_send_basis_ms",  # failed fetch sent - DELETE sent
    "deny_to_identity_gone_ms",        # failed fetch received - first 403 received
    "denial_window_ms",                # first 403 received - last 200 sent: the uncertainty in when the denial began
    "denials", "other_statuses", "first_403_token_is_ready_token", "distinct_tokens",
    "polls", "transport_errors", "pre_ready_fetch_failures", "pre_ready_denials",
    "loop_gap_mean_ms", "loop_gap_max_ms", "fetch_latency_mean_ms", "fetch_latency_max_ms",
    "call_latency_mean_ms", "call_latency_max_ms",
    "wait_event",
    # cross-checks
    "resource_deny_ns", "resource_deny_after_send_ms", "resource_deny_inside_403_request", "resource_deny_reason",
    "resource_denies_for_child",
    "policy_dispose_ns", "policy_dispose_after_send_ms",
    "vending_dispose_ns", "vending_dispose_after_send_ms",
    "server_delete_entry_ns", "server_delete_entry_after_send_ms",
    "phase_since_child_agent_sync_ms",  # t0 - C's agent's last SyncAuthorizedEntries before it
    "child_agent_last_sync_before_delete_ns",
    "child_agent_sync_before_gone_ns", "child_agent_sync_before_gone_after_send_ms",
    "child_agent_syncs_between",       # C's agent's syncs after t0 up to the failed fetch
    "agent_log_ns", "agent_log_after_send_ms", "agent_log_message",
    "c_entry_gone", "order_ok", "dispose_status",
    "log_window_start_ns", "log_window_end_ns",
    "vending_service_log_lines", "spire_server_log_lines", "resource_log_lines", "policy_engine_log_lines",
    "spire_agent_log_lines", "parent_log_lines",
]

COMPONENTS = (  # directory name -> (namespace, container); the pod is resolved in main()
    ("vending-service", "nhi", "vending-service"),
    ("spire-server", "spire", "spire-server"),
    ("resource", "nhi", "resource"),
    ("policy-engine", "nhi", "policy-engine"),
    ("spire-agent", "spire", "spire-agent"),
)


def events_in(lines: list[str]) -> list[dict]:
    """The JSON audit events in a component's log window (runtime timestamp first on each line)."""
    out = []
    for ln in lines:
        _, _, body = ln.partition(" ")
        if body.startswith("{"):
            try:
                out.append(json.loads(body))
            except json.JSONDecodeError:
                continue
    return out


def resource_deny(lines: list[str], row: dict) -> tuple[dict, dict | None]:
    """The resource's first deny audit event for C's identity, and how it sits against the first 403."""
    denies = [e for e in events_in(lines) if e.get("actor_spiffe_id") == row["child_spiffe_id"] and e.get("outcome") == "deny"]
    out: dict = {"resource_denies_for_child": len(denies)}
    if not denies:
        return out, None
    first = min(denies, key=lambda e: parse_rfc3339_ns(e["timestamp"]))
    ns = parse_rfc3339_ns(first["timestamp"])
    out.update(resource_deny_ns=ns, resource_deny_after_send_ms=ms(ns - row["delete_send_ns"]),
               resource_deny_reason=(first.get("detail") or {}).get("reason", ""))
    if row["first_403_send_ns"] != "":
        out["resource_deny_inside_403_request"] = (row["first_403_send_ns"] - CLOCK_SLACK_NS <= ns
                                                   <= row["first_403_recv_ns"] + CLOCK_SLACK_NS)
    return out, first


def stage_event(lines: list[str], row: dict, stage: str, field: str) -> tuple[dict, dict | None]:
    """The allow-outcome `stage` event for C's chain in a component's window; its time after the DELETE."""
    evs = [e for e in events_in(lines) if e.get("stage") == stage and e.get("chain_id") == row["chain_id"]
           and e.get("outcome") == "allow"]
    if not evs:
        return {}, None
    first = min(evs, key=lambda e: parse_rfc3339_ns(e["timestamp"]))
    ns = parse_rfc3339_ns(first["timestamp"])
    return {f"{field}_ns": ns, f"{field}_after_send_ms": ms(ns - row["delete_send_ns"])}, first


def server_delete_entry(lines: list[str], row: dict) -> dict:
    """The SPIRE server's first BatchDeleteEntry audit line that names C's entry."""
    for ln in lines:
        if "type=audit" not in ln or "method=BatchDeleteEntry" not in ln:
            continue
        f = {k: (m.group(1) if (m := rx.search(ln)) else None) for k, rx in AUDIT_FIELDS.items()}
        if f["entry"] == row["entry_id"]:
            ts = parse_rfc3339_ns(ln.partition(" ")[0])
            return {"server_delete_entry_ns": ts, "server_delete_entry_after_send_ms": ms(ts - row["delete_send_ns"])}
    return {}


def agent_sync_fields(syncs: list[int], row: dict) -> dict:
    """C's node agent's SyncAuthorizedEntries calls around the revoke."""
    t0, gone = row["delete_send_ns"], row["failed_fetch_recv_ns"]
    out: dict = {}
    before = [ts for ts in syncs if ts < t0]
    if before:
        out.update(phase_since_child_agent_sync_ms=ms(t0 - max(before)), child_agent_last_sync_before_delete_ns=max(before))
    if gone != "":
        upto = [ts for ts in syncs if ts <= gone]
        if upto:
            out.update(child_agent_sync_before_gone_ns=max(upto), child_agent_sync_before_gone_after_send_ms=ms(max(upto) - t0))
        out["child_agent_syncs_between"] = sum(1 for ts in syncs if t0 < ts <= gone)
    return out


# --------------------------------------------------------------------------
# one trial

def revoke_wait(pod: str, child_id: str, args: argparse.Namespace) -> ParentsimStream:
    return ParentsimStream(pod, "revoke-wait", f"-expect-id={child_id}", f"-call-url={DATASET_URL}",
                           f"-call-audience={c.RESOURCE_AUD}", f"-poll-interval={args.interval_ms}ms",
                           f"-poll-timeout={args.wait_timeout_s}s")


def run_trial(trial: int, run_id: str, pods: dict[str, str], args: argparse.Namespace, jitter_s: float) -> tuple[dict, dict]:
    row: dict = {k: "" for k in CSV_FIELDS}
    row["trial"], row["ready_jitter_ms"] = trial, round(jitter_s * 1000, 3)
    raw: dict = {"trial": trial, "parent_log": []}
    tag = f"{run_id}-{trial:02d}"

    def fail(msg: str) -> tuple[dict, dict]:
        row["ok"], row["error"] = False, msg
        raw["error"] = msg
        return row, raw

    hint = f"child/r2d-{tag}"
    child_id = f"{PARENT_ID}/{hint}"
    row["child_spiffe_id"] = child_id

    waiter = None
    chain_id = None
    dele = None
    try:
        # --- P vends C's identity; wait until C holds it ------------------------
        r = vend(pods["p"], hint, f"r2d_{tag}", CHILD_SA, SCOPES, args.ttl)
        raw["parent_log"] += stamp_lines("parentsim vend", r.raw)
        if r.code != 201:
            return fail(f"vend failed: {r.code} {r.raw[:200]}")
        body = json.loads(r.body)
        chain_id = body["chain_id"]
        row.update(chain_id=chain_id, entry_id=body.get("entry_id", ""), vend_status=r.code)
        if not wait_for_svid(pods["c"], child_id):
            return fail("C pod never obtained its SVID")

        # --- C starts its request loop and is answered 200 ----------------------
        waiter = revoke_wait(pods["c"], child_id, args)
        ready = waiter.next_event(30)
        raw["wait_ready"] = ready
        if not ready or ready.get("event") != "ready":
            return fail(f"revoke-wait never reported ready: {ready} {waiter.other[-3:]}")
        row.update(ready_recv_ns=ready["recv_ns"])
        # a seeded random point of the agent's sync cycle, then a short settle
        time.sleep(jitter_s + args.settle_s)

        # --- t0: P revokes C, stamping the clock around the DELETE in its pod ----
        out = c.exec_pod(NS, pods["p"], "parentsim", "/parentsim", "dispose-timed", f"-chain-id={chain_id}")
        raw["parent_log"] += stamp_lines("parentsim dispose-timed", out)
        dele = json_line(out)
        raw["delete"] = dele
        if not dele or dele.get("status") != 200:
            return fail(f"timed DELETE failed: {out[:200]}")
        row.update(delete_send_ns=dele["send_ns"], delete_recv_ns=dele["recv_ns"], delete_status=dele["status"],
                   delete_round_trip_ms=ms(dele["round_trip_ns"]), dispose_status=dele["status"])

        # --- C's first 403 and then its first failed fetch ------------------------
        final = waiter.next_event(args.wait_timeout_s + 15)
        raw["wait_final"] = final
        if not final:
            return fail(f"revoke-wait reported nothing after the DELETE: {waiter.other[-3:]}")
    finally:
        if waiter:
            waiter.close()
        # Dispose even when the trial failed before the DELETE was answered, so the
        # next trial starts with no identity.
        if chain_id and not (dele and dele.get("status") == 200):
            d = c.parentsim(NS, pods["p"], "dispose", f"-chain-id={chain_id}")
            raw["dispose"] = d.code
            raw["parent_log"] += stamp_lines("parentsim dispose", d.raw)

    t0 = dele["send_ns"]
    row["wait_event"] = final.get("event", "")
    row.update(
        first_denial_status=403 if final.get("first_403_recv_ns") else final.get("status", ""),
        first_403_send_ns=final.get("first_403_send_ns", ""), first_403_recv_ns=final.get("first_403_recv_ns", ""),
        first_403_jwt_send_ns=final.get("first_403_jwt_send_ns", ""), first_403_jwt_recv_ns=final.get("first_403_jwt_recv_ns", ""),
        last_200_send_ns=final.get("last_200_send_ns", ""), last_200_recv_ns=final.get("last_200_recv_ns", ""),
        last_fetch_ok_send_ns=final.get("last_fetch_ok_send_ns", ""), last_fetch_ok_recv_ns=final.get("last_fetch_ok_recv_ns", ""),
        failed_fetch_send_ns=final.get("failed_fetch_send_ns", ""), failed_fetch_recv_ns=final.get("failed_fetch_recv_ns", ""),
        failed_fetch_error=final.get("failed_fetch_error", ""),
        ready_before_delete_ms=ms(t0 - ready["recv_ns"]),
        denials=final.get("denials", 0), other_statuses=json.dumps(final.get("other_statuses", {}), sort_keys=True),
        first_403_token_is_ready_token=final.get("first_403_token_is_ready_token", ""),
        distinct_tokens=final.get("distinct_tokens", 0),
        polls=final.get("polls", 0), transport_errors=final.get("transport_errors", 0),
        pre_ready_fetch_failures=final.get("pre_ready_fetch_failures", 0), pre_ready_denials=final.get("pre_ready_denials", 0),
        loop_gap_mean_ms=ms(final.get("gap_mean_ns", 0)), loop_gap_max_ms=ms(final.get("gap_max_ns", 0)),
        fetch_latency_mean_ms=ms(final.get("fetch_latency_mean_ns", 0)), fetch_latency_max_ms=ms(final.get("fetch_latency_max_ns", 0)),
        call_latency_mean_ms=ms(final.get("call_latency_mean_ns", 0)), call_latency_max_ms=ms(final.get("call_latency_max_ns", 0)),
    )
    if final.get("first_403_recv_ns"):
        row.update(revoke_to_deny_ms=ms(final["first_403_recv_ns"] - t0), revoke_to_deny_send_basis_ms=ms(final["first_403_send_ns"] - t0))
        if final.get("last_200_send_ns"):
            row["denial_window_ms"] = ms(final["first_403_recv_ns"] - final["last_200_send_ns"])
    if final.get("failed_fetch_recv_ns"):
        row.update(revoke_to_identity_gone_ms=ms(final["failed_fetch_recv_ns"] - t0),
                   revoke_to_identity_gone_send_basis_ms=ms(final["failed_fetch_send_ns"] - t0))
        if final.get("first_403_recv_ns"):
            row["deny_to_identity_gone_ms"] = ms(final["failed_fetch_recv_ns"] - final["first_403_recv_ns"])

    row["c_entry_gone"] = not c.entry_exists(child_id)

    # ok: the DELETE answered 200, a 200 before it, the first refusal after it a
    # 403 (the loop ends "unexpected" on any other status), and a failed fetch seen.
    problems = []
    if final.get("event") != "identity_gone":
        problems.append(f"loop ended {final.get('event')}: {final.get('error', '')}")
    if not final.get("first_403_recv_ns"):
        problems.append("no 403 seen")
    elif final["first_403_recv_ns"] <= t0:
        problems.append("the first 403 was received before the DELETE was sent")
    if ready["recv_ns"] >= t0:
        problems.append("no 200 before the DELETE")
    if problems:
        return fail("; ".join(problems))
    row["ok"] = True
    return row, raw


# --------------------------------------------------------------------------
# summary

def count(rows: list[dict], key: str, want: object = True) -> int:
    return sum(1 for r in rows if r[key] == want)


def summarise(rows: list[dict], args: argparse.Namespace, inv: dict, started: str, finished: str) -> dict:
    ok_rows = [r for r in rows if r["ok"]]
    with_t0 = [r for r in rows if r["delete_send_ns"] != ""]
    first_status: dict[str, int] = {}
    for r in with_t0:
        k = str(r["first_denial_status"])
        first_status[k] = first_status.get(k, 0) + 1
    return {
        "run_id": args.run_id, "started_at": started, "finished_at": finished,
        "trials_requested": args.trials, "trials_completed": len(ok_rows), "trials_failed": len(rows) - len(ok_rows),
        "config": {
            "poll_interval_target_ms": args.interval_ms, "settle_s": args.settle_s, "ttl_s": args.ttl,
            "jitter_s": args.jitter_s, "jitter_seed": args.seed, "wait_timeout_s": args.wait_timeout_s,
            "jitter_applies": "after C's ready and before the DELETE: a seeded uniform random 0..jitter_s wait, then settle_s",
            "spire_server_audit_log_enabled": inv.get("spire_server_audit_log_enabled"),
        },
        "percentile_method": "nearest-rank", "stdev_method": "sample (n-1)", "unit": "ms",
        "headline": "revoke_to_deny_ms: P sends DELETE /delegations/{chain_id} (t0) -> C receives its first 403 from the resource "
                    "for GET /datasets/A, sent with a JWT-SVID C fetched from its agent in the same tick",
        "secondary": "revoke_to_identity_gone_ms: t0 -> C receives the answer to its first failed JWT-SVID fetch "
                     "(no identity issued); C does not call the resource without a token",
        "revoke_to_deny_ms": stats(column(rows, "revoke_to_deny_ms")),
        "revoke_to_identity_gone_ms": stats(column(rows, "revoke_to_identity_gone_ms")),
        "deny_to_identity_gone_ms (first 403 received -> failed fetch received)": stats(column(rows, "deny_to_identity_gone_ms")),
        "revoke_to_deny_send_basis_ms (t0 -> first 403 request sent)": stats(column(rows, "revoke_to_deny_send_basis_ms")),
        "revoke_to_identity_gone_send_basis_ms (t0 -> failed fetch sent)": stats(column(rows, "revoke_to_identity_gone_send_basis_ms")),
        "denial_window_ms (first 403 received - last 200 sent: uncertainty in when the denial began)": stats(column(rows, "denial_window_ms")),
        "delete_round_trip_ms": stats(column(rows, "delete_round_trip_ms")),
        "resource_deny_after_send_ms (t0 -> the resource's first deny audit event)": stats(column(rows, "resource_deny_after_send_ms")),
        "policy_dispose_after_send_ms (t0 -> the policy engine's dispose event, grant removed)": stats(column(rows, "policy_dispose_after_send_ms")),
        "vending_dispose_after_send_ms (t0 -> the vending service's dispose event)": stats(column(rows, "vending_dispose_after_send_ms")),
        "server_delete_entry_after_send_ms (t0 -> server audit BatchDeleteEntry)": stats(column(rows, "server_delete_entry_after_send_ms")),
        "phase_since_child_agent_sync_ms (t0 - C's agent's last sync before it)": stats(column(rows, "phase_since_child_agent_sync_ms")),
        "child_agent_sync_before_gone_after_send_ms (t0 -> C's agent's last sync before the failed fetch)": stats(column(rows, "child_agent_sync_before_gone_after_send_ms")),
        "child_agent_syncs_between (C's agent's syncs after t0 up to the failed fetch)": {
            str(k): sum(1 for r in ok_rows if r["child_agent_syncs_between"] == k)
            for k in sorted({r["child_agent_syncs_between"] for r in ok_rows if r["child_agent_syncs_between"] != ""})},
        "agent_log_after_send_ms (t0 -> C's node agent's first log line naming C)": stats(column(rows, "agent_log_after_send_ms")),
        "first_denial_status_counts (trials with a DELETE answered)": first_status,
        "denials_before_identity_gone": stats(column(rows, "denials")),
        "tokens": {
            "trials_first_403_used_the_ready_token": count(ok_rows, "first_403_token_is_ready_token", True),
            "trials_first_403_used_a_different_token": count(ok_rows, "first_403_token_is_ready_token", False),
            "distinct_tokens_per_trial": {str(k): sum(1 for r in ok_rows if r["distinct_tokens"] == k)
                                          for k in sorted({r["distinct_tokens"] for r in ok_rows})},
        },
        "achieved_loop_gap_ms": {
            "mean_of_trial_means": round(statistics.fmean(column(rows, "loop_gap_mean_ms")), 3) if ok_rows else None,
            "max_of_trial_maxes": max(column(rows, "loop_gap_max_ms"), default=None),
            "trials_with_mean_gap_over_50ms": sum(1 for v in column(rows, "loop_gap_mean_ms") if v > 50),
        },
        "fetch_latency_ms": {"mean_of_trial_means": round(statistics.fmean(column(rows, "fetch_latency_mean_ms")), 3) if ok_rows else None,
                             "max_of_trial_maxes": max(column(rows, "fetch_latency_max_ms"), default=None)},
        "call_latency_ms": {"mean_of_trial_means": round(statistics.fmean(column(rows, "call_latency_mean_ms")), 3) if ok_rows else None,
                            "max_of_trial_maxes": max(column(rows, "call_latency_max_ms"), default=None)},
        "checks": {
            "trials_ok": len(ok_rows),
            "trials_delete_200": sum(1 for r in rows if r["delete_status"] == 200),
            "trials_first_denial_403": sum(1 for r in with_t0 if r["first_denial_status"] == 403),
            "trials_with_resource_deny_event": sum(1 for r in ok_rows if r["resource_deny_ns"] != ""),
            "trials_resource_deny_inside_403_request": count(ok_rows, "resource_deny_inside_403_request"),
            "trials_with_policy_dispose_event": sum(1 for r in ok_rows if r["policy_dispose_ns"] != ""),
            "trials_with_vending_dispose_event": sum(1 for r in ok_rows if r["vending_dispose_ns"] != ""),
            "trials_with_server_delete_entry": sum(1 for r in ok_rows if r["server_delete_entry_ns"] != ""),
            "trials_with_agent_sync_before_delete": sum(1 for r in ok_rows if r["phase_since_child_agent_sync_ms"] != ""),
            "trials_with_agent_sync_before_gone": sum(1 for r in ok_rows if r["child_agent_sync_before_gone_ns"] != ""),
            "trials_with_agent_log_line": sum(1 for r in ok_rows if r["agent_log_ns"] != ""),
            "trials_c_entry_gone": count(ok_rows, "c_entry_gone"),
            "trials_order_ok": count(ok_rows, "order_ok"),
            "trials_with_transport_errors": sum(1 for r in ok_rows if r["transport_errors"] not in ("", 0)),
            "trials_with_other_statuses": sum(1 for r in ok_rows if r["other_statuses"] not in ("", "{}")),
        },
        "logs": {
            "dir": "logs/",
            "files": "logs/{vending-service,spire-server,resource,policy-engine,spire-agent,parent}/trial-NN.log",
            "window": "contiguous per trial: from the end of the previous trial's window (the first starts 1 s before trial 1) "
                      "to the moment C held no identity again after the revoke",
            "timestamp": "first field of each line: the container runtime's capture time (kubectl logs --timestamps); "
                         "for parent/, the time this host received P's command output; spire-agent/ is C's node agent",
            "spire_server_audit_log_enabled": inv.get("spire_server_audit_log_enabled"),
            "lines": {k: sum(int(r[f"{k}_log_lines"] or 0) for r in rows)
                      for k in ("vending_service", "spire_server", "resource", "policy_engine", "spire_agent", "parent")},
        },
        "host": inv,
    }


# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--trials", type=int, default=int(os.environ.get("REVOKE_DENY_TRIALS", "50")))
    ap.add_argument("--interval-ms", type=int, default=20, help="C's loop interval (1-50)")
    ap.add_argument("--settle-s", type=float, default=0.2, help="waiting time after the jitter, before P's DELETE")
    ap.add_argument("--wait-timeout-s", type=int, default=60, help="give up on a trial's loop after this long")
    ap.add_argument("--ttl", type=int, default=300, help="ttl_seconds of each vended child")
    ap.add_argument("--jitter-s", type=float, default=float(os.environ.get("REVOKE_DENY_JITTER_S", "0")),
                    help="after C's ready, wait a uniform random 0..J s before the DELETE, so it lands at a random point of the agent's sync cycle")
    ap.add_argument("--seed", type=int, default=None, help="seed for --jitter-s (default: random, recorded in the summary)")
    ap.add_argument("--run-id", default=None)
    args = ap.parse_args()
    if not 1 <= args.interval_ms <= 50:
        ap.error("--interval-ms must be between 1 and 50")
    if args.jitter_s < 0:
        ap.error("--jitter-s must not be negative")
    if args.run_id is None:
        args.run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-revoke-to-deny"
    if args.seed is None:
        args.seed = random.SystemRandom().randrange(2**32)
    rng = random.Random(args.seed)

    print(f"== revoke to deny: {args.trials} trials, C fetches a token and calls the resource every {args.interval_ms} ms"
          + (f", random 0-{args.jitter_s:g} s wait before each DELETE (seed {args.seed})" if args.jitter_s else "") + " ==")
    pods = {"p": c.wait_for_pod(NS, "app=experiments-parent"), "c": c.wait_for_pod(NS, "app=experiments-child")}
    node, agent_pod = agent_pod_for(pods["c"])
    print(f"P={pods['p']} C={pods['c']} (node {node}, agent {agent_pod})")

    # The fixture pods run a fixed image tag; one started before revoke-wait
    # existed does not have it.
    if "revoke-wait requires" not in c.parentsim(NS, pods["c"], "revoke-wait").raw:
        print("FATAL: the fixture pods run a parentsim image without the `revoke-wait` mode.\n"
              "       Rebuild and recreate them:  make experiments-fixtures-down experiments-fixtures-up", file=sys.stderr)
        return 2
    if not wait_for_svid(pods["p"], PARENT_ID):
        print("FATAL: P does not hold its own identity", file=sys.stderr)
        return 2
    if not wait_no_identity(pods["c"]):
        print("FATAL: C still holds an identity from an earlier run", file=sys.stderr)
        return 2

    inv = host_inventory()
    inv["load_average_start"] = [round(x, 2) for x in os.getloadavg()]
    inv["spire_images"] = c.kubectl("get", "pods", "-n", "spire", "-o",
                                    "jsonpath={range .items[*]}{.metadata.name}={.spec.containers[0].image}{'\\n'}{end}",
                                    check=False).stdout.strip().splitlines()
    inv["child_node"], inv["child_agent_pod"] = node, agent_pod
    comp_pods = {"vending-service": c.running_pod("nhi", "app=vending-service"),
                 "spire-server": "spire-server-0",
                 "resource": c.running_pod("nhi", "app=resource"),
                 "policy-engine": c.running_pod("nhi", "app=policy-engine"),
                 "spire-agent": agent_pod}
    if not all(comp_pods.values()):
        print(f"FATAL: need running vending-service, resource and policy-engine pods (got {comp_pods})", file=sys.stderr)
        return 2
    inv["component_pods"] = comp_pods
    inv["spire_server_audit_log_enabled"] = spire_server_audit_enabled()
    agents = agent_ids_by_node()
    inv["agent_ids_by_node"] = agents
    print(f"vending service {comp_pods['vending-service']}; resource {comp_pods['resource']}; "
          f"policy engine {comp_pods['policy-engine']}; "
          f"SPIRE server audit log {'on' if inv['spire_server_audit_log_enabled'] else 'OFF'}")
    out_dir = Path(__file__).parent / "results" / args.run_id
    log_dirs = {n: out_dir / "logs" / n for n in [x[0] for x in COMPONENTS] + ["parent"]}
    for d in log_dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    started = c.now_iso()
    window_start = time.time_ns() - 1_000_000_000

    run_id = uuid.uuid4().hex[:6]
    rows: list[dict] = []
    raws: list[dict] = []
    child_agent_syncs: list[int] = []
    for t in range(1, args.trials + 1):
        jitter = rng.uniform(0, args.jitter_s) if args.jitter_s else 0.0
        t_start = time.monotonic()
        try:
            row, raw = run_trial(t, run_id, pods, args, jitter)
        except Exception as exc:  # noqa: BLE001 - one bad trial must not lose the others
            row = {k: "" for k in CSV_FIELDS}
            row.update(trial=t, ok=False, error=f"exception: {exc}", ready_jitter_ms=round(jitter * 1000, 3))
            raw = {"trial": t, "error": str(exc), "parent_log": []}
        rows.append(row)
        raws.append(raw)
        shown = (f"deny {row['revoke_to_deny_ms']:.1f} ms, identity gone {row['revoke_to_identity_gone_ms']:.1f} ms "
                 f"(wait {row['ready_jitter_ms'] / 1000:.2f} s)" if row["ok"] else f"FAILED ({row['error']})")
        print(f"  trial {t:2d}/{args.trials}: {shown}  [{time.monotonic() - t_start:.1f}s]", flush=True)
        # Leave C without an identity so the next trial starts clean.
        wait_no_identity(pods["c"])

        # This trial's log window, one file per component.
        window_end = time.time_ns()
        have_t0 = row["delete_send_ns"] != ""
        for name, ns, ctr in COMPONENTS:
            lines = component_logs(ns, comp_pods[name], ctr, window_start, window_end)
            (log_dirs[name] / f"trial-{t:02d}.log").write_text("".join(ln + "\n" for ln in lines))
            row[f"{name.replace('-', '_')}_log_lines"] = len(lines)
            if name == "spire-server":
                server_lines = [ln for ln in lines if "type=audit" in ln]
                child_agent_syncs += [parse_rfc3339_ns(ln.partition(" ")[0]) for ln in server_lines
                                      if "method=SyncAuthorizedEntries" in ln and f'caller_id="{agents[node]}"' in ln]
                if have_t0:
                    row.update(server_delete_entry(lines, row))
                    row.update(agent_sync_fields(child_agent_syncs, row))
            elif not have_t0:
                continue
            elif name == "resource":
                fields, raw["resource_first_deny"] = resource_deny(lines, row)
                row.update(fields)
            elif name == "policy-engine":
                fields, raw["policy_dispose"] = stage_event(lines, row, "dispose", "policy_dispose")
                row.update(fields)
            elif name == "vending-service":
                fields, raw["vending_dispose"] = stage_event(lines, row, "dispose", "vending_dispose")
                row.update(fields)
            elif name == "spire-agent":
                hits = []
                for ln in lines:
                    ts, _, rest = ln.partition(" ")
                    if row["child_spiffe_id"] in ln and parse_rfc3339_ns(ts) > row["delete_send_ns"]:
                        hits.append((parse_rfc3339_ns(ts), rest[:300]))
                raw["agent_log"] = {"ns": hits[0][0], "line": hits[0][1]} if hits else None
                if hits:
                    row.update(agent_log_ns=hits[0][0], agent_log_after_send_ms=ms(hits[0][0] - row["delete_send_ns"]),
                               agent_log_message=hits[0][1])
        parent_lines = raw.get("parent_log", [])
        (log_dirs["parent"] / f"trial-{t:02d}.log").write_text("".join(ln + "\n" for ln in parent_lines))
        row["parent_log_lines"] = len(parent_lines)
        row["log_window_start_ns"], row["log_window_end_ns"] = window_start, window_end
        if row["ok"]:
            # Causality: t0 < first 403 received <= failed fetch received, and the
            # resource's deny event falls inside the 403 request.
            row["order_ok"] = (row["delete_send_ns"] < row["first_403_recv_ns"] <= row["failed_fetch_recv_ns"]
                               and row["resource_deny_inside_403_request"] is True)
        window_start = window_end

    inv["load_average_end"] = [round(x, 2) for x in os.getloadavg()]
    summary = summarise(rows, args, inv, started, c.now_iso())

    with (out_dir / "revoke_to_deny.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)
    (out_dir / "revoke_to_deny_summary.json").write_text(json.dumps(summary, indent=2, default=str))
    (out_dir / "revoke_to_deny_raw.json").write_text(json.dumps(raws, indent=2, default=str))

    print()
    print(f"  trials completed {summary['trials_completed']}/{args.trials}, failed {summary['trials_failed']}")
    for k in ("revoke_to_deny_ms", "revoke_to_identity_gone_ms"):
        s = summary[k]
        if s.get("n"):
            print(f"  {k}: p50 {s['p50']}  p95 {s['p95']}  min {s['min']}  max {s['max']}  mean {s['mean']}  stdev {s['stdev']}")
    print(f"  checks: {summary['checks']}")
    print(f"results: {out_dir}")
    return 0 if summary["trials_failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
