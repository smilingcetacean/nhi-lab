#!/usr/bin/env python3
"""Vend to identity: how long after a parent sends its vend request can the child obtain its SVID?

`make vend-to-svid` is the entry point. Not part of `make experiments`.

Each trial has the experiments parent P vend a fresh child SPIFFE ID for the
experiments child pod C, and measures the time from the moment P sends
`POST /delegations` (t0) to the moment C first receives the matching
X.509-SVID from its SPIRE agent's Workload API (t3). That is the headline.

The intermediate instants are recorded alongside it:

  t1  P receives the 201. The vending service creates the SPIRE registration
      entry (BatchCreateEntry) before it answers, so by t1 the entry is in the
      SPIRE server's datastore.
  t2  C's node agent logs the new entry, i.e. the agent's sync has brought it
      from the server. Read from `kubectl logs --timestamps` (the container
      runtime's capture time), so it has no in-process clock of its own.

The vending service's audit events (attest allow, vend allow) are recorded too,
to split t0 -> t1 into network and server time. With the SPIRE server's API
audit log on, its lines give the server's side: when it created the entry
(BatchCreateEntry), when C's node agent synced (SyncAuthorizedEntries), and when
that agent had the server sign C's X.509-SVID (BatchNewX509SVID). The count of
C's agent's syncs after t1 that did not bring the entry shows how long the
entry took to become available to agents, as against being in the datastore.

Why the timing is taken inside the cluster
------------------------------------------
One `kubectl exec` costs 50-70 ms, the same order as t0 -> t1, so neither
stamp can be taken from this host. Instead:

  * C's pod runs `parentsim svid-wait`: a loop that asks the Workload API for
    the pod's X.509-SVIDs every `--interval-ms` (default 20 ms) and stops at
    the first answer that contains the expected SPIFFE ID. It reports "ready"
    after its first answered miss, and the harness vends only after that, so
    every trial starts from a pod with no identity.
  * P's pod runs `parentsim vend-timed`, which signs the manifest first and
    then stamps the wall clock just before it writes the POST and just after it
    reads the response headers.

Both stamp CLOCK_REALTIME in Unix nanoseconds. The kind nodes are containers on
one host and share its kernel clock, so stamps from different pods are directly
comparable (the same assumption as revocation_speed.py). It would not hold on a
cluster whose nodes are separate machines.

Phase. C's agent syncs with the server about every 5 s, and the old identity
leaves C only at such a sync, so a trial that starts as soon as C is clear
vends at about the same point of the sync cycle every time. `--jitter-s J`
waits a uniform random 0..J s before each trial (seeded; the seed is in the
summary) so the vend lands at a random point of the cycle instead. Each row
records `pre_trial_jitter_ms` and `phase_since_child_agent_sync_ms` (t0 minus
C's agent's last SyncAuthorizedEntries before it; needs the server audit log).

Resolution: C received the identity at t3 (the headline). It became available
to C some time after the last miss was sent, so each row also carries
`svid_window_ms` (t3 minus the last miss's send), the width of that
uncertainty, and `vend_to_svid_send_basis_ms`, measured to the obtaining
fetch's send.

Output (`results/<run-id>/`)
----------------------------
  vend_to_svid.csv            one row per trial
  vend_to_svid_summary.json   statistics, histogram, host inventory
  vend_to_svid_raw.json       the raw waiter / vend / audit / agent-log records
  logs/vending-service/trial-NN.log
  logs/spire-server/trial-NN.log
                              each component's log lines for one trial (its vend,
                              the identity's delivery, the dispose and the drain
                              before the next trial), prefixed with the container
                              runtime's timestamp. The windows are contiguous, so
                              every line of the run is in exactly one trial file.
                              The SPIRE server logs nothing per request at its
                              default INFO level; its API audit log
                              (`audit_log_enabled = true` in server.conf) makes it
                              log each call, and the summary records whether it
                              was on.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import re
import statistics
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from lib import cluster as c  # noqa: E402
from revocation_speed import (  # noqa: E402  - shared timing helpers
    NS, PARENT_ID, ParentsimStream, audit_events, host_inventory, json_line, ms,
    nearest_rank, parse_rfc3339_ns, wait_for_svid, wait_no_identity,
)

CHILD_SA = "nhi-exp-child"
SCOPES = "resource:read:datasetA"
CLOCK_SLACK_NS = 2_000_000  # 2 ms of clock-read skew between processes
HIST_BIN_MS = 500

CSV_FIELDS = [
    "trial", "ok", "error", "child_spiffe_id", "chain_id", "entry_id",
    "vend_attempts", "vend_status",
    # t0, t1 (P's pod)
    "vend_send_ns", "vend_recv_ns", "vend_round_trip_ms",
    # vending-service audit
    "audit_attest_allow_ns", "audit_vend_allow_ns", "server_attest_to_vend_ms",
    "audit_vend_allow_after_send_ms", "audit_inside_vend_request",
    # t2 (C's node agent log)
    "agent_log_ns", "agent_log_after_send_ms", "agent_log_message",
    # t3 (C's pod)
    "svid_obtained_send_ns", "svid_obtained_recv_ns", "last_miss_send_ns", "last_miss_recv_ns",
    "vend_to_svid_ms",              # t3 - t0: the headline
    "vend_to_svid_send_basis_ms",   # obtaining fetch sent - t0
    "svid_after_vend_response_ms",  # t3 - t1
    "svid_window_ms",               # t3 - last miss sent: the uncertainty in the arrival instant
    "wait_attempts", "wait_misses", "wait_gap_mean_ms", "wait_gap_max_ms",
    "wait_latency_mean_ms", "wait_latency_max_ms", "miss_reasons",
    "svid_not_after", "order_ok", "dispose_status",
    "log_window_start_ns", "log_window_end_ns", "vending_service_log_lines", "spire_server_log_lines",
    # SPIRE server API audit log (runtime timestamps); empty when the audit log is off
    "server_create_entry_ns", "server_create_entry_after_send_ms",
    "server_first_svid_ns", "server_first_svid_node", "server_first_svid_after_send_ms",
    "server_child_agent_svid_ns", "server_child_agent_svid_after_send_ms",
    "child_agent_finding_sync_ns", "child_agent_finding_sync_after_send_ms", "child_agent_syncs_missed",
    "pre_trial_jitter_ms", "phase_since_child_agent_sync_ms",
]

AUDIT_FIELDS = {
    "method": re.compile(r'\bmethod=(\w+)'),
    "caller": re.compile(r'\bcaller_id="([^"]+)"'),
    "entry": re.compile(r'\bentry_id=([0-9a-f-]+)'),
    "spiffe": re.compile(r'\bspiffe_id="([^"]+)"'),
}


def ns_to_rfc3339(ns: int) -> str:
    secs, frac = divmod(ns, 1_000_000_000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(secs)) + f".{frac:09d}Z"


def vend_timed(pod: str, hint: str, nonce: str, ttl: int) -> tuple[dict | None, str, int]:
    """`parentsim vend-timed`, retrying a transient policy-engine connect delay on a
    fresh nonce (as revocation_speed.vend does). The timing is that of the attempt
    that answered. Returns (timed result, raw output, attempts)."""
    out = ""
    for attempt in range(1, 5):
        n = nonce if attempt == 1 else f"{nonce}_r{attempt}"
        out = c.exec_pod(NS, pod, "parentsim", "/parentsim", "vend-timed",
                         f"-child-path-hint={hint}", f"-nonce={n}", f"-scopes={SCOPES}",
                         "-task-context=vend to svid", f"-selectors=k8s:ns={NS},k8s:sa={CHILD_SA}", f"-ttl={ttl}")
        res = json_line(out)
        if res and res.get("status") == 502 and "context deadline exceeded" in res.get("response", ""):
            time.sleep(3)
            continue
        return res, out, attempt
    return json_line(out), out, 4


def component_logs(ns: str, pod: str, container: str, start_ns: int, end_ns: int) -> list[str]:
    """A container's log lines captured in [start_ns, end_ns), runtime timestamp first.
    --since-time is whole seconds, so the window is cut precisely here."""
    res = c.kubectl("logs", "-n", ns, pod, "-c", container, "--timestamps",
                    f"--since-time={ns_to_rfc3339(start_ns - start_ns % 1_000_000_000)}", check=False, timeout=60)
    keep = []
    for ln in (res.stdout or "").splitlines():
        try:
            t = parse_rfc3339_ns(ln.partition(" ")[0])
        except ValueError:
            continue
        if start_ns <= t < end_ns:
            keep.append(ln)
    return keep


def agent_ids_by_node() -> dict[str, str]:
    """node name -> the SPIFFE ID its agent attests as (k8s_psat: the node's UID)."""
    out = c.kubectl("get", "nodes", "-o", "jsonpath={range .items[*]}{.metadata.name}={.metadata.uid}{'\\n'}{end}").stdout
    return {n: f"spiffe://{c.TRUST_DOMAIN}/spire/agent/k8s_psat/{c.CLUSTER_NAME}/{u}"
            for n, _, u in (ln.partition("=") for ln in out.split()) if u}


def server_audit(lines: list[str], row: dict, agents: dict[str, str], child_node: str) -> dict:
    """The server-side instants of one trial, from the SPIRE server's API audit lines."""
    calls = []
    for ln in lines:
        if "type=audit" not in ln:
            continue
        f = {k: (m.group(1) if (m := rx.search(ln)) else None) for k, rx in AUDIT_FIELDS.items()}
        calls.append((parse_rfc3339_ns(ln.partition(" ")[0]), f))
    t0, t1, child_agent = row["vend_send_ns"], row["vend_recv_ns"], agents[child_node]
    node_of = {v: k for k, v in agents.items()}
    out: dict = {}
    create = [ts for ts, f in calls if f["method"] == "BatchCreateEntry" and f["spiffe"] == row["child_spiffe_id"]]
    if create:
        out.update(server_create_entry_ns=create[0], server_create_entry_after_send_ms=ms(create[0] - t0))
    svids = sorted((ts, f["caller"]) for ts, f in calls
                   if f["method"] == "BatchNewX509SVID" and f["entry"] == row["entry_id"])
    if svids:
        out.update(server_first_svid_ns=svids[0][0], server_first_svid_node=node_of.get(svids[0][1], svids[0][1]),
                   server_first_svid_after_send_ms=ms(svids[0][0] - t0))
    mine = [ts for ts, who in svids if who == child_agent]
    if mine:
        out.update(server_child_agent_svid_ns=mine[0], server_child_agent_svid_after_send_ms=ms(mine[0] - t0))
        syncs = [ts for ts, f in calls if f["method"] == "SyncAuthorizedEntries" and f["caller"] == child_agent]
        before = [ts for ts in syncs if ts <= mine[0]]
        if before:
            finding = before[-1]
            out.update(child_agent_finding_sync_ns=finding, child_agent_finding_sync_after_send_ms=ms(finding - t0),
                       child_agent_syncs_missed=sum(1 for ts in syncs if t1 < ts < finding))
    return out


def vending_audit(chain_id: str, t0: int, t1: int) -> tuple[dict, dict | None, dict | None]:
    """The vending service's attest-allow and vend-allow audit events for one vend.
    Returns (row fields, vend-allow event, attest-allow event)."""
    vend_ev = attest_ev = None
    for _ in range(10):
        evs = audit_events("app=vending-service", "vending-service")
        vend_ev = next((e for e in evs if e.get("chain_id") == chain_id and e.get("stage") == "vend"
                        and e.get("outcome") == "allow"), None)
        if vend_ev:
            v_ns = parse_rfc3339_ns(vend_ev["timestamp"])
            # attest allow carries no chain_id: take P's last one at or before the vend allow
            cands = [e for e in evs if e.get("stage") == "attest" and e.get("outcome") == "allow"
                     and e.get("actor_spiffe_id") == PARENT_ID
                     and t0 - CLOCK_SLACK_NS <= parse_rfc3339_ns(e["timestamp"]) <= v_ns]
            attest_ev = max(cands, key=lambda e: parse_rfc3339_ns(e["timestamp"])) if cands else None
            break
        time.sleep(0.5)
    fields: dict = {}
    if vend_ev:
        v_ns = parse_rfc3339_ns(vend_ev["timestamp"])
        fields.update(audit_vend_allow_ns=v_ns, audit_vend_allow_after_send_ms=ms(v_ns - t0),
                      audit_inside_vend_request=t0 - CLOCK_SLACK_NS <= v_ns <= t1 + CLOCK_SLACK_NS)
        if attest_ev:
            a_ns = parse_rfc3339_ns(attest_ev["timestamp"])
            fields.update(audit_attest_allow_ns=a_ns, server_attest_to_vend_ms=ms(v_ns - a_ns))
    return fields, vend_ev, attest_ev


def spire_server_audit_enabled() -> bool:
    conf = c.kubectl("get", "configmap", "-n", "spire", "spire-server", "-o", "jsonpath={.data.server\\.conf}",
                     check=False).stdout
    return any(ln.split("#")[0].replace(" ", "") == "audit_log_enabled=true" for ln in conf.splitlines())


def agent_pod_for(pod: str) -> tuple[str, str]:
    """The SPIRE agent pod on the node that runs `pod`."""
    node = c.kubectl("get", "pod", "-n", NS, pod, "-o", "jsonpath={.spec.nodeName}").stdout.strip()
    agent = c.kubectl("get", "pods", "-n", "spire", "-l", "app=spire-agent",
                      f"--field-selector=spec.nodeName={node}", "-o", "jsonpath={.items[0].metadata.name}").stdout.strip()
    if not agent:
        raise RuntimeError(f"no SPIRE agent pod on node {node}")
    return node, agent


def agent_first_line(agent_pod: str, spiffe_id: str, since_ns: int) -> tuple[int | None, str]:
    """The earliest agent log line naming spiffe_id, with its container-runtime timestamp."""
    res = c.kubectl("logs", "-n", "spire", agent_pod, "-c", "spire-agent", "--timestamps",
                    f"--since-time={ns_to_rfc3339(since_ns)}", check=False, timeout=30)
    best: tuple[int | None, str] = (None, "")
    for ln in (res.stdout or "").splitlines():
        if spiffe_id not in ln:
            continue
        ts, _, rest = ln.partition(" ")
        try:
            t = parse_rfc3339_ns(ts)
        except ValueError:
            continue
        if best[0] is None or t < best[0]:
            best = (t, rest[:300])
    return best


# --------------------------------------------------------------------------
# one trial

def run_trial(trial: int, run_id: str, pods: dict[str, str], agent_pod: str,
              args: argparse.Namespace) -> tuple[dict, dict]:
    row: dict = {k: "" for k in CSV_FIELDS}
    row["trial"] = trial
    raw: dict = {"trial": trial}
    tag = f"{run_id}-{trial:02d}"

    def fail(msg: str) -> tuple[dict, dict]:
        row["ok"], row["error"] = False, msg
        raw["error"] = msg
        return row, raw

    hint = f"child/v2s-{tag}"
    child_id = f"{PARENT_ID}/{hint}"
    row["child_spiffe_id"] = child_id
    started_ns = time.time_ns()

    # --- C starts asking for the identity before P vends it -----------------
    waiter = ParentsimStream(pods["c"], "svid-wait", f"-expect-id={child_id}",
                             f"-poll-interval={args.interval_ms}ms", f"-poll-timeout={args.wait_timeout_s}s")
    chain_id = None
    try:
        ready = waiter.next_event(20)
        raw["wait_ready"] = ready
        if not ready or ready.get("event") != "ready":
            return fail(f"svid-wait never reported ready: {ready} {waiter.other[-3:]}")
        time.sleep(args.settle_s)  # let the loop reach steady state before vending

        # --- t0 / t1: P vends, stamping the clock around the POST in its pod --
        vend, out, attempts = vend_timed(pods["p"], hint, f"v2s_{tag}", args.ttl)
        raw["vend"] = vend
        row["vend_attempts"] = attempts
        if not vend or vend.get("status") != 201:
            return fail(f"timed vend failed: {out[:300]}")
        body = json.loads(vend["response"])
        chain_id = body["chain_id"]
        row.update(chain_id=chain_id, entry_id=body.get("entry_id", ""), vend_status=vend["status"],
                   vend_send_ns=vend["send_ns"], vend_recv_ns=vend["recv_ns"],
                   vend_round_trip_ms=ms(vend["round_trip_ns"]))

        # --- t3: C's first fetch that returns the new identity --------------
        final = waiter.next_event(args.wait_timeout_s + 10)
        raw["wait_final"] = final
        if not final or final.get("event") != "obtained":
            return fail(f"svid-wait did not report the identity: {final} {waiter.other[-3:]}")
    finally:
        waiter.close()
        # Dispose even when the trial failed after the vend, so the next trial
        # starts with no identity. Recorded below for successful trials.
        if chain_id:
            raw["dispose"] = c.parentsim(NS, pods["p"], "dispose", f"-chain-id={chain_id}").code

    t0, t1 = vend["send_ns"], vend["recv_ns"]
    t3 = final["recv_ns"]
    row.update(
        svid_obtained_send_ns=final["send_ns"], svid_obtained_recv_ns=t3,
        last_miss_send_ns=final.get("last_miss_send_ns", ""), last_miss_recv_ns=final.get("last_miss_recv_ns", ""),
        vend_to_svid_ms=ms(t3 - t0),
        vend_to_svid_send_basis_ms=ms(final["send_ns"] - t0),
        svid_after_vend_response_ms=ms(t3 - t1),
        svid_window_ms=ms(t3 - final["last_miss_send_ns"]) if final.get("last_miss_send_ns") else "",
        wait_attempts=final.get("attempts", 0), wait_misses=final.get("misses", 0),
        wait_gap_mean_ms=ms(final.get("gap_mean_ns", 0)), wait_gap_max_ms=ms(final.get("gap_max_ns", 0)),
        wait_latency_mean_ms=ms(final.get("latency_mean_ns", 0)), wait_latency_max_ms=ms(final.get("latency_max_ns", 0)),
        miss_reasons=json.dumps(final.get("miss_reasons", {}), sort_keys=True),
        svid_not_after=final.get("not_after", ""),
        dispose_status=raw.get("dispose", ""),
    )

    # --- vending-service audit: attest allow and vend allow for this chain ---
    fields, raw["audit_vend_allow"], raw["audit_attest_allow"] = vending_audit(chain_id, t0, t1)
    row.update(fields)

    # --- t2: the agent on C's node logs the new entry ------------------------
    t2, msg = agent_first_line(agent_pod, child_id, started_ns - 1_000_000_000)
    raw["agent_log"] = {"ns": t2, "line": msg}
    if t2 is not None:
        row["agent_log_ns"] = t2
        row["agent_log_after_send_ms"] = ms(t2 - t0)
        row["agent_log_message"] = msg

    # Causality: P's send precedes everything else, and C held no identity
    # before P sent (its last miss was answered after t0, or it would not be a
    # miss of this vend).
    row["order_ok"] = (t0 < t1 + CLOCK_SLACK_NS and t0 < final["send_ns"]
                       and (t2 is None or t0 - CLOCK_SLACK_NS <= t2 <= t3 + CLOCK_SLACK_NS))
    row["ok"] = True
    return row, raw


# --------------------------------------------------------------------------
# summary

def stats(vals: list[float]) -> dict:
    if not vals:
        return {"n": 0}
    s = sorted(vals)
    return {
        "n": len(s), "min": s[0], "p50": nearest_rank(s, 50), "p90": nearest_rank(s, 90),
        "p95": nearest_rank(s, 95), "p99": nearest_rank(s, 99), "max": s[-1],
        "mean": round(statistics.fmean(s), 3), "stdev": round(statistics.stdev(s), 3) if len(s) > 1 else 0.0,
    }


def column(rows: list[dict], key: str) -> list[float]:
    return [float(r[key]) for r in rows if r["ok"] and r[key] != ""]


def summarise(rows: list[dict], args: argparse.Namespace, inv: dict, started: str, finished: str) -> dict:
    ok_rows = [r for r in rows if r["ok"]]
    headline = column(rows, "vend_to_svid_ms")
    hist: dict[str, int] = {}
    for v in headline:
        lo = int(v // HIST_BIN_MS) * HIST_BIN_MS
        hist[f"{lo}-{lo + HIST_BIN_MS}"] = hist.get(f"{lo}-{lo + HIST_BIN_MS}", 0) + 1
    return {
        "run_id": args.run_id, "started_at": started, "finished_at": finished,
        "trials_requested": args.trials, "trials_completed": len(ok_rows), "trials_failed": len(rows) - len(ok_rows),
        "poll_interval_target_ms": args.interval_ms, "settle_s": args.settle_s, "ttl_s": args.ttl,
        "jitter_s": args.jitter_s, "jitter_seed": args.seed,
        "percentile_method": "nearest-rank", "stdev_method": "sample (n-1)", "unit": "ms",
        "headline": "vend_to_svid_ms: P sends POST /delegations (t0) -> C's first Workload API answer holding the new SVID received (t3)",
        "vend_to_svid_ms": stats(headline),
        "vend_to_svid_ms_histogram": {"bin_ms": HIST_BIN_MS, "counts": dict(sorted(hist.items(), key=lambda kv: int(kv[0].split("-")[0])))},
        "vend_round_trip_ms (t0 -> t1, entry created on the SPIRE server)": stats(column(rows, "vend_round_trip_ms")),
        "audit_vend_allow_after_send_ms (t0 -> vend allow audit event)": stats(column(rows, "audit_vend_allow_after_send_ms")),
        "server_attest_to_vend_ms (attest allow -> vend allow audit events)": stats(column(rows, "server_attest_to_vend_ms")),
        "agent_log_after_send_ms (t0 -> t2, C's node agent logs the entry)": stats(column(rows, "agent_log_after_send_ms")),
        "svid_after_vend_response_ms (t1 -> t3)": stats(column(rows, "svid_after_vend_response_ms")),
        "vend_to_svid_send_basis_ms (t0 -> obtaining fetch sent)": stats(column(rows, "vend_to_svid_send_basis_ms")),
        "svid_window_ms (t3 - last miss sent: arrival uncertainty)": stats(column(rows, "svid_window_ms")),
        "server_create_entry_after_send_ms (t0 -> server audit BatchCreateEntry)": stats(column(rows, "server_create_entry_after_send_ms")),
        "server_first_svid_after_send_ms (t0 -> first agent's BatchNewX509SVID, any node)": stats(column(rows, "server_first_svid_after_send_ms")),
        "server_child_agent_svid_after_send_ms (t0 -> C's agent's BatchNewX509SVID)": stats(column(rows, "server_child_agent_svid_after_send_ms")),
        "child_agent_finding_sync_after_send_ms (t0 -> C's agent's sync that brought the entry)": stats(column(rows, "child_agent_finding_sync_after_send_ms")),
        "child_agent_syncs_missed (C's agent's syncs after t1 that did not bring the entry)": {
            str(k): sum(1 for r in ok_rows if r["child_agent_syncs_missed"] == k)
            for k in sorted({r["child_agent_syncs_missed"] for r in ok_rows if r["child_agent_syncs_missed"] != ""})},
        "phase_since_child_agent_sync_ms (t0 - C's agent's last sync before it)": stats(column(rows, "phase_since_child_agent_sync_ms")),
        "trials_first_svid_on_another_node": sum(1 for r in ok_rows if r["server_first_svid_node"] not in ("", inv.get("child_node"))),
        "achieved_wait_gap_ms": {
            "mean_of_trial_means": round(statistics.fmean(column(rows, "wait_gap_mean_ms")), 3) if ok_rows else None,
            "max_of_trial_maxes": max(column(rows, "wait_gap_max_ms"), default=None),
        },
        "checks": {
            "trials_with_agent_log_line": sum(1 for r in ok_rows if r["agent_log_ns"] != ""),
            "trials_audit_vend_allow_inside_vend_request": sum(1 for r in ok_rows if r["audit_inside_vend_request"] is True),
            "trials_order_ok": sum(1 for r in ok_rows if r["order_ok"]),
            "trials_disposed_200": sum(1 for r in ok_rows if r["dispose_status"] == 200),
            "trials_vend_retried": sum(1 for r in ok_rows if int(r["vend_attempts"] or 1) > 1),
        },
        "logs": {
            "dir": "logs/", "files": "logs/vending-service/trial-NN.log, logs/spire-server/trial-NN.log",
            "window": "contiguous per trial: from the end of the previous trial's window (the first starts 1 s before trial 1) "
                      "to the moment C held no identity again after the dispose",
            "timestamp": "first field of each line: the container runtime's capture time (kubectl logs --timestamps)",
            "spire_server_audit_log_enabled": inv.get("spire_server_audit_log_enabled"),
            "vending_service_lines": sum(int(r["vending_service_log_lines"] or 0) for r in rows),
            "spire_server_lines": sum(int(r["spire_server_log_lines"] or 0) for r in rows),
        },
        "host": inv,
    }


# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--trials", type=int, default=int(os.environ.get("VEND_SVID_TRIALS", "50")))
    ap.add_argument("--interval-ms", type=int, default=20, help="C's Workload API fetch interval (1-50)")
    ap.add_argument("--settle-s", type=float, default=0.2, help="waiting time between C's ready and P's vend")
    ap.add_argument("--wait-timeout-s", type=int, default=60, help="give up on a trial's identity after this long")
    ap.add_argument("--ttl", type=int, default=300, help="ttl_seconds of each vended child")
    ap.add_argument("--jitter-s", type=float, default=float(os.environ.get("VEND_SVID_JITTER_S", "0")),
                    help="wait a uniform random 0..J s before each trial, so vends land at random points of the agent's sync cycle")
    ap.add_argument("--seed", type=int, default=None, help="seed for --jitter-s (default: random, recorded in the summary)")
    ap.add_argument("--run-id", default=time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-vend-to-svid")
    args = ap.parse_args()
    if not 1 <= args.interval_ms <= 50:
        ap.error("--interval-ms must be between 1 and 50")
    if args.jitter_s < 0:
        ap.error("--jitter-s must not be negative")
    if args.seed is None:
        args.seed = random.SystemRandom().randrange(2**32)
    rng = random.Random(args.seed)

    print(f"== vend to svid: {args.trials} trials, C fetches every {args.interval_ms} ms"
          + (f", random 0-{args.jitter_s:g} s wait before each trial (seed {args.seed})" if args.jitter_s else "") + " ==")
    pods = {"p": c.wait_for_pod(NS, "app=experiments-parent"), "c": c.wait_for_pod(NS, "app=experiments-child")}
    node, agent_pod = agent_pod_for(pods["c"])
    print(f"P={pods['p']} C={pods['c']} (node {node}, agent {agent_pod})")

    # The fixture pods run a fixed image tag; one started before svid-wait /
    # vend-timed existed does not have them.
    for who in ("p", "c"):
        if "svid-wait requires" not in c.parentsim(NS, pods[who], "svid-wait").raw:
            print("FATAL: the fixture pods run a parentsim image without the `svid-wait` mode.\n"
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
    vs_pod = c.running_pod("nhi", "app=vending-service")
    if not vs_pod:
        print("FATAL: no running vending-service pod", file=sys.stderr)
        return 2
    inv["vending_service_pod"] = vs_pod
    inv["spire_server_audit_log_enabled"] = spire_server_audit_enabled()
    agents = agent_ids_by_node()
    inv["agent_ids_by_node"] = agents
    print(f"vending service {vs_pod}; SPIRE server audit log {'on' if inv['spire_server_audit_log_enabled'] else 'OFF'}")
    out_dir = Path(__file__).parent / "results" / args.run_id
    log_dirs = {"vending-service": out_dir / "logs" / "vending-service", "spire-server": out_dir / "logs" / "spire-server"}
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
        time.sleep(jitter)
        t_start = time.monotonic()
        try:
            row, raw = run_trial(t, run_id, pods, agent_pod, args)
        except Exception as exc:  # noqa: BLE001 - one bad trial must not lose the others
            row = {k: "" for k in CSV_FIELDS}
            row.update(trial=t, ok=False, error=f"exception: {exc}")
            raw = {"trial": t, "error": str(exc)}
        rows.append(row)
        raws.append(raw)
        shown = (f"{row['vend_to_svid_ms']:.1f} ms  (vend {row['vend_round_trip_ms']:.1f} ms)"
                 if row["ok"] else f"FAILED ({row['error']})")
        print(f"  trial {t:2d}/{args.trials}: {shown}  [{time.monotonic() - t_start:.1f}s]", flush=True)
        # Leave C without an identity so the next trial starts clean.
        wait_no_identity(pods["c"])

        # This trial's log window, from both components, each in its own file.
        window_end = time.time_ns()
        for name, (ns, pod, ctr), col in (
                ("vending-service", ("nhi", vs_pod, "vending-service"), "vending_service_log_lines"),
                ("spire-server", ("spire", "spire-server-0", "spire-server"), "spire_server_log_lines")):
            lines = component_logs(ns, pod, ctr, window_start, window_end)
            (log_dirs[name] / f"trial-{t:02d}.log").write_text("".join(ln + "\n" for ln in lines))
            row[col] = len(lines)
            if name == "spire-server":
                child_agent_syncs += [parse_rfc3339_ns(ln.partition(" ")[0]) for ln in lines
                                      if "method=SyncAuthorizedEntries" in ln and f'caller_id="{agents[node]}"' in ln]
                if row["ok"]:
                    row.update(server_audit(lines, row, agents, node))
        row["log_window_start_ns"], row["log_window_end_ns"] = window_start, window_end
        row["pre_trial_jitter_ms"] = round(jitter * 1000, 3)
        if row["ok"]:
            before = [ts for ts in child_agent_syncs if ts < row["vend_send_ns"]]
            if before:
                row["phase_since_child_agent_sync_ms"] = ms(row["vend_send_ns"] - max(before))
        window_start = window_end

    inv["load_average_end"] = [round(x, 2) for x in os.getloadavg()]
    summary = summarise(rows, args, inv, started, c.now_iso())

    with (out_dir / "vend_to_svid.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)
    (out_dir / "vend_to_svid_summary.json").write_text(json.dumps(summary, indent=2, default=str))
    (out_dir / "vend_to_svid_raw.json").write_text(json.dumps(raws, indent=2, default=str))

    print()
    print(f"  trials completed {summary['trials_completed']}/{args.trials}, failed {summary['trials_failed']}")
    for k in ("vend_to_svid_ms",):
        s = summary[k]
        if s.get("n"):
            print(f"  {k}: p50 {s['p50']}  p95 {s['p95']}  min {s['min']}  max {s['max']}  mean {s['mean']}  stdev {s['stdev']}")
    print(f"  checks: {summary['checks']}")
    print(f"results: {out_dir}")
    return 0 if summary["trials_failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
