#!/usr/bin/env python3
"""Vend to access: how long after a parent sends its vend request can the child read the protected resource?

`make vend-to-access` is the entry point. Not part of `make experiments`.

Each trial has the experiments parent P vend a fresh child SPIFFE ID for the
experiments child pod C, and measures the time from the moment P sends
`POST /delegations` (t0) to the moment C receives the resource's first 200 for
`GET /datasets/A`, sent with C's own JWT-SVID (audience the resource). That is
the headline, `vend_to_access_ms`. It is the vend-to-SVID benchmark
(vend_to_svid.py) carried on to the operate stage, and reuses its parts.

The intermediate instants are recorded alongside it:

  t1      P receives the 201. By then the SPIRE entry exists and the policy
          engine has pushed C's grant to OPA.
  t2      C's node agent logs the new entry (container-runtime timestamp).
  t_jwt   C receives the JWT-SVID it then presents.
  t_allow the resource's own audit event allowing C's request.

C's side runs `parentsim access-wait` in C's pod, in one of two styles (`--style`):

  poll      every `--interval-ms` (default 20 ms): fetch a JWT-SVID, and once one
            for C's ID arrives, send the GET in the same tick, reusing the token
            until a 200. Started before the vend; it reports "ready" after its
            first miss and P vends only after that. Measures when access first
            becomes possible.
  child-py  the lab's real child, src/agents/child.py, step for step: fetch the
            X.509-SVID, retrying up to 30 times 2 s apart; then a JWT-SVID the
            same way; then one GET. Started as soon as the vend returns, as
            parent.py starts a child only after its vend succeeds. C's pod
            already exists, so pod start-up time is not included; `kubectl exec`
            adds about 50-70 ms before the first attempt, recorded per trial as
            `child_start_after_vend_response_ms`. Measures what that child sees.

Clocks, phase and jitter are as in vend_to_svid.py: every stamp is CLOCK_REALTIME
in Unix nanoseconds on one host's kernel clock, and `--jitter-s J` waits a seeded
uniform random 0..J s before each trial so vends land at random points of the
agent's sync cycle.

Output (`results/<run-id>/`)
----------------------------
  vend_to_access.csv            one row per trial
  vend_to_access_summary.json   statistics, histogram, host inventory
  vend_to_access_raw.json       the raw child / vend / audit / agent-log records
  logs/vending-service/trial-NN.log
  logs/spire-server/trial-NN.log
  logs/resource/trial-NN.log    each component's log lines for one trial,
                                prefixed with the container runtime's timestamp;
                                contiguous windows, as in vend_to_svid.py
  logs/parent/trial-NN.log      P's output for the trial (`parentsim vend-timed`
                                and `parentsim dispose`; P's pod logs nothing of
                                its own), each line prefixed with the time this
                                host received it
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
    NS, PARENT_ID, ParentsimStream, host_inventory, ms, parse_rfc3339_ns, wait_for_svid, wait_no_identity,
)
from vend_to_svid import (  # noqa: E402  - the vend-to-SVID benchmark's parts
    AUDIT_FIELDS, CLOCK_SLACK_NS, agent_first_line, agent_ids_by_node, agent_pod_for, column, component_logs,
    ns_to_rfc3339, server_audit, spire_server_audit_enabled, stats, vend_timed, vending_audit,
)

HIST_BIN_MS = 500
DATASET_URL = f"{c.RESOURCE_URL}/datasets/A"  # needs resource:read:datasetA, the scope vend_timed requests

CSV_FIELDS = [
    "trial", "ok", "error", "style", "child_spiffe_id", "chain_id", "entry_id",
    "vend_attempts", "vend_status",
    # t0, t1 (P's pod)
    "vend_send_ns", "vend_recv_ns", "vend_round_trip_ms",
    # vending-service audit
    "audit_attest_allow_ns", "audit_vend_allow_ns", "server_attest_to_vend_ms",
    "audit_vend_allow_after_send_ms", "audit_inside_vend_request",
    # t2 (C's node agent log)
    "agent_log_ns", "agent_log_after_send_ms", "agent_log_message",
    # C's pod
    "child_first_send_ns", "child_start_after_vend_response_ms",
    "x509_obtained_send_ns", "x509_obtained_recv_ns", "vend_to_x509_ms",
    "jwt_obtained_send_ns", "jwt_obtained_recv_ns", "vend_to_jwt_ms",
    "access_send_ns", "access_recv_ns", "access_status",
    "vend_to_access_ms",             # access_recv - t0: the headline
    "access_after_vend_response_ms",  # access_recv - t1
    "jwt_to_access_ms",              # access_recv - jwt_recv
    "access_window_ms",              # access_recv - last miss sent: the uncertainty in when access became possible
    "child_attempts", "child_misses", "x509_attempts", "jwt_attempts", "resource_attempts",
    "child_gap_mean_ms", "child_gap_max_ms", "miss_reasons",
    # the resource's own audit events for C
    "resource_allow_ns", "resource_allow_after_send_ms", "resource_allow_inside_access_request",
    "resource_decision_latency_ms", "resource_denies_for_child",
    "order_ok", "dispose_status",
    "log_window_start_ns", "log_window_end_ns",
    "vending_service_log_lines", "spire_server_log_lines", "resource_log_lines", "parent_log_lines",
    # SPIRE server API audit log (runtime timestamps); empty when the audit log is off
    "server_create_entry_ns", "server_create_entry_after_send_ms",
    "server_first_svid_ns", "server_first_svid_node", "server_first_svid_after_send_ms",
    "server_child_agent_svid_ns", "server_child_agent_svid_after_send_ms",
    "server_child_jwt_ns", "server_child_jwt_after_send_ms",
    "child_agent_finding_sync_ns", "child_agent_finding_sync_after_send_ms", "child_agent_syncs_missed",
    "pre_trial_jitter_ms", "phase_since_child_agent_sync_ms",
]


def stamp_lines(cmd: str, out: str) -> list[str]:
    """P's command output as log lines, each prefixed with this host's receive time."""
    now = ns_to_rfc3339(time.time_ns())
    return [f"{now} {cmd}: {ln}" for ln in out.splitlines() if ln.strip()]


def resource_audit(lines: list[str], row: dict) -> dict:
    """The resource's audit events for C's identity in one trial's resource log window."""
    allows, denies = [], 0
    for ln in lines:
        _, _, body = ln.partition(" ")
        if not body.startswith("{"):
            continue
        try:
            ev = json.loads(body)
        except json.JSONDecodeError:
            continue
        if ev.get("actor_spiffe_id") != row["child_spiffe_id"]:
            continue
        if ev.get("outcome") == "allow":
            allows.append(ev)
        else:
            denies += 1
    out: dict = {"resource_denies_for_child": denies}
    if allows:
        first = min(allows, key=lambda e: parse_rfc3339_ns(e["timestamp"]))
        a_ns = parse_rfc3339_ns(first["timestamp"])
        out.update(resource_allow_ns=a_ns, resource_allow_after_send_ms=ms(a_ns - row["vend_send_ns"]),
                   resource_allow_inside_access_request=(row["access_send_ns"] - CLOCK_SLACK_NS <= a_ns
                                                         <= row["access_recv_ns"] + CLOCK_SLACK_NS))
        lat = (first.get("detail") or {}).get("decision_latency_ms")
        if lat is not None:
            out["resource_decision_latency_ms"] = lat
    return out


def server_jwt(lines: list[str], row: dict, child_agent: str) -> dict:
    """The SPIRE server's first NewJWTSVID for C, called by C's node agent."""
    for ln in lines:
        if "method=NewJWTSVID" not in ln or "type=audit" not in ln:
            continue
        f = {k: (m.group(1) if (m := rx.search(ln)) else None) for k, rx in AUDIT_FIELDS.items()}
        if f["caller"] == child_agent and (f["entry"] == row["entry_id"] or f["spiffe"] == row["child_spiffe_id"]):
            ts = parse_rfc3339_ns(ln.partition(" ")[0])
            return {"server_child_jwt_ns": ts, "server_child_jwt_after_send_ms": ms(ts - row["vend_send_ns"])}
    return {}


# --------------------------------------------------------------------------
# one trial

def access_wait(pod: str, style: str, child_id: str, args: argparse.Namespace) -> ParentsimStream:
    return ParentsimStream(pod, "access-wait", f"-access-style={style}", f"-expect-id={child_id}",
                           f"-call-url={DATASET_URL}", f"-call-audience={c.RESOURCE_AUD}",
                           f"-poll-interval={args.interval_ms}ms", f"-poll-timeout={args.wait_timeout_s}s")


def run_trial(trial: int, run_id: str, pods: dict[str, str], agent_pod: str,
              args: argparse.Namespace) -> tuple[dict, dict]:
    row: dict = {k: "" for k in CSV_FIELDS}
    row["trial"], row["style"] = trial, args.style
    raw: dict = {"trial": trial, "parent_log": []}
    tag = f"{run_id}-{trial:02d}"

    def fail(msg: str) -> tuple[dict, dict]:
        row["ok"], row["error"] = False, msg
        raw["error"] = msg
        return row, raw

    hint = f"child/v2a-{tag}"
    child_id = f"{PARENT_ID}/{hint}"
    row["child_spiffe_id"] = child_id
    started_ns = time.time_ns()

    waiter = None
    chain_id = None
    try:
        if args.style == "poll":
            # --- C starts asking before P vends ---------------------------------
            waiter = access_wait(pods["c"], "poll", child_id, args)
            ready = waiter.next_event(20)
            raw["wait_ready"] = ready
            if not ready or ready.get("event") != "ready":
                return fail(f"access-wait never reported ready: {ready} {waiter.other[-3:]}")
            time.sleep(args.settle_s)

        # --- t0 / t1: P vends, stamping the clock around the POST in its pod ----
        vend, out, attempts = vend_timed(pods["p"], hint, f"v2a_{tag}", args.ttl)
        raw["parent_log"] += stamp_lines("parentsim vend-timed", out)
        raw["vend"] = vend
        row["vend_attempts"] = attempts
        if not vend or vend.get("status") != 201:
            return fail(f"timed vend failed: {out[:300]}")
        body = json.loads(vend["response"])
        chain_id = body["chain_id"]
        row.update(chain_id=chain_id, entry_id=body.get("entry_id", ""), vend_status=vend["status"],
                   vend_send_ns=vend["send_ns"], vend_recv_ns=vend["recv_ns"],
                   vend_round_trip_ms=ms(vend["round_trip_ns"]))

        if args.style == "child-py":
            # --- C starts only now, as parent.py starts a child after its vend ---
            waiter = access_wait(pods["c"], "child-py", child_id, args)

        # --- C's first 200 from the resource -----------------------------------
        final = waiter.next_event(args.wait_timeout_s + 15)
        raw["wait_final"] = final
        if not final or final.get("event") != "granted":
            return fail(f"access-wait did not report access: {final} {waiter.other[-3:]}")
    finally:
        if waiter:
            waiter.close()
        # Dispose even when the trial failed after the vend, so the next trial
        # starts with no identity. Recorded below for successful trials.
        if chain_id:
            d = c.parentsim(NS, pods["p"], "dispose", f"-chain-id={chain_id}")
            raw["dispose"] = d.code
            raw["parent_log"] += stamp_lines("parentsim dispose", d.raw)

    t0, t1 = vend["send_ns"], vend["recv_ns"]
    t_acc, t_jwt = final["recv_ns"], final["jwt_recv_ns"]
    row.update(
        child_first_send_ns=final.get("first_send_ns", ""),
        child_start_after_vend_response_ms=ms(final["first_send_ns"] - t1) if args.style == "child-py" else "",
        x509_obtained_send_ns=final.get("x509_send_ns", ""), x509_obtained_recv_ns=final.get("x509_recv_ns", ""),
        vend_to_x509_ms=ms(final["x509_recv_ns"] - t0) if final.get("x509_recv_ns") else "",
        jwt_obtained_send_ns=final["jwt_send_ns"], jwt_obtained_recv_ns=t_jwt, vend_to_jwt_ms=ms(t_jwt - t0),
        access_send_ns=final["send_ns"], access_recv_ns=t_acc, access_status=final["status"],
        vend_to_access_ms=ms(t_acc - t0),
        access_after_vend_response_ms=ms(t_acc - t1),
        jwt_to_access_ms=ms(t_acc - t_jwt),
        access_window_ms=ms(t_acc - final["last_miss_send_ns"]) if final.get("last_miss_send_ns") else "",
        child_attempts=final.get("attempts", 0), child_misses=final.get("misses", 0),
        x509_attempts=final.get("x509_attempts", 0), jwt_attempts=final.get("jwt_attempts", 0),
        resource_attempts=final.get("resource_attempts", 0),
        child_gap_mean_ms=ms(final.get("gap_mean_ns", 0)), child_gap_max_ms=ms(final.get("gap_max_ns", 0)),
        miss_reasons=json.dumps(final.get("miss_reasons", {}), sort_keys=True),
        dispose_status=raw.get("dispose", ""),
    )

    fields, raw["audit_vend_allow"], raw["audit_attest_allow"] = vending_audit(chain_id, t0, t1)
    row.update(fields)

    # --- t2: the agent on C's node logs the new entry --------------------------
    t2, msg = agent_first_line(agent_pod, child_id, started_ns - 1_000_000_000)
    raw["agent_log"] = {"ns": t2, "line": msg}
    if t2 is not None:
        row.update(agent_log_ns=t2, agent_log_after_send_ms=ms(t2 - t0), agent_log_message=msg)

    # Causality: P's send precedes C's JWT, which precedes the granting request;
    # the agent logged the entry between t0 and C's JWT.
    row["order_ok"] = (t0 < t1 + CLOCK_SLACK_NS and t0 < final["jwt_send_ns"]
                       and t_jwt <= final["send_ns"] + CLOCK_SLACK_NS and final["send_ns"] <= t_acc
                       and (t2 is None or t0 - CLOCK_SLACK_NS <= t2 <= t_jwt + CLOCK_SLACK_NS))
    row["ok"] = True
    return row, raw


# --------------------------------------------------------------------------
# summary

def summarise(rows: list[dict], args: argparse.Namespace, inv: dict, started: str, finished: str) -> dict:
    ok_rows = [r for r in rows if r["ok"]]
    headline = column(rows, "vend_to_access_ms")
    hist: dict[str, int] = {}
    for v in headline:
        lo = int(v // HIST_BIN_MS) * HIST_BIN_MS
        hist[f"{lo}-{lo + HIST_BIN_MS}"] = hist.get(f"{lo}-{lo + HIST_BIN_MS}", 0) + 1
    return {
        "run_id": args.run_id, "started_at": started, "finished_at": finished, "style": args.style,
        "trials_requested": args.trials, "trials_completed": len(ok_rows), "trials_failed": len(rows) - len(ok_rows),
        "poll_interval_target_ms": args.interval_ms if args.style == "poll" else None,
        "child_py_retry": {"delay_s": 2, "attempts": 30} if args.style == "child-py" else None,
        "settle_s": args.settle_s, "ttl_s": args.ttl, "jitter_s": args.jitter_s, "jitter_seed": args.seed,
        "percentile_method": "nearest-rank", "stdev_method": "sample (n-1)", "unit": "ms",
        "headline": "vend_to_access_ms: P sends POST /delegations (t0) -> C receives the resource's first 200 "
                    "for GET /datasets/A with its own JWT-SVID",
        "vend_to_access_ms": stats(headline),
        "vend_to_access_ms_histogram": {"bin_ms": HIST_BIN_MS, "counts": dict(sorted(hist.items(), key=lambda kv: int(kv[0].split("-")[0])))},
        "vend_round_trip_ms (t0 -> t1)": stats(column(rows, "vend_round_trip_ms")),
        "agent_log_after_send_ms (t0 -> t2, C's node agent logs the entry)": stats(column(rows, "agent_log_after_send_ms")),
        "vend_to_x509_ms (t0 -> C holds its X.509-SVID; child-py only)": stats(column(rows, "vend_to_x509_ms")),
        "vend_to_jwt_ms (t0 -> C holds its JWT-SVID)": stats(column(rows, "vend_to_jwt_ms")),
        "jwt_to_access_ms (C holds the JWT -> first 200 received)": stats(column(rows, "jwt_to_access_ms")),
        "access_after_vend_response_ms (t1 -> first 200 received)": stats(column(rows, "access_after_vend_response_ms")),
        "access_window_ms (first 200 - last miss sent)": stats(column(rows, "access_window_ms")),
        "child_start_after_vend_response_ms (child-py: t1 -> C's first attempt)": stats(column(rows, "child_start_after_vend_response_ms")),
        "resource_allow_after_send_ms (t0 -> the resource's allow audit event)": stats(column(rows, "resource_allow_after_send_ms")),
        "resource_decision_latency_ms (the resource's OPA decision time)": stats(column(rows, "resource_decision_latency_ms")),
        "server_create_entry_after_send_ms (t0 -> server audit BatchCreateEntry)": stats(column(rows, "server_create_entry_after_send_ms")),
        "server_child_agent_svid_after_send_ms (t0 -> C's agent's BatchNewX509SVID)": stats(column(rows, "server_child_agent_svid_after_send_ms")),
        "server_child_jwt_after_send_ms (t0 -> C's agent's NewJWTSVID)": stats(column(rows, "server_child_jwt_after_send_ms")),
        "child_agent_finding_sync_after_send_ms (t0 -> C's agent's sync that brought the entry)": stats(column(rows, "child_agent_finding_sync_after_send_ms")),
        "child_agent_syncs_missed (C's agent's syncs after t1 that did not bring the entry)": {
            str(k): sum(1 for r in ok_rows if r["child_agent_syncs_missed"] == k)
            for k in sorted({r["child_agent_syncs_missed"] for r in ok_rows if r["child_agent_syncs_missed"] != ""})},
        "attempts_by_step": {k: {str(v): sum(1 for r in ok_rows if r[k] == v) for v in sorted({r[k] for r in ok_rows})}
                             for k in ("x509_attempts", "jwt_attempts", "resource_attempts")},
        "phase_since_child_agent_sync_ms (t0 - C's agent's last sync before it)": stats(column(rows, "phase_since_child_agent_sync_ms")),
        "achieved_child_gap_ms": {
            "mean_of_trial_means": round(statistics.fmean(column(rows, "child_gap_mean_ms")), 3) if ok_rows else None,
            "max_of_trial_maxes": max(column(rows, "child_gap_max_ms"), default=None),
        },
        "checks": {
            "trials_with_agent_log_line": sum(1 for r in ok_rows if r["agent_log_ns"] != ""),
            "trials_audit_vend_allow_inside_vend_request": sum(1 for r in ok_rows if r["audit_inside_vend_request"] is True),
            "trials_resource_allow_inside_access_request": sum(1 for r in ok_rows if r["resource_allow_inside_access_request"] is True),
            "trials_with_resource_denies_for_child": sum(1 for r in ok_rows if r["resource_denies_for_child"] not in ("", 0)),
            "trials_order_ok": sum(1 for r in ok_rows if r["order_ok"]),
            "trials_disposed_200": sum(1 for r in ok_rows if r["dispose_status"] == 200),
            "trials_vend_retried": sum(1 for r in ok_rows if int(r["vend_attempts"] or 1) > 1),
        },
        "logs": {
            "dir": "logs/",
            "files": "logs/{vending-service,spire-server,resource,parent}/trial-NN.log",
            "window": "contiguous per trial: from the end of the previous trial's window (the first starts 1 s before trial 1) "
                      "to the moment C held no identity again after the dispose",
            "timestamp": "first field of each line: the container runtime's capture time (kubectl logs --timestamps); "
                         "for parent/, the time this host received P's command output",
            "spire_server_audit_log_enabled": inv.get("spire_server_audit_log_enabled"),
            "lines": {k: sum(int(r[f"{k}_log_lines"] or 0) for r in rows)
                      for k in ("vending_service", "spire_server", "resource", "parent")},
        },
        "host": inv,
    }


# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--style", choices=("poll", "child-py"), default=os.environ.get("VEND_ACCESS_STYLE", "poll"),
                    help="C's behaviour: poll (every --interval-ms) or child-py (src/agents/child.py's 2 s retries)")
    ap.add_argument("--trials", type=int, default=int(os.environ.get("VEND_ACCESS_TRIALS", "50")))
    ap.add_argument("--interval-ms", type=int, default=20, help="poll: C's attempt interval (1-50)")
    ap.add_argument("--settle-s", type=float, default=0.2, help="poll: waiting time between C's ready and P's vend")
    ap.add_argument("--wait-timeout-s", type=int, default=None,
                    help="give up on a trial's access after this long (default 60 for poll, 150 for child-py)")
    ap.add_argument("--ttl", type=int, default=300, help="ttl_seconds of each vended child")
    ap.add_argument("--jitter-s", type=float, default=float(os.environ.get("VEND_ACCESS_JITTER_S", "0")),
                    help="wait a uniform random 0..J s before each trial, so vends land at random points of the agent's sync cycle")
    ap.add_argument("--seed", type=int, default=None, help="seed for --jitter-s (default: random, recorded in the summary)")
    ap.add_argument("--run-id", default=None)
    args = ap.parse_args()
    if not 1 <= args.interval_ms <= 50:
        ap.error("--interval-ms must be between 1 and 50")
    if args.jitter_s < 0:
        ap.error("--jitter-s must not be negative")
    if args.wait_timeout_s is None:
        args.wait_timeout_s = 60 if args.style == "poll" else 150
    if args.run_id is None:
        args.run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-vend-to-access-{args.style}"
    if args.seed is None:
        args.seed = random.SystemRandom().randrange(2**32)
    rng = random.Random(args.seed)

    how = f"C polls every {args.interval_ms} ms" if args.style == "poll" else "C retries as child.py does (2 s)"
    print(f"== vend to access: {args.trials} trials, {how}"
          + (f", random 0-{args.jitter_s:g} s wait before each trial (seed {args.seed})" if args.jitter_s else "") + " ==")
    pods = {"p": c.wait_for_pod(NS, "app=experiments-parent"), "c": c.wait_for_pod(NS, "app=experiments-child")}
    node, agent_pod = agent_pod_for(pods["c"])
    print(f"P={pods['p']} C={pods['c']} (node {node}, agent {agent_pod})")

    if "access-wait requires" not in c.parentsim(NS, pods["c"], "access-wait").raw:
        print("FATAL: the fixture pods run a parentsim image without the `access-wait` mode.\n"
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
    res_pod = c.running_pod("nhi", "app=resource")
    if not vs_pod or not res_pod:
        print(f"FATAL: need running vending-service and resource pods (got {vs_pod}, {res_pod})", file=sys.stderr)
        return 2
    inv["vending_service_pod"], inv["resource_pod"] = vs_pod, res_pod
    inv["spire_server_audit_log_enabled"] = spire_server_audit_enabled()
    agents = agent_ids_by_node()
    inv["agent_ids_by_node"] = agents
    print(f"vending service {vs_pod}; resource {res_pod}; "
          f"SPIRE server audit log {'on' if inv['spire_server_audit_log_enabled'] else 'OFF'}")
    out_dir = Path(__file__).parent / "results" / args.run_id
    names = ("vending-service", "spire-server", "resource", "parent")
    log_dirs = {n: out_dir / "logs" / n for n in names}
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
            row.update(trial=t, ok=False, error=f"exception: {exc}", style=args.style)
            raw = {"trial": t, "error": str(exc), "parent_log": []}
        rows.append(row)
        raws.append(raw)
        shown = (f"{row['vend_to_access_ms']:.1f} ms  (jwt {row['vend_to_jwt_ms']:.1f} ms, vend {row['vend_round_trip_ms']:.1f} ms)"
                 if row["ok"] else f"FAILED ({row['error']})")
        print(f"  trial {t:2d}/{args.trials}: {shown}  [{time.monotonic() - t_start:.1f}s]", flush=True)
        # Leave C without an identity so the next trial starts clean.
        wait_no_identity(pods["c"])

        # This trial's log window, one file per component.
        window_end = time.time_ns()
        for name, (ns, pod, ctr) in (("vending-service", ("nhi", vs_pod, "vending-service")),
                                     ("spire-server", ("spire", "spire-server-0", "spire-server")),
                                     ("resource", ("nhi", res_pod, "resource"))):
            lines = component_logs(ns, pod, ctr, window_start, window_end)
            (log_dirs[name] / f"trial-{t:02d}.log").write_text("".join(ln + "\n" for ln in lines))
            row[f"{name.replace('-', '_')}_log_lines"] = len(lines)
            if not row["ok"]:
                continue
            if name == "spire-server":
                child_agent_syncs += [parse_rfc3339_ns(ln.partition(" ")[0]) for ln in lines
                                      if "method=SyncAuthorizedEntries" in ln and f'caller_id="{agents[node]}"' in ln]
                row.update(server_audit(lines, row, agents, node))
                row.update(server_jwt(lines, row, agents[node]))
            elif name == "resource":
                row.update(resource_audit(lines, row))
        parent_lines = raw.get("parent_log", [])
        (log_dirs["parent"] / f"trial-{t:02d}.log").write_text("".join(ln + "\n" for ln in parent_lines))
        row["parent_log_lines"] = len(parent_lines)
        row["log_window_start_ns"], row["log_window_end_ns"] = window_start, window_end
        row["pre_trial_jitter_ms"] = round(jitter * 1000, 3)
        if row["ok"]:
            before = [ts for ts in child_agent_syncs if ts < row["vend_send_ns"]]
            if before:
                row["phase_since_child_agent_sync_ms"] = ms(row["vend_send_ns"] - max(before))
        window_start = window_end

    inv["load_average_end"] = [round(x, 2) for x in os.getloadavg()]
    summary = summarise(rows, args, inv, started, c.now_iso())

    with (out_dir / "vend_to_access.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)
    (out_dir / "vend_to_access_summary.json").write_text(json.dumps(summary, indent=2, default=str))
    (out_dir / "vend_to_access_raw.json").write_text(json.dumps(raws, indent=2, default=str))

    print()
    print(f"  trials completed {summary['trials_completed']}/{args.trials}, failed {summary['trials_failed']}")
    s = summary["vend_to_access_ms"]
    if s.get("n"):
        print(f"  vend_to_access_ms: p50 {s['p50']}  p95 {s['p95']}  min {s['min']}  max {s['max']}  mean {s['mean']}  stdev {s['stdev']}")
    print(f"  checks: {summary['checks']}")
    print(f"results: {out_dir}")
    return 0 if summary["trials_failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
