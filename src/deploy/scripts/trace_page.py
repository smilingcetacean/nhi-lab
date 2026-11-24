"""Render recorded lifecycle audit events as an offline trace page."""

import argparse
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys


FIELDS = {"timestamp", "stage", "chain_id", "actor_spiffe_id", "outcome", "detail"}
STAGES = {"spawn", "attest", "vend", "operate", "dispose"}
OUTCOMES = {"allow", "deny", "error"}
CALLBACK_KINDS = ("callback_refused", "result_rejected", "result_returned", "callback_missing")
TIMESTAMP = re.compile(
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.([0-9]{1,9}))?(Z|[+-]\d{2}:\d{2})"
)
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
ACTOR_JOIN = "actor_spiffe_id = vended child"
ATTEST_JOIN = "next vend by the same parent"


def timestamp_ns(value):
    match = TIMESTAMP.fullmatch(value)
    if not match:
        raise ValueError("invalid audit timestamp")
    seconds, fraction, offset = match.groups()
    elapsed = datetime.fromisoformat(seconds + offset) - EPOCH
    return (elapsed.days * 86400 + elapsed.seconds) * 10**9 + int((fraction or "").ljust(9, "0"))


def read_events(paths):
    events = []
    skipped = 0
    for path in paths:
        previous_count = len(events)
        with Path(path).open("rb") as lines:
            for line in lines:
                try:
                    event = json.loads(line)
                    if (
                        not isinstance(event, dict)
                        or event.keys() != FIELDS
                        or not isinstance(event["detail"], dict)
                        or not all(isinstance(event[key], str) for key in FIELDS - {"detail"})
                        or event["stage"] not in STAGES
                        or event["outcome"] not in OUTCOMES
                    ):
                        raise ValueError("invalid audit event")
                    event["ns"] = timestamp_ns(event["timestamp"])
                except (UnicodeError, ValueError, RecursionError):
                    skipped += 1
                else:
                    events.append(event)
        if len(events) == previous_count:
            raise ValueError(f"{str(path)!r} contains no audit event")
    return events, skipped


def detail_text(detail, key):
    value = detail.get(key)
    return value if isinstance(value, str) else ""


def emitting_service(event):
    stage, detail = event["stage"], event["detail"]
    if stage == "spawn":
        return "parent"
    if stage in ("vend", "dispose"):
        if event["actor_spiffe_id"].endswith("/svc/vending-service") and "entry_id" not in detail:
            return "policy-engine"
        return "vending-service"
    if stage == "attest":
        return "vending-service"
    if "method" in detail:
        return "resource"
    if detail.get("kind") in CALLBACK_KINDS:
        return "parent"
    return "child"


def row_label(event, service):
    stage, detail = event["stage"], event["detail"]
    if stage in ("spawn", "attest"):
        return stage
    if stage == "vend":
        if detail.get("reason") == "no such delegation":
            return "delegation lookup"
        return "vend: scopes" if service == "policy-engine" else "vend: entry"
    if stage == "dispose":
        return "dispose: grant" if service == "policy-engine" else "dispose: entry"
    if service == "resource":
        return f"{detail_text(detail, 'method')} {detail_text(detail, 'path')}".strip()
    return detail_text(detail, "kind").replace("_", " ") or "operate"


def scopes(detail, key):
    values = detail.get(key)
    return [value for value in values if isinstance(value, str)] if isinstance(values, list) else []


def short_scopes(values, prefix):
    names = [value.rsplit(":", 1)[-1] for value in values]
    return ", ".join(
        prefix + name.removeprefix("dataset") if name.startswith("dataset") else name
        for name in names
    )


def row_summary(event, service, label):
    detail = event["detail"]
    reason = detail_text(detail, "reason")
    if label == "spawn":
        child = detail_text(detail, "child_spiffe_id").rsplit("/", 1)[-1]
        return f"child {child}, requested {scopes(detail, 'requested_scopes')}"
    if label == "vend: scopes" and event["outcome"] == "allow":
        fields = (
            ("requested", "requested_scopes"),
            ("parent", "parent_scopes"),
            ("granted", "child_scopes"),
        )
        return ", ".join(
            f"{name} {{{short_scopes(scopes(detail, key), '')}}}" for name, key in fields
        )
    if label == "vend: entry" and event["outcome"] == "allow":
        entry = detail_text(detail, "entry_id")[:8]
        policy = detail_text(detail, "policy_id")[:21]
        summary = f"SPIRE entry {entry} created, policy {policy}"
        return f"{summary}; {reason}" if reason else summary
    if service == "resource" and isinstance(detail.get("policy_decision"), bool):
        decision = "allow" if detail["policy_decision"] else "deny"
        latency = detail.get("decision_latency_ms", 0)
        if not isinstance(latency, (float, int)):
            latency = 0
        return f"OPA {decision} in {latency:.2f} ms, chain_id_source {detail_text(detail, 'chain_id_source')}"
    return reason


def title_and_status(events, children):
    relevant = [event for event, label in events if label != "delegation lookup"]
    requested = next(
        (values for event in relevant if (values := scopes(event["detail"], "requested_scopes"))),
        [],
    )
    scope = short_scopes(requested, "Dataset ") or "Delegation"
    if any(event["stage"] == "vend" and event["outcome"] != "allow" for event in relevant):
        return f"{scope} denied", "deny"
    if children and any(
        event["detail"].get("kind") == "callback_refused"
        and (peer := detail_text(event["detail"], "peer"))
        and peer not in children
        for event in relevant
    ):
        return "Impostor refused", "warn"
    if any(event["outcome"] != "allow" for event in relevant):
        return f"{scope}: refusal recorded", "warn"
    if not any(event["stage"] == "dispose" for event in relevant):
        return f"{scope} live", "open"
    return f"{scope} granted", "ok"


def build_traces(events):
    events = sorted(events, key=lambda event: event["ns"])
    vends_by_child = defaultdict(list)
    children_by_chain = defaultdict(set)
    next_vend_by_parent = {}
    attestation_chains = {}
    # A newer successful attest supersedes any older unmatched attest for that parent.
    for index in range(len(events) - 1, -1, -1):
        event = events[index]
        detail, chain = event["detail"], event["chain_id"]
        if event["stage"] == "vend" and chain:
            parent = detail_text(detail, "parent_spiffe_id")
            if parent:
                next_vend_by_parent[parent] = chain
        if event["stage"] == "attest" and event["outcome"] == "allow":
            chain = next_vend_by_parent.pop(event["actor_spiffe_id"], "")
            if chain and not detail_text(detail, "child_spiffe_id") and not event["chain_id"]:
                attestation_chains[index] = chain

    for event in events:
        child = detail_text(event["detail"], "child_spiffe_id")
        if event["stage"] == "vend" and event["chain_id"] and child:
            vends_by_child[child].append(event)
            children_by_chain[event["chain_id"]].add(child)

    grouped = defaultdict(list)
    joins, services = Counter(), Counter()
    unattached = disagreements = 0
    for index, event in enumerate(events):
        service = emitting_service(event)
        services[service] += 1
        chain, join = event["chain_id"], "chain_id"
        ns = event["ns"]
        if service == "resource":
            vends = vends_by_child.get(event["actor_spiffe_id"], [])
            position = bisect_right(vends, ns, key=lambda vend: vend["ns"])
            chain = vends[position - 1]["chain_id"] if position else ""
            join = ACTOR_JOIN
        elif not chain:
            child = detail_text(event["detail"], "child_spiffe_id")
            vends = vends_by_child.get(child, [])
            position = bisect_left(vends, ns, key=lambda vend: vend["ns"])
            if position < len(vends):
                chain, join = vends[position]["chain_id"], "child_spiffe_id"
            elif index in attestation_chains:
                chain, join = attestation_chains[index], ATTEST_JOIN
        if not chain:
            unattached += 1
            continue

        joins[join] += 1
        if service == "resource" and event["chain_id"] and event["chain_id"] != chain:
            disagreements += 1
            join += f"; WARNING client-asserted chain_id {event['chain_id']} disagrees"
        label = row_label(event, service)
        grouped[chain].append((event, label, service, join))

    traces = []
    for chain, rows in grouped.items():
        title, status = title_and_status(
            [(event, label) for event, label, _, _ in rows], children_by_chain[chain]
        )
        start = rows[0][0]["ns"]
        trace_events = [
            {
                "at_ms": round((event["ns"] - start) / 10**6, 1),
                "stage": event["stage"],
                "service": service,
                "label": label,
                "outcome": event["outcome"],
                "summary": row_summary(event, service, label),
                "join": join,
            }
            for event, label, service, join in rows
        ]
        traces.append({"id": chain, "title": title, "status": status, "events": trace_events})
    return traces, joins, services, unattached, disagreements


def render_html(traces):
    template = Path(__file__).with_suffix(".html").read_text(encoding="utf-8")
    data = json.dumps(traces, ensure_ascii=False).replace("<", "\\u003c")
    return template.replace("__TRACES__", data, 1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument("--out", type=Path, help="output HTML file")
    output.add_argument("--json", action="store_true", help="print trace data as JSON")
    parser.add_argument("inputs", nargs="+", type=Path, help="audit logs to merge")
    args = parser.parse_args(argv)
    try:
        events, skipped = read_events(args.inputs)
        traces, joins, services, unattached, disagreements = build_traces(events)
        if args.json:
            print(json.dumps(traces))
        else:
            args.out.write_text(render_html(traces), encoding="utf-8", errors="backslashreplace")
    except (OSError, ValueError) as error:
        message = str(error).replace("\r", r"\r").replace("\n", r"\n")
        print(f"trace_page: {message}", file=sys.stderr)
        return 1
    print(
        f"events={len(events)} skipped={skipped} traces={len(traces)} unattached={unattached} "
        f"joins={json.dumps(joins, sort_keys=True)} services={json.dumps(services, sort_keys=True)} "
        f"header_disagreements={disagreements}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
