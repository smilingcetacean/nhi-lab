import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("trace_page.py")
PARENT = "spiffe://example.test/agent/parent"
CHILD = "spiffe://example.test/agent/child"
VENDING = "spiffe://example.test/svc/vending-service"


def event(timestamp, stage, *, chain_id="", actor=PARENT, outcome="allow", **detail):
    return {
        "timestamp": f"2026-01-01T00:00:{timestamp}Z",
        "stage": stage,
        "chain_id": chain_id,
        "actor_spiffe_id": actor,
        "outcome": outcome,
        "detail": detail,
    }


def vend(timestamp, chain_id="chain-a"):
    return event(
        timestamp,
        "vend",
        chain_id=chain_id,
        child_spiffe_id=CHILD,
        parent_spiffe_id=PARENT,
        entry_id="entry123456",
        policy_id="policy123456",
    )


class TracePageTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def write_audit(self, name, *events):
        path = self.directory / name
        path.write_text("".join(json.dumps(row) + "\n" for row in events), encoding="utf-8")
        return path

    def cli(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *map(str, args)],
            cwd=self.directory,
            capture_output=True,
            text=True,
            check=False,
        )

    def read_traces(self, *paths):
        result = self.cli("--json", *paths)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stderr.splitlines()), 1, result.stderr)
        return json.loads(result.stdout), result.stderr

    def test_orders_fractional_timestamps_and_preserves_input_order_for_ties(self):
        first = self.write_audit(
            "first.jsonl",
            event("22.20008919", "operate", chain_id="chain-a", kind="later"),
            event("22.2", "operate", chain_id="chain-a", kind="first_tie"),
            event("22.200000002", "operate", chain_id="chain-a", kind="two_nanoseconds"),
        )
        second = self.write_audit(
            "second.jsonl",
            event("22", "operate", chain_id="chain-a", kind="whole_second"),
            event("22.200", "operate", chain_id="chain-a", kind="second_tie"),
            event("22.200000001", "operate", chain_id="chain-a", kind="one_nanosecond"),
        )
        traces, _ = self.read_traces(first, second)
        self.assertEqual(
            [(row["label"], row["at_ms"]) for row in traces[0]["events"]],
            [
                ("whole second", 0.0),
                ("first tie", 200.0),
                ("second tie", 200.0),
                ("one nanosecond", 200.0),
                ("two nanoseconds", 200.0),
                ("later", 200.1),
            ],
        )

    def test_resource_associates_with_authenticated_child_despite_header(self):
        path = self.write_audit(
            "audit.jsonl",
            vend("01"),
            event("02", "vend", chain_id="other-chain", child_spiffe_id="different-child"),
            event("03", "operate", chain_id="other-chain", actor=CHILD, method="GET", path="/example"),
        )
        traces, stats = self.read_traces(path)
        self.assertEqual([trace["id"] for trace in traces], ["chain-a", "other-chain"])
        row = traces[0]["events"][-1]
        self.assertEqual(row["service"], "resource")
        self.assertEqual(
            row["join"],
            "actor_spiffe_id = vended child; WARNING client-asserted chain_id other-chain disagrees",
        )
        self.assertEqual(len(traces[1]["events"]), 1)
        self.assertRegex(stats, r"header[ _-]disagreements\s*[:=]\s*1\b")

    def test_associates_with_earliest_future_and_latest_prior_vend(self):
        path = self.write_audit(
            "audit.jsonl",
            event("01", "spawn", child_spiffe_id=CHILD),
            vend("02"),
            event("03", "spawn", child_spiffe_id=CHILD),
            vend("04", "chain-b"),
            event("03", "operate", actor=CHILD, method="GET", path="/first"),
            event("05", "operate", actor=CHILD, method="GET", path="/second"),
            event("06", "operate", chain_id="chain-b", actor=PARENT, method="GET", path="/unmatched"),
        )
        traces, _ = self.read_traces(path)
        self.assertEqual(
            [[row["label"] for row in trace["events"]] for trace in traces],
            [["spawn", "vend: entry", "GET /first"], ["spawn", "vend: entry", "GET /second"]],
        )

    def test_second_attest_prevents_association_of_first_with_vend(self):
        path = self.write_audit(
            "audit.jsonl",
            event("01", "attest", reason="first attest"),
            event("02", "attest", reason="second attest"),
            vend("03"),
        )
        traces, _ = self.read_traces(path)
        self.assertEqual(len(traces[0]["events"]), 2)
        row = traces[0]["events"][0]
        self.assertEqual(row["summary"], "second attest")
        self.assertEqual(row["join"], "next vend by the same parent")

    def test_html_escapes_script_markup_in_embedded_event_data(self):
        request_path = "/examples/</script><img src=x>"
        path = self.write_audit(
            "audit.jsonl",
            vend("01"),
            event("02", "operate", actor=CHILD, method="GET", path=request_path),
        )
        output = self.directory / "trace.html"
        result = self.cli("--out", output, path)
        self.assertEqual(result.returncode, 0, result.stderr)
        html = output.read_text(encoding="utf-8")
        self.assertNotIn(request_path, html)
        self.assertIn("Content-Security-Policy", html)
        self.assertNotIn("innerHTML", html)
        self.assertNotIn("__TRACES__", html)
        match = re.search(r'<script id="data" type="application/json">(.*?)</script>', html, re.S)
        self.assertIsNotNone(match)
        row = json.loads(match.group(1))[0]["events"][-1]
        self.assertEqual(row["label"], f"GET {request_path}")

    def test_disposal_with_entry_id_is_attributed_to_vending_service(self):
        path = self.write_audit(
            "audit.jsonl",
            vend("01"),
            event("02", "dispose", chain_id="chain-a", actor=VENDING),
            event("03", "dispose", chain_id="chain-a", actor=VENDING, entry_id="entry123456"),
        )
        traces, _ = self.read_traces(path)
        self.assertEqual(
            [(row["service"], row["label"]) for row in traces[0]["events"][-2:]],
            [("policy-engine", "dispose: grant"), ("vending-service", "dispose: entry")],
        )

    def test_empty_invalid_or_missing_input_reports_one_line_and_writes_nothing(self):
        empty = self.write_audit("empty.jsonl")
        invalid = self.directory / "invalid.jsonl"
        invalid.write_text('startup message\n{"detail": {}}\n', encoding="utf-8")
        missing = self.directory / "missing.jsonl"
        for path in (empty, invalid, missing):
            with self.subTest(path=path.name):
                output = self.directory / "trace.html"
                result = self.cli("--out", output, path)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertEqual(len(result.stderr.strip().splitlines()), 1, result.stderr)
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
