# Evidence index

This index maps each claim the project makes to the run that tests it, the
file that holds the result, the result itself, and what the test does not
show. Every number below was read from the committed result files named in
its row. Percentiles are nearest-rank, as the harnesses compute them; `t0` is
the moment the parent sends its request.

**Current evidence** is the clean AWS run of 2026-11-21 at source `ea47be3`
(SPIRE agent `sync_interval` and server `cache_reload_interval` both 1 s,
unlimited CPU credits). Each item ran on its own fresh kind cluster, one after
another, on one VM. The storage-growth accumulate item failed there and was
rerun on the same VM at `a69d56f`, which differs from `ea47be3` only in
`register-entries.sh`. The [superseded AWS run](#superseded-runs) and the
[earlier local runs](#earlier-local-runs) are kept as history.

| Clean-run item | Directory | Status |
|---|---|---|
| a. Offline unit tests | [tests/20261121T203212Z](tests/20261121T203212Z/) | PASS |
| b. `make verify` + `make experiments` | [tests/20261121T203409Z](tests/20261121T203409Z/) | PASS (one AlreadyExists retry) |
| c. Vend to SVID | [20261121T204658Z-vend-to-svid](20261121T204658Z-vend-to-svid/) | PASS, 50/50 trials (retry) |
| d. Vend to access, poll | [20261121T205509Z-vend-to-access-poll](20261121T205509Z-vend-to-access-poll/) | PASS, 50/50 (retry) |
| e. Vend to access, child.py | [20261121T210346Z-vend-to-access-child-py](20261121T210346Z-vend-to-access-child-py/) | PASS, 50/50 (retry) |
| f. Revoke to deny | [20261121T211226Z-revoke-to-deny](20261121T211226Z-revoke-to-deny/) | PASS, 50/50 (retry) |
| g. Revocation speed (cascade) | [20261121T212106Z-revocation-speed](20261121T212106Z-revocation-speed/) | PASS, 30/30 |
| h. Storage growth, accumulate | [20261121T212719Z-storage-growth-accumulate](20261121T212719Z-storage-growth-accumulate/) | **FAILED**, no data ([failure-note.txt](20261121T212719Z-storage-growth-accumulate/failure-note.txt)) |
| h'. Storage growth, accumulate rerun at `a69d56f` | [20261121T215047Z-storage-growth-accumulate](20261121T215047Z-storage-growth-accumulate/) | PASS, `all_ok: true`; no workarounds or retries; register-entries fix verified ([fix-check.log](20261121T215047Z-storage-growth-accumulate/fix-check.log)) |
| i. Storage growth, churn | [20261121T213006Z-storage-growth-churn](20261121T213006Z-storage-growth-churn/) | PASS (retry) |

"Retry" means the first bring-up hit the `register-entries.sh` AlreadyExists
bug and the queue reran it with `make -o entries`; see
[Known anomalies](#known-anomalies-and-limitations). Item h failed for a
different reason (the queue did not raise `MAX_LIVE_CHILDREN`) and stays
recorded as a failure; h' replaces it as evidence.

Plots for these runs are in [plots/](plots/) and are regenerated from the
committed CSV and JSON files by [plots/plot_runs.py](plots/plot_runs.py).

---

## Claim 1: a subagent identity can be provisioned autonomously

The parent asks the vending service for a child identity over an API call; no
human step is involved between the request and the child holding a SPIFFE
SVID.

| Evidence | Result | File |
|---|---|---|
| Baseline `make verify` on the clean VM | `VERIFY: PASS (17 checks)` | [baseline-verify.log](tests/20261121T203409Z/baseline-verify.log) |
| Multi-hop P → C → G | Both hops returned 201; C and G each obtained an SVID; Π(C) ⊆ Π(P) and Π(G) ⊆ Π(C); G's `write:jobs` request was attenuated; G got 200 on `/datasets/A` and 403 on `POST /jobs`; after C was disposed G got 403 and G's entry was gone; `overall_pass: true` | [multi_hop.json](tests/20261121T203409Z/multi_hop.json) |
| Performance suite (vend → SVID → operate → dispose) | 100 of 100 runs `ok`, 100 of 100 `got_svid` | [performance_summary.json](tests/20261121T203409Z/performance_summary.json), [performance_runs.csv](tests/20261121T203409Z/performance_runs.csv) |
| Vend to SVID benchmark | 50 of 50 trials: the child's Workload API returned the new X.509-SVID; vend audit event inside the vend request 50/50; order checks 50/50; dispose 200 in 50/50 | [vend_to_svid_summary.json](20261121T204658Z-vend-to-svid/vend_to_svid_summary.json) |

Plots: [vend-to-svid CDF](plots/20261121T204658Z-vend-to-svid_cdf.png),
[stages by trial](plots/20261121T204658Z-vend-to-svid_t0-t3.png).

**Limitations.** The parent in these runs is `parentsim`, a scripted client,
not an LLM agent. The OpenCode parent path (`make verify-present`,
`verify-exit-hooks`) was last run on 2026-11-09 on the local host
([tests/20261109T020524Z/verify-present](tests/20261109T020524Z/verify-present/)),
not on the clean VM. The child workloads are pods in a two-node kind cluster
on one machine.

## Claim 2: a child gets scoped access only

| Evidence | Result | File |
|---|---|---|
| Scope containment, 30 randomized scope sets | 30/30 pass (26 vends returned 201 with Π(C) = requested ∩ Π(P); 4 requests with an empty intersection returned 403) | [functional_scope_containment.csv](tests/20261121T203409Z/functional_scope_containment.csv), [functional_tests_summary.json](tests/20261121T203409Z/functional_tests_summary.json) |
| Credential expiry on disposal, 10 runs | 10/10 pass; time until the Workload API stopped serving the credential 1.351–1.437 s (median 1.382 s) | [functional_credential_expiry.csv](tests/20261121T203409Z/functional_credential_expiry.csv) |
| Negative tests, 5 cases | 5/5 pass: forged parent signature → 401; scope escalation → 403; replayed manifest → 201 then 409; captured JWT reused after disposal → 403; orphaned child reaped. No-pod service-account precondition passed. The forged-signature, escalation and replay denials each matched exactly one audit event of their own request. | [negative_tests.json](tests/20261121T203409Z/negative_tests.json) |
| Falsification of the five guards (2026-11-09) | Each guard g1–g5 mutated in turn: its own negative test failed and only that test (g1 forged signature, g2 empty attenuation, g3 nonce replay, g4 dispose grant, g5 reaper); every reverted image passed 5/5. Repeated on two independent clusters. | [tests/20261109T024542Z/summary.json](tests/20261109T024542Z/summary.json), [primary/summary-table.txt](tests/20261109T024542Z/primary/summary-table.txt), [replication/summary-table.txt](tests/20261109T024542Z/replication/summary-table.txt); first pass with the original suite in [tests/20261109T020524Z/falsification](tests/20261109T020524Z/falsification/) |

**Limitations.** The falsification ran on the owner's local 16-CPU host at
`58a8c7d`/`0b0fcca` with the stock 5 s SPIRE intervals, **not on the clean
VM** and not at `ea47be3`. The guards it exercised did not change between
those commits and `ea47be3` (`ea47be3` touches only the two SPIRE
ConfigMaps), but the mutated builds were not rerun on AWS. Scope containment
uses 30 seeded random scope sets over the lab's three scopes; it is a sample,
not an exhaustive or formal check.

## Claim 3: revocation is fast and effective

| Evidence | Result | File |
|---|---|---|
| Revoke to first 403 (P revokes C; C polls every 20 ms with a fresh JWT-SVID) | 50/50 trials: first denial was a 403; DELETE → first 403 p50 33.6 ms, p95 45.9 ms, max 46.8 ms; the resource's deny audit event fell inside the denied request in 50/50; policy engine removed the grant at p50 23.9 ms | [revoke_to_deny_summary.json](20261121T211226Z-revoke-to-deny/revoke_to_deny_summary.json), [revoke_to_deny.csv](20261121T211226Z-revoke-to-deny/revoke_to_deny.csv) |
| Revoke to SVID gone (C's first failed JWT-SVID fetch, "no identity issued") | 50/50; p50 930.0 ms, p95 1,713.9 ms, max 2,001.5 ms; C's entry gone in 50/50 | same files |
| Cascade revocation (P revokes C; grandchild G polls) | 30/30 under the 1 s target; DELETE → G's first 403 p50 30.7 ms, p95 40.1 ms, max 41.5 ms; G's and C's entries gone and G's row revoked by cascade in 30/30; resource audit event inside the denied request 30/30, within 0.902 ms of the poller | [revocation_speed_summary.json](20261121T212106Z-revocation-speed/revocation_speed_summary.json), [revocation_speed.csv](20261121T212106Z-revocation-speed/revocation_speed.csv) |
| Captured JWT reused after disposal | 403 (negative test) | [negative_tests.json](tests/20261121T203409Z/negative_tests.json) |

Plots: [revoke-to-deny CDF](plots/20261121T211226Z-revoke-to-deny_cdf.png),
[by trial](plots/20261121T211226Z-revoke-to-deny_by-trial.png),
[cascade CDF](plots/20261121T212106Z-revocation-speed_cdf.png),
[cascade by trial](plots/20261121T212106Z-revocation-speed_by-trial.png).

**Limitations.** The fast 403 comes from the policy side: the policy engine
removes the grant from OPA and the resource asks OPA on every request. The
revoked child's JWT-SVID stays cryptographically valid until it expires (the
first 403 used the same token the child held before the revoke in 50/50
trials). A relying party that checked only the token signature, without
asking OPA, would accept it until expiry. Withdrawal of the SVID itself
follows the SPIRE agent sync and took up to 2.0 s here. The timings use
`CLOCK_REALTIME` stamps from pods on one host; on separate machines clock
skew would enter the result.

## Latency split: time to create vs time until usable

"Create" is the time until the child holds its new SVID; "usable" is the time
until the child receives its first 200 from the protected resource with that
identity. All rows are from the clean run (`ea47be3`, 1 s intervals).

| Measure | Definition | n | p50 (ms) | p95 (ms) | Source (file, column) |
|---|---|---|---|---|---|
| Registration entry created | t0 → vend returns 201 (t1) | 50 | 51.0 | 95.0 | [vend_to_svid.csv](20261121T204658Z-vend-to-svid/vend_to_svid.csv), `vend_round_trip_ms` |
| **Time to create** | t0 → child's Workload API answer holds the new X.509-SVID (t3) | 50 | **1,104.3** | **1,708.8** | [vend_to_svid.csv](20261121T204658Z-vend-to-svid/vend_to_svid.csv), `vend_to_svid_ms` |
| Created, poll run | t0 → child holds its JWT-SVID | 50 | 1,108.6 | 1,712.4 | [vend_to_access.csv](20261121T205509Z-vend-to-access-poll/vend_to_access.csv), `vend_to_jwt_ms` |
| **Time until usable, poll** (child retries every 20 ms) | t0 → first 200 | 50 | **1,118.9** | **1,720.9** | [vend_to_access.csv](20261121T205509Z-vend-to-access-poll/vend_to_access.csv), `vend_to_access_ms` |
| Created → usable, poll | JWT-SVID held → first 200 | 50 | 9.8 | 17.3 | same file, `jwt_to_access_ms` |
| Created, child.py run | t0 → child holds its X.509-SVID | 50 | 2,244.8 | 2,309.7 | [vend_to_access.csv](20261121T210346Z-vend-to-access-child-py/vend_to_access.csv), `vend_to_x509_ms` |
| **Time until usable, child.py** (child retries every 2 s, as `src/agents/child.py` does) | t0 → first 200 | 50 | **2,263.5** | **2,325.8** | [vend_to_access.csv](20261121T210346Z-vend-to-access-child-py/vend_to_access.csv), `vend_to_access_ms` |
| Created → usable, child.py | X.509-SVID held → first 200 (computed per trial: `vend_to_access_ms − vend_to_x509_ms`) | 50 | 14.7 | 29.7 | same file |
| **Revoke → 403** | DELETE sent → C's first 403 | 50 | **33.6** | **45.9** | [revoke_to_deny.csv](20261121T211226Z-revoke-to-deny/revoke_to_deny.csv), `revoke_to_deny_ms` |
| **Revoke → SVID gone** | DELETE sent → C's first failed SVID fetch | 50 | **930.0** | **1,713.9** | same file, `revoke_to_identity_gone_ms` |
| Cascade revoke → grandchild's 403 | DELETE of C sent → G's first 403 | 30 | 30.7 | 40.1 | [revocation_speed.csv](20261121T212106Z-revocation-speed/revocation_speed.csv), `delta_ms` |

Plots: [poll CDF](plots/20261121T205509Z-vend-to-access-poll_cdf.png),
[poll by trial](plots/20261121T205509Z-vend-to-access-poll_by-trial.png),
[child.py CDF](plots/20261121T210346Z-vend-to-access-child-py_cdf.png),
[child.py by trial](plots/20261121T210346Z-vend-to-access-child-py_by-trial.png).

What the split shows:

- Almost all of "time to create" is the wait for the child's SPIRE agent to
  pick up the new entry. In the vend-to-svid run the medians are t0→t1 51 ms,
  t1→t2 (agent logs the entry) 922 ms, t2→t3 13 ms.
- Once the child holds an SVID it is usable within tens of milliseconds
  (p95 17.3 ms in the poll run, 29.7 ms in the child.py run).
- With the lab's own child (`child.py`), time until usable is set mainly by
  its 2 s retry delay, not by SPIRE: its agent had the entry at a median of
  1,000.6 ms, but the child first looked at about 0.2 s and next at about
  2.2 s.

**Limitations.** One run of 50 trials per row (30 for the cascade) on one VM.
The values depend on the 1 s SPIRE intervals; the stock 5 s intervals give
several seconds (see [superseded runs](#superseded-runs)). The "created"
stamps are the moment the child's own fetch returned, so they include the
child's polling granularity (20 ms in the poll run, 2 s in the child.py run).

## Claim 4: actions are traceable

| Evidence | Result | File |
|---|---|---|
| Vend audit event per vend | The vending service's `vend` allow event (with parent and child SPIFFE IDs, chain ID, entry ID, policy ID, scopes) fell inside the vend request in 50/50 trials of each of the three vend runs | `checks.trials_audit_vend_allow_inside_vend_request` in [vend_to_svid_summary.json](20261121T204658Z-vend-to-svid/vend_to_svid_summary.json), [poll](20261121T205509Z-vend-to-access-poll/vend_to_access_summary.json), [child.py](20261121T210346Z-vend-to-access-child-py/vend_to_access_summary.json) |
| Resource decisions | Resource allow event inside the access request 50/50 (poll and child.py); deny event inside the 403 request 50/50 (revoke-to-deny) and 30/30 (cascade) | same summaries; [revoke_to_deny_summary.json](20261121T211226Z-revoke-to-deny/revoke_to_deny_summary.json); [revocation_speed_summary.json](20261121T212106Z-revocation-speed/revocation_speed_summary.json) |
| Disposal events | Policy-engine and vending-service `dispose` events found in 50/50 revoke trials | [revoke_to_deny_summary.json](20261121T211226Z-revoke-to-deny/revoke_to_deny_summary.json) |
| Lineage across hops | Hop 2's vend event names C as the actor; G's SPIFFE ID nests under C's (`…/exp-root/child/mh-c-…/child/mh-g-…`); `lineage_traceable_via_audit: true` | [multi_hop.json](tests/20261121T203409Z/multi_hop.json) |
| Per-trial logs | Vending service, resource, policy engine, SPIRE agent and parent logs for each trial window | `logs/` in each run directory, e.g. [revoke-to-deny logs](20261121T211226Z-revoke-to-deny/logs/) |
| Audit trail survives a restart | `PERSISTENCE VERIFY: PASS (10 steps)` (local, 2026-11-09) | [tests/20261109T020524Z/verify-core](tests/20261109T020524Z/verify-core/) |

**Limitations.** The trail is built from the components' own logs: the
vending service, policy engine and resource write their own audit events, and
SPIRE identities are issued by the SPIRE server. The trail is only as
trustworthy as those components. It assumes that the vending service and the
SPIRE server are not compromised; a compromised vending service could mint an
identity and write a matching, false audit event. The Nov 9 falsification
found one concrete case: with the signature guard removed (g1), the vend
audit event still said the signature was verified, because that reason text
is fixed and written after the check
([summary.json](tests/20261109T020524Z/summary.json), `findings`). The audit
files are not signed or shipped to an external store. The SPIRE server's own
audit log was **disabled** in the clean runs (`spire_server_audit_log_enabled:
false`, 0 server log lines), so the clean evidence has no SPIRE-side record of
entry creation or SVID signing; the Nov 1–2 local runs enabled it per cluster.

## Reproducibility

| Item | Value | Where recorded |
|---|---|---|
| VM | EC2 `i-01d083bbb690a12c2`, t3a.large Spot, us-east-1f, unlimited CPU credits; 2 vCPU AMD EPYC 7571, 7.7 GiB; fresh instance replacing `i-0c432f8d182025e8d` | [host.txt](tests/20261121T203409Z/host.txt), each `outcome.json` |
| Infrastructure definition | OpenTofu: one Spot instance, security group with no ingress and egress on TCP 80/443 only, SSM instance profile, `cpu_credits = "unlimited"` | [../infra/aws-lab/main.tf](../infra/aws-lab/main.tf) (untracked at the time of writing; state and plan files are git-ignored) |
| Source | `ea47be3c910bcd3d43a5b2fef09cdeca57343918`; accumulate rerun h' at `a69d56fc017cd890d2d5eacbd1f2ca05dec249b2` | `source_commit` in each `host.txt`, `source_sha` in each `outcome.json` |
| Source archive | sha256 `651b450c3d455dcc5db8b6edc024b7ca1b98a2c427eb40d895e9642004f2142d` (`ea47be3`); `af895909039a6752e412c6889279b1f3cbde22d47d6ad77bdb6ba122cda3794f` (`a69d56f`, made with the same `git archive` command); each verified on the guest and locally | `source_archive_sha256_guest_and_local` in each `artifact-verification.json` |
| Result transfer | Each result tarball's sha256 matched on the guest and locally (`sha256_match: true` for all eleven clean items, h' included); transport was SSM Run Command, no ingress | each `artifact-verification.json`, `transport.json` |
| OS and tools | Ubuntu 24.04.5, kernel 7.0.0-1018-aws; Docker 29.1.3 (Ubuntu build), containerd 2.2.1, runc 1.3.4; kind v0.32.0 (node image kindest/node v1.36.1); kubectl v1.36.2; Go 1.26.5; OPA 1.18.2; uv 0.13.7 with Python 3.14.6; GNU Make 4.3; jq 1.7; bash 5.2.21; SPIRE server and agent 1.15.2 | [host.txt](tests/20261121T203409Z/host.txt), `host` block of each summary |
| Trial settings | 50 trials (30 for the cascade); jitter 0–5 s before each trial with seed 115506412; 20 ms poll interval | each summary JSON, `console.log` |

How to rerun, per item, on a fresh cluster (`KIND_CLUSTER=<name>`):

1. `make cluster-up spire-up`, then
   `make policy-engine-up vending-service-up resource-up experiments-fixtures-up`.
   Before `a69d56f`, a second `make` pass could stop on `AlreadyExists` in
   `register-entries.sh`; the queue then reran with `make -o entries …`. At
   `a69d56f` and later no `-o entries` is needed (verified in h').
2. Offline checks: `make resource-test policy-engine-test vending-service-test agents-test rego-test`.
   Functional: `make verify` and `make experiments`.
3. Latency benchmarks, from `src/experiments` with
   `CLUSTER_NAME=nhi-lab KUBECTX=kind-<name> TRUST_DOMAIN=lab.local`, exactly
   as the queue ran them ([console.log](20261121T204658Z-vend-to-svid/console.log)):
   `uv run python3 vend_to_svid.py --trials 50 --jitter-s 5 --seed 115506412`,
   `vend_to_access.py --style poll|child-py …`, `revoke_to_deny.py …`. The
   Make targets `make vend-to-svid VEND_SVID_JITTER_S=5`,
   `make vend-to-access VEND_ACCESS_STYLE=poll|child-py VEND_ACCESS_JITTER_S=5`
   and `make revoke-to-deny REVOKE_DENY_JITTER_S=5` run the same harnesses
   with a random seed. Cascade: `make revocation-speed`.
4. Storage growth: churn needs no setup:
   `uv run python3 storage_growth.py --phase churn --n 100 --step 25`.
   **Accumulate needs the live-children cap raised first**, or the harness
   exits with `MAX_LIVE_CHILDREN is 8 … this run needs 200`:
   `kubectl -n nhi set env deployment/vending-service MAX_LIVE_CHILDREN=200`,
   wait for the rollout, then
   `uv run python3 storage_growth.py --phase accumulate --n 200 --step 25`.
   h' did exactly this and recorded it in
   [setup-cap.log](20261121T215047Z-storage-growth-accumulate/setup-cap.log).
5. Plots: `uv run --with matplotlib python3 benchmarks/plots/plot_runs.py`
   from the repository root.

## Storage growth

| Evidence | Result | File |
|---|---|---|
| 100 vend-then-dispose cycles, live children stay 0 | All consistency checks `ok` (`all_ok: true`): delegation and nonce rows +1 per vend; SPIRE entries, selector rows and OPA modules return to baseline; `quick_check` ok. Vending volume 78 kB → 4.02 MB on disk, almost all in the `-wal` file (3.85 MB); its logical SQLite content 28.7 kB → 86.0 kB; audit.jsonl 138 kB. SPIRE volume 0.90 MB → 4.35 MB, again almost all `-wal` (4.15 MB, flat from cycle 50); logical content 143 kB → 172 kB. | [storage_growth_summary.json](20261121T213006Z-storage-growth-churn/storage_growth_summary.json), [storage_growth.csv](20261121T213006Z-storage-growth-churn/storage_growth.csv) |
| Accumulate to 200 live children, then drain (oldest first); rerun h' at `a69d56f` | All consistency checks `ok` (`all_ok: true`); `max_live_children_in_running_pod: 200`. Per live child (OLS slope over the accumulate checkpoints): 6 rows (SPIRE `registered_entries` 1, `registered_entries_events` 1, `selectors` 2; vending `delegations` 1, `used_nonces` 1); logical SQLite bytes SPIRE 946.6, vending 591.1; audit.jsonl 901.8 B. OPA `GET /v1/policies` grows 1,126.99 B per live grant module (R² ≈ 1.0); a linear projection, not a measurement, puts the policy engine's 4 MiB read limit at about 3,688 live modules. Drain freed logical space (SPIRE 135,168 B to the freelist) but no disk space: on-disk size after the drain was 49 kB (SPIRE) and 96 kB (vending) **larger** than at the peak. All the per-child logical figures and the OPA figures equal those of the local 20261107T181324Z run. | [storage_growth_summary.json](20261121T215047Z-storage-growth-accumulate/storage_growth_summary.json), [storage_growth.csv](20261121T215047Z-storage-growth-accumulate/storage_growth.csv), [storage_growth_tables.csv](20261121T215047Z-storage-growth-accumulate/storage_growth_tables.csv), [storage_growth_ops.csv](20261121T215047Z-storage-growth-accumulate/storage_growth_ops.csv) |

Plots: [churn bytes vs cycles](plots/20261121T213006Z-storage-growth-churn_bytes-vs-cycles.png),
[accumulate bytes vs N](plots/20261121T215047Z-storage-growth-accumulate_bytes-vs-n.png),
[OPA response size](plots/20261121T215047Z-storage-growth-accumulate_opa-resp-bytes.png),
[per-table bytes](plots/20261121T215047Z-storage-growth-accumulate_per-table-bytes.png).

**Limitations.** On-disk size here is dominated by SQLite write-ahead logs,
which grow in page steps and shrink only at a checkpoint; 100 cycles is too
short to show the long-run size. For the same reason the on-disk slope per
child is not a clean per-child figure: in h' the SPIRE on-disk slope is
19,282 B per child against 22,965 B in the Nov 7 local run, but most of it is
`-wal` growth (17,622 B per child), and the two runs start from different
`-wal` sizes (865,232 B at step 0 in h', 115,392 B on Nov 7). The churn run on
the clean VM also started at 865,232 B, so the larger start is not specific
to the h' bring-up; its cause was not established. Use the logical bytes and
row counts as the per-child cost. One run per phase. In h', `vmstat.txt`
covers the whole item from bring-up (21:50:47Z), not only the benchmark
window (21:54:11Z–21:58:18Z). Both runs'
`provenance.json` files are partly wrong; see the known issue below.

## Known anomalies and limitations

- **AlreadyExists retries.** Seven of the nine clean items (b–f, h, i) hit
  `AlreadyExists` from `register-entries.sh` during bring-up; the queue reran
  each with `make -o entries`, which succeeded. Each case is recorded in that
  item's `outcome.json` (`workarounds`). Cause: `entry show | grep -q` under
  `pipefail` can fail with SIGPIPE (exit 141), so an existing entry read as
  absent. Fixed in `a69d56f`, after these runs. **The fix is verified on a
  real cluster** in the accumulate rerun h': after a full bring-up, a second
  `make entries` exited 0 at 21:52:45Z with all 12 static entries reported
  "already registered", and the prerequisite targets then ran **without**
  `-o entries` and exited 0 at 21:54:06Z. No output line contained
  `AlreadyExists`, and h' records no workarounds or retries
  ([fix-check.log](20261121T215047Z-storage-growth-accumulate/fix-check.log),
  [outcome.json](20261121T215047Z-storage-growth-accumulate/outcome.json)).
  This is one cluster bring-up; the race is intermittent, so it shows the fix
  works on that path, not that the race can no longer occur in any setting.
- **Known issue: storage-growth `provenance.json` is partly hard-coded.**
  `storage_growth.py` writes fixed text into `provenance.json`: it claims
  `audit_log_enabled = true`, SPIRE intervals set by hand on the cluster, and
  `MAX_LIVE_CHILDREN = 200`, and its `code.branch` and `code.base_commit` are
  empty when the source is an archive rather than a git checkout. On the
  clean VM the SPIRE server audit log was off (0 server lines), the 1 s
  intervals came from the repository manifests, and in the churn run the cap
  stayed at 8. For storage-growth runs, rely on `storage_growth_summary.json`
  (its `host` block records the real cap and audit-log state) and
  `outcome.json`, not on `provenance.json`.
- **CPU credits.** CloudWatch reported `CPUCreditBalance` 1.15 in the 20:30Z
  bucket (unit tests) and 0 in every bucket from 20:35Z on. In unlimited mode
  the instance then spends surplus credits instead of being throttled:
  `CPUSurplusCreditBalance` rose to 27.2 by the 21:30Z bucket, and
  `CPUSurplusCreditsCharged` was 0 in every bucket at query time. CPU
  utilization averaged about 34–80 % per 5-minute bucket. See each item's
  `cloudwatch-cpu-credit-balance.json`. During the accumulate rerun h' the
  balance was again 0, CPU peaked at 77.8 % (5-minute maximum), the surplus
  balance was 20.8–22.9 and nothing was charged. The CloudWatch data are 5-minute
  averages, so short throttling inside a bucket cannot be ruled out from
  them, though unlimited mode does not throttle at a zero balance.
- **n = 49 for `access_window_ms` in the child.py run.** Not a lost trial.
  In trial 9 the child's agent logged the entry 114 ms after the vend, before
  the child's first attempt (about 180 ms after the vend response), so the
  child got its X.509-SVID on the first attempt (`x509_attempts` 1,
  `child_misses` 0, `miss_reasons {}`). `access_window_ms` is defined as
  first 200 minus the last missed attempt; with no miss there is nothing to
  subtract, and `vend_to_access.py` leaves the field empty
  ([raw record](20261121T210346Z-vend-to-access-child-py/vend_to_access_raw.json),
  trial 9). The other 49 trials each had one miss. Trial 9 is also the 239 ms
  minimum of `vend_to_access_ms`.
- **Sample size.** One VM, one run per item, 50 trials per latency benchmark
  (30 for the cascade). No run-to-run variance is measured, and the numbers
  are for a two-node kind cluster on a 2-vCPU host, not a production cluster.
- **Single point of failure.** The vending service is the only path to a
  child identity and holds the lab's highest-privilege credential. If it is
  down, no new children can be provisioned; if it is compromised, see the
  traceability limitation above. Nothing here tests high availability.
- **Failure resilience untested.** No run injected faults (node loss, SPIRE
  server or OPA outage, network partition, Spot interruption) on the clean
  VM. The local `verify-persistence` and `verify-exit-hooks` checks of
  2026-11-09 cover a pod restart and parent pod deletion only.
- **Not done (listed by the owner):** no alignment with OpenID standards
  (for example OpenID Connect or token exchange) and no formal proof of the
  containment or revocation properties. All results here are empirical.
- **Comparison with the superseded run.** The SPIRE intervals (5 s → 1 s) and
  the CPU credit mode (Standard, throttled → unlimited) changed together, and
  the VM and its Docker build (29.6.2 → 29.1.3) differ too, so the
  [comparison figure](plots/20261121-aws-c1e4dbe-vs-ea47be3_p50-p95.png)
  cannot attribute the difference to any one change.

## Superseded runs

AWS run of 2026-11-21 at `c1e4dbe`: stock 5 s SPIRE intervals, Standard CPU
credits, on the earlier instance `i-0c432f8d182025e8d`. CloudWatch showed the
credit balance at 0–0.018 during sampling, so the CPU was throttled. Kept as
history; superseded by the clean run above.

| Directory | What it is | Status |
|---|---|---|
| [20261121T182437Z-vend-to-svid](20261121T182437Z-vend-to-svid/) | First vend-to-SVID attempt | Failed in bring-up (AlreadyExists), no samples |
| [20261121T184346Z-vend-to-svid](20261121T184346Z-vend-to-svid/) | Vend to SVID | 50/50; p50 5,469 ms, p95 8,815 ms |
| [20261121T190208Z-vend-to-access-poll](20261121T190208Z-vend-to-access-poll/) | Vend to access, poll | 50/50; p50 5,233 ms, p95 8,349 ms |
| [20261121T192916Z-revoke-to-deny](20261121T192916Z-revoke-to-deny/) | Revoke to deny | 50/50; revoke → 403 p50 35.1 ms, p95 53.8 ms; revoke → SVID gone p50 4,852 ms, p95 7,360 ms |
| [20261121T194348Z-vend-to-access-child-py](20261121T194348Z-vend-to-access-child-py/) | Vend to access, child.py | 50/50; p50 8,258 ms, p95 10,294 ms |
| [20261121T200215Z-revocation-speed-cancelled](20261121T200215Z-revocation-speed-cancelled/) | Cascade revocation | Cancelled by the owner after 6 of 30 trials; not a valid result |
| [tests/20261121T183125Z](tests/20261121T183125Z/) | Offline checks | Go targets failed (no Go module cache in the SSM shell); Rego and agents passed |
| [tests/20261121T183141Z](tests/20261121T183141Z/) | Functional (`verify`, experiments) | Passed |
| [tests/20261121T183906Z](tests/20261121T183906Z/) | Offline checks, retry | Passed |

## Earlier local runs

Run on the owner's workstation in throwaway kind clusters. The November 1–2
benchmark runs used an uncommitted working tree on top of `39eac90`.
"1 s" means the SPIRE agent `sync_interval` and server
`cache_reload_interval` were set to 1 s on that cluster only (per-cluster
override, repository manifests unchanged); "5 s" is the stock default of the
time.

| Directory | What it is | SPIRE intervals |
|---|---|---|
| [20261101T220757Z-vend-to-svid](20261101T220757Z-vend-to-svid/) | Vend to SVID, phase-locked start | 5 s |
| [20261101T223329Z-vend-to-svid-random-phase](20261101T223329Z-vend-to-svid-random-phase/) | Vend to SVID, random start | 5 s |
| [20261101T234407Z-vend-to-svid-random-phase-1s](20261101T234407Z-vend-to-svid-random-phase-1s/) | Vend to SVID, random start | 1 s |
| [20261102T032618Z-vend-to-svid-server-telemetry](20261102T032618Z-vend-to-svid-server-telemetry/) | Vend to SVID with SPIRE server telemetry | 5 s |
| [20261102T040134Z-vend-to-access-poll-1s](20261102T040134Z-vend-to-access-poll-1s/) | Vend to access, poll | 1 s |
| [20261102T040601Z-vend-to-access-child-py-1s](20261102T040601Z-vend-to-access-child-py-1s/) | Vend to access, child.py | 1 s |
| [20261103T044158Z-revoke-to-deny-1s](20261103T044158Z-revoke-to-deny-1s/) | Revoke to deny | 1 s |
| [20261107T181324Z-storage-growth-accumulate-1s](20261107T181324Z-storage-growth-accumulate-1s/) | Storage growth, accumulate to 200 and drain (`MAX_LIVE_CHILDREN=200`) | 1 s |
| [20261107T181817Z-storage-growth-churn-1s](20261107T181817Z-storage-growth-churn-1s/) | Storage growth, churn | 1 s |
| [tests/20261109T020524Z](tests/20261109T020524Z/) | Negative, functional, verify and first falsification pass; five clusters in parallel on a 16-CPU host, at `58a8c7d` | 5 s |
| [tests/20261109T024542Z](tests/20261109T024542Z/) | Falsification with the corrected negative tests, two independent clusters, at `0b0fcca` | 5 s |

The PNGs of the November runs in [plots/](plots/) were made ad hoc before
`plot_runs.py` existed; the script does not overwrite them.
