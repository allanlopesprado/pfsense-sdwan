# ERP-only WAN failure on FreeBSD PF

In three SD-WAN runs, new ERP connections received replies through WAN2 **3.492 s** after ERP stopped responding on WAN1. The backup and DNS flows succeeded throughout. The native gateway-group control did not move ERP to WAN2 during any of its three 12.009 s fault windows. [GitHub Actions run](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44941257858)

## Setup and comparison

| Item | Setting |
| --- | --- |
| Test run | GitHub Actions 44941257858, FreeBSD job 136996383367 |
| Guest | FreeBSD 15.1-RELEASE amd64 with VNET jails, epair links, dpinger, and kernel PF |
| SD-WAN source | Benchmark branch commit `32435462fa3e19089da87bffa4409a6b607e804c` with port version `0.4.28` |
| Native filter source | pfSense commit `9363ac5b8651a1c7a333180425ce7719070f95f9` |
| Control | The pinned pfSense rule compiler generated the ERP rule for the native gateway group. Both gateway monitors remained healthy. |
| SD-WAN | The same compiler generated the ERP rule with the adapter and an explicit binding. The harness invoked the real package observer in single-cycle mode and loaded each new selection into PF. |
| Fault | Peer PF dropped TCP to the ERP service and its standby probe on WAN1. WAN1 DNS and the backup TCP flow remained available. |
| Traffic | A separate new ERP connection, queries on an already-open ERP socket, backup TCP connections, and DNS requests in both modes |
| Repetitions | Three runs per mode, in order native, SD-WAN, SD-WAN, native, native, SD-WAN |
| Measurement cadence | A client attempt every 250 ms per flow with a 200 ms timeout. The observer target interval was 1 s. |
| Measurement phases | 5 s baseline, 12 s fault, 38 s recovery requested. The report includes the observed durations. |

[Source commit](https://github.com/allanlopesprado/pfsense-sdwan/commit/32435462fa3e19089da87bffa4409a6b607e804c) · [Workflow and exact commands](https://github.com/allanlopesprado/pfsense-sdwan/blob/32435462fa3e19089da87bffa4409a6b607e804c/.github/workflows/benchmark.yml) · [Pinned pfSense source](https://github.com/pfsense/pfsense/commit/9363ac5b8651a1c7a333180425ce7719070f95f9)

## Results

| During the ERP fault, three runs per mode | Native gateway group | SD-WAN |
| --- | ---: | ---: |
| New ERP connections with a valid reply | 0 / 144 (0.00%) | 105 / 144 (72.92%) |
| New ERP connection attempts that timed out | 144 / 144 (100.00%) | 39 / 144 (27.08%) |
| ERP transactions on the already-open socket that returned a valid reply | 0 / 144 (0.00%) | 0 / 144 (0.00%) |
| Backup TCP connections with a valid reply | 144 / 144 (100.00%) | 144 / 144 (100.00%) |
| DNS requests with a valid reply | 144 / 144 (100.00%) | 144 / 144 (100.00%) |
| WAN2 confirmed in loaded PF rules after the fault | No WAN2 rule during the observation windows | 3.321 s in each run |
| First ERP reply in the sustained WAN2 sequence | None within 12.009 s per run | 3.492 s in each run |
| Third consecutive ERP reply through WAN2 | None within 12.009 s per run | 3.992 to 3.993 s |
| WAN1 reconfirmed by three ERP replies after repair | 0.733 to 0.734 s | 31.483 to 31.484 s |

In the baseline, ERP succeeded **63 / 63** times in each mode. The pooled p95 for those successful responses was **2.288 ms** native and **2.237 ms** with SD-WAN. The recovery-phase result was **452 / 453** new ERP replies in each mode. In SD-WAN runs, ERP was already replying through WAN2 at the end of the fault. It returned to the preferred WAN1 about 31 s after repair.

The loaded ERP tracker `41001` moved from WAN1 next hop `198.51.100.2` to WAN2 next hop `203.0.113.2`. The reply included the source seen by the server after NAT. All 105 successful ERP replies during the fault reported WAN2 source `203.0.113.1`, and all 144 backup replies reported WAN1 source `198.51.100.1` in each mode. The 12 rule loads recorded the same NAT rules SHA-256. An open ERP session stopped replying during the fault in both modes, with sustained replies resuming about 5.98 s after repair.

### Independent rerun of the same workflow

The second Actions attempt repeated all six trials against the same source revision. It again recorded 0/144 new ERP replies in native mode and 105/144 with SD-WAN, with the first WAN2 reply at 3.492 s and the third at 3.992 to 3.993 s. Across both attempts, new ERP replies during the fault totaled 0/288 native and 210/288 (72.92%) with SD-WAN. Backup and DNS each returned 288/288 replies in each mode during the fault. The original ERP sockets returned 0/288 in both modes during the fault. The rerun measured baseline ERP response p95 at 1.961 ms native and 1.946 ms with SD-WAN, with 63 successful replies per mode. In the rerun's recovery window new ERP replies were 453/453 in both modes. [Rerun in Actions](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44941257858/attempts/2) · [Rerun tables](evidence/freebsd-erp-44941257858-attempt2/report.md) · [Rerun raw measurements](evidence/freebsd-erp-44941257858-attempt2/)

Read the [complete per-run and pooled tables for the first attempt](evidence/freebsd-erp-44941257858/report.md) for attempt counts, failure and timeout rates, response and connection p50, p95 and maximum, source breakout, boundary-crossing requests, probe timing, and gateway loss and RTT. The [machine-readable summary](evidence/freebsd-erp-44941257858/summary.json) contains the same results with the recorded observation windows.

## Interpretation

Times start at the recorded fault or repair event. The first successful reply belongs to a streak of three consecutive successes. The confirmation time is the end of that streak. When the event was absent during the measured interval, the observation window gives a lower bound. Attempts that begin in one phase and finish in another count in the phase where they started. This produces 48 ERP attempts per run in the fault table and 47 completed attempts within each native run's fault window. Latency percentiles use successful replies only, with nearest-rank p95.

The benchmark measures how routing reacts to one application outage while gateway monitoring remains healthy. With three repetitions per mode, synthetic links, a VNET guest, and a polling harness, these numbers describe this topology and schedule. They give no estimate of throughput, failover under production link loss, or the timing of the installed appliance daemon. The raw event log records 12 observer interval overruns, preserving the difference between the configured 1 s target and actual scheduling. The earlier two-run Action ended with a nonzero exit code and is excluded from the completed dataset. [Earlier attempt](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44940760216)

## Inspect or reproduce

- [All 5,280 client observations](evidence/freebsd-erp-44941257858/transactions.csv) and [timestamped gateway, observer, and PF events](evidence/freebsd-erp-44941257858/events.csv) retain the raw measurements for all six runs.
- [Run metadata and fixture topology](evidence/freebsd-erp-44941257858/metadata.json), [example WAN2 rules](evidence/freebsd-erp-44941257858/pf-02-02.txt), and [example peer fault counters](evidence/freebsd-erp-44941257858/peer-02-during-fault.txt) show the paths being compared. All 12 PF snapshots and six peer-counter captures are in the evidence directory.
- [Evidence SHA-256 checksums](evidence/freebsd-erp-44941257858/SHA256SUMS) cover the retained Actions output, including the [exit code](evidence/freebsd-erp-44941257858/exit-code), report, and CSVs. The combined transaction CSV contains the complete per-run records.
- These records were generated in the project's synthetic test fixture. Network addresses are documentation addresses from RFC 5737. The linked pfSense source and Actions dependencies retain their respective license terms. The evidence directory contains the measurements and rule output produced by the run.

To regenerate the tables offline, use the pinned [benchmark report script](https://github.com/allanlopesprado/pfsense-sdwan/blob/32435462fa3e19089da87bffa4409a6b607e804c/tests/lab/benchmark_report.py) with a copy of the evidence directory as its input. To repeat the forwarding test, use the FreeBSD guest and pinned source in the workflow above. The shell test creates and removes isolated VNET nodes and loads PF rules inside them.
