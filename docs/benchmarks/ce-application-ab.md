# Two-WAN CE application benchmark

Run **CE two-WAN appliance** with the `benchmark` scenario to build the candidate and run an A/B comparison in a disconnected QEMU topology. Each pair runs both native and SD-WAN forwarding on the same disposable system. Consecutive pairs reverse the order. The package observer runs in both modes to collect the same DNS and HTTPS measurements. Native mode has no SD-WAN rule bindings. Both modes use the same WAN preference, LAN rules, outbound NAT, native gateway monitor, skip-on-down setting, and adjacent block rules. SD-WAN also uses a 40 ms RTT, 30 ms RTT deviation, and 5% loss SLA.

The benchmark records the source port of each request. The ERP and backup clients each cycle through a separate set of 6,000 ports, leaving at least 25 minutes between uses of one port at the fastest sampling rate. Older runs left source-port selection to the operating system.

### Candidate with verified overlay boot

Two A/B pairs ran on each CE version using the same candidate package and a 30-second preferred-path recovery hold. The times below are the observed range across the two trials in each mode. The failure window for ERP was 40 seconds. The ERP-only outage left WAN1's gateway and DNS monitor reachable.

| CE | Scenario | Native | SD-WAN |
| --- | --- | --- | --- |
| 2.9.1 | ERP-only outage on WAN1 | 0/158 replies | 125/160 replies via WAN2, first in 4.549–13.002 s, successful reply latency p95 2.122 ms |
| 2.9.1 | Complete WAN1 outage | First WAN2 reply in 2.522–2.733 s, 150/160 replies | First WAN2 reply in 4.636–6.660 s, 138/160 replies |
| 2.9.1 | WAN1 returns | First WAN1 reply in 13.234–13.460 s, 260/260 replies | First WAN1 reply in 35.315–36.841 s, 260/260 replies |
| 2.9.2 | ERP-only outage on WAN1 | 0/158 replies | 109/160 replies via WAN2, first in 11.810–14.008 s, successful reply latency p95 1.490 ms |
| 2.9.2 | Complete WAN1 outage | First WAN2 reply in 2.729–2.906 s, 150/160 replies | First WAN2 reply in 3.883–5.582 s, 142/160 replies |
| 2.9.2 | WAN1 returns | First WAN1 reply in 12.645–13.462 s, 260/260 replies | First WAN1 reply in 36.291–44.585 s, 260/260 replies |

Backup delivered 160/160 replies via WAN1 during ERP-only loss in every version and mode. Both versions reported zero unexpected sources in steady phases. The artifacts contain per-request timestamps, source ports, reported NAT sources, phase statistics, and the ERP packet captures for LAN and both WANs. [CE 2.9.1 benchmark](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/45295565939) · [CE 2.9.2 benchmark](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/45295549345)

The first CE 2.9.2 run with automatic port selection recorded four connection timeouts after ERP recovery in native mode. All four LAN SYNs reused ports from previous incomplete attempts, and the captures showed no corresponding SYN on either WAN. The run remains recorded with its failing assertion. [Earlier run and packet captures](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/45291849463)

Two processes on the LAN client continuously open TCP connections, send unique request markers, and check the returned markers. The peer includes the source address it saw after NAT in every reply. The test collects PF rules, probe results, and application observations through healthy routing, preferred WAN loss, WAN restoration, an ERP-only fault, and service recovery. During the ERP-only fault, the fixture blocks ERP transactions and its associated DNS probe on WAN1. The backup service and its certificate-verified HTTPS probe remain available. The domains, certificates, addresses, and applications belong to the disconnected lab.

Each successful transaction includes the return path. The time origin for an interruption is the completion of the lab fault command. A measurement phase excludes attempts that cross its boundaries. A recovery beyond the observation window is right-censored. The report includes the count of censored runs and calculates recovery percentiles over observed events. Use more than one pair to compare repeatability. The timings measure application reply delays on fresh TCP flows within the isolated topology.

| Artifact | Contents |
| --- | --- |
| `summary.json` | Candidate digest, loss, application reply p95, individual times to a reply from the expected WAN, censored runs, source anomalies, and observer resource samples. It reports recovery p95 with at least 20 observed recoveries. |
| `phases.csv` | Per-phase raw counts, expected source, addresses seen by the peer, first successful reply, and first reply from the expected WAN. |
| `erp.ndjson` and `backup.ndjson` | Start/end timestamps, observed source, and the connection, send, or reply stage for socket errors. |
| `phases.ndjson` | Fault and recovery boundaries, loaded PF rules, and the observer snapshot at the end of each phase. |
| `activations.ndjson` | Mode change boundaries and PF confirmation. The summary reports separate per-flow errors for these windows. |
| `resources.ndjson` | Periodic worker PID, `ps` CPU percentage, and resident memory in KiB. |
| `sw-out*-erp.pcap*` | Optional bounded captures of synthetic ERP TCP on the LAN and both WANs. Use `wall_start_ns` to correlate a socket error with packets. |

### Timing the policy and filter separately

The **CE two-WAN appliance** benchmark offers four profiles. Use the same profile and recovery hold for both modes in each pair.

| Profile | What it measures |
| --- | --- |
| `legacy` | Repeats the historical control with ERP and its policy's required DNS probe interrupted on WAN1. |
| `timed` | Keeps the historical topology, traffic, and fault. Reads the recommendation, steering decision, reload receipt, and loaded PF trackers during transitions. |
| `erp-https` | Interrupts ERP traffic and its corresponding certificate-verified HTTPS check on WAN1. The required backup DNS check and WAN1 remain available. The benchmark checks that a valid observer sample detects the service fault while that DNS check passes, and that each new backup request replies through WAN1. |
| `erp-https-loaded` | Repeats the HTTPS profile with a background LAN-to-backup TCP echo workload targeting 1 MiB/s in each direction. Four more ERP outages of 3, 6, 4 and 8 seconds are interspersed with healthy periods. The summary reports the actual echoed bytes, losses, and source changes across the intermittent sequence. Short pulses measure behavior even if no policy switch occurs. |

The timed profiles record the host-monotonic interval in which the isolated loss or restoration command ran. `start_ns` is the command completion, which is also the origin for application recovery times. Each subsequent state read has its own host-monotonic interval. `timing.ndjson` includes the probe results, recommendation, steering intent, matching reload receipt, and live PF rules for ERP and backup. A stage's host bounds cover the interval from the last observed contrary state to the first matching observation. A missing lower bound means the matching state was already present on the first usable read. A missing stage means it was not observed.

The guest also records the exact monotonic clock values when its check batch completes, SLA evaluation finishes, steering is decided, and a PF readback finishes. Subtract these values only within the same guest clock. The check time includes the whole batch. PF readback and the reload acknowledgement bracket parts of the control path, while packets and replies demonstrate forwarding. Polling limits the precision of the instant when the kernel loaded a rule. During activation, native and bound rules may already point to the same next hop. The benchmark uses a confirmed receipt and matching live rules to identify the bound state.

`activations.ndjson` includes the initial binding command interval and first confirmed PF proof. `summary.json` keeps activation losses and the longest gap between successful replies within the activation window separate from stable traffic. `sessions.ndjson` records replies from ERP and backup TCP connections opened before the service fault and tested during loss and after recovery. The new-connection data stays in `erp.ndjson` and `backup.ndjson`.

Use `timed` to investigate the timings reported below on the historical fault. Use the HTTPS profiles to verify service-only failure with DNS still healthy. Timing reads add guest work, so include a same-topology `legacy` control when evaluating any timing difference. Earlier runs did not collect these intermediate timestamps. They establish end-to-end delays and packet locations but cannot apportion those delays between stages.

To run locally, use an unbooted raw disk made by the signed Netgate package lab. Copy the disk before running since the lab writes to it.

```sh
sudo /usr/bin/python3 tests/lab/ce-ab-benchmark.py ./ce292-ab.raw 2.9.2 \
  --pairs 2 --profile erp-https-loaded --capture-erp --output ./ce-ab-results
```

For a prolonged run, use a dedicated Linux runner with persistent storage and keep the isolated namespaces active. The following command intersperses WAN loss and recovery with steady application traffic, reports source anomalies outside fault windows, and samples the observer every 60 seconds. The workflow dispatch supports shorter observation windows.

```sh
sudo /usr/bin/python3 tests/lab/ce-ab-benchmark.py ./ce292-soak.raw 2.9.2 \
  --pairs 0 --soak-hours 48 --sample-seconds 60 --output ./ce-soak-results
```

Use `--fault-interval-seconds` to change the healthy interval between simulated incidents. Use `--recovery-hold-seconds` to compare preferred-path requalification settings without changing the package defaults. Both settings are also available as workflow inputs. Compare runs on the same CE version and topology with the same observation windows.

## Measured application recovery

Times are seconds from the phase start to the first reply from the expected WAN. Each test window lasts 40 seconds during loss and 65 seconds during recovery. A 40-second censored result means that the application supplied no valid reply during the loss window. Reply percentiles for individual successful transactions are recorded in the artifacts.

| CE lab | Phase | Native | SD-WAN |
| --- | --- | ---: | ---: |
| 2.9.1 | ERP on first-WAN loss | 3.06 s | 3.98 s |
| 2.9.1 | ERP return to the first WAN | 13.78 s | 44.69 s |
| 2.9.1 | ERP-only failure on first WAN | 40 s, censored | 11.91 s |
| 2.9.2 | ERP on first-WAN loss | 3.22–3.56 s | 4.01–5.72 s |
| 2.9.2 | ERP return to the first WAN | 12.95–13.29 s | 36.43–44.72 s |
| 2.9.2 | ERP-only failure on first WAN | 40 s, censored twice | 3.66–11.94 s |

The CE 2.9.1 run observed 80 ERP attempts in the service-only loss window. Native forwarding lost 80 and SD-WAN lost 23. The backup lost zero of 80 attempts in each mode. The short stable observation completed 720 transactions in 180 seconds with zero loss. The artifact contains one native/SD-WAN pair. [Raw CE 2.9.1 evidence](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/45048873467)

The CE 2.9.2 run observed two pairs with alternating order. During the service-only loss, native forwarding completed zero of 159 ERP attempts and SD-WAN completed 130 of 160. Backup completed 160 of 160 attempts on WAN1 in each mode. During return after full WAN loss, ERP completed all 260 attempts in each mode, including replies via the still-working standby while the preferred path was being qualified. The 360-second stable observation completed 1,440 transactions without a lost reply, unexpected source, or observer PID change. The resource samples showed a peak worker RSS of 63,240 KiB in both modes. [Raw CE 2.9.2 evidence](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/45048303655)

## CE 2.9.2 with a 15-second preferred-path hold

One A/B pair used a 15-second requalification hold. During the service-only failure, ERP completed 57 of 80 SD-WAN attempts and zero of 80 native attempts. Its first successful response via WAN2 arrived at 11.924 s. Backup completed 80 of 80 attempts in each mode via WAN1. Full WAN1 loss moved ERP to WAN2 in 2.998 s with SD-WAN and 3.056 s with the native group. When WAN1 returned, ERP returned to it in 34.707 s with SD-WAN and 12.792 s natively, with zero lost replies in either return window.

The continuous observation measured 1,255.6 seconds and four simulated WAN1 outages. All 3,344 transactions in the stable periods succeeded on the expected WAN, with no observer restart. ERP's response p95 was 2.266 ms and backup's was 1.778 ms in those periods. Each application lost 49 of 320 attempts in the four outage windows and completed all 520 attempts in the return windows. Management HTTPS and the reference NAT and default route checks passed after every incident.

The workflow reported a failure for two ERP timeouts in the six-second baseline immediately after SD-WAN activation. The other ten ERP attempts and all twelve backup attempts succeeded. The PF sample showed both trackers applied and the next ERP attempt succeeded after each timeout. The captured data did not identify the connection stage or root cause. The raw results retain the timeouts. [A/B and continuous observation](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/45057850498/artifacts/14768949982)

Across the three 15-second A/B pairs, service-only failure yielded 169 of 240 ERP replies with SD-WAN and zero of 239 with native forwarding. The backup completed all 479 transactions on WAN1 across both modes. The first ERP reply via WAN2 took 11.924–12.888 s. After full WAN1 loss, its first reply via WAN2 took 2.536–3.056 s natively and 2.998–4.988 s with SD-WAN. Return to WAN1 took 12.792–13.787 s natively and 25.178–34.707 s with SD-WAN.

The instrumented A/B-only run passed. The other repeat completed the baseline without timeouts, then recorded two ERP timeouts in the return window, around 26 seconds after ERP had already returned to WAN1. Its separate six-minute continuous observation completed the single planned outage and all 1,014 stable-period transactions. All four unexpected timeouts across the two failing runs occurred near 590 seconds of host uptime. The available evidence does not establish causation. [Repeated A/B and continuous observation](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/45061393300) · [Socket-instrumented A/B](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/45061580413)

Two separate 648-second controls then kept WAN1 healthy and captured ERP TCP on the LAN and both WANs. Each control completed all 2,592 measured requests. Each also included eight ERP and eight backup attempts inside the original 587–591 s host-uptime window, with zero losses. ERP response p95 was 2.343 ms in the native control and 1.737 ms in the SD-WAN control. These lab measurements bound the observed behavior and leave the earlier intermittent failures unresolved.

Before the measured interval, while activating the SD-WAN bindings, each client recorded 19 connection timeouts over approximately 9.4 seconds. The ERP capture shows the 19 SYN packets at the LAN and none on either WAN during that interval. The native control recorded no connection timeout before its measurement. Keep activation traffic and stable forwarding separate when assessing availability. [Native control and captures](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/45063455624) · [SD-WAN control and captures](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/45063455711)

With the dedicated activation window, an isolated CE 2.9.2 run recorded 20.55 seconds from the bind command to PF confirmation, with 18 connection timeouts and 23 successful attempts per application during that interval. The gap between successful replies was 9.50 seconds on each flow. Captures showed 18 ERP SYN packets on LAN and zero on either WAN during the timeout burst. The following stable phase completed all 360 requests on the expected path. Activation metrics are reported separately from the existing steady forwarding criteria. [Activation benchmark and raw captures](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/45068794234)
