# Two-WAN CE application benchmark

Run **CE two-WAN appliance** with the `benchmark` scenario to build the candidate and run an A/B comparison in a disconnected QEMU topology. Each pair runs both native and SD-WAN forwarding on the same disposable system. Consecutive pairs reverse the order. The package observer runs in both modes to collect the same DNS and HTTPS measurements. Native mode has no SD-WAN rule bindings. Both modes use the same WAN preference, LAN rules, outbound NAT, native gateway monitor, skip-on-down setting, and adjacent block rules. SD-WAN also uses a 40 ms RTT, 30 ms RTT deviation, and 5% loss SLA.

Two processes on the LAN client continuously open TCP connections, send unique request markers, and check the returned markers. The peer includes the source address it saw after NAT in every reply. The test collects PF rules, probe results, and application observations through healthy routing, preferred WAN loss, WAN restoration, an ERP-only fault, and service recovery. During the ERP-only fault, the fixture blocks ERP transactions and its associated DNS probe on WAN1. The backup service and its certificate-verified HTTPS probe remain available. The domains, certificates, addresses, and applications belong to the disconnected lab.

Each successful transaction includes the return path. The time origin for an interruption is the completion of the lab fault command. A measurement phase excludes attempts that cross its boundaries. A recovery beyond the observation window is right-censored. The report includes the count of censored runs and calculates recovery percentiles over observed events. Use more than one pair to compare repeatability. The timings measure application reply delays on fresh TCP flows within the isolated topology.

| Artifact | Contents |
| --- | --- |
| `summary.json` | Candidate digest, loss, application reply p95, time to first reply from the expected WAN p95, censored runs, steady-state source anomalies, and observer resource samples. |
| `phases.csv` | Per-phase raw counts, expected source, addresses seen by the peer, first successful reply, and first reply from the expected WAN. |
| `erp.ndjson` and `backup.ndjson` | Start/end timestamps, errors, and observed source for each application attempt. |
| `phases.ndjson` | Fault and recovery boundaries, loaded PF rules, and the observer snapshot at the end of each phase. |
| `resources.ndjson` | Periodic worker PID, `ps` CPU percentage, and resident memory in KiB. |

To run locally, use an unbooted raw disk made by the signed Netgate package lab. Copy the disk before running since the lab writes to it.

```sh
sudo /usr/bin/python3 tests/lab/ce-ab-benchmark.py ./ce292-ab.raw 2.9.2 \
  --pairs 2 --output ./ce-ab-results
```

For a prolonged run, use a dedicated Linux runner with persistent storage and keep the isolated namespaces active. The following command intersperses WAN loss and recovery with steady application traffic, reports source anomalies outside fault windows, and samples the observer every 60 seconds. The workflow dispatch supports shorter observation windows.

```sh
sudo /usr/bin/python3 tests/lab/ce-ab-benchmark.py ./ce292-soak.raw 2.9.2 \
  --pairs 0 --soak-hours 48 --sample-seconds 60 --output ./ce-soak-results
```

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
