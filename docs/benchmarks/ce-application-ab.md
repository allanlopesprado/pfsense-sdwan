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
