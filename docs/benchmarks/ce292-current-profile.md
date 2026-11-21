# Two-WAN interruption with the 40 ms / 30 ms / 5% profile

This experiment used the released SD-WAN 0.4.28 and the matching ABI 2 adapter on an isolated `2.9.2-RELEASE` appliance assembled from signed Netgate packages. The QEMU guest used synthetic WAN gateways on `em0` and `em2`. The LAN rule under test was scoped to TCP port 18080 and tracker `771292101`, with an adjacent scoped block rule (`771292102`).

Both modes preferred WAN2 for the LAN rule. The native control used a gateway group with WAN2 in Tier 1, WAN1 in Tier 2 and the Member Down trigger. It had the binding removed and the observer stopped. In SD-WAN mode the same native rule was bound, with WAN2 at cost 1, WAN1 at cost 2, and limits of 40 ms mean RTT, 30 ms RTT standard deviation and 5% loss. A separate default gateway group preferred WAN1 for the firewall. This setup matches the healthy egress in both controls while leaving the firewall default independent of the rule. The dpinger command used a 500 ms interval, 2,000 ms loss interval and 60,000 ms averaging window. The two measured endpoints were the link gateways. The phase run had no configured application probe.

Each phase measures from when the interface command completed. The first PF reading is when the expected kernel rule was first seen. The confirmation time is when the third consecutive poll had the expected PF path and both expected ICMP outcomes. A poll counts when all three observations have completed. A receipt is checked against the observer's current forwarding signature. Polls sample the transition about once per second when commands return quickly. Command execution, probe timeouts and guest scheduling increase that interval. The pings originate from the firewall's WAN addresses. Application continuity and remote NAT source have their own [FreeBSD client benchmark](freebsd-erp.md) and [CE 2.9.1 peer log](evidence/ce291-appliance/ce291-result.log).

## Results

| Phase and expected loaded rule | Native first PF / third combined poll | SD-WAN first PF / third combined poll |
| --- | ---: | ---: |
| Baseline already on WAN2 | 0.460 / 2.325 s | 0.369 / 3.951 s |
| WAN1 down, remain on WAN2 | 0.381 / 5.905 s | 0.332 / 6.148 s |
| WAN1 restored, remain on WAN2 | 1.019 / 4.957 s | 0.492 / 17.937 s |
| Preferred WAN2 down, switch to WAN1 | 26.534 / 31.949 s | 16.665 / 23.455 s |
| Both WANs down, block | Censored at 101.227 s (50 polls) | 25.147 / 32.222 s |
| Only WAN1 restored, forward through WAN1 | 41.990 / 47.375 s | 45.462 / 53.389 s |
| WAN2 restored, return to preferred WAN2 | 56.296 / 58.352 s | 103.619 / 108.179 s |

During the preferred WAN2 outage, the SD-WAN group selected WAN1 as its forwarding target at 16.242 s. PF first showed WAN1 at 16.665 s and the matching receipt confirmed it at 23.658 s. Native PF first showed WAN1 at 26.534 s. The first PF observation was 9.869 s earlier with SD-WAN, a 37.2% reduction in this single pair. The third combined PF and ICMP observation was 8.494 s earlier, a 26.6% reduction.

During the two-WAN outage, native PF retained `route-to` on a WAN interface in all 50 polls over 101.227 s. Both WAN gateways had stopped responding. In SD-WAN mode the observer reported no eligible gateway at 18.782 s, PF showed an explicit scoped block at 25.147 s, and the receipt confirmed it at 28.287 s. The third combined PF and ICMP confirmation arrived at 32.222 s. The native control had **Do not create rules when gateway is down** disabled. A native deployment can use that option with its own adjacent block rule. [Netgate policy-routing configuration](https://docs.netgate.com/pfsense/en/latest/multiwan/policy-route.html#enforcing-gateway-use)

Restoring only WAN1 took 3.472 s longer to first PF with SD-WAN. When WAN2 returned, it was first eligible at 66.963 s. It became the group forwarding target at 97.333 s, after 30.370 s, and PF confirmed it with a matching receipt at 109.589 s. The first loaded rule sent traffic back to WAN2 47.323 s later than native, an 84.1% increase in this pair. The 30 s hold kept the still-eligible WAN1 in use while WAN2 recovered. In the CSV, `first_recommendation_ms` records the group's forwarding target from `steering.gateway`. The policy's earlier recommendation is distinct. [Guest log excerpt](evidence/ce292-current-profile/guest-final-checks.txt)

When the nonpreferred WAN1 was restored, the native pass tracker was absent in 1/20 polls after initial confirmation. The SD-WAN rule remained on WAN2 in 4/4 polls. Gateway success counts, RTT percentiles and sampling windows are available in the CSVs. The two modes ran sequentially with one iteration each. The timings describe the running appliance's loaded rule and gateway reachability. The native trial finished its seven phases before an inspection helper error in the post-trial metadata read. The SD-WAN trial resumed on the same boot and saved configuration with a guard for snapshots that lacked a steering decision. The comparison keeps the original phase observations and the resumed SD-WAN observations.

## Inspect or reproduce

- [All 850 events](evidence/ce292-current-profile/events.jsonl), [272 PF polls](evidence/ce292-current-profile/pf.csv), [544 gateway ICMP attempts](evidence/ce292-current-profile/ping.csv), [gateway loss and RTT statistics](evidence/ce292-current-profile/ping-summary.csv), and [all 14 phase outcomes](evidence/ce292-current-profile/phases.csv).
- [Harness and resumed collectors](evidence/ce292-current-profile/harness/) and [evidence SHA-256 digests](evidence/ce292-current-profile/SHA256SUMS). The harness requires the named isolated QEMU guest, the [synthetic topology](evidence/ce292-interface-original/native-scenario.php) and the released package with the matching adapter.

Regenerate the CSVs from the raw events with Python 3.

```sh
d=docs/benchmarks/evidence/ce292-current-profile
python3 "$d/summarize.py" "$d/events.jsonl" /tmp/sdwan-ce292-current-profile
```
