# Interface interruption on pfSense CE 2.9.2

This pair of trials used the released SD-WAN 0.4.28 package and ABI 2 adapter on an isolated QEMU appliance running pfSense CE 2.9.2-RELEASE. The signed Netgate package set provided the appliance software. WAN1 and WAN2 used QEMU user networks with synthetic addresses and no access to production. The package SHA-256 was `c23dfbc1f1484469e9831a5099402c93a5a22d4bd9c0f339ab42d6a074398fe5`. [Pinned release index](https://github.com/allanlopesprado/pfsense-sdwan/blob/v0.4.28/dist/release.json)

The native gateway group used WAN1 in Tier 1 and WAN2 in Tier 2, with Member Down as its trigger. SD-WAN also preferred WAN1, with costs 10 and 20, an RTT limit of 250 ms, and loss of at most 25%. No RTT standard-deviation limit was set. The same scoped LAN rule and its adjacent block rule were present in both modes. Native mode had the binding removed and the observer stopped. SD-WAN mode restored the binding and started the observer. There was one trial in each mode, in that order.

The fault was `ifconfig down` on the virtual interface. The measurements are from the end of that command to the first matching PF observation and the third consecutive matching observation. Polls were about one second apart plus command delays. The ICMP checks originated on the firewall and were pinned to the respective WAN gateway by source address. The separately linked [ERP TCP benchmark](freebsd-erp.md) measures application traffic from a LAN client.

| Phase | Native first / third PF observation | SD-WAN first / third PF observation |
| --- | ---: | ---: |
| WAN1 down, expect WAN2 | 21.748 / 25.510 s | 20.798 / 24.496 s |
| Both down, expect block | Not observed in 13.667 s (7 polls) | Not observed in 13.988 s (7 polls) |
| WAN2 up, WAN1 still down | 0.430 / 4.896 s | 0.604 / 6.069 s |
| WAN1 up, expect preferred WAN1 | 51.333 / 53.357 s | 61.424 / 63.487 s |

During the WAN1 outage the first PF observation of WAN2 was 0.950 s earlier with SD-WAN. During WAN1 recovery the first PF observation of WAN1 was 10.091 s later with SD-WAN. These are differences between two trials at the resolution of this collector. When WAN2 was restored, the first poll already showed WAN2 in both modes. After the first three consecutive observations, the path deviated in 16 subsequent native samples and 8 subsequent SD-WAN samples before finishing on WAN2. The first poll and third consecutive observation therefore measure observations, not the time of a permanent transition.

The two unavailable gateways returned zero of seven ICMP checks each in both modes. In a separate, longer CE exercise the kernel installed an explicit `block drop` for tracker `771292101` when neither WAN was usable. With WAN1 unavailable for an extended window PF installed `route-to (em2 198.18.20.2)` on the same tracker. The [acceptance log](evidence/ce292-interface-original/qemu-ce292-acceptance.txt) also records native install and filter reload, unbinding, and an XML restore followed by reboot. The SHA-256 of the test scope matched after restore.

## Data and reproduction

- [All gateway ping and PF aggregates, including the median, p95 and maximum RTT](evidence/ce292-interface-original/native-wan-summary.md)
- [Every timestamped sample and PF rule](evidence/ce292-interface-original/native-wan-raw.log)
- [PF observations and window boundaries by path](evidence/ce292-interface-original/native-wan-pf.csv) and [ICMP counts and times by gateway and phase](evidence/ce292-interface-original/native-wan-ping.csv)
- [CE scenario](evidence/ce292-interface-original/native-scenario.php), [installation and rollback actions](evidence/ce292-interface-original/native-cycle.sh) and [measurement harness](evidence/ce292-interface-original/measure-native-wan.py)

The harness requires the named isolated CE lab disk and expected interfaces. The raw measurement log SHA-256 is `409439961d826591239092fc369c2ba2a7b4a463bd5749e42217bf5b88094138`. Recompute the CSV and Markdown files from the repository root.

```sh
d=docs/benchmarks/evidence/ce292-interface-original
python3 "$d/report-native-wan.py" --require-complete "$d/native-wan-raw.log" /tmp/sdwan-ce292-interface
```
