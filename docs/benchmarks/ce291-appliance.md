# Policy forwarding on a pfSense CE 2.9.1 appliance

The two runs assembled an isolated QEMU appliance from signed Netgate packages and exercised the native pfSense filter queue, kernel PF, package hooks and the SD-WAN adapter. The source builds carried the package version `0.4.28` and policy-specific probes. Their SHA-256 values differ from the public package. The scenarios used an 80 ms RTT limit, a 5% loss limit, WAN1 and WAN2 costs of 10 and 20, and zero configured recovery delay. These are acceptance checkpoints with observed replies, rules and state IDs. The source logs have no elapsed failover timings.

| Run | Source | Lab package SHA-256 | Raw evidence |
| --- | --- | --- | --- |
| 44754290652 | `a5a2d16258f2a6ca6911be73f595fe340aed9f1d` | `537ef4f726decb642691dc7a66556fed3d2111ced952e6abe39ab417cf1424d4` | [Results](evidence/ce291-appliance/ce291-result.log) · [Actions](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44754290652) |
| 44836162263 attempt 2 | `adcf677441cf15527b68c87edd75c534aa4bee99` | `4341d965a5de91a24d5940ae5ad1555e48c8eaec523cfef0232341e4da67abde` | [Results](evidence/ce291-appliance-adcf677/ce291-result.log) · [Provenance and digests](evidence/ce291-appliance-adcf677/provenance.json) · [Actions](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44836162263/attempts/2) |

| Checkpoint in attempt 2 | Observed result |
| --- | --- |
| Selective ERP loss on WAN1 | ERP tracker `41001` moved from WAN1 `198.51.100.2` to WAN2 `203.0.113.2`. A new ERP connection returned the WAN2 NAT source `203.0.113.1`. Backup tracker `41003` and the backup reply stayed on WAN1 with NAT source `198.51.100.1`. WAN1 DNS replied during the fault. Four established PF state IDs and their creator IDs were preserved. |
| Same target by both WANs | Target `192.0.2.168` returned twice, through two FIBs, reporting sources `198.51.100.1` and `203.0.113.1`. |
| Reload accepted with a divergent PF rule | The observer detected the divergence, retained the retry budget across worker restart, and reached the configured limit of three attempts. Repairing the renderer let PF confirm the requested path. LAN HTTPS kept returning the original certificate. |
| Expired measurement | Both scoped connections were blocked with the old observation and both recovered after a fresh observation. The condition was recorded in System Logs. LAN HTTPS remained reachable. |
| DHCP address and next hop changed | The WAN2 lease moved from `203.0.113.1` to `203.0.113.4`, and next hop from `203.0.113.2` to `203.0.113.3`. The new ERP reply reported source `203.0.113.4`, the PF tracker used next hop `203.0.113.3`, and backup stayed on WAN1. |
| Both WANs unavailable and restored | PF installed explicit blocks on 2/2 tested rules. Neither of the two new connections replied. After recovery, both new paths and the two original TCP sockets replied. LAN HTTPS remained available during the outage. |
| VTI without a security association | The protected connection was blocked and no protected cleartext was observed. |
| Package lifecycle | Install executed native hooks and stock CE entered observation mode. Upgrade preserved policy configuration. Reboot, adapter rollback and package rollback restored the two expected reply paths. |

The first result log has SHA-256 `2892d22d694e4d4c98c1721c3a277b73f1232fe18f93adfe024d97189916a4de`. The second log has SHA-256 `c2ea882acca6e6cc0b593599c73f394a3195701cd2c8c7f3e6821519cd5a3dea`. The [build manifest for the earlier run](https://github.com/allanlopesprado/pfsense-sdwan/blob/a5a2d16258f2a6ca6911be73f595fe340aed9f1d/dist/pfSense-pkg-SDWAN-0.4.28.pkg.sha256) and [the revised build manifest](https://github.com/allanlopesprado/pfsense-sdwan/blob/adcf677441cf15527b68c87edd75c534aa4bee99/dist/pfSense-pkg-SDWAN-0.4.28.pkg.sha256) pin the respective binaries. The [FreeBSD A/B report](freebsd-erp.md) measures recovery and per-request latency. The [CE 2.9.2 interface report](ce292-interface-original.md) uses the released package.
