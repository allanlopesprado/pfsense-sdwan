# Compatibility with other pfSense packages

On standard pfSense CE, this SD-WAN package reads dpinger statistics and displays a policy recommendation. The existing pfSense firewall rules, gateway groups, NAT, and routing continue to handle traffic. Experimental steering applies only to explicitly bound rules on a compatible native integration. An **Online** gateway has a working monitor path. An application on that gateway can still be blocked by an IPS, PF, or DNS policy. If a blocking rule also affects the monitor address, check the monitor route and the corresponding inspection or firewall event. [Gateway status](https://docs.netgate.com/pfsense/en/latest/monitoring/status/gateways.html) · [Experimental forwarding](INTEGRATION.md)

## IDS and IPS

| Mode | Coexistence with SD-WAN |
| --- | --- |
| **Snort or Suricata in alert-only mode** | A match generates an alert while ordinary firewall and routing decisions still apply. Inspect the LAN or the interfaces that carry the traffic of interest. Compare an application transaction with the gateway probe. [Snort interface settings](https://docs.netgate.com/pfsense/en/latest/packages/snort/interface-settings.html) |
| **Legacy offender blocking** | A package can add offenders to PF. pfSense puts the native `snort2c` quick blocks before user rules in both directions, so the table can still block a new connection after a gateway change. With Snort, **Kill States** also terminates matching existing states. Check state handling separately from new connections. [pfSense filter source](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/filter.inc#L4707-L4712) · [Snort interface settings](https://docs.netgate.com/pfsense/en/latest/packages/snort/interface-settings.html) |
| **Suricata inline IPS** | Apply equivalent inspection to all eligible paths or inspect on a common interface that carries the traffic in scope. Confirm behavior on the installed NIC driver and package version. The pfSense Suricata port configures inline inspection through netmap and can select the parent interface for a VLAN. Include the actual VLAN parent, VirtIO or physical NIC, and any LAGG in acceptance testing. [pfSense Suricata configuration source](https://github.com/pfsense/FreeBSD-ports/blob/devel/security/pfSense-pkg-suricata/files/usr/local/pkg/suricata/suricata_generate_yaml.php#L1249-L1295) · [Netgate hardware sizing](https://docs.netgate.com/pfsense/en/latest/hardware/size.html) |
| **Traffic inside a VPN** | Inspect a point where the protected application traffic is visible, such as the internal LAN carrying it. An encrypted WAN capture can identify the outer VPN flow. Confirm each path and traffic direction with the tunnel up and again after renegotiation. [pfSense IPsec packet filtering](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/firewall-rules.html) |

## Other common packages

| Package | What to verify after a WAN change |
| --- | --- |
| **pfBlockerNG** | Check PF blocks using new connections on both paths. Check DNSBL using the actual client resolver separately. Gateway health can remain online while a destination or domain is blocked. [pfBlockerNG](https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html) |
| **HAProxy** | Check that the frontend accepts requests and that backends answer. Test the backend connection separately, since a proxy on the firewall opens its own connections. [Multi-WAN troubleshooting](https://docs.netgate.com/pfsense/en/latest/troubleshooting/multi-wan.html) |
| **FRR and WireGuard** | Compare the routes installed by the routing daemon with the desired egress, then test both directions of the tunnel. For traffic that depends on the routing table, check the route selected during a link failure and after recovery. [WireGuard routing](https://docs.netgate.com/pfsense/en/latest/vpn/wireguard/routing.html) |
| **OpenVPN Client Export** | Verify that the generated profile lists the intended endpoints. The Multi-WAN export options derive endpoints from the configured port forwards and, for DDNS, the matching hostnames. Confirm that a client can reconnect to the backup endpoint and carry tunnel traffic. [OpenVPN Client Export](https://docs.netgate.com/pfsense/en/latest/packages/openvpn-client-export.html) |
| **System Patches** | Review applied patches that change the filter generator, gateway monitoring, or routing. Rerun the relevant tests with those patches installed on a clone. [System Patches](https://docs.netgate.com/pfsense/en/latest/development/system-patches.html) |

## Native settings that can change the observed path

| Setting | What to verify |
| --- | --- |
| Floating quick rules, interface groups and package block tables | Rules that match earlier determine the outcome. Compare a permitted new connection and a denied one with PF rule counters, state, and the reply path. |
| Traffic shaper, limiters and logging | The binding must preserve the logged match and the native queue or pipe qualifiers. Verify the loaded tracker, then confirm throughput and queue counters separately with the actual limiter configuration. |
| Sticky connections | An updated lab adapter preserves source affinity for a weighted pool when the native setting is enabled. Use new connections from the same LAN source and compare the translated address observed by the peer. |
| DHCP, PPPoE and IPv6 transition interfaces | Recheck the current device and next hop after renewal, plus the selected source address and NAT. The configured interface name may differ from the device that PF uses. |
| CARP, IP aliases and routed IPsec | Check the underlay of each VTI. Paths on the same physical transport share its failure domain even when they use distinct VIPs. Full tunnel, HA and state migration require an isolated test with the actual peer and addresses. |

A rule reported as applied has the expected forwarding path in PF. Use counters and a bidirectional application transaction to check that an earlier rule or packet inspector allows a representative flow. Include the actual package versions and interface drivers in the test record.

## Verification

- The [Suricata lab](../tests/lab/inspection.py) exercises real Suricata in passive PCAP mode and inline Linux NFQUEUE mode across two paths. It compares the SD-WAN policy evaluator against live ICMP probes and checks application responses, EVE alert and drop events, and the path used by ordinary and blocked requests. It also checks what happens to queued HTTP traffic when the inspector stops. The lab applies the evaluator's recommendation to Linux routes.
- The [FreeBSD netmap lab](../tests/lab/freebsd-netmap.sh) exercises Suricata's host-stack copy path on an isolated epair. It checks HTTP delivery, EVE block events, ICMP, and recovery when the inspector stops. [Native FreeBSD job](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44587248657/job/135783422131)
- The [CE netmap lab](../tests/lab/ce-sdwan-inspection.py) runs the Netgate Suricata 8.0.7 engine directly on two VirtIO WANs. It verifies EVE blocks, remote captures, the applied PF rules, and selective failover while inspection is active. [CE results](RESULTS.md#two-wan-service-checks-and-pf-verification-in-the-0429-candidate)
- The [FreeBSD PF lab](../tests/lab/freebsd-dataplane.sh) checks that the native-style offender table keeps blocking a new TCP connection after the gateway changes on an explicitly bound PF rule. It verifies a control flow and confirms that removing the test offender restores access.
- Acceptance on a pfSense CE clone requires the installed Snort or Suricata package and the same interfaces and drivers as production. Check a harmless local signature in alert and block modes, exercise each WAN under load, and test failover, recovery, and IPS restart while comparing gateway probes, application responses, PF states, and inspector drop counters. With HA, verify coverage on both nodes after a role change. [Lab procedure](LAB.md) · [GitHub Actions](https://github.com/allanlopesprado/pfsense-sdwan/actions/workflows/checks.yml)
