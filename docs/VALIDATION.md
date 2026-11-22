# SD-WAN validation on pfSense

The appliance targets are pfSense CE 2.9.1 and 2.9.2. The package uses native gateways, dpinger, privileges, forms, services, and System Logs. On a compatible lab core, the recommendation applies to explicitly bound rule trackers. Comparable products inform the test scenarios. Cross-vendor acceptance requires exercising the same flow on both devices. [Integration and package limits](INTEGRATION.md)

## Recurring regression and divergence audit

**Package checks** runs daily at 05:23 UTC on the default branch. It can also run from **Actions → Package checks → Run workflow**. The workflow runs the existing FreeBSD/PF and interoperability checks and a separate offline audit of forwarding, policy decisions, transitions, and service lifecycle. The scheduled jobs use GitHub-hosted runners and synthetic test environments. [Workflow and recent runs](https://github.com/allanlopesprado/pfsense-sdwan/actions/workflows/checks.yml)

The run summary and the `sdwan-divergence-audit` artifact record the revision, seed, expected values, and observed values. An unexpected mismatch fails the audit. A previously reproduced discrepancy remains visible as a warning while it matches its recorded outcome. When its expected behavior starts passing, the audit reports it as resolved. GitHub can disable scheduled runs in public repositories after 60 days of inactivity. [GitHub schedule behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)

An unexpected result also starts a second pass with a different seed. The artifact retains both reports and the job retains the original failure. When an audit exposes a discrepancy, preserve a minimal reproduction and the nearest controls that delimit the failure. The follow-up checks cover a refused or accepted reload during binding removal, fresh and expired snapshots, rendering when the observer is unavailable, and resolved addresses and next hops during DHCP changes. The fixtures run with synthetic observations and rule text. The FreeBSD and appliance logs provide the separate evidence for real PF and packet delivery. [Appliance and FreeBSD measurements](benchmarks/README.md)

Reproduce an offline run with PHP CLI and Python 3. Use its run ID as the seed.

```sh
python3 tests/audit/run.py --seed 44955564168 --output ./audit-results
```

## Vendor references and test implications

| Official reference | Documented behavior | pfSense verification |
|---|---|---|
| [Netgate Gateway Groups](https://docs.netgate.com/pfsense/en/latest/routing/gateway-groups.html) and [Gateway Settings](https://docs.netgate.com/pfsense/en/latest/routing/gateway-configure.html) | Tiers, triggers, monitoring actions, and state policy. Each gateway needs a distinct Monitor IP. | Reject monitor collisions, including outside the group. Check selection by tracker and the tier in the PF rule. |
| [Netgate Policy Routing](https://docs.netgate.com/pfsense/en/latest/multiwan/policy-route.html) and [VTI](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/routed-vti.html) | Rule order governs forwarding. An assigned VTI can provide a native gateway. | Block the bound flow when all paths fail, keep a control flow working, and measure ESP at both ends. |
| [OPNsense Gateway groups](https://docs.opnsense.org/manual/multiwan.html) | Priority, loss, latency, and return to the preferred path after recovery. | Exercise A, fail A, lose all paths, recover B, then recover A. |
| [FortiOS Link health monitor](https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/580649/link-health-monitor) and [Passive health-check](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/379794/passive-health-check-measurement-by-internet-service-and-application) | Active checks and passive per-application or per-service measurements in supported configurations. | Record each probe target and run a real transaction. An ICMP probe covers the route to its target. |
| [PAN-OS Path Quality](https://docs.paloaltonetworks.com/sd-wan/administration/enable-sd-wan-without-auto-vpn/manage-sd-wan-link-failovers/define-your-custom-sd-wan-application-thresholds) | Threshold-based path qualification and distribution-profile selection. | Test inclusive limits, missing samples, and tie-breaks. |
| [Cisco Secure Firewall PBR Path Monitoring](https://secure.cisco.com/secure-firewall/v7.3/docs/policy-based-routing-with-path-monitoring) | Monitored egress selection by policy. | Verify IPv4 and IPv6 policies in PF while the default route remains native. |
| [Cisco Catalyst SD-WAN Application-Aware Routing](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/policies/ios-xe-17/policies-book-xe/m-enhanced-application-aware-routing.html) | Path probes, including BFD, supply SLA metrics. | Record the sample interval and window. Time loss, decision, and first application reply separately. |
| [Cisco Meraki MX Flow Preferences](https://documentation.meraki.com/SASE_and_SD-WAN/MX/Design_and_Configure/Configuration_Guides/Firewall_and_Traffic_Shaping/MX_Load_Balancing_and_Flow_Preferences) | Performance classes and path preference in AutoVPN. | Verify the VTI between peers using protected traffic and measure return. AutoVPN preferences have their own scope. |
| [Sophos Firewall SD-WAN profiles](https://docs.sophos.com/nsg/sophos-firewall/21.5/Help/en-us/webhelp/onlinehelp/AdministratorHelp/Routing/SDWANRoutes/SDWANProfiles/RoutingSDWANProfileAdd/index.html) | First available, SLA, and load-balancing methods. Custom SLA scenarios document a return to availability-based strategy. | Test a policy with no eligible path. The package's protected binding produces a block in the tested scenario. |
| [WatchGuard Firebox SD-WAN](https://www.watchguard.com/help/docs/help-center/en-us/Content/en-US/Fireware/sd-wan/sd_wan_routing_about.html) | Link Monitor ping, TCP, or DNS probes and policy actions. | Compare dpinger with TCP delivery and distinguish probe failures from application failures. |
| [Check Point Quantum Steering Behavior](https://sc1.checkpoint.com/documents/Infinity_Portal/WebAdminGuides/EN/Quantum-SD-WAN-Admin-Guide/Content/Topics-SD-WAN/Configuration-Steering.htm) | Path quality thresholds, priorities, and switching margins in compatible strategies. | Confirm that the current path holds during oscillations and is dropped when it becomes ineligible. |
| [SonicWall SonicOS SD-WAN](https://www.sonicwall.com/techdocs/pdf/sonicos-8-0-sdwan.pdf) | SLA classes, probes, and selection profiles inform rules. | Match each sample to the correct interface, address family, source, and target. |
| [Juniper SRX IP Monitoring](https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/example/ip-monitoring-security-configuring.html) | RPM and route actions respond to path reachability. | Verify recovery while preserving the native default route during policy switches. |
| [VyOS WAN load balancing](https://docs.vyos.io/en/rolling/configuration/loadbalancing/wan.html) | Failure tests and return-path persistence. | Verify new-session selection and existing-session continuity independently, including return traffic. |
| [MikroTik RouterOS Failover](https://help.mikrotik.com/docs/spaces/ROS/pages/26476608/Failover%2BWAN%2BBackup) | Recursive routes can probe a target beyond the next hop. | Confirm in the lab that the target represents the intended link before attributing loss to the WAN. |

**RTTsd** displays RTT standard deviation as measured by dpinger. Package SLAs use mean RTT and loss. Compare metrics and measurement windows before reusing thresholds from products that calculate jitter differently or use application probes. [Gateway Status](https://docs.netgate.com/pfsense/en/latest/monitoring/status/gateways.html) · [dpinger format](https://github.com/dennypage/dpinger/blob/master/README.md)

## Impact matrix

The [native settings matrix](CONFIGURATIONS.md) lists WebGUI controls, expected effects, and available evidence.

| Area | Automated verification and limits |
|---|---|
| IPv4 and IPv6 WAN | The observer reads three real dpinger processes through all eight total-loss combinations. Concurrent one-, two-, and three-link policies verify eligibility and recovery. A single link supports observation. The native generator and the VM's PF exercise two- and three-link forwarding. IPv6 includes a link-local next hop. |
| NAT and inbound connections | The peer checks each WAN's translated address and session continuity during a rule change. Port forwarding on B and C verifies replies through the ingress WAN while the default route is A. The lab uses interface-based outbound NAT. Hybrid, manual, 1:1, and reflection NAT, NAT64, and CGNAT require their own topologies. [NAT and Multi-WAN](https://docs.netgate.com/pfsense/en/latest/multiwan/nat.html) |
| IPsec VTI and IKEv2 | The generator checks IPv4 and IPv6 VTI groups with two and three links across all availability combinations. The FreeBSD VM checks ESP and absence of cleartext after removal of a manual SA. Actions negotiates, rekeys, removes, and restores IKEv2 over one, two, and three paths with strongSwan. The full CE sequence with path selection, VTI, and IKEv2 requires a real peer. |
| Policy-based VPN, OpenVPN, WireGuard, GRE, and GIF | The generator compares VPN service rules with the original. Ubuntu verifies OpenVPN and WireGuard transfers in both directions, plus a DNS lookup from the VPN node over the same selected underlay. The backup path has a 1280-byte MTU and the tunnel interfaces use 1200 bytes. The lab selects the WAN and captures both outside paths. Native CE integration and GRE/GIF traffic tests require clones. [VPN rules](https://docs.netgate.com/pfsense/en/latest/vpn/firewall-rules.html) |
| Interfaces and dependencies | Preflight checks VLAN, QinQ, LAGG, bridge, and PPPoE dependencies. The lab renews DHCP and starts a second PPPoE session, changing address and next hop. The package rejects the previous monitor metadata. IPv6-PD verifies RA renumbering and client delivery. Native integration needs a test with dpinger and CE services. |
| Independent services and rules | The generator compares DNS, limiter, state, WAN, and VPN rules with the original. The VM preserves the default route and verifies traffic outside the policy during loss of all paths. Put explicit local, static-route, and VPN exceptions before broad WAN bindings. [Rule order and routing exceptions](https://docs.netgate.com/pfsense/en/latest/multiwan/policy-route.html) |
| Dynamically configured services | Test dynamic FRR, Captive Portal, proxies, IDS/IPS, HA XMLRPC, DNS Resolver and Forwarder, DHCP, RA, and firewall-originated services with each active. Include restart, partial loss, address change, MTU and MSS, VPN over NAT, ingress rules, and application session recovery. [Local services and Multi-WAN](https://docs.netgate.com/pfsense/en/latest/multiwan/considerations.html) |

## Required evidence

| Scenario | Evidence |
|---|---|
| Native telemetry and policies | The VM runs dpinger on two VNET links. The daemon reads sockets and publishes decisions after selective loss and recovery. The lab controls topology and observer configuration. |
| WebGUI, privileges, and logs | Chromium exercises forms and log filtering. Tests cover delegated roles, CSRF, and missing or restored data. Appliance checks include all seven tabs, the widget, Diagnostics, Updates, and System Logs. |
| IPv4 and IPv6 forwarding | The reference generator produces the rules that PF loads in the VM. The collector verifies TCP delivery, return, IPv4 NAT, IPv6 link-local next hop, a block without paths, and the control flow. |
| Reload and release lifecycle | Test reload rejection, timeout and retry, installation, corrupted archives, upgrades, and rollback. Check installed integrity and compare PF, NAT, and default route. |
| IPsec | Verify ESP, absence of protected cleartext after SA removal, and IKEv2 rekey with strongSwan. |
| CARP and pfsync | The VM verifies both VIPs moving, the same NAT address, TCP state synchronization, and another transaction on the original connection after failover and failback. The pfsync-disabled control verifies reconnection is required. |
| End-to-end acceptance | Use two CE 2.9.1 nodes, two WANs, and a versioned IPsec peer. Track VIP ownership, state synchronization, SA negotiation, return path, and first successful application transaction during the same failure. [Netgate HA and IPsec](https://docs.netgate.com/pfsense/en/latest/highavailability/ipsec.html) · [State synchronization](https://docs.netgate.com/pfsense/en/latest/highavailability/pfsync.html) |

Record the operating system, generator revision, and test steps. Queue acknowledgement confirms receipt. Check loaded rules and a new application session to verify the data plane. [Lab procedure](LAB.md) · [Recorded results](RESULTS.md)
