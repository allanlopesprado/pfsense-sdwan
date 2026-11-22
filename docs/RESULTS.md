# SD-WAN lab results

[A/B benchmarks with counts, timings and raw data](benchmarks/README.md)

## Read this evidence by environment

The current release notes link to the exact GitHub Actions run. PHP and native filter compilation tests verify decisions, rule generation and UI diagnostics. The FreeBSD VM loads the generated rules into PF and checks new flows, return traffic, NAT, existing states and supported failure cases. Separate labs cover VPN and inspection implementations. A passing CI run does not certify every combination of packages on a specific pfSense appliance.

On a CE 2.9.2 appliance with the matching experimental core and two working WANs, SD-WAN 0.4.27 selected WAN2 for new LAN connections while the default route remained on WAN1. PF showed the rule tracker, next hop and both directions of real TCP and UDP flows. The NAT state translated them to WAN2's address. External HTTPS management and the two port forwards answered on both WANs. The isolated CE 2.9.2 lab observed reboot and restore separately. Physical circuit interruption and combined HA and IPsec interoperability require their own evidence. [Isolated CE 2.9.2 acceptance](benchmarks/ce292-interface-original.md)

[Current release evidence](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest) · [Compatibility matrix](PACKAGE-COMPATIBILITY.md) · [Acceptance procedure](LAB.md)

## Two-WAN interface interruption on CE 2.9.2

A CE 2.9.2 appliance running SD-WAN 0.4.28 used two active interfaces. Each interface was disabled administratively in a separate trial. SSH stayed on the other WAN and a local timer was ready to re-enable the affected interface independently. An external HTTPS client sampled both management addresses.

| Trial | Forwarding and management outcome |
| --- | --- |
| WAN2 disabled while SD-WAN used WAN2 | PF applied WAN1. The simultaneous check of the new rule and failed gateway passed after 15 seconds. Management remained reachable over WAN1. The WAN2 monitor reported online 48 seconds after the interface was re-enabled. |
| WAN1 disabled while SD-WAN and the system default used WAN1 | PF applied WAN2 at the first check about 5 seconds after the interface was disabled. The system default moved to WAN2 after 18 seconds. Management remained reachable over WAN2. After re-enabling WAN1, its monitor reported online in 48 seconds and the default route returned 10 seconds later. |

The saved configuration and the loaded NAT rules matched their pre-test copies. The timings describe administrative interface loss and the polling interval on this appliance. Modem power loss, upstream service loss, and interruption of both links belong in an isolated trial with a dedicated client and console. [Netgate Multi-WAN verification](https://docs.netgate.com/pfsense/en/latest/multiwan/test.html)

## Supervised observer recovery

On the same CE 2.9.2 appliance, an abrupt stop of the worker left its supervisor in place. The replacement worker retired the previous decision. The active PF rule was observed blocking new connections before forwarding was confirmed again, nine seconds after the worker stopped. The saved configuration and NAT matched the pre-test copies.

In the FreeBSD VNET lab, a deliberate worker failure exercised the supervisor and actual PF. The old TCP session and the control flow continued over WAN1 while the scoped guard blocked a new connection. After recovery, a new session completed over WAN2. [FreeBSD recovery job](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44920325087/job/136895159788)

## Early laboratory acceptance

Package 0.3.0 includes the WebGUI, widget, measurement daemon, and selection module. The filter adapter ships separately for a lab image. The `pfSense-pkg-SDWAN-0.3.0.pkg` archive is 25,004 bytes with SHA-256 `6552b2fcbc97de2be53a5c926c7f1539d06514902a42b1eb87f9b0a2aa595476`. [Pinned binary](https://github.com/allanlopesprado/pfsense-sdwan/blob/fe20885be522fb680e2c607bb4c298fbfdb76490/dist/pfSense-pkg-SDWAN-0.3.0.pkg)

| Test | Observation |
|---|---|
| Upgrade and rollback | The CI VM downloaded the archive with the README command. In an isolated root, the pkg database went from 0.2.0 to 0.3.0 and back to 0.2.0. It rejected a truncated archive. The root used the target ABI metadata. Separate tests exercise hooks and WebGUI registration. |
| Telemetry and compilation | The daemon received controlled dpinger-format samples over Unix sockets. The pfSense source generator with the adapter produced rules for A, B, and no eligible path. The same binding kept one decision across two trackers in a single reload. An expired snapshot, group removal, or provider removal produced a block during compilation. |
| Forwarded traffic | FreeBSD PF loaded the generated rules. A remote TCP application replied with the source address it saw after NAT. After a selection change, the existing session used A and a new one used B. With both paths ineligible, the matched connection was blocked while a control destination remained reachable over the default route. |
| CARP | Two VNET instances shared a VIP. After the MASTER lost its interface, an existing client and a new client reached the VIP through the new MASTER. The original preference returned on recovery. Timing includes probe intervals and depends on topology. |
| VTI without SA | With a tunnel route but no security association, the IPsec missing-SA counter increased. The peer's cleartext ICMP count stayed the same. Before and after the test, controls reached the destination outside the tunnel. |
| VTI with ESP | The peer and firewall received ESP on their physical interfaces and the destination returned three replies through the tunnel. Removing **one outbound SA** stopped the flow, increased the missing-SA counter, and left protected cleartext ICMP at baseline. Both peers used manual SAs. |

The VTI and CARP failover tests used different topologies. The CARP test measures VIP availability. Recovery of an application session through an IPsec tunnel after MASTER transfer is a separate criterion. [ESP test and block after SA removal](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44459464879/job/135342599341)

The VM ran FreeBSD 15. The public pfSense generator identifies itself as `2.9.0-DEVELOPMENT`, revision `9363ac5b8651a1c7a333180425ce7719070f95f9`. The daemon consumed controlled samples and TCP traffic traversed actual VNET interfaces. Measuring end-to-end convergence requires captures on an appliance where dpinger observes physical link degradation. [pfSense rules and FreeBSD traffic test](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44459108859)

## Widget and WebGUI in 0.4.0

The 0.4.0 package on `main` is **28,924 bytes** with SHA-256 `67251efd7fd8841fb26b65dbfead379867ddf5274adfe456766d3db182d8c7d8`. Two independent builds produced identical bytes. The installer verifies this checksum before calling the package manager. [Pinned installer archive](https://github.com/allanlopesprado/pfsense-sdwan/blob/c0372cadc2ce6be6afa7c01c0db85bba23bc26d6/dist/pfSense-pkg-SDWAN-0.4.0.pkg)

Chromium rendered the widget with the light and dark pfSense CSS at 360 and 640 px. Test data and long identifiers fit without horizontal scrolling in all four combinations. Keyboard focus stayed on the selected policy after AJAX refresh. Minimum measured contrast for values and labels was 12:1 in light mode and 10.05:1 in dark mode. Forms and links used navigation, log filters, privilege checks, and CSRF protection from the reference source. Sign in to GitHub to download the `sdwan-dashboard` artifact while it is retained. [Workflow run](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44461547088)

## System Logs events

The test extracted the 0.4.0 emitter and ran it with FreeBSD 15.1 `syslogd`. The General page reader recognized five distinct events from `sdwan` in RFC 3164 and five in RFC 5424 at default severity. Filtering at `warning` left two visible events. Twenty-five identical failures produced one error. A control message from `dpinger` went to the gateway log. This used the actual emitter, log routing rules, and parser. Visiting the page on CE 2.9.1 remains part of appliance acceptance. [Full run log](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44462039273/job/135351197785)

## Log transport fix in 0.4.1

One repeat of the 0.4.0 test recorded only the first event in a sequence. The package opened and closed a local connection per message. When a Unix datagram sender disconnects, FreeBSD can discard pending messages if the receiver's shared queue already contains data. Release 0.4.1 keeps one connection in the dedicated service and restores the PHP identity between calls. [FreeBSD 15.1 kernel behavior](https://github.com/freebsd/freebsd-src/blob/releng/15.1/sys/kern/uipc_usrreq.c#L3230-L3266)

The 0.4.1 test compares nine combinations of format, severity, and run lifecycle. The third round pauses syslogd before the first event, sends the sequence once, then resumes reading. It checks received messages, which entries appear in General, and the identity of a later PHP message. The package is **29,140 bytes** and two independent builds produced the same SHA-256. [Pinned installer archive](https://github.com/allanlopesprado/pfsense-sdwan/blob/f3f669217300c2ebd126119cb87bfcf34ef3d94a/dist/pfSense-pkg-SDWAN-0.4.1.pkg)

All nine combinations passed on FreeBSD 15.1. In each round, General showed five events at the default severity in both formats and two at `warning`. The same job tested upgrading from the three earlier versions and rolling back with hooks disabled in isolated roots. [0.4.1 FreeBSD results](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44463868187/job/135357178008) · [WebGUI and theme tests](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44463868187/job/135356837862)

## IKEv2 negotiation on two paths

Two strongSwan processes on Ubuntu 24.04 negotiated two independent IKE SAs and two CHILD_SAs. The test observed ESP in both directions on each link and data counters at both ends. During A's CHILD_SA and IKE SA rekeys, B kept its SPIs and carried data. After A's SA was removed, its protected probes failed in both directions, and cleartext counters stayed unchanged on both links. [strongSwan 5.9.13 run](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44460493186/job/135345795505)

## TCP continuity with CARP and pfsync

In a FreeBSD 15.1 VM, two VNET nodes shared a LAN VIP and a WAN VIP. pfsync used a dedicated link and floating PF states. With pfsync disabled, the open TCP session stopped receiving replies after VIP transfer. A new connection succeeded through the node that took over.

With pfsync enabled, the standby received the established TCP state with the same PF state ID and creator. When the preferred node lost both links, the same socket completed another transaction with the same state and translated WAN address. It completed a further transaction with preserved NAT state after the preferred node reclaimed both VIPs. [GitHub Actions regression](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44503280903/job/135488666307)

## VPN and dynamic WAN recovery

OpenVPN and WireGuard transferred a byte-verified 64 KiB in both directions over the original path, after interrupting WAN A, and after it returned. During the interruption, the test required no VPN response and no protected cleartext HTTP in either WAN capture. The lab selected the access route. The WireGuard peer confirmed the authenticated source address on WAN B. [OpenVPN](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44517334352/job/135536646310) · [WireGuard](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44517334352/job/135536646345)

DHCP renewed the lease, then acquired a different address and gateway after release. PPPoE ended its first session on link loss and negotiated another address pair. Using the observed session data, the SD-WAN matcher rejected both the old source and the old next hop. [DHCP](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44517334352/job/135536646518) · [PPPoE](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44517334352/job/135536646195)

Kea issued two successive /56 prefixes to the same DHCPv6 client. For each lease, the router advertised a /64 and the LAN client reached the destination with an address from that prefix. Egress failed while the first route was withdrawn. The test waited for the old address to expire before verifying delivery with the new prefix. [DHCPv6-PD and LAN renumbering](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44518652364/job/135541214456)

## Dashboard, observer, and WAN recovery in 0.4.19

Chromium rejected an HTML sign-in response and hid old readings after 30 seconds without a valid refresh. A valid response restored the readings. The visual tests also checked both native themes and four panel widths. [Browser test](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44581476703/job/135762965421)

FreeBSD restarted the test worker after an unexpected exit. A deliberate stop left the service stopped. The WebGUI upgrade routine rejected interrupted and corrupted downloads from a 0.4.18 baseline, then upgraded on retry in an isolated package root. The observer recovered after a failed snapshot replacement. [FreeBSD job](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44582106827/job/135766245531) · [Snapshot and WebGUI tests](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44582106827/job/135765207125)

A test destination beyond the configured next-hop address stopped responding to TCP while its immediate next hop remained eligible. A dpinger monitor on the farther address detected the outage. Two- and three-link policies recommended the healthy backup, and the application and probe recovered after the outage ended. [FreeBSD upstream test](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44582106827/job/135766245531)

OpenVPN and WireGuard transferred 64 KiB of verified data in both directions over a 1280-byte backup WAN with a 1200-byte tunnel MTU. DNS initiated by the VPN node also succeeded over the active WAN. The Linux lab selected the route and recorded outer traffic during failure and recovery. [OpenVPN](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44582400239/job/135766221951) · [WireGuard](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44582400239/job/135766221473)

## Startup, restore, and HA lab coverage

The running observer started with no WAN monitor sockets and recovered on the same process when they became available. The pinned pfSense XML parser preserved the SD-WAN policy after a physical interface remap, and the inventory revision invalidated old readings. A renamed gateway required an explicit member change. An import without package settings started with an empty SD-WAN configuration. [Observer and restored XML tests](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44586802461/job/135781826298)

FreeBSD moved both CARP VIPs to the standby while it held the original protected TCP state from pfsync. New protected requests failed during the interval without an SA. After the lab installed independent ESP SAs on the new owner and peer, the original socket and new connections worked. Failback restored encrypted delivery with a fresh set of SAs. The WAN rules recorded no protected plaintext. [CARP and VTI test](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44586802461/job/135783079110)

In a separate Linux lab, the protected endpoint moved between network namespaces after terminating the first IKE process. strongSwan negotiated new IKE and CHILD_SA SPIs with the existing peer. Bidirectional probes recovered and the WAN capture found no protected plaintext. [Negotiated endpoint takeover](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44587488845/job/135784270477)

Suricata 8.0.8 on FreeBSD 15.1 intercepted a disposable epair through netmap host-stack mode. It passed HTTP control requests and ICMP, recorded the expected EVE block, and prevented the matched request from reaching the server. A control request succeeded after the inspector stopped. [FreeBSD netmap test](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44587248657/job/135783422131)

## Appliance acceptance

On CE 2.9.1, upgrading from 0.4.2 to 0.4.3 ran the actual hooks. On-appliance checks verified package integrity, package and service registration, a current sample, and events in the native log reader. SD-WAN configuration and PF and NAT rules matched before and after. [Release 0.4.3](https://github.com/allanlopesprado/pfsense-sdwan/releases/tag/v0.4.3)

Appliance acceptance still includes a full cold boot with the WAN disconnected, restoration onto different NIC assignments, inline Suricata on VirtIO, and a single combined test of IKEv2 and symmetric return through two CE 2.9.1 nodes and a licensed FortiGate. Experimental forwarding selects a path for ingress rules. The firewall's own default route and catalog distribution have separate acceptance criteria. [Interoperability matrix](FORTIOS.md) · [Acceptance procedure](LAB.md)
