# FortiGate interoperability over two IPsec tunnels

The target scenario is a pfSense branch with two WANs, two route-based IPsec tunnels, and a FortiGate at the far end. Each firewall manages its own side. End-to-end acceptance on pfSense CE 2.9.1 and FortiOS remains pending. Repository tests exercise package, rule generation, and FreeBSD components. In the paired test, record the exact versions and application traffic in both directions. [Integration](INTEGRATION.md) · [Lab](LAB.md)

## Capabilities and limits

| Area | Project implementation | FortiGate or Junos reference |
|---|---|---|
| Measurement | dpinger reports RTT, RTT standard deviation, and gateway loss. SLAs use RTT and loss. Among eligible members, a policy prefers the lowest configured cost or lowest RTT. A single member supports SLA monitoring. | FortiOS also measures jitter, supports passive measurements, and makes decisions using its own rules. Junos RPM measures response time, variation, and loss. The three methods can produce different values on the same path. |
| Forwarding | Stock pfSense uses the recommendation for observation. With the experimental ABI 1 core, an explicit binding can select a gateway for new flows matching the identified rules. A binding requires a dedicated group, members of the same address family, and an adjacent block rule of equal scope. | The operator configures zones, routes, and SD-WAN rules on FortiGate. Each firewall selects its own member. |
| Two tunnels | Enabling a binding requires two VTI gateways with distinct, identifiable transport interfaces. Two children of one Phase 1 share IKE negotiation and transport dependencies. Different VLANs or virtual NICs can still use the same physical circuit. | FortiGate can group IPsec interfaces in an overlay zone. On Junos, routing selects a secure `st0.x` interface and security policies authorize the traffic. |
| Administration | The operator manages IKE, CARP, NAT, routes, and remote policies. | Centralized FortiManager management, dynamically formed ADVPN tunnels, and application selection are FortiOS capabilities separate from this package. |

[Fortinet members and zones](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/942095/sd-wan-zones) · [Fortinet Performance SLA](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/584396/sd-wan-performance-sla) · [Juniper route-based VPN](https://www.juniper.net/documentation/us/en/software/junos/vpn-ipsec/topics/topic-map/security-route-based-ipsec-vpns.html) · [Juniper RPM](https://www.juniper.net/documentation/us/en/software/junos/flow-monitoring/network-mgmt/topics/topic-map/real-time-performance-monitoring.html)

## Where to use `0.0.0.0/0`

| Location | Effect and verification |
|---|---|
| CHILD_SA selectors | The reviewed pfSense VTI code adds broad IPv4 and IPv6 selectors. FortiGate permits broad local and remote selectors. Check the **negotiated** selectors in each CHILD_SA. The Phase 2 network fields in pfSense VTI mode define the tunnel's inner addresses. |
| LAN rule destination | A specific branch source with IPv4 destination `any` can route matching new flows through the tunnel. Rule order must preserve routes to local networks, management, and other VPNs. The package rejects a binding when both source and destination are unrestricted. |
| Default route in the system table | Changes the overall IPv4 path, including local services according to their routes and bindings. The package rejects the system default gateway group for experimental binding. In a full-tunnel design, verify that public IKE addresses stay reachable over physical WANs during failure and reconvergence. Evaluate `::/0` separately. |

[Netgate Phase 2](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/configure-p2.html) · [Reviewed pfSense VTI code](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/ipsec.inc#L2347-L2364) · [Fortinet Phase 2 selectors](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/604285/phase-2-configuration) · [Fortinet routing decisions](https://docs.fortinet.com/document/fortigate/7.6.0/sd-wan-architecture-for-enterprise/768108/sd-wan-routing-logic)

## Settings to agree on with the peer administrator

| Layer | Checks for each pfSense–FortiGate pair |
|---|---|
| IKE | Bind each Phase 1 to the corresponding WAN or WAN VIP for independent paths. Agree on IKE version, local and remote identities, PSK or certificate authentication, and compatible encryption, integrity, PRF, and DH proposals. Record DPD, timers, and rekey behavior. |
| ESP | Associate each Phase 2 with its Phase 1. Agree on ESP proposals, selectors, and PFS/DH group. Record lifetimes and verify CHILD_SA rekey while traffic flows. Use distinct inner address pairs and verify the neighbor on each VTI. |
| NAT, return paths, and HA | Decide where to apply SNAT when the hub provides Internet egress. On routed private networks, preserve source addresses when required and install return routes to the original prefix. NAT-T carries IPsec over UDP. On pfSense, VTI NAT and `reply-to` depend on a global filtering mode that also affects policy-based tunnels. With CARP, verify the Phase 1 WAN VIP and VTI assignment order on both nodes. |

[Netgate Phase 1](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/configure-p1.html) · [Fortinet Phase 1](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/790613/phase-1-configuration) · [Netgate VTI filtering](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/routed-vti.html) · [Netgate IPsec in HA](https://docs.netgate.com/pfsense/en/latest/highavailability/ipsec.html)

## Acceptance tests for the firewall pair

1. **Delivery over each tunnel.** With both tunnels negotiated, test A and B independently against the same remote service. Use distinct, comparable monitoring targets reached through each tunnel. Record a complete TCP transaction at the client and destination, the VTI capture, ESP or UDP/4500 on the intended WAN, effective NAT, return traffic, and the MTU under transfer load.
2. **Quality and asymmetry.** Apply controlled loss or latency only to A. Time the first successful new connection on B and separately track existing sessions. Verify session data, return interface, and counters on both firewalls. On recovery, the preferred healthy path must sustain its advantage for 30 seconds in the package. The reload queue and observation cycle add latency.
3. **Loss of both tunnels.** Keep both physical WANs up with both SAs unavailable. Generate dedicated test traffic for the protected prefix. Capture after NAT on both WANs and check block and destination counters. Acceptance requires zero cleartext delivery of the protected flow, including during reload. Record dropped capture packets.
4. **Recovery and rollback.** Repeat with IKE and ESP rekeys, loss of the active CARP node, and its return. Record the first successful response, the MASTER node for each VIP, and any session interruption. Unbind the policy, open a new connection, and identify the native route it uses. Attach versions, rules, captures, and timestamps without credentials or keys.
