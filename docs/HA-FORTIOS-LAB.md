# Two-node pfSense HA and FortiGate acceptance

Use a disconnected lab with two disposable pfSense CE nodes of the **same** release and an authorized FortiGate. Repeat the matrix independently on CE 2.9.1 and CE 2.9.2. Record the exact FortiOS build and license class. Use the same SD-WAN archive and overlay commit on both CE nodes. FortiOS interoperability remains pending until verified on the actual peer.

Keep independent hypervisor or serial consoles and take snapshots before changes. Use only synthetic traffic, randomly generated lab-only PSKs, and isolated switches. Keep management on a separate link when capturing traffic.

## Topology

| Segment | CE-A | CE-B | Shared CE VIP | Remote end |
| --- | --- | --- | --- | --- |
| LAN | `10.61.10.2/24` | `10.61.10.3/24` | `10.61.10.1/24`, VHID 41 | ERP client `10.61.10.10`, backup client `10.61.10.11`, gateway `10.61.10.1` |
| WAN A | `198.51.100.2/29` | `198.51.100.3/29` | `198.51.100.1/29`, VHID 42 | FortiGate `port1`: `198.51.100.4/29`; lab gateway `198.51.100.6` |
| WAN B | `203.0.113.2/29` | `203.0.113.3/29` | `203.0.113.1/29`, VHID 43 | FortiGate `port2`: `203.0.113.4/29`; lab gateway `203.0.113.6` |
| SYNC | `192.0.2.241/30` | `192.0.2.242/30` | None | Dedicated to the CE nodes |
| VTI A | `10.63.0.1` | `10.63.0.1` | Active node owns the tunnel | FortiGate `LAB-A`: `10.63.0.2` |
| VTI B | `10.63.0.5` | `10.63.0.5` | Active node owns the tunnel | FortiGate `LAB-B`: `10.63.0.6` |
| Remote LAN |  |  |  | FortiGate `port3`: `10.62.10.1/24`; ERP `10.62.10.10:8443`; backup `10.62.10.11:9443` |

Use independent virtual switches for LAN, WAN A, WAN B, SYNC, and remote LAN. Permit CARP on each of the three data segments. Both WAN capture points must see the paths to both CE nodes. The .6 lab gateways are isolated router instances that answer ICMP. FortiGate's IKE peers are on-link, which keeps WAN and IPsec health independent. Add `10.62.10.12/24` and `10.62.10.13/24` as aliases on the ERP host. Both aliases expose the same synthetic service. Route protected flows without NAT.

## pfSense CE configuration

1. Assign LAN, WAN A, WAN B, and SYNC in the same order on both nodes, using the static addresses above. In **System → Routing**, add `LAB_WAN_A` and `LAB_WAN_B` with the respective .6 next hop and monitoring address. Use an explicit WAN failover group as the IPv4 default, with A tier 1 and B tier 2.
2. In **Firewall → Virtual IPs**, configure the three CARP VIPs on both nodes. Use matching VHID and password per pair, advertising base 1, skew 0 on CE-A and 100 on CE-B. In **System → High Availability Sync**, enable pfsync on SYNC, with the other node's SYNC address as the peer. Use distinct Filter Host IDs, e.g. `61a00001` and `61a00002`. Permit pfsync only between SYNC addresses. In this lab select **Floating States** under **System → Advanced → Firewall & NAT → Firewall State Policy** and disable native automatic state termination for the session continuity comparison. [Netgate CARP and pfsync](https://docs.netgate.com/pfsense/en/latest/highavailability/pfsync.html)
3. Configure both nodes manually for the first trial. In a separate XMLRPC trial, enable configuration synchronization only on CE-A to CE-B's HTTPS SYNC address. Permit HTTPS from CE-A on SYNC and use the documented sync account. Select the firewall rules, virtual IPs, and IPsec settings. After synchronization verify both VTI assignments and gateways on CE-B manually. Confirm package version, overlay, local observer and policy approvals on **both** nodes. Record which SD-WAN settings synchronized. [Netgate XMLRPC sync](https://docs.netgate.com/pfsense/en/latest/highavailability/xmlrpc-sync.html)
4. In **VPN → IPsec**, create two Phase 1s with the appropriate WAN **CARP VIP** as Interface and the corresponding FortiGate IP as Remote Gateway. Use IKEv2, IPv4, mutual PSK, local and peer IP identities, AES-256-CBC, SHA-256, DH 14, 28,800 s lifetime, NAT-T Auto, and DPD 10 s with three failures. Generate a distinct PSK for each pair. Use one **Routed (VTI)** IPv4 Phase 2 per Phase 1, with the corresponding CE and FortiGate inner addresses above, ESP AES-256-GCM, PFS group 14, and a 3,600 s lifetime. [Netgate Phase 1](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/configure-p1.html) · [Phase 2](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/configure-p2.html) · [IPsec with CARP](https://docs.netgate.com/pfsense/en/latest/highavailability/ipsec.html)
5. Assign and enable each generated `ipsecX` in **Interfaces → Assignments** as `LAB_VTI_A` and `LAB_VTI_B`, in the same order on both nodes. Keep the negotiated inner addresses. Verify the generated IPv4 VTI gateways use `10.63.0.2` and `10.63.0.6` as next hops. Monitor these distinct VTI peer addresses with alarm actions enabled. Choose **Filter IPsec VTI on assigned interfaces** in the advanced IPsec settings for this VTI-only lab. Add narrow inbound accept rules on each VTI for the synthetic remote-to-LAN TCP requests and the monitor traffic. Verify the intended `reply-to` on the active PF rule. [Netgate routed VTI](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/routed-vti.html)
6. In **System → Routing → Gateway Groups**, create `LAB_VTI_ERP` and `LAB_VTI_BACKUP`, with A tier 1 and B tier 2 in each. Enable **Do not create rules when gateway is down**. Place the following rules before general LAN rules and record their actual trackers. Do not NAT these private prefixes over either VTI. Verify the observed inner source at the peer. [Netgate enforcing gateway use](https://docs.netgate.com/pfsense/en/latest/multiwan/policy-route.html#enforcing-gateway-use)

| Order | Action | Source | Destination | Gateway |
| --- | --- | --- | --- | --- |
| 1 | Pass/log | `10.61.10.10/32` | `10.62.10.10/32 TCP/8443` | `LAB_VTI_ERP` |
| 2 | Block/log | `10.61.10.10/32` | `10.62.10.10/32 TCP/8443` | Default, equal match to rule 1 |
| 3 | Pass/log | `10.61.10.11/32` | `10.62.10.11/32 TCP/9443` | `LAB_VTI_BACKUP` |
| 4 | Block/log | `10.61.10.11/32` | `10.62.10.11/32 TCP/9443` | Default, equal match to rule 3 |
| 5 | Block/log | `10.61.10.0/24` | `10.62.10.0/24 any` | Default |

Under **Firewall → Rules → Floating**, add a logged quick outbound block to `10.62.10.0/24` on both physical WANs. Inspect the effective native rule order and existing states. An existing matching PF state can have precedence over this rule.

7. Add host routes for `10.62.10.12/32` through VTI A and `10.62.10.13/32` through VTI B. In the SD-WAN Members editor, create `VTI_A` and `VTI_B` for the corresponding gateways, with costs 10 and 20. Set the Primary checks to `tcp://10.62.10.12:8443` and `tcp://10.62.10.13:8443`. Verify each route from **Review probe routes** and the response from Diagnostics. Create the ERP policy with both members, lowest cost, Primary check required, maximum RTT 40 ms, maximum loss 5%, and 30 s recovery hold. Keep the backup on its native group. Save separate native/observation and adapter trials. For the adapter trial, boot the matching overlay and approve `LAB_VTI_ERP` on each node as needed. Verify a new LAN connection when each node owns the VIPs. [Adapter preparation](../core/README.md) · [Policy integration](INTEGRATION.md)

## FortiGate reference configuration

Use a FortiOS build and license supporting the selected proposals. Export the lab VDOM snapshot. Use separate non-zone tunnels for this profile so the operator can apply a fault to only one inbound interface. FortiGate SD-WAN zones are a separate comparison.

| Setting | LAB-A | LAB-B |
| --- | --- | --- |
| **VPN → IPsec Tunnels** | Custom route-based, static peer, IKEv2 | Same |
| Physical interface and local IP | `port1`, `198.51.100.4` | `port2`, `203.0.113.4` |
| Remote gateway and IP identity | `198.51.100.1` | `203.0.113.1` |
| Phase 1 | `aes256-sha256`, DH 14, 28,800 s, NAT-T enabled, DPD on-idle 10 s × 3, lab PSK A | Same with lab PSK B |
| Phase 2 | `aes256gcm`, PFS DH 14, 3,600 s, local and remote selectors `0.0.0.0/0` | Same |
| Scope | Disable automatic selector routes with Phase 1 `add-route disable` | Same |
| **Network → Interfaces**, IP and remote IP | `10.63.0.2/32`, remote `10.63.0.1/30`, allow PING | `10.63.0.6/32`, remote `10.63.0.5/30`, allow PING |
| **Static Routes**, prefix `10.61.10.0/24` | `LAB-A` via `10.63.0.1`, distance 10 and priority 10 | `LAB-B` via `10.63.0.5`, distance 10 and priority 10 |

Confirm the peer IDs and negotiated selectors. Set a third blackhole route for `10.61.10.0/24` at distance 254. Verify both equal-cost overlay routes are usable in the RIB and keep feasible-path source checks enabled. Confirm there is no selector-generated default route or LAN-to-physical-WAN rule for protected traffic. [Fortinet Phase 1](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/790613/phase-1-configuration) · [Phase 2](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/604285/phase-2-configuration) · [Reverse-path checks](https://docs.fortinet.com/document/fortigate/7.4.1/administration-guide/139692/routing-concepts)

1. In **Policy & Objects → Firewall Policy**, create separate accept policies `LAB-A → port3` and `LAB-B → port3`. Sources are `10.61.10.10/32`, `10.61.10.11/32`, and the corresponding CE VTI address /32. Permit TCP/8443 and TCP/9443 to the ERP and backup hosts and the corresponding monitor alias. Set NAT off and log sessions. Add separate reverse accept policies `port3 → LAB-A` and `port3 → LAB-B` from `10.62.10.10/32` to `10.61.10.10/32` for TCP/8443 with NAT off. [Fortinet route-based policies](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/806643/vpn-security-policies)
2. Set `auxiliary-session disable` in the isolated VDOM. Open a connection on B while A is available, and verify the reply leaves on B. Capture both overlays to prove symmetry. [Fortinet auxiliary-session behavior](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/14295/controlling-return-path-with-auxiliary-session)
3. For the reverse test, add a **Network → Policy Routes** entry from input `port3`, source `10.62.10.10/32`, destination `10.61.10.10/32`, TCP destination port 8443, outgoing `LAB-A` via `10.63.0.1`. Repeat with `LAB-B` via `10.63.0.5`. Enable only the intended rule for each forced path test. Record manual route changes separately from automatic recovery. Verify the active CE `reply-to` and the actual return. [Fortinet policy routes](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/144044/policy-routes)

## Run and record the scenarios

Run each of these listeners separately on the corresponding lab host. For the reverse-direction test also run `python3 -u tests/lab/ha-echo.py 10.61.10.10 8443` on the branch ERP client.

```sh
python3 -u tests/lab/ha-echo.py 10.62.10.10 8443
python3 -u tests/lab/ha-echo.py 10.62.10.12 8443
python3 -u tests/lab/ha-echo.py 10.62.10.13 8443
python3 -u tests/lab/ha-echo.py 10.62.10.11 9443
```

From the separate branch clients, open a new TCP connection per sample and record the timestamp, unique marker and reply. Compare the echoed source with the capture. In the reverse trial, run a FortiGate-routed request from the remote ERP host to `10.61.10.10:8443`.

```sh
printf 'lab-erp-%s\n' "$(date +%s%N)" | nc -4 -n -N -w 2 10.62.10.10 8443
printf 'lab-backup-%s\n' "$(date +%s%N)" | nc -4 -n -N -w 2 10.62.10.11 9443
```

Before each fault, also open one interactive `nc` connection per direction and send `lab-held-before`. Keep the socket open and send a new marker after the transition. Record the original tuple and PF state ID/creator. Report separately whether the original socket replied or required a new connection. Sample fresh requests at least once per second and report the actual cadence. Restore both valid probes and bidirectional delivery between phases.

| Scenario | Lab injection | Required outcome and record |
| --- | --- | --- |
| Each overlay | None. Select A, then B, in each direction. | Matching inner request and reply. ESP or NAT-T on the intended WAN and correct server source. |
| WAN A unavailable | On the isolated WAN A bridge, drop IPv4 except CARP protocol 112. Leave links, SYNC, and WAN B intact. | A's .6 monitor stops. New protected ERP flows use B in the adapter trial. Record MASTER for all VIPs and when A recovers. |
| Tunnel A unavailable | On WAN A block ESP and UDP ports 500 and 4500 between `198.51.100.1` and `198.51.100.4` in both directions. | A's .6 monitor stays up. VTI A monitor fails. Log whether DPD removes the SAs or they remain installed without traffic. ERP uses B. |
| ERP-only fault on A | Above FortiGate's A accept rule, add a logged deny from `LAB-A` to `port3`, TCP/8443 to `10.62.10.10` and `10.62.10.12`, using the ERP client and probe source. | A's VTI monitor and SAs stay up. A's ERP probe fails and new ERP flows use B after PF confirms the change. Backup continues on A. Record how the deny affects the held socket. |
| Both tunnels unavailable | Apply the same ESP and UDP filter on A and B. Leave both WAN monitors online. Continue fresh and held TCP requests. | Both VTI monitors go down. No valid protected reply during the blackout. No protected plaintext on either WAN before, during or after the effective PF block. |
| CE-A → CE-B | With both tunnels restored, shut down CE-A through its console. | VIP transfer, new IKE and CHILD_SAs, observed PF state, forward/return path and first valid fresh and held replies. |
| CE-B → CE-A | Restore CE-A and observe preemption. If it stays BACKUP, use controlled demotion of CE-B under **Status → CARP (failover)**. Record which method was used. | One MASTER per VIP, new SAs on CE-A, the first valid transaction, and whether held sessions survived. |
| Rollback | Withdraw the ERP binding on the isolated pair. Repeat a fresh ERP request and the both-tunnel blackout. Restore the saved configs and overlay snapshot. | Native preference, management and the system default match baseline. No protected plaintext during the blackout. |

Repeat isolated WAN and tunnel loss with B initially selected and the mirrored fault. For tunnel B the outer endpoints are `203.0.113.1` and `203.0.113.4`.

## Evidence

Capture WAN and VTI interfaces simultaneously from before each fault until after recovery. Use a tap or mirror position that can see traffic from either node. For example, use the following filters on the WAN collectors. Stop the captures after the trial and retain the counters printed by tcpdump.

```sh
tcpdump -ni wan-a-tap -s 128 -U -w wan-a.pcap 'ip proto 50 or udp port 500 or udp port 4500 or net 10.61.10.0/24 or net 10.62.10.0/24'
tcpdump -ni wan-b-tap -s 128 -U -w wan-b.pcap 'ip proto 50 or udp port 500 or udp port 4500 or net 10.61.10.0/24 or net 10.62.10.0/24'
tcpdump -nr wan-a.pcap 'net 10.61.10.0/24 or net 10.62.10.0/24'
tcpdump -nr wan-b.pcap 'net 10.61.10.0/24 or net 10.62.10.0/24'
```

Confirm ESP or NAT-T traffic in both directions in the healthy baselines to prove that the taps see the expected path. The two plaintext filters must match zero packets. Capture drops must also be zero. On CE, retain the CARP output from `ifconfig`, IKE and CHILD_SA identifiers from `swanctl --list-sas`, active PF rules and states from `pfctl -vvsr` and `pfctl -vv -ss`, NAT from `pfctl -sn`, and the routing table. Match the active rule tracker to Forwarding and correlate the System Logs. On FortiGate inspect `get vpn ipsec tunnel summary`, `diagnose vpn ike gateway list`, `diagnose vpn tunnel list`, the route table and the relevant sessions. **Raw FortiGate tunnel details can contain key material.** Publish only names, states, SPIs, selectors, endpoints and counters.

```text
ce_version,fortios_version,package_sha256,overlay_sha256,scenario,trial,direction,fault_time_utc,master_lan,master_wan_a,master_wan_b,ike_spi,child_spi_in,child_spi_out,pf_tracker,egress_tunnel,return_tunnel,first_valid_reply_utc,server_source,requests_sent,valid_replies,held_state_id,held_outcome,wan_a_clear_frames,wan_b_clear_frames,capture_drops
```

Use one record per scenario, trial and direction. Record VIP ownership, SA availability and application recovery as separate events. If there is no valid reply during the observation window, mark the result as censored and report the window. Record whether the path was selected natively, by the approved SD-WAN policy, or manually.

## Independent tests in the repository

- `sh tests/lab/freebsd-carp.sh` exercises three CARP VIPs, NAT, a pfsync negative control, two VTI paths, separate upstream, tunnel and service faults, both SA loss, and CARP failover and failback. Run as root in a disposable FreeBSD 15.1 VM. It uses manual ESP SAs and explicit route selection. Set `SDWAN_CARP_EVIDENCE` for WAN captures and counters. CI uploads this directory as `freebsd-carp-vti-captures`.
- [Linux strongSwan checks](../tests/lab/ikev2/README.md) verify IKE/CHILD rekey, distinct paths with broad selectors, return-path alignment and separate IP endpoint takeover.
- [CE appliance evidence](RESULTS.md) covers active egress, the ERP-only regression, reboot and rollback on individual CE appliances. The combined **CE pair and licensed FortiGate** result remains pending.
