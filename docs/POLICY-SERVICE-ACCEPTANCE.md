# Policy routing and service health acceptance

The historical baseline is [v0.4.25](https://github.com/allanlopesprado/pfsense-sdwan/releases/tag/v0.4.25). The branch starts from main at `65d18857a120a7aee46d9a2a19d9d0ea4c007aab`. It keeps the policy-oriented widget from 0.4.26, DNS and dynamic next-hop verification from 0.4.27, and the audited filter input for CE 2.9.2. The candidate package is for an isolated lab.

## From the monitor to the firewall rule

1. `sdwand.php` reads pfSense configuration and the native dpinger sockets. The collector rejects samples whose source address or monitor target no longer belongs to the gateway. It also runs configured service probes over explicit host routes and checks the interface, source address and next hop before and after each request.
2. `sdwan_engine.inc` evaluates WAN loss, RTT and RTT standard deviation separately from service outcomes. A policy can require the primary slot, the secondary slot or both. With no required slots, at least one selected optional slot must pass. With both controls left at **Member default**, any successful configured member probe satisfies service health as in earlier versions. Choose **Ignore** for slots outside a policy's scope.
3. `sdwan_steering.inc` computes the desired next hops from members approved for a dedicated gateway group. The binding records the policy revision, the matched ingress rules and their native trackers. The adapter uses only the native next hops available during rule generation. It rechecks the scope and keeps the following native block or reject as a second guard.
4. Forwarding and the observer share the verification of loaded PF. They compare each tracker's ingress interface, assigned egress device, current next hop and expected weights for a balancing pool. The observer publishes the decision before asking the native reload service to apply it.
5. The reload queue acknowledges receipt. The observer waits up to 30 seconds before deciding the request did not take effect. It records each attempt in `/var/run/sdwan-observer.json.forwarded`, including rejected requests. After three attempts for the same decision it reports persistent mismatch. A fresh configuration, renewed next hop or verified convergence can reset that budget. A process restart or managed service restart preserves the receipt and its attempt count. An ordinary stop or package removal retires it.

| State | Evidence |
| --- | --- |
| Recommended | The observer evaluated current measurements and selected the desired path. |
| Reload requested | The native reload service accepted the request for the stored decision. |
| Applied or blocked | The active PF rules match the intended egress or block for the bound trackers. Existing states retain their original path. |
| Divergent | PF is readable and its loaded rule differs from the current decision. Persistent divergence appears after the retry limit. |
| Sample expired | The last sample exceeded 30 seconds. The interface hides the old decision and the observer records expiry when it resumes publishing. A native reload without a valid sample denies the bound path. |

If the observer and the filter reload service are unavailable together, a loaded kernel rule can remain in effect until the next native reload. When PF is disabled or cannot be read, verification is unavailable. The package cannot prove a rule is applied from an acknowledgement alone.

## Services and recovery

The service results report **Failed** for a completed negative response or an attempted timeout. An unavailable source, route change or absent result is **No measurement**. A check skipped because the WAN is unavailable or the observation budget ended is **Not run**. The Diagnostics page shows the WAN metrics and the requested service slots separately.

A policy normally excludes an out-of-SLA WAN immediately and retains a healthy current path for up to 30 seconds while a better path settles. **Confirm WAN degradation** allows an operator to keep a previously verified and already active path for a bounded number of consecutive samples that exceed the WAN metrics. The setting defaults to one sample. A known down gateway, missing measurement or failed required service bypasses this hold. The adapter selects only paths already approved by the binding and its transport checks. It never widens a protected VTI policy to direct WAN. **Recovery hold** controls return to a better path. Weighted pools admit SLA-eligible members and may briefly retain previously verified members within an explicit soft-degradation window.

Destination addresses for probes must be distinct in the current implementation. A shared service can expose a different probe VIP on each WAN with certificates and the application behind both addresses. Capture the probe on both WAN interfaces and record the peer's source and reply. The client traffic in this lab reaches the same ERP destination over both WANs as its policy changes.

The appliance workflow also exercises an identical TCP probe IP with separate FreeBSD FIBs. It gives FIBs 1 and 2 independent host routes and source addresses, checks both next hops and runs both probes concurrently with `setfib`. It checks the provider's ingress interface counters, both server replies and the unchanged FIB 0 default route and NAT. This independently validates a possible transport for identical destinations. The package's configured probes currently use the ordinary routing table and separate destination addresses. [Appliance procedure](CE291-APPLIANCE.md), [FreeBSD setfib](https://man.freebsd.org/cgi/man.cgi?query=setfib&sektion=1)

## Firmware and rollback

The package provides observation on stock CE 2.9.1. Active steering requires the project's separate adapter built from the exact CE 2.9.1 `filter.inc`. The prepare tool checks the original digest and creates an overlay outside the checkout. Netgate's ordinary policy routing remains the reference for native gateway groups and the system's default route. [Prepare the CE 2.9.1 overlay](../core/README.md), [Netgate policy routing](https://docs.netgate.com/pfsense/en/latest/multiwan/policy-route.html)

Use a clone with two independent WANs, a management path and console access. Save the boot image, configuration and previous package before changing the core. Start with the candidate package on stock CE and verify **Observation only**. Apply the matching lab overlay, restart SD-WAN and inspect **Forwarding**. Create dedicated native groups and equivalent adjacent native guards. Scope the ERP and backup rules to their own traffic. Keep management, native routing exceptions, default routes, NAT and protected VPN prefixes outside the test rules.

After reboot, compare the boot version, the adapter ABI, installed package, native routes and NAT, then wait for fresh observations. If firmware replaces the generator, derive a fresh overlay from that version's audited input. For rollback, unbind each policy through **Forwarding**, confirm that PF loaded the original native rules, and repeat both traffic captures. Then use the previous image or package as appropriate. Compare a held TCP stream independently from new connections. [Installation and rollback](LAB.md), [pfSense upgrade process](https://docs.netgate.com/pfsense/en/latest/install/upgrade-guide-overview.html)

## Reproduce the two-policy test

The [Actions workflow](../.github/workflows/ce291-policy.yml) verifies the official system archive by its pinned digest and manifest version, extracts the CE 2.9.1 source used for the generator and runs isolated FreeBSD VNETs. To repeat it on a disposable FreeBSD VM as root with Git, Python, PHP with ctype, filter and mbstring and dpinger installed, obtain the official `pfSense-system-2.9.1.pkg` and run the same commands.

```sh
python3 tests/lab/ce291-source.py /path/to/pfSense-system-2.9.1.pkg lab-ce291
python3 tools/prepare-core.py --ce-291-lab --source lab-ce291 --out lab-overlay
SDWAN_CE291_CORE="$PWD/lab-ce291" sh tests/lab/freebsd-dataplane.sh
```

On an appliance clone, reproduce the same five phases with two client flows and two concurrent WAN captures. Configure ERP to require its TCP probe and backup to require a different TCP probe. Keep an independent DNS responder on WAN1. Make the ERP endpoint and its probe unavailable on WAN1 at the peer, including the traffic of its established connection. Keep the gateway, DNS and backup reachable on WAN1. Save the two selected rules from `pfctl -sr`, state identifiers and next hops from `pfctl -ss -vv`, the client reply and the NAT source observed by each server. Repeat the checks in each phase below. Archive only test traffic and the required rule or state evidence.

| Phase | ERP new TCP | Backup new TCP | Existing sessions |
| --- | --- | --- | --- |
| Baseline | WAN1 | WAN1 | Open both and record the PF state IDs. |
| ERP outage on WAN1 | WAN2 | WAN1 | The previous ERP state stays on WAN1 and cannot deliver during the induced fault. The backup socket still replies on WAN1. |
| ERP recovery | WAN1 after the configured hold | WAN1 | Compare the original ERP socket with a new connection. |
| Both WANs unavailable | Blocked for the bound traffic | Blocked for the bound traffic | Record state behavior separately. |
| Native rollback after WAN recovery | Native group via WAN1 | Native group via WAN1 | Confirm the kernel default and NAT agree with the baseline. |

## Recorded FreeBSD results

During the ERP outage, dpinger continued to report WAN1 online and the DNS control received a real A response. The ERP rule (tracker 41001) used route-to (epair2a 203.0.113.2) and the backup rule (tracker 41003) used route-to (epair1a 198.51.100.2). The echo server returned its observed peer address to each client. New ERP connections returned through 203.0.113.1 and backup connections through 198.51.100.1. Both returned through 198.51.100.1 at baseline, on recovery and after unbinding. The fixture compares the default route and NAT before and after applying each decision.

The established ERP stream retained its path and stopped delivering during the outage. Backup continued on its existing socket. The original ERP stream delivered its pending message when WAN1 recovered. With both WANs unavailable, both bound trackers rendered quick blocks and neither new TCP flow received a reply. The held sockets delivered again after the WANs returned. The rollback rendered the stock rules byte for byte and kept the established sockets usable. [Policy traffic results on Actions](https://github.com/allanlopesprado/pfsense-sdwan/actions/workflows/ce291-policy.yml?query=branch%3Amilestone%2Fpolicy-service-forwarding)

| Environment | Scope |
| --- | --- |
| Unit and PHP fixture tests | Passed. Per-policy requirements and legacy defaults, hard and soft degradation, recovery, DHCP next-hop changes, stale samples, restart and accepted reloads with divergent PF. |
| FreeBSD 15.1 and PF with CE 2.9.1 source | The workflow compiles the exact generator against lab inputs and checks real probes, loaded rules and server-observed packet delivery on a stock FreeBSD kernel. The lab supplies configuration and gateway inventory fixtures and a Unix socket that acknowledges requests. It runs the renderer and loads the rules through the real PF separately. The appliance workflow verifies the live native reload service separately. |
| pfSense CE 2.9.1 appliance clone | The isolated QEMU appliance verified native reload, two-policy traffic, original TCP state preservation during the service outage, recovery, both WANs unavailable, reboot and rollback. The extended appliance run also passed the native upgrade, DHCP next-hop change, same-IP FIB probes, observer restart, unapplied reload, expiry and VTI no-SA checks. See the [appliance procedure and recorded results](CE291-APPLIANCE.md). |
