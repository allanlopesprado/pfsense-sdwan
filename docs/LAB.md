# Acceptance testing on pfSense CE 2.9.1

The experimental distribution includes an observer and a lab forwarding integration. Record the package and core revisions separately. Use a stock clone to validate observation and native forwarding. To test the effect of path selection, use a lab image that includes the core integration. [IPsec, CARP, NAT, states, and routing integration](INTEGRATION.md)

## Topology and evidence

Use a CE 2.9.1 clone with an independent console. For HA, include two pfSense nodes, a peer on another network, two virtual WANs that can be degraded independently, a client LAN, and a synchronization network. Use lab addresses and certificates. Record the Git revision, package version, architecture, peer version, actual interface names, dpinger settings, and each SLA limit. Keep a local configuration backup and take node snapshots before installing.

One monitored gateway is enough to observe an SLA. To compare alternatives, configure two or more same-family gateways with targets that represent the same service and known return routes. For a VTI, identify its transport. For HA, assign the VTI interfaces independently in the same order on both nodes. Bind Phase 1 to the WAN VIP that corresponds to the tunnel. Test a connection over the active path and record the result before installing.

## Core dependency for forwarding tests

The package installs its files under `/usr/local` and its privilege definition under `/etc/inc/priv`. The rule generator adapter is part of a **separate lab image**. A package-only installation supports previews. To test rule bindings, check ABI 1 availability in **Forwarding**.

The patch uses public commit `9363ac5b8651a1c7a333180425ce7719070f95f9`. Its `src/etc/version` identifies `2.9.0-DEVELOPMENT`. Before building the target image, compare the rule generator and gateway inventory with the exact tree that will produce the clone. In the base **build** checkout, validate the patch with `git apply --check /path/to/filter-sdwan.patch`. Integrate `src/etc/inc/filter-sdwan.inc` alongside the change to `filter.inc`. On the clone, check the core revision, interfaces, and compiled rules. Run traffic tests even if the patch applies cleanly. [Rule generator patch](../core/filter-sdwan.patch) · [ABI 1 adapter](../core/filter-sdwan.inc)

## Build and install

For direct WebGUI download and installation, see [Install from Diagnostics → Command Prompt](../README.md#install-from-diagnostics--command-prompt).

The [dist directory](../dist/) contains lab packages and checksums. Download both files to the same directory on the clone and verify integrity before using `pkg add`. This example uses 0.4.7.

```sh
sha256 -c "$(awk '{print $1}' pfSense-pkg-SDWAN-0.4.7.pkg.sha256)" pfSense-pkg-SDWAN-0.4.7.pkg
```

Use a FreeBSD or pfSense builder with a ports tree, dependencies, and ABI compatible with the target appliance. The directory containing this project's Makefile is the port. Make it available as `net/pfSense-pkg-SDWAN` in the builder's working tree. In that directory, run the following commands.

```sh
make stage
make check-plist
make stage-qa
make package
make -V PKGFILE
```

### Alternative lab packaging

You can reproduce the lab package with Python 3.9+, the official FreeBSD `pkg` v2 tool tested at 2.9.3, and an environment that represents package files as UID 0/GID 0. On Linux, install these dependencies and `fakeroot` before running the build.

```sh
fakeroot python3 tools/build-lab-pkg.py --output ./dist
```

After packaging, follow the [versioning and publishing workflow](VERSIONING.md#prepare-a-release) to generate the index used by **Updates** and the pinned README command. Starting with 0.4.8, the WebGUI offers installation when the release is published and the tagged package's SHA-256 matches the index.

The builder includes the files in `pkg-plist`, populates the manifest and hooks, and verifies bytes, modes, and ownership before printing the checksum. The port declares `NO_ARCH`. The package ABI is `FreeBSD:16:*`. Confirm the family and major version with `pkg config ABI` on the target. The temporary-root extraction test disables scripts. Validating hooks, the WebGUI, the service, and HA requires installation on a clone.

### Install on the clone

The final ports build command reports the package path. Record its SHA-256 on the builder and verify the same value after copying the file to the clone. As root on the clone, replace the path below with the exact filename.

```sh
cat /etc/version
uname -m
pkg -vv | grep ABI
pkg add /path/to/package.pkg
pkg info -l pfSense-pkg-SDWAN
/usr/local/etc/rc.d/sdwand.sh status
```

Check the version with `pkg query '%n-%v' pfSense-pkg-SDWAN` and open **Services → SD-WAN**. In **Updates**, verify the installed version and click **Check GitHub** to compare it with the public project index. **System → Package Manager** uses the product repository and may omit packages installed directly from files. Netgate reviews additions to its catalog. Record the original output for any registration, ABI, dependency, checksum, or menu error. [Package catalog](https://docs.netgate.com/pfsense/en/latest/packages/manager.html) · [Submitting ports](https://docs.netgate.com/pfsense/en/latest/development/develop-packages.html)

## Removal and rollback

Identify the core image and package revisions separately in the lab. Save a clone snapshot before changing the core, a configuration backup, and the previous package with its SHA-256. The suite covers observer release 0.2.0 and lab release 0.3.0. Track both a new connection and one that was already established during the round-trip test.

1. In **Services → SD-WAN → Forwarding → Configured bindings**, select **Remove binding** for each group to restore native forwarding. Wait for the filter reload. Check the operator's pfSense rules and groups, egress route, and return path for a new connection. For protected prefixes, verify the native block when the tunnel is unavailable.
2. With the WebGUI available, run `pkg delete -y pfSense-pkg-SDWAN` in Command Prompt. Reopen the dashboard and Services menu. Check files and the process using the README commands. `pkg` removes its registered files and `rc.packages` updates the menu and service registry. If a binding is still registered, the package clears its transient selection and requests a reload. In the experimental core, the binding marker can still block new flows once the reload completes without the provider. Existing states follow native policy. If the package was already removed with bindings, reinstall the compatible package and use **Remove binding** before removing it again. Administrator-created rules, routes, and groups have separate lifecycles.
3. To test **package** rollback, remove the test version and reinstall the original package. Verify its SHA-256, its version with `pkg query '%n-%v' pfSense-pkg-SDWAN`, and file integrity with `pkg check -s pfSense-pkg-SDWAN`. Check the menu, service, and path of a new connection. [Previous packages](../dist/)
4. To roll back the **core**, restore the lab image snapshot. Compare the base version, configuration, and first successful transaction with the baseline. In HA, check each node's role and both versions.

The automated FreeBSD package test uses isolated roots and disables system hooks. The separate lifecycle suite runs the package scripts and service registration code with controlled adapters, including when PHP-FPM is unavailable. Actual WebGUI registration, session continuity, and core rollback require a clone.

## Baseline

Collect these results on each node before installation, with the service running, after a policy edit, and after removal. Save the output locally. Counters, lifetimes, ephemeral IDs, and session counts can change normally. Compare the effective rules, destination, next hop, and path for the same class of flows.

```sh
pfctl -sr
pfctl -sn
netstat -rn -f inet
netstat -rn -f inet6
ifconfig -a
/usr/local/sbin/swanctl --list-sas
```

Check relevant states in **Diagnostics → States**. Capture a test connection on the LAN and at the destination. With VTIs, capture on each tunnel interface as well. On physical WANs, verify external peer addresses and encapsulation. Observe the first useful packet and its reply at the client and destination. Verify packet delivery alongside the SA status.

## Observer acceptance matrix

| Test | Lab action | Expected evidence |
|---|---|---|
| Clean installation | Open every tab with an empty configuration. | Navigation works and there is no recommendation for a missing policy. Default route and pass rules match the baseline. |
| One path | Create a policy with one monitored member and make its target unavailable. | The member appears while eligible. Losing the reading or exceeding the SLA leaves the policy without an alternative. |
| Upgrade | Install the source version on each clone, save a single-member policy, and record its configuration. Apply the new package with the README installer and confirm service restart through package registration. | The local check identifies the new version. The policy loads, the service publishes a fresh sample, and the member still represents one path. |
| Dashboard widget | Use **+ → SD-WAN** under **Status → Dashboard**. Compare gateway IP, RTT, RTTsd, loss, and status with local telemetry. Check policy preference and the empty-member configuration. Stop the observer, wait for expiration, then remove the widget with **×**. | Valid measurements appear, expired data is unavailable, diagnostics permissions apply, and the widget can be removed. |
| Version check | Open **Updates**, check the installed version, click **Check GitHub**, then repeat with HTTPS egress unavailable. | A click triggers the external check. The page distinguishes a published version, a failed check, and unknown local version. Checking displays information. |
| Two healthy paths | Add members with real gateways, an SLA, and a policy using both members. Set different costs and check the lowest-latency strategy too. | The selection and reason match telemetry and the configured criterion. New flows follow the existing **native** rules. |
| Degradation with an active tunnel | Add loss or delay only to transport A using the WAN emulator. Wait for the dpinger window and observer cycle. | Confirm the effect on A under **Status → Gateways**. Record the first recommendation change and capture on both paths. Attribute any native rule failover separately. |
| Target failure | Take a monitor target offline and remove eligible candidates from a test policy. | The result reflects the member's loss of observability. A policy with no eligible members offers no healthy path. The real service and probe target can behave differently. |
| Missing sample and restart | Stop the observer normally, then test an unexpected worker exit on the clone. Interrupt the browser's dashboard requests and restore them. | A deliberate stop stays stopped. After an unexpected exit, the supervisor restarts the worker. The dashboard hides the old readings after 30 seconds without a valid refresh and recovers on a valid response. Native forwarding stays available. |
| Configuration integrity | Save a valid policy, try invalid references, and open the page in two sessions. Reopen it after restart. | The valid configuration persists. Validation errors and revision conflicts do not silently overwrite it. |
| Access control | Test as administrator, as a user without privileges, and after ending the session. Open direct URLs as well. | The WebGUI enforces permissions, including on save forms. |
| Reload | On a clone carrying traffic, reload using **Status → Filter Reload**. Repeat with the service stopped. | Routes, NAT, native policy, and management reachability match the baseline. In observation mode, forwarding rules are native. |
| HA | Install the same version and configure both test nodes. Keep a TCP session open and record its PF state on both nodes before shutting down the MASTER. Track VIPs, the original session, SAs, the first successful transaction, and telemetry on the new MASTER. | Time VIP transfer, application recovery, and IPsec renegotiation separately. Determine whether the original socket survived or reconnected. Node promotion and tunnel restart remain native responsibilities. [pfSense state synchronization](https://docs.netgate.com/pfsense/en/latest/highavailability/pfsync.html) |
| Removal | In **Diagnostics → Command Prompt**, run `pkg delete -y pfSense-pkg-SDWAN` and the README checks. Reload the WebGUI and reinstall the package. | The package leaves the local database. The process, menu, widget file, and sample file disappear. Record rule and route comparisons, preference retention, and reinstall results. |

Attribution is easier if the initial native policy fixes a path for the test flow. If a configured native gateway group fails over, repeat with the observer stopped and compare events. Native mechanisms can change routes independently of the package.

## Additional acceptance for active steering

The reviewed PF generator snapshot can omit package rules during a `packagelock` or when a generated rule fails validation. Verify that any mandatory VPN policy continues to apply during reload, upgrade, and package unavailability on the exact CE build.

1. Degrade A while both SAs remain up. Capture **new** sessions in the configured class on the expected path at both ends. Measure established flows and preserved NAT separately.
2. Remove both VTIs while leaving the physical WANs active. Generate a marked, repeating flow to a private test network. Capture physical egress after NAT and at the destination. Verify encryption while a tunnel is available and zero cleartext delivery of private traffic during the outage, reload, and module restart. Record capture drops.
3. With native forwarding over a default-route tunnel, verify that IKE, management, and more specific routes stay on their expected paths. When testing an experimental VTI binding, use a specific protected prefix. Repeat with an identical peer on both WANs and dynamic routes when those features are in scope.
4. Verify the same profile with pfSense↔pfSense, pfSense↔FortiGate, and a FortiGate↔FortiGate reference. Publish metrics by version and pairing, including loss, outage duration, and time to the first useful packet.

## Automated evidence and clone acceptance

The [Access and VPN recovery labs workflow](../.github/workflows/homologation.yml) runs five tests in isolated Ubuntu namespaces. Use the following commands to repeat the tests in a disposable VM with the workflow dependencies.

```sh
sudo python3 -B -u tests/lab/vpn-recovery.py openvpn
sudo python3 -B -u tests/lab/vpn-recovery.py wireguard
sudo python3 -B -u tests/lab/renew-dynamic-wan.py dhcp
sudo python3 -B -u tests/lab/renew-dynamic-wan.py pppoe
sudo python3 -B -u tests/lab/ipv6-pd.py
```

For VPN tests, keep the same protected network. Compare a verified 64 KiB transfer in each direction and the capture on each WAN. Separate access-network forwarding from tunnel recovery. The harness selects the WAN and, for WireGuard, reapplies the destination endpoint over that route. The peer must learn the current source from authenticated traffic. The tests exercise new flows after reconnection. Existing socket continuity and native pfSense behavior after a gateway change require a clone. [OpenVPN and Multi-WAN](https://docs.netgate.com/pfsense/en/latest/vpn/openvpn/multi-wan.html) · [WireGuard and namespaces](https://www.wireguard.com/netns/)

For access tests, DHCP renewal keeps the lease, and a new lease changes the address and next hop. PPPoE establishes a session, loses the link, and negotiates a new address pair. The PHP test passes both observed pairs to the monitor matcher. On CE, repeat with dpinger active and record the new process's source address, installed gateway, first accepted sample, and first successful transaction. In the IPv6-PD test, Kea delegates the prefix, the router advertises a /64 on the LAN, and the IPv6 client reaches the destination using that prefix. After withdrawal, the old path fails and the client resumes using the new prefix. Repeat on CE with the native access client and Router Advertisement service. [Kea prefix delegation](https://kea.readthedocs.io/en/kea-2.3.3/arm/dhcp6-srv.html#subnet-and-prefix-delegation-pools)

For HA and interoperability, use two CE 2.9.1 clones with independent consoles and isolated WAN A, WAN B, LAN, and synchronization segments. Prepare a reference peer and a FortiGate licensed for the chosen proposals. In each pairing, record VIP ownership, PF states, IKE and CHILD_SA negotiation, and the first application transaction during the same failure. Use **a management session independent of the interrupted path**. Record XMLRPC synchronization, dynamic routing, and restoration of the lab image snapshot. [Official CE installer](https://docs.netgate.com/pfsense/en/latest/install/download-installer-image.html) · [FortiGate-VM evaluation license limits](https://docs.fortinet.com/document/fortigate/7.2.10/administration-guide/441460) · [IPsec in HA](https://docs.netgate.com/pfsense/en/latest/highavailability/ipsec.html)

## Sources

- [Developing pfSense packages](https://docs.netgate.com/pfsense/en/latest/development/develop-packages.html)
- [FreeBSD port checks](https://docs.freebsd.org/en/books/porters-handbook/quick-porting/)
- [VTI on pfSense](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/routed-vti.html)
- [IPsec in HA, VTI assignment, DPD, and CARP VIPs](https://docs.netgate.com/pfsense/en/latest/highavailability/ipsec.html)
- [Pinned PF rule generator](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/filter.inc#L6098-L6162)
