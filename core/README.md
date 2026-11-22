# pfSense rule generator integration

ABI 2 adds weighted round-robin across eligible next hops for approved ingress rules. To honor native sticky connections on balance policies, use the adapter from 0.4.28 or later. The package still supports a single active next hop on ABI 1. This release uses public source identified as `2.9.0-DEVELOPMENT` at revision `9363ac5b8651a1c7a333180425ce7719070f95f9`. The preparation tool also accepts the audited rule generator from the signed CE 2.9.1 and 2.9.2 system packages. [Pinned rule generator source](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/filter.inc)

## Prepare source on the build host

Use Python 3 and Git in a workspace containing this project as `pfsense-sdwan`. Choose a new output directory.

```sh
git clone https://github.com/pfsense/pfsense.git pfsense-base
git -C pfsense-base checkout --detach 9363ac5b8651a1c7a333180425ce7719070f95f9
python3 pfsense-sdwan/tools/prepare-core.py --source pfsense-base --out sdwan-core-lab
git diff --no-index pfsense-base/src/etc/inc/filter.inc sdwan-core-lab/src/etc/inc/filter.inc
```

The last command displays the diff and returns 1 when there are changes. The tool checks the original file's SHA-256, patches a copy, and generates two files under `sdwan-core-lab/src/etc/inc`. Incorporate both into the matching revision used by the image build. Before porting to another base, compare gateway inventory, rule generation, XML parsing, and filter reload behavior. Restoring the clone snapshot recovers its reference image. [Building away from the firewall](https://docs.netgate.com/pfsense/en/latest/development/compile-software.html) · [Image tests and rollback](../docs/LAB.md)

Restart the SD-WAN service after changing the native adapter so its long-running PHP process loads the updated generator. Use a dedicated gateway group and verify that a fresh connection follows the policy while the system default route stays on the original WAN.

### Signed CE 2.9.1 and CE 2.9.2 lab copies

The [two-WAN appliance workflow](../.github/workflows/ce291-appliance.yml) extracts the audited rule generator from the signed Netgate system package for each target. Both audited packages contain a `src/etc/inc/filter.inc` with SHA-256 `70758089d12a271ff08ccf3e20a180d3f441f8d468e984be6b1476c366c66c30`. Use `--ce-292-lab` for this fingerprint from either package. Use `--ce-291-lab` for the previously audited CE 2.9.1 copy with SHA-256 `6acd8621e4f88660759c5656488d81f580b49f4c9848b19048ae6a2570e177b4`.

The workflow has verified two-path traffic, filter reloads, reboot, and rollback on both versions. Verify those behaviors on a clone of the target image before deployment. A firmware upgrade can replace the patched generator. Generate the overlay from the signed package for the installed version, then check the active PF rules and restart SD-WAN after installing the matching overlay. [Netgate CE 2.9.2 release notes](https://docs.netgate.com/pfsense/en/latest/releases/26-07-2_2-9-2.html)

## Forwarding scope

The generator uses the next hops that pfSense calculated for the current reload. A binding identifies the approved rule trackers, address family, dedicated group, members, and revision of the match conditions. It uses the same gateway or weighted pool across all trackers in a full rule generation. Without a valid sample, recompiling the filter turns a bound rule into a block. Preflight also requires a permanent native block with the same scope immediately after the pass rule, for cases in which pfSense omits a rule.

Wide destinations can trigger pfSense exceptions for VPN and static-route networks. Inspect the `negate_networks` table and effective rule order. To preserve local services when all members fail, put the required exceptions in native rules above the pass/block pair. If no usable path exists, the TCP block also covers stateless segments. Explicit TCP flag constraints on the rule remain part of the selector.

The policy applies to new connections that reach the rule. Review earlier rules, NAT, firewall-originated traffic, and established states separately. The operator manages the block rule. The PF gateway group label includes the tier of the selected member, so native gateway recovery can kill states according to the operator's settings. The observer reserves up to three reload attempts per unresolved decision. A native queue acknowledgement remains pending until the observer sees the expected rule in PF. Confirmation resets the retry budget, and changing the selected path or its resolved next hop starts a new decision. When the supervisor restarts the worker, the worker retires the prior snapshot and waits for PF to show that the bound pass rules are absent before publishing a new choice. If the supervisor is also unavailable or the worker hangs, expiration of the snapshot prevents new filter generations from using it, and the last rule can remain in the kernel until a native reload. Check PF counters and captures in both directions. Use **Forwarding** to unbind a policy and restore the native gateway group decision.

Forwarding confirmation compares the loaded packet selectors with the approved interface rule and verifies the paired native block. PF can expand one TCP/UDP rule into two entries with the same identifier. Confirming the pair requires both protocol entries and both blocks. The observer can detect full coverage by an earlier simple quick rule. For package anchors, table contents, and complex floating matches, use a fresh connection and packet captures on the expected ingress and egress. [Floating rule precedence](https://docs.netgate.com/pfsense/en/latest/firewall/floating-rules.html)

After removing a binding, Forwarding displays the verification status until the observer sees the affected trackers leave PF or identifies a native filter generation that no longer delegates those trackers. The updated adapter records its frozen tracker list and the pfSense ruleset hash after a successful load or a verified no-op. The observer checks that hash against the active default-deny rules. Earlier adapters can confirm absence of an affected tracker. If the native rule reuses the tracker, confirmation requires the updated adapter. A stopped observer leaves its pending receipt available to Forwarding and to the next observer process. [Viewing the PF ruleset](https://docs.netgate.com/pfsense/en/latest/firewall/pf-ruleset.html)

The system's `0.0.0.0/0` route and IKE endpoints remain under native control. A direct WAN policy can use broad destinations with a scoped source, compatible return routes, and earlier local exceptions. A VTI binding requires a specific protected address or prefix. The pilot requires at least two paths and separate groups for WANs and VTIs. For high availability, validate each CARP VIP, SA recovery, and the first successful transaction. [Integration matrix](../docs/INTEGRATION.md)
