# IKEv2 negotiation and rekey on Linux

The lab runs two independent strongSwan processes on Ubuntu 24.04. Each peer has its own network namespace, configuration, runtime directory, and control socket. A third namespace contains two isolated Ethernet bridges for transit captures. The external IPs are documentation addresses. The lab owns the inner IPs, routes, captures, and keys.

| Path | External addresses | Protected IPs | Kernel CHILD identifier |
|---|---|---|---|
| A | 192.0.2.1 and 192.0.2.2 | 10.241.1.1 and 10.241.1.2 | 101 |
| B | 198.51.100.1 and 198.51.100.2 | 10.241.2.1 and 10.241.2.2 | 102 |

Each path negotiates an IKE SA and a CHILD_SA using a pair of identities and a random preshared key unique to the run. Proposals use AES-128-GCM with a 128-bit tag and ECP-256, including for CHILD_SA rekey. The daemon installs IPsec associations and policies in the Linux kernel. Each protected pair has its own route and an nftables guard that requires the path's IPsec identifier for egress.

## Passing criteria

1. Before enabling the guard, the client and peer exchange pings. Transit captures see cleartext on both links to establish that the test can observe a leak.
2. Both pairs negotiate IKEv2 and ESP. The test compares each peer's outbound SPI with the other peer's inbound SPI. Probes must succeed from both ends, SA byte counters must increase, and ESP packets must carry the expected SPIs in both directions.
3. The initiator requests a CHILD_SA rekey on path A. Both ESP SPIs must change. It then rekeys A's IKE SA and checks the IKE SPI changes. Path B retains its associations. The test repeats the probe and ESP checks after each change.
4. The test terminates A's IKE SA and observes removal at both ends. A's protected probes must fail, local block counters must rise, and both transit captures must be free of cleartext ICMP between protected addresses. Path B must still answer over ESP.

The lab exercises two Linux strongSwan peers with separate protected address sets. It measures negotiation, rekey, and path isolation. Switching the same flow across pfSense tunnels, CARP failover during renegotiation, and FortiOS interoperability require separate tests. The egress guard is specific to this nftables lab.

## Two tunnels with the same selectors

The shared-selector case negotiates `0.0.0.0/0` on both sides of both CHILD_SAs using separate Linux XFRM interface IDs. Both tunnels can reach the same protected host pair. The lab verifies that negotiation leaves the default routing table without a default route. Captures distinguish requests and replies by each tunnel's ESP SPI.

The test starts with both peers using A. It then directs replies to B and verifies that requests stay on A with the same negotiated selectors. Aligning both peers on B restores symmetry. Removing B's SA while the route still points to it blocks the flow, with no cleartext observed. Both peers then return to A. This test isolates the effect of routing preferences. Validation of pfSense `reply-to`, FortiOS session policy, and end-to-end interoperability requires the two-firewall procedure. [strongSwan route-based VPNs](https://docs.strongswan.org/docs/5.9/features/routeBasedVpn.html) · [FortiGate acceptance](../../../docs/FORTIOS.md)

## Run the test

On an Ubuntu 24.04 lab VM with root access, network and mount namespaces, Linux XFRM, and nftables, install the distribution packages and start the test from the repository root.

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends iproute2 iputils-ping nftables tcpdump strongswan-charon strongswan-swanctl libstrongswan-standard-plugins
sudo python3 -B -u tests/lab/ikev2/run.py
sudo python3 -B -u tests/lab/ikev2/run.py --shared-selectors
```

After dependency installation, the lab runs without vendor images or external access. The script removes its processes, namespaces, test configurations and keys, and temporary captures. [IKEv2 tunnel checks workflow](../../../.github/workflows/ikev2.yml)

[strongSwan in Linux namespaces](https://docs.strongswan.org/docs/latest/howtos/nameSpaces.html) · [Connection and CHILD_SA configuration](https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html) · [Rekey command](https://docs.strongswan.org/docs/latest/swanctl/swanctlRekey.html) · [Status fields and counters](https://docs.strongswan.org/docs/latest/swanctl/swanctlListSas.html)
