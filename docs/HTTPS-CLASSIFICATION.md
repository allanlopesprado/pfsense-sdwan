# HTTPS policies by destination

Use dedicated IPv4 destinations to put two HTTPS services on independent SD-WAN policies. This profile uses the native ingress rule's destination and TCP port. A health check separately decides whether each WAN still reaches the service. On stock CE the package observes the probes. The matching lab adapter applies a policy to the associated PF rules. [Forwarding integration](INTEGRATION.md)

## Configure a test client

1. In **Firewall → Aliases**, create a Host alias per service, such as `ERP_TLS` and `BACKUP_TLS`. Use literal IPv4 addresses dedicated to the service. From the console run:

   ```sh
   php /root/check-https-destinations.php ERP_TLS BACKUP_TLS
   ```

   Copy [the read-only checker](../tools/check-https-destinations.php) to that path from the same Git revision. It checks the configured sets for duplicates across services. Confirm each live PF table separately under **Diagnostics → Tables**.

2. Limit the trial to a test host or VLAN. Use a LAN ingress pass rule for each alias and TCP/443, with its own dedicated gateway group. Put a native block with the same source, destination and port immediately below each pass, with no gateway selected. Keep management and VPN exceptions in their required positions. Place an explicit rule after both pairs for unknown TCP/443 and UDP/443. Choose the existing native path or block that traffic according to the test network's requirements. Leave this rule outside the SD-WAN bindings. [Alias types](https://docs.netgate.com/pfsense/en/latest/firewall/aliases.html) · [Gateway and rule ordering](https://docs.netgate.com/pfsense/en/latest/multiwan/policy-route.html)

3. Set one certificate-verified HTTPS readiness check per service and WAN, using the expected host routes. Bind each policy to its own group and verify the applied rule in **Forwarding**. Open a new connection from the LAN and compare the application's reported client address with the chosen WAN and active PF tracker.

## Shared addresses and encrypted handshakes

Two applications on one IP and port share the same network match. Leave the shared address on the chosen native fallback. CDN DNS can return different addresses to the client and the firewall, so this pilot uses fixed addresses. An alias that might move onto a shared address needs a separate operating policy. The checker evaluates the configured alias entries. The live table and packets provide separate evidence. [Alias resolution](https://docs.netgate.com/pfsense/en/latest/firewall/aliases-features.html#hostnames-in-aliases)

PF chooses the route and creates the state on the first packet. In HTTPS over ordinary TCP, the TLS ClientHello carrying SNI arrives after that choice. ECH protects the inner hostname. A QUIC Initial can carry the ClientHello on UDP. That would require protocol decoding outside the native PF match, and ECH still protects the inner name. The pilot sends UDP/443 to the explicit fallback and tests that transport separately. [PF states and routing](https://man.freebsd.org/cgi/man.cgi?query=pf.conf&sektion=5) · [SNI](https://www.rfc-editor.org/rfc/rfc6066.html#section-3) · [QUIC](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.2) · [ECH](https://www.rfc-editor.org/rfc/rfc9849.html)

## Appliance evidence

Use the **CE two-WAN appliance** workflow with `scenario=https-classification` on each supported CE release. It configures two IP-scoped services on TCP/443 and creates a private CA for the disposable HTTPS servers. It compares PF trackers, table membership, peer ingress counters and the source seen by the HTTPS server. When the ERP service fails on WAN1, the test requires the gateway and DNS to stay healthy, new ERP connections to use WAN2, and backup to continue on WAN1.

The same test checks that an overlapping alias is refused by the checker, that two HTTPS names on one unknown IP follow the native fallback, and that UDP/443 to the ERP destination follows that same fallback. It checks the fallback rule's own counters and repeats both HTTPS flows after recovery. The UDP test supplies a transport datagram, and the appliance output records evidence for the tested destination profile. [Workflow](../.github/workflows/ce291-appliance.yml) · [Scenario](../tests/lab/ce-shared-target.py)
