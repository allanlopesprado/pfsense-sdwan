# Verify a client's round trip on a clone

Use this test when you know which LAN interface receives the flow and which interface should forward it. Captures run at two points on the same firewall. A lab client sends an IPv4 ping to a dedicated ICMP responder. To check another circuit, repeat with its interface. For a VTI, use the interface carrying the inner flow.

**In the clone shell**, run the repository's collector. Replace the sample interfaces and documentation addresses. The arguments are the LAN interface, expected egress interface, client IP on LAN, client's post-NAT source IP on egress, target IP, and duration in seconds. With no NAT, repeat the client IP in the fourth argument. For a VLAN, use its assigned logical interface.

```sh
sh tests/lab/observe-path.sh vtnet1 vtnet2 192.0.2.10 198.51.100.20 203.0.113.50 20
```

**On the client**, wait for `Captures ready`, then run a new ping process and let it finish. Stop other pings between the same addresses first. Reserve a dedicated target during the capture when several clients share the translated IP.

```sh
ping -c 3 203.0.113.50
```

The collector correlates the four events using ICMP echo type, direction, and sequence. NAT can change the identifier between LAN and egress. Three replies with no loss produce the following result.

```json
{"result":"round_trip_observed","window_s":20,"lan_requests":3,"path_requests":3,"path_replies":3,"lan_replies":3,"complete_sequences":3}
```

| Result | Interpretation |
|---|---|
| `round_trip_observed` | Each observed sequence has a request and reply on both interfaces. Compare counts with the client's sent and received pings. |
| `incomplete` | At least one sequence lacks one of the four events. Use the counts to identify the last observed step. Verify translation, the interface, the return path, and state. |
| `no_samples` | The capture window ended without matching packets. Check that both captures were active and that the target and interfaces are correct. |
| `multiple_flows` | At least one interface saw multiple ICMP identifiers. Repeat with one ping process and a dedicated target. |

The exit code is `0` for an observed round trip, `1` for the other three results, and `2` for capture errors, kernel drops, incomplete decoding, or invalid arguments. JSON output contains counts only. Private temporary files hold identifiers, sequence numbers, and tcpdump diagnostics during the test. The process removes them on exit. The report excludes raw packets, configuration, and IPsec material.

Run one window before failure and another after switchover with a new ping process. Record application results and the alternate path separately. ICMP results require additional checks for TCP, UDP, IPv6, a return path through another firewall, tunnel confidentiality, and selector coverage. For IPsec containment, also capture on candidate WANs for cleartext traffic to the private destination, including after NAT. Verify encapsulated traffic, tunnel counters, and delivery at the peer. [Netgate multi-WAN troubleshooting](https://docs.netgate.com/pfsense/en/latest/troubleshooting/multi-wan.html)
