# CE 2.9.1 appliance acceptance

The appliance workflow creates a disposable UFS disk using the official Netgate CE 2.9.1 signed archives. It verifies the Netgate repository fingerprint, the system package digest used for the adapter, and the installed kernel and userland version. The workflow installs the system packages on the guest with the native package manager. This method prepares a test disk for the exact release without using the Netgate Installer interface.

The guest has three virtio interfaces attached to isolated QEMU taps. The Linux runner creates separate client and fake provider namespaces with documentation addresses. The guest has no interface on the runner's Internet-facing network. The system artifacts needed for installation are downloaded and checked by the preparation VM before the guest boots.

The test installs SD-WAN 0.4.28 with its package hooks, checks stock observation mode, applies the audited adapter and binds the two policies through the package APIs. It removes only the ERP path through the first fake provider. The test checks the native reload receipt, the PF trackers and the return payloads with the source seen by the peer. It also exercises original TCP state preservation, recovery, both WANs unavailable, a reboot with the native observer and reload service, unbinding with stock filter restoration, and a package downgrade to 0.4.27.

## Extended acceptance checks

| Scenario | Required evidence |
| --- | --- |
| Package upgrade | The native package manager replaces 0.4.27 with the candidate and the stored policy digest matches the original. |
| Same service IP on two WANs | Concurrent TCP probes use FIB 1 and FIB 2. Provider counters identify both ingress interfaces, both replies report the expected client source, and FIB 0's default route and PF NAT match the baseline. |
| Unapplied native reload | The native queue acknowledges each request while the disposable renderer keeps the ERP tracker on WAN1. The observer keeps its retry receipt through a service restart, logs persistent divergence after the third attempt and resets the attempt counter on verified convergence. |
| Stale observation | The paused observer's sample expires. A native reload blocks both approved policies, management remains reachable and the expiry is recorded in System Logs when the observer resumes. |
| WAN2 DHCP | The isolated provider issues a new IPv4 address and router to the native DHCP client. The ERP tracker uses the current next hop and the remote service returns the new NAT source while backup continues on WAN1. PF retains the original NAT rule structure and the default route. The original lease and NAT address are then restored. |
| Management and VTI | The LAN WebGUI presents the same certificate during failures and rollback. A LAN packet routed to a VTI without an SA increments the kernel no-SA counter and sends no protected packet in cleartext to the provider. |
| Established TCP | Held sockets are checked during service interruption, during simultaneous WAN loss, after connectivity returns and across native rollback and package downgrade. |

Start the [appliance workflow](../.github/workflows/ce291-appliance.yml) on branch `lab/ce291-appliance` by pushing a commit or dispatching it when available. The accept result reports stage markers and explicitly verifies the package version before and after the downgrade. The serial console and the test transcript are the only uploaded artifacts.

## Verified result

Run [44836162263](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44836162263) passed on commit adcf677441cf15527b68c87edd75c534aa4bee99 and uploaded the console and traffic transcript as **ce291-result**.

- During the ERP-only outage, tracker 41001 used vtnet2 via 203.0.113.2 and the ERP peer saw 203.0.113.1. The backup peer continued to see 198.51.100.1. WAN1 DNS and gateway checks kept responding.
- Renewing WAN2 changed the next hop from 203.0.113.2 to 203.0.113.3 and the ERP peer saw 203.0.113.4. The NAT rules used the new IPv4 address on WAN2 and the default remained 198.51.100.2 through vtnet0.
- After simultaneous WAN loss, existing TCP sessions resumed on their original path. New connections were blocked until recovery. Sockets established after the reboot also survived native rollback and package downgrade.

The [package matrix](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44836162319) passed on the same commit. The [reproducible build](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44833021102) produced identical packages from the runtime sources used by this appliance.
