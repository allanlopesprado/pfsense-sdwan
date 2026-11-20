# CE 2.9.1 appliance acceptance

The appliance workflow creates a disposable UFS disk using the official Netgate CE 2.9.1 signed archives. It verifies the Netgate repository fingerprint, the system package digest used for the adapter, and the installed kernel and userland version. The workflow installs the system packages on the guest with the native package manager. This method prepares a test disk for the exact release without using the Netgate Installer interface.

The guest has three virtio interfaces attached to isolated QEMU taps. The Linux runner creates separate client and fake provider namespaces with documentation addresses. The guest has no interface on the runner's Internet-facing network. The system artifacts needed for installation are downloaded and checked by the preparation VM before the guest boots.

The test installs SD-WAN 0.4.28 with its package hooks, checks stock observation mode, applies the audited adapter and binds the two policies through the package APIs. It removes only the ERP path through the first fake provider. The test checks the native reload receipt, the PF trackers and the return payloads with the source seen by the peer. It also exercises original TCP state preservation, recovery, both WANs unavailable, a reboot with the native observer and reload service, unbinding with stock filter restoration, and a package downgrade to 0.4.27.

Start the [appliance workflow](../.github/workflows/ce291-appliance.yml) on branch `lab/ce291-appliance` by pushing a commit or dispatching it when available. The accept result reports stage markers and explicitly verifies the package version before and after the downgrade. The serial console and the test transcript are the only uploaded artifacts.

