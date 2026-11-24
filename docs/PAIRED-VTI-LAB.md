# Stage a hub and branch VTI

This pilot prepares and reconciles **offline configuration copies** for an IPv4, IKEv2 PSK tunnel between two pfSense CE clones. Native pfSense owns the deployment and verification of IKE, routes and PF. Keep two out-of-band consoles and a snapshot for each clone. Keep exports and rollback copies private because pfSense configurations can contain credentials. [Native VTI setup](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/routed-vti.html) · [Native backup and restore](https://docs.netgate.com/pfsense/en/latest/backup/restore.html)

## Prepare both views in pfSense

1. On each clone, record `cat /etc/version` and `pkg config ABI`, the current WAN and LAN assignments and the applicable native rules. Leave the default route and NAT settings under their original configuration.
2. Enable native IPsec and create a quick IPv4 egress block on the WAN for the peer's private LAN prefix, ahead of any applicable pass. Keep management access on the independent console and management network. Export this baseline as `current.xml` for each site.
3. In separate working snapshots, save a Phase 1 bound to the declared WAN and peer with matching IKEv2 proposals and PSK. Enter the key in each native console. Save a VTI Phase 2 with reversed inner addresses and matching ESP proposals. Assign and enable the new VTI interface, define its gateway using the peer VTI address, and add a route only for the peer LAN. Export the staged copy as `staged.xml`. The plan uses the saved Phase 1 ID, Phase 2 request ID and assigned interface names.

Use a private working directory named `lab` containing `hub/current.xml`, `hub/staged.xml`, `branch/current.xml` and `branch/staged.xml`. Use a separate directory per rollout. This example plan contains synthetic addresses:

```json
{
  "schema": 1,
  "sites": [
    {
      "name": "hub", "wan": "wan", "vti": "opt2", "gateway": "VTI_BRANCH",
      "outer": "198.51.100.1", "inner": "169.254.33.1/30", "lan": "10.44.0.0/24",
      "ikeid": 11, "reqid": 101
    },
    {
      "name": "branch", "wan": "wan", "vti": "opt3", "gateway": "VTI_HUB",
      "outer": "203.0.113.1", "inner": "169.254.33.2/30", "lan": "10.45.0.0/24",
      "ikeid": 12, "reqid": 102
    }
  ]
}
```

```sh
python3 tools/paired-vti.py ./lab ./plan.json preview
python3 tools/paired-vti.py ./lab ./plan.json apply
```

Compare the preview with both consoles. The tool checks both configurations before updating either offline copy. It checks the native objects, WAN block, LAN prefixes, reciprocal tunnel addresses and matching keys. The preview prints scoped identifiers and hashes. A failure during the second write restores the first copy if it still matches the applied fingerprint. The original files are saved as `before-vti.xml`. For a complete or interrupted operation, check both fingerprints and use `python3 tools/paired-vti.py ./lab ./plan.json rollback`. If another operation changed either configuration, review both copies before compensating.

## Validate on two clones

Review the native **Backup & Restore** diff for each copy. Apply the prepared configuration through the native consoles during an exclusive change window and verify each assigned VTI, parent WAN and native block. Leave the WAN block active throughout. If one console applies and the other rejects its configuration, compare the live configuration with the applied copy. Restore the private original snapshot on the first console when it matches. If the live state is unclear or was edited independently, keep both WAN blocks active and reconcile both consoles before restoring. The offline utility never writes to the appliances.

Verify `swanctl --list-sas`, `route -n get <peer-LAN-host>`, `pfctl -P -sr` and captures on the VTI and physical WAN. Require a new LAN connection to the peer LAN in both directions. Disable the lab SA and prove that the protected flow produces no cleartext packets on the physical WAN. Record versions, SA IDs, trackers, peer source and response. Repeat after rollback. The automated Python fixture validates offline compensation and scope. This PR has no evidence from two paired CE appliances yet.
