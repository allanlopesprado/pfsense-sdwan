# Versioned policy pilot for a branch

Use this pilot with a preconfigured forwarding binding on an isolated pfSense CE clone. The NOC host keeps site enrollment, policy artifacts and imported reports. The root console tool applies one existing policy's SLA or strategy through the same configuration writer as the WebGUI. The console operation leaves members, probes, native rules and firewall routes under site administration.

Copy `tools/fleet-site.php` from a reviewed source revision to the appliance console. Keep the controller directory private to authorized operators. Use authenticated administrative transport for every import and transfer. Read the expected SHA-256 from the trusted controller before applying the transferred policy. The controller accepts locally supplied reports and has no appliance listener.

## Enroll, distribute and verify

On the controller host:

```sh
python3 tools/fleet-controller.py ./fleet enroll pilot
```

On the appliance, open a root console:

```sh
php /root/fleet-site.php enroll pilot
php /root/fleet-site.php status
```

Copy the report through the authenticated transport into `pilot.json` on the controller. Use its `config_sha256` as the expected settings revision. Use the site's existing policy and SLA names.

```sh
python3 tools/fleet-controller.py ./fleet report pilot pilot.json
python3 tools/fleet-controller.py ./fleet inventory
python3 tools/fleet-controller.py ./fleet publish pilot 1 '<config_sha256>' ERP lab balance
```

Copy the generated `revision-1.json` to the clone. On the clone, supply the expected SHA-256 shown by the controller.

```sh
php /root/fleet-site.php apply /root/revision-1.json '<sha256>'
php /root/fleet-site.php status
```

Recheck after the observer reloads PF. For acceptance, the report must show the revision, `drifted=false`, the expected trackers, and `applied` with the intended gateways. Open new LAN connections and compare the source seen by the remote server. Import the resulting report to inspect the inventory. Treat each report as evidence at its recorded `observed_at`, with fresh reads required after changes.

## Controller outage and rollback

The local observer, rules, and service checks continue to run while the controller is unavailable. From the root console, run `php /root/fleet-site.php rollback` to restore the last managed policy fields while their expected settings revision still matches. The appliance retains the highest accepted revision so the removed bundle cannot be replayed. Apply a higher new revision for the next change. Confirm the rollback in PF and with another new connection.

The site journal stores the original managed fields and the expected settings hashes before applying. On the next console operation, a change interrupted by restart can be reconciled when the actual settings match either side of that write. If settings changed independently, the console reports the conflict for review. Keep the native configuration backup and the root-owned journal local.

The two-WAN workflow's `fleet-pilot` scenario uses an isolated controller directory and CE appliance. It imports PF evidence after distributing ERP revision 1, removes the controller directory, verifies remote source addresses for ERP and backup and repeats the PF and reachability checks after rollback. [Appliance workflow](../.github/workflows/ce291-appliance.yml)
