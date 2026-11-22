# SD-WAN for pfSense CE

[![Package checks](https://github.com/allanlopesprado/pfsense-sdwan/actions/workflows/checks.yml/badge.svg?branch=main)](https://github.com/allanlopesprado/pfsense-sdwan/actions/workflows/checks.yml)

An experimental package for monitoring WAN links, assessing application reachability, and comparing gateways against policy SLAs in **pfSense CE 2.9.1 and 2.9.2**. This project is independent of Netgate.

[Install](#install-from-diagnostics--command-prompt) · [Latest release](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest) · [Documentation](docs/README.md) · [Changelog](CHANGELOG.md)

## What the package does

| Environment | Behavior |
| --- | --- |
| **Stock pfSense CE** | The observer reads native gateway measurements and recommends paths. Native rules govern forwarding. |
| **CE with the matching lab core** | The experimental [core adapter](core/README.md) applies policies to explicitly bound ingress rules. Policies can prefer lower latency or cost, or distribute new connections across eligible links. |

The dashboard shows gateway health and backup availability, with verified egress for active bindings. **Diagnostics** explains SLA and service probe results. Events appear under **Status → System Logs → General**.

![SD-WAN dashboard widget showing verified egress, backup availability and gateway health](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest/download/widget-light-554.png)

[Dark theme](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest/download/widget-dark-554.png) · [Status screen](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest/download/status-pfSense.png) · [Updates screen](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest/download/updates-pfSense.png)

<a id="como-instalar-pelo-diagnostics--command-prompt"></a>

## Install from Diagnostics → Command Prompt

1. Open **Diagnostics → Command Prompt** on a lab clone with administrative access. Run `cat /etc/version && pkg config ABI` to confirm **CE 2.9.1 or 2.9.2** and **FreeBSD:16:amd64**.
2. Run the pinned install command. It verifies the package's SHA-256 before calling `pkg add`.

<!-- install-command -->
```sh
d=$(mktemp -d /tmp/sdwan.XXXXXXXX) && (trap 'rm -rf "$d"' EXIT; p="$d/pfSense-pkg-SDWAN-0.4.28.pkg"; fetch -o "$p" 'https://raw.githubusercontent.com/allanlopesprado/pfsense-sdwan/17c95ad19d322866f2ade3a3c6147276415f535a/dist/pfSense-pkg-SDWAN-0.4.28.pkg' && sha256 -c c23dfbc1f1484469e9831a5099402c93a5a22d4bd9c0f339ab42d6a074398fe5 "$p" && pkg add "$p")
```

3. Open **Services → SD-WAN** and check for a current observation. The `sdwan` service is listed in **Status → Services**. **SD-WAN → Updates** shows the installed version.

If WebGUI registration is deferred, wait for PHP-FPM to return and run `/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-SDWAN POST-INSTALL`. [Lab installation and verification](docs/LAB.md#build-and-install)

## Configure and update

1. Confirm monitoring in **Status → Gateways**, then select the gateways in **SD-WAN → Members**.
2. Set RTT, loss, and optional RTT standard deviation limits in **Performance SLAs**. Add TCP, DNS, or HTTPS service checks in **Members** when the policy needs application-level reachability. Each check requires a dedicated native host route.
3. Choose a strategy in **Policies** and check the decision in **Diagnostics**. With the lab core, use **Forwarding** to inspect the bound group and active PF rules. Add the SD-WAN widget under **Status → Dashboard**.

For SD-WAN **0.4.8** and later, open **SD-WAN → Updates**, click **Check GitHub**, and select **Upgrade to …**. Upgrading requires the native package installation privilege. On **CE 2.9.2**, use the manual install command once from SD-WAN **0.4.27 or earlier**. [Removal and rollback](docs/LAB.md#removal-and-rollback)

## Development and validation

[Validation coverage](docs/VALIDATION.md) · [Lab results](docs/RESULTS.md) · [Benchmarks and raw data](docs/benchmarks/README.md) · [Versioning and publishing](docs/VERSIONING.md)

Run `sh tests/run.sh` from a full Git checkout with PHP CLI 8.2+, Python 3, a POSIX shell, ShellCheck and xmllint. After installation, run [`verify-appliance.sh`](tools/verify-appliance.sh) with the expected version to check the package, WebGUI registration, service, and current sample.
