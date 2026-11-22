# SD-WAN for pfSense CE

An experimental package for monitoring links, comparing gateways against SLAs, and viewing path recommendations in the **pfSense CE 2.9.1 and 2.9.2** WebGUI. This project is independent of Netgate.

[Download the latest release](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest) · [Installation](#install-from-diagnostics--command-prompt) · [Changelog](CHANGELOG.md) · [A/B benchmarks and raw data](docs/benchmarks/README.md)

[![Package checks](https://github.com/allanlopesprado/pfsense-sdwan/actions/workflows/checks.yml/badge.svg?branch=main)](https://github.com/allanlopesprado/pfsense-sdwan/actions/workflows/checks.yml)

## What the package does

- **Dashboard** shows each gateway's IP address, RTT, RTT standard deviation, loss, and status.
- **Policies** select a path by latency or cost, or distribute new connections across healthy links with the native forwarding adapter. **Diagnostics** shows SLA and TCP, DNS or HTTPS results.
- **Status → Services** lists the `sdwan` service with native controls. Events appear under **Status → System Logs → General**.
- **Updates** checks GitHub, verifies the SHA-256 checksum, and installs the published release from the WebGUI.

![SD-WAN widget showing verified egress, backup availability and policy status in the light theme](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest/download/widget-light-554.png)

[Dark-theme widget](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest/download/widget-dark-554.png) · [Status screen](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest/download/status-pfSense.png) · [Updates screen](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest/download/updates-pfSense.png)

| Environment | Use |
| --- | --- |
| **Stock pfSense CE 2.9.1 or 2.9.2** | Gateway monitoring, SLA evaluation, and path recommendations. |
| **pfSense CE 2.9.1 or 2.9.2 with the matching lab core** | Policy-based forwarding experiments with the [core adapter](core/README.md) and a dedicated native gateway group. |

<a id="como-instalar-pelo-diagnostics--command-prompt"></a>

## Install from Diagnostics → Command Prompt

1. On a lab clone, open **Diagnostics → Command Prompt** with administrative access. Run `cat /etc/version && pkg config ABI` to confirm **CE 2.9.1 or 2.9.2** and **FreeBSD:16:amd64**.
2. Run the line below. It downloads the package from a pinned revision to a temporary directory, verifies SHA-256, and installs it with `pkg`.

<!-- install-command -->
```sh
d=$(mktemp -d /tmp/sdwan.XXXXXXXX) && (trap 'rm -rf "$d"' EXIT; p="$d/pfSense-pkg-SDWAN-0.4.28.pkg"; fetch -o "$p" 'https://raw.githubusercontent.com/allanlopesprado/pfsense-sdwan/17c95ad19d322866f2ade3a3c6147276415f535a/dist/pfSense-pkg-SDWAN-0.4.28.pkg' && sha256 -c c23dfbc1f1484469e9831a5099402c93a5a22d4bd9c0f339ab42d6a074398fe5 "$p" && pkg add "$p")
```

3. Open **Services → SD-WAN**. Check the service under **Status → Services** and the installed version under **SD-WAN → Updates**.

If installation defers WebGUI registration, wait for PHP-FPM to return and run `/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-SDWAN POST-INSTALL`. [Lab installation and verification](docs/LAB.md#build-and-install)

The install progress reports the observer's start or restart separately from package registration. Check the SD-WAN Status page for a current observation before using forwarding. If the service action fails, check Status > Services and System Logs.

## Configure and update

1. Confirm measurements in **Status → Gateways** and add the links under **Services → SD-WAN → Members**.
2. Set RTT, loss and optional RTT standard deviation limits in **Performance SLAs**. To monitor application reachability, configure TCP, DNS or HTTPS checks in **Members** with dedicated native host routes. A TCP check such as tcp://192.0.2.20:587 verifies the connection. An HTTPS check also verifies the certificate and response.
3. Select a strategy in **Policies** and review **Diagnostics**. Use **Forwarding** to inspect the gateway group, paired rules and active PF paths. Under **Status → Dashboard**, use **+ → SD-WAN** to see policy status, verified egress for new connections and SLA-eligible backup paths.

For installations running **0.4.8** or later, open **SD-WAN → Updates**, click **Check GitHub**, and select **Upgrade to …** when a release is available. This action uses the native package installation privilege.

On CE 2.9.2, upgrade manually once from SD-WAN 0.4.27 or earlier. Version 0.4.28 and later recognize CE 2.9.2 in the Updates tab.

[pfSense log settings and severity](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/settings.html) · [Removal and rollback](docs/LAB.md#removal-and-rollback)

## Development and validation

- [Versioning and publishing](docs/VERSIONING.md)
- [Configuration impact matrix](docs/CONFIGURATIONS.md)
- [Validation scenarios and tests](docs/VALIDATION.md)
- [A/B benchmarks, timings, and raw data](docs/benchmarks/README.md)
- [Lab results and evidence](docs/RESULTS.md)
- [Compatibility with IDS, IPS, and other packages](docs/PACKAGE-COMPATIBILITY.md)
- [IPsec, CARP, NAT, and routing integration](docs/INTEGRATION.md)
- [FortiOS interoperability](docs/FORTIOS.md)

Run `sh tests/run.sh` with PHP CLI 8.2+, Python 3, and a POSIX shell. After installation, run [`verify-appliance.sh`](tools/verify-appliance.sh) with the expected version to check the package, WebGUI registration, service, and current sample.
