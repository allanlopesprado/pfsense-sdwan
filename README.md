# SD-WAN for pfSense CE

An experimental package for monitoring links, comparing gateways against SLAs, and viewing path recommendations in the **pfSense CE 2.9.1** WebGUI. This project is independent of Netgate.

[Download the latest release](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest) · [Installation](#install-from-diagnostics--command-prompt) · [Changelog](CHANGELOG.md) · [Lab results](docs/RESULTS.md)

[![Package checks](https://github.com/allanlopesprado/pfsense-sdwan/actions/workflows/checks.yml/badge.svg?branch=main)](https://github.com/allanlopesprado/pfsense-sdwan/actions/workflows/checks.yml)

## What the package does

- **Dashboard** shows each gateway's IP address, RTT, RTT standard deviation, loss, and status.
- **Policies** rank paths by latency, packet loss, and cost. **Diagnostics** explains how each candidate was evaluated.
- **Status → Services** lists the `sdwan` service with native controls. Events appear under **Status → System Logs → General**.
- **Updates** checks GitHub, verifies the SHA-256 checksum, and installs the published release from the WebGUI.

![SD-WAN widget showing metrics and status for three gateways in the light theme](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest/download/widget-light-554.png)

[Dark-theme widget](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest/download/widget-dark-554.png) · [Status screen](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest/download/status-pfSense.png) · [Updates screen](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest/download/updates-pfSense.png)

| Environment | Use |
| --- | --- |
| **Stock pfSense CE 2.9.1** | Gateway monitoring, SLA evaluation, and path recommendations. |
| **pfSense CE 2.9.1 with the lab core** | Policy-based forwarding experiments with the [core adapter](core/README.md) and a dedicated native gateway group. |

<a id="como-instalar-pelo-diagnostics--command-prompt"></a>

## Install from Diagnostics → Command Prompt

1. On a lab clone, open **Diagnostics → Command Prompt** with administrative access. Run `cat /etc/version && pkg config ABI` to confirm **CE 2.9.1** and **FreeBSD:16:amd64**.
2. Run the line below. It downloads the package from a pinned revision to a temporary directory, verifies SHA-256, and installs it with `pkg`.

<!-- install-command -->
```sh
d=$(mktemp -d /tmp/sdwan.XXXXXXXX) && (trap 'rm -rf "$d"' EXIT; p="$d/pfSense-pkg-SDWAN-0.4.17.pkg"; fetch -o "$p" 'https://raw.githubusercontent.com/allanlopesprado/pfsense-sdwan/3e96d30ab2540ef163eb8c819baf1e6a4883f465/dist/pfSense-pkg-SDWAN-0.4.17.pkg' && sha256 -c ec7e17ae797071f14daa82e8c2697df565f9df2e2d52f49461d710578ced70ca "$p" && pkg add "$p")
```

3. Open **Services → SD-WAN**. Check the service under **Status → Services** and the installed version under **SD-WAN → Updates**.

If installation defers WebGUI registration, wait for PHP-FPM to return and run `/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-SDWAN POST-INSTALL`. [Lab installation and verification](docs/LAB.md#build-and-install)

## Configure and update

1. Confirm measurements in **Status → Gateways** and add the links under **Services → SD-WAN → Members**.
2. Set RTT and packet loss limits in **Performance SLAs**, then assign the links to a policy in **Policies**.
3. Review the decision in **Status** and **Diagnostics**. Under **Status → Dashboard**, use **+ → SD-WAN** to add the widget.

For installations running **0.4.8** or later, open **SD-WAN → Updates**, click **Check GitHub**, and select **Upgrade to …** when a release is available. This action uses the native package installation privilege.

[pfSense log settings and severity](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/settings.html) · [Removal and rollback](docs/LAB.md#removal-and-rollback)

## Development and validation

- [Versioning and publishing](docs/VERSIONING.md)
- [Configuration impact matrix](docs/CONFIGURATIONS.md)
- [Validation scenarios and tests](docs/VALIDATION.md)
- [Lab results and evidence](docs/RESULTS.md)
- [IPsec, CARP, NAT, and routing integration](docs/INTEGRATION.md)
- [FortiOS interoperability](docs/FORTIOS.md)

Run `sh tests/run.sh` with PHP CLI 8.2+, Python 3, and a POSIX shell. After installation, run [`verify-appliance.sh`](tools/verify-appliance.sh) with the expected version to check the package, WebGUI registration, service, and current sample.
