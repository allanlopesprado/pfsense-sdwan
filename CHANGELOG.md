# Changelog

Versions are listed newest first, in numeric order. The [dist directory](dist/) contains the lab packages and their checksums. The current distribution is available from [GitHub Releases](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest).

| Version | Main changes | Notes |
| --- | --- | --- |
| 0.4.29 | Protect forwarding against configuration changes, harden policy service checks, and restore the previous package after a failed upgrade. | [Notes](docs/releases/v0.4.29.md) |
| 0.4.28 | Enable CE 2.9.2 updates and verify PF reconciliation, supervised recovery, sticky pools, and VTI transports. | [Notes](docs/releases/v0.4.28.md) |
| 0.4.27 | Verify native rule reloads, check dynamic next hops and validate DNS answers. | [Notes](docs/releases/v0.4.27.md) |
| 0.4.26 | Show verified egress and backup availability per policy in the dashboard widget. | [Notes](docs/releases/v0.4.26.md) |
| 0.4.25 | Align Status, Diagnostics, Forwarding and the dashboard widget with the native WebGUI. | [Notes](docs/releases/v0.4.25.md) |
| 0.4.24 | Add source-bound TCP service checks with dedicated native host routes. | [Notes](docs/releases/v0.4.24.md) |
| 0.4.23 | Add service-aware SLAs, weighted forwarding, guided setup and selective session recovery. | [Notes](docs/releases/v0.4.23.md) |
| 0.4.22 | Edit active policy settings in place and verify the selected path against PF. | [Notes](docs/releases/v0.4.22.md) |
| 0.4.21 | Protect sources covered by policy-based IPsec full tunnels from direct WAN steering. | [Notes](docs/releases/v0.4.21.md) |
| 0.4.20 | Preserve active forwarding bindings when pfSense reloads XML configuration. | [Notes](docs/releases/v0.4.20.md) |
| 0.4.19 | Expire dashboard readings after a lost refresh and restart the observer after an unexpected exit. | [Notes](docs/releases/v0.4.19.md) |
| 0.4.18 | Remove the preferred policy label and link from gateway rows in the dashboard widget. | [Notes](docs/releases/v0.4.18.md) |
| 0.4.17 | Remove the sample timestamp from the Status page. | [Notes](docs/releases/v0.4.17.md) |
| 0.4.16 | Invalidate samples after changes to monitored gateways and document the impact of native settings. | [Notes](docs/releases/v0.4.16.md) |
| 0.4.15 | Remove the service banner from the Status tab. | [Notes](docs/releases/v0.4.15.md) |
| 0.4.14 | Show the recommendation, decision reason, SLA limits, and highlighted measurements in gateway diagnostics. | [Notes](docs/releases/v0.4.14.md) |
| 0.4.13 | Add native service controls to the SD-WAN toolbar and show observer state in Status. | [Notes](docs/releases/v0.4.13.md) |
| 0.4.12 | Register the service as `sdwan` and add native shortcuts under Status → Services. | [Notes](docs/releases/v0.4.12.md) |
| 0.4.11 | Fix initial focus on the System Logs button. | [Notes](docs/releases/v0.4.11.md) |
| 0.4.10 | Remove the Installed Packages shortcut from Updates. | [Notes](docs/releases/v0.4.10.md) |
| 0.4.9 | Use the native gateway monitoring layout for the widget, including IP address, RTTsd, and status. | [Notes](docs/releases/v0.4.9.md) |
| 0.4.8 | Upgrade from the Updates tab, with package and service verification. | [Notes](docs/releases/v0.4.8.md) |
| 0.4.7 | Show one row per gateway in the widget, with RTT, loss, and status. | [Notes](docs/releases/v0.4.7.md) |
| 0.4.6 | Validate physical dependencies, require a protected VTI destination, and test one to three links. | [Notes](docs/releases/v0.4.6.md) |
| 0.4.5 | Revise the widget, validate the Monitor IP, and test with real dpinger processes. | [Notes](docs/releases/v0.4.5.md) |
| 0.4.4 | Retry failed filter reloads, support the lab core, and test two-path IPv6 traffic. | [Notes](docs/releases/v0.4.4.md) |
| 0.4.3 | Add native log filtering for delegated accounts, align forwarding permissions, and publish after the Actions matrix passes. | [Notes](docs/releases/v0.4.3.md) |
| 0.4.2 | Align tables, editors, and diagnostics with the pfSense CE 2.9.1 WebGUI. | [Notes](docs/releases/v0.4.2.md) |
| 0.4.1 | Publish on GitHub Releases and preserve consecutive syslog events. | [Notes](docs/releases/v0.4.1.md) |
| 0.4.0 | Revise the WebGUI and widget, write events to General logs, and check versions on `main`. | [Notes](docs/releases/v0.4.0.md) |
| 0.3.0 | Preview forwarding with optional lab core integration. | [Notes](docs/releases/v0.3.0.md) |
| 0.2.0 | Add gateway monitoring, SLAs, and path recommendations. | [Revision](https://github.com/allanlopesprado/pfsense-sdwan/tree/ef7d32da3a09cd5d33867eccae07588276e0cb4b) |
| 0.1.1 | Lab package with a pinned checksum. | [Package](dist/pfSense-pkg-SDWAN-0.1.1.pkg) |
| 0.1.0 | First reproducible lab distribution. | [Package](dist/pfSense-pkg-SDWAN-0.1.0.pkg) |
