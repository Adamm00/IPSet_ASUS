# Getting started

[← User guide](README.md) · [WebUI guide](webui.md) · [Command reference](user-guide.md) · [Troubleshooting](troubleshooting.md)

## What you need

- A supported ASUS router running **Asuswrt-Merlin**, with IPSet **6 or 7**.
- A writable **USB partition** with space for policy data, history, backups and any required swap file.
- **SSH access** for manual installation. The installer enables custom JFFS scripts if required and may request a reboot.

Swap is optional on 2GB-class routers with at least 1.5GiB of usable RAM. Smaller routers require a swap file: **1GB minimum, 2GB recommended**. The installer can create it; swap partitions are not supported.

Skynet's blocklists apply to IPv4. The WebUI uses Merlin's Addons API, and Block History uses the router's native SQLite support. No additional database package is required.

## Install or update

### New installation

Run this from an SSH session on your router:

```sh
/usr/sbin/curl -fsSL "https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh" -o "/jffs/scripts/firewall" && chmod 755 "/jffs/scripts/firewall" && sh "/jffs/scripts/firewall" install
```

Alternatively, run `amtm` and select Skynet.

The installer guides you through the USB partition, swap, traffic filtering, logging and update schedules. It downloads the matching WebUI as part of installation.

### Existing installation

Update directly:

```sh
firewall update
```

Supported settings and saved policy are preserved when upgrading from public v8 releases. Existing text packet history is imported into the database. Upgrades from earlier releases and unreleased v9 development formats are not supported by that migration path; see the [detailed upgrade notes](user-guide.md#diagnostics-and-maintenance).

### Moving to another USB partition

Reinstalling onto another partition copies saved policy, feed selections, history and recovery archives. Allow enough space for the copied data. The original directory is retained for recovery; remove it only after confirming the new installation works.

## Your first visit

1. Open **Firewall → Skynet** in Merlin's WebUI.
2. Visit **Updates** to review your threat feeds and refresh schedule.
3. Visit **Protection** to review the traffic direction and protection settings.
4. Use **Rules** for bans and whitelists, **Countries** for country blocking, and **IoT** for device WAN restrictions.
5. Enable **Packet Logging** under **Statistics** if you want traffic charts and history.
6. After activity has been collected, use **Refresh Stats** on Overview. Open **History** to search recorded events.

The **Statistics** tab contains logging settings. Traffic charts and device breakdowns are on **Overview**.

## Prefer SSH?

Open the interactive menu:

```sh
firewall
```

Useful commands to start with:

| Command | Purpose |
| --- | --- |
| `firewall rules status` | Review rule totals and domain health. |
| `firewall banmalware sources` | Inspect saved threat feeds and their state. |
| `firewall stats` | Display traffic statistics. |
| `firewall debug genstats` | Refresh WebUI statistics. |
| `firewall debug info` | Inspect configuration and integrity diagnostics. |

Let Skynet manage `skynet.cfg`; change settings through the WebUI or CLI.

---

**Next:** [Take a tour of the WebUI →](webui.md)
