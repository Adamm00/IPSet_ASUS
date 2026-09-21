# Using the WebUI

[← User guide](README.md) · [Getting started](getting-started.md) · [Command reference](user-guide.md) · [Troubleshooting](troubleshooting.md)

Open **Firewall → Skynet** in the router's WebUI. Settings, rules and feed management remain available with packet logging disabled.

| Tab | Use it for |
| --- | --- |
| [Overview](#overview) | Block counters, activity charts and traffic breakdowns. |
| [Updates](#updates) | Skynet updates, threat feeds, backups and activity history. |
| [Protection](#protection) | Traffic filtering, protection settings and restarting Skynet. |
| [Rules](#rules) | Manual bans, trusted destinations and temporary rules. |
| [IoT](#iot) | Device WAN blocking and permitted ports. |
| [Countries](#countries) | Country selections and source health. |
| [Statistics](#statistics) | Logging, storage and statistics settings. |
| [History](#history) | Searchable packet events and longer-term trends. |

## Overview

The dashboard shows the latest generated ban totals, packet counters and a rolling 24-hour activity chart. Below it, explore traffic by device, address, country and port. Select chart entries for IP, device or port details where available.

Use **Refresh Stats** to collect pending events and regenerate the charts. Changing a setting does not necessarily rebuild chart statistics. If generation fails, the previous charts remain visible.

### Understanding the numbers

| Display | What it measures |
| --- | --- |
| IPs / ranges banned | The blacklist totals captured when statistics were generated. |
| Inbound / outbound headline counters | Packets since their firewall rules were installed; rebuilding rules or rebooting resets them. |
| Activity charts and history | Retained logged events; these survive restarts while their history is retained. |

Logging can be disabled or rate-limited, so logged-event totals may differ from packet counters. History gaps indicate no recorded bucket, not confirmed zero traffic. Rule matches in IP details describe the saved policy snapshot, not necessarily the policy when an older event occurred.

## Updates

Review the Skynet update schedule and configure threat-feed refreshes. In the feed manager, enable or disable sources, add URLs, and inspect usable entry counts and content age.

Normal malware updates retain your saved selection. **Use Template** replaces it with the default or configured custom filter list after confirmation.

| Source state | Meaning |
| --- | --- |
| Current | A current source check succeeded. |
| Cached | A validated copy is being used while the source cannot be refreshed. |
| Failed | The source could not provide usable data. |
| Excluded | The source is disabled. |
| Pending | No matching check is available yet. |

If an enabled source has no valid matching cache, the update fails and retains the existing blacklist and saved source selection. See [threat-feed behaviour](user-guide.md#malware-lists) for the full details.

### Backups

Use **Create Backup** to create a dated restore point. Select a point to see its creation time and size, then download or restore it. Skynet retains the latest three points.

Restoring replaces settings, rules, source caches and block history; current activity history is retained. The restore requires confirmation, and traffic may be interrupted briefly while rules are rebuilt. Backups that disable WebUI integration must be restored through SSH.

Download older points before creating more if you want to keep them. Backup archives contain private network data. See [backup commands and recovery behaviour](user-guide.md#diagnostics-and-maintenance).

### Activity history

Activity History records settings changes, policy operations and failures. It is separate from the packet events under **History**. Filter by category, result or text, and export matching entries to CSV.

## Protection

Choose inbound, outbound or both traffic directions and review private-address whitelisting, AiProtection imports, Secure Mode and CDN whitelisting.

Secure Mode restricts WAN management access to SSH and the router WebUI. **Restart Skynet** requests a Merlin firewall restart; connections may be briefly interrupted. Apply changed settings and check the result shown on the page.

## Rules

Choose an action and rule type, enter the destination or group, then apply the rule. For IPv4/CIDR batches, **Add Entries** stages addresses with their current comment; **Apply Rules** submits the complete batch.

- Use a permanent ban or one of the temporary lifetimes for IPv4/CIDR and ASN bans.
- Search saved rules by entry or comment, and use the Temporary filter to inspect expiring rules.
- Expand domain rules to inspect retained resolved addresses. **Refresh Dynamic Rules** updates domain and ASN data.
- Imported lists are one-time copies. Add a threat-feed URL under Updates when you want scheduled blacklist refreshes.

**Whitelists apply to all clients and take precedence over bans.** They do not create an exception for a single device. Domain rules operate on resolved IP addresses, so other services sharing an address can also be affected.

Removing one rule does not remove an overlapping rule's coverage. Temporary-rule controls wait for synchronized router time.

## IoT

Select detected devices or enter IPv4 addresses. Configure WAN blocking independently of the saved device list, and choose permitted ports and protocols where needed. Apply the changes with **Apply IoT**.

Pausing blocking retains the list. Clearing devices changes the saved selection. These controls govern WAN access; use Merlin's bridge and guest-network settings for local network isolation.

## Countries

Select the countries whose IPv4 ranges you want to block, then use **Apply Countries**. Applying a selection replaces the previous country selection. **Refresh Sources** updates the sources for the saved selection.

Country lists describe address allocation and are not a guarantee of a person's physical location. If a selected source is unavailable, Skynet uses its validated cache where possible; without a matching cache, the previous complete selection is retained.

## Statistics

Configure Packet Logging, Invalid Packet Logging, Firewall Drop Logging, storage budget, Extended Statistics, Country Lookup and syslog source paths.

Automatic log-source detection follows the running system logger or Scribe's installed Skynet handler. Custom mode keeps the paths you supply. The storage budget accepts **10–200MB**.

Disabling Packet Logging pauses collection and scheduled chart generation. It leaves protection, the WebUI and retained history available.

## History

Choose Today, Last 7 Days or Last 90 Days. Set any category, IP/CIDR, protocol or port filters, then select **Refresh History**. Expand an event for packet details, or use **Export CSV**.

- Trends show recorded category totals. IP, protocol and port filters apply to detailed events below the chart.
- Detailed events are retained for **up to seven days** within the storage budget; category totals are retained for **90 days**.
- Older category totals cannot be searched by individual address or port after their detailed events expire.
- Results are paged in groups of 100. CSV export includes up to the newest 1,000 matching events and reports when the limit applies.
- Pagination keeps the original query window; Refresh History collects pending records and starts a new view.

---

[View screenshots](../README.md#explore-the-interface) · [Resolve a problem](troubleshooting.md) · [Full command reference](user-guide.md)
