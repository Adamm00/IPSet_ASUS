# Troubleshooting

[← User guide](README.md) · [Getting started](getting-started.md) · [WebUI guide](webui.md) · [Command reference](user-guide.md)

Start with the symptom below. For configuration, storage and integrity information, run:

```sh
firewall debug info
```

| Symptom | Where to start |
| --- | --- |
| A website or application is blocked | [Find the destination and matching rule](#a-website-or-application-is-blocked) |
| Skynet is missing from the WebUI | [Check WebUI integration](#skynet-is-missing-from-the-webui) |
| Charts are empty or stale | [Check logging and refresh statistics](#charts-are-empty-or-stale) |
| History is empty or unavailable | [Check collection, filters and retention](#history-is-empty-or-unavailable) |
| A command reports a lock or busy state | [Let the active operation finish](#a-command-reports-a-lock-or-busy-state) |
| A source update fails | [Inspect source health](#a-feed-or-country-update-fails) |
| Time-dependent features are pending | [Check router time](#router-time-is-not-synchronized) |
| Storage or integrity checks fail | [Storage and integrity](#storage-and-integrity) |

## A website or application is blocked

1. Enable **Packet Logging** under Statistics if it is disabled.
2. Reproduce the problem from the affected device.
3. Open History, refresh it and filter by the device's IPv4 address. Inspect outbound destinations and ports.
4. Use Overview's IP details and matching rules to investigate the destination. Associated domains are supporting information; shared addresses may serve several services.
5. If you have confirmed the destination should be allowed, add an appropriate whitelist rule under Rules and retry the application.

For a live view over SSH:

```sh
firewall debug watch
```

Stop watching with **Ctrl+C**. Look for the affected device's source address and the destination (`DST=`), rather than assuming the most frequent event caused the problem.

Whitelisting allows that destination for **all clients** and takes precedence over bans. If the problem remains, check other filtering layers such as DNS blocking, AiProtection or device software. An absence of recorded events alone does not prove that no packet was blocked.

## Skynet is missing from the WebUI

Look under **Firewall → Skynet**. If integration is disabled, enable it over SSH:

```sh
firewall settings webui enable
```

Refresh the router page after the command completes. Check `firewall debug info` if the page is still missing. WebUI integration requires Merlin's Addons API and the matching Skynet WebUI file. It does not require Packet Logging to be enabled.

## Charts are empty or stale

Traffic charts are on **Overview**; the **Statistics** tab contains their settings.

Check Packet Logging, router time and the selected log source. Charts need recorded blocked traffic; enabling logging does not create historical events. Use **Refresh Stats**, or:

```sh
firewall debug genstats
```

If refresh fails, Skynet retains the previous charts. Read the result message and diagnostics instead of treating old charts as live data. Headline counters and logged-event totals measure different things; see [understanding the numbers](webui.md#understanding-the-numbers).

## History is empty or unavailable

Clear restrictive filters and select **Refresh History**. Confirm that logging was enabled during the period you are investigating and that the router's clock is synchronized.

Detailed events last up to seven days within the storage budget. Older category totals can remain visible for 90 days after individual packet details have expired. Disabling logging retains existing history but adds no new events.

Block History uses native SQLite. If loading fails, inspect storage, free space and diagnostic output. Preserve the database and existing logs while investigating; deleting them removes information that may be recoverable. Events already overwritten by syslog rotation cannot be collected later.

## A command reports a lock or busy state

Skynet serializes operations so simultaneous changes cannot overwrite one another. Let the active update, restore or other command finish, then retry. Duration depends on the operation and router.

Do not remove an active lock to force another command through. If the state persists, include the reported command, process/runtime information and `firewall debug info` output in a support request.

## A feed or country update fails

Inspect source state and the result message under Updates or Countries. For threat feeds, the CLI also provides:

```sh
firewall banmalware status
firewall banmalware sources
```

Check that the router can reach the source, DNS is working and the clock is correct for HTTPS. A feed must contain usable IPv4 addresses or CIDRs; an HTML error page or domain-only list is not an address feed.

A validated cache may keep the previous data available during an outage. If a required source has no valid matching cache, the update retains the previous complete policy. Fix the source or intentionally change your selection before retrying. **Use Template** replaces your source selection; it is not a routine refresh.

## Router time is not synchronized

Check the router's date, time, timezone and NTP status in Merlin. Skynet waits for trustworthy timestamps before logging, restoring temporary rules and performing other time-dependent operations.

Permanent blocking, whitelisting, rule removal and IoT enforcement can remain available while time is pending. If synchronization takes longer than five minutes, startup completes in a degraded state; the next firewall reconciliation or hourly maintenance enables the pending features when time is ready.

## Storage and integrity

### USB location is missing or not writable

Confirm that the expected partition is mounted and writable, with enough free space. Check storage diagnostics before reinstalling or moving files. Do not unplug the drive while Skynet is using it.

### IPSet support or extensions

Use supported Asuswrt-Merlin firmware with IPSet 6 or 7. Historical minimum firmware versions from older Skynet documentation are not a current compatibility guarantee. Include your exact model and firmware in a report if required set features are unavailable.

### Firewall rule integrity

Inspect diagnostics and recent changes by other firewall scripts or add-ons. Skynet verifies its rules and reconciles missing or stale entries. Repeated failures need investigation rather than repeated manual IPSet edits.

### Configuration or script errors

Capture the exact command and error, and inspect USB health and free space. Do not manually edit `skynet.cfg` or discard the installation data. Backups and recovery details are documented in the [command reference](user-guide.md#diagnostics-and-maintenance).

## Reporting a problem

Use the [SNBForums support thread](https://www.snbforums.com/threads/skynet-v8-router-firewall-security-enhancements.96167/) for questions, or [GitHub Issues](https://github.com/Adamm00/IPSet_ASUS/issues) for reproducible bugs.

Include the router model, firmware and Skynet versions, what you did, what you expected, what happened, and relevant output from `firewall debug info` and syslog. Check attachments for private addresses, hostnames, credentials and other information you do not want to publish. Keep timestamps and error text where possible.

---

[Back to the user guide](README.md) · [Command reference](user-guide.md)
