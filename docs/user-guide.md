# Skynet command reference

[← User guide](README.md) · [Getting started](getting-started.md) · [WebUI guide](webui.md) · [Troubleshooting](troubleshooting.md)

The complete command reference and operating notes for Skynet v9. Run `firewall` over SSH for the interactive menu, or open **Firewall → Skynet** in the classic WebUI or **Settings → Firewall → Skynet** on AsusWRT 6. For a walkthrough, start with the [user guide](README.md).

Commands return `0` on success, `1` for a runtime failure, and `2` for an invalid command or input. Examples that change policy should be adapted to the addresses and services you actually want to manage.

## In this guide

- [Blocking and temporary bans](#blocking)
- [Malware lists and threat feeds](#malware-lists)
- [Whitelisting](#whitelisting)
- [Importing and removing lists](#importing-and-removing-lists)
- [Rule storage and ownership](#rule-storage)
- [Updates](#updates)
- [Settings and IoT isolation](#settings)
- [Statistics](#statistics)
- [Block history and retention](#block-history)
- [Backups, diagnostics and maintenance](#diagnostics-and-maintenance)
- [WebUI features](#webui)
- [Action history](#action-history)
- [Troubleshooting](#help)

## Moving an installation

Reinstalling onto another partition copies saved policy, feed selections, history and recovery archives. The original Skynet directory is retained for recovery; remove it manually only after confirming the new installation works. Allow enough space on the destination for the copied data.

## Command Reference

### Blocking

- `firewall ban ip 8.8.8.8 1.1.1.1` - Ban one or more IPv4 addresses.
- `firewall ban ip 8.8.8.8 1.1.1.1 comment "Apples"` - Ban multiple IPv4 addresses with one optional quoted comment.
- `firewall ban ip 8.8.8.8 1.1.1.1 timeout 1h` - Ban multiple IPv4 addresses for one hour.
- `firewall ban ip 8.8.8.8 timeout 24h comment "Persistent scanner"` - Add a temporary ban with an optional quoted comment.
- `firewall ban range 8.8.8.0/24 1.1.1.0/24` - Ban one or more IPv4 CIDR ranges.
- `firewall ban range 8.8.8.0/24 1.1.1.0/24 comment "Apples"` - Ban multiple ranges with one optional quoted comment.
- `firewall ban range 8.8.8.0/24 timeout 7d comment "Persistent scanner"` - Temporarily ban an IPv4 range.
- `firewall ban domain example.com example.net` - Resolve one or more domains and ban their current public IPv4 addresses.
- `firewall ban country pk cn sa` - Replace the current country bans with the known IPv4 ranges assigned to the supplied two-letter country codes.
- `firewall ban country status` - Display the selected countries and their source health.
- `firewall ban country refresh` - Refresh every selected country without changing the selection.
- `firewall ban asn AS123456 AS654321` - Download and ban the IPv4 ranges announced by one or more ASNs.
- `firewall ban asn AS123456 AS654321 timeout 1h` - Temporarily ban the ranges of one or more ASNs. An optional `comment "text"` follows the lifetime.
- `firewall unban ip 8.8.8.8 1.1.1.1` - Remove one or more direct permanent or temporary IPv4 rules.
- `firewall unban range 8.8.8.0/24 1.1.1.0/24` - Remove one or more direct permanent or temporary CIDR rules.
- `firewall unban domain example.com example.net` - Remove one or more stored manual domain bans without another DNS lookup.
- `firewall unban comment "Apples"` - Remove direct IP and CIDR ban rules whose comments contain the supplied text.
- `firewall unban country` - Remove all entries created by country blocking.
- `firewall unban asn AS123456 AS654321` - Remove one or more registered ASN ban rules.
- `firewall unban malware` - Remove entries created from malware feeds.
- `firewall unban nomanual` - Remove automatic blacklist entries while retaining every registered user rule.
- `firewall unban all` - Remove bans. Recorded traffic history is retained.

Temporary bans accept `15m`, `1h`, `6h`, `24h`, or `7d`. Arguments must be supplied as entries, an optional `timeout`, then an optional `comment`. Re-adding a temporary rule resets its expiry. Adding the same entry permanently promotes it, while a temporary request for an existing permanent rule leaves the permanent rule unchanged. Unbanning an exact address or range removes its direct permanent or temporary rule; another overlapping rule may continue to cover it.

Temporary bans expire automatically and keep their original expiry across restarts or power loss.

ASN refreshes retain the original rule deadline, including when the announced ranges change. Overlapping temporary owners retain the latest applicable expiry; permanent owners remain active independently. `firewall unban asn` removes the selected ASN's permanent or temporary ownership without removing other rules. Domain bans, imports and whitelists remain permanent.

Country blocking downloads the selected IPdeny lists concurrently over verified HTTPS and accepts only complete public IPv4 CIDRs. Selected country sources refresh automatically once a week, independently of the malware-list schedule. A URL-bound validated cache is used with a warning when a selected list is temporarily unavailable. If no matching cache exists, the complete previous country selection is retained. Applying a new country selection replaces the previous selection rather than appending to it.

Domain rules filter resolved IPv4 addresses, so other services sharing those addresses may also be affected. Skynet resolves them every six hours, while dnsmasq adds newly observed answers between refreshes. A successful refresh replaces the complete answer set so addresses no longer returned by DNS are removed. Validated answers may be retained for up to 24 hours during a resolver failure; after that they expire instead of remaining trusted indefinitely. New domain rules still require a successful initial resolution, and removals use the stored rule rather than resolving the domain again.

Domain health is reported as `current`, `cached`, `empty`, `expired`, or `failed`. One completed empty lookup retains a recent validated answer; two consecutive empty lookups remove it. Resolver failures retain validated answers within the 24-hour safety window, then report `expired`. Removing a domain does not remove addresses still owned by another rule.

Startup restores valid cached domain answers and preserves their remaining lifetime across restarts. A failed refresh retains the previous rules and health information.

DNS rollback restores Skynet's marked entries while retaining current settings from other add-ons in the shared dnsmasq configuration.

- `firewall rules status` - Display registered rule totals and the current health of every dynamic domain rule.
- `firewall rules refresh` - Refresh registered domain rules and ASN ranges. Scheduled refreshes update domains every six hours and ASNs once daily.

If an ASN source fails or returns no usable public IPv4 entries, refresh retains that rule's validated cached ranges and continues updating healthy sources. The result is marked degraded, with each affected ASN and reason listed in Action History. If no valid cache exists, the refresh fails and restores the previous rule state.

### Malware Lists

A Skynet filter list contains one HTTP or HTTPS threat-feed URL per line. It supplies the initial selection or replaces it when explicitly imported. Normal updates use the saved selection, so added, removed and disabled sources remain as configured. Existing source details and exclusions are carried into the saved selection; when no source details exist, the configured custom or default filter list is imported on the first malware update.

Skynet refreshes required whitelists, conditionally downloads enabled feeds, validates their IPv4 entries, removes private and reserved ranges, and rebuilds the malware portion of the blacklist. CIDRs are normalized to their network address, `/32` entries become individual IPs, and source counts include only unique usable entries. Ranges overlapping private or reserved space are excluded. Changing a feed URL requires a valid download from the new source. Source names remain stable when other sources are removed.

When sources and policy are unchanged, Skynet keeps the existing blacklist while continuing source checks, whitelist refreshes and AiProtection processing.

Each source is reported as `current`, `cached`, `failed`, or `excluded`; `pending` means no matching check is available yet. A validated cache may be used when its source cannot be refreshed. If any enabled source has no valid matching cache, the update fails and the complete existing blacklist and saved source selection are retained.

- `firewall banmalware` - Refresh the malware blacklist using the saved sources.
- `firewall banmalware https://example.com/filter.list` - Replace the saved selection with the supplied filter-list template and refresh the malware blacklist.
- `firewall banmalware reset` - Replace the saved selection with Skynet's default filter list and refresh the malware blacklist.
- `firewall banmalware add https://example.com/addresses.ipset` - Add a feed URL to the saved selection and refresh the blacklist. Multiple URLs may be supplied as separate arguments.
- `firewall banmalware remove list1.ipset list2.ipset` - Remove the named sources and rebuild the blacklist without them.
- `firewall banmalware status` - Display the update schedule, filter list, last update, and source-state totals.
- `firewall banmalware sources` - Display every source, its usable entry count, state, last successful check, content-change time, and URL.
- `firewall banmalware exclude list1.ipset list2.ipset` - Replace the disabled-source selection with the supplied filenames, then refresh the malware blacklist. Other sources are enabled.
- `firewall banmalware include list1.ipset list2.ipset` - Re-enable one or more excluded source filenames, then refresh the malware blacklist.
- `firewall banmalware exclude reset` - Clear the excluded filenames and refresh the malware blacklist.

### Whitelisting

- `firewall whitelist ip 8.8.8.8 1.1.1.1 comment "Trusted"` - Whitelist one or more IPv4 addresses with one optional quoted comment. Existing bans are retained and become effective again if the whitelist is removed.
- `firewall whitelist range 8.8.8.0/24 1.1.1.0/24 comment "Trusted"` - Whitelist one or more IPv4 CIDR ranges with one optional quoted comment. Existing bans are retained and become effective again if the whitelist is removed.
- `firewall whitelist domain example.com example.net` - Resolve one or more domains and whitelist their current IPv4 addresses.
- `firewall whitelist asn AS123456 AS654321` - Download and whitelist the IPv4 ranges announced by one or more ASNs.
- `firewall whitelist vpn` - Refresh VPN whitelist entries from Merlin's configured NVRAM values.
- `firewall whitelist remove entry 8.8.8.8` - Remove an exact direct IPv4 or CIDR whitelist rule.
- `firewall whitelist remove domain example.com example.net` - Remove one or more stored manual domain whitelists without another DNS lookup.
- `firewall whitelist remove asn AS123456 AS654321` - Remove one or more registered ASN whitelist rules.
- `firewall whitelist remove comment "Apples"` - Remove direct IP and CIDR whitelist rules whose comments contain the supplied text.
- `firewall whitelist remove all` - Remove every registered user whitelist rule while retaining automatic and shared policy.
- `firewall whitelist refresh` - Refresh automatic, shared, VPN, CDN, and persistent domain whitelist entries.
- `firewall whitelist view` - Display automatic whitelist entries.
- `firewall whitelist view ips|domains|asns|imported` - Display only the selected class of user whitelist rule.

Skynet automatically exempts enabled feed endpoints and shared service hosts, including IPdeny. One shared whitelist refresh resolves their current public IPv4 addresses before country and malware-list downloads. These entries remain separate from user domain rules, so a rule refresh cannot erase them. Learned addresses expire after 24 hours unless renewed; a failed DNS lookup retains their remaining lifetime.

VPN whitelisting uses Merlin's configured NVRAM values without scanning active routes or interfaces. Each enabled OpenVPN server pool uses its configured subnet and netmask. Configured OpenVPN and WireGuard client endpoints are whitelisted as `/24` networks. Server firewall rules are installed only while the corresponding OpenVPN or WireGuard server is enabled.

### Importing and Removing Lists

Import accepts either a local file path or an HTTP/HTTPS URL. Input files contain one IPv4 address or CIDR range per line, optionally followed by `# comment`:

```text
1.1.1.1 # this is my comment
8.8.8.0/24 # Google DNS range
9.9.9.9
```

Inline comments are retained for matching-rule explanations in statistics and IP details, including after restarts and backup restores. The import remains one removable group; its optional command-line comment labels that group and supplies the reason for entries without inline comments. Blank lines and comment-only lines are ignored. Leading/trailing spaces are trimmed; comments may contain up to 242 bytes and must not contain control characters. An invalid comment on an accepted public address rejects the import without applying it.

Private and reserved ranges are ignored. Bare addresses and `/32` entries are handled as IPs; other valid CIDRs are normalised to their network address. Duplicate normalised entries use the first occurrence and its comment. Existing imports must be imported again to acquire comments from the original file.

Imports are one-time copies. Skynet retains the imported entries but does not fetch the original file again. For a blacklist that refreshes on schedule, add its URL to Malware Blacklist sources with `firewall banmalware add <url>` or the WebUI threat feed manager. Threat feeds are for blocking, not scheduled whitelist imports.

- `firewall import blacklist /path/to/list.txt "Apples"` - Add valid entries to the blacklist with an optional comment.
- `firewall import whitelist https://example.com/list.txt "Apples"` - Add valid entries to the whitelist with an optional comment.
- `firewall rules remove <rule-id>` - Remove one direct, domain, ASN or imported rule by its stable ID.

### Rule Storage

Each saved rule has a stable ID. Comments are descriptive labels. Direct IP, CIDR and domain rules remain individually manageable, while ASN and imported lists are managed as groups.

Removing one rule does not remove an address still covered by another rule.

Large lists require sufficient router RAM, including space to prepare a replacement while the current policy remains active. A failed replacement retains the previous policy.

### Updates

- `firewall update` - Check for an updated Skynet release and install it when available.
- `firewall update check` - Check for an update without installing it.
- `firewall update -f` - Download and install the current release even when the local file already matches.

Skynet validates the matching firewall script and WebUI before installing an update. Download or validation failures leave the running installation untouched. Failed or interrupted installation restores the previous files and restarts Merlin's firewall to recover protection, schedules and WebUI integration. If recovery cannot finish, Skynet reports where the recovery copies are stored.

### Settings

The interactive Settings menu groups options under Updates & Lists, Protection, IoT WAN Blocking, Logging & Statistics, and Integration & Advanced. Commands remain available directly as documented below.

#### Updates & Lists

- `firewall settings autoupdate enable|disable` - Enable weekly automatic Skynet updates. When disabled, Skynet checks weekly but does not install an update.
- `firewall settings banmalware daily|weekly|disable [hour|auto]` - Set or disable scheduled malware blacklist refreshes. Choose an hour from 0–23 in router local time; jobs run at minute 25, on Monday for weekly updates. `auto` keeps the default random hour (1–23), selected when the schedule is installed. Omitting the hour retains the saved choice, including while updates are disabled. The hour is also available under WebUI Updates and is saved with Apply Settings.

#### Protection

- `firewall settings filter all|inbound|outbound` - Select which traffic direction Skynet filters.
- `firewall settings unbanprivate enable|disable` - Automatically whitelist private addresses observed in blocked traffic and remove exact entries from the IP blacklist.
- `firewall settings banaiprotect enable|disable` - Import or remove IPv4 threats recorded by AiProtection.
- `firewall settings securemode enable|disable` - Control whether Skynet disables WAN access to SSH and the router WebUI when detected.

Secure Mode restricts WAN management access. It does not scan router files for malware or remove software, user profiles or VPN settings. AiProtection ingestion and threat-feed blocking operate independently.
- `firewall settings cdnwhitelist enable|disable` - Add or remove supported CDN, service, and public DNS ranges from the whitelist.

AiProtection domain lookups are reused for 24 hours after success or seven days after failure. A newer AiProtection event triggers an immediate retry. A previous valid address mapping is retained if a later lookup fails.

CDN whitelist updates require valid IPv4 data from every required source. If a source is unavailable or invalid, the previous entries are retained.

#### IoT Isolation

IoT WAN blocking applies to devices in the Skynet IoT IPSet. When enabled, their forwarded WAN traffic is blocked except for the configured TCP/UDP ports and traffic routed through OpenVPN or WireGuard server interfaces. Traffic between local bridges remains subject to Merlin's access controls; Skynet does not override LAN isolation. By default, UDP port 123 remains available for NTP time synchronization; accurate device time is required by certificates, secure connections and scheduled activity. The default can be replaced with up to 15 custom ports or disabled entirely. The saved device list and the blocking switch are managed independently.

- `firewall settings iot ban 192.168.1.50 192.168.1.60` - Add one or more IPv4 addresses or CIDR ranges to the IoT list.
- `firewall settings iot unban 192.168.1.50 192.168.1.60` - Remove one or more IPv4 addresses or CIDR ranges from the IoT list. Recorded traffic history is retained.
- `firewall settings iot enable|disable` - Start or pause IoT WAN blocking without clearing the saved device list.
- `firewall settings iot view` - Display detected clients, their IoT state, and the current allowed protocol and ports.
- `firewall settings iot ports 123 124 125` - Replace the allowed WAN port list. Ports must be between 1 and 65535, with a maximum of 15 entries.
- `firewall settings iot ports default` - Allow only UDP port 123 for NTP time synchronization.
- `firewall settings iot ports none` - Allow no TCP or UDP WAN ports. Local bridge traffic and VPN server-interface exceptions remain subject to Merlin's access controls.
- `firewall settings iot proto udp|tcp|all` - Select the protocol used by a custom allowed-port list.
- `firewall settings iotlogging enable|disable` - Enable or disable logging for blocked IoT traffic.

Changing the IoT device list does not enable or disable enforcement. Use the master IoT setting in the CLI or WebUI to control blocking.

Enabling isolation, adding devices while it is enabled, or changing allowed ports/protocol resets the affected devices' existing source-NAT connections so accelerated WAN sessions cannot retain the previous policy. Allowed WAN services reconnect normally; other clients and ordinary LAN connections are unaffected.

#### Logging & Statistics

- `firewall settings logmode enable|disable` - Enable or disable logging of Skynet blocks. Disabling logging pauses scheduled chart generation without removing the WebUI, retained block history or protection. Enabling logging restores the statistics schedule.
- `firewall settings loginvalid enable|disable` - Enable or disable logging of conntrack INVALID packets handled by the router's drop chain. Other rejected new connections are not classified as invalid.
- `firewall settings logfirewall enable|disable` - Enable or disable the separate **Firewall Drops** category. Disabled by default; requires Packet Logging.
- `firewall settings logsize 10` - Set the collected traffic storage budget from 10 to 200MB. Older detailed events expire first when the budget is reached. Saved budgets above 200MB are capped at 200MB.
- `firewall settings extendedstats enable|disable` - Add associated domain names to statistics when dnsmasq logs are available.
- `firewall settings lookupcountry enable|disable` - Enable or disable online country lookups for statistics.
- `firewall settings syslog auto` - Follow the running logger automatically. Uses Scribe's installed Skynet destination while syslog-ng runs, otherwise the system logger's `-O` output or `/tmp/syslog.log`. Symlinks are resolved and the rotated path defaults to the current path plus `-1`.
- `firewall settings syslog /path/to/syslog [/path/to/rotated-log]` - Select Custom mode and set one or both source paths. Both paths are validated before either changes.
- `firewall settings syslog1 /path/to/rotated-log` - Select Custom mode and change only the rotated source path. Custom paths remain unchanged across startup and logger detection.

While active, Skynet suppresses the firmware's default IPv4 and IPv6 `DROP ` packet loggers, including after firewall rebuilds and with Skynet packet logging disabled. The firmware's DROP verdicts remain in place. INVALID blocking continues to use the native INPUT/FORWARD rules and their existing exceptions; Skynet only adds a log entry immediately before the native drop-chain verdict. Disabling INVALID logging does not disable native INVALID blocking.

Optional **Firewall Drops** logging records IPv4 NEW packets that reach the native `logdrop` chain, using `[BLOCKED - FIREWALL]`. This includes rejected connections to the router and rejected forwarded traffic. Packets dropped elsewhere or by IPv6 rules are outside this category. The logger runs immediately before the native DROP verdict and does not change blocking or whitelist decisions. Its shared rate limit is 4 packets/second with a burst of 10 across all sources. Statistics and exports count recorded packets, which may undercount actual drops and are not unique connection counts. Firewall Drops and INVALID logging have independent switches under Packet Logging; disabling either retains its collected history.

Log sources can also be selected under WebUI Statistics. Configurations without a saved log-source mode default to Automatic, including those with existing custom paths. Select Custom to pin specific paths; an explicitly saved Custom mode is preserved. Skynet does not install, remove or reconfigure Scribe's filters. Install or reconfigure Scribe through its own installer; its existing Skynet CLI callback remains supported.

#### Integration & Advanced

- `firewall settings webui enable|disable` - Mount or remove the Skynet page in the Asuswrt-Merlin WebUI.

### Statistics

- `firewall stats` - Display the standard top 10 statistics report.
- `firewall stats 20` - Display up to 20 results per report section.
- `firewall stats tcp|udp|icmp` - Limit the report to a protocol.
- `firewall stats tcp 20` - Combine a protocol filter with a custom result count.
- `firewall stats search port 23 [count]` - Show activity involving a port.
- `firewall stats search ip 8.8.8.8 [count]` - Show current ban and whitelist matches, reasons, associated domains, location, and logged activity for an IPv4 address. Checks include automatic, domain, manual and temporary sets. Whitelist matches take precedence over matching bans.
- `firewall stats search domain example.com` - Resolve a domain and show available statistics and matching rule reasons for each resulting IPv4 address.
- `firewall stats search malware 8.8.8.8` - Find exact or covering entries across local malware-feed caches. IPv4 and CIDR queries are supported; excluded feeds and unavailable caches are identified separately. No network lookup is performed.
- `firewall stats search reason "spamhaus" [count]` - Search active automatic and registered rule reasons without performing network lookups.
- `firewall stats search manualbans [count]` - Show recorded manual bans.
- `firewall stats search actions [count]` - Show recent CLI, WebUI, scheduled and startup actions, including degraded and failed outcomes.
- `firewall stats search device 192.168.1.50 [count]` - Show outbound blocks generated by a LAN device.
- `firewall stats search reports [count]` - Show saved periodic summaries.
- `firewall stats search invalid [count]` - Show logged invalid-state packets.
- `firewall stats search firewall [count]` - Show recorded Firewall Drops. The category also appears in source charts, activity trends, Block History filters and CSV exports.
- `firewall stats search iot [count]` - Show logged IoT blocks.
- `firewall stats search connections [ip|port|proto|id] [value]` - Show or filter active connection data when the required AiProtection data is available.
- `firewall stats remove ip 8.8.8.8` - Remove retained events containing an IPv4 address and subtract their contribution from hourly totals.
- `firewall stats remove port 23` - Remove retained events containing a port and subtract their contribution from hourly totals.
- `firewall stats reset` - Generate the current WebUI statistics and clear collected events and trend totals. Cleared events are not imported again.

Country fields are omitted when country lookup is disabled. Associated domains are included only when Extended Statistics is enabled and dnsmasq logging data is available.

Country lookup results are reused for seven days. Cached results remain available during a provider outage, and unused entries expire after 30 days. A country lookup failure does not prevent statistics generation.

A failed statistics refresh retains the previous charts.

### Block History

Skynet uses the router's native SQLite support to store collected packet events in `history.db`. No additional package or database server is required. Existing text logs are imported before statistics switch to the database.

Detailed events are retained for up to seven days within the configured storage budget. Hourly category totals remain available for 90 days. Capacity may shorten detailed retention; the WebUI shows the oldest available event and whether storage limits have applied. Older trend totals cannot be searched by individual IP address, protocol or port after their detailed events expire.

Each event retains its timestamp, category, source and destination IPv4 addresses, protocol, ports, packet length, interfaces, TCP flags, available ICMP details and logged MAC/link-layer data. The logged link-layer header may identify a gateway rather than the remote IP's device. Normal packet logging omits optional TCP sequence numbers and TCP/IP option dumps. This changes diagnostic detail, not packet blocking or the number of collected events.

The 30-minute collector, hourly maintenance and explicit refreshes collect newly completed syslog records. Packet entries are removed from active and rotated syslog files only after successful collection. Records already lost to system-log rotation cannot be recovered. Counts represent recorded packet events, not unique connections or every packet the firewall may have dropped.

Changing rules or removing IoT entries does not erase historical traffic. Use the explicit statistics removal or reset commands to delete collected records. Domain names and ban reasons shown by current lookups describe current metadata, not necessarily the policy that applied when an older packet was logged.

### Diagnostics and Maintenance

- `firewall debug watch` - Follow Skynet block entries in real time.
- `firewall debug watch ip 8.8.8.8` - Follow entries involving an IPv4 address.
- `firewall debug watch port 23` - Follow entries involving a port.
- `firewall debug info` - Display system, storage, logging, configuration, and integrity checks.
- `firewall debug info extended` - Include the current Skynet configuration in the diagnostic output.
- `firewall debug genstats` - Regenerate WebUI statistics.
- `firewall collect` - Collect pending packet events without refreshing charts or checking firewall integrity. Runs automatically every 30 minutes while Packet Logging is enabled; skips a run if another Skynet command holds the state lock.
- `firewall debug clean` - Archive and clean handled Skynet syslog entries.
- `firewall debug swap install|uninstall` - Create or remove a standard USB `myswap.swp` swap file (1GB minimum), including one created by another script. Removal disables that file and cleans its file-specific hooks; unrelated and shared hooks are retained.
- `firewall debug backup` - Save configuration, rules, source caches, IPSet data and logs. Skynet retains the latest three dated restore points in `backups/` and the latest backup as `Skynet-Backup.tar.gz`. An existing archive is retained as the first point when upgrading. A failed backup retains the previous archive. Creating dated points requires synchronized router time.
- `firewall debug restore [point-id]` - Validate and restore the latest backup or a specific point, retaining current action history. The point ID is the timestamp and digest in its filename, without `Skynet-Backup-` or `.tar.gz`. Rebuilds Skynet policy from local data without restarting Merlin's firewall. Cached manual domain rules are restored; transient DNS-learned addresses repopulate through normal DNS queries. Previous files are retained until policy and integration checks pass, and restored if the operation fails. Invalid archives are rejected before changing installed data.

Backup validation rejects symbolic and hard links, unsupported archive paths, executable configuration content and unsupported history schemas. Valid empty IPSet snapshots remain restorable. Concurrent firewall-start events wait for an in-progress restore before inspecting the replacement policy.
- `firewall save` - Archive pending logs, verify integrity, and persist durable state only when it changed.
- `firewall restart` - Restart Merlin's firewall once and reconcile Skynet rules without unloading its IPSet data, WebUI, or schedules.

A Merlin firewall reload checks Skynet protection and repairs missing or stale rules. It does not download sources or regenerate existing statistics. Cold startup restores saved protection without requiring internet access. Failed startup work is retried on the next start.

Packet logging, temporary-rule restoration, rule additions and refreshes, and persistent action timestamps wait for a trustworthy system clock. Permanent blocking, whitelisting, rule removal and IoT enforcement remain available while time synchronization is pending. If time is not ready within five minutes, startup completes in a degraded state and the next firewall reconciliation or hourly maintenance enables the pending time-dependent features.

Upgrading from public v8 releases preserves supported settings, saved rules, feed and country selections, IoT devices, cached domain answers and activity history. Obsolete WebUI files are removed during the upgrade.

An interrupted v8 upgrade resumes on the next start. Restoring a v8 backup uses the same migration process. Releases before v8 and unsupported data formats require a fresh installation.

Existing text packet history is imported after database activation. Completed imports are not repeated.

While Packet Logging is enabled, collection runs at minutes 0 and 30. It collects new records from active and rotated logs after time synchronization and startup complete. A busy Skynet command causes that collection run to be skipped. Collection does not refresh charts. Disabling Packet Logging stops this schedule; re-enabling restores it independently of the WebUI.

Hourly maintenance runs at a randomized minute. It collects new block records, enforces the storage limit, removes expired rules and checks firewall integrity. It also saves changed state and updates WebUI settings when needed.

After successful collection, Skynet removes handled packet records and native `DROP` messages from syslog while retaining unrelated system messages. Failed imports and incomplete records remain available for retry. The system logger is not restarted or reconfigured.

Manual `firewall save` stops with a failure status if private-address whitelisting or log archival fails, without continuing to save the IPSet snapshot.

If maintenance cannot update the WebUI after a change, it retries the refresh on the next successful run.

Maintenance waits up to 60 seconds for an active Skynet command to finish. If Skynet remains busy, maintenance returns a failure status and records `deferred (state-lock)` in diagnostics without interrupting that command. Collection cannot recover syslog records already lost to rotation during sustained traffic.

## WebUI

The WebUI provides:

- Packet logging and syslog source paths under Statistics, alongside the existing protection, update, IoT and country settings. Changes use the same commands as the CLI. Disabling WebUI integration remains CLI-only because it removes the management page.

- The latest generated blacklist totals and inbound/outbound packet counters.
- Daily block activity and the main CLI top-10 statistics as charts or tables.
- Block History queries retained events in pages of 100, with period, category, IPv4/CIDR, protocol and port filters. Each event expands to show packet details. Export CSV includes up to the newest 1,000 matching events, with a notice when more matches exist.
- History trends show category totals for Today, seven days or 90 days. IP, protocol and port filters apply to detailed events only. Gaps indicate no recorded bucket, not confirmed zero traffic. Pagination keeps the original query window; Refresh History collects pending records and starts a new view.
- IP details including ban reason, country, associated domains, AlienVault OTX, and SpeedGuide links where applicable. Saved rule matches show overlapping bans and allowances, with whitelist precedence and the statistics refresh time. These describe the saved metadata at refresh, not live enforcement or the policy when each historical event occurred.
- Refresh statistics in the background without leaving the page. Busy or failed requests show an error and retain the existing charts.
- Common Skynet settings with descriptions and documented defaults.
- Restart Skynet under Protection requests the same Merlin firewall restart as `firewall restart`, with confirmation and a tracked result. Connections may be briefly interrupted; IPSet data and schedules are retained.
- Threat-feed status, usable entry counts, last successful checks, content age, source toggles, manual refresh, and feed URL additions/removals. Use Template replaces the saved selection with the default or custom filter list after confirmation.
- Country blocking with country selection and removal.
- Manual IP, range, domain and ASN ban, unban and whitelist management, including grouped imported lists.
- Domain rules expand to show their retained resolved IPv4 addresses and whether the result is current or cached. Up to 64 addresses are displayed per rule, with copying and an explicit limit when more are retained. Opening these details performs no DNS lookup; Refresh Dynamic Rules updates the cached results.
- IP Details lists matching rule owners, identifies permanent and temporary rules, and shows temporary expiry in local 12-hour time. CLI IP searches show remaining lifetime. These details use the saved rule snapshot; they do not reconstruct the policy at the time of an older packet event.
- Find matching feeds beneath Ban Matches in IP Details checks local feed caches on demand, showing matching sources and covering networks only when requested. Cached membership does not establish an active ban; excluded sources are not enforced. Use Manage Rules for ban, unban and whitelist controls; global whitelists apply to all clients, not just one device.
- Add Entries stages IPv4/CIDR entries with the comment currently entered. Staged tags show their saved comments; Apply Rules submits the complete batch together. Changing the comment field does not change previously staged entries. Re-adding a staged address updates its comment.
- Permanent or preset temporary IPv4/CIDR and ASN bans, remaining lifetime, stable rule removal, and a dedicated Temporary filter.
- Activity History shows the latest 200 valid journal entries, ten per page, with category, result and text filters. Export CSV downloads all matching entries within that window, not just the visible page. Older retained entries remain in `events.log`. Country changes identify the countries added or removed, while source refreshes are recorded only when validated content changes.
- Create Backup under Updates runs the same archive operation as `firewall debug backup`. Select a dated restore point to see its local creation time and size. Download Backup saves that point through an authenticated WebUI route. Restore Backup requires confirmation and restores the selected archive using the same validation and rollback as the CLI. Settings, rules, source caches and block history are replaced; current activity history is retained. Traffic may be interrupted briefly while rules are rebuilt. Backups that disable the WebUI must be restored through SSH. Only the latest three points are retained; download older points before creating more backups if you want to keep them. Archives contain private network data; keep downloaded copies somewhere safe.
- IoT isolation with detected client, hostname, IPv4, MAC, online state, device list, port and protocol controls.
- Copyable MAC addresses in blocked-device details when neighbour data is available.

Empty or disabled data sections are collapsed or omitted where appropriate. Retained Block History remains accessible with packet logging disabled. Charts use collected events; blacklist totals and packet counters reflect the latest statistics refresh.

Block Activity shows the past 24 hours at the last statistics refresh, grouped by local clock hour with labels such as 1am, 2am and 3am. The first and current hours include only events inside that rolling window, so a refresh between hours shows 25 buckets with partial totals at each end. Chart hits count retained logged events and survive restarts while that history remains available. The inbound/outbound headline counters count packets since their firewall rules were installed; they reset when those rules are rebuilt or the router reboots. They are not lifetime totals and can differ from logged-event counts when logging is disabled or rate-limited. Log storage accepts 10–200MB.

Temporary-rule controls are disabled until the router clock is synchronized. Expired rows are hidden immediately, while counters and settings refresh without rebuilding chart statistics.

## Action History

Skynet records completed changes and operational failures in `events.log`, including their origin, result, operation and affected values. The journal retains up to 2,000 entries within 1MB. Existing v8 activity is retained during an upgrade, with an unknown year where none was recorded. Restoring a backup retains current activity history.

Action records are written only after the router clock is synchronized, preventing persistent entries with incorrect startup timestamps.

The WebUI groups each activity by category and shows the operation and affected values in Details, such as `Setting Change` with `Enabled Packet Logging`.

Successful dynamic-rule refreshes that leave content and health unchanged do not create an action entry. Changes, degraded sources and failures remain visible. Temporary-ban actions include a readable expiry time in the router's timezone.

Temporary bans expire in the kernel without waiting for maintenance. Hourly maintenance records detected expiries when removing their saved rules; the entry time is the detection time and its details include the original deadline. Malware refresh entries report current, cached and excluded source counts rather than implying that every source changed.

## Help

Run the following command first when troubleshooting:

```sh
firewall debug info
```

Include the complete output, the command that failed, and the relevant syslog lines when requesting support. Do not manually edit `skynet.cfg`; it is generated and maintained by Skynet.

- [Troubleshooting and common issues](troubleshooting.md)
- [Official SNBForums support thread](https://www.snbforums.com/threads/skynet-v8-router-firewall-security-enhancements.96167/)
- [GitHub issues](https://github.com/Adamm00/IPSet_ASUS/issues)
