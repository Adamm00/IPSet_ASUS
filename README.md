# Skynet - Router Firewall & Security Enhancements

Skynet is an IPSet-based firewall extension for ASUS routers running [Asuswrt-Merlin](https://github.com/RMerl/asuswrt-merlin.ng). It adds configurable IPv4 blacklists and whitelists to the router firewall without replacing the built-in SPI firewall or AiProtection.

Skynet can filter inbound and outbound traffic, including traffic handled by OpenVPN and WireGuard server interfaces. Entries can be managed as individual IPv4 addresses, CIDR ranges, resolved domains, ASNs, countries, or consolidated threat feeds. Logging, statistics, IoT isolation, scheduled updates, a command-line interface, and an Asuswrt-Merlin WebUI are included.

Official source code and releases are published through the [Skynet GitHub repository](https://github.com/Adamm00/IPSet_ASUS). Support and release discussion are available on [SNBForums](https://www.snbforums.com/threads/skynet-v8-router-firewall-security-enhancements.96167/).

## Donate

Skynet is free and open source. Development can be supported through [PayPal](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=BPN4LTRZKDTML).

## Features

- Blocks configured sources before inbound traffic reaches the router or forwarded services.
- Blocks configured destinations for LAN clients, the router itself, and supported VPN server traffic.
- Maintains separate IPSet collections for automatic, domain, user, temporary, whitelist, and IoT policy.
- Downloads, validates, caches, consolidates, and reports a managed selection of IPv4 threat feeds, including source state and content age. A default or custom filter list supplies the initial selection.
- Supports permanent and temporary IPv4/CIDR and ASN bans, plus manual rules for domains, countries, imports, and whitelists.
- Imports AiProtection detections and automatically whitelists required router, DNS, VPN, and optional CDN ranges.
- Restricts selected IoT devices while retaining access to configured services and supported VPN server networks.
- Records blocked traffic and provides searchable CLI reports, connection details, associated domains, and country information when enabled.
- Integrates with the Asuswrt-Merlin WebUI for statistics, common settings, manual rules, threat-feed management, malware list updates, country blocking, and IoT isolation.

## Requirements

- A supported ASUS router running Asuswrt-Merlin with IPSet version 6 or 7.
- A writable USB partition recognised by the installer.
- Enough free USB space for Skynet data and swap when required. A 1GB swap file is the minimum supported size; 2GB is recommended.
- SSH access to the router for manual installation. The installer enables custom JFFS scripts if required and may request a reboot.

Swap is optional on 2GB-class routers with at least 1.5GiB of usable RAM. Smaller routers require a swap file rather than a swap partition. The installer can create and maintain the swap file automatically; existing optional swap is left in place.

## Installation

Run the following command from an SSH session:

```sh
/usr/sbin/curl -fsSL "https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh" -o "/jffs/scripts/firewall" && chmod 755 "/jffs/scripts/firewall" && sh "/jffs/scripts/firewall" install
```

Skynet can also be installed through amtm:

```sh
amtm
```

The installer prompts for the USB partition, swap size, traffic direction, logging, malware list schedule, and Skynet update schedule. Installation stops if the required WebUI file cannot be downloaded.

## Usage

Run `firewall` to open the interactive menu:

```sh
firewall
```

The same command accepts the arguments documented below. The WebUI is mounted under **Firewall > Skynet** when WebUI integration is enabled and the Asuswrt-Merlin Addons API is available. Packet logging is required only for traffic statistics; settings, rules and source management remain available with logging disabled.

Commands return `0` on success, `1` for a runtime failure, and `2` for an invalid command or input.

[![Skynet CLI](https://i.imgur.com/GLQk72O.png "Skynet CLI")](https://i.imgur.com/GLQk72O.png)

[![Skynet WebUI Overview](https://i.imgur.com/21oBvs5.png "Skynet WebUI Overview")](https://i.imgur.com/21oBvs5.png)

[![Skynet WebUI Settings](https://i.imgur.com/W0zq5GI.png "Skynet WebUI Settings")](https://i.imgur.com/W0zq5GI.png)

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

Temporary rules expire in the kernel without requiring a scheduled Skynet process. Their absolute deadlines are stored separately and recalculated at startup, so restarting or powering off the router cannot extend a ban.

ASN refreshes retain the original rule deadline, including when the announced ranges change. Overlapping temporary owners retain the latest applicable expiry; permanent owners remain active independently. `firewall unban asn` removes the selected ASN's permanent or temporary ownership without removing other rules. Domain bans, imports and whitelists remain permanent.

Country blocking downloads the selected IPdeny lists concurrently over verified HTTPS and accepts only complete public IPv4 CIDRs. A URL-bound validated cache is used with a warning when a selected list is temporarily unavailable. If no matching cache exists, the complete previous country selection is retained. Applying a new country selection replaces the previous selection rather than appending to it.

Domain rules are stored as logical policy and materialised in dedicated dynamic IP sets. Skynet resolves them every six hours, while dnsmasq adds newly observed answers between refreshes. A successful refresh replaces the complete answer set so addresses no longer returned by DNS are removed. Validated answers may be retained for up to 24 hours during a resolver failure; after that they expire instead of remaining trusted indefinitely. New domain rules still require a successful initial resolution, and removals use the stored rule rather than resolving the domain again.

Domain health is reported as `current`, `cached`, `empty`, `expired`, or `failed`. One completed empty lookup retains a recent validated answer; two consecutive empty lookups remove it. Resolver failures retain validated answers within the 24-hour safety window, then report `expired`. Removing a domain does not remove addresses still owned by another rule.

Startup restores validated domain caches without a DNS lookup. Once time is synchronized, known answers retain only the remainder of their 24-hour lifetime, including across restarts. Cached refreshes cannot extend that deadline; shared addresses remain active while any owner has a valid answer. New answers learned by dnsmasq receive the dynamic set's normal timeout. Cached answers recovered from older installations have no recorded lookup time until a successful refresh. Cache-only operations preserve existing lookup timestamps, and identical cache contents are not rewritten. Failed publication restores the previous domain sets, registry and health data.

- `firewall rules status` - Display registered rule totals and the current health of every dynamic domain rule.
- `firewall rules refresh` - Refresh registered domain rules and ASN ranges. Scheduled refreshes update domains every six hours and ASNs once daily.

### Malware Lists

A Skynet filter list contains one HTTP or HTTPS threat-feed URL per line. It supplies the initial selection or replaces it when explicitly imported. Normal updates use the saved selection, so added, removed and disabled sources remain as configured. Existing source details and exclusions are carried into the saved selection; when no source details exist, the configured custom or default filter list is imported on the first malware update.

Skynet refreshes required whitelists, conditionally downloads enabled feeds, validates their IPv4 entries, removes private and reserved ranges, and rebuilds the malware portion of the blacklist. CIDRs are normalized to their network address, `/32` entries become individual IPs, and source counts include only unique usable entries. Ranges overlapping private or reserved space are excluded. Cached files are bound to their complete source URL so changed URLs cannot inherit stale content with the same filename. Source names remain stable when other sources are removed.

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

VPN whitelisting uses Merlin's configured NVRAM values without scanning active routes or interfaces. Each enabled OpenVPN server pool uses its configured subnet and netmask. Configured OpenVPN and WireGuard client endpoints are whitelisted as `/24` networks. Server firewall rules are installed only while the corresponding OpenVPN or WireGuard server is enabled.

### Importing and Removing Lists

Import accepts either a local file path or an HTTP/HTTPS URL. Input files must contain one IPv4 address or CIDR range per line. Private and reserved ranges are ignored. Bare addresses and `/32` entries are handled as IPs; all other valid CIDRs are handled as ranges.

Imports are one-time copies. Skynet retains the imported entries but does not fetch the original file again. For a blacklist that refreshes on schedule, add its URL to Malware Blacklist sources with `firewall banmalware add <url>` or the WebUI threat feed manager. Threat feeds are for blocking, not scheduled whitelist imports.

- `firewall import blacklist /path/to/list.txt "Apples"` - Add valid entries to the blacklist with an optional comment.
- `firewall import whitelist https://example.com/list.txt "Apples"` - Add valid entries to the whitelist with an optional comment.
- `firewall rules remove <rule-id>` - Remove one direct, domain, ASN or imported rule by its stable ID.

### Rule Storage

Skynet records user rules in an atomic rule registry and assigns each rule a stable ID. Comments are descriptive labels and are not used to determine ownership. Direct IP, CIDR and domain rules remain individually manageable, while ASN and imported lists are stored as logical groups backed by validated data.

Automatic feeds, resolved domains, permanent user rules and temporary bans are compiled into separate IPSet components. The firewall continues to use one blocking master and one whitelist master, keeping packet matching short while allowing each policy source to be refreshed or removed independently. Removing one rule does not remove an address still owned or covered by another rule.

Replacement sets size their entry capacity from the prepared list, retaining the standard limits as minimums and allowing 25% headroom for larger inputs. Capacity is a ceiling, not preallocated storage; hash tables start small and grow as entries are loaded. Overlapping rule owners may produce a conservative capacity estimate. Available router RAM still limits usable list size, especially while old and replacement sets coexist. A failed replacement leaves the previous policy active. Existing compatible sets retain their capacity until replaced, and startup restores saved entries without replaying obsolete set-creation limits.

Automatic addresses and ranges remain in `Skynet-Blacklist` and `Skynet-BlockedRanges`. Resolved domain bans use `Skynet-BlacklistDomains`, permanent user rules use `Skynet-UserBans`, and expiring rules use `Skynet-TemporaryBans`. Automatic, domain, and user whitelist entries are separated in the same way. `Skynet-IOT` remains independent.

### Updates

- `firewall update` - Check for an updated Skynet release and install it when available.
- `firewall update check` - Check for an update without installing it.
- `firewall update -f` - Download and install the current release even when the local file already matches.

Updates stage and validate both the firewall script and WebUI before Skynet is unloaded. The staged firewall must pass a shell syntax check and both files must be non-empty. Download or validation failures leave the running installation untouched. Failed unloading, replacement or an interrupted update restores the previous files and uses Merlin's firewall restart to recover protection, schedules and WebUI integration. If files cannot be restored, recovery copies are retained and their location is reported.

### Settings

The interactive Settings menu groups options under Updates & Lists, Protection, IoT WAN Blocking, Logging & Statistics, and Integration & Advanced. Commands remain available directly as documented below.

#### Updates & Lists

- `firewall settings autoupdate enable|disable` - Enable weekly automatic Skynet updates. When disabled, Skynet checks weekly but does not install an update.
- `firewall settings banmalware daily|weekly|disable` - Set or disable scheduled malware blacklist refreshes.

#### Protection

- `firewall settings filter all|inbound|outbound` - Select which traffic direction Skynet filters.
- `firewall settings unbanprivate enable|disable` - Automatically whitelist private addresses observed in blocked traffic and remove exact entries from the IP blacklist.
- `firewall settings banaiprotect enable|disable` - Import or remove IPv4 threats recorded by AiProtection.
- `firewall settings securemode enable|disable` - Control whether Skynet disables WAN access to SSH and the router WebUI when detected.
- `firewall settings cdnwhitelist enable|disable` - Add or remove supported CDN, service, and public DNS ranges from the whitelist.

Repeated AiProtection records are grouped before processing. Successful domain resolutions are reused for 24 hours and failed resolutions for seven days, while a newer AiProtection event is retried immediately. A previous valid mapping is retained if a later lookup fails.

CDN source data is downloaded concurrently and validated before the dynamic whitelist is replaced. If any required source is unavailable or contains no valid IPv4 data, the previous dynamic entries are retained.

#### IoT Isolation

IoT WAN blocking applies to devices in the Skynet IoT IPSet. When enabled, their forwarded WAN traffic is blocked except for the configured TCP/UDP ports and traffic routed through OpenVPN or WireGuard server interfaces. Traffic between local bridges remains subject to Merlin's access controls; Skynet does not override LAN isolation. By default, UDP port 123 remains available for NTP time synchronization; accurate device time is required by certificates, secure connections and scheduled activity. The default can be replaced with up to 15 custom ports or disabled entirely. The saved device list and the blocking switch are managed independently.

- `firewall settings iot ban 192.168.1.50 192.168.1.60` - Add one or more IPv4 addresses or CIDR ranges to the IoT list.
- `firewall settings iot unban 192.168.1.50 192.168.1.60` - Remove one or more IPv4 addresses or CIDR ranges from the IoT list and clear their recorded IoT blocks. Other traffic records are retained.
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
- `firewall settings logsize 10` - Set the collected traffic storage budget from 10 to 200MB. Older detailed events expire first when the budget is reached. Saved budgets above 200MB are capped at 200MB.
- `firewall settings extendedstats enable|disable` - Add associated domain names to statistics when dnsmasq logs are available.
- `firewall settings lookupcountry enable|disable` - Enable or disable online country lookups for statistics.
- `firewall settings syslog auto` - Follow the running logger automatically. Uses Scribe's installed Skynet destination while syslog-ng runs, otherwise the system logger's `-O` output or `/tmp/syslog.log`. Symlinks are resolved and the rotated path defaults to the current path plus `-1`.
- `firewall settings syslog /path/to/syslog [/path/to/rotated-log]` - Select Custom mode and set one or both source paths. Both paths are validated before either changes.
- `firewall settings syslog1 /path/to/rotated-log` - Select Custom mode and change only the rotated source path. Custom paths remain unchanged across startup and logger detection.

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
- `firewall stats search domain example.com` - Resolve a domain and report the available data for each resulting IPv4 address. Rule reasons are joined for the complete address batch, including overlapping manual, imported and domain owners.
- `firewall stats search malware 8.8.8.8` - Search downloaded malware feeds for an IPv4 address or CIDR range.
- `firewall stats search reason "spamhaus" [count]` - Search active automatic and registered rule reasons without performing network lookups.
- `firewall stats search manualbans [count]` - Show recorded manual bans.
- `firewall stats search actions [count]` - Show recent CLI, WebUI, scheduled and startup actions, including degraded and failed outcomes.
- `firewall stats search device 192.168.1.50 [count]` - Show outbound blocks generated by a LAN device.
- `firewall stats search reports [count]` - Show saved periodic summaries.
- `firewall stats search invalid [count]` - Show logged invalid-state packets.
- `firewall stats search iot [count]` - Show logged IoT blocks.
- `firewall stats search connections [ip|port|proto|id] [value]` - Show or filter active connection data when the required AiProtection data is available.
- `firewall stats remove ip 8.8.8.8` - Remove retained events containing an IPv4 address and subtract their contribution from hourly totals.
- `firewall stats remove port 23` - Remove retained events containing a port and subtract their contribution from hourly totals.
- `firewall stats reset` - Generate the current WebUI statistics and clear collected events and trend totals. Collection checkpoints are retained so cleared events are not imported again.

Country fields are omitted when country lookup is disabled. Associated domains are included only when Extended Statistics is enabled and dnsmasq logging data is available.

Generated WebUI statistics resolve country codes in batches of up to 32 addresses and reuse results for seven days. Stale values remain available during a provider outage, unused entries expire after 30 days, and a country lookup failure never prevents statistics generation.

Temporary chart indexes are built in RAM and removed after generation. Only a complete statistics payload is published to USB; a failed generation retains the previous charts. Ban-reason lookups retain metadata only for requested addresses, including matches from imported ranges. Associated-domain scans are skipped when no chart addresses need enrichment.

### Block History

On firmware with compatible built-in SQLite support, Skynet stores collected packet events in `history.db`. No additional package or database server is required. Existing text logs are imported before statistics switch to the database; unsupported firmware retains text logging.

Statistics aggregate retained events directly in SQLite. Whole-history charts use sequential scans, while targeted address searches retain the IP indexes. The WebUI receives bounded results rather than a copy of the database.

Domain-history searches query resolved addresses in one read transaction and return only the first and requested recent events per address, alongside totals and port summaries. Duplicate addresses are searched once.

Detailed events are retained for up to seven days within the configured storage budget. Hourly category totals remain available for 90 days. Capacity may shorten detailed retention; the WebUI shows the oldest available event and whether storage limits have applied. Older trend totals cannot be searched by individual IP address, protocol or port after their detailed events expire.

Each event retains its timestamp, category, source and destination IPv4 addresses, protocol, ports, packet length, interfaces, TCP flags, available ICMP details and logged MAC/link-layer data. The logged link-layer header may identify a gateway rather than the remote IP's device. Normal packet logging omits optional TCP sequence numbers and TCP/IP option dumps. This changes diagnostic detail, not packet blocking or the number of collected events.

Hourly maintenance and explicit refreshes collect newly completed syslog records. Ingestion checkpoints advance only with committed events. Records already lost to system-log rotation cannot be recovered. Counts represent recorded packet events, not unique connections or every packet the firewall may have dropped.

Unchanged source files are skipped after their saved checkpoint is verified. Storage-budget checks use database page metadata and count retained events only when space must be reclaimed.

Changing rules or removing IoT entries does not erase historical traffic. Use the explicit statistics removal or reset commands to delete collected records. Domain names and ban reasons shown by current lookups describe current metadata, not necessarily the policy that applied when an older packet was logged.

### Diagnostics and Maintenance

- `firewall debug watch` - Follow Skynet block entries in real time.
- `firewall debug watch ip 8.8.8.8` - Follow entries involving an IPv4 address.
- `firewall debug watch port 23` - Follow entries involving a port.
- `firewall debug info` - Display system, storage, logging, configuration, and integrity checks.
- `firewall debug info extended` - Include the current Skynet configuration in the diagnostic output.
- `firewall debug genstats` - Regenerate WebUI statistics.
- `firewall debug clean` - Archive and clean handled Skynet syslog entries.
- `firewall debug swap install|uninstall` - Create or remove the Skynet-managed swap file.
- `firewall debug backup` - Save configuration, logical rules, source caches, IPSet data and logs. Keep the latest three dated restore points in `backups/`, with `Skynet-Backup.tar.gz` also pointing to the latest archive's data where hard links are supported. The existing archive is retained as the first point when upgrading. A failed archive build retains the previous backup. Creating dated points requires synchronized router time.
- `firewall debug restore [point-id]` - Validate and restore the latest backup or a specific point, retaining current action history. The point ID is the timestamp and digest in its filename, without `Skynet-Backup-` or `.tar.gz`. Rebuilds Skynet policy from local data without restarting Merlin's firewall. Cached manual domain rules are restored; transient DNS-learned addresses repopulate through normal DNS queries. Previous files are retained until policy and integration checks pass, and restored if the operation fails. Invalid archives are rejected before changing installed data.

Backup validation rejects symbolic and hard links, unsupported archive paths, executable configuration content and unsupported history schemas. Valid empty IPSet snapshots remain restorable. Concurrent firewall-start events wait for an in-progress restore before inspecting the replacement policy.
- `firewall save` - Archive pending logs, verify integrity, and persist durable state only when it changed.
- `firewall restart` - Restart Merlin's firewall once and reconcile Skynet rules without unloading its IPSet data, WebUI, or schedules.

Skynet separates firewall reconciliation from scheduled maintenance. A normal Merlin firewall reload verifies the IPSet topology and Skynet rules, exits immediately when they are correct, or repairs only missing or stale rules. It does not download sources, rebuild existing statistics, rewrite configuration, or save unchanged IPSet data. A cold start restores validated local data and enables permanent protection without requiring internet access. Failed policy initialization is retried on the next start; unfinished WebUI and schedule setup resumes without reloading a successfully restored policy. A missing initial statistics payload is retried separately once time is synchronized, with logging and the WebUI enabled. Completion markers are kept in RAM and reset on reboot.

Packet logging, temporary-rule restoration, rule additions and refreshes, and persistent action timestamps wait for a trustworthy system clock. Permanent blocking, whitelisting, rule removal and IoT enforcement remain available while time synchronization is pending. If time is not ready within five minutes, startup completes in a degraded state and the next firewall reconciliation or hourly maintenance enables the pending time-dependent features.

Startup commits migrated configuration only after the restored policy passes verification. Failed migrations remain eligible for retry; successful migrations are not repeated on subsequent boots.

Hourly maintenance runs at a randomized minute and replaces the previous unconditional full save. It archives new block records, enforces the log limit, prunes expired rules, checks firewall integrity, and writes durable state or WebUI settings only when something changed. Log archival retains Skynet block records and discards Merlin's native `DROP` packet messages, including those recorded before Skynet starts. Unrelated system messages are preserved. The shutdown persistence hook performs a narrow conditional commit without running statistics, security remediation, or a firewall restart.

Manual `firewall save` stops with a failure status if private-address whitelisting or log archival fails, without continuing to save the IPSet snapshot.

If maintenance changes rule or time-dependent state but cannot finish updating the WebUI, a pending marker in RAM retains the refresh request for the next successful maintenance run. Unchanged runs do not regenerate settings.

If another command is active, maintenance waits up to 60 seconds for the state lock. If it remains busy, the run returns a failure status and records `deferred (state-lock)` in debug information without interrupting the active command. Saved settings are reloaded after acquiring the lock. The rule registry is staged for expiry pruning only when a deadline is due; unchanged registries are read without a staging write. Hourly collection cannot recover syslog records already overwritten by rotation during sustained traffic bursts.

## WebUI

The WebUI provides:

- Packet logging and syslog source paths under Statistics, alongside the existing protection, update, IoT and country settings. Changes use the same commands as the CLI. Disabling WebUI integration remains CLI-only because it removes the management page.

- The latest generated blacklist totals and inbound/outbound packet counters.
- Daily block activity and the main CLI top-10 statistics as charts or tables.
- Block History queries retained events in pages of 100, with period, category, IPv4/CIDR, protocol and port filters. Each event expands to show packet details. Export CSV includes up to the newest 1,000 matching events, with a notice when more matches exist.
- History trends show category totals for Today, seven days or 90 days. IP, protocol and port filters apply to detailed events only. Gaps indicate no recorded bucket, not confirmed zero traffic. Pagination keeps the original query window; Refresh History collects pending records and starts a new view.
- IP details including ban reason, country, associated domains, AlienVault OTX, and SpeedGuide links where applicable. Saved rule matches show overlapping bans and allowances, with whitelist precedence and the statistics refresh time. These describe the saved metadata at refresh, not live enforcement or the policy when each historical event occurred.
- Background statistics refresh without navigating away from the page. Every action waits for its matching worker result, and statistics also verify the chart payload belongs to that request. Busy or failed requests report an error and retain the existing charts.
- Common Skynet settings with descriptions and documented defaults.
- Threat-feed status, usable entry counts, last successful checks, content age, source toggles, manual refresh, and feed URL additions/removals. Use Template replaces the saved selection with the default or custom filter list after confirmation.
- Country blocking with country selection and removal.
- Manual IP, range, domain and ASN ban, unban and whitelist management, including grouped imported lists.
- Domain rules expand to show their retained resolved IPv4 addresses and whether the result is current or cached. Up to 64 addresses are displayed per rule, with copying and an explicit limit when more are retained. Opening these details performs no DNS lookup; Refresh Dynamic Rules updates the cached results.
- IP Details lists matching rule owners, identifies permanent and temporary rules, and shows temporary expiry in local 12-hour time. CLI IP searches show remaining lifetime. These details use the saved rule snapshot; they do not reconstruct the policy at the time of an older packet event.
- Add Entries stages IPv4/CIDR entries with the comment currently entered. Staged tags show their saved comments; Apply Rules submits the complete batch together. Changing the comment field does not change previously staged entries. Re-adding a staged address updates its comment.
- Permanent or preset temporary IPv4/CIDR and ASN bans, remaining lifetime, stable rule removal, and a dedicated Temporary filter.
- Activity History shows the latest 200 valid journal entries, ten per page, with category, result and text filters. Export CSV downloads all matching entries within that window, not just the visible page. Older retained entries remain in `events.log`. Country changes identify the countries added or removed, while source refreshes are recorded only when validated content changes.
- Create Backup under Updates runs the same archive operation as `firewall debug backup`. Select a dated restore point to see its local creation time and size. Download Backup saves that point through an authenticated WebUI route. Restore Backup requires confirmation and restores the selected archive using the same validation and rollback as the CLI. Settings, rules, source caches and block history are replaced; current activity history is retained. Traffic may be interrupted briefly while rules are rebuilt. Backups that disable the WebUI must be restored through SSH. Only the latest three points are retained; download older points before creating more backups if you want to keep them. Archives contain private network data; keep downloaded copies somewhere safe.
- IoT isolation with detected client, hostname, IPv4, MAC, online state, device list, port and protocol controls.
- Copyable MAC addresses in blocked-device details when neighbour data is available.

Empty or disabled data sections are collapsed or omitted where appropriate. Retained Block History remains accessible with packet logging disabled. Charts are generated from collected events, while blacklist totals and packet counters are captured during statistics generation. The page does not query the live firewall for every chart or download the complete history database.

Block Activity shows the past 24 hours at the last statistics refresh, grouped by local clock hour with labels such as 1am, 2am and 3am. The first and current hours include only events inside that rolling window, so a refresh between hours shows 25 buckets with partial totals at each end. Chart hits count retained logged events and survive restarts while that history remains available. The inbound/outbound headline counters count packets since their firewall rules were installed; they reset when those rules are rebuilt or the router reboots. They are not lifetime totals and can differ from logged-event counts when logging is disabled or rate-limited. Log storage accepts 10–200MB.

Temporary-rule controls are disabled until the router clock is synchronized. Expired rows are hidden immediately, while counters and settings refresh without rebuilding chart statistics.

## Action History

Skynet records completed changes and operational failures as a structured, bounded action journal in `events.log`. Each entry identifies its origin, result, subsystem, operation and affected values. Normal writes append one small record; the file is compacted only when it exceeds 1MB or 2,000 entries. Existing text summaries remain available until normal retention compaction, invalid or incomplete records are discarded during compaction, and the current history is retained when restoring an older Skynet backup.

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

- [Common issues and documentation](https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues)
- [Official SNBForums support thread](https://www.snbforums.com/threads/release-skynet-router-firewall-security-enhancements.16798/)
- [GitHub issues](https://github.com/Adamm00/IPSet_ASUS/issues)


## About

> Skynet gained self-awareness after it had spread into millions of computer servers all across the world; realizing the extent of its abilities, its creators tried to deactivate it. In the interest of self-preservation, Skynet concluded that all of humanity would attempt to destroy it and impede its capability in safeguarding the world. Its operations are almost exclusively performed by servers, mobile devices, drones, military satellites, war-machines, androids and cyborgs (usually a terminator), and other computer systems. As a programming directive, Skynet's manifestation is that of an overarching, global, artificial intelligence hierarchy (AI takeover), which seeks to exterminate the human race in order to fulfill the mandates of its original coding. (▀̿Ĺ̯▀̿ ̿)
