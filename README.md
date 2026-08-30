# Skynet - Router Firewall & Security Enhancements

Skynet is an IPSet-based firewall extension for ASUS routers running [Asuswrt-Merlin](https://github.com/RMerl/asuswrt-merlin.ng). It adds configurable IPv4 blacklists and whitelists to the router firewall without replacing the built-in SPI firewall or AiProtection.

Skynet can filter inbound and outbound traffic, including traffic handled by OpenVPN and WireGuard server interfaces. Entries can be managed as individual IPv4 addresses, CIDR ranges, resolved domains, ASNs, countries, or consolidated threat feeds. Logging, statistics, IoT isolation, scheduled updates, a command-line interface, and an Asuswrt-Merlin WebUI are included.

Official source code and releases are published through the [Skynet GitHub repository](https://github.com/Adamm00/IPSet_ASUS). Support and release discussion are available on [SNBForums](https://www.snbforums.com/threads/skynet-v8-router-firewall-security-enhancements.96167/).

## Donate

Skynet is free and open source. Development can be supported through [PayPal](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=BPN4LTRZKDTML).

## Features

- Blocks configured sources before inbound traffic reaches the router or forwarded services.
- Blocks configured destinations for LAN clients, the router itself, and supported VPN server traffic.
- Maintains separate IPSet collections for individual IPv4 addresses, network ranges, whitelisted entries, and IoT devices.
- Downloads, validates, caches, consolidates, and reports IPv4 threat feeds from a configurable filter list.
- Supports manual bans and whitelists by IPv4 address, CIDR range, domain, ASN, country, or comment.
- Imports AiProtection detections and automatically whitelists required router, DNS, VPN, and optional CDN ranges.
- Restricts selected IoT devices while retaining access to configured services and supported VPN server networks.
- Records blocked traffic and provides searchable CLI reports, connection details, associated domains, and country information when enabled.
- Integrates with the Asuswrt-Merlin WebUI for statistics, common settings, threat-feed management, malware list updates, and country blocking.

## Requirements

- A supported ASUS router running Asuswrt-Merlin with IPSet version 6 or 7.
- A writable USB partition recognised by the installer.
- Enough free USB space for a swap file and Skynet data. A 1GB swap file is the minimum supported size; 2GB is recommended.
- SSH access to the router for manual installation. The installer enables custom JFFS scripts if required and may request a reboot.

Skynet requires a swap file rather than a swap partition. The installer can create and maintain the swap file automatically.

## Installation

Run the following command from an SSH session:

```sh
/usr/sbin/curl -fsSL "https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh" -o "/jffs/scripts/firewall" && chmod 755 "/jffs/scripts/firewall" && sh "/jffs/scripts/firewall" install
```

Skynet can also be installed through amtm:

```sh
amtm
```

The installer prompts for the USB partition, swap size, traffic direction, logging, malware list schedule, and Skynet update schedule.

## Usage

Run `firewall` to open the interactive menu:

```sh
firewall
```

The same command accepts the arguments documented below. The WebUI is mounted under **Firewall > Skynet** when logging, WebUI integration, and the Asuswrt-Merlin Addons API are available.

Commands return `0` on success, `1` for a runtime failure, and `2` for an invalid command or input.

[![Skynet CLI](https://i.imgur.com/GLQk72O.png "Skynet CLI")](https://i.imgur.com/GLQk72O.png)

[![Skynet WebUI Overview](https://i.imgur.com/21oBvs5.png "Skynet WebUI Overview")](https://i.imgur.com/21oBvs5.png)

[![Skynet WebUI Settings](https://i.imgur.com/W0zq5GI.png "Skynet WebUI Settings")](https://i.imgur.com/W0zq5GI.png)

## Command Reference

### Blocking

- `firewall ban ip 8.8.8.8 "Apples"` - Ban an IPv4 address with an optional comment.
- `firewall ban range 8.8.8.0/24 "Apples"` - Ban an IPv4 CIDR range with an optional comment.
- `firewall ban domain example.com` - Resolve a domain and ban its current public IPv4 addresses.
- `firewall ban country pk cn sa` - Replace the current country bans with the known IPv4 ranges assigned to the supplied two-letter country codes.
- `firewall ban asn AS123456` - Download and ban the IPv4 ranges announced by an ASN.
- `firewall unban ip 8.8.8.8 1.1.1.1` - Remove one or more IPv4 addresses from the blacklist.
- `firewall unban range 8.8.8.0/24 1.1.1.0/24` - Remove one or more exact CIDR ranges from the range blacklist.
- `firewall unban domain example.com` - Resolve a domain and unban its current IPv4 addresses.
- `firewall unban comment "Apples"` - Remove blacklist entries whose comments contain the supplied text.
- `firewall unban country` - Remove all entries created by country blocking.
- `firewall unban asn AS123456` - Remove entries labelled with the supplied ASN.
- `firewall unban malware` - Remove entries created from malware feeds.
- `firewall unban nomanual` - Remove all non-manual bans while retaining manual IP and range bans.
- `firewall unban all` - Flush both blacklists and clear the stored block log.

Country blocking uses aggregated IPv4 allocation data. Applying a new country selection replaces the previous selection rather than appending to it.

Domain commands validate the hostname and resolve its complete IPv4 answer set before changing the firewall. A failed lookup or update leaves the existing IPSet unchanged.

### Malware Lists

A Skynet filter list contains one HTTP or HTTPS threat-feed URL per line. Skynet resolves the complete source list before exclusions, refreshes required whitelists, conditionally downloads enabled feeds, validates their IPv4 entries, removes private and reserved ranges, and rebuilds the malware portion of the blacklist. Cached files are bound to their complete source URL so changed URLs cannot inherit stale content with the same filename.

Each source is reported as `current`, `cached`, `failed`, or `excluded`. A validated cache may be used when its source cannot be refreshed. If any enabled source has no valid matching cache, the update fails and the complete existing blacklist and saved source selection are retained.

- `firewall banmalware` - Refresh the malware blacklist using the configured filter list.
- `firewall banmalware https://example.com/filter.list` - Save the supplied filter-list URL as the primary source and refresh the malware blacklist.
- `firewall banmalware reset` - Restore the default Skynet filter-list URL and refresh the malware blacklist.
- `firewall banmalware status` - Display the update schedule, filter list, last update, and source-state totals.
- `firewall banmalware sources` - Display every source, its usable entry count, state, last successful check, and URL.
- `firewall banmalware exclude list1.ipset list2.ipset` - Exclude filter-list URLs with the supplied filenames, then refresh the malware blacklist.
- `firewall banmalware include list1.ipset list2.ipset` - Re-enable one or more excluded source filenames, then refresh the malware blacklist.
- `firewall banmalware exclude reset` - Clear the excluded filenames and refresh the malware blacklist.

### Whitelisting

- `firewall whitelist ip 8.8.8.8 "Apples"` - Whitelist an IPv4 address with an optional comment and remove an exact matching ban.
- `firewall whitelist range 8.8.8.0/24 "Apples"` - Whitelist an IPv4 CIDR range with an optional comment and remove an exact matching ban.
- `firewall whitelist domain example.com` - Resolve a domain and whitelist its current IPv4 addresses.
- `firewall whitelist asn AS123456` - Download and whitelist the IPv4 ranges announced by an ASN.
- `firewall whitelist vpn` - Refresh detected VPN subnet whitelist entries.
- `firewall whitelist remove entry 8.8.8.8` - Remove an exact IPv4 address or CIDR range from the whitelist.
- `firewall whitelist remove comment "Apples"` - Remove whitelist entries whose comments contain the supplied text.
- `firewall whitelist remove all` - Flush the whitelist and rebuild only the automatic and shared entries.
- `firewall whitelist refresh` - Refresh automatic, shared, VPN, CDN, and persistent domain whitelist entries.
- `firewall whitelist view` - Display all whitelist entries.
- `firewall whitelist view ips|domains|imported` - Display only the selected class of manual whitelist entry.

### Importing and Removing Lists

Import and deport accept either a local file path or an HTTP/HTTPS URL. Input files must contain one IPv4 address or CIDR range per line. Private and reserved ranges are ignored.

- `firewall import blacklist /path/to/list.txt "Apples"` - Add valid entries to the blacklist with an optional comment.
- `firewall import whitelist https://example.com/list.txt "Apples"` - Add valid entries to the whitelist with an optional comment.
- `firewall deport blacklist /path/to/list.txt` - Remove exact entries in the file from the blacklists.
- `firewall deport whitelist https://example.com/list.txt` - Remove exact entries in the file from the whitelist.

### Updates

- `firewall update` - Check for an updated Skynet release and install it when available.
- `firewall update check` - Check for an update without installing it.
- `firewall update -f` - Download and install the current release even when the local file already matches.

Each managed file is downloaded to a temporary path and replaces its existing copy only after that transfer completes successfully.

### Settings

The interactive Settings menu groups options under Updates & Lists, Protection, IoT Isolation, Logging & Statistics, and Integration & Advanced. Commands remain available directly as documented below.

#### Updates & Lists

- `firewall settings autoupdate enable|disable` - Enable weekly automatic Skynet updates. When disabled, Skynet checks weekly but does not install an update.
- `firewall settings banmalware daily|weekly|disable` - Set or disable scheduled malware blacklist refreshes.

#### Protection

- `firewall settings filter all|inbound|outbound` - Select which traffic direction Skynet filters.
- `firewall settings unbanprivate enable|disable` - Automatically whitelist private addresses observed in blocked traffic and remove exact entries from the IP blacklist.
- `firewall settings banaiprotect enable|disable` - Import or remove IPv4 threats recorded by AiProtection.
- `firewall settings securemode enable|disable` - Control whether Skynet disables WAN access to SSH and the router WebUI when detected.
- `firewall settings cdnwhitelist enable|disable` - Add or remove supported CDN, service, and public DNS ranges from the whitelist.

#### IoT Isolation

IoT blocking applies to devices in the Skynet IoT IPSet. When enabled, their forwarded WAN traffic is blocked except for ICMP, the configured TCP/UDP ports, and traffic routed through active OpenVPN or WireGuard server interfaces. By default, UDP port 123 remains available for NTP time synchronization; accurate device time is required by certificates, secure connections and scheduled activity. The default can be replaced with up to 15 custom ports or disabled entirely. The saved device list and the blocking switch are managed independently.

- `firewall settings iot ban 192.168.1.50 192.168.1.60` - Add one or more IPv4 addresses or CIDR ranges to the IoT list.
- `firewall settings iot unban 192.168.1.50 192.168.1.60` - Remove one or more IPv4 addresses or CIDR ranges from the IoT list.
- `firewall settings iot enable|disable` - Start or pause IoT blocking without clearing the saved device list.
- `firewall settings iot view` - Display detected clients, their IoT state, and the current allowed protocol and ports.
- `firewall settings iot ports 123 124 125` - Replace the allowed WAN port list. Ports must be between 1 and 65535, with a maximum of 15 entries.
- `firewall settings iot ports default` - Allow only UDP port 123 for NTP time synchronization.
- `firewall settings iot ports none` - Allow no TCP or UDP WAN ports. ICMP and active VPN server-interface exceptions remain available.
- `firewall settings iot proto udp|tcp|all` - Select the protocol used by a custom allowed-port list.
- `firewall settings iotlogging enable|disable` - Enable or disable logging for blocked IoT traffic.

Changing the IoT device list does not enable or disable enforcement. Use the master IoT setting in the CLI or WebUI to control blocking.

#### Logging & Statistics

- `firewall settings logmode enable|disable` - Enable or disable logging of Skynet blocks. Statistics depend on this data.
- `firewall settings loginvalid enable|disable` - Enable or disable logging of new invalid-state packets handled by the router's drop chain.
- `firewall settings logsize 10` - Set the block-log limit in MB. The minimum value is 10MB.
- `firewall settings extendedstats enable|disable` - Add associated domain names to statistics when dnsmasq logs are available.
- `firewall settings syslog /path/to/syslog|default` - Set the active syslog path or restore `/tmp/syslog.log`.
- `firewall settings syslog1 /path/to/syslog-1|default` - Set the rotated syslog path or restore `/tmp/syslog.log-1`.
- `firewall settings lookupcountry enable|disable` - Enable or disable online country lookups for statistics.

#### Integration & Advanced

- `firewall settings webui enable|disable` - Mount or remove the Skynet page in the Asuswrt-Merlin WebUI.

### Statistics

- `firewall stats` - Display the standard top 10 statistics report.
- `firewall stats 20` - Display up to 20 results per report section.
- `firewall stats tcp|udp|icmp` - Limit the report to a protocol.
- `firewall stats tcp 20` - Combine a protocol filter with a custom result count.
- `firewall stats search port 23 [count]` - Show activity involving a port.
- `firewall stats search ip 8.8.8.8 [count]` - Show ban status, reasons, associated domains, location, and logged activity for an IPv4 address.
- `firewall stats search domain example.com` - Resolve a domain and report the available data for each resulting IPv4 address.
- `firewall stats search malware 8.8.8.8` - Search downloaded malware feeds for an IPv4 address or CIDR range.
- `firewall stats search reason "spamhaus" [count]` - Search live IPSet comments for a ban reason without performing network lookups.
- `firewall stats search manualbans [count]` - Show recorded manual bans.
- `firewall stats search device 192.168.1.50 [count]` - Show outbound blocks generated by a LAN device.
- `firewall stats search reports [count]` - Show saved periodic summaries.
- `firewall stats search invalid [count]` - Show logged invalid-state packets.
- `firewall stats search iot [count]` - Show logged IoT blocks.
- `firewall stats search connections [ip|port|proto|id] [value]` - Show or filter active connection data when the required AiProtection data is available.
- `firewall stats remove ip 8.8.8.8` - Remove logged entries containing an IPv4 address.
- `firewall stats remove port 23` - Remove logged entries containing a port.
- `firewall stats reset` - Generate the current WebUI statistics and clear collected block data.

Country fields are omitted when country lookup is disabled. Associated domains are included only when Extended Statistics is enabled and dnsmasq logging data is available.

### Diagnostics and Maintenance

- `firewall debug watch` - Follow Skynet block entries in real time.
- `firewall debug watch ip 8.8.8.8` - Follow entries involving an IPv4 address.
- `firewall debug watch port 23` - Follow entries involving a port.
- `firewall debug info` - Display system, storage, logging, configuration, and integrity checks.
- `firewall debug info extended` - Include the current Skynet configuration in the diagnostic output.
- `firewall debug genstats` - Regenerate WebUI statistics.
- `firewall debug clean` - Archive and clean handled Skynet syslog entries.
- `firewall debug swap install|uninstall` - Create or remove the Skynet-managed swap file.
- `firewall debug backup` - Save the current configuration, IPSet data, and logs to `Skynet-Backup.tar.gz` in the install directory.
- `firewall debug restore` - Restore `Skynet-Backup.tar.gz` and restart the firewall service.

## WebUI

The WebUI provides:

- The latest generated blacklist totals and inbound/outbound packet counters.
- Daily block activity and the main CLI top-10 statistics as charts or tables.
- IP details including ban reason, country, associated domains, AlienVault OTX, and SpeedGuide links where applicable.
- Background statistics refresh without navigating away from the page.
- Common Skynet settings with descriptions and documented defaults.
- Threat-feed status, usable entry counts, last successful checks, source toggles, manual refresh, and primary filter-list configuration.
- Country blocking with country selection and removal.
- IoT isolation with detected client, hostname, IPv4, MAC, online state, device list, port and protocol controls.
- Copyable MAC addresses in blocked-device details when neighbour data is available.

Empty or disabled data sections are collapsed or omitted where appropriate. Charts are generated from Skynet's stored logs, while blacklist totals and packet counters are captured during statistics generation. The page does not query the live firewall for every chart.

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
