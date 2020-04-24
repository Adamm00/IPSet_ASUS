# Skynet - Firewall & Security Enhancements   [![Build Status](https://travis-ci.com/Adamm00/IPSet_ASUS.svg?branch=master)](https://travis-ci.com/Adamm00/IPSet_ASUS)

Lightweight firewall addition for ARM/HND based ASUS Routers using IPSet as seen on [SmallNetBuilder](https://www.snbforums.com/threads/release-skynet-router-firewall-security-enhancements.16798/)

Skynet is the first comprehensive IP banning and security tool exclusively for Asus Devices.

The goal of this tool is to enhance the firmware's built in functionality such as the SPI Firewall, Brute Force Detection and AiProtect while adding easy to use tools for users to implement custom firewall rules they desire. Skynet has a range of feature from banning single IPs, domains, entire countries or pulling predefined malware lists from reputable providers. Skynet can also be used to secure IOT device and prevent them from phoning home. It is the one stop shop for router security and the first line of defense in your home network.

Skynet fully supports OpenVPN implementations from providers like [Private Internet Access](https://www.privateinternetaccess.com/), along with various user scripts such as [Diversion](https://www.snbforums.com/threads/diversion-the-router-adblocker.48538/) & [Scribe](https://www.snbforums.com/threads/scribe-syslog-ng-and-logrotate-installer.55853/). Extensive testing has also been done with home security products like the [Annke DW81KE](https://www.amazon.com/dp/B07L4R4YNP/?tag=snbforums-20) and NAS systems including the [QNAP TVS-672XT](https://www.amazon.com/dp/B07JNLNHD1/?tag=snbforums-20).

## Donate

This script will always be open source and free to use, but if you want to support future development you can do so by [Donating With PayPal.](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=BPN4LTRZKDTML)

## Usage

Skynet provides both a user interactive menu, and command line interface for those who prefer it.

To open the menu its as simple as;

```Shell
firewall
```

[![Skynet GUI](https://i.imgur.com/q8AGBQp.png "Skynet GUI")](https://i.imgur.com/q8AGBQp.png "Skynet GUI")

[![Skynet WebUI 1](https://i.imgur.com/OgWhLN5.png "Skynet WebUI 1")](https://i.imgur.com/OgWhLN5.png "Skynet WebUI 1")

[![Skynet WebUI 2](https://i.imgur.com/zTncPFV.png "Skynet WebUI 2")](https://i.imgur.com/zTncPFV.png "Skynet WebUI 2")

[![Skynet WebUI 3](https://i.imgur.com/v4BAIS3.png "Skynet WebUI 3")](https://i.imgur.com/v4BAIS3.png "Skynet WebUI 3")


## Installation

In your favorite SSH Client;

```Shell
/usr/sbin/curl -s "https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh" -o "/jffs/scripts/firewall" && chmod 755 /jffs/scripts/firewall && sh /jffs/scripts/firewall install
```

For firmware versions 384.15+ this can also be installed via AMTM by following the menu prompts;
```Shell
amtm
```

## Help

```Shell
Example Unban Commands;
( firewall unban ip 8.8.8.8 ) This Unbans The IP Specified
( firewall unban range 8.8.8.8/24 ) This Unbans the CIDR Block Specified
( firewall unban domain google.com ) This Unbans the URL Specified
( firewall unban comment "Apples" ) This Unbans Entries With The Comment Apples
( firewall unban country ) This Unbans Entries Added By The "Ban Country" Feature
( firewall unban asn AS123456 ) This Unbans the ASN Specified
( firewall unban malware ) This Unbans Entries Added By The "Ban Malware" Feature
( firewall unban nomanual ) This Unbans Everything But Manual Bans
( firewall unban all ) This Unbans All Entries From Both Blacklists

Example Ban Commands;
( firewall ban ip 8.8.8.8 "Apples" ) This Bans The IP Specified With The Comment Apples
( firewall ban range 8.8.8.8/24 "Apples" ) This Bans the CIDR Block Specified With The Comment Apples
( firewall ban domain google.com ) This Bans the URL Specified
( firewall ban country "pk cn sa" ) This Bans The Known IPs For The Specified Countries (Accepts Single/Multiple Inputs If Quoted) https://www.ipdeny.com/ipblocks/
( firewall ban asn AS123456 ) This Bans the ASN Specified

Example Banmalware Commands;
( firewall banmalware ) This Bans IPs From The Predefined Filter List
( firewall banmalware google.com/filter.list ) This Uses The Filter List From The Specified URL
( firewall banmalware reset ) This Will Reset Skynet Back To The Default Filter URL
( firewall banmalware exclude "list1.ipset|list2.ipset" ) This Will Exclude Lists Matching The Names "list1.ipset list2.ipset" From The Current Filter (Quotes And Pipes Are Nessessary For Seperating Multiple Entries!)
( firewall banmalware exclude reset ) This Will Reset The Exclusion List

Example Whitelist Commands;
( firewall whitelist ip 8.8.8.8 "Apples" ) This Whitelists The IP Specified With The Comment Apples
( firewall whitelist range 8.8.8.8/24 "Apples" ) This Whitelists The Range Specified With The Comment Apples
( firewall whitelist domain google.com) This Whitelists the URL Specified
( firewall whitelist asn AS123456 ) This Whitelists the ASN Specified
( firewall whitelist vpn) Refresh VPN Whitelist
( firewall whitelist remove all) This Removes All Non-Default Entries
( firewall whitelist remove entry 8.8.8.8) This Removes IP/Range Specified
( firewall whitelist remove comment "Apples" ) This Removes Entries With The Comment Apples
( firewall whitelist refresh ) Regenerate Shared Whitelist Files
( firewall whitelist view ips|domains|imported ) View Whitelist Entries Based On Category (Leave Blank For All)

Example Import Commands;
( firewall import blacklist file.txt "Apples" ) This Bans All IPs From URL/Local File With The Comment Apples
( firewall import whitelist file.txt "Apples" ) This Whitelists All IPs From URL/Local File With The Comment Apples

Example Deport Commands;
( firewall deport blacklist file.txt ) This Unbans All IPs From URL/Local File
( firewall deport whitelist file.txt ) This Unwhitelists All IPs From URL/Local File

Example Update Commands;
( firewall update ) Standard Update Check - If Nothing Detected Exit
( firewall update check ) Check For Updates Only - Wont Update If Detected
( firewall update -f ) Force Update Even If No Changes Detected

Example Settings Commands;
( firewall settings autoupdate enable|disable ) Enable/Disable Skynet Autoupdating
( firewall settings banmalware daily|weekly|disable ) Enable/Disable Automatic Malware List Updating
( firewall settings logmode enable|disable ) Enable/Disable Logging
( firewall settings filter all|inbound|outbound ) Select What Traffic To Filter
( firewall settings unbanprivate enable|disable ) Enable/Disable Unban_PrivateIP Function
( firewall settings loginvalid enable|disable ) Enable/Disable Invalid Packet Logging
( firewall settings banaiprotect enable|disable ) Enable/Disable Banning IPs Flagged By AiProtect
( firewall settings securemode enable|disable ) Enable/Disable Insecure Settings Being Applied In WebUI
( firewall settings fs google.com/filter.list|disable ) Configure/Disable Fast Malware List Switching
( firewall settings syslog|syslog1 /tmp/syslog.log|default ) Configure Custom Syslog/Syslog-1 Location
( firewall settings iot unban|ban 8.8.8.8,9.9.9.9 ) Unban|Ban IOT Device(s) (or CIDR) From Accessing WAN (Allow NTP / Remote Access Via OpenVPN Only) (Use Comma As Separator)
( firewall settings iot view ) View Currently Banned IOT Devices
( firewall settings iot ports 123,124,125 ) Allow Port(s) To Access WAN (Use Comma As Separator)
( firewall settings iot ports reset ) Reset Allowed Port List To Default
( firewall settings iot proto udp|tcp|all ) Select IOT Allowed Port Protocol
( firewall settings lookupcountry enable|disable ) Enable/Disable Country Lookup For Stat Data
( firewall settings cdnwhitelist enable|disable ) Enable/Disable CDN Whitelisting
( firewall settings webui enable|disable ) Enable/Disable WebUI

Example Debug Commands;
( firewall debug watch ) Show Debug Entries As They Appear
( firewall debug info ) Print Useful Debug Info
( firewall debug info extended ) Debug Info + Config
( firewall debug genstats ) Update WebUI Stats
( firewall debug clean ) Cleanup Syslog Entries
( firewall debug swap install|uninstall ) Install/Uninstall SWAP File
( firewall debug backup ) Backup Skynet Files To Skynets Install Directory With The Name "Skynet-Backup.tar.gz"
( firewall debug restore ) Restore Backup Files From Skynets Install Directory With The Name "Skynet-Backup.tar.gz"

Example Stats Commands;
( firewall stats ) Compile Stats With Default Top10 Output
( firewall stats 20 ) Compile Stats With Customizable Top20 Output
( firewall stats tcp ) Compile Stats Showing Only TCP Entries
( firewall stats tcp 20 ) Compile Stats Showing Only TCP Entries With Customizable Top20 Output
( firewall stats search port 23 ) Search Logs For Entries On Port 23
( firewall stats search port 23 20 ) Search Logs For Entries On Port 23 With Customizable Top20 Output
( firewall stats search ip 8.8.8.8 ) Search Logs For Entries On 8.8.8.8
( firewall stats search ip 8.8.8.8 20 ) Search Logs For Entries On 8.8.8.8 With Customizable Top20 Output
( firewall stats search malware 8.8.8.8 ) Search Malwarelists For Specified IP
( firewall stats search manualbans ) Search For All Manual Bans
( firewall stats search device 192.168.1.134 ) Search For All Outbound Entries From Local Device 192.168.1.134
( firewall stats search device reports ) Search Previous Hourly Report History
( firewall stats search invalid ) Search For Invalid Packets
( firewall stats search iot ) Search For IOT Packets
( firewall stats search connections ip|port|proto|id xxxxxxxxxx) Search Active Connections
( firewall stats remove ip 8.8.8.8 ) Remove Log Entries Containing IP 8.8.8.8
( firewall stats remove port 23 ) Remove Log Entries Containing Port 23
( firewall stats reset ) Reset All Collected Logs
```

### About

> Skynet gained self-awareness after it had spread into millions of computer servers all across the world; realizing the extent of its abilities, its creators tried to deactivate it. In the interest of self-preservation, Skynet concluded that all of humanity would attempt to destroy it and impede its capability in safeguarding the world. Its operations are almost exclusively performed by servers, mobile devices, drones, military satellites, war-machines, androids and cyborgs (usually a terminator), and other computer systems. As a programming directive, Skynet's manifestation is that of an overarching, global, artificial intelligence hierarchy (AI takeover), which seeks to exterminate the human race in order to fulfill the mandates of its original coding. (▀̿Ĺ̯▀̿ ̿)
