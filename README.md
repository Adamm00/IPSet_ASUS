# Skynet - Firewall & Security Enhancements   [![Build Status](https://travis-ci.com/Adamm00/IPSet_ASUS.svg?branch=master)](https://travis-ci.com/Adamm00/IPSet_ASUS)

Are you concerned about the security of your home network? Look no further than Skynet - a powerful firewall and security tool designed exclusively for ASUS routers running the [AsusWRT-Merlin firmware](https://github.com/RMerl/asuswrt-merlin.ng).

Skynet is a lightweight firewall addition that uses IPSet and has been featured on [SmallNetBuilder](https://www.snbforums.com/threads/release-skynet-router-firewall-security-enhancements.16798/). Its goal is to enhance the firmware's built-in functionality, including SPI Firewall, Brute Force Detection, and AiProtect. With Skynet, you can easily implement custom firewall rules that meet your specific needs and preferences.

But Skynet is much more than just a firewall. It's a comprehensive security tool that can ban single IPs, domains, or entire countries. It can also pull predefined malware lists from reputable providers and even secure IoT devices to prevent unauthorized connections. Skynet serves as the one-stop-shop for all your router security needs and is the first line of defense for your home network.

Moreover, Skynet is fully compatible with OpenVPN implementations from popular providers like [Private Internet Access](https://www.privateinternetaccess.com/). It also supports various user scripts such as [Diversion](https://www.snbforums.com/threads/diversion-the-router-adblocker.48538/) & [Scribe](https://www.snbforums.com/threads/scribe-syslog-ng-and-logrotate-installer.55853/).

With Skynet and AsusWRT-Merlin, you can rest assured that your router is fully protected against potential security threats. It's the perfect solution for ASUS router users looking for a reliable and easy-to-use security tool.

In conclusion, if you're an ASUS router user running the AsusWRT-Merlin firmware and looking for a way to enhance your router's built-in security features, Skynet is the ideal solution. Its comprehensive range of features and capabilities make it the go-to choice for router security, so don't wait any longer to get started with Skynet and safeguard your network today.

## Donate

You can use this script for free as it will always remain open source. However, if you would like to contribute to future development efforts, you have the option to support us by [Donating With PayPal.](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=BPN4LTRZKDTML)

## Usage

Skynet provides both a user interactive menu, and command line interface for those who prefer it.

To open the menu its as simple as;

```Shell
firewall
```

[![Skynet GUI](https://i.imgur.com/RgvGQKn.png "Skynet GUI")](https://i.imgur.com/RgvGQKn.png "Skynet GUI")

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
( firewall settings iotlogging enable|disable ) Enabled/Disable IOT Logging For Protected Devices
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
