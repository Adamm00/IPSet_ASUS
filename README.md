# Skynet - Asus Firewall Addition
Lightweight firewall addition for ARM based ASUS Routers using IPSet as seen on [SmallNetBuilder](https://www.snbforums.com/threads/skynet-asus-firewall-addition-dynamic-malware-country-manual-ip-blocking.16798/)


This script is an extra line of defense from malicious attackers (mostly bots) who repeatedly probe for vunelerabilities and easy to use IPSet functionality to block anything you desire.


## Usage

sh /jffs/scripts/firewall *commandhere*

    "unban"        # <-- Remove Entry From Blacklist (IP/Range/Domain/Port/Country/Malware/Autobans/Nomanual/All)
    "ban"          # <-- Adds Entry To Blacklist (IP/Range/Domain/Port/Country)
    "banmalware"   # <-- Bans Various Malware Domains
    "whitelist"    # <-- Add Entry To Whitelist (IP/Range/Domain/Port/Remove/Refresh/List)
    "import"       # <-- Bans All IPs From URL
    "deport"       # <-- Unbans All IPs From URL
    "save"         # <-- Save Blacklists To ipset.txt
    "disable"      # <-- Disable Firewall
    "update"       # <-- Update Script To Latest Version (check github for changes)
    "debug"	       # <-- Debug Features (Restart/Disable/Watch/Info)
    "stats"        # <-- Show/Search Stats Of Banned IPs (Requires debugging enabled)
    "install"      # <-- Install Script (Or Change Boot Args)
    "uninstall     # <-- Uninstall All Traces Of Script


## Installation

In your favorite SSH Client;

```sh
/usr/sbin/wget -O /jffs/scripts/firewall https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh
chmod +x /jffs/scripts/firewall
sh /jffs/scripts/firewall install
```

## Help

```
Here Are Some Example Unban Commands;
(sh /jffs/scripts/firewall unban) This Requires Manual Input (Only IPs accepted)
(sh /jffs/scripts/firewall unban 8.8.8.8) This Unbans The IP Specified
(sh /jffs/scripts/firewall unban range 8.8.8.8/24) This Unbans the CIDR Block Specified
(sh /jffs/scripts/firewall unban domain) This Requires Manual Input (Only Domains Accepted)
(sh /jffs/scripts/firewall unban domain google.com) This Unbans the URL Specified
(sh /jffs/scripts/firewall unban port 23) This Unbans All Autobans Based On Traffic From Port 23
(sh /jffs/scripts/firewall unban comment "Apples") This Unbans Entries With Comment Containing The Word Apples
(sh /jffs/scripts/firewall unban country) This Unbans Entries Added By The "Ban Country" Feature
(sh /jffs/scripts/firewall unban malware) This Unbans Entries Added By The "Ban Malware" Feature
(sh /jffs/scripts/firewall unban autobans) This Unbans All Autobans
(sh /jffs/scripts/firewall unban nomanual) This Unbans Everything But Manual Bans
(sh /jffs/scripts/firewall unban all) This Unbans All Entries From Both Blacklists

Here Are Some Example Ban Commands;
(sh /jffs/scripts/firewall ban) This Requires Manual Input (Only IPs accepted)
(sh /jffs/scripts/firewall ban 8.8.8.8 Apples) This Bans The IP Specified With Comment Apples
(sh /jffs/scripts/firewall ban range 8.8.8.8/24 Apples) This Bans the CIDR Block Specified With Comment Apples
(sh /jffs/scripts/firewall ban domain) This Requires Manual Input (Only Domains Accepted)
(sh /jffs/scripts/firewall ban domain google.com) This Bans the URL Specified
(sh /jffs/scripts/firewall ban country "pk cn sa") This Bans The Known IPs For The Specified Countries (accepts single/multiple inputs if quoted) http://www.ipdeny.com/ipblocks/data/countries/

Here Are Some Example Banmalware Commands;
(sh /jffs/scripts/firewall banmalware) This Bans IPs From The Predefined Filter List
(sh /jffs/scripts/firewall banmalware google.com/filter.list) This Uses The Fitler List From The Specified URL

Here Are Some Example Whitelist Commands;
(sh /jffs/scripts/firewall whitelist) This Requires Manual Input (Only IPs accepted)
(sh /jffs/scripts/firewall whitelist 8.8.8.8 Apples) This Whitelists The IP or Range Specified With Comment Apples
(sh /jffs/scripts/firewall whitelist domain) This Requires Manual Input (Only Domains Accepted)
(sh /jffs/scripts/firewall whitelist domain google.com) This Whitelists the URL Specified
(sh /jffs/scripts/firewall whitelist port 23) This Whitelists All Autobans Based On Traffic From Port 23
(sh /jffs/scripts/firewall whitelist remove) This Removes All Non-Default Entries
(sh /jffs/scripts/firewall whitelist remove ip 8.8.8.8) This Removes IP Specified
(sh /jffs/scripts/firewall whitelist remove comment "apple" ) This Removes Entries With Comment Containing The Word Apple
(sh /jffs/scripts/firewall whitelist refresh ) Regenerate Shared Whitelist Files
(sh /jffs/scripts/firewall whitelist list ) List All Whitelist Entries
(sh /jffs/scripts/firewall whitelist list ips ) List Manually Added IP Entries
(sh /jffs/scripts/firewall whitelist list domains ) List Manually Added Domain Entries

Here Are Some Example Import Commands;
(sh /jffs/scripts/firewall import URL) This Bans All IPs From URL

Here Are Some Example Deport Commands;
(sh /jffs/scripts/firewall deport URL) This Unbans All IPs From URL

Here Are Some Example Debug Commands;
(sh /jffs/scripts/firewall debug restart) Restart Firewall
(sh /jffs/scripts/firewall debug disable) Disable Raw Debugging
(sh /jffs/scripts/firewall debug watch) Show Debug Entries As They Appear
(sh /jffs/scripts/firewall debug info) Print Usefull Debug Info

Here Are Some Example Update Commands;
(sh /jffs/scripts/firewall update) Standard Update Check - If Nothing Detected Exit
(sh /jffs/scripts/firewall update check) Check For Updates Only - Wont Update If Detected
(sh /jffs/scripts/firewall update -f) Force Update Even If No Changes Detected

Here Are Some Example Stat Commands;
(sh /jffs/scripts/firewall stats) Compile Stats With Default Top10 Output
(sh /jffs/scripts/firewall stats 20) Compile Stats With Customiseable Top20 Output
(sh /jffs/scripts/firewall stats tcp) Compile Stats Showing Only TCP Entries
(sh /jffs/scripts/firewall stats tcp 20) Compile Stats Showing Only TCP Entries With Customiseable Top20 Output
(sh /jffs/scripts/firewall stats search port 23) Search All Debug Data For Entries On Port 23
(sh /jffs/scripts/firewall stats search port 23 20) Search All Debug Data For Entries On Port 23 With Customiseable Top20 Output
(sh /jffs/scripts/firewall stats search ip 8.8.8.8) Search All Debug Data For Entries On 8.8.8.8
(sh /jffs/scripts/firewall stats search ip 8.8.8.8 20) Search All Debug Data For Entries On 8.8.8.8 With Customiseable Top20 Output
(sh /jffs/scripts/firewall stats search malware 8.8.8.8) Search Malwarelists For Specified IP
(sh /jffs/scripts/firewall stats search autobans) Search For All Autobans
(sh /jffs/scripts/firewall stats search manualbans) Search For All Manual Bans
(sh /jffs/scripts/firewall stats reset) Reset All Collected Debug Data
```


### About

```Skynet gained self-awareness after it had spread into millions of computer servers all across the world; realising the extent of its abilities, its creators tried to deactivate it. In the interest of self-preservation, Skynet concluded that all of humanity would attempt to destroy it and impede its capability in safeguarding the world. Its operations are almost exclusively performed by servers, mobile devices, drones, military satellites, war-machines, androids and cyborgs (usually a terminator), and other computer systems. As a programming directive, Skynet's manifestation is that of an overarching, global, artificial intelligence hierarchy (AI takeover), which seeks to exterminate the human race in order to fulfill the mandates of its original coding. (▀̿Ĺ̯▀̿ ̿)```
