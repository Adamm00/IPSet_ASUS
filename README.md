# Skynet - Asus Firewall Addition
Lightweight firewall addition for ARM based ASUS Routers using IPSet as seen on [SmallNetBuilder](https://www.snbforums.com/threads/how-to-dynamically-ban-malicious-ips-using-ipset-adamm-version.16798/)


This script is an extra line of defense from malicious attackers (mostly bots) who repeatedly probe for vunelerabilities and easy to use IPSet functionality to block anything you desire.


## Usage

sh /jffs/scripts/firewall *commandhere*

    "unban"        # <-- Remove Entry From Blacklist (IP/Range/Domain/All)   
    "save"         # <-- Save Blacklists To /jffs/scripts/ipset.txt
    "ban"          # <-- Adds Entry To Blacklist (IP/Range/Domain/Country)     
    "banmalware"   # <-- Bans Various Malware Domains  
    "whitelist"    # <-- Add Entry To Whitelist (IP/Range/Domain)  
    "import"       # <-- Import And Merge IPSet Save To Firewall  
    "disable"      # <-- Disable Firewall  
    "update"       # <-- Update Script To Latest Version (check github for changes)  


## Installation

Edit these files manually if you have other conflicting scripts, otherwise do the following.

```sh
wget -O /jffs/scripts/firewall https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh
wget -O /jffs/scripts/firewall-start https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall-start.sh
chmod +x /jffs/scripts/firewall
chmod +x /jffs/scripts/firewall-start
```

## Help

```
Here Are Some Example Unban Commands;
"./jffs/scripts/firewall unban" This Requires Manual Input (Only IPs accepted)
"./jffs/scripts/firewall unban 8.8.8.8" his Unbans The IP Specified
"./jffs/scripts/firewall unban range 8.8.8.8/24" This Unbans the CIDR Block Specified
"./jffs/scripts/firewall unban domain" This Requires Manual Input (Only Domains Accepted)
"./jffs/scripts/firewall unban domain google.com" This Unbans the URL Specified
"./jffs/scripts/firewall unban all" This Unbans All Entries From Both Blacklists

Here Are Some Example Ban Commands;
"./jffs/scripts/firewall ban" This Requires Manual Input (Only IPs accepted)
"./jffs/scripts/firewall ban 8.8.8.8" This Bans The IP Specified
"./jffs/scripts/firewall ban range 8.8.8.8/24" This Bans the CIDR Block Specified
"./jffs/scripts/firewall ban domain" This Requires Manual Input (Only Domains Accepted)
"./jffs/scripts/firewall ban domain google.com" This Bans the URL Specified
"./jffs/scripts/firewall ban country pk" This Bans The Known IPs For The Specified Country http://www.ipdeny.com/ipblocks/data/countries/

Here Are Some Example Banmalware Commands;
"./jffs/scripts/firewall banmalware" This Bans IPs From The Predefined Filter List
"./jffs/scripts/firewall banmalware google.com/filter.list" This Uses The Fitler List From The Specified URL

Here Are Some Example Whitelist Commands;
"./jffs/scripts/firewall whitelist" This Requires Manual Input (Only IPs accepted)
"./jffs/scripts/firewall whitelist IP" This Bans The IP or Range Specified
"./jffs/scripts/firewall whitelist domain" This Requires Manual Input (Only Domains Accepted)
"./jffs/scripts/firewall whitelist domain google.com" This Bans the URL Specified

Here Are Some Example Debug Commands;
"./jffs/scripts/firewall debug enable" Enable Debugging To Syslog
"./jffs/scripts/firewall debug disable" Disable Debugging

Here Are Some Example Update Commands;
"./jffs/scripts/firewall update" Standard Update Check - If Nothing Detected Exit
"./jffs/scripts/firewall update check" Check For Updates Only - Wont Update If Detected
"./jffs/scripts/firewall update -f" Force Update Even If No Changes Detected
```


### About

```Skynet gained self-awareness after it had spread into millions of computer servers all across the world; realising the extent of its abilities, its creators tried to deactivate it. In the interest of self-preservation, Skynet concluded that all of humanity would attempt to destroy it and impede its capability in safeguarding the world. Its operations are almost exclusively performed by servers, mobile devices, drones, military satellites, war-machines, androids and cyborgs (usually a terminator), and other computer systems. As a programming directive, Skynet's manifestation is that of an overarching, global, artificial intelligence hierarchy (AI takeover), which seeks to exterminate the human race in order to fulfill the mandates of its original coding. (▀̿Ĺ̯▀̿ ̿)```
