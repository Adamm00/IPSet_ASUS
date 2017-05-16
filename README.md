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
    "deport"       # <-- Remove All IPs From IPSet Save From Firewall
    "disable"      # <-- Disable Firewall  
    "update"       # <-- Update Script To Latest Version (check github for changes)  
    "stats"        # <-- Print/Search Stats Of Recently Banned IPs (Requires debugging enabled)


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
"./jffs/scripts/firewall ban country "pk cn sa"" This Bans The Known IPs For The Specified Countries (accepts single/multiple inputs if quoted) http://www.ipdeny.com/ipblocks/data/countries/

Here Are Some Example Banmalware Commands;
"./jffs/scripts/firewall banmalware" This Bans IPs From The Predefined Filter List
"./jffs/scripts/firewall banmalware google.com/filter.list" This Uses The Fitler List From The Specified URL

Here Are Some Example Whitelist Commands;
"./jffs/scripts/firewall whitelist" This Requires Manual Input (Only IPs accepted)
"./jffs/scripts/firewall whitelist IP" This Bans The IP or Range Specified
"./jffs/scripts/firewall whitelist domain" This Requires Manual Input (Only Domains Accepted)
"./jffs/scripts/firewall whitelist domain google.com" This Bans the URL Specified

Here Are Some Example Import Commands;
"./jffs/scripts/firewall import" This Reads IPSet Save File From /jffs/scripts/ipset2.txt And Saves All IPs To Blacklist
"./jffs/scripts/firewall import URL" This Reads IPSet Save File From A Custom URL And Saves All IPs To Blacklist

Here Are Some Example Deport Commands;
"./jffs/scripts/firewall deport" This Reads IPSet Save File From /jffs/scripts/ipset2.txt And Removes All IPs From Blacklist
"./jffs/scripts/firewall import URL" This Reads IPSet Save File From A Custom URL And Removes All IPs From Blacklist

Here Are Some Example Debug Commands;
"./jffs/scripts/firewall debug enable" Enable Raw Debugging To Syslog
"./jffs/scripts/firewall debug disable" Disable Raw Debugging

Here Are Some Example Update Commands;
"./jffs/scripts/firewall update" Standard Update Check - If Nothing Detected Exit
"./jffs/scripts/firewall update check" Check For Updates Only - Wont Update If Detected
"./jffs/scripts/firewall update -f" Force Update Even If No Changes Detected

Here Are Some Example Stat Commands;
"./jffs/scripts/firewall stats" Compile Stats With Default Top10 Output
"./jffs/scripts/firewall stats 20" Compile Stats With Customiseable Top20 Output
"./jffs/scripts/firewall stats search ip 8.8.8.8" Search All Debug Data For Entries On 8.8.8.8
"./jffs/scripts/firewall stats search ip 8.8.8.8 20" Search All Debug Data For Entries On 8.8.8.8 With Customiseable Top20 Output
"./jffs/scripts/firewall stats search port 23" Search All Debug Data For Entries On Port 23
"./jffs/scripts/firewall stats search port 23 20" Search All Debug Data For Entries On Port 23 With Customiseable Top20 Output
"./jffs/scripts/firewall stats reset" Reset All Collected Debug Data

Here Are Some Example Startup Commands (for firewall-start);
"./jffs/scripts/firewall start" Normal Startup With Default Features
"./jffs/scripts/firewall start noautoban" Startup With Autobanning Disabled
"./jffs/scripts/firewall start debug" Startup With Debug Mode Enabled (Also Used For Stat Report Generation)
```


### About

```Skynet gained self-awareness after it had spread into millions of computer servers all across the world; realising the extent of its abilities, its creators tried to deactivate it. In the interest of self-preservation, Skynet concluded that all of humanity would attempt to destroy it and impede its capability in safeguarding the world. Its operations are almost exclusively performed by servers, mobile devices, drones, military satellites, war-machines, androids and cyborgs (usually a terminator), and other computer systems. As a programming directive, Skynet's manifestation is that of an overarching, global, artificial intelligence hierarchy (AI takeover), which seeks to exterminate the human race in order to fulfill the mandates of its original coding. (▀̿Ĺ̯▀̿ ̿)```
