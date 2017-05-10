# Skynet - Asus Firewall Addition
Lightweight firewall addition for ARM based ASUS Routers using IPSet as seen on [SmallNetBuilder](https://www.snbforums.com/threads/how-to-dynamically-ban-malicious-ips-using-ipset-adamm-version.16798/)


This script is an extra line of defense from malicious attackers (mostly bots) who repeatedly probe for vunelerabilities and easy to use IPSet functionality to block anything you desire.


## Usage

sh /jffs/scripts/firewall *commandhere*

    "unban"        # <-- Remove Single IP From Blacklist  
    "unbanall"     # <-- Remove All Entries From Blacklist  
    "unbandomain"  # <-- Unban IP's Associated With Domain  
    "save"         # <-- Save Blacklists To /jffs/scripts/ipset.txt
    "ban"          # <-- Adds Entry To Blacklist  
    "bandomain"    # <-- Ban IP's Associated With Domain  
    "country"      # <-- Adds Entire Country To Blacklist  
    "bancountry"   # <-- Bans Specified Countries In This File  
    "banmalware"   # <-- Bans Various Malware Domains  
    "whitelist"    # <-- Add IP Range To Whitelist  
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


### About

```Skynet gained self-awareness after it had spread into millions of computer servers all across the world; realising the extent of its abilities, its creators tried to deactivate it. In the interest of self-preservation, Skynet concluded that all of humanity would attempt to destroy it and impede its capability in safeguarding the world. Its operations are almost exclusively performed by servers, mobile devices, drones, military satellites, war-machines, androids and cyborgs (usually a terminator), and other computer systems. As a programming directive, Skynet's manifestation is that of an overarching, global, artificial intelligence hierarchy (AI takeover), which seeks to exterminate the human race in order to fulfill the mandates of its original coding. (▀̿Ĺ̯▀̿ ̿)```
