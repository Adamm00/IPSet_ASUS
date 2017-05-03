# Asus Firewall Addition
Lightweight firewall addition for ARM based ASUS Routers using IPSet as seen on [SmallNetBuilder](https://www.snbforums.com/threads/how-to-dynamically-ban-malicious-ips-using-ipset-adamm-version.16798/)


This script is an extra line of defense from malicious attackers (mostly bots) who repeatedly probe for vunelerabilities and easy to use IPSet functionality to block anything you desire.


## Usage

sh /jffs/scripts/firewall *commandhere*

"unban"       # <-- Remove Single IP From Blacklist  
"removeall"   # <-- Remove All Entries From Blacklist  
"save"        # <-- Save Blacklists to /jffs/scripts/ipset.txt  
"ban"         # <-- Adds Entry To Blacklist  
"country"     # <-- Adds entire country to blacklist  
"bancountry"  # <-- Bans specified countries in this file  
"banmalware"  # <-- Bans various malware domains  
"whitelist"   # <-- Add IPs from path to Whitelist  
"new"		      # <-- Create new IPSet Blacklist  
"disable"	    # <-- Disable Firewall  
"update"		  # <-- Update Script to latest version (check github for changes)  


## Installation

Edit these files manually if you have other conflicting scripts, otherwise do the following.

```sh
wget -O /jffs/scripts/firewall https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh
wget -O /jffs/scripts/firewall-start https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall-start.sh
chmod +x /jffs/scripts/firewall
chmod +x /jffs/scripts/firewall-start
```
