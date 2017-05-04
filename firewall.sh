#!/bin/sh
#################################################################################################
## - 04/05/2017 ---		RT-AC56U/RT-AC68U Firewall Addition By Adamm v3.2.5 -  		#
## 					https://github.com/Adamm00/IPSet_ASUS			#
###################################################################################################################
###			       ----- Make Sure To Edit The Following Files -----				  #
### /jffs/scripts/firewall-start			         <-- Sets up cronjob/iptables rules		  #
### /jffs/scripts/firewall					 <-- Blacklists IP's From /jffs/scripts/ipset.txt #
### /jffs/scripts/ipset.txt					 <-- Banned IP List/IPSet Rules			  #
###################################################################################################################

##############################
###	  Commands	   ###
##############################
UNBANSINGLE="unban"          # <-- Remove Single IP From Blacklist
REMOVEBANS="removeall"       # <-- Remove All Entries From Blacklist
SAVEIPSET="save"             # <-- Save Blacklists to /jffs/scripts/ipset.txt
BANSINGLE="ban"              # <-- Adds Entry To Blacklist
BANCOUNTRYSINGLE="country"   # <-- Adds entire country to blacklist
BANCOUNTRYLIST="bancountry"  # <-- Bans specified countries in this file
BANMALWARE="banmalware"      # <-- Bans various malware domains
WHITELIST="whitelist"        # <-- Add IP range to whitelist
NEWLIST="new"		     # <-- Create new IPSet Blacklist
DISABLE="disable"	     # <-- Disable Firewall
DEBUG="debug"		     # <-- Enable/Disable Debug Output
UPDATE="update"		     # <-- Update Script to latest version (check github for changes)
##############################

start_time=`date +%s`
cat /jffs/scripts/firewall | head -28

#####################################################################################################################################
# -        Unban / Removeall / Save / Ban / Country / Bancountry / Banmalware / Whitelist / New / Disable / Debug / Update	  - #
#####################################################################################################################################

if [ X"$@" = X"$UNBANSINGLE" ]
then
	echo "Input IP Address To Unban"
	read unbannedip
	logger -t Firewall "[Unbanning And Removing $unbannedip From Blacklist] ... ... ..."
	ipset -D Blacklist $unbannedip
	echo "`sed /$unbannedip/d /jffs/scripts/ipset.txt`" > /jffs/scripts/ipset.txt
	echo "$unbannedip Is Now Unbanned"

elif [ X"$@" = X"$REMOVEBANS" ]
then
	nvram set Blacklist=`expr \`ipset -L Blacklist | wc -l\` - 6`
	echo "[Deleting All `echo \`nvram get Blacklist\`` Entries From Blacklist] ... ... ..."
	logger -t Firewall "[Deleting All `echo \`nvram get Blacklist\`` Entries From Blacklist] ... ... ..."
	ipset --flush Blacklist
	ipset --flush BlockedRanges
	ipset --save > /jffs/scripts/ipset.txt

elif [ X"$@" = X"$SAVEIPSET" ]
then
	echo "[Saving Blacklists] ... ... ..."
	ipset --save > /jffs/scripts/ipset.txt
	echo "`sed '/USER admin pid/d' /tmp/syslog.log`" > /tmp/syslog.log

elif [ X"$@" = X"$BANSINGLE" ]
then
	echo "Input IP Address"
	read bannedip
	logger -t Firewall "[Adding $bannedip To Blacklist] ... ... ..."
	ipset -A Blacklist $bannedip
	echo "$bannedip Is Now Banned"

elif [ X"$@" = X"$BANCOUNTRYSINGLE" ]
then
	echo "Input Country Abbreviation"
	read country
		for IP in $(wget -q -O - http://www.ipdeny.com/ipblocks/data/countries/$country.zone)
		do
		ipset -q -A BlockedRanges $IP
		done

elif [ X"$@" = X"$BANCOUNTRYLIST" ]
then
	echo "[Banning Spam Countries] ... ... ..."
	for country in pk cn in jp ru sa
	do
        for IP in $(wget -q -O - http://www.ipdeny.com/ipblocks/data/countries/$country.zone)
       	do
    	ipset -q -A BlockedRanges $IP
		done
	done

elif [ X"$@" = X"$BANMALWARE" ]
then

if [ -f /jffs/scripts/malware-filter ]; then
   echo "Malware-filter by @swetoast detected, please use this instead."
else
   	echo "Banning Known Malware IP (ETA 6mins)"
	echo "Downloading Lists"
	echo `wget -qO- http://cinsscore.com/list/ci-badguys.txt` >> /tmp/malwarelist.txt
	echo `wget -qO- http://malc0de.com/bl/IP_Blacklist.txt` >> /tmp/malwarelist.txt
	echo `wget -qO- http://sanyalnet-cloud-vps.freeddns.org/mirai-ips.txt` >> /tmp/malwarelist.txt
	echo `wget -qO- http://www.abuseat.org/iotcc.txt` >> /tmp/malwarelist.txt
	echo `wget -qO- http://www.malwaredomainlist.com/hostslist/ip.txt` >> /tmp/malwarelist.txt
	echo `wget -qO- https://feodotracker.abuse.ch/blocklist/?download=ipblocklist` >> /tmp/malwarelist.txt
	echo `wget -qO- https://lists.blocklist.de/lists/bots.txt` >> /tmp/malwarelist.txt
	echo `wget -qO- https://lists.blocklist.de/lists/ssh.txt` >> /tmp/malwarelist.txt
	echo `wget -qO- https://ransomwaretracker.abuse.ch/downloads/CW_PS_IPBL.txt` >> /tmp/malwarelist.txt
	echo `wget -qO- https://ransomwaretracker.abuse.ch/downloads/LY_PS_IPBL.txt` >> /tmp/malwarelist.txt
	echo `wget -qO- https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt` >> /tmp/malwarelist.txt
	echo `wget -qO- https://ransomwaretracker.abuse.ch/downloads/TC_PS_IPBL.txt` >> /tmp/malwarelist.txt
	echo `wget -qO- https://ransomwaretracker.abuse.ch/downloads/TL_C2_IPBL.txt` >> /tmp/malwarelist.txt
	echo `wget -qO- https://ransomwaretracker.abuse.ch/downloads/TL_PS_IPBL.txt` >> /tmp/malwarelist.txt
	echo `wget -qO- https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt` >> /tmp/malwarelist.txt
	echo `wget -qO- https://zeustracker.abuse.ch/blocklist.php?download=badips` >> /tmp/malwarelist.txt
	echo "Filtering IPv4 Ranges"
	cat /tmp/malwarelist.txt | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}\b" > /tmp/malwarelist1.txt
	echo "Filtering IPv4 Addresses"
	grep -vf /tmp/malwarelist1.txt /tmp/malwarelist.txt > /tmp/malwarelist2.txt
	cat /tmp/malwarelist2.txt | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" > /tmp/malwarelist3.txt
	echo "Banning `cat /tmp/malwarelist3.txt | wc -l` IPv4 Adresses"
		for IP in `cat /tmp/malwarelist3.txt`
		do
		ipset -q -A Blacklist $IP
		done
	echo "Banning `cat /tmp/malwarelist1.txt | wc -l` IPv4 Ranges"
		for IP in `cat /tmp/malwarelist1.txt`
		do
		ipset -q -A BlockedRanges $IP
		done
	rm -rf /tmp/malwarelist.txt
	rm -rf /tmp/malwarelist1.txt
	rm -rf /tmp/malwarelist2.txt
	rm -rf /tmp/malwarelist3.txt
fi

elif [ X"$@" = X"$WHITELIST" ]
then
	echo "Input IP Range To Whitelist"
	read whitelistip
	logger -t Firewall "[Adding $whitelistip To Whitelist] ... ... ..."
	ipset -A Whitelist $whitelistip
	echo "$whitelistip Is Now Whitelisted"
	ipset --save > /jffs/scripts/ipset.txt

elif [ X"$@" = X"$NEWLIST" ]
then
	echo "Does The Blacklist Need To Be Downloaded? yes/no"
	read ENABLEDOWNLOAD
		if [ X"$ENABLEDOWNLOAD" = X"yes" ]; then
			echo "Input URL For IPSet Blacklist"
			read DOWNLOADURL
			wget -O /jffs/scripts/ipset2.txt $DOWNLOADURL
		fi
	echo "Input Old Set Name"
	read SET1
	echo "Input New Set Name"
	read SET2
	sed -i "s/$SET1/$SET2/g" /jffs/scripts/ipset2.txt
	ipset -q -R  < /jffs/scripts/ipset2.txt
	echo "Successfully Added New Set"
	
elif [ X"$@" = X"$DISABLE" ]
then
	echo "[Disabling Firewall] ... ... ..."
	logger -t Firewall "[Disabling Firewall] ... ... ..."
	iptables -D INPUT -m set --match-set Whitelist src -j ACCEPT > /dev/null 2>&1
	iptables -D INPUT -m set --match-set Blacklist src -j DROP > /dev/null 2>&1
	iptables -D INPUT -m set --match-set BlockedRanges src -j DROP > /dev/null 2>&1
	iptables -D FORWARD -m set --match-set Blacklist src,dst -j DROP > /dev/null 2>&1
	iptables -D FORWARD -m set --match-set BlockedRanges src,dst -j DROP > /dev/null 2>&1
	iptables -D FORWARD -m set --match-set Whitelist src,dst -j ACCEPT > /dev/null 2>&1
	iptables -D logdrop -m state --state NEW -j SET --add-set Blacklist src > /dev/null 2>&1
	
elif [ X"$@" = X"$DEBUG" ]
then
	echo "Select Debug Mode (enable/disable)"
	read DEBUGMODE
		if [ X"$DEBUGMODE" = X"enable" ]; then
			echo "[Enabling Debug Mode] ... ... ..."
			logger -t Firewall "[Enabling Debug Mode] ... ... ..."
			iptables -I INPUT -m set --match-set Blacklist src -j LOG --log-prefix "[BLOCKED - INPUT] " --log-tcp-sequence --log-tcp-options --log-ip-options
			iptables -I FORWARD -m set --match-set Blacklist src -j LOG --log-prefix "[BLOCKED - FORWARD] " --log-tcp-sequence --log-tcp-options --log-ip-options
		elif [ X"$DEBUGMODE" = X"disable" ]; then
			echo "[Disabling Debug Mode] ... ... ..."
			logger -t Firewall "[Disabling Debug Mode] ... ... ..."
			iptables -D INPUT -m set --match-set Blacklist src -j LOG --log-prefix "[BLOCKED - INPUT] " --log-tcp-sequence --log-tcp-options --log-ip-options
			iptables -D FORWARD -m set --match-set Blacklist src -j LOG --log-prefix "[BLOCKED - FORWARD] " --log-tcp-sequence --log-tcp-options --log-ip-options
		fi
	
elif [ X"$@" = X"$UPDATE" ]
then
	if [ X"`cat /jffs/scripts/firewall`" = X"`wget -q -O - https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh`" ]; then
		echo "Firewall Up To Date"
		logger -t Firewall "[Firewall Up To Date]"
	else
		echo "[New Version Detected - Updating]... ... ..."
		logger -t Firewall "[New Version Detected - Updating]... ... ..."
		wget -O /jffs/scripts/firewall https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh
	fi
	
else

		if [ X"`nvram get jffs2_scripts`" = X"1" ]
		then
			echo "Correct Settings Detected."
		else
			echo "Enabled Custom JFFS Scripts"
			nvram set jffs2_scripts=1
			nvram commit
		fi

		if [ X"`nvram get fw_enable_x`" = X"1" ]
		then
			echo "Correct Settings Detected."
		else
			echo "Enabled SPI Firewall"
			nvram set fw_enable_x=1
			nvram commit
		fi

		if [ X"`nvram get fw_log_x`" = X"drop" ]
		then
			echo "Correct Settings Detected."
		else
			echo "Enabled Firewall Logging"
			nvram set fw_log_x=drop
			nvram commit
		fi


	echo "`sed '/IP Banning Started/d' /tmp/syslog.log`" > /tmp/syslog.log
	echo "[IP Banning Started] ... ... ..."
	logger -t Firewall "[IP Banning Started] ... ... ..."
	insmod xt_set > /dev/null 2>&1
	ipset -q -R  < /jffs/scripts/ipset.txt
	ipset -q -N Whitelist nethash
	ipset -q -N Blacklist iphash --maxelem 500000
	ipset -q -N BlockedRanges nethash
	iptables -D logdrop -m state --state NEW -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options  > /dev/null 2>&1
	iptables -D INPUT -m set --match-set Whitelist src -j ACCEPT > /dev/null 2>&1
	iptables -D INPUT -m set --match-set Blacklist src -j DROP > /dev/null 2>&1
	iptables -D INPUT -m set --match-set BlockedRanges src -j DROP > /dev/null 2>&1
	iptables -D FORWARD -m set --match-set Blacklist src,dst -j DROP > /dev/null 2>&1
	iptables -D FORWARD -m set --match-set BlockedRanges src,dst -j DROP > /dev/null 2>&1
	iptables -D FORWARD -m set --match-set Whitelist src,dst -j ACCEPT > /dev/null 2>&1
	iptables -D logdrop -m state --state NEW -j SET --add-set Blacklist src > /dev/null 2>&1
	iptables -I INPUT -m set --match-set Blacklist src -j DROP > /dev/null 2>&1
	iptables -I INPUT -m set --match-set BlockedRanges src -j DROP > /dev/null 2>&1
	iptables -I INPUT -m set --match-set Whitelist src -j ACCEPT > /dev/null 2>&1
	iptables -I FORWARD -m set --match-set Blacklist src,dst -j DROP > /dev/null 2>&1
	iptables -I FORWARD -m set --match-set BlockedRanges src,dst -j DROP > /dev/null 2>&1
	iptables -I FORWARD -m set --match-set Whitelist src,dst -j ACCEPT > /dev/null 2>&1
	iptables -I logdrop -m state --state NEW -j SET --add-set Blacklist src > /dev/null 2>&1
	ipset -q -A Whitelist 192.168.1.0/24
	ipset -q -A Whitelist `nvram get lan_ipaddr`/24
	echo "`sed '/DROP IN=/d' /tmp/syslog.log`" > /tmp/syslog.log
	echo "`sed '/DROP IN=/d' /tmp/syslog.log-1`" > /tmp/syslog.log-1

fi

###############
# - Logging - #
###############
OLDAMOUNT=`nvram get Blacklist`
nvram set Blacklist=`expr \`ipset -L Blacklist | wc -l\` - 6`
NEWAMOUNT=`nvram get Blacklist`
nvram commit
HITS=$(expr `iptables --line -nvL INPUT | grep -E "set.*Blacklist" | awk '{print $2}'` + `iptables --line -nvL FORWARD | grep -E "set.*Blacklist" | awk '{print $2}'`)
start_time=$(expr `date +%s` - $start_time)
echo "[Complete] $NEWAMOUNT IPs currently banned. `expr $NEWAMOUNT - $OLDAMOUNT` New IP's Banned. $HITS Connections Blocked! [`echo $start_time`s]"
logger -t Firewall "[Complete] $NEWAMOUNT IPs currently banned. `expr $NEWAMOUNT - $OLDAMOUNT` New IP's Banned. $HITS Connections Blocked! [`echo $start_time`s]"
