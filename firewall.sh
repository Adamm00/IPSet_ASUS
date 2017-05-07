#!/bin/sh
#################################################################################################
## - 07/05/2017 ---		RT-AC56U/RT-AC68U Firewall Addition By Adamm v3.3.4 -  		#
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
IMPORTLIST="import"	     # <-- Import and merge IPSet save to firewall
DISABLE="disable"	     # <-- Disable Firewall
DEBUG="debug"		     # <-- Enable/Disable Debug Output
UPDATE="update"		     # <-- Update Script to latest version (check github for changes)
##############################

start_time=`date +%s`
cat /jffs/scripts/firewall | head -28

#####################################################################################################################################
# -      Unban / Removeall / Save / Ban / Country / Bancountry / Banmalware / Whitelist / Import / Disable / Debug / Update       - #
#####################################################################################################################################

if [ X"$@" = X"$UNBANSINGLE" ]
then
	echo "Input IP Address To Unban"
	read unbannedip
	logger -t Firewall "[Unbanning And Removing $unbannedip From Blacklist] ... ... ..."
	ipset -D Blacklist $unbannedip
	sed -i /$unbannedip/d /jffs/scripts/ipset.txt
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
	sed -i '/USER admin pid/d' /tmp/syslog.log

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
elif [ -f /jffs/scripts/ya-malware-block.sh ]; then
	echo "Ya-Malware-Block by @redhat27 detected, please use this instead."
else
   	echo "Banning Known Malware IPs"
	echo "Downloading Lists"
	wget -q --no-check-certificate -O /tmp/malwarelist.txt -i https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/filter.list
	echo "Filtering IPv4 Addresses"
	cat /tmp/malwarelist.txt | sed -n "s/\r//;/^$/d;/^[0-9,\.]*$/s/^/add Blacklist /p" | sort -u > /tmp/malwarelist1.txt
	echo "Filtering IPv4 Ranges"
	cat /tmp/malwarelist.txt | sed -n "s/\r//;/^$/d;/^[0-9,\.,\/]*$/s/^/add BlockedRanges /p" | grep "/" | sort -u >> /tmp/malwarelist1.txt
	echo "Applying Blacklists"
	ipset -q -R -! < /tmp/malwarelist1.txt
	rm -rf /tmp/malwarelist*.txt
fi

elif [ X"$@" = X"$WHITELIST" ]
then
	echo "Input IP Range To Whitelist"
	read whitelistip
	logger -t Firewall "[Adding $whitelistip To Whitelist] ... ... ..."
	ipset -A Whitelist $whitelistip
	echo "$whitelistip Is Now Whitelisted"
	ipset --save > /jffs/scripts/ipset.txt

elif [ X"$@" = X"$IMPORTLIST" ]
then
	echo "Does The Blacklist Need To Be Downloaded? yes/no"
	echo "If No Than List Will Be Read From /tmp/ipset2.txt"
	read ENABLEDOWNLOAD
		if [ X"$ENABLEDOWNLOAD" = X"yes" ]; then
			echo "Input URL For IPSet Blacklist"
			read DOWNLOADURL
			wget -q --no-check-certificate -O /tmp/ipset2.txt -i $DOWNLOADURL
		fi
	echo "Input Old Set Name"
	read SET1
	echo "Input Set To Merge Into"
	read SET2
	sed -i "s/$SET1/$SET2/g" /tmp/ipset2.txt
	ipset -q -R -! < /tmp/ipset2.txt
	rm -rf /tmp/ipset2.txt
	echo "Successfully Merged Blacklist"
	
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


	sed -i '/IP Banning Started/d' /tmp/syslog.log
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
	ipset -q -A Whitelist 151.101.96.133/32
	sed -i '/DROP IN=/d' /tmp/syslog.log
	sed -i '/DROP IN=/d' /tmp/syslog.log-1

fi

###############
# - Logging - #
###############
OLDIPS=`nvram get Blacklist`
OLDRANGES=`nvram get BlockedRanges`
nvram set Blacklist=`expr \`ipset -L Blacklist | wc -l\` - 7`
nvram set BlockedRanges=`expr \`ipset -L BlockedRanges | wc -l\` - 7`
NEWIPS=`nvram get Blacklist`
NEWRANGES=`nvram get BlockedRanges`
nvram commit
HITS=$(expr `iptables --line -nvL INPUT | grep -E "set.*Blacklist" | awk '{print $2}'` + `iptables --line -nvL INPUT | grep -E "set.*BlockedRanges" | awk '{print $2}'` + `iptables --line -nvL FORWARD | grep -E "set.*Blacklist" | awk '{print $2}'` + `iptables --line -nvL FORWARD | grep -E "set.*BlockedRanges" | awk '{print $2}'`)
start_time=$(expr `date +%s` - $start_time)
echo "[Complete] $NEWIPS IPs / $NEWRANGES Ranges banned. `expr $NEWIPS - $OLDIPS` New IPs / `expr $NEWRANGES - $OLDRANGES` New Ranges Banned. $HITS Connections Blocked! [`echo $start_time`s]"
logger -t Firewall "[Complete] $NEWIPS IPs / $NEWRANGES Ranges banned. `expr $NEWIPS - $OLDIPS` New IPs / `expr $NEWRANGES - $OLDRANGES` New Ranges Banned. $HITS Connections Blocked! [`echo $start_time`s]"
