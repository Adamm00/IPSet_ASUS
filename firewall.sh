#!/bin/sh
#################################################################################################
## - 09/05/2017 ---		RT-AC56U/RT-AC68U Firewall Addition By Adamm v3.4.4 -  		#
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
#	  "unban"	     # <-- Remove Single IP From Blacklist
#	  "unbanall"	     # <-- Remove All Entries From Blacklist
#	  "save"	     # <-- Save Blacklists to /jffs/scripts/ipset.txt
#	  "ban"		     # <-- Adds Entry To Blacklist
# 	  "country"	     # <-- Adds entire country to blacklist
#	  "bancountry"	     # <-- Bans specified countries in this file
#	  "banmalware"	     # <-- Bans various malware domains
#	  "whitelist"        # <-- Add IP range to whitelist
#	  "import"	     # <-- Import and merge IPSet save to firewall
#	  "disable"	     # <-- Disable Firewall
#	  "debug"	     # <-- Enable/Disable Debug Output
#	  "update"	     # <-- Update Script to latest version (check github for changes)
#	  "start"	     # <-- Initiate Firewall
##############################

start_time=`date +%s`
cat /jffs/scripts/firewall | head -29

Check_Settings () {
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
}


Unload_IPTables () {
		iptables -D logdrop -m state --state NEW -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options  > /dev/null 2>&1
		iptables -t raw -D PREROUTING -m set --match-set Blacklist src -j DROP > /dev/null 2>&1
		iptables -t raw -D PREROUTING -m set --match-set BlockedRanges src -j DROP > /dev/null 2>&1
		iptables -t raw -D PREROUTING -m set --match-set Whitelist src -j ACCEPT > /dev/null 2>&1
		iptables -D logdrop -m state --state NEW -j SET --add-set Blacklist src > /dev/null 2>&1
}


Load_IPTables () {
		iptables -t raw -I PREROUTING -m set --match-set Blacklist src -j DROP > /dev/null 2>&1
		iptables -t raw -I PREROUTING -m set --match-set BlockedRanges src -j DROP > /dev/null 2>&1
		iptables -t raw -I PREROUTING -m set --match-set Whitelist src -j ACCEPT > /dev/null 2>&1
		iptables -I logdrop -m state --state NEW -j SET --add-set Blacklist src > /dev/null 2>&1
}


Logging () {
		OLDIPS=`nvram get Blacklist`
		OLDRANGES=`nvram get BlockedRanges`
		nvram set Blacklist=`expr \`ipset -L Blacklist | wc -l\` - 7`
		nvram set BlockedRanges=`expr \`ipset -L BlockedRanges | wc -l\` - 7`
		NEWIPS=`nvram get Blacklist`
		NEWRANGES=`nvram get BlockedRanges`
		nvram commit
		HITS1=`iptables --line -vL -nt raw | grep -E "set.*Blacklist" | awk '{print $2}'`
		HITS2=`iptables --line -vL -nt raw | grep -E "set.*BlockedRanges" | awk '{print $2}'`
		start_time=$(expr `date +%s` - $start_time)
		logger -st Firewall "[Complete] $NEWIPS IPs / $NEWRANGES Ranges banned. `expr $NEWIPS - $OLDIPS` New IPs / `expr $NEWRANGES - $OLDRANGES` New Ranges Banned. $HITS1 IP / $HITS2 Range Connections Blocked! [`echo $start_time`s]"
}

#####################################################################################################################################
# -   Unban / Unbanall / Save / Ban / Country / Bancountry / Banmalware / Whitelist / Import / Disable / Debug / Update / Start   - #
#####################################################################################################################################


case $1 in
	unban)
		if [ -z $2 ]; then
			echo "Input IP Address To Unban"
			read unbannedip
		else
			unbannedip=$2
		fi
		
		logger -st Firewall "[Unbanning And Removing $unbannedip From Blacklist] ... ... ..."
		ipset -D Blacklist $unbannedip
		sed -i /$unbannedip/d /jffs/scripts/ipset.txt
		;;

	unbanall)
		nvram set Blacklist=`expr \`ipset -L Blacklist | wc -l\` - 6`
		logger -st Firewall "[Deleting All `echo \`nvram get Blacklist\`` Entries From Blacklist] ... ... ..."
		ipset --flush Blacklist
		ipset --flush BlockedRanges
		ipset --save > /jffs/scripts/ipset.txt
		;;

	save)
		echo "[Saving Blacklists] ... ... ..."
		ipset --save > /jffs/scripts/ipset.txt
		sed -i '/USER admin pid .*firewall/d' /tmp/syslog.log
		;;

	ban)
		if [ -z $2 ]; then
			echo "Input IP Address To Ban"
			read bannedip
		else
			bannedip=$2
		fi
		
		logger -st Firewall "[Adding $bannedip To Blacklist] ... ... ..."
		ipset -A Blacklist $bannedip
		;;

	country)
		echo "Input Country Abbreviation"
		read country
			for IP in $(wget -q -O - http://www.ipdeny.com/ipblocks/data/countries/$country.zone)
			do
			ipset -q -A BlockedRanges $IP
			done
		;;

	bancountry)
		echo "[Banning Spam Countries] ... ... ..."
		for country in pk cn in jp ru sa
		do
			for IP in $(wget -q -O - http://www.ipdeny.com/ipblocks/data/countries/$country.zone)
			do
			ipset -q -A BlockedRanges $IP
			done
		done
		;;

	banmalware)
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
		;;
		
	whitelist)
		if [ -z $2 ]; then
			echo "Input IP Range To Whitelist"
			read whitelistip
		else
			whitelistip=$2
		fi
		
		logger -st Firewall "[Adding $whitelistip To Whitelist] ... ... ..."
		ipset -A Whitelist $whitelistip
		ipset --save > /jffs/scripts/ipset.txt
		;;

	import)
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
		;;

	disable)
			logger -st Firewall "[Disabling Firewall] ... ... ..."
			Unload_IPTables
		;;

	debug)
			if [ X"$2" = X"enable" ]; then
				logger -st Firewall "[Enabling Debug Mode] ... ... ..."
				iptables -t raw -I PREROUTING -m set --match-set Blacklist src -j LOG --log-prefix "[BLOCKED - RAW] " --log-tcp-sequence --log-tcp-options --log-ip-options
			elif [ X"$2" = X"disable" ]; then
				logger -st Firewall "[Disabling Debug Mode] ... ... ..."
				iptables -t raw -D PREROUTING -m set --match-set Blacklist src -j LOG --log-prefix "[BLOCKED - RAW] " --log-tcp-sequence --log-tcp-options --log-ip-options
			else
				echo "Error - Use Syntax './jffs/scripts/firewall debug (enable/disable)'"
			fi
		;;

	update)
		if [ X"`cat /jffs/scripts/firewall`" = X"`wget -q -O - https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh`" ]; then
			logger -st Firewall "[Firewall Up To Date]"
		else
			logger -st Firewall "[New Version Detected - Updating]... ... ..."
			wget -q --no-check-certificate -O /jffs/scripts/firewall https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh
		fi
		;;

	start)
		Check_Settings
		sed -i '/IP Banning Started/d' /tmp/syslog.log
		logger -st Firewall "[IP Banning Started] ... ... ..."
		insmod xt_set > /dev/null 2>&1
		ipset -q -R  < /jffs/scripts/ipset.txt
		ipset -q -N Whitelist nethash
		ipset -q -N Blacklist iphash --maxelem 500000
		ipset -q -N BlockedRanges nethash
		ipset -q -A Whitelist 192.168.1.0/24
		ipset -q -A Whitelist `nvram get lan_ipaddr`/24
		ipset -q -A Whitelist 151.101.96.133/32
		Unload_IPTables
		Load_IPTables
		sed -i '/DROP IN=/d' /tmp/syslog.log
		;;

     *)
          echo "Command not found, please try again."
		;;

esac

Logging
