#!/bin/sh
#############################################################################################################
#                           ______ _                        _ _               _     _ _ _   _               #
#     /\                   |  ____(_)                      | | |     /\      | |   | (_) | (_)              #
#    /  \   ___ _   _ ___  | |__   _ _ __ _____      ____ _| | |    /  \   __| | __| |_| |_ _  ___  _ __    #
#   / /\ \ / __| | | / __| |  __| | | '__/ _ \ \ /\ / / _` | | |   / /\ \ / _` |/ _` | | __| |/ _ \| '_ \   # 
#  / ____ \\__ \ |_| \__ \ | |    | | | |  __/\ V  V / (_| | | |  / ____ \ (_| | (_| | | |_| | (_) | | | |  #
# /_/    \_\___/\__,_|___/ |_|    |_|_|  \___| \_/\_/ \__,_|_|_| /_/    \_\__,_|\__,_|_|\__|_|\___/|_| |_|  #
#													    #
## - 10/05/2017 -		        Asus Firewall Addition By Adamm v3.5.1				    #
## 					https://github.com/Adamm00/IPSet_ASUS				    #
###################################################################################################################
###			       ----- Make Sure To Edit The Following Files -----				  #
### /jffs/scripts/firewall-start			         <-- Sets up cronjob/initial execution		  #
### /jffs/scripts/firewall					 <-- Blacklists IP's From /jffs/scripts/ipset.txt #
### /jffs/scripts/ipset.txt					 <-- Banned IP List/IPSet Rules			  #
###################################################################################################################

##############################
###	  Commands	   ###
##############################
#	  "unban"	     # <-- Remove Single IP From Blacklist
#	  "unbanall"	     # <-- Remove All Entries From Blacklist
#	  "unbandomain"	     # <-- Unban IP's associated with domain
#	  "save"	     # <-- Save Blacklists to /jffs/scripts/ipset.txt
#	  "ban"		     # <-- Adds Entry To Blacklist
#	  "bandomain"	     # <-- Ban IP's associated with domain
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
cat /jffs/scripts/firewall | head -38

Check_Settings () {
			if [ X"`ipset -v | grep -o v6`" != X"v6" ]; then
				echo "IPSet version not supported"
				exit
			fi
			
			if [ -d "/opt/bin" ] && [ ! -f /opt/bin/firewall ]; then
				echo "Enabling /opt/bin Symlink"
				ln -s /jffs/scripts/firewall /opt/bin
			fi

			if [ X"`nvram get jffs2_scripts`" != X"1" ]; then
				echo "Enabling Custom JFFS Scripts"
				nvram set jffs2_scripts=1
				nvram commit
			fi

			if [ X"`nvram get fw_enable_x`" != X"1" ];then
				echo "Enabling SPI Firewall"
				nvram set fw_enable_x=1
				nvram commit
			fi
	
			if [ X"`nvram get fw_log_x`" != X"drop" ];then
				echo "Enabling Firewall Logging"
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
		HITS1=`iptables -vL -nt raw | grep -E "set.*Blacklist" | awk '{print $1}'`
		HITS2=`iptables -vL -nt raw | grep -E "set.*BlockedRanges" | awk '{print $1}'`
		start_time=$(expr `date +%s` - $start_time)
		logger -st Firewall "[Complete] $NEWIPS IPs / $NEWRANGES Ranges banned. `expr $NEWIPS - $OLDIPS` New IPs / `expr $NEWRANGES - $OLDRANGES` New Ranges Banned. $HITS1 IP / $HITS2 Range Connections Blocked! [`echo $start_time`s]"
}

Unban_PrivateIP () {
		for $IP in `ipset -L Blacklist | grep -E '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)'`
			do
			ipset -D Blacklist $IP
		done
		
		for $IP in `ipset -L BlockedRanges | grep -E '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)'`
			do
			ipset -D BlockedRanges $IP
		done
}

###################################################################################################################################################
# -   unban / unbandomain / unbanall / save / ban / country / bancountry / banmalware / whitelist / import / disable / debug / update / start   - #
###################################################################################################################################################


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
		
	unbandomain)
		if [ -z $2 ]; then
			echo "Input Domain To Unban"
			read unbannedip
		else
			unbannedip=$2
		fi
		
		logger -st Firewall "[Unbanning And Removing $unbannedip From Blacklist] ... ... ..."
		for IP in $(nslookup $unbannedip | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | awk 'NR>2')
			do
			ipset -D Blacklist $IP
			sed -i /$IP/d /jffs/scripts/ipset.txt
		done
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
		Unban_PrivateIP
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
		
	bandomain)
		if [ -z $2 ]; then
			echo "Input Domain To Ban"
			read bannedip
		else
			bannedip=$2
		fi
		
		logger -st Firewall "[Adding $bannedip To Blacklist] ... ... ..."
		for IP in $(nslookup $bannedip | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | awk 'NR>2')
			do
			ipset -A Blacklist $IP
		done
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
		cat /tmp/malwarelist.txt | grep -vE '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)'| sed -n "s/\r//;/^$/d;/^[0-9,\.]*$/s/^/add Blacklist /p" | sort -u > /tmp/malwarelist1.txt
		echo "Filtering IPv4 Ranges"
		cat /tmp/malwarelist.txt | grep -vE '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)' | sed -n "s/\r//;/^$/d;/^[0-9,\.,\/]*$/s/^/add BlockedRanges /p" | grep "/" | sort -u >> /tmp/malwarelist1.txt
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
				logger -st Firewall "[Enabling Debug Output] ... ... ..."
				iptables -t raw -I PREROUTING -m set --match-set Blacklist src -j LOG --log-prefix "[BLOCKED - RAW] " --log-tcp-sequence --log-tcp-options --log-ip-options
			elif [ X"$2" = X"disable" ]; then
				logger -st Firewall "[Disabling Debug Output] ... ... ..."
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
			wget -q --no-check-certificate -O /jffs/scripts/firewall https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh && logger -st Firewall "[Firewall Sucessfully Updated]"
			exit
		fi
		;;

	start)
		Check_Settings
		sed -i '/IP Banning Started/d' /tmp/syslog.log
		logger -st Firewall "[IP Banning Started] ... ... ..."
		insmod xt_set > /dev/null 2>&1
		ipset -q -R  < /jffs/scripts/ipset.txt
		Unban_PrivateIP
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
          echo "Command not recognised, please try again"
		;;

esac

Logging
