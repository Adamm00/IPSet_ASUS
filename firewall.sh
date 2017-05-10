#!/bin/sh
#############################################################################################################
#			       _____ _                     _           ____   				    #
#			      / ____| |                   | |         |___ \				    # 
#			     | (___ | | ___   _ _ __   ___| |_  __   __ __) |				    #	
#			      \___ \| |/ / | | | '_ \ / _ \ __| \ \ / /|__ < 				    #
#			      ____) |   <| |_| | | | |  __/ |_   \ V / ___) |				    #
#			     |_____/|_|\_\\__, |_| |_|\___|\__|   \_(_)____/ 				    #
#			                   __/ |                             				    #
# 			                  |___/                              				    #
#													    #
## - 10/05/2017 -		   Asus Firewall Addition By Adamm v3.5.5				    #
## 				   https://github.com/Adamm00/IPSet_ASUS				    #
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

start_time=$(date +%s)
cat $0 | head -40

Check_Settings () {
			if [ "$(ipset -v | grep -o v6)" != "v6" ]; then
				echo "IPSet version not supported"
				exit
			fi
			
			if [ -d "/opt/bin" ] && [ ! -f /opt/bin/firewall ]; then
				echo "Enabling /opt/bin Symlink"
				ln -s /jffs/scripts/firewall /opt/bin
			fi

			if [ "$(nvram get jffs2_scripts)" != "1" ]; then
				echo "Enabling Custom JFFS Scripts"
				nvram set jffs2_scripts=1
				nvram commit
			fi

			if [ "$(nvram get fw_enable_x)" != "1" ]; then
				echo "Enabling SPI Firewall"
				nvram set fw_enable_x=1
				nvram commit
			fi
	
			if [ "$(nvram get fw_log_x)" != "drop" ]; then
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
		OLDIPS=$(nvram get Blacklist)
		OLDRANGES=$(nvram get BlockedRanges)
		nvram set Blacklist=$(expr $(ipset -L Blacklist | wc -l) - 7)
		nvram set BlockedRanges=$(expr $(ipset -L BlockedRanges | wc -l) - 7)
		NEWIPS=$(nvram get Blacklist)
		NEWRANGES=$(nvram get BlockedRanges)
		nvram commit
		HITS1=$(iptables -vL -nt raw | grep -E "set.*Blacklist" | awk '{print $1}')
		HITS2=$(iptables -vL -nt raw | grep -E "set.*BlockedRanges" | awk '{print $1}')
		start_time=$(expr $(date +%s) - $start_time)
		logger -st Skynet "[Complete] $NEWIPS IPs / $NEWRANGES Ranges banned. $(expr $NEWIPS - $OLDIPS) New IPs / $(expr $NEWRANGES - $OLDRANGES) New Ranges Banned. $HITS1 IP / $HITS2 Range Connections Blocked! [$(echo $start_time)s]"
}

Unban_PrivateIP () {
		for IP in $(ipset -L Blacklist | grep -E '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)')
			do
			ipset -D Blacklist $IP
		done
		
		for IP in $(ipset -L BlockedRanges | grep -E '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)')
			do
			ipset -D BlockedRanges $IP
		done
}

###################################################################################################################################################
# -   unban / unbandomain / unbanall / save / ban / country / bancountry / banmalware / whitelist / import / disable / debug / update / start   - #
###################################################################################################################################################


case $1 in
	unban)
		if [ -z "$2" ]; then
			echo "For Automated Unbanning In Future Use; \"sh $0 unban IP\""
			echo "Input IP Address To Unban"
			read unbannedip
		else
			unbannedip=$2
		fi
		
		logger -st Skynet "[Unbanning And Removing $unbannedip From Blacklist] ... ... ..."
		ipset -D Blacklist $unbannedip
		sed -i /$unbannedip/d /jffs/scripts/ipset.txt
		;;
		
	unbandomain)
		if [ -z "$2" ]; then
			echo "For Automated Unbanning In Future Use; \"sh $0 unbandomain DOMAIN\""
			echo "Input Domain To Unban"
			read unbannedip
		else
			unbannedip=$2
		fi
		
		logger -st Skynet "[Unbanning And Removing $unbannedip From Blacklist] ... ... ..."
		for IP in $(nslookup $unbannedip | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | awk 'NR>2')
			do
			ipset -D Blacklist $IP
			sed -i /$IP/d /jffs/scripts/ipset.txt
		done
		;;

	unbanall)
		nvram set Blacklist=$(expr $(ipset -L Blacklist | wc -l) - 6)
		logger -st Skynet "[Deleting All $(nvram get Blacklist) Entries From Blacklist] ... ... ..."
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
		if [ -z "$2" ]; then
			echo "For Automated Banning In Future Use; \"sh $0 ban IP\""
			echo "Input IP Address To Ban"
			read bannedip
		else
			bannedip=$2
		fi
		
		logger -st Skynet "[Adding $bannedip To Blacklist] ... ... ..."
		ipset -A Blacklist $bannedip
		;;
		
	bandomain)
		if [ -z "$2" ]; then
			echo "For Automated Banning In Future Use; \"sh $0 bandomain DOMAIN\""
			echo "Input Domain To Ban"
			read bannedip
		else
			bannedip=$2
		fi
		
		logger -st Skynet "[Adding $bannedip To Blacklist] ... ... ..."
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
	if [ "$2" != "-f" ] && [ -f /jffs/scripts/malware-filter ] || [ -f /jffs/scripts/ya-malware-block.sh ]; then
		echo "Another Malware Filter Script Detected And May Cause Conflicts, Are You Sure You Want To Continue? (yes/no)"
		echo "To Ignore This Error In Future Use; \"sh $0 banmalware -f\""
		read CONTINUE
		if [ "$CONTINUE" != "yes" ]; then
			exit
		fi
	fi
		echo "Banning Known Malware IPs"
		if  [ -n "$2" ] && [ "$2" != "-f" ]; then
			listurl=$2
			echo "Custom List Detected: $2"
		elif [ -n "$3" ]; then
			listurl=$3
			echo "Custom List Detected: $3"
		else
			echo "To Use A Custom List In Future Use; \"sh $0 banmalware URL\""
			listurl="https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/filter.list"
		fi
		echo "Downloading Lists"
		wget -q --no-check-certificate -O /tmp/malwarelist.txt -i $listurl
		echo "Filtering IPv4 Addresses"
		cat /tmp/malwarelist.txt | grep -vE '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)'| sed -n "s/\r//;/^$/d;/^[0-9,\.]*$/s/^/add Blacklist /p" | sort -u > /tmp/malwarelist1.txt
		echo "Filtering IPv4 Ranges"
		cat /tmp/malwarelist.txt | grep -vE '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)' | sed -n "s/\r//;/^$/d;/^[0-9,\.,\/]*$/s/^/add BlockedRanges /p" | grep "/" | sort -u >> /tmp/malwarelist1.txt
		echo "Applying Blacklists"
		ipset -q -R -! < /tmp/malwarelist1.txt
		rm -rf /tmp/malwarelist*.txt
		;;
		
	whitelist)
		if [ -z "$2" ]; then
			echo "For Automated Whitelisting In Future Use; \"sh $0 whitelist IP\""
			echo "Input IP Range To Whitelist"
			read whitelistip
		else
			whitelistip=$2
		fi
		
		logger -st Skynet "[Adding $whitelistip To Whitelist] ... ... ..."
		ipset -A Whitelist $whitelistip
		ipset --save > /jffs/scripts/ipset.txt
		;;

	import)
			if [ -n "$2" ] && [ "$2" != "local" ]; then
				echo "Custom List Detected: $2"
				wget -q --no-check-certificate -O /tmp/ipset2.txt -i $2
			else
				echo "To Use A Custom List In Future Use; \"sh $0 import URL\""
				echo "Defaulting To Local Set At /tmp/ipset2.txt"
			fi
			
			if [ -n "$3" ] && [ -n "$4" ]; then
				echo "Merging Old Set $3 Into $4"
				SET1=$3
				SET2=$4
			else
				echo "To Automate This In Future Use;"
				echo "\"sh $0 import URL/local OLDSET NEWSET\""
				echo "Input Old Set Name"
				read SET1
				echo "Input Set To Merge Into"
				read SET2
			fi
		sed -i "s/$SET1/$SET2/g" /tmp/ipset2.txt
		ipset -q -R -! < /tmp/ipset2.txt
		rm -rf /tmp/ipset2.txt
		echo "Successfully Merged Blacklist"
		;;

	disable)
		logger -st Skynet "[Disabling Firewall] ... ... ..."
		Unload_IPTables
	;;

	debug)
		case $2 in
			enable)
				logger -st Skynet "[Enabling Debug Output] ... ... ..."
				iptables -t raw -I PREROUTING -m set --match-set Blacklist src -j LOG --log-prefix "[BLOCKED - RAW] " --log-tcp-sequence --log-tcp-options --log-ip-options
			;;
			disable)
				logger -st Skynet "[Disabling Debug Output] ... ... ..."
				iptables -t raw -D PREROUTING -m set --match-set Blacklist src -j LOG --log-prefix "[BLOCKED - RAW] " --log-tcp-sequence --log-tcp-options --log-ip-options
			;;
			filter)
				echo "Unbanning Private IP's"
				Unban_PrivateIP
			;;
		*)
			echo "Error - Use Syntax './jffs/scripts/firewall debug (enable/disable)'"
		esac
		;;

	update)
		if [ "$(cat $0)" = "$(wget -q -O - https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh)" ]; then
			logger -st Skynet "[Firewall Up To Date]"
		else
			logger -st Skynet "[New Version Detected - Updating]... ... ..."
			wget -q --no-check-certificate -O $0 https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh && logger -st Skynet "[Firewall Sucessfully Updated]"
			exit
		fi
		;;

	start)
		Check_Settings
		sed -i '/IP Banning Started/d' /tmp/syslog.log
		logger -st Skynet "[IP Banning Started] ... ... ..."
		insmod xt_set > /dev/null 2>&1
		ipset -q -R  < /jffs/scripts/ipset.txt
		Unban_PrivateIP
		ipset -q -N Whitelist nethash
		ipset -q -N Blacklist iphash --maxelem 500000
		ipset -q -N BlockedRanges nethash
		ipset -q -A Whitelist 192.168.1.0/24
		ipset -q -A Whitelist $(nvram get lan_ipaddr)/24
		ipset -q -A Whitelist 151.101.96.133/32
		Unload_IPTables
		Load_IPTables
		sed -i '/DROP IN=/d' /tmp/syslog.log
		;;

     *)
          echo "Command Not Recognised, Please Try Again"
		;;

esac

Logging
