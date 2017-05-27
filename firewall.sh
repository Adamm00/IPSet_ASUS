#!/bin/sh
#############################################################################################################
#			       _____ _                     _           _  _   				    #
#			      / ____| |                   | |         | || |				    #
#			     | (___ | | ___   _ _ __   ___| |_  __   _| || |_				    #
#			      \___ \| |/ / | | | '_ \ / _ \ __| \ \ / /__   _|				    #
#			      ____) |   <| |_| | | | |  __/ |_   \ V /   | |				    #
#			     |_____/|_|\_\\__, |_| |_|\___|\__|   \_(_)  |_| 				    #
#			                   __/ |                             				    #
# 			                  |___/                               				    #
#													    #
## - 27/05/2017 -		   Asus Firewall Addition By Adamm v4.4.5				    #
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
#	  "unban"	     # <-- Remove Entry From Blacklist (IP/Range/Domain/Port/Country/Malware/All)
#	  "save"	     # <-- Save Blacklists To /jffs/scripts/ipset.txt
#	  "ban"		     # <-- Adds Entry To Blacklist (IP/Range/Domain/Port/Country)
#	  "banmalware"	     # <-- Bans Various Malware Domains
#	  "whitelist"        # <-- Add Entry To Whitelist (IP/Range/Domain/Remove)
#	  "import"	     # <-- Import And Merge IPSet Save To Firewall
#	  "deport"	     # <-- Remove All IPs From IPSet Save From Firewall
#	  "disable"	     # <-- Disable Firewall
#	  "debug"	     # <-- Specific Debug Features (Restart/Disable/Watch/Info)
#	  "update"	     # <-- Update Script To Latest Version (check github for changes)
#	  "start"	     # <-- Initiate Firewall
#	  "stats"	     # <-- Print/Search Stats Of Recently Banned IPs (Requires debugging enabled)
#	  "install"          # <-- Install Script (Or Change Boot Args)
#	  "uninstall"        # <-- Uninstall All Traces Of Script
##############################

head -39 "$0"
start_time=$(date +%s)
export LC_ALL=C
#set -x

Check_Settings () {
		if [ -f "/jffs/scripts/IPSET_Block.sh" ]; then
			logger -st Skynet "[IPSet_Block.sh Detected - This script will cause conflicts and does not have saftey checks like Skynet, please uninstall it ASAP]"
		fi

		if [ "$1" = "banmalware" ] || [ "$2" = "banmalware" ] || [ "$3" = "banmalware" ]; then
			cru a Firewall_banmalware "25 1 * * 1 sh /jffs/scripts/firewall banmalware"
		fi

		if [ "$1" = "autoupdate" ] || [ "$2" = "autoupdate" ] || [ "$3" = "autoupdate" ] || [ "$4" = "autoupdate" ]; then
			cru a Firewall_autoupdate "25 1 * * * sh /jffs/scripts/firewall update"
		else
			cru a Firewall_checkupdate "25 2 * * * sh /jffs/scripts/firewall update check"
		fi

		if [ "$(ipset -v | grep -Fo v6)" != "v6" ]; then
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
		fi

		if [ "$(nvram get fw_enable_x)" != "1" ]; then
			echo "Enabling SPI Firewall"
			nvram set fw_enable_x=1
		fi

		if [ "$(nvram get fw_log_x)" != "drop" ]; then
			echo "Enabling Firewall Logging"
			nvram set fw_log_x=drop
		fi
}

Unload_DebugIPTables () {
		iptables -t raw -D PREROUTING -m set --match-set BlockedRanges src -j LOG --log-prefix "[BLOCKED - RAW] " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
		iptables -t raw -D PREROUTING -m set --match-set Blacklist src -j LOG --log-prefix "[BLOCKED - RAW] " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
}

Unload_IPTables () {
		iptables -D logdrop -m state --state NEW -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
		iptables -t raw -D PREROUTING -m set --match-set Blacklist src -j DROP >/dev/null 2>&1
		iptables -t raw -D PREROUTING -m set --match-set BlockedRanges src -j DROP >/dev/null 2>&1
		iptables -t raw -D PREROUTING -m set --match-set Whitelist src -j ACCEPT >/dev/null 2>&1
		iptables -D logdrop -m state --state INVALID -j SET --add-set Blacklist src >/dev/null 2>&1
		iptables -D logdrop -m state --state INVALID -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
		iptables -D logdrop -p tcp -m multiport --sports 80,443 -m state --state INVALID -j DROP
		iptables -D logdrop -m set --match-set Whitelist src -j ACCEPT >/dev/null 2>&1
}

Load_IPTables () {
		iptables -t raw -I PREROUTING -m set --match-set Blacklist src -j DROP >/dev/null 2>&1
		iptables -t raw -I PREROUTING -m set --match-set BlockedRanges src -j DROP >/dev/null 2>&1
		iptables -t raw -I PREROUTING -m set --match-set Whitelist src -j ACCEPT >/dev/null 2>&1
		if [ "$1" = "noautoban" ]; then
			logger -st Skynet "[Enabling No-Autoban Mode] ... ... ..."
		else
			iptables -I logdrop -m state --state INVALID -j SET --add-set Blacklist src >/dev/null 2>&1
			iptables -I logdrop -m state --state INVALID -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
			iptables -I logdrop -p tcp -m multiport --sports 80,443 -m state --state INVALID -j DROP
			iptables -I logdrop -m set --match-set Whitelist src -j ACCEPT >/dev/null 2>&1
		fi
}

Logging () {
		OLDIPS=$(nvram get Blacklist)
		OLDRANGES=$(nvram get BlockedRanges)
		nvram set Blacklist="$(grep -Foc "d Black" /jffs/scripts/ipset.txt 2> /dev/null)"
		nvram set BlockedRanges="$(grep -Foc "d Block" /jffs/scripts/ipset.txt 2> /dev/null)"
		NEWIPS=$(nvram get Blacklist)
		NEWRANGES=$(nvram get BlockedRanges)
		nvram commit
		HITS1=$(iptables -vL -nt raw | grep -Fv "LOG" | grep -F "Blacklist src" | awk '{print $1}')
		HITS2=$(iptables -vL -nt raw | grep -Fv "LOG" | grep -F "BlockedRanges src" | awk '{print $1}')
		start_time=$(($(date +%s) - start_time))
		logger -st Skynet "[Complete] $NEWIPS IPs / $NEWRANGES Ranges banned. $((NEWIPS - OLDIPS)) New IPs / $((NEWRANGES - OLDRANGES)) New Ranges Banned. $HITS1 IP / $HITS2 Range Connections Blocked! [${start_time}s]"
}

Domain_Lookup () {
		nslookup "$1" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | awk 'NR>2'
}

Filter_Version () {
		if [ -n "$1" ]; then
			grep -oE 'v[0-9]{1,2}([.][0-9]{1,2})([.][0-9]{1,2})' "$1"
		elif [ -z "$1" ]; then
			grep -oE 'v[0-9]{1,2}([.][0-9]{1,2})([.][0-9]{1,2})'
		fi
}

Filter_Date () {
		grep -oE '[0-9]{1,2}([/][0-9]{1,2})([/][0-9]{1,4})' "$1"
}

Filter_PrivateIP () {
		echo '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)'
}

Filter_SRC () {
		echo '(SRC=127\.)|(SRC=10\.)|(SRC=172\.1[6-9]\.)|(SRC=172\.2[0-9]\.)|(SRC=172\.3[0-1]\.)|(SRC=192\.168\.)|(SRC=0.)|(SRC=169\.254\.)'
}

Unban_PrivateIP () {
		grep -E "$(Filter_SRC)" /tmp/syslog.log | grep -oE 'SRC=[0-9,\.]* ' | cut -c 5- | while IFS= read -r ip
			do
			ipset -D Blacklist "$ip"
			ipset -D BlockedRanges "$ip"
			sed -i "/SRC=${ip}/d" /tmp/syslog.log
		done
}

Purge_Logs () {
		if [ "$(ls -l /jffs/skynet.log | awk '{print $5}')" -ge "7000000" ]; then
			rm -rf /jffs/skynet.log
		fi
		sed -i '/Aug  1 1/d' /tmp/syslog.log-1 >/dev/null 2>&1
		sed -i '/Aug  1 1/d' /tmp/syslog.log
		sed '/BLOCKED -/!d' /tmp/syslog.log-1 >> /jffs/skynet.log >/dev/null 2>&1
		sed -i '/BLOCKED -/d' /tmp/syslog.log-1 >/dev/null 2>&1
		sed '/BLOCKED -/!d' /tmp/syslog.log >> /jffs/skynet.log
		sed -i '/BLOCKED -/d' /tmp/syslog.log
}

Enable_Debug () {
		if [ "$1" = "debug" ] || [ "$2" = "debug" ]; then
			logger -st Skynet "[Enabling Raw Debug Output] ... ... ..."
			iptables -t raw -I PREROUTING 2 -m set --match-set BlockedRanges src -j LOG --log-prefix "[BLOCKED - RAW] " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
			iptables -t raw -I PREROUTING 4 -m set --match-set Blacklist src -j LOG --log-prefix "[BLOCKED - RAW] " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
		fi
}

#####################################################################################################################
# -   unban  / save / ban / banmalware / whitelist / import / deport / disable / debug / update / start / stats   - #
#####################################################################################################################


case $1 in
	unban)
		Purge_Logs
		if [ -z "$2" ]; then
			echo "For Automated IP Unbanning Use; \"sh $0 unban IP\""
			echo "For Automated IP Range Unbanning Use; \"sh $0 unban range IP\""
			echo "For Automated Domain Unbanning Use; \"sh $0 unban domain URL\""
			echo "To Unban All Domains Use; \"sh $0 unban all\""
			echo "Input IP To Unban"
			read -r unbanip
			logger -st Skynet "[Removing $unbanip From Blacklist] ... ... ..."
			ipset -D Blacklist "$unbanip"
			sed -i "/$unbanip/d" /jffs/skynet.log
		elif [ -n "$2" ] && [ "$2" != "domain" ] && [ "$2" != "range" ] && [ "$2" != "port" ] && [ "$2" != "country" ] && [ "$2" != "malware" ] && [ "$2" != "all" ]; then
			logger -st Skynet "[Removing $2 From Blacklist] ... ... ..."
			ipset -D Blacklist "$2"
			sed -i "/$2/d" /jffs/skynet.log
		elif [ "$2" = "range" ] && [ -n "$3" ]; then
			logger -st Skynet "[Removing $3 From Blacklist] ... ... ..."
			ipset -D BlockedRanges "$3"
			sed -i "\~$3~d" /jffs/skynet.log
		elif [ "$2" = "domain" ] && [ -z "$3" ]; then
			echo "Input Domain To Unban"
			read -r unbandomain
			logger -st Skynet "[Removing $unbandomain From Blacklist] ... ... ..."
			for ip in $(Domain_Lookup "$unbandomain")
				do
				ipset -D Blacklist "$ip"
				sed -i "/$ip/d" /jffs/skynet.log
			done
		elif [ "$2" = "domain" ] && [ -n "$3" ]; then
		logger -st Skynet "[Removing $3 From Blacklist] ... ... ..."
		for ip in $(Domain_Lookup "$3")
			do
			ipset -D Blacklist "$ip"
			sed -i "/$ip/d" /jffs/skynet.log
		done
		elif [ "$2" = "port" ] && [ -n "$3" ]; then
			logger -st Skynet "[Unbanning Autobans Issued On Traffic From Port $3] ... ... ..."
			grep -F "NEW" /jffs/skynet.log | grep -F "DPT=$3 " | grep -oE 'SRC=[0-9,\.]* ' | cut -c 5- | while IFS= read -r ip
				do
				echo "Unbanning $ip"
				ipset -D Blacklist "$ip"
			done
			sed -i "/DPT=${3} /d" /jffs/skynet.log
		elif [ "$2" = "country" ]; then
			echo "Removing Previous Country Bans"
			sed 's/add/del/g' /jffs/scripts/countrylist.txt | ipset -q -R -!
			rm -rf /jffs/scripts/countrylist.txt
		elif [ "$2" = "malware" ]; then
			echo "Removing Previous Malware Bans"
			sed 's/add/del/g' /jffs/scripts/malwarelist.txt | ipset -q -R -!
			rm -rf /jffs/scripts/malwarelist.txt
		elif [ "$2" = "all" ]; then
			nvram set Blacklist=$(($(grep -Foc "d Black" /jffs/scripts/ipset.txt) + $(grep -Foc "d Block" /jffs/scripts/ipset.txt)))
			logger -st Skynet "[Removing All $(nvram get Blacklist) Entries From Blacklist] ... ... ..."
			ipset --flush Blacklist
			ipset --flush BlockedRanges
			rm -rf /jffs/skynet.log /jffs/scripts/countrylist.txt /jffs/scripts/malwarelist.txt
		else
			echo "Command Not Recognised, Please Try Again"
			exit
		fi
		ipset --save > /jffs/scripts/ipset.txt
		;;

	save)
		echo "[Saving Blacklists] ... ... ..."
		Unban_PrivateIP
		Purge_Logs
		ipset --save > /jffs/scripts/ipset.txt
		sed -i '/USER admin pid .*firewall/d' /tmp/syslog.log
		;;

	ban)
		Purge_Logs
		if [ -z "$2" ]; then
			echo "For Automated IP Banning Use; \"sh $0 ban IP\""
			echo "For Automated IP Range Banning Use; \"sh $0 ban range IP\""
			echo "For Automated Domain Banning Use; \"sh $0 ban domain URL\""
			echo "For Automated Country Banning Use; \"sh $0 ban country zone\""
			echo "Input IP To Ban"
			read -r banip
			logger -st Skynet "[Adding $banip To Blacklist] ... ... ..."
			ipset -A Blacklist "$banip"
		elif [ -n "$2" ] && [ "$2" != "range" ] && [ "$2" != "domain" ] && [ "$2" != "country" ] && [ "$2" != "countrylist" ]; then
			logger -st Skynet "[Adding $2 To Blacklist] ... ... ..."
			ipset -A Blacklist "$2"
		elif [ "$2" = "range" ] && [ -n "$3" ]; then
			logger -st Skynet "[Adding $3 To Blacklist] ... ... ..."
			ipset -A BlockedRanges "$3"
		elif [ "$2" = "domain" ] && [ -z "$3" ]; then
			echo "Input Domain To Blacklist"
			read -r bandomain
			logger -st Skynet "[Adding $bandomain To Blacklist] ... ... ..."
			for ip in $(Domain_Lookup "$bandomain")
				do
				ipset -A Blacklist "$ip"
			done
		elif [ "$2" = "domain" ] && [ -n "$3" ]; then
		logger -st Skynet "[Adding $3 To Blacklist] ... ... ..."
		for ip in $(Domain_Lookup "$3")
			do
			ipset -A Blacklist "$ip"
		done
		elif [ "$2" = "country" ] && [ -n "$3" ]; then
			echo "Removing Previous Country Bans"
			sed 's/add/del/g' /jffs/scripts/countrylist.txt | ipset -q -R -!
			echo "Banning Known IP Ranges For $3"
			echo "Downloading Lists"
			for country in $3
			do
				wget -q -O - http://www.ipdeny.com/ipblocks/data/countries/"$country".zone >> /tmp/countrylist.txt
			done
			echo "Filtering IPv4 Ranges"
			sed -n "s/\r//;/^$/d;/^[0-9,\.,\/]*$/s/^/add BlockedRanges /p" /tmp/countrylist.txt | grep -F "/" | awk '!x[$0]++' >> /jffs/scripts/countrylist.txt
			echo "Applying Blacklists"
			ipset -q -R -! < /jffs/scripts/countrylist.txt
			rm -rf /tmp/countrylist*.txt
		else
			echo "Command Not Recognised, Please Try Again"
			exit
		fi
		ipset --save > /jffs/scripts/ipset.txt
		;;

	banmalware)
	if [ "$2" != "-f" ] && [ -f /jffs/scripts/malware-filter ] || [ -f /jffs/scripts/ya-malware-block.sh ] || [ -f /jffs/scripts/ipBLOCKer.sh ]; then
		echo "Another Malware Filter Script Detected And May Cause Conflicts, Are You Sure You Want To Continue? (yes/no)"
		echo "To Ignore This Error In Future Use; \"sh $0 banmalware -f\""
		read -r continue
		if [ "$continue" != "yes" ]; then
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
			echo "Removing Previous Malware Bans"
			sed 's/add/del/g' /jffs/scripts/malwarelist.txt | ipset -q -R -!
		fi
		echo "Downloading Lists"
		wget -q --no-check-certificate $listurl -O /tmp/filter.list
		wget --no-check-certificate -i /tmp/filter.list -qO- | awk '!x[$0]++' | grep -vE "$(Filter_PrivateIP)" > /tmp/malwarelist.txt
		echo "Filtering IPv4 Addresses"
		sed -n "s/\r//;/^$/d;/^[0-9,\.]*$/s/^/add Blacklist /p" /tmp/malwarelist.txt > /jffs/scripts/malwarelist.txt
		echo "Filtering IPv4 Ranges"
		sed -n "s/\r//;/^$/d;/^[0-9,\.,\/]*$/s/^/add BlockedRanges /p" /tmp/malwarelist.txt | grep -F "/" >> /jffs/scripts/malwarelist.txt
		echo "Applying Blacklists"
		ipset -q -R -! < /jffs/scripts/malwarelist.txt
		rm -rf /tmp/malwarelist.txt /tmp/filter.list
		if [ -f /home/root/ab-solution.sh ]; then
			ipset -q -A Whitelist 213.230.210.230 # AB-Solution Host File
		fi
		echo "Warning; This May Have Blocked Your Favorite Torrent Website"
		echo "To Whitelist It Use; \"sh $0 whitelist domain URL\""
		ipset --save > /jffs/scripts/ipset.txt
		;;

	whitelist)
		Purge_Logs
		if [ -z "$2" ]; then
			echo "For Automated IP Whitelisting Use; \"sh $0 whitelist IP\""
			echo "For Automated Domain Whitelisting Use; \"sh $0 whitelist domain URL\""
			echo "Input IP To Whitelist"
			read -r whitelistip
			logger -st Skynet "[Adding $whitelistip To Whitelist] ... ... ..."
			ipset -A Whitelist "$whitelistip"
			ipset -D Blacklist "$whitelistip"
			sed -i "\~$whitelistip~d" /jffs/skynet.log
		elif [ -n "$2" ] && [ "$2" != "domain" ] && [ "$2" != "port" ] && [ "$2" != "remove" ]; then
			logger -st Skynet "[Adding $2 To Whitelist] ... ... ..."
			ipset -A Whitelist "$2"
			ipset -D Blacklist "$2"
			sed -i "\~$2~d" /jffs/skynet.log
		elif [ "$2" = "domain" ] && [ -z "$3" ];then
			echo "Input Domain To Whitelist"
			read -r whitelistdomain
			logger -st Skynet "[Adding $whitelistdomain To Whitelist] ... ... ..."
			for ip in $(Domain_Lookup "$whitelistdomain")
				do
				ipset -A Whitelist "$ip"
				ipset -D Blacklist "$ip"
				sed -i "/$ip/d" /jffs/skynet.log
			done
		elif [ "$2" = "domain" ] && [ -n "$3" ]; then
		logger -st Skynet "[Adding $3 To Whitelist] ... ... ..."
		for ip in $(Domain_Lookup "$3")
			do
			ipset -A Whitelist "$ip"
			ipset -D Blacklist "$ip"
			sed -i "/$ip/d" /jffs/skynet.log
		done
		elif [ "$2" = "port" ] && [ -n "$3" ]; then
			logger -st Skynet "[Whitelisting Autobans Issued On Traffic From Port $3] ... ... ..."
			grep -F "NEW" /jffs/skynet.log | grep -F "DPT=$3 " | grep -oE 'SRC=[0-9,\.]* ' | cut -c 5- | while IFS= read -r ip
				do
				echo "Whitelisting $ip"
				ipset -A Whitelist "$ip"
				ipset -D Blacklist "$ip"
				sed -i "/$ip/d" /jffs/skynet.log
			done
		elif [ "$2" = "remove" ]; then
			echo "Removing All Non-Default Whitelist Entries"
			ipset --flush Whitelist
			ipset --save > /jffs/scripts/ipset.txt
			echo "Restarting Firewall"
			service restart_firewall
			exit
		else
			echo "Command Not Recognised, Please Try Again"
			exit
		fi
		ipset --save > /jffs/scripts/ipset.txt
		;;

	import)
		echo "This Function Only Supports IPSet Generated Save Files And Adds Them ALL To Blacklist"
		echo "To Save A Specific Set In SSH Use; 'ipset --save Blacklist > /jffs/scripts/ipset2.txt'"
		if [ -n "$2" ]; then
			echo "Custom List Detected: $2"
			wget -q --no-check-certificate -O /jffs/scripts/ipset2.txt "$2"
		else
			echo "To Download A Custom List Use; \"sh $0 import URL\""
			echo "Defaulting Blacklist Location To /jffs/scripts/ipset2.txt"
		fi
		if [ ! -f /jffs/scripts/ipset2.txt ]; then
			echo "No IPSet Backup Detected - Exiting"
			exit
		fi
		echo "Filtering IPv4 Addresses"
		grep -Fv "create" /jffs/scripts/ipset2.txt |  awk '{print $3}' | grep -vE "$(Filter_PrivateIP)" | sed -n "s/\r//;/^$/d;/^[0-9,\.]*$/s/^/add Blacklist /p" > /tmp/ipset3.txt
		echo "Filtering IPv4 Ranges"
		grep -Fv "create" /jffs/scripts/ipset2.txt |  awk '{print $3}' | grep -vE "$(Filter_PrivateIP)" | sed -n "s/\r//;/^$/d;/^[0-9,\.,\/]*$/s/^/add BlockedRanges /p" | grep -F "/" >> /tmp/ipset3.txt
		echo "Importing IPs To Blacklist"
		ipset -q -R -! < /tmp/ipset3.txt
		rm -rf /tmp/ipset3.txt
		ipset --save > /jffs/scripts/ipset.txt
		;;

	deport)
		echo "This Function Only Supports IPSet Generated Save Files And Removes Them ALL From Blacklist"
		echo "To Save A Specific Set In SSH Use; 'ipset --save Blacklist > /jffs/scripts/ipset2.txt'"
		if [ -n "$2" ]; then
			echo "Custom List Detected: $2"
			wget -q --no-check-certificate -O /jffs/scripts/ipset2.txt "$2"
		else
			echo "To Download A Custom List Use; \"sh $0 import URL\""
			echo "Defaulting Blacklist Location To /jffs/scripts/ipset2.txt"
		fi
		if [ ! -f /jffs/scripts/ipset2.txt ]; then
			echo "No IPSet Backup Detected - Exiting"
			exit
		fi
		echo "Filtering IPv4 Addresses"
		grep -Fv "create" /jffs/scripts/ipset2.txt |  awk '{print $3}' | sed -n "s/\r//;/^$/d;/^[0-9,\.]*$/s/^/del Blacklist /p" > /tmp/ipset3.txt
		echo "Filtering IPv4 Ranges"
		grep -Fv "create" /jffs/scripts/ipset2.txt |  awk '{print $3}' | sed -n "s/\r//;/^$/d;/^[0-9,\.,\/]*$/s/^/del BlockedRanges /p" | grep -F "/" >> /tmp/ipset3.txt
		echo "Removing IPs From Blacklist"
		ipset -q -R -! < /tmp/ipset3.txt
		rm -rf /tmp/ipset3.txt
		ipset --save > /jffs/scripts/ipset.txt
		;;

	disable)
		logger -st Skynet "[Disabling Skynet] ... ... ..."
		Unload_IPTables
		Unload_DebugIPTables
		Purge_Logs
	;;

	debug)
		case $2 in
			restart)
				echo "Restarting Firewall Service"
				service restart_firewall
				exit
			;;
			disable)
				logger -st Skynet "[Temporarily Disabling Raw Debug Output] ... ... ..."
				Unload_DebugIPTables
				Purge_Logs
			;;
			watch)
				Purge_Logs
				echo "Watching Logs For Debug Entries (ctrl +c) To Stop"
				echo
				tail -f /tmp/syslog.log | grep -F "BLOCKED"
			;;
			info)
				RED="printf \e[0;31m%-6s\e[m\n"
				GRN="printf \e[0;32m%-6s\e[m\n"
				echo "Router Model: $(uname -n)"
				echo "Skynet Version: $(Filter_Version "$0") ($(Filter_Date "$0"))"
				iptables --version
				ipset -v
				echo "FW Version: $(nvram get buildno)_$(nvram get extendno)"
				grep -F "firewall start" /jffs/scripts/firewall-start >/dev/null 2>&1 && $GRN "Startup Entry Detected" || $RED "Startup Entry Not Detected"
				cru l | grep -F "firewall" >/dev/null 2>&1 && $GRN "Cronjob Detected" || $RED "Cronjob Not Detected"
				iptables -L | grep -F "LOG" | grep -F "BAN" >/dev/null 2>&1 && $GRN "Autobanning Enabled" || $RED "Autobanning Disabled"
				iptables -vL -nt raw | grep -F "Whitelist" >/dev/null 2>&1 && $GRN "Whitelist IPTable Detected" || $RED "Whitelist IPTable Not Detected"
				iptables -vL -nt raw | grep -v "LOG" | grep -F "BlockedRanges" >/dev/null 2>&1 && $GRN "BlockedRanges IPTable Detected" || $RED "BlockedRanges IPTable Not Detected"
				iptables -vL -nt raw | grep -v "LOG" | grep -F "Blacklist" >/dev/null 2>&1 && $GRN "Blacklist IPTable Detected" || $RED "Blacklist IPTable Not Detected"
				ipset -L Whitelist >/dev/null 2>&1 && $GRN "Whitelist IPSet Detected" || $RED "Whitelist IPSet Not Detected"
				ipset -L BlockedRanges >/dev/null 2>&1 && $GRN "BlockedRanges IPSet Detected" || $RED "BlockedRanges IPSet Not Detected"
				ipset -L Blacklist >/dev/null 2>&1 && $GRN "Blacklist IPSet Detected" || $RED "Blacklist IPSet Not Detected"
			;;

		*)
			echo "Error - Use Syntax './jffs/scripts/firewall debug (enable/disable/filter/info)'"
		esac
		;;

	update)
		localver="$(Filter_Version "$0")"
		remotever="$(wget -q -O - https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh | Filter_Version)"
		if [ "$localver" = "$remotever" ] && [ "$2" != "-f" ]; then
			echo "To Use Only Check For Update Use; \"sh $0 update check\""
			echo "To Force Update Use; \"sh $0 update -f\""
			logger -st Skynet "[Skynet Up To Date - $localver]"
			exit
		elif [ "$localver" != "$remotever" ] && [ "$2" = "check" ]; then
			logger -st Skynet "[Skynet Update Detected - $remotever]"
			exit
		elif [ "$2" = "-f" ]; then
			logger -st Skynet "[Forcing Update]"
		fi
		if [ "$localver" != "$remotever" ] || [ "$2" = "-f" ]; then
			logger -st Skynet "[New Version Detected - Updating To $remotever]... ... ..."
			wget -q --no-check-certificate -O "$0" https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh && logger -st Skynet "[Skynet Sucessfully Updated - Restarting Firewall]"
			service restart_firewall
			exit
		fi
		;;

	start)
		iptables -t raw -F
		Check_Settings "$2" "$3" "$4" "$5"
		cru a Firewall_save "0 * * * * /jffs/scripts/firewall save"
		sed -i '/IP Banning Started/d' /tmp/syslog.log
		logger -st Skynet "[IP Banning Started] ... ... ..."
		insmod xt_set >/dev/null 2>&1
		ipset -q -R >/dev/null 2>&1 < /jffs/scripts/ipset.txt
		Unban_PrivateIP
		Purge_Logs
		ipset -q -N Whitelist nethash
		ipset -q -N Blacklist iphash --maxelem 500000
		ipset -q -N BlockedRanges nethash
		ipset -q -A Whitelist 192.168.1.0/24
		ipset -q -A Whitelist "$(nvram get wan0_ipaddr)"/32
		ipset -q -A Whitelist "$(nvram get lan_ipaddr)"/24
		ipset -q -A Whitelist "$(nvram get wan_dns1_x)"/32
		ipset -q -A Whitelist "$(nvram get wan_dns2_x)"/32
		ipset -q -A Whitelist 151.101.96.133/32   # raw.githubusercontent.com Update Server
		Unload_IPTables
		Unload_DebugIPTables
		Load_IPTables "$2"
		Enable_Debug "$2" "$3"
		sed -i '/DROP IN=/d' /tmp/syslog.log
		;;

	stats)
		Purge_Logs
		if ! iptables -L -nt raw | grep -qF "LOG"; then
			echo
			echo "!!! Debug Mode Is Disabled !!!"
			echo "To Enable Use 'sh $0 install'"
			echo
		fi
		if [ -f /jffs/skynet.log ] && [ "$(wc -l /jffs/skynet.log | awk '{print $1}')" != "0" ]; then
			echo "Debug Data Detected in /jffs/skynet.log - $(ls -lh /jffs/skynet.log | awk '{print $5}')"
		else
			echo "No Debug Data Detected - Give This Time To Generate"
			exit
		fi
		if ! iptables -L -nt raw | grep -qF "BLOCKED"; then
			echo "Only New Bans Being Tracked (enable debug mode for connection tracking)"
		fi
		if [ "$2" = "reset" ]; then
			rm -rf /jffs/skynet.log
			echo "Stat Data Reset"
			exit
		fi
		echo "Monitoring From $(head -1 /jffs/skynet.log | awk '{print $1" "$2" "$3}') To $(tail -1 /jffs/skynet.log | awk '{print $1" "$2" "$3}')"
		echo "$(wc -l /jffs/skynet.log | awk '{print $1}') Total Connections Detected"
		echo "$(grep -oE ' SRC=[0-9,\.]* ' /jffs/skynet.log | cut -c 6- | awk '!x[$0]++' | wc -l) Unique IP Connections"
		echo "$(grep -Fc "NEW BAN" /jffs/skynet.log) Autobans Issued"
		echo
		counter=10
		if [ -n "$2" ] && [ "$2" != "search" ] && [ "$2" -eq "$2" ] 2>/dev/null; then
			counter=$2
		elif [ -n "$5" ] && [ "$5" -eq "$5" ] 2>/dev/null; then
			counter=$5
		elif [ "$3" = "autobans" ] && [ "$4" -eq "$4" ] 2>/dev/null; then
			counter=$4
		fi
		if [ "$2" = "tcp" ] || [ "$3" = "tcp" ]; then
			proto=TCP
		elif [ "$2" = "udp" ] || [ "$3" = "udp" ]; then
			proto=UDP
		elif [ "$2" = "icmp" ] || [ "$3" = "icmp" ]; then
			proto=ICMP
		fi
		if [ "$2" = "search" ] && [ "$3" = "port" ]; then
			echo "Port $4 First Tracked On $(grep -F "DPT=$4 " /jffs/skynet.log | head -1 | awk '{print $1" "$2" "$3}')"
			echo "Port $4 Last Tracked On $(grep -F "DPT=$4 " /jffs/skynet.log | tail -1 | awk '{print $1" "$2" "$3}')"
			echo "$(grep -Foc "DPT=$4 " /jffs/skynet.log) Attempts Total"
			echo
			echo "First Attack Tracked On Port $4;"
			grep -F "DPT=$4 " /jffs/skynet.log | head -1
			echo
			echo "$counter Most Recent Attacks On Port $4;";
			grep -F "DPT=$4 " /jffs/skynet.log | tail -"$counter"
			exit
		elif [ "$2" = "search" ] && [ "$3" = "ip" ]; then
			ipset test Whitelist "$4"
			ipset test Blacklist "$4"
			ipset test BlockedRanges "$4"
			echo
			echo "$4 First Tracked On $(grep -F "SRC=$4 " /jffs/skynet.log | head -1 | awk '{print $1" "$2" "$3}')"
			echo "$4 Last Tracked On $(grep -F "SRC=$4 " /jffs/skynet.log | tail -1 | awk '{print $1" "$2" "$3}')"
			echo "$(grep -Foc "SRC=$4 " /jffs/skynet.log) Attempts Total"
			echo
			echo "First Attack Tracked From $4;"
			grep -F "SRC=$4 " /jffs/skynet.log | head -1
			echo
			echo "$counter Most Recent Attacks From $4;"
			grep -F "SRC=$4 " /jffs/skynet.log | tail -"$counter"
			exit
		elif [ "$2" = "search" ] && [ "$3" = "autobans" ]; then
			echo "First Autoban Issued On $(grep -F "NEW BAN" /jffs/skynet.log | head -1 | awk '{print $1" "$2" "$3}')"
			echo "Last Autoban Issued On $(grep -F "NEW BAN" /jffs/skynet.log | tail -1 | awk '{print $1" "$2" "$3}')"
			echo
			echo "First Autoban Issued;"
			grep -F "NEW BAN" /jffs/skynet.log | head -1
			echo
			echo "$counter Most Recent Autobans;"
			grep -F "NEW BAN" /jffs/skynet.log | tail -"$counter"
			exit
		fi
		echo "Top $counter Ports Attacked; (Torrent Clients May Cause Excess Hits In Debug Mode)"
		grep -vE 'SPT=80 |SPT=443 ' /jffs/skynet.log | grep -F "$proto" | grep -oE 'DPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://www.speedguide.net/port.php?port="$2}'
		echo
		echo "Top $counter Attacker Source Ports;"
		grep -vE 'SPT=80 |SPT=443 ' /jffs/skynet.log | grep -F "$proto" | grep -oE 'SPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://www.speedguide.net/port.php?port="$2}'
		echo
		echo "Last $counter Unique Connections Blocked;"
		grep -vE 'SPT=80 |SPT=443 ' /jffs/skynet.log | grep -F "$proto" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | awk '!x[$0]++' | tail -"$counter" | sed '1!G;h;$!d' | awk '{print "https://otx.alienvault.com/indicator/ip/"$1}'
		echo
		echo "Last $counter Autobans;"
		grep -vE 'SPT=80 |SPT=443 ' /jffs/skynet.log | grep -F "$proto" | grep -F "NEW BAN" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | tail -"$counter" | sed '1!G;h;$!d' | awk '{print "https://otx.alienvault.com/indicator/ip/"$1}'
		echo
		echo "Last $counter Unique HTTP(s) Blocks;"
		grep -E 'SPT=80 |SPT=443 ' /jffs/skynet.log | grep -F "$proto" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | awk '!x[$0]++' | tail -"$counter" | sed '1!G;h;$!d' | awk '{print "https://otx.alienvault.com/indicator/ip/"$1}'
		echo
		echo "Top $counter HTTP(s) Blocks;"
		grep -E 'SPT=80 |SPT=443 ' /jffs/skynet.log | grep -F "$proto" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://otx.alienvault.com/indicator/ip/"$2}'
		echo
		echo "Top $counter Attackers;"
		grep -vE 'SPT=80 |SPT=443 ' /jffs/skynet.log | grep -F "$proto" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://otx.alienvault.com/indicator/ip/"$2}'
		echo
		;;

	install)
		if [ ! -f /jffs/scripts/firewall-start ]; then
			echo "#!/bin/sh" > /jffs/scripts/firewall-start
		elif [ -f /jffs/scripts/firewall-start ] && ! grep -qF "#!/bin" /jffs/scripts/firewall-start; then
			sed -i '1s~^~#!/bin/sh\n~' /jffs/scripts/firewall-start
		fi
		echo "Installing Skynet $(Filter_Version "$0")"
		echo "This Will Remove Any Old Install Arguements And Can Be Run Multiple Times"
		echo "Please Select Installation Mode (Number)"
		echo "1. Vanilla -           Default Installation"
		echo "2. NoAuto -            Default Installation Without Autobanning"
		echo "3. Debug -             Default Installation With Debug Print For Extended Stat Reporting"
		echo "4. NoAuto & Debug -    Default Installation With No Autobanning And Debug Print"
		echo
		read -r mode
		case $mode in
			1)
			echo "Vanilla Selected"
			set1="start"
			;;
			2)
			echo "NoAuto Selected"
			set1="start noautoban"
			;;
			3)
			echo "Debug Selected"
			set1="start debug"
			;;
			4)
			echo "NoAuto Debug Selected"
			set1="start noautoban debug"
			;;
			*)
			echo "Mode Not Recognised - Please Run The Command And Try Again"
			exit
			;;
		esac
		echo
		echo "Would You Like To Enable Weekly Malwarelist Updating"
		echo "1. Yes"
		echo "2. No"
		echo "Please Select Option (Number)"
		read -r mode2
		case $mode2 in
			1)
			echo "Malware List Updating Enabled"
			echo "Malware Updates Scheduled For 1.25am Every Monday"
			set2="banmalware"
			;;
			*)
			echo "Malware List Updating Disabled"
			;;
		esac
		echo
		echo "Would You Like To Enable Daily Auto Script Updating"
		echo "Skynet By Default Only Checks For Updates But They Are Never Downloaded"
		echo
		echo "1. Yes"
		echo "2. No"
		echo "Please Select Option (Number)"
		read -r mode2
		case $mode2 in
			1)
			echo "Auto Updating Enabled"
			echo "Skynet Updates Scheduled For 2.25am Daily"
			sed -i '\~/jffs/scripts/firewall ~d' /jffs/scripts/firewall-start
			echo "sh /jffs/scripts/firewall $set1 $set2 autoupdate # Skynet Firewall Addition" >> /jffs/scripts/firewall-start
			;;
			*)
			echo "Auto Updating Disabled"
			sed -i '\~/jffs/scripts/firewall ~d' /jffs/scripts/firewall-start
			echo "sh /jffs/scripts/firewall $set1 $set2 # Skynet Firewall Addition" >> /jffs/scripts/firewall-start
			;;
		esac
		chmod +x /jffs/scripts/firewall-start
		echo
		echo "Restarting Firewall To Apply Changes"
		cru d Firewall_save
		cru d Firewall_banmalware
		cru d Firewall_autoupdate
		cru d Firewall_checkupdate
		service restart_firewall
		exit
		;;

	uninstall)
		echo "Uninstalling All Traces Of Skynet"
		echo "If You Were Experiencing Bugs, Try Update Or Visit SNBForums/Github"
		echo "https://github.com/Adamm00/IPSet_ASUS"
		echo "Type 'yes' To Continue"
		read -r continue
		if [ "$continue" = "yes" ]; then
			echo "Uninstalling And Restarting Firewall"
			sed -i '\~/jffs/scripts/firewall ~d' /jffs/scripts/firewall-start
			rm -rf /jffs/scripts/ipset.txt /jffs/scripts/ipset2.txt /jffs/scripts/ipset3.txt /jffs/scripts/malwarelist.txt /jffs/scripts/countrylist.txt /jffs/skynet.log /jffs/scripts/firewall
			iptables -t raw -F
			service restart_firewall
			exit
		fi
		;;

	*)
        echo "Command Not Recognised, Please Try Again"
		echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
		;;

esac

Logging
