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
## - 11/05/2017 -		   Asus Firewall Addition By Adamm v3.6.1				    #
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
#	  "unban"	     # <-- Remove Entry From Blacklist (IP/Range/Domain/All)
#	  "save"	     # <-- Save Blacklists To /jffs/scripts/ipset.txt
#	  "ban"		     # <-- Adds Entry To Blacklist (IP/Range/Domain/Country)
#	  "banmalware"	     # <-- Bans Various Malware Domains
#	  "whitelist"        # <-- Add Entry To Whitelist (IP/Range/Domain)
#	  "import"	     # <-- Import And Merge IPSet Backup To Firewall
#	  "disable"	     # <-- Disable Firewall
#	  "debug"	     # <-- Enable/Disable Debug Output
#	  "update"	     # <-- Update Script To Latest Version (check github for changes)
#	  "start"	     # <-- Initiate Firewall
##############################

start_time=$(date +%s)
cat $0 | head -35

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
		for ip in $(ipset -L Blacklist | grep -E '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)')
			do
			ipset -D Blacklist $ip
		done
		
		for ip in $(ipset -L BlockedRanges | grep -E '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)')
			do
			ipset -D BlockedRanges $ip
		done
}

Domain_Lookup () {
		echo "$(nslookup $1 | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | awk 'NR>2')"
}

####################################################################################################
# -   unban  / save / ban / banmalware / whitelist / import / disable / debug / update / start   - #
####################################################################################################


case $1 in
	unban)
		if [ -z "$2" ]; then
			echo "For Automated IP Unbanning Use; \"sh $0 unban IP\""
			echo "For Automated IP Range Unbanning Use; \"sh $0 unban range IP\""
			echo "For Automated Domain Unbanning Use; \"sh $0 unban domain URL\""
			echo "To Unban All Domains Use; \"sh $0 unban all\""
			echo "Input IP To Unban"
			read unbanip
			logger -st Skynet "[Removing $unbanip From Blacklist] ... ... ..."
			ipset -D Blacklist $unbanip
		elif [ -n "$2" ] && [ "$2" != "domain" ]&& [ "$2" != "range" ] && [ "$2" != "all" ]; then
			logger -st Skynet "[Removing $2 From Blacklist] ... ... ..."
			ipset -D Blacklist $2
		elif [ "$2" = "range" ] && [ -n "$3" ]; then
			logger -st Skynet "[Removing $3 From Blacklist] ... ... ..."
			ipset -D BlockedRanges $3
		elif [ "$2" = "domain" ] && [ -z "$3" ]; then
			echo "Input Domain To Unban"
			read unbandomain
			logger -st Skynet "[Removing $unbandomain From Blacklist] ... ... ..."
			for ip in $(Domain_Lookup $unbandomain)
				do
				ipset -D Blacklist $ip
			done
		elif [ "$2" = "domain" ] && [ -n "$3" ]; then
		logger -st Skynet "[Removing $3 From Blacklist] ... ... ..."
		for ip in $(Domain_Lookup $3)
			do
			ipset -D Blacklist $ip
		done
		elif [ "$2" = "all" ]; then
			nvram set Blacklist=$(expr $(ipset -L Blacklist | wc -l) - 6)
			logger -st Skynet "[Removing All $(nvram get Blacklist) Entries From Blacklist] ... ... ..."
			ipset --flush Blacklist
			ipset --flush BlockedRanges
		else
			echo "Command Not Recognised, Please Try Again"
			exit
		fi
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
			echo "For Automated IP Banning Use; \"sh $0 ban IP\""
			echo "For Automated IP Range Banning Use; \"sh $0 ban range IP\""
			echo "For Automated Domain Banning Use; \"sh $0 ban domain URL\""
			echo "For Automated Manual Country Banning Use; \"sh $0 ban country zone\""
			echo "Input IP To Ban"
			read banip
			logger -st Skynet "[Adding $banip To Blacklist] ... ... ..."
			ipset -A Blacklist $banip
		elif [ -n "$2" ] && [ "$2" != "range" ] && [ "$2" != "domain" ] && [ "$2" != "country" ] && [ "$2" != "countrylist" ]; then
			logger -st Skynet "[Adding $2 To Blacklist] ... ... ..."
			ipset -A Blacklist $2
		elif [ "$2" = "range" ] && [ -n "$3" ]; then
			logger -st Skynet "[Adding $3 To Blacklist] ... ... ..."
			ipset -A BlockedRanges $3
		elif [ "$2" = "domain" ] && [ -z "$3" ]; then
			echo "Input Domain To Blacklist"
			read bandomain
			logger -st Skynet "[Adding $bandomain To Blacklist] ... ... ..."
			for ip in $(Domain_Lookup $bandomain)
				do
				ipset -A Blacklist $ip
			done
		elif [ "$2" = "domain" ] && [ -n "$3" ]; then
		logger -st Skynet "[Adding $3 To Blacklist] ... ... ..."
		for ip in $(Domain_Lookup $3)
			do
			ipset -A Blacklist $ip
		done
		elif [ "$2" = "country" ] && [ -n "$3" ]; then
			echo "Banning Known IP Ranges For $3"
			echo "Downloading Lists"
			wget -q --no-check-certificate -O /tmp/countrylist.txt -i http://www.ipdeny.com/ipblocks/data/countries/$3.zone
			echo "Filtering IPv4 Ranges"
			cat /tmp/countrylist.txt | sed -n "s/\r//;/^$/d;/^[0-9,\.,\/]*$/s/^/add BlockedRanges /p" | grep "/" | sort -u >> /tmp/countrylist1.txt
			echo "Applying Blacklists"
			ipset -q -R -! < /tmp/countrylist1.txt
			rm -rf /tmp/countrylist*.txt
		else
			echo "Command Not Recognised, Please Try Again"
			exit
		fi
		;;

	banmalware)
	if [ "$2" != "-f" ] && [ -f /jffs/scripts/malware-filter ] || [ -f /jffs/scripts/ya-malware-block.sh ]; then
		echo "Another Malware Filter Script Detected And May Cause Conflicts, Are You Sure You Want To Continue? (yes/no)"
		echo "To Ignore This Error In Future Use; \"sh $0 banmalware -f\""
		read continue
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
			echo "For Automated IP Whitelisting Use; \"sh $0 whitelist IP\""
			echo "For Automated Domain Whitelisting Use; \"sh $0 whitelist domain URL\""
			echo "Input IP To Whitelist"
			read whitelistip
			logger -st Skynet "[Adding $whitelistip To Whitelist] ... ... ..."
			ipset -A Whitelist $whitelistip
		elif [ -n "$2" ] && [ "$2" != "domain" ]; then
			logger -st Skynet "[Adding $2 To Whitelist] ... ... ..."
			ipset -A Whitelist $2
		elif [ "$2" = "domain" ] && [ -z "$3" ];then
			echo "Input Domain To Whitelist"
			read whitelistdomain
			logger -st Skynet "[Adding $whitelistdomain To Whitelist] ... ... ..."
			for ip in $(Domain_Lookup $whitelistdomain)
				do
				ipset -A Whitelist $ip
			done
		elif [ "$2" = "domain" ] && [ -n "$3" ]; then
		logger -st Skynet "[Adding $3 To Whitelist] ... ... ..."
		for ip in $(Domain_Lookup $3)
			do
			ipset -A Whitelist $ip
		done
		else
			echo "Command Not Recognised, Please Try Again"
			exit
		fi
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
			set1=$3
			set2=$4
		else
			echo "To Automate Importing Use; \"sh $0 import URL/local OLDSET NEWSET\""
			echo "Input Old Set Name"
			read set1
			echo "Input Set To Merge Into"
			read set2
		fi
		sed -i "s/$set1/$set2/g" /tmp/ipset2.txt
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
		localver="$(cat $0 | grep -oE 'v[0-9]{1,2}([.][0-9]{1,2})([.][0-9]{1,2})')"
		remotever="$(wget -q -O - https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh | grep -oE 'v[0-9]{1,2}([.][0-9]{1,2})([.][0-9]{1,2})')"
		if [ "$localver" = "$remotever" ] && [ "$2" != "-f" ]; then
			echo "To Use Only Check For Update Use; \"sh $0 update check\""
			echo "To Force Update Use; \"sh $0 update -f\""
			logger -st Skynet "[Firewall Up To Date - $localver]"
			exit
		elif [ "$localver" != "$remotever" ] && [ "$2" = "check" ]; then
			logger -st Skynet "[Firewall Update Detected - $remotever]"
			exit
		elif [ "$2" = "-f" ]; then
			logger -st Skynet "[Forcing Update]"
		fi
		if [ "$localver" != "$remotever" ] || [ "$2" = "-f" ]; then
			logger -st Skynet "[New Version Detected - Updating To $remotever]... ... ..."
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
		ipset -q -A Whitelist 151.101.96.133/32   # raw.githubusercontent.com Update Server
		Unload_IPTables
		Load_IPTables
		sed -i '/DROP IN=/d' /tmp/syslog.log
		;;
		
	*)
        echo "Command Not Recognised, Please Try Again"
		echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
		;;

esac

Logging
