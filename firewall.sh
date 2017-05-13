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
## - 14/05/2017 -		   Asus Firewall Addition By Adamm v3.8.6				    #
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
#	  "stats"	     # <-- Print/Search Stats Of Recently Banned IPs (Requires debugging enabled)
##############################

start_time=$(date +%s)
cat $0 | head -36

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

Unload_DebugIPTables () {
		iptables -t raw -D PREROUTING -m set --match-set Blacklist src -j LOG --log-prefix "[BLOCKED - RAW] " --log-tcp-sequence --log-tcp-options --log-ip-options &>-
		iptables -D logdrop -m state --state NEW -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options &>-
		iptables -D logdrop -m set --match-set Whitelist src -j ACCEPT &>-
}

Unload_IPTables () {
		iptables -D logdrop -m state --state NEW -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options &>-
		iptables -t raw -D PREROUTING -m set --match-set Blacklist src -j DROP &>-
		iptables -t raw -D PREROUTING -m set --match-set BlockedRanges src -j DROP &>-
		iptables -t raw -D PREROUTING -m set --match-set Whitelist src -j ACCEPT &>-
		iptables -D logdrop -m state --state NEW -j SET --add-set Blacklist src &>-
}

Load_IPTables () {
		iptables -t raw -I PREROUTING -m set --match-set Blacklist src -j DROP &>-
		iptables -t raw -I PREROUTING -m set --match-set BlockedRanges src -j DROP &>-
		iptables -t raw -I PREROUTING -m set --match-set Whitelist src -j ACCEPT &>-
		if [ "$1" = "noautoban" ]; then
			echo "No Autoban Specified"
		else
			iptables -I logdrop -m state --state NEW -j SET --add-set Blacklist src &>-
		fi
}

Logging () {
		OLDIPS=$(nvram get Blacklist)
		OLDRANGES=$(nvram get BlockedRanges)
		nvram set Blacklist=$(expr $(ipset -L Blacklist | wc -l) - 7)
		nvram set BlockedRanges=$(expr $(ipset -L BlockedRanges | wc -l) - 7)
		NEWIPS=$(nvram get Blacklist)
		NEWRANGES=$(nvram get BlockedRanges)
		nvram commit
		HITS1=$(iptables -vL -nt raw | grep -v LOG | grep "Blacklist src" | awk '{print $1}')
		HITS2=$(iptables -vL -nt raw | grep "BlockedRanges src" | awk '{print $1}')
		start_time=$(expr $(date +%s) - $start_time)
		logger -st Skynet "[Complete] $NEWIPS IPs / $NEWRANGES Ranges banned. $(expr $NEWIPS - $OLDIPS) New IPs / $(expr $NEWRANGES - $OLDRANGES) New Ranges Banned. $HITS1 IP / $HITS2 Range Connections Blocked! [$(echo $start_time)s]"
}

Domain_Lookup () {
		echo "$(nslookup $1 | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | awk 'NR>2')"
}

Filter_Version () {
		grep -oE 'v[0-9]{1,2}([.][0-9]{1,2})([.][0-9]{1,2})'
}

Filter_Date () {
		grep -oE '[0-9]{1,2}([/][0-9]{1,2})([/][0-9]{1,4})'
}

Filter_PrivateIP () {
		echo '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)'
}

Unban_PrivateIP () {
		for ip in $(ipset -L Blacklist | grep -E $(Filter_PrivateIP))
			do
			ipset -D Blacklist $ip
			sed -i /$ip/d /jffs/skynet.log
		done
		
		for ip in $(ipset -L BlockedRanges | grep -E $(Filter_PrivateIP))
			do
			ipset -D BlockedRanges $ip
			sed -i /$ip/d /jffs/skynet.log
		done
}

Purge_Logs () {
		find /jffs/skynet.log -mtime +7 -type f -delete &>-
		cat /tmp/syslog.log-1 | sed '/BLOCKED -/!d' >> /jffs/skynet.log
		sed -i '/BLOCKED -/d' /tmp/syslog.log-1
		cat /tmp/syslog.log | sed '/BLOCKED -/!d' >> /jffs/skynet.log
		sed -i '/BLOCKED -/d' /tmp/syslog.log
		sed -i '/Aug  1 1/d' /jffs/skynet.log
		}
		
Unban_HTTP () {
		for ip in $(grep -E 'SPT=80 |SPT=443 ' /jffs/skynet.log | grep NEW | grep -oE 'SRC=[0-9,\.]* ' | grep -oE '[0-9,\.]* ')
			do
			ipset -D Blacklist $ip
			logger -st Skynet "[Removing $ip From Blacklist (false positive detected)]"
			sed -i /$ip/d /jffs/skynet.log
		done
		}


############################################################################################################
# -   unban  / save / ban / banmalware / whitelist / import / disable / debug / update / start / stats   - #
############################################################################################################


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
			sed -i /$unbanip/d /jffs/skynet.log
		elif [ -n "$2" ] && [ "$2" != "domain" ]&& [ "$2" != "range" ] && [ "$2" != "all" ]; then
			logger -st Skynet "[Removing $2 From Blacklist] ... ... ..."
			ipset -D Blacklist $2
			sed -i /$2/d /jffs/skynet.log
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
				sed -i /$ip/d /jffs/skynet.log
			done
		elif [ "$2" = "domain" ] && [ -n "$3" ]; then
		logger -st Skynet "[Removing $3 From Blacklist] ... ... ..."
		for ip in $(Domain_Lookup $3)
			do
			ipset -D Blacklist $ip
			sed -i /$ip/d /jffs/skynet.log
		done
		elif [ "$2" = "all" ]; then
			nvram set Blacklist=$(expr $(ipset -L Blacklist | wc -l) - 6)
			logger -st Skynet "[Removing All $(nvram get Blacklist) Entries From Blacklist] ... ... ..."
			ipset --flush Blacklist
			ipset --flush BlockedRanges
			Purge_Logs
			rm -rf /jffs/skynet.log
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
		Unban_HTTP
		ipset --save > /jffs/scripts/ipset.txt
		sed -i '/USER admin pid .*firewall/d' /tmp/syslog.log
		;;

	ban)
		if [ -z "$2" ]; then
			echo "For Automated IP Banning Use; \"sh $0 ban IP\""
			echo "For Automated IP Range Banning Use; \"sh $0 ban range IP\""
			echo "For Automated Domain Banning Use; \"sh $0 ban domain URL\""
			echo "For Automated Country Banning Use; \"sh $0 ban country zone\""
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
			for country in $3
			do
				wget -q -O - http://www.ipdeny.com/ipblocks/data/countries/$country.zone >> /tmp/countrylist.txt
			done
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
		grep -vE $(Filter_PrivateIP) /tmp/malwarelist.txt | sed -n "s/\r//;/^$/d;/^[0-9,\.]*$/s/^/add Blacklist /p" | sort -u > /tmp/malwarelist1.txt
		echo "Filtering IPv4 Ranges"
		grep -vE $(Filter_PrivateIP) /tmp/malwarelist.txt | sed -n "s/\r//;/^$/d;/^[0-9,\.,\/]*$/s/^/add BlockedRanges /p" | grep "/" | sort -u >> /tmp/malwarelist1.txt
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
			ipset -D Blacklist $whitelistip
			sed -i /$whitelistip/d /jffs/skynet.log
		elif [ -n "$2" ] && [ "$2" != "domain" ]; then
			logger -st Skynet "[Adding $2 To Whitelist] ... ... ..."
			ipset -A Whitelist $2
			ipset -D Blacklist $2
			sed -i /$2/d /jffs/skynet.log
		elif [ "$2" = "domain" ] && [ -z "$3" ];then
			echo "Input Domain To Whitelist"
			read whitelistdomain
			logger -st Skynet "[Adding $whitelistdomain To Whitelist] ... ... ..."
			for ip in $(Domain_Lookup $whitelistdomain)
				do
				ipset -A Whitelist $ip
				ipset -D Blacklist $ip
				sed -i /$ip/d /jffs/skynet.log
			done
		elif [ "$2" = "domain" ] && [ -n "$3" ]; then
		logger -st Skynet "[Adding $3 To Whitelist] ... ... ..."
		for ip in $(Domain_Lookup $3)
			do
			ipset -A Whitelist $ip
			ipset -D Blacklist $ip
			sed -i /$ip/d /jffs/skynet.log
		done
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
			wget -q --no-check-certificate -O /jffs/scripts/ipset2.txt http://www.abuseat.org/iotcc.txt
		else
			echo "To Download A Custom List Use; \"sh $0 import URL\""
			echo "Defaulting Blacklist Location To /tmp/ipset2.txt"
		fi
		if [ ! -f /jffs/scripts/ipset2.txt ]; then
			echo "No IPSet Backup Detected - Exiting"
			exit
		fi
		echo "Stripping Old List Data"
		echo "Filtering IPv4 Addresses"
		grep -v "create" /jffs/scripts/ipset2.txt |  awk '{print $3}' | grep -vE $(Filter_PrivateIP) | sed -n "s/\r//;/^$/d;/^[0-9,\.]*$/s/^/add Blacklist /p" > /jffs/scripts/ipset3.txt
		echo "Filtering IPv4 Ranges"
		grep -v "create" /jffs/scripts/ipset2.txt |  awk '{print $3}' | grep -vE $(Filter_PrivateIP) | sed -n "s/\r//;/^$/d;/^[0-9,\.,\/]*$/s/^/add BlockedRanges /p" | grep "/" >> /jffs/scripts/ipset3.txt
		echo "Importing IPs To Blacklist"
		ipset -q -R -! < /tmp/ipset3.txt
		rm -rf /tmp/ipset3.txt
		;;

	disable)
		logger -st Skynet "[Disabling Skynet] ... ... ..."
		Unload_IPTables
		Unload_DebugIPTables
		Purge_Logs
		Unban_HTTP
	;;

	debug)
		case $2 in
			enable)
				Unload_DebugIPTables
				if [ "$3" = "newbans" ]; then
					logger -st Skynet "[Enabling New Ban Debug Output] ... ... ..."
					iptables -I logdrop -m state --state NEW -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options &>-
					iptables -I logdrop -m set --match-set Whitelist src -j ACCEPT &>-
				elif [ "$3" = "blocked" ]; then
					logger -st Skynet "[Enabling Blocked Packet Debug Output] ... ... ..."
					iptables -t raw -I PREROUTING 2 -m set --match-set Blacklist src -j LOG --log-prefix "[BLOCKED - RAW] " --log-tcp-sequence --log-tcp-options --log-ip-options &>-
				else
					logger -st Skynet "[Enabling All Debug Output] ... ... ..."
					iptables -t raw -I PREROUTING 2 -m set --match-set Blacklist src -j LOG --log-prefix "[BLOCKED - RAW] " --log-tcp-sequence --log-tcp-options --log-ip-options &>-
					iptables -I logdrop -m state --state NEW -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options &>-
					iptables -I logdrop -m set --match-set Whitelist src -j ACCEPT &>-
				fi
			;;
			disable)
				logger -st Skynet "[Disabling All Debug Output] ... ... ..."
				Unload_DebugIPTables
				Purge_Logs
				Unban_HTTP
			;;
			filter)
				echo "Unbanning Private IP's"
				Unban_PrivateIP
			;;
			info)
				RED='\033[0;31m'
				GRN='\033[0;32m'
				NC='\033[0m'
				echo "Router Model: $(uname -n)"
				echo "Skynet Version: $(cat $0 | Filter_Version) ($(cat $0 | Filter_Date))"
				iptables --version
				ipset -v
				echo "FW Version: $(nvram get buildno)_$(nvram get extendno)"
				grep "firewall start" /jffs/scripts/firewall-start &>- && echo -e $GRN"Startup Entry Detected"$NC || echo -e $GRN"Startup Entry Not Detected"$NC
				cru l | grep firewall &>- && echo -e $GRN"Cronjob Detected"$NC || echo -e $GRN"Cronjob Not Detected"$NC
				iptables -L | grep LOG | grep BAN &>- && echo -e $GRN"Autobanning Enabled"$NC || echo -e $RED"Autobanning Disabled"$NC
				iptables -vL -nt raw | grep Whitelist &>- && echo -e $GRN"Whitelist IPTable Detected"$NC || echo -e $RED"Whitelist IPTable Not Detected"$NC
				iptables -vL -nt raw | grep BlockedRanges &>- && echo -e $GRN"BlockedRanges IPTable Detected"$NC || echo -e $RED"BlockedRanges IPTable Not Detected"$NC
				iptables -vL -nt raw | grep Blacklist &>- && echo -e $GRN"Blacklist IPTable Detected"$NC || echo -e $RED"Blacklist IPTable Not Detected"$NC
				ipset -L Whitelist &>- && echo -e $GRN"Whitelist IPSet Detected"$NC || echo -e $RED"Whitelist IPSet Not Detected"$NC
				ipset -L BlockedRanges &>- && echo -e $GRN"BlockedRanges IPSet Detected"$NC || echo -e $RED"BlockedRanges IPSet Not Detected"$NC
				ipset -L Blacklist &>- && echo -e $GRN"Blacklist IPSet Detected"$NC || echo -e $RED"Blacklist IPSet Not Detected"$NC
			;;
			
		*)
			echo "Error - Use Syntax './jffs/scripts/firewall debug (enable/disable/filter/info)'"
		esac
		;;

	update)
		localver="$(cat $0 | Filter_Version)"
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
			wget -q --no-check-certificate -O $0 https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh && logger -st Skynet "[Skynet Sucessfully Updated]"
			exit
		fi
		;;

	start)
		Check_Settings
		sed -i '/IP Banning Started/d' /tmp/syslog.log
		logger -st Skynet "[IP Banning Started] ... ... ..."
		insmod xt_set &>-
		ipset -q -R  < /jffs/scripts/ipset.txt
		Unban_PrivateIP
		ipset -q -N Whitelist nethash
		ipset -q -N Blacklist iphash --maxelem 500000
		ipset -q -N BlockedRanges nethash
		ipset -q -A Whitelist 192.168.1.0/24
		ipset -q -A Whitelist $(nvram get lan_ipaddr)/24
		ipset -q -A Whitelist 151.101.96.133/32   # raw.githubusercontent.com Update Server
		Unload_IPTables
		Unload_DebugIPTables
		Load_IPTables $2
		sed -i '/DROP IN=/d' /tmp/syslog.log
		;;
	
	stats)
		Filter_DST () {
			echo '(DST=127\.)|(DST=10\.)|(DST=172\.1[6-9]\.)|(DST=172\.2[0-9]\.)|(DST=172\.3[0-1]\.)|(DST=192\.168\.)|(DST=0.)|(DST=169\.254\.)'
		}
		Purge_Logs
		Unban_HTTP
		if [ -f /jffs/skynet.log ] && [ "$(wc -l /jffs/skynet.log | awk '{print $1}')" != "0" ]; then
			echo "Debug Data Detected in /jffs/skynet.log - $(ls -lh /jffs/skynet.log | awk '{print $5}')"
		else
			echo "No Debug Data Detected - Make Sure Debug Mode Is Enabled To Compile Stats"
			exit
		fi
		if [ "$2" = "reset" ]; then
			rm -rf /jffs/skynet.log
			echo "Stat Data Reset"
			exit
		fi
		echo "Monitoring From $(awk '{print $1" "$2" "$3}' /jffs/skynet.log | head -1) To $(awk '{print $1" "$2" "$3}' /jffs/skynet.log | tail -1)"
		echo "$(grep -vE 'SPT=80 |SPT=443 ' /jffs/skynet.log | grep -oE 'SRC=[0-9,\.]* ' | cut -c 5- | grep -vE $(Filter_PrivateIP) | wc -l) Connections Detected"
		echo "$(grep -vE 'SPT=80 |SPT=443 ' /jffs/skynet.log | grep "NEW BAN"| wc -l) Autobans Issued"
		echo
		counter=10
		if [ -n "$2" ] && [ "$2" != "search" ] && [ -z "$3" ]; then
			counter=$2
		elif [ -n "$5" ]; then
			counter=$5
		fi
		if [ "$2" = "search" ] && [ "$3" = "port" ]; then
			echo "Port $4 First Tracked On $(grep "DPT=$4 " /jffs/skynet.log | head -1 | awk '{print $1" "$2" "$3}')"
			echo "Port $4 Last Tracked On $(grep "DPT=$4 " /jffs/skynet.log | tail -1 | awk '{print $1" "$2" "$3}')"
			echo "$(grep "DPT=$4 " /jffs/skynet.log | wc -l) Attempts Total"
			echo
			echo "First Attack Tracked On Port $4;"
			grep "DPT=$4 " /jffs/skynet.log | head -1
			echo
			echo "$counter Most Recent Attacks On Port $4;";
			grep "DPT=$4 " /jffs/skynet.log | tail -$counter
			exit
		elif [ "$2" = "search" ] && [ "$3" = "ip" ]; then
			if [ -n "$(ipset -L Blacklist | grep $4)" ]; then
				echo "IP Is Still Banned"
			else
				echo "IP Is No Longer Banned"
			fi
			echo "$4 First Tracked On $(grep "SRC=$4 " /jffs/skynet.log | head -1 | awk '{print $1" "$2" "$3}')"
			echo "$4 Last Tracked On $(grep "SRC=$4 " /jffs/skynet.log | tail -1 | awk '{print $1" "$2" "$3}')"
			echo "$(grep "SRC=$4 " /jffs/skynet.log | wc -l) Attempts Total"
			echo
			echo "First Attack Tracked From $4;"
			grep "SRC=$4 " /jffs/skynet.log | head -1
			echo
			echo "$counter Most Recent Attacks From $4;"
			grep "SRC=$4 " /jffs/skynet.log | tail -$counter
			exit
		fi
		echo "Top $counter Ports Attacked;"
		grep -vE 'SPT=80 |SPT=443 ' /jffs/skynet.log | grep -vE $(Filter_DST) | grep -oE 'DPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -$counter | awk '{print $1"x http://www.speedguide.net/port.php?port="$2}'
		echo
		echo "Top $counter Attacker Source Ports;"
		grep -vE 'SPT=80 |SPT=443 ' /jffs/skynet.log | grep -vE $(Filter_DST) | grep -oE 'SPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -$counter | awk '{print $1"x http://www.speedguide.net/port.php?port="$2}'
		echo
		echo "Last $counter Connections Blocked;"
		grep -vE 'SPT=80 |SPT=443 ' /jffs/skynet.log | grep -oE 'SRC=[0-9,\.]* ' | cut -c 5- | grep -vE $(Filter_PrivateIP) | tail -$counter | sed '1!G;h;$!d' | awk '{print "https://www.abuseipdb.com/check/"$1}'
		echo
		echo "Last $counter New Bans;"
		grep -vE 'SPT=80 |SPT=443 ' /jffs/skynet.log | grep "NEW BAN" | grep -oE 'SRC=[0-9,\.]* ' | cut -c 5- | grep -vE $(Filter_PrivateIP) | tail -$counter | sed '1!G;h;$!d' | awk '{print "https://www.abuseipdb.com/check/"$1}'
		echo
		echo "Top $counter HTTP(s) Blocks;"
		grep -E 'SPT=80 |SPT=443 ' /jffs/skynet.log | grep -oE 'SRC=[0-9,\.]* ' | cut -c 5- | grep -vE $(Filter_PrivateIP) | sort -n | uniq -c | sort -nr | head -$counter | awk '{print $1"x https://www.abuseipdb.com/check/"$2}'
		echo
		echo "Top $counter Attackers;"
		grep -vE 'SPT=80 |SPT=443 ' /jffs/skynet.log | grep -oE 'SRC=[0-9,\.]* ' | cut -c 5- | grep -vE $(Filter_PrivateIP) | sort -n | uniq -c | sort -nr | head -$counter | awk '{print $1"x https://www.abuseipdb.com/check/"$2}'
		echo
		;;
		
	*)
        echo "Command Not Recognised, Please Try Again"
		echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
		;;

esac

Logging
