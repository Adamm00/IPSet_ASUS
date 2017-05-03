#!/bin/sh
#################################################################################################
## - 04/05/2017 ---		RT-AC56U/RT-AC68U Firewall Addition By Adamm v3.1.1 -  					#
###################################################################################################################
###			       ----- Make Sure To Edit The Following Files -----				  #
### /jffs/scripts/firewall-start			         <-- Sets up cronjob/iptables rules		  #
### /jffs/scripts/firewall					 <-- Blacklists IP's From /jffs/scripts/ipset.txt #
### /jffs/scripts/ipset.txt					 <-- Banned IP List/IPSet Rules			  #
###################################################################################################################

##############################
###		  Commands		   ###
##############################
UNBANSINGLE="unban"          # <-- Remove Single IP From Blacklist
REMOVEBANS="removeall"       # <-- Remove All Entries From Blacklist
SAVEIPSET="save"             # <-- Save Blacklists to /jffs/scripts/ipset.txt
BANSINGLE="ban"              # <-- Adds Entry To Blacklist
BANCOUNTRYSINGLE="country"   # <-- Adds entire country to blacklist
BANCOUNTRYLIST="bancountry"  # <-- Bans specified countries in this file
BANMALWARE="banmalware"      # <-- Bans various malware domains
WHITELIST="whitelist"        # <-- Add IPs from path to Whitelist
NEWLIST="new"			     # <-- Create new IPSet Blacklist
DISABLE="disable"			 # <-- Disable Firewall
##############################

start_time=`date +%s`
cat /jffs/scripts/firewall | head -25

#####################################################################################################################################
# -           Unban / Unbanall / Removeall / Save / Ban / Country / Bancountry / Banmalware / New / Whitelist					  - #
#####################################################################################################################################

if [ X"$@" = X"$UNBANSINGLE" ]
then
	echo "Input IP Address To Unban"
	read unbannedip
	logger -t Firewall "[Unbanning And Removing $unbannedip From Blacklist] ... ... ..."
	ipset  -D Blacklist $unbannedip
	echo "`sed /$unbannedip/d /jffs/scripts/ipset.txt`" > /jffs/scripts/ipset.txt
	echo "$unbannedip Is Now Unbanned"

elif [ X"$@" = X"$REMOVEBANS" ]
then
	nvram set Blacklist=`expr \`ipset -L Blacklist | wc -l\` - 6`
	echo "[Deleting All `echo \`nvram get Blacklist\`` Entries From Blacklist] ... ... ..."
	logger -t Firewall "[Deleting All `echo \`nvram get Blacklist\`` Entries From Blacklist] ... ... ..."
	ipset --flush Blacklist
	ipset --flush BlockedCountries
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
	ipset -q -A Blacklist $bannedip
	echo "$bannedip Is Now Banned"

elif [ X"$@" = X"$BANCOUNTRYSINGLE" ]
then
	echo "Input Country Abbreviation"
	read country
	for IP in $(wget -q -O - http://www.ipdeny.com/ipblocks/data/countries/$country.zone)
	do
	ipset -q -A BlockedCountries $IP
	done

elif [ X"$@" = X"$BANCOUNTRYLIST" ]
then
	echo "[Banning Spam Countries] ... ... ..."
	for country in pk cn in jp ru sa
	do
        for IP in $(wget -q -O - http://www.ipdeny.com/ipblocks/data/countries/$country.zone)
       	do
    	ipset -q -A BlockedCountries $IP
	done
	done

elif [ X"$@" = X"$BANMALWARE" ]
then
	echo "Banning Known Malware IP (ETA 3mins)"
	echo `wget -qO- https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt` >> /tmp/malwarelist.txt
	echo `wget -qO- https://zeustracker.abuse.ch/blocklist.php?download=badips` >> /tmp/malwarelist.txt
	echo `wget -qO- https://feodotracker.abuse.ch/blocklist/?download=ipblocklist` >> /tmp/malwarelist.txt
	echo `wget -qO- http://www.malwaredomainlist.com/hostslist/ip.txt` >> /tmp/malwarelist.txt
	echo `wget -qO- http://cinsscore.com/list/ci-badguys.txt` >> /tmp/malwarelist.txt
	echo `wget -qO- http://sanyalnet-cloud-vps.freeddns.org/mirai-ips.txt` >> /tmp/malwarelist.txt
	echo `wget -qO- https://lists.blocklist.de/lists/all.txt` >> /tmp/malwarelist.txt
	for IP in `cat /tmp/malwarelist.txt`
	do
	ipset -q -A Blacklist $IP
	done
	rm -rf /tmp/malwarelist.txt

elif [ X"$@" = X"$WHITELIST" ]
then
	echo "Input file location"
	read WHITELISTFILE
	for IP in `cat $WHITELISTFILE`
	do
	ipset -q -A Whitelist $IP
	echo $IP
	done
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
	echo "Disabling Firewall"
	logger -t Firewall "[Disabling Firewall] "
	iptables -D INPUT -m set --match-set Whitelist src -j ACCEPT
	iptables -D INPUT -m set --match-set Blacklist src -j DROP
	iptables -D INPUT -m set --match-set BlockedCountries src -j DROP
	iptables -D FORWARD -m set --match-set Blacklist src,dst -j DROP
	iptables -D FORWARD -m set --match-set BlockedCountries src,dst -j DROP
	iptables -D FORWARD -m set --match-set Whitelist src,dst -j ACCEPT
	iptables -D logdrop -m state --state NEW -j SET --add-set Blacklist src	
	
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
			echo "Correct Settings Detected"
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
	ipset -q -N BlockedCountries nethash
	iptables -D logdrop -m state --state NEW -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options  > /dev/null 2>&1
	iptables -D INPUT -m set --match-set Whitelist src -j ACCEPT
	iptables -D INPUT -m set --match-set Blacklist src -j DROP
	iptables -D INPUT -m set --match-set BlockedCountries src -j DROP
	iptables -D FORWARD -m set --match-set Blacklist src,dst -j DROP
	iptables -D FORWARD -m set --match-set BlockedCountries src,dst -j DROP
	iptables -D FORWARD -m set --match-set Whitelist src,dst -j ACCEPT
	iptables -D logdrop -m state --state NEW -j SET --add-set Blacklist src	
	iptables -I INPUT -m set --match-set Blacklist src -j DROP
	iptables -I INPUT -m set --match-set BlockedCountries src -j DROP
	iptables -I INPUT -m set --match-set Whitelist src -j ACCEPT
	iptables -I FORWARD -m set --match-set Blacklist src,dst -j DROP
	iptables -I FORWARD -m set --match-set BlockedCountries src,dst -j DROP
	iptables -I FORWARD -m set --match-set Whitelist src,dst -j ACCEPT
	iptables -I logdrop -m state --state NEW -j SET --add-set Blacklist src
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
start_time=$(expr `date +%s` - $start_time)
echo "[Complete] $NEWAMOUNT IPs currently banned. `expr $NEWAMOUNT - $OLDAMOUNT` New IP's Banned. [`echo $start_time`s]"
logger -t Firewall "[Complete] $NEWAMOUNT IPs currently banned. `expr $NEWAMOUNT - $OLDAMOUNT` New IP's Banned. [`echo $start_time`s]"
