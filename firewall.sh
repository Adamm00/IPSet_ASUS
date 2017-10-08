#!/bin/sh
#############################################################################################################
#			        _____ _                     _           _____ 				    #
#			       / ____| |                   | |         | ____|				    #
#			      | (___ | | ___   _ _ __   ___| |_  __   _| |__  				    #
#			       \___ \| |/ / | | | '_ \ / _ \ __| \ \ / /___ \ 				    #
#			       ____) |   <| |_| | | | |  __/ |_   \ V / ___) |				    #
#			      |_____/|_|\_\\__, |_| |_|\___|\__|   \_/ |____/ 				    #
#			                    __/ |                             				    #
#			                   |___/                              				    #
#													    #
## - 09/10/2017 -		   Asus Firewall Addition By Adamm v5.2.4				    #
##				   https://github.com/Adamm00/IPSet_ASUS				    #
#############################################################################################################


##############################
###	  Commands	   ###
##############################
#	  "unban"	     # <-- Remove From Blacklist (IP/Range/Domain/Port/Comment/Country/Malware/Autobans/Nomanual/All)
#	  "ban"		     # <-- Adds Entry To Blacklist (IP/Range/Domain/Port/Country)
#	  "banmalware"	     # <-- Bans Various Malware Domains
#	  "whitelist"        # <-- Add Entry To Whitelist (IP/Range/Domain/Port/Remove/Refresh/List)
#	  "import"	     # <-- Bans All IPs From URL
#	  "deport"	     # <-- Unbans All IPs From URL
#	  "save"	     # <-- Save Blacklists To ipset.txt
#	  "disable"	     # <-- Disable Firewall
#	  "update"	     # <-- Update Script To Latest Version (check github for changes)
#	  "debug"	     # <-- Debug Features (Restart/Disable/Watch/Info)
#	  "stats"	     # <-- Show/Search Stats Of Banned IPs (Requires debugging enabled)
#	  "install"          # <-- Install Script (Or Change Boot Args)
#	  "uninstall"        # <-- Uninstall All Traces Of Skynet
##############################

head -34 "$0"
export LC_ALL=C
while [ "$(nvram get ntp_ready)" = "0" ]; do
	sleep 1
done
stime="$(date +%s)"

Check_Lock () {
		if [ -f "/tmp/skynet.lock" ] && [ -d "/proc/$(sed -n '2p' /tmp/skynet.lock)" ]; then
			logger -st Skynet "[INFO] Lock File Detected ($(sed -n '1p' /tmp/skynet.lock)) (pid=$(sed -n '2p' /tmp/skynet.lock)) - Exiting"
			exit 1
		else
			echo "$@" > /tmp/skynet.lock
			echo "$$" >> /tmp/skynet.lock
		fi
}

if grep -F "Skynet" /jffs/scripts/firewall-start 2>/dev/null | grep -qF "usb"; then
	location="$(grep -ow "usb=.*" /jffs/scripts/firewall-start | awk '{print $1}' | cut -c 5-)/skynet"
	if [ ! -d "$location" ]; then
		Check_Lock "$@"
		retry=1
		while [ ! -d "$location" ] && [ "$retry" -lt "11" ]; do
			logger -st Skynet "[INFO] USB Not Found - Sleeping For 10 Seconds ( Attempt $retry Of 10 )"
			retry=$((retry+1))
			sleep 10
		done
		if [ ! -d "$location" ] && ! echo "$@" | grep -wqE "(install|uninstall|disable|update|restart|info)"; then
			logger -st Skynet "[ERROR] USB Not Found After 10 Attempts - Please Fix Immediately!"
			logger -st Skynet "[ERROR] When Fixed Run ( sh $0 debug restart )"
			rm -rf /tmp/skynet.lock
			exit 1
		fi
		rm -rf /tmp/skynet.lock
	fi
else
	location="/jffs"
fi


if [ "$(nvram get wan0_proto)" = "pppoe" ] || [ "$(nvram get wan0_proto)" = "pptp" ] || [ "$(nvram get wan0_proto)" = "l2tp" ]; then
	iface="ppp0"
else
	iface="$(nvram get wan0_ifname)"
fi


Kill_Lock () {
		if [ -f "/tmp/skynet.lock" ] && [ -d "/proc/$(sed -n '2p' /tmp/skynet.lock)" ]; then
			logger -st Skynet "[INFO] Killing Locked Processes ($(sed -n '1p' /tmp/skynet.lock)) (pid=$(sed -n '2p' /tmp/skynet.lock))"
			logger -st Skynet "[INFO] $(ps | awk -v pid="$(sed -n '2p' /tmp/skynet.lock)" '$1 == pid')"
			kill "$(sed -n '2p' /tmp/skynet.lock)"
			rm -rf /tmp/skynet.lock
		fi
}

Check_Settings () {
		if ! grep -qF "Skynet" /jffs/scripts/firewall-start; then
			logger -st Skynet "[ERROR] Installation Not Detected - Please Use Install Command To Continue"
			rm -rf /tmp/skynet.lock
			exit 1
		fi

		conflicting_scripts="(IPSet_Block.sh|malware-filter|privacy-filter|ipBLOCKer.sh|ya-malware-block.sh|iblocklist-loader.sh|firewall-reinstate.sh)$"
		if /usr/bin/find /jffs /tmp/mnt | grep -qE "$conflicting_scripts"; then
			logger -st Skynet "[ERROR] $(/usr/bin/find /jffs /tmp/mnt | grep -E "$conflicting_scripts" | xargs) Detected - This Script Will Cause Conflicts! Please Uninstall It ASAP"
		fi

		if echo "$@" | grep -qF "banmalware "; then
			cru a Skynet_banmalware "25 2 * * * sh /jffs/scripts/firewall banmalware"
		elif echo "$@" | grep -qF "banmalwareweekly "; then
			cru a Skynet_banmalware "25 2 * * Mon sh /jffs/scripts/firewall banmalware"
		fi

		if echo "$@" | grep -qF "autoupdate"; then
			cru a Skynet_autoupdate "25 1 * * Mon sh /jffs/scripts/firewall update"
		else
			cru a Skynet_checkupdate "25 1 * * Mon sh /jffs/scripts/firewall update check"
		fi

		if [ -d "/opt/bin" ] && [ ! -f "/opt/bin/firewall" ]; then
			ln -s /jffs/scripts/firewall /opt/bin
		fi

		if [ "$(nvram get jffs2_scripts)" != "1" ]; then
			nvram set jffs2_scripts=1
			logger -st Skynet "[INFO] Custom JFFS Scripts Enabled - Please Manually Reboot To Apply Changes"
		fi

		if [ "$(nvram get fw_enable_x)" != "1" ]; then
			nvram set fw_enable_x=1
		fi

		if [ "$(nvram get fw_log_x)" != "drop" ] && [ "$(nvram get fw_log_x)" != "both" ]; then
			nvram set fw_log_x=drop
		fi
}

Unload_IPTables () {
		iptables -D logdrop -m state --state NEW -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
		ip6tables -D logdrop -m state --state NEW -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
		iptables -t raw -D PREROUTING -i "$iface" -m set --match-set Skynet src -j DROP >/dev/null 2>&1
		iptables -t raw -D PREROUTING -i "$iface" -m set --match-set Whitelist src -j ACCEPT >/dev/null 2>&1
		iptables -t raw -D PREROUTING -i br0 -m set --match-set Skynet dst -j DROP >/dev/null 2>&1
		iptables -t raw -D PREROUTING -i br0 -m set --match-set Whitelist dst -j ACCEPT >/dev/null 2>&1
		iptables -D logdrop -i "$iface" -m state --state INVALID -j SET --add-set Skynet src >/dev/null 2>&1
		iptables -D logdrop -i "$iface" -m state --state INVALID -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
		iptables -D logdrop -i "$iface" -p tcp -m multiport --sports 80,443,143,993,110,995,25,465 -m state --state INVALID -j DROP >/dev/null 2>&1
		iptables -D logdrop -i "$iface" -m set --match-set Whitelist src -j ACCEPT >/dev/null 2>&1
		iptables -D logdrop -p tcp --tcp-flags ALL RST,ACK -j ACCEPT >/dev/null 2>&1
		iptables -D logdrop -p tcp --tcp-flags ALL RST -j ACCEPT >/dev/null 2>&1
		iptables -D logdrop -p tcp --tcp-flags ALL FIN,ACK -j ACCEPT >/dev/null 2>&1
		iptables -D logdrop -p tcp --tcp-flags ALL ACK,PSH,FIN -j ACCEPT >/dev/null 2>&1
		iptables -D logdrop -p icmp --icmp-type 3 -j ACCEPT >/dev/null 2>&1
		iptables -D logdrop -p icmp --icmp-type 11 -j ACCEPT >/dev/null 2>&1
		iptables -D SSHBFP -m recent --update --seconds 60 --hitcount 4 --name SSH --rsource -j SET --add-set Blacklist src >/dev/null 2>&1
		iptables -D SSHBFP -m recent --update --seconds 60 --hitcount 4 --name SSH --rsource -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
}

Load_IPTables () {
		iptables -t raw -I PREROUTING -i "$iface" -m set --match-set Skynet src -j DROP >/dev/null 2>&1
		iptables -t raw -I PREROUTING -i "$iface" -m set --match-set Whitelist src -j ACCEPT >/dev/null 2>&1
		iptables -t raw -I PREROUTING -i br0 -m set --match-set Skynet dst -j DROP >/dev/null 2>&1
		iptables -t raw -I PREROUTING -i br0 -m set --match-set Whitelist dst -j ACCEPT >/dev/null 2>&1
		if echo "$@" | grep -qF "noautoban"; then
			logger -st Skynet "[INFO] Enabling No-Autoban Mode..."
		else
			iptables -I logdrop -i "$iface" -m state --state INVALID -j SET --add-set Skynet src >/dev/null 2>&1
			iptables -I logdrop -i "$iface" -m state --state INVALID -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
			iptables -I logdrop -p tcp --tcp-flags ALL RST,ACK -j ACCEPT >/dev/null 2>&1
			iptables -I logdrop -p tcp --tcp-flags ALL RST -j ACCEPT >/dev/null 2>&1
			iptables -I logdrop -p tcp --tcp-flags ALL FIN,ACK -j ACCEPT >/dev/null 2>&1
			iptables -I logdrop -p tcp --tcp-flags ALL ACK,PSH,FIN -j ACCEPT >/dev/null 2>&1
			iptables -I logdrop -p icmp --icmp-type 3 -j ACCEPT >/dev/null 2>&1
			iptables -I logdrop -p icmp --icmp-type 11 -j ACCEPT >/dev/null 2>&1
			iptables -I logdrop -i "$iface" -p tcp -m multiport --sports 80,443,143,993,110,995,25,465 -m state --state INVALID -j DROP >/dev/null 2>&1
			iptables -I logdrop -i "$iface" -m set --match-set Whitelist src -j ACCEPT >/dev/null 2>&1
		fi
		if [ "$(nvram get sshd_enable)" = "1" ] && [ "$(nvram get sshd_bfp)" = "1" ]; then
			pos3="$(iptables --line -nL SSHBFP | grep -F "seconds: 60 hit_count: 4" | grep -F "logdrop" | awk '{print $1}')"
			iptables -I SSHBFP "$pos3" -m recent --update --seconds 60 --hitcount 4 --name SSH --rsource -j SET --add-set Skynet src >/dev/null 2>&1
			iptables -I SSHBFP "$pos3" -m recent --update --seconds 60 --hitcount 4 --name SSH --rsource -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
		fi
}

Unload_DebugIPTables () {
		iptables -t raw -D PREROUTING -i "$iface" -m set --match-set Skynet src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
		iptables -t raw -D PREROUTING -i br0 -m set --match-set Skynet dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
}

Load_DebugIPTables () {
		if echo "$@" | grep -qF "debug"; then
			pos1="$(iptables --line -nL PREROUTING -t raw | grep -F "Skynet src" | grep -F "DROP" | awk '{print $1}')"
			iptables -t raw -I PREROUTING "$pos1" -i "$iface" -m set --match-set Skynet src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
			pos2="$(iptables --line -nL PREROUTING -t raw | grep -F "Skynet dst" | grep -F "DROP" | awk '{print $1}')"
			iptables -t raw -I PREROUTING "$pos2" -i br0 -m set --match-set Skynet dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
		fi
}

Unload_IPSets () {
		ipset -q destroy Skynet
		ipset -q destroy Blacklist
		ipset -q destroy BlockedRanges
		ipset -q destroy Whitelist
}

Unload_Cron () {
		cru d Skynet_save
		cru d Skynet_banmalware
		cru d Skynet_autoupdate
		cru d Skynet_checkupdate
}

Is_IP () {
		grep -wqE '([0-9]{1,3}\.){3}[0-9]{1,3}'
}

Domain_Lookup () {
		nslookup "$(echo "$1" | sed 's~http[s]*://~~;s~/.*~~')" | grep -woE '([0-9]{1,3}\.){3}[0-9]{1,3}' | awk 'NR>2'
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
		grep -vE '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)'
}

Filter_PrivateSRC () {
		grep -E '(SRC=127\.)|(SRC=10\.)|(SRC=172\.1[6-9]\.)|(SRC=172\.2[0-9]\.)|(SRC=172\.3[0-1]\.)|(SRC=192\.168\.)|(SRC=0.)|(SRC=169\.254\.)'
}

Filter_PrivateDST () {
		grep -E '(DST=127\.)|(DST=10\.)|(DST=172\.1[6-9]\.)|(DST=172\.2[0-9]\.)|(DST=172\.3[0-1]\.)|(DST=192\.168\.)|(DST=0.)|(DST=169\.254\.)'
}

Save_IPSets () {
		if ipset -q -n -L Whitelist >/dev/null 2>&1; then
			echo "Saving Changes"
			{ ipset save Whitelist; ipset save Blacklist; ipset save BlockedRanges; ipset save Skynet; } > "${location}/scripts/ipset.txt" 2>/dev/null
		fi
}

Unban_PrivateIP () {
		grep -F "INBOUND" /tmp/syslog.log | Filter_PrivateSRC | grep -oE 'SRC=[0-9,\.]* ' | cut -c 5- | while IFS= read -r ip; do
			ipset -q -A Whitelist "$ip" comment "PrivateIP"
			ipset -q -D Blacklist "$ip"
			sed -i "/SRC=${ip} /d" /tmp/syslog.log
		done
		grep -F "OUTBOUND" /tmp/syslog.log | Filter_PrivateDST | grep -oE 'DST=[0-9,\.]* ' | cut -c 5- | while IFS= read -r ip; do
			ipset -q -A Whitelist "$ip" comment "PrivateIP"
			ipset -q -D Blacklist "$ip"
			sed -i "/DST=${ip} /d" /tmp/syslog.log
		done
}

Whitelist_Extra () {
		{ sed '\~ManualWlistD: ~!d;s~.*ManualWlistD: ~~g;s~"~~g' "$location/scripts/ipset.txt"
		echo "ipdeny.com"
		echo "speedguide.net"
		echo "otx.alienvault.com"
		echo "raw.githubusercontent.com"
		echo "astrill.com"
		echo "strongpath.net"
		nvram get ntp_server0 
		nvram get ntp_server1 
		nvram get firmware_server; } | awk '!x[$0]++' > /jffs/shared-Skynet2-whitelist
}

Whitelist_Shared () {
		ipset -q -A Whitelist "$(nvram get wan0_ipaddr)"/32 comment "nvram: wan0_ipaddr"
		ipset -q -A Whitelist "$(nvram get lan_ipaddr)"/24 comment "nvram: lan_ipaddr"
		ipset -q -A Whitelist "$(nvram get wan_dns1_x)"/32 comment "nvram: wan_dns1_x"
		ipset -q -A Whitelist "$(nvram get wan_dns2_x)"/32 comment "nvram: wan_dns2_x"
		ipset -q -A Whitelist "$(nvram get wan0_dns1_x)"/32 comment "nvram: wan0_dns1_x"
		ipset -q -A Whitelist "$(nvram get wan0_dns2_x)"/32 comment "nvram: wan0_dns2_x"
		ipset -q -A Whitelist "$(nvram get wan_dns | awk '{print $1}')"/32 comment "nvram: wan_dns"
		ipset -q -A Whitelist "$(nvram get wan_dns | awk '{print $2}')"/32 comment "nvram: wan_dns"
		ipset -q -A Whitelist "$(nvram get wan0_xdns | awk '{print $1}')"/32 comment "nvram: wan0_xdns"
		ipset -q -A Whitelist "$(nvram get wan0_xdns | awk '{print $2}')"/32 comment "nvram: wan0_xdns"
		ipset -q -A Whitelist "$(nvram get vpn_server1_sn)"/24 comment "nvram: vpn_server1_sn"
		ipset -q -A Whitelist "$(nvram get vpn_server2_sn)"/24 comment "nvram: vpn_server2_sn"
		ipset -q -A Whitelist "$(nvram get vpn_server_sn)"/24 comment "nvram: vpn_server_sn"
		ipset -q -A Whitelist "$(nvram get vpn_client1_addr)"/24 comment "nvram: vpn_client1_addr"
		ipset -q -A Whitelist "$(nvram get vpn_client2_addr)"/24 comment "nvram: vpn_client2_addr"
		ipset -q -A Whitelist "$(nvram get vpn_client3_addr)"/24 comment "nvram: vpn_client3_addr"
		ipset -q -A Whitelist "$(nvram get vpn_client4_addr)"/24 comment "nvram: vpn_client4_addr"
		ipset -q -A Whitelist "$(nvram get vpn_client5_addr)"/24 comment "nvram: vpn_client5_addr"
		if [ -f "/dev/astrill/openvpn.conf" ]; then ipset -q -A Whitelist "$(sed '\~remote ~!d;s~remote ~~' "/dev/astrill/openvpn.conf")"/24 comment "nvram: Astrill_VPN"; fi
		ipset -q -A Whitelist 192.168.1.0/24 comment "nvram: LAN Subnet"
		if [ -n "$(/usr/bin/find /jffs -name 'shared-*-whitelist')" ]; then
			echo "Whitelisting Shared Domains"
			sed '\~add Whitelist ~!d;\~Shared-Whitelist~!d;s~ comment.*~~;s~add~del~g' "${location}/scripts/ipset.txt" | ipset restore -!
			grep -hvF "#" /jffs/shared-*-whitelist | sed 's~http[s]*://~~;s~/.*~~' | awk '!x[$0]++' | while IFS= read -r domain; do
				for ip in $(Domain_Lookup "$domain" 2> /dev/null); do
					ipset -q -A Whitelist "$ip" comment "Shared-Whitelist: $domain"
				done
			done
		fi
}

Purge_Logs () {
		sed '/BLOCKED -/!d' /tmp/syslog.log-1 >/dev/null 2>&1 >> "${location}/skynet.log"
		sed -i '/BLOCKED -/d' /tmp/syslog.log-1 >/dev/null 2>&1
		sed '/BLOCKED -/!d' /tmp/syslog.log >/dev/null 2>&1 >> "${location}/skynet.log"
		sed -i '/BLOCKED -/d' /tmp/syslog.log >/dev/null 2>&1
		if [ "$(du ${location}/skynet.log | awk '{print $1}')" -ge "7000" ]; then
			sed -i '/BLOCKED - .*BOUND/d' "${location}/skynet.log"
			if [ "$(du ${location}/skynet.log | awk '{print $1}')" -ge "3000" ]; then
				true > "${location}/skynet.log"
			fi
		fi
}

Logging () {
		oldips="$(sed -n '1p' /tmp/counter.txt 2> /dev/null)"
		oldranges="$(sed -n '2p' /tmp/counter.txt 2> /dev/null)"
		grep -Foc "add Black" "${location}/scripts/ipset.txt" 2> /dev/null > /tmp/counter.txt
		grep -Foc "add Block" "${location}/scripts/ipset.txt" 2> /dev/null >> /tmp/counter.txt
		newips="$(sed -n '1p' /tmp/counter.txt)"
		newranges="$(sed -n '2p' /tmp/counter.txt)"
		if iptables -t raw -C PREROUTING -i "$iface" -m set --match-set Skynet src -j DROP 2>/dev/null; then
			hits1="$(iptables -xnvL -t raw | grep -Fv "LOG" | grep -F "Skynet src" | awk '{print $1}')"
			hits2="$(iptables -xnvL -t raw | grep -Fv "LOG" | grep -F "Skynet dst" | awk '{print $1}')"
		fi
		ftime="$(($(date +%s) - stime))"
		logger -st Skynet "[Complete] $newips IPs / $newranges Ranges Banned. $((newips - oldips)) New IPs / $((newranges - oldranges)) New Ranges Banned. $hits1 Inbound / $hits2 Outbound Connections Blocked! [${ftime}s]"
}

##########################################################################################################################################
# -   unban / ban / banmalware / whitelist / import / deport / save / start / disable / update / debug / stats / install / uninstall   - #
##########################################################################################################################################


case "$1" in
	unban)
		Purge_Logs
		if [ -z "$2" ]; then
			printf "Input IP: "
			read -r ip
			echo "Unbanning $ip"
			ipset -D Blacklist "$ip"
			sed -i "\\~$ip ~d" "${location}/skynet.log"
		elif echo "$2" | Is_IP; then
			echo "Unbanning $2"
			ipset -D Blacklist "$2"
			sed -i "\\~$2 ~d" "${location}/skynet.log"
		elif [ "$2" = "range" ] && [ -n "$3" ]; then
			echo "Unbanning $3"
			ipset -D BlockedRanges "$3"
			sed -i "\\~$3 ~d" "${location}/skynet.log"
		elif [ "$2" = "domain" ] && [ -z "$3" ]; then
			printf "Input URL: "
			read -r unbandomain
			logger -st Skynet "[INFO] Removing $unbandomain From Blacklist..."
			for ip in $(Domain_Lookup "$unbandomain"); do
				echo "Unbanning $ip"
				ipset -D Blacklist "$ip"
				sed -i "\\~$ip ~d" "${location}/skynet.log"
			done
		elif [ "$2" = "domain" ] && [ -n "$3" ]; then
		logger -st Skynet "[INFO] Removing $3 From Blacklist..."
		for ip in $(Domain_Lookup "$3"); do
			echo "Unbanning $ip"
			ipset -D Blacklist "$ip"
			sed -i "\\~$ip ~d" "${location}/skynet.log"
		done
		elif [ "$2" = "port" ] && [ -n "$3" ]; then
			logger -st Skynet "[INFO] Unbanning Autobans Issued On Traffic From Source/Destination Port $3..."
			grep -F "NEW" "${location}/skynet.log" | grep -F "PT=$3 " | grep -oE 'SRC=[0-9,\.]* ' | cut -c 5- | while IFS= read -r ip; do
				echo "Unbanning $ip"
				ipset -D Blacklist "$ip"
			done
			sed -i "/PT=${3} /d" "${location}/skynet.log"
		elif [ "$2" = "comment" ] && [ -n "$3" ]; then
			echo "Removing Bans With Comment Containing ($3)"
			sed "\\~add Whitelist ~d;\\~$3~!d;s~ comment.*~~;s~add~del~g" "${location}/scripts/ipset.txt" | ipset restore -!
		elif [ "$2" = "country" ]; then
			echo "Removing Previous Country Bans"
			sed '\~add Whitelist ~d;\~Country: ~!d;s~ comment.*~~;s~add~del~g' "${location}/scripts/ipset.txt" | ipset restore -!
		elif [ "$2" = "malware" ]; then
			echo "Removing Previous Malware Bans"
			sed '\~add Whitelist ~d;\~BanMalware~!d;s~ comment.*~~;s~add~del~g' "${location}/scripts/ipset.txt" | ipset restore -!
		elif [ "$2" = "autobans" ]; then
			grep -F "NEW" "${location}/skynet.log" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | tr -d " " | while IFS= read -r ip; do
				echo "Unbanning $ip"
				ipset -D Blacklist "$ip"
				sed -i "\\~$ip ~d" "${location}/skynet.log"
			done
		elif [ "$2" = "nomanual" ]; then
			sed -i '/Manual /!d' "${location}/skynet.log"
			ipset flush Blacklist
			ipset flush BlockedRanges
			sed '\~add Whitelist ~d;\~Manual[R]*Ban: ~!d' "${location}/scripts/ipset.txt" | ipset restore -!
			iptables -Z PREROUTING -t raw
		elif [ "$2" = "all" ]; then
			logger -st Skynet "[INFO] Removing All $(($(sed -n '1p' /tmp/counter.txt) + $(sed -n '2p' /tmp/counter.txt))) Entries From Blacklist..."
			ipset flush Blacklist
			ipset flush BlockedRanges
			iptables -Z PREROUTING -t raw
			true > "${location}/skynet.log"
		else
			echo "Command Not Recognised, Please Try Again"
			exit 2
		fi
		Save_IPSets
		;;

	ban)
		Purge_Logs
		if [ -z "$2" ]; then
			printf "Input IP: "
			read -r ip
			printf "Input Ban Comment: "
			read -r desc
			echo "Banning $ip"
			ipset -A Blacklist "$ip" comment "ManualBan: $desc" && echo "$(date +"%b %d %T") Skynet: [Manual Ban] TYPE=Single SRC=$ip COMMENT=$desc " >> "${location}/skynet.log"
		elif echo "$2" | Is_IP; then
			echo "Banning $2"
			desc="$3"
			if [ -z "$3" ]; then
				desc="$(date +"%b %d %T")"
			fi
			ipset -A Blacklist "$2" comment "ManualBan: $desc" && echo "$(date +"%b %d %T") Skynet: [Manual Ban] TYPE=Single SRC=$2 COMMENT=$3 " >> "${location}/skynet.log"
		elif [ "$2" = "range" ] && [ -n "$3" ]; then
			echo "Banning $3"
			desc="$4"
			if [ -z "$4" ]; then
				desc="$(date +"%b %d %T")"
			fi
			ipset -A BlockedRanges "$3" comment "ManualRBan: $desc" && echo "$(date +"%b %d %T") Skynet: [Manual Ban] TYPE=Range SRC=$3 COMMENT=$4 " >> "${location}/skynet.log"
		elif [ "$2" = "domain" ] && [ -z "$3" ]; then
			printf "Input URL: "
			read -r bandomain
			logger -st Skynet "[INFO] Adding $bandomain To Blacklist..."
			for ip in $(Domain_Lookup "$bandomain"); do
				echo "Banning $ip"
				ipset -A Blacklist "$ip" comment "ManualBan: $bandomain" && echo "$(date +"%b %d %T") Skynet: [Manual Ban] TYPE=Domain SRC=$ip Host=$bandomain " >> "${location}/skynet.log"
			done
		elif [ "$2" = "domain" ] && [ -n "$3" ]; then
		logger -st Skynet "[INFO] Adding $3 To Blacklist..."
		for ip in $(Domain_Lookup "$3"); do
			echo "Banning $ip"
			ipset -A Blacklist "$ip" comment "ManualBan: $3" && echo "$(date +"%b %d %T") Skynet: [Manual Ban] TYPE=Domain SRC=$ip Host=$3 " >> "${location}/skynet.log"
		done
		elif [ "$2" = "country" ] && [ -n "$3" ]; then
			if [ -f "${location}/scripts/countrylist.txt" ]; then
				echo "Removing Previous Legacy Country Bans"
				sed 's/add/del/g' "${location}/scripts/countrylist.txt" | ipset restore -!
				rm -rf "${location}/scripts/countrylist.txt"
			fi
			echo "Removing Previous Country Bans"
			sed '\~add Whitelist ~d;\~Country: ~!d;s~ comment.*~~;s~add~del~g' "${location}/scripts/ipset.txt" | ipset restore -!
			echo "Banning Known IP Ranges For $3"
			echo "Downloading Lists"
			for country in $3; do
				/usr/sbin/wget http://ipdeny.com/ipblocks/data/aggregated/"$country"-aggregated.zone -t2 -T2 -qO- >> /tmp/countrylist.txt
			done
			echo "Filtering IPv4 Ranges & Applying Blacklists"
			grep -F "/" /tmp/countrylist.txt | sed -n "s/\\r//;/^$/d;/^[0-9,\\.,\\/]*$/s/^/add BlockedRanges /p" | sed "s/$/& comment \"Country: $3\"/" | ipset restore -!
			rm -rf "/tmp/countrylist.txt"
		else
			echo "Command Not Recognised, Please Try Again"
			exit 2
		fi
		Save_IPSets
		;;

	banmalware)
		if [ -n "$2" ]; then
			listurl="$2"
			echo "Custom List Detected: $2"
		else
			listurl="https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/filter.list"
		fi
		/usr/sbin/wget "$listurl" -t2 -T2 -qO- >/dev/null 2>&1 || { logger -st Skynet "[ERROR] 404 Error Detected - Stopping Banmalware" ; exit 1; }
		Check_Lock "$@"
		if [ -f "${location}/scripts/malwarelist.txt" ]; then
			echo "Removing Previous Legacy Malware Bans"
			sed 's/add/del/g' "${location}/scripts/malwarelist.txt" | ipset restore -!
			rm -rf "${location}/scripts/malwarelist.txt"
		fi
		btime="$(date +%s)" && printf "Removing Previous Malware Bans "
		sed '\~add Whitelist ~d;\~BanMalware~!d;s~ comment.*~~;s~add~del~g' "${location}/scripts/ipset.txt" | ipset restore -! && echo "[$(($(date +%s) - btime))s]"
		btime="$(date +%s)" && printf "Downloading filter.list "
		/usr/sbin/wget "$listurl" -qO /jffs/shared-Skynet-whitelist && echo "[$(($(date +%s) - btime))s]"
		btime="$(date +%s)" && printf "Whitelisting Shared Domains "
		Whitelist_Extra
		Whitelist_Shared >/dev/null 2>&1 && echo "[$(($(date +%s) - btime))s]"
		btime="$(date +%s)" && printf "Consolidating Blacklist "
		/usr/sbin/wget -t2 -T2 -i /jffs/shared-Skynet-whitelist -qO- | sed -n "s/\\r//;/^$/d;/^[0-9,\\.,\\/]*$/p" | awk '!x[$0]++' | Filter_PrivateIP > /tmp/malwarelist.txt && echo "[$(($(date +%s) - btime))s]"
		btime="$(date +%s)" && printf "Filtering IPv4 Addresses "
		grep -vF "/" /tmp/malwarelist.txt | awk '{print "add Blacklist " $1 " comment BanMalware"}' > "/tmp/malwarelist2.txt" && echo "[$(($(date +%s) - btime))s]"
		btime="$(date +%s)" && printf "Filtering IPv4 Ranges "
		grep -F "/" /tmp/malwarelist.txt | awk '{print "add BlockedRanges " $1 " comment BanMalware"}' >> "/tmp/malwarelist2.txt" && echo "[$(($(date +%s) - btime))s]"
		btime="$(date +%s)" && printf "Applying Blacklists "
		ipset restore -! -f "/tmp/malwarelist2.txt" && echo "[$(($(date +%s) - btime))s]"
		rm -rf "/tmp/malwarelist.txt" "/tmp/malwarelist2.txt"
		btime="$(date +%s)" && printf "Saving Changes "
		Save_IPSets >/dev/null 2>&1 && echo "[$(($(date +%s) - btime))s]"
		echo "Warning! This May Have Blocked Your Favorite Website. To Unblock It Use; ( sh $0 whitelist domain URL )"
		rm -rf /tmp/skynet.lock
		;;

	whitelist)
		Purge_Logs
		if [ -z "$2" ]; then
			printf "Input IP: "
			read -r ip
			printf "Input Whitelist Comment: "
			read -r desc
			echo "Whitelisting $ip"
			ipset -A Whitelist "$ip" comment "ManualWlist: $desc"
			ipset -q -D Blacklist "$ip"
			sed -i "\\~$ip ~d" "${location}/skynet.log"
		elif echo "$2" | Is_IP; then
			echo "Whitelisting $2"
			desc="$3"
			if [ -z "$3" ]; then
				desc="$(date +"%b %d %T")"
			fi
			ipset -A Whitelist "$2" comment "ManualWlist: $desc"
			ipset -q -D Blacklist "$2"
			sed -i "\\~$2 ~d" "${location}/skynet.log"
		elif [ "$2" = "range" ] && echo "$3" | Is_IP; then
			echo "Whitelisting $3"
			desc="$4"
			if [ -z "$4" ]; then
				desc="$(date +"%b %d %T")"
			fi
			ipset -A Whitelist "$3" comment "ManualWlist: $desc"
			ipset -q -D Blacklist "$3"
			sed -i "\\~$3 ~d" "${location}/skynet.log"
		elif [ "$2" = "domain" ] && [ -z "$3" ];then
			printf "Input URL: "
			read -r whitelistdomain
			logger -st Skynet "[INFO] Adding $whitelistdomain To Whitelist..."
			for ip in $(Domain_Lookup "$whitelistdomain"); do
				echo "Whitelisting $ip"
				ipset -A Whitelist "$ip" comment "ManualWlistD: $whitelistdomain"
				ipset -q -D Blacklist "$ip"
				sed -i "\\~$ip ~d" "${location}/skynet.log"
			done
		elif [ "$2" = "domain" ] && [ -n "$3" ]; then
		logger -st Skynet "[INFO] Adding $3 To Whitelist..."
		for ip in $(Domain_Lookup "$3"); do
			echo "Whitelisting $ip"
			ipset -A Whitelist "$ip" comment "ManualWlistD: $3"
			ipset -q -D Blacklist "$ip"
			sed -i "\\~$ip ~d" "${location}/skynet.log"
		done
		elif [ "$2" = "port" ] && [ -n "$3" ]; then
			logger -st Skynet "[INFO] Whitelisting Autobans Issued On Traffic From Port $3..."
			grep -F "NEW" "${location}/skynet.log" | grep -F "DPT=$3 " | grep -oE 'SRC=[0-9,\.]* ' | cut -c 5- | while IFS= read -r ip; do
				echo "Whitelisting $ip"
				ipset -A Whitelist "$ip" comment "ManualWlist: Port $3 Traffic"
				ipset -q -D Blacklist "$ip"
				sed -i "\\~$ip ~d" "${location}/skynet.log"
			done
		elif [ "$2" = "remove" ] && [ -z "$3" ]; then
			echo "Flushing Whitelist"
			ipset flush Whitelist
			echo "Adding Default Entries"
			true > "${location}/scripts/ipset.txt"
			Whitelist_Extra
			Whitelist_Shared
		elif [ "$2" = "remove" ] && [ "$3" = "ip" ] && [ -n "$4" ]; then
			echo "Removing $4 From Whitelist"
			ipset -D Whitelist "$4"
		elif [ "$2" = "remove" ] && [ "$3" = "comment" ] && [ -n "$4" ]; then
			echo "Removing All Entries With Comment Matching \"$4\" From Whitelist"
			sed "\\~add Whitelist ~!d;\\~$4~!d;s~ comment.*~~;s~add~del~g" "${location}/scripts/ipset.txt" | ipset restore -!
		elif [ "$2" = "refresh" ]; then
			echo "Refreshing Shared Whitelist Files"
			Whitelist_Extra
			Whitelist_Shared
		elif [ "$2" = "list" ] && [ -z "$3" ]; then
			sed '\~add Whitelist ~!d;s~add Whitelist ~~' "${location}/scripts/ipset.txt"
		elif [ "$2" = "list" ] && [ "$3" = "ips" ]; then
			sed '\~add Whitelist ~!d;\~ManualWlist:~!d;s~add Whitelist ~~' "${location}/scripts/ipset.txt"
		elif [ "$2" = "list" ] && [ "$3" = "domains" ]; then
			sed '\~add Whitelist ~!d;\~ManualWlistD:~!d;s~add Whitelist ~~' "${location}/scripts/ipset.txt"
		else
			echo "Command Not Recognised, Please Try Again"
			exit 2
		fi
		Save_IPSets
		;;

	import)
		echo "This Function Extracts All IPs And Adds Them ALL To Blacklist"
		if [ -n "$2" ]; then
			Check_Lock "$@"
			echo "Custom List Detected: $2"
			/usr/sbin/wget "$2" --no-check-certificate -t2 -T2 -qO /tmp/iplist-unfiltered.txt || { logger -st Skynet "[ERROR] 404 Error Detected - Stopping Import" ; exit 1; }
		else
			echo "No List URL Specified - Exiting"
			exit 2
		fi
		imptime="$(date +"%b %d %T")"
		echo "Filtering IPv4 Addresses"
		grep -woE '([0-9]{1,3}\.){3}[0-9]{1,3}' /tmp/iplist-unfiltered.txt | Filter_PrivateIP | awk -v imptime="$imptime" '{print "add Blacklist " $1 " comment \"Imported: " imptime "\""}' > /tmp/iplist-filtered.txt
		echo "Filtering IPv4 Ranges"
		grep -woE '([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}' /tmp/iplist-unfiltered.txt | Filter_PrivateIP | awk -v imptime="$imptime" '{print "add BlockedRanges " $1 " comment \"Imported: " imptime "\""}' >> /tmp/iplist-filtered.txt
		echo "Adding IPs To Blacklist"
		ipset restore -! -f "/tmp/iplist-filtered.txt"
		rm -rf /tmp/iplist-unfiltered.txt /tmp/iplist-filtered.txt
		Save_IPSets
		rm -rf /tmp/skynet.lock
		;;

	deport)
		echo "This Function Extracts All IPs And Removes Them ALL From Blacklist"
		if [ -n "$2" ]; then
			Check_Lock "$@"
			echo "Custom List Detected: $2"
			/usr/sbin/wget "$2" --no-check-certificate -t2 -T2 -qO /tmp/iplist-unfiltered.txt || { logger -st Skynet "[ERROR] 404 Error Detected - Stopping Deport" ; exit 1; }
		else
			echo "No List URL Specified - Exiting"
			exit 2
		fi
		echo "Filtering IPv4 Addresses"
		grep -woE '([0-9]{1,3}\.){3}[0-9]{1,3}' /tmp/iplist-unfiltered.txt | Filter_PrivateIP | awk '{print "del Blacklist " $1}' > /tmp/iplist-filtered.txt
		echo "Filtering IPv4 Ranges"
		grep -woE '([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}' /tmp/iplist-unfiltered.txt | Filter_PrivateIP | awk '{print "del BlockedRanges " $1}' >> /tmp/iplist-filtered.txt
		echo "Removing IPs From Blacklist"
		ipset restore -! -f "/tmp/iplist-filtered.txt"
		rm -rf /tmp/iplist-unfiltered.txt /tmp/iplist-filtered.txt
		Save_IPSets
		;;

	save)
		Check_Lock "$@"
		Unban_PrivateIP
		Purge_Logs
		Save_IPSets
		sed -i "\\~USER $(nvram get http_username) pid .*/jffs/scripts/firewall ~d" /tmp/syslog.log
		rm -rf /tmp/skynet.lock
		;;

	start)
		Check_Lock "$@"
		logger -st Skynet "[INFO] Startup Initiated... ( $(echo "$@" | sed "s/start //g") )"
		Unload_Cron
		Check_Settings "$@"
		cru a Skynet_save "0 * * * * sh /jffs/scripts/firewall save"
		modprobe xt_set
		ipset restore -! -f "${location}/scripts/ipset.txt" || touch "${location}/scripts/ipset.txt"
		if ! ipset -L -n Whitelist >/dev/null 2>&1; then ipset -q create Whitelist hash:net comment; forcesave=1; fi
		if ! ipset -L -n Blacklist >/dev/null 2>&1; then ipset -q create Blacklist hash:ip --maxelem 500000 comment; forcesave=1; fi
		if ! ipset -L -n BlockedRanges >/dev/null 2>&1; then ipset -q create BlockedRanges hash:net comment; forcesave=1; fi
		if ! ipset -L -n Skynet >/dev/null 2>&1; then ipset -q create Skynet list:set; ipset -q -A Skynet Blacklist; ipset -q -A Skynet BlockedRanges; forcesave=1; fi
		ipset -q -A Skynet Blacklist
		ipset -q -A Skynet BlockedRanges
		Unban_PrivateIP
		Purge_Logs
		sed '\~add Whitelist ~!d;\~nvram: ~!d;s~ comment.*~~;s~add~del~g' "${location}/scripts/ipset.txt" | ipset restore -!
		Whitelist_Extra
		Whitelist_Shared
		if [ -z "$forcesave" ]; then Save_IPSets; fi
		while [ "$(($(date +%s) - stime))" -lt "20" ]; do
			sleep 1
		done
		Unload_IPTables
		Unload_DebugIPTables
		Load_IPTables "$@"
		Load_DebugIPTables "$@"
		sed -i '/DROP IN=/d' /tmp/syslog.log-1 2>/dev/null
		sed -i '/DROP IN=/d' /tmp/syslog.log 2>/dev/null
		rm -rf /tmp/skynet.lock
		;;

	disable)
		logger -st Skynet "[INFO] Disabling Skynet..."
		Save_IPSets
		echo "Unloading IPTables Rules"
		Unload_IPTables
		Unload_DebugIPTables
		echo "Unloading IPSets"
		Unload_IPSets
		Purge_Logs
		Unload_Cron
		Kill_Lock
		exit 0
	;;

	update)
		remoteurl="https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh"
		/usr/sbin/wget "$remoteurl" -t2 -T2 -qO- | grep -qF "Adamm" || { logger -st Skynet "[ERROR] 404 Error Detected - Stopping Update" ; exit 1; }
		localver="$(Filter_Version "$0")"
		remotever="$(/usr/sbin/wget "$remoteurl" -qO- | Filter_Version)"
		if [ "$localver" = "$remotever" ] && [ "$2" != "-f" ]; then
			logger -st Skynet "[INFO] Skynet Up To Date - $localver"
			exit 0
		elif [ "$localver" != "$remotever" ] && [ "$2" = "check" ]; then
			logger -st Skynet "[INFO] Skynet Update Detected - $remotever"
			exit 0
		elif [ "$2" = "-f" ]; then
			logger -st Skynet "[INFO] Forcing Update"
		fi
		if [ "$localver" != "$remotever" ] || [ "$2" = "-f" ]; then
			Check_Lock "$@"
			logger -st Skynet "[INFO] New Version Detected - Updating To $remotever... ... ..."
			Save_IPSets >/dev/null 2>&1
			Unload_Cron
			Unload_IPTables
			Unload_DebugIPTables
			Unload_IPSets
			iptables -t raw -F
			/usr/sbin/wget "$remoteurl" -qO "$0" && logger -st Skynet "[INFO] Skynet Sucessfully Updated - Restarting Firewall"
			rm -rf /tmp/skynet.lock
			service restart_firewall
			exit 0
		fi
		;;

	debug)
		case "$2" in
			restart)
				Unload_Cron
				Kill_Lock
				Save_IPSets
				Unload_IPTables
				Unload_DebugIPTables
				Unload_IPSets
				echo "Restarting Firewall Service"
				iptables -t raw -F
				service restart_firewall
				exit 0
			;;
			disable)
				logger -st Skynet "[INFO] Temporarily Disabling Debug Output..."
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
				red="printf \\e[5;31m%s\\e[0m\\n"
				grn="printf \\e[1;32m%s\\e[0m\\n"
				echo "Router Model; $(nvram get productid)"
				echo "Skynet Version; $(Filter_Version "$0") ($(Filter_Date "$0"))"
				echo "$(iptables --version) - ($iface)"
				ipset -v
				echo "FW Version; $(nvram get buildno)_$(nvram get extendno) ($(uname -v | awk '{print $5" "$6" "$9}'))"
				echo "Install Dir; $location ($(df -h $location | xargs | awk '{print $9}') Space Available)"
				echo "Boot Args; $(grep -F "Skynet" /jffs/scripts/firewall-start | cut -c 4- | cut -d '#' -f1)"
				if grep -qF "Country:" "$location/scripts/ipset.txt"; then echo "Banned Countries; $(grep -m1 -F "Country:" "$location/scripts/ipset.txt" | sed 's~.*Country: ~~;s~"~~')"; fi
				if [ -w "$location" ]; then $grn "Install Dir Writeable"; else $red "Can't Write To Install Dir"; fi
				if grep -qF "Skynet" /jffs/scripts/firewall-start; then $grn "Startup Entry Detected"; else $red "Startup Entry Not Detected"; fi
				if [ -f "/tmp/skynet.lock" ] && [ -d "/proc/$(sed -n '2p' /tmp/skynet.lock)" ]; then $red "Lock File Detected ($(sed -n '1p' /tmp/skynet.lock)) (pid=$(sed -n '2p' /tmp/skynet.lock))"; else $grn "No Lock File Found"; fi
				if cru l | grep -qF "Skynet"; then $grn "Cronjobs Detected"; else $red "Cronjobs Not Detected"; fi
				if [ -f /lib/modules/2.6.36.4brcmarm/kernel/net/netfilter/ipset/ip_set_hash_ipmac.ko ] || [ -f /lib/modules/4.1.27/kernel/net/netfilter/ipset/ip_set_hash_ipmac.ko ]; then $grn "IPSet Supports Comments"; else $red "IPSet Doesn't Support Comments - Please Update To 380.68 / V26E3 Or Newer Firmware"; fi
				if [ "$(nvram get message_loglevel)" -le "$(nvram get log_level)" ]; then $grn "Level $(nvram get message_loglevel) Messages Will Be Logged"; else $red "Level $(nvram get message_loglevel) Messages Won't Be Logged - Only $(nvram get log_level)+"; fi
				if iptables -C logdrop -i "$iface" -m state --state INVALID -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null; then $grn "Autobanning Enabled"; else $red "Autobanning Disabled"; fi
				if iptables -t raw -C PREROUTING -i "$iface" -m set --match-set Skynet src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null; then $grn "Debug Mode Enabled"; else $red "Debug Mode Disabled"; fi
				if [ "$(iptables-save -t raw | sort | uniq -d | grep -c " ")" = "0" ]; then $grn "No Duplicate Rules Detected In RAW"; else $red "Duplicate Rules Detected In RAW"; fi
				if [ "$(iptables-save -t filter | sort | uniq -d | grep -c " ")" = "0" ]; then $grn "No Duplicate Rules Detected In FILTER"; else $red "Duplicate Rules Detected In FILTER"; fi
				if iptables -t raw -C PREROUTING -i "$iface" -m set --match-set Whitelist src -j ACCEPT 2>/dev/null; then $grn "Whitelist IPTable Detected"; else $red "Whitelist IPTable Not Detected"; fi
				if iptables -t raw -C PREROUTING -i "$iface" -m set --match-set Skynet src -j DROP 2>/dev/null; then $grn "Skynet IPTable Detected"; else $red "Skynet IPTable Not Detected"; fi
				if ipset -L -n Whitelist >/dev/null 2>&1; then $grn "Whitelist IPSet Detected"; else $red "Whitelist IPSet Not Detected"; fi
				if ipset -L -n BlockedRanges >/dev/null 2>&1; then $grn "BlockedRanges IPSet Detected"; else $red "BlockedRanges IPSet Not Detected"; fi
				if ipset -L -n Blacklist >/dev/null 2>&1; then $grn "Blacklist IPSet Detected"; else $red "Blacklist IPSet Not Detected"; fi
				if ipset -L -n Skynet >/dev/null 2>&1; then $grn "Skynet IPSet Detected"; else $red "Skynet IPSet Not Detected"; fi
			;;

		*)
			echo "Error - Use Syntax 'sh $0 debug (restart/disable/watch/info)'"
		esac
		;;

	stats)
		Purge_Logs
		if ! grep -F "Skynet" /jffs/scripts/firewall-start | grep -qF "debug"; then
			echo
			echo "!!! Debug Mode Is Disabled !!!"
			echo "To Enable Use ( sh $0 install )"
			echo
		fi
		if [ -s "${location}/skynet.log" ]; then
			echo "Debug Data Detected in ${location}/skynet.log - $(du -h ${location}/skynet.log | awk '{print $1}')"
		else
			echo "No Debug Data Detected - Give This Time To Generate"
			exit 0
		fi
		if [ "$2" = "reset" ]; then
			sed -i '/BLOCKED - .*BOUND/d' "${location}/skynet.log"
			iptables -Z PREROUTING -t raw
			echo "Stat Data Reset"
			exit 0
		fi
		echo "Monitoring From $(grep -m1 -E 'INBOUND|OUTBOUND' ${location}/skynet.log | awk '{print $1" "$2" "$3}') To $(grep -E 'INBOUND|OUTBOUND' ${location}/skynet.log | tail -1 | awk '{print $1" "$2" "$3}')"
		echo "$(wc -l ${location}/skynet.log | awk '{print $1}') Total Events Detected"
		echo "$({ grep -F "INBOUND" ${location}/skynet.log | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- ; grep -F "OUTBOUND" ${location}/skynet.log | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- ; } | awk '!x[$0]++' | wc -l) Unique IPs"
		echo "$(grep -Fc "NEW BAN" ${location}/skynet.log) Autobans Issued"
		echo "$(grep -Fc "Manual Ban" ${location}/skynet.log) Manual Bans Issued"
		echo
		counter=10
		if [ -n "$2" ] && [ "$2" != "search" ] && [ "$2" -eq "$2" ] 2>/dev/null; then
			counter="$2"
		elif [ -n "$5" ] && [ "$5" -eq "$5" ] 2>/dev/null; then
			counter="$5"
		elif [ "$3" = "autobans" ] && [ "$4" -eq "$4" ] 2>/dev/null; then
			counter="$4"
		elif [ "$3" = "manualbans" ] && [ "$4" -eq "$4" ] 2>/dev/null; then
			counter="$4"
		fi
		if [ "$2" = "tcp" ] || [ "$3" = "tcp" ]; then
			proto=TCP
		elif [ "$2" = "udp" ] || [ "$3" = "udp" ]; then
			proto=UDP
		elif [ "$2" = "icmp" ] || [ "$3" = "icmp" ]; then
			proto=ICMP
		fi
		if [ "$2" = "search" ] && [ "$3" = "port" ] && [ -n "$4" ]; then
			echo "Port $4 First Tracked On $(grep -m1 -F "PT=$4 " ${location}/skynet.log | awk '{print $1" "$2" "$3}')"
			echo "Port $4 Last Tracked On $(grep -F "PT=$4 " ${location}/skynet.log | tail -1 | awk '{print $1" "$2" "$3}')"
			echo "$(grep -Foc "PT=$4 " ${location}/skynet.log) Attempts Total"
			echo "$(grep -F "PT=$4 " ${location}/skynet.log | grep -oE ' SRC=[0-9,\.]* ' | awk '!x[$0]++' | wc -l) Unique IPs"
			echo "$(grep -F "PT=$4 " ${location}/skynet.log | grep -cF NEW) Autobans From This Port"
			echo
			echo "First Block Tracked On Port $4;"
			grep -m1 -F "PT=$4 " "${location}/skynet.log"
			echo
			echo "$counter Most Recent Blocks On Port $4;";
			grep -F "PT=$4 " "${location}/skynet.log" | tail -"$counter"
			exit 0
		elif [ "$2" = "search" ] && [ "$3" = "ip" ] && [ -n "$4" ]; then
			ipset test Whitelist "$4" && found1=true
			ipset test Blacklist "$4" && found2=true
			ipset test BlockedRanges "$4" && found3=true
			echo
			if [ -n "$found1" ]; then echo "Whitelist Reason; $(grep -E "Whitelist.*$4 " ${location}/scripts/ipset.txt | awk '{$1=$2=$3=$4=""; print $0}' | tr -s " ")"; fi
			if [ -n "$found2" ]; then echo "Blacklist Reason; $(grep -E "Blacklist.*$4 " ${location}/scripts/ipset.txt | awk '{$1=$2=$3=$4=""; print $0}' | tr -s " ")"; fi
			if [ -n "$found3" ]; then echo "BlockedRanges Reason; $(grep -E "BlockedRanges.*$(echo "$4" | cut -d '.' -f1-3)." ${location}/scripts/ipset.txt | awk '{$1=$2=$4=""; print $0}' | tr -s " ")"; fi
			echo
			echo "$4 First Tracked On $(grep -m1 -F "=$4 " ${location}/skynet.log | awk '{print $1" "$2" "$3}')"
			echo "$4 Last Tracked On $(grep -F "=$4 " ${location}/skynet.log | tail -1 | awk '{print $1" "$2" "$3}')"
			echo "$(grep -Foc "=$4 " ${location}/skynet.log) Events Total"
			echo
			echo "First Block Tracked From $4;"
			grep -m1 -F "=$4 " "${location}/skynet.log"
			echo
			echo "$counter Most Recent Blocks From $4;"
			grep -F "=$4 " "${location}/skynet.log" | tail -"$counter"
			echo
			echo "Top $counter Targeted Ports From $4 (Inbound);"
			grep -E "INBOUND.*SRC=$4.*$proto" "${location}/skynet.log" | grep -oE 'DPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://www.speedguide.net/port.php?port="$2}'
			echo
			echo "Top $counter Sourced Ports From $4 (Inbound);"
			grep -E "INBOUND.*SRC=$4.*$proto" "${location}/skynet.log" | grep -oE 'SPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://www.speedguide.net/port.php?port="$2}'
			echo
			exit 0
		elif [ "$2" = "search" ] && [ "$3" = "malware" ] && [ -n "$4" ]; then
			/usr/sbin/wget https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/filter.list -qO- | while IFS= read -r url; do
				/usr/sbin/wget "$url" -qO /tmp/malwarelist.txt
				{ grep -E "^$4" /tmp/malwarelist.txt && echo "Found In $url"; } | xargs -r
				{ grep -F "/" /tmp/malwarelist.txt | grep -E "^$(echo "$4" | cut -d '.' -f1-3)." && echo "Possible CIDR Match In $url"; } | xargs -r
			done
			rm -rf /tmp/malwarelist.txt
			echo
			Logging
			exit 0
		elif [ "$2" = "search" ] && [ "$3" = "autobans" ]; then
			echo "First Autoban Issued On $(grep -m1 -F "NEW BAN" ${location}/skynet.log | awk '{print $1" "$2" "$3}')"
			echo "Last Autoban Issued On $(grep -F "NEW BAN" ${location}/skynet.log | tail -1 | awk '{print $1" "$2" "$3}')"
			echo
			echo "First Autoban Issued;"
			grep -m1 -F "NEW BAN" "${location}/skynet.log"
			echo
			echo "$counter Most Recent Autobans;"
			grep -F "NEW BAN" "${location}/skynet.log" | tail -"$counter"
			exit 0
		elif [ "$2" = "search" ] && [ "$3" = "manualbans" ]; then
			echo "First Manual Ban Issued On $(grep -m1 -F "Manual Ban" ${location}/skynet.log | awk '{print $1" "$2" "$3}')"
			echo "Last Manual Ban Issued On $(grep -F "Manual Ban" ${location}/skynet.log | tail -1 | awk '{print $1" "$2" "$3}')"
			echo
			echo "First Manual Ban Issued;"
			grep -m1 -F "Manual Ban" "${location}/skynet.log"
			echo
			echo "$counter Most Recent Manual Bans;"
			grep -F "Manual Ban" "${location}/skynet.log" | tail -"$counter"
			exit 0
		fi
		echo "Top $counter Targeted Ports (Inbound); (Torrent Clients May Cause Excess Hits In Debug Mode)"
		grep -E "INBOUND.*$proto" "${location}/skynet.log" | grep -oE 'DPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://www.speedguide.net/port.php?port="$2}'
		echo
		echo "Top $counter Source Ports (Inbound);"
		grep -E "INBOUND.*$proto" "${location}/skynet.log" | grep -oE 'SPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://www.speedguide.net/port.php?port="$2}'
		echo
		echo "Last $counter Unique Connections Blocked (Inbound);"
		grep -E "INBOUND.*$proto" "${location}/skynet.log" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | awk '!x[$0]++' | tail -"$counter" | sed '1!G;h;$!d' | awk '{print "https://otx.alienvault.com/indicator/ip/"$1}'
		echo
		echo "Last $counter Unique Connections Blocked (Outbound);"
		grep -E "OUTBOUND.*$proto" "${location}/skynet.log" | grep -vE 'DPT=80 |DPT=443 ' | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | awk '!x[$0]++' | tail -"$counter" | sed '1!G;h;$!d' | awk '{print "https://otx.alienvault.com/indicator/ip/"$1}'
		echo
		echo "Last $counter Autobans;"
		grep -E "NEW BAN.*$proto" "${location}/skynet.log" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | tail -"$counter" | sed '1!G;h;$!d' | awk '{print "https://otx.alienvault.com/indicator/ip/"$1}'
		echo
		echo "Last $counter Manual Bans;"
		grep -F "Manual Ban" "${location}/skynet.log" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | tail -"$counter" | sed '1!G;h;$!d' | awk '{print "https://otx.alienvault.com/indicator/ip/"$1}'
		echo
		echo "Last $counter Unique HTTP(s) Blocks (Outbound);"
		grep -E 'DPT=80 |DPT=443 ' "${location}/skynet.log" | grep -E "OUTBOUND.*$proto" | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | awk '!x[$0]++' | tail -"$counter" | sed '1!G;h;$!d' | awk '{print "https://otx.alienvault.com/indicator/ip/"$1}'
		echo
		echo "Top $counter HTTP(s) Blocks (Outbound);"
		grep -E 'DPT=80 |DPT=443 ' "${location}/skynet.log" | grep -E "OUTBOUND.*$proto" | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://otx.alienvault.com/indicator/ip/"$2}'
		echo
		echo "Top $counter Blocks (Inbound);"
		grep -E "INBOUND.*$proto" "${location}/skynet.log" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://otx.alienvault.com/indicator/ip/"$2}'
		echo
		echo "Top $counter Blocks (Outbound);"
		grep -E "OUTBOUND.*$proto" "${location}/skynet.log" | grep -vE 'DPT=80 |DPT=443 ' | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://otx.alienvault.com/indicator/ip/"$2}'
		echo
		;;

	install)
		Check_Lock "$@"
		if [ "$(ipset -v | grep -Fo v6)" != "v6" ]; then
			logger -st Skynet "[ERROR] IPSet Version Not Supported"
			rm -rf /tmp/skynet.lock
			exit 1
		fi
		if [ ! -f /lib/modules/2.6.36.4brcmarm/kernel/net/netfilter/ipset/ip_set_hash_ipmac.ko ] && [ ! -f /lib/modules/4.1.27/kernel/net/netfilter/ipset/ip_set_hash_ipmac.ko ]; then
			logger -st Skynet "[ERROR] IPSet Extensions Not Enabled - Please Update To 380.68 / V26E3 Or Newer Firmware"
			rm -rf /tmp/skynet.lock
			exit 1
		fi
		if [ "$(nvram get jffs2_scripts)" != "1" ]; then
			nvram set jffs2_scripts=1
			forcereboot=1
		fi
		if [ "$(nvram get fw_enable_x)" != "1" ]; then
			nvram set fw_enable_x=1
		fi
		if [ "$(nvram get fw_log_x)" != "drop" ] && [ "$(nvram get fw_log_x)" != "both" ]; then
			nvram set fw_log_x=drop
		fi
		if [ ! -f "/jffs/scripts/firewall-start" ]; then
			echo "#!/bin/sh" > /jffs/scripts/firewall-start
		elif [ -f "/jffs/scripts/firewall-start" ] && ! head -1 /jffs/scripts/firewall-start | grep -qE "^#!/bin/sh"; then
			sed -i '1s~^~#!/bin/sh\n~' /jffs/scripts/firewall-start
		fi
		echo "Installing Skynet $(Filter_Version "$0")"
		echo "This Will Remove Any Old Install Arguements And Can Be Run Multiple Times"
		echo "[1] --> Vanilla -           Default Installation"
		echo "[2] --> NoAuto -            Default Installation Without Autobanning"
		echo "[3] --> Debug -             Default Installation With Debug Print For Extended Stat Reporting"
		echo "[4] --> NoAuto & Debug -    Default Installation With No Autobanning And Debug Print"
		echo
		echo "Please Select Installation Mode"
		printf "[1-4]: "
		read -r mode1
		case "$mode1" in
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
			rm -rf /tmp/skynet.lock
			exit 2
			;;
		esac
		echo
		echo
		echo "Would You Like To Enable Malwarelist Updating?"
		echo "[1] --> Yes (Daily)  - (Recommended)"
		echo "[2] --> Yes (Weekly)"
		echo "[3] --> No"
		echo
		echo "Please Select Option"
		printf "[1-3]: "
		read -r mode2
		case "$mode2" in
			1)
			echo "Malware List Updating Enabled & Scheduled For 2.25am Every Day"
			set2="banmalware"
			;;
			2)
			echo "Malware List Updating Enabled & Scheduled For 2.25am Every Monday"
			set2="banmalwareweekly"
			;;
			*)
			echo "Malware List Updating Disabled"
			;;
		esac
		echo
		echo
		echo "Would You Like To Enable Weekly Skynet Updating?"
		echo "[1] --> Yes  - (Recommended)"
		echo "[2] --> No"
		echo
		echo "Please Select Option"
		printf "[1-2]: "
		read -r mode3
		case "$mode3" in
			1)
			echo "Skynet Updating Enabled & Scheduled For 1.25am Every Monday"
			set3="autoupdate"
			;;
			*)
			echo "Auto Updating Disabled"
			;;
		esac
		echo
		echo
		echo "Where Would You Like To Install Skynet?"
		echo "[1] --> JFFS"
		echo "[2] --> USB - (Recommended)"
		echo
		echo "Please Select Option"
		printf "[1-2]: "
		read -r mode4
		case "$mode4" in
			2)
			echo "USB Installation Selected"
			echo
			echo "Looking For Available Partitions..."
			i=1
			IFS="
			"
			for mounted in $(/bin/mount | grep -E "ext2|ext3|ext4|tfat|exfat" | awk '{print $3" - ("$1")"}') ; do
				echo "[$i] --> $mounted"
				eval mounts$i="$(echo "$mounted" | awk '{print $1}')"
				i=$((i + 1))
			done
			unset IFS
			if [ $i = "1" ]; then
				echo "No Compadible Partitions Found. Exiting..."
				rm -rf /tmp/skynet.lock
				exit 1
			fi
			echo
			echo "Please Enter Partition Number Or 0 To Exit"
			printf "[0-%s]: " "$((i - 1))"
			read -r partitionNumber
			if [ "$partitionNumber" = "0" ]; then
				echo "Exiting..."
				rm -rf /tmp/skynet.lock
				exit 0
			fi
			if [ -z "$partitionNumber" ] || [ "$partitionNumber" -gt $((i - 1)) ]; then
				echo "Invalid Partition Number! Exiting..."
				rm -rf /tmp/skynet.lock
				exit 2
			fi
			device=""
			eval device=\$mounts"$partitionNumber"
			echo "$device Selected."
			mkdir -p "${device}/skynet"
			mkdir -p "${device}/skynet/scripts"
			touch "${device}/skynet/rwtest"
			if [ ! -w "${device}/skynet/rwtest" ]; then
				echo "Writing To $device Failed - Exiting Installation"
				rm -rf /tmp/skynet.lock
				exit 1
			else
				rm -rf "${device}/skynet/rwtest"
			fi
			if [ -f "${location}/scripts/ipset.txt" ]; then mv "${location}/scripts/ipset.txt" "${device}/skynet/scripts/"; fi
			if [ -f "${location}/skynet.log" ]; then mv "${location}/skynet.log" "${device}/skynet/"; fi
			sed -i '\~ Skynet ~d' /jffs/scripts/firewall-start
			echo "sh /jffs/scripts/firewall $set1 $set2 $set3 usb=${device} # Skynet Firewall Addition" | tr -s " " >> /jffs/scripts/firewall-start
			;;
			*)
			echo "JFFS Installation Selected"
			mkdir -p "/jffs/scripts"
			if [ -f "${location}/scripts/ipset.txt" ]; then mv "${location}/scripts/ipset.txt" "/jffs/scripts/"; fi
			if [ -f "${location}/skynet.log" ]; then mv "${location}/skynet.log" "/jffs/"; fi
			sed -i '\~ Skynet ~d' /jffs/scripts/firewall-start
			echo "sh /jffs/scripts/firewall $set1 $set2 $set3 # Skynet Firewall Addition" | tr -s " " >> /jffs/scripts/firewall-start
			;;
		esac
		chmod +x /jffs/scripts/firewall
		chmod +x /jffs/scripts/firewall-start
		echo
		nvram commit
		if [ "$forcereboot" = "1" ]; then
			echo "Rebooting Router To Complete Installation"
			reboot
			exit 0
		fi
		echo "Restarting Firewall To Complete Installation"
		Unload_Cron
		Unload_IPTables
		Unload_DebugIPTables
		Unload_IPSets
		iptables -t raw -F
		rm -rf /tmp/skynet.lock
		service restart_firewall
		exit 0
		;;

	uninstall)
		echo "If You Were Experiencing Issues, Try Update Or Visit SNBForums/Github For Support"
		echo "https://github.com/Adamm00/IPSet_ASUS"
		echo "Type 'yes' To Continue Uninstall"
		echo
		printf "[yes/no]: "
		read -r continue
		if [ "$continue" = "yes" ]; then
			echo "Uninstalling And Restarting Firewall"
			Unload_Cron
			Kill_Lock
			Unload_IPTables
			Unload_DebugIPTables
			Unload_IPSets
			sed -i '\~ Skynet ~d' /jffs/scripts/firewall-start
			rm -rf "${location}/scripts/ipset.txt" "${location}/skynet.log" "/jffs/shared-Skynet-whitelist" "/jffs/shared-Skynet2-whitelist" "/opt/bin/firewall" "/jffs/scripts/firewall"
			iptables -t raw -F
			service restart_firewall
			exit 0
		fi
		;;

	*)
		echo "Command Not Recognised, Please Try Again"
		echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
		;;

esac

Logging