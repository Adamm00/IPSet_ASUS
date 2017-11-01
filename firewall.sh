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
## - 2/11/2017 -		   Asus Firewall Addition By Adamm v5.4.4				    #
##				   https://github.com/Adamm00/IPSet_ASUS				    #
#############################################################################################################


clear
head -16 "$0"
export LC_ALL=C
while [ "$(nvram get ntp_ready)" = "0" ]; do
	sleep 1
done
red="printf \\e[1;31m%s\\e[0m\\n"
grn="printf \\e[1;32m%s\\e[0m\\n"
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

if grep -qE "usb=.* # Skynet" /jffs/scripts/firewall-start 2>/dev/null; then
	location="$(grep -ow "usb=.*" /jffs/scripts/firewall-start | awk '{print $1}' | cut -c 5-)/skynet"
	if [ ! -d "$location" ] && ! echo "$@" | grep -wqE "(install|uninstall|disable|update|restart|info)"; then
		Check_Lock "$@"
		retry=1
		while [ ! -d "$location" ] && [ "$retry" -lt "11" ]; do
			logger -st Skynet "[INFO] USB Not Found - Sleeping For 10 Seconds ( Attempt $retry Of 10 )"
			retry=$((retry+1))
			sleep 10
		done
		if [ ! -d "$location" ]; then
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

		if echo "$@" | grep -qF "autoupdate "; then
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
		iptables -D logdrop -m state --state NEW -j LOG --log-prefix --log --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1 # Temp .382 Codebase Fix
		ip6tables -D logdrop -m state --state NEW -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
		iptables -t raw -D PREROUTING -i "$iface" -m set ! --match-set Whitelist src -m set --match-set Skynet src -j DROP >/dev/null 2>&1
		iptables -t raw -D PREROUTING -i br0 -m set ! --match-set Whitelist dst -m set --match-set Skynet dst -j DROP >/dev/null 2>&1
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
		iptables -t raw -I PREROUTING -i "$iface" -m set ! --match-set Whitelist src -m set --match-set Skynet src -j DROP >/dev/null 2>&1
		iptables -t raw -I PREROUTING -i br0 -m set ! --match-set Whitelist dst -m set --match-set Skynet dst -j DROP >/dev/null 2>&1
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
		iptables -t raw -D PREROUTING -i "$iface" -m set ! --match-set Whitelist src -m set --match-set Skynet src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
		iptables -t raw -D PREROUTING -i br0 -m set ! --match-set Whitelist dst -m set --match-set Skynet dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
}

Load_DebugIPTables () {
		if echo "$@" | grep -qF "debug"; then
			pos1="$(iptables --line -nL PREROUTING -t raw | grep -F "Skynet src" | grep -F "DROP" | awk '{print $1}')"
			iptables -t raw -I PREROUTING "$pos1" -i "$iface" -m set ! --match-set Whitelist src -m set --match-set Skynet src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
			pos2="$(iptables --line -nL PREROUTING -t raw | grep -F "Skynet dst" | grep -F "DROP" | awk '{print $1}')"
			iptables -t raw -I PREROUTING "$pos2" -i br0 -m set ! --match-set Whitelist dst -m set --match-set Skynet dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options >/dev/null 2>&1
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

Is_Range () {
		grep -wqE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}'
}

Is_Port () {
		grep -wqE '[0-9]{1,5}'
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
		grep -vE '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)|(^22[4-9]\.)|(^23[0-9]\.)'
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
		grep -F "INBOUND" /tmp/syslog.log | Filter_PrivateSRC | grep -oE 'SRC=[0-9,\.]* ' | cut -c 5- | while IFS= read -r "ip"; do
			ipset -q -A Whitelist "$ip" comment "PrivateIP"
			ipset -q -D Blacklist "$ip"
			sed -i "/SRC=${ip} /d" /tmp/syslog.log
		done
		grep -F "OUTBOUND" /tmp/syslog.log | Filter_PrivateDST | grep -oE 'DST=[0-9,\.]* ' | cut -c 5- | while IFS= read -r "ip"; do
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
		echo "iplists.firehol.org"
		echo "astrill.com"
		echo "strongpath.net"
		nvram get ntp_server0
		nvram get ntp_server1
		nvram get firmware_server; } | awk '!x[$0]++' > /jffs/shared-Skynet2-whitelist
}

Whitelist_VPN () {
		ipset -q -A Whitelist "$(nvram get vpn_server1_sn)"/24 comment "nvram: vpn_server1_sn"
		ipset -q -A Whitelist "$(nvram get vpn_server2_sn)"/24 comment "nvram: vpn_server2_sn"
		ipset -q -A Whitelist "$(nvram get vpn_server_sn)"/24 comment "nvram: vpn_server_sn"
		ipset -q -A Whitelist "$(nvram get vpn_client1_addr)"/24 comment "nvram: vpn_client1_addr"
		ipset -q -A Whitelist "$(nvram get vpn_client2_addr)"/24 comment "nvram: vpn_client2_addr"
		ipset -q -A Whitelist "$(nvram get vpn_client3_addr)"/24 comment "nvram: vpn_client3_addr"
		ipset -q -A Whitelist "$(nvram get vpn_client4_addr)"/24 comment "nvram: vpn_client4_addr"
		ipset -q -A Whitelist "$(nvram get vpn_client5_addr)"/24 comment "nvram: vpn_client5_addr"
		if [ -f "/dev/astrill/openvpn.conf" ]; then ipset -q -A Whitelist "$(sed '\~remote ~!d;s~remote ~~' "/dev/astrill/openvpn.conf")"/24 comment "nvram: Astrill_VPN"; fi
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
		ipset -q -A Whitelist 192.168.1.0/24 comment "nvram: LAN Subnet"
		if [ -n "$(/usr/bin/find /jffs -name 'shared-*-whitelist')" ]; then
			echo "Whitelisting Shared Domains"
			sed '\~add Whitelist ~!d;\~Shared-Whitelist~!d;s~ comment.*~~;s~add~del~g' "${location}/scripts/ipset.txt" | ipset restore -!
			grep -hvF "#" /jffs/shared-*-whitelist | sed 's~http[s]*://~~;s~/.*~~' | awk '!x[$0]++' | while IFS= read -r "domain"; do
				for ip in $(Domain_Lookup "$domain" 2> /dev/null); do
					ipset -q -A Whitelist "$ip" comment "Shared-Whitelist: $domain"
				done &
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
			echo "$(awk '!x[$0]++' "${location}/skynet.log")" > "${location}/skynet.log"
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
		if iptables -t raw -C PREROUTING -i "$iface" -m set ! --match-set Whitelist src -m set --match-set Skynet src -j DROP 2>/dev/null; then
			hits1="$(iptables -xnvL -t raw | grep -Fv "LOG" | grep -F "Skynet src" | awk '{print $1}')"
			hits2="$(iptables -xnvL -t raw | grep -Fv "LOG" | grep -F "Skynet dst" | awk '{print $1}')"
		fi
		ftime="$(($(date +%s) - stime))"
		if [ "$1" = "minimal" ]; then
			$grn "$newips IPs / $newranges Ranges Banned. $((newips - oldips)) New IPs / $((newranges - oldranges)) New Ranges Banned. $hits1 Inbound / $hits2 Outbound Connections Blocked!"
		else
			logger -st Skynet "[Complete] $newips IPs / $newranges Ranges Banned. $((newips - oldips)) New IPs / $((newranges - oldranges)) New Ranges Banned. $hits1 Inbound / $hits2 Outbound Connections Blocked! [${ftime}s]"
		fi
}

####################################################################################################################################################
# -   unban / ban / banmalware / whitelist / import / deport / save / start / restart / disable / update / debug / stats / install / uninstall   - #
####################################################################################################################################################

Load_Menu () {
	echo "Router Model; $(nvram get productid)"
	echo "Skynet Version; $(Filter_Version "$0") ($(Filter_Date "$0"))"
	echo "$(iptables --version) - ($iface @ $(nvram get lan_ipaddr))"
	ipset -v
	echo "FW Version; $(nvram get buildno)_$(nvram get extendno) ($(uname -v | awk '{print $5" "$6" "$9}')) ($(uname -r))"
	echo "Install Dir; $location ($(df -h $location | xargs | awk '{print $9}') Space Available)"
	echo "Boot Args; $(grep -F "Skynet" /jffs/scripts/firewall-start 2>/dev/null | cut -c 4- | cut -d '#' -f1)"
	if grep -qF "Country:" "$location/scripts/ipset.txt" 2>/dev/null; then echo "Banned Countries; $(grep -m1 -F "Country:" "$location/scripts/ipset.txt" | sed 's~.*Country: ~~;s~"~~')"; fi
	if [ -f "/tmp/skynet.lock" ] && [ -d "/proc/$(sed -n '2p' /tmp/skynet.lock)" ]; then $red "Lock File Detected ($(sed -n '1p' /tmp/skynet.lock)) (pid=$(sed -n '2p' /tmp/skynet.lock))"; fi
	echo
	if ! grep -qF "Skynet" /jffs/scripts/firewall-start 2>/dev/null; then printf "Checking Firewall-Start Entry...			"; $red "[Failed]"; fi
	if ! iptables -t raw -C PREROUTING -i "$iface" -m set ! --match-set Whitelist src -m set --match-set Skynet src -j DROP 2>/dev/null; then printf "Checking Skynet IPTable...				"; $red "[Failed]"; NoLog="1"; fi
	if ! ipset -L -n Whitelist >/dev/null 2>&1; then printf "Checking Whitelist IPSet...				"; $red "[Failed]"; NoLog="1"; fi
	if ! ipset -L -n BlockedRanges >/dev/null 2>&1; then printf "Checking BlockedRanges IPSet...				"; $red "[Failed]"; NoLog="1"; fi
	if ! ipset -L -n Blacklist >/dev/null 2>&1; then printf "Checking Blacklist IPSet...				"; $red "[Failed]"; NoLog="1"; fi
	if ! ipset -L -n Skynet >/dev/null 2>&1; then printf "Checking Skynet IPSet...				"; $red "[Failed]"; NoLog="1"; fi
	if [ -z "$NoLog" ]; then Logging minimal; fi
	echo
	while true; do
		echo "Select Menu Option:"
		echo "[1]  --> Unban"
		echo "[2]  --> Ban"
		echo "[3]  --> Banmalware"
		echo "[4]  --> Whitelist"
		echo "[5]  --> Import IP List"
		echo "[6]  --> Deport IP List"
		echo "[7]  --> Save"
		echo "[8]  --> Restart Skynet"
		echo "[9]  --> Temporarily Disable Skynet"
		echo "[10] --> Update Skynet"
		echo "[11] --> Debug Options"
		echo "[12] --> Stats"
		echo "[13] --> Install Skynet / Change Boot Options"
		echo "[14] --> Uninstall"
		echo
		echo "[e]  --> Exit Menu"
		echo
		printf "[1-13]: "
		read -r "menu"
		echo
		case "$menu" in
			1)
				option1="unban"
				while true; do
					echo "What Type Of Input Would You Like To Unban:"
					echo "[1]  --> IP"
					echo "[2]  --> Range"
					echo "[3]  --> Domain"
					echo "[4]  --> Port"
					echo "[5]  --> Comment"
					echo "[6]  --> Country"
					echo "[7]  --> Malware"
					echo "[8]  --> Autobans"
					echo "[9]  --> Non Manual Bans"
					echo "[10] --> All"
					echo
					printf "[1-10]: "
					read -r "menu2"
					echo
					case "$menu2" in
						1)
							option2="ip"
							echo "Input IP To Unban:"
							echo
							printf "[IP]: "
							read -r "option3"
							echo
							if ! echo "$option3" | Is_IP; then echo "$option3 Is Not A Valid IP"; echo; continue; fi
							break
						;;
						2)
							option2="range"
							echo "Input Range To Unban:"
							echo
							printf "[Range]: "
							read -r "option3"
							echo
							if ! echo "$option3" | Is_Range; then echo "$option3 Is Not A Valid Range"; echo; continue; fi
							break
						;;
						3)
							option2="domain"
							echo "Input Domain To Unban:"
							echo
							printf "[URL]: "
							read -r "option3"
							echo
							if [ -z "$option3" ]; then echo "URL Field Can't Be Empty - Please Try Again"; echo; continue; fi
							break
						;;
						4)
							option2="port"
							echo "Remove Autobans Based On Port:"
							echo
							printf "[Port]: "
							read -r "option3"
							echo
							if ! echo "$option3" | Is_Port; then echo "$option3 Is Not A Valid Port"; echo; continue; fi
							break
						;;
						5)
							option2="comment"
							echo "Remove Bans Matching Comment:"
							echo
							printf "[Comment]: "
							read -r "option3"
							echo
							if [ "${#option3}" -gt "255" ]; then echo "$option3 Is Not A Valid Comment. 255 Chars Max"; echo; continue; fi
							break
						;;
						6)
							option2="country"
							break
						;;
						7)
							option2="malware"
							break
						;;
						8)
							option2="autobans"
							break
						;;
						9)
							option2="nomanual"
							break
						;;
						10)
							option2="all"
							break
						;;
						e|exit|back|menu)
							unset "$option1" "$option2" "$option3" "$option4" "$option5"
							clear
							Load_Menu
							break
						;;
						*)
							echo "$menu2 Isn't An Option!"
							echo
						;;
					esac
				done
				break
			;;
			2)
				option1="ban"
				while true; do
					echo "What Type Of Input Would You Like To Ban:"
					echo "[1] --> IP"
					echo "[2] --> Range"
					echo "[3] --> Domain"
					echo "[4] --> Country"
					echo
					printf "[1-4]: "
					read -r "menu2"
					echo
					case "$menu2" in
						1)
							option2="ip"
							echo "Input IP To Ban:"
							echo
							printf "[IP]: "
							read -r "option3"
							echo
							if ! echo "$option3" | Is_IP; then echo "$option3 Is Not A Valid IP"; echo; continue; fi
							echo "Input Comment For Ban:"
							echo
							printf "[Comment]: "
							read -r "option4"
							echo
							if [ "${#option4}" -gt "255" ]; then echo "$option4 Is Not A Valid Comment. 255 Chars Max"; echo; continue; fi
							break
						;;
						2)
							option2="range"
							echo "Input Range To Ban:"
							echo
							printf "[Range]: "
							read -r "option3"
							echo
							if ! echo "$option3" | Is_Range; then echo "$option3 Is Not A Valid Range"; echo; continue; fi
							echo "Input Comment For Ban:"
							echo
							printf "[Comment]: "
							read -r "option4"
							echo
							if [ "${#option3}" -gt "255" ]; then echo "$option3 Is Not A Valid Comment. 255 Chars Max"; echo; continue; fi
							break
						;;
						3)
							option2="domain"
							echo "Input Domain To Ban:"
							echo
							printf "[URL]: "
							read -r "option3"
							echo
							if [ -z "$option3" ]; then echo "URL Field Can't Be Empty - Please Try Again"; echo; continue; fi
							break
						;;
						4)
							option2="country"
							echo "Input Country Abbreviations To Ban:"
							echo
							printf "[Countries]: "
							read -r "option3"
							echo
							break
						;;
						e|exit|back|menu)
							unset "$option1" "$option2" "$option3" "$option4" "$option5"
							clear
							Load_Menu
							break
						;;
						*)
							echo "$menu2 Isn't An Option!"
							echo
						;;
					esac
				done
				break
			;;
			3)
				option1="banmalware"
				while true; do
					echo "Select Filter List:"
					echo "[1] --> Default"
					echo "[2] --> Custom"
					echo
					printf "[1-2]: "
					read -r "menu2"
					echo
					case "$menu2" in
						1)
							break
						;;
						2)
							echo "Input Custom Filter List URL:"
							printf "[URL]: "
							read -r "option2"
							echo
							if [ -z "$option2" ]; then echo "URL Field Can't Be Empty - Please Try Again"; echo; continue; fi
							break
						;;
						e|exit|back|menu)
							unset "$option1" "$option2" "$option3" "$option4" "$option5"
							clear
							Load_Menu
							break
						;;
						*)
							echo "$menu2 Isn't An Option!"
							echo
						;;
					esac
				done
				break
			;;
			4)
				option1="whitelist"
				while true; do
					echo "Select Whitelist Option:"
					echo "[1]  --> IP/Range"
					echo "[2]  --> Domain"
					echo "[3]  --> Port"
					echo "[4]  --> Refresh VPN Whitelist"
					echo "[5]  --> Remove Entries"
					echo "[6]  --> Refresh Entries"
					echo "[7]  --> List Entries"
					echo
					printf "[1-7]: "
					read -r "menu2"
					echo
					case "$menu2" in
						1)
							option2="ip"
							echo "Input IP Or Range To Whitelist:"
							echo
							printf "[IP/Range]: "
							read -r "option3"
							echo
							if ! echo "$option3" | Is_IP && ! echo "$option3" | Is_Range ; then echo "$option3 Is Not A Valid IP/Range"; echo; continue; fi
							echo "Input Comment For Whitelist:"
							echo
							printf "[Comment]: "
							read -r "option4"
							echo
							if [ "${#option4}" -gt "255" ]; then echo "$option4 Is Not A Valid Comment. 255 Chars Max"; echo; continue; fi
							break
						;;
						2)
							option2="domain"
							echo "Input Domain To Whitelist:"
							echo
							printf "[URL]: "
							read -r "option3"
							echo
							if [ -z "$option3" ]; then echo "URL Field Can't Be Empty - Please Try Again"; echo; continue; fi
							break
						;;
						3)
							option2="port"
							echo "Whitelist Autobans Based On Port:"
							echo
							printf "[Port]: "
							read -r "option3"
							echo
							if ! echo "$option3" | Is_Port; then echo "$option3 Is Not A Valid Port"; echo; continue; fi
							break
						;;
						4)
							option2="vpn"
							break
						;;
						5)
							option2="remove"
							while true; do
								echo "Remove From Whitelist:"
								echo "[1]  --> All Non-Default Entries"
								echo "[2]  --> IP/Range"
								echo "[3]  --> Entries Matching Comment"
								echo
								printf "[1-3]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										break
									;;
									2)
										option3="entry"
										echo "Input IP Or Range To Remove:"
										echo
										printf "[IP/Range]: "
										read -r "option4"
										echo
										if ! echo "$option4" | Is_IP && ! echo "$option4" | Is_Range ; then echo "$option4 Is Not A Valid IP/Range"; echo; continue; fi
										break
									;;
									3)
										option3="comment"
										echo "Remove Entries Based On Comment:"
										echo
										printf "[Comment]: "
										read -r "option4"
										echo
										if [ "${#option4}" -gt "255" ]; then echo "$option4 Is Not A Valid Comment. 255 Chars Max"; echo; continue; fi
										break
									;;
									e|exit|back|menu)
										unset "$option1" "$option2" "$option3" "$option4" "$option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "$menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						6)
							option2="refresh"
							break
						;;
						7)
							option2="list"
							while true; do
								echo "Select Entries To List:"
								echo "[1]  --> All"
								echo "[2]  --> Manually Added IPs"
								echo "[3]  --> Manually Added Domains"
								echo
								printf "[1-3]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										break
									;;
									2)
										option3="ips"
										break
									;;
									3)
										option3="domains"
										break
									;;
									e|exit|back|menu)
										unset "$option1" "$option2" "$option3" "$option4" "$option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "$menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						e|exit|back|menu)
							unset "$option1" "$option2" "$option3" "$option4" "$option5"
							clear
							Load_Menu
							break
						;;
						*)
							echo "$menu2 Isn't An Option!"
							echo
						;;
					esac
				done
				break
			;;
			5)
				option1="import"
				echo "Input URL To Import"
				echo
				printf "[URL]: "
				read -r "option2"
				echo
				if [ -z "$option2" ]; then echo "URL Field Can't Be Empty - Please Try Again"; echo; continue; fi
				break
			;;
			6)
				option1="deport"
				echo "Input URL To Deport"
				echo
				printf "[URL]: "
				read -r "option2"
				echo
				if [ -z "$option2" ]; then echo "URL Field Can't Be Empty - Please Try Again"; echo; continue; fi
				break
			;;
			7)
				option1="save"
				break
			;;
			8)
				option1="restart"
				break
			;;
			9)
				option1="disable"
				break
			;;
			10)
				option1="update"
				while true; do
					echo "Select Update Option:"
					echo "[1]  --> Check For And Install Any New Updates"
					echo "[2]  --> Check For Updates Only"
					echo "[3]  --> Force Update Even If No Updates Detected"
					echo
					printf "[1-3]: "
					read -r "menu2"
					echo
					case "$menu2" in
						1)
							break
						;;
						2)
							option2="check"
							break
						;;
						3)
							option2="-f"
							break
						;;
						e|exit|back|menu)
							unset "$option1" "$option2" "$option3" "$option4" "$option5"
							clear
							Load_Menu
							break
						;;
						*)
							echo "$menu2 Isn't An Option!"
							echo
						;;
					esac
				done
				break
			;;
			11)
				option1="debug"
				while true; do
					echo "Select Debug Option:"
					echo "[1]  --> Temporarily Disable Debug Output"
					echo "[2]  --> Show Debug Entries As They Appear"
					echo "[3]  --> Print Debug Info"
					echo "[4]  --> Cleanup Syslog Entries"
					echo
					printf "[1-4]: "
					read -r "menu2"
					echo
					case "$menu2" in
						1)
							option2="disable"
							break
						;;
						2)
							option2="watch"
							break
						;;
						3)
							option2="info"
							break
						;;
						4)
							option2="clean"
							break
						;;
						e|exit|back|menu)
							unset "$option1" "$option2" "$option3" "$option4" "$option5"
							clear
							Load_Menu
							break
						;;
						*)
							echo "$menu2 Isn't An Option!"
							echo
						;;
					esac
				done
				break
			;;
			12)
				option1="stats"
				while true; do
					echo "Select Stat Option:"
					echo "[1]  --> Display"
					echo "[2]  --> Search"
					echo "[3]  --> Reset"
					echo
					printf "[1-3]: "
					read -r "menu2"
					echo
					case "$menu2" in
						1)
							while true; do
								echo "Show Top x Results:"
								echo "[1]  --> 10"
								echo "[2]  --> 20"
								echo "[3]  --> 50"
								echo "[4]  --> Custom"
								echo
								printf "[1-4]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										option3="10"
										break
									;;
									2)
										option3="20"
										break
									;;
									3)
										option3="50"
										break
									;;
									4)
										echo "Enter Custom Amount:"
										echo
										printf "[Number]: "
										read -r "option3"
										echo
										if ! [ "$option3" -eq "$option3" ] 2>/dev/null; then echo "$option3 Isn't A Valid Number!"; echo; continue; fi
										break
									;;
									e|exit|back|menu)
										unset "$option1" "$option2" "$option3" "$option4" "$option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "$menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							while true; do
								echo "Show Packet Type:"
								echo "[1]  --> All"
								echo "[2]  --> TCP"
								echo "[3]  --> UDP"
								echo "[4]  --> ICMP"
								echo
								printf "[1-4]: "
								read -r "menu4"
								echo
								case "$menu4" in
									1)
										break
									;;
									2)
										option2="tcp"
										break
									;;
									3)
										option2="udp"
										break
									;;
									4)
										option2="icmp"
										break
									;;
									e|exit|back|menu)
										unset "$option1" "$option2" "$option3" "$option4" "$option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "$menu4 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						2)
							option2="search"
							while true; do
								echo "Show Top x Results:"
								echo "[1]  --> 10"
								echo "[2]  --> 20"
								echo "[3]  --> 50"
								echo "[4]  --> Custom"
								echo
								printf "[1-4]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										option5="10"
										break
									;;
									2)
										option5="20"
										break
									;;
									3)
										option5="50"
										break
									;;
									4)
										echo "Enter Custom Amount:"
										echo
										printf "[Number]: "
										read -r "option5"
										echo
										if ! [ "$option5" -eq "$option5" ] 2>/dev/null; then echo "$option5 Isn't A Valid Number!"; echo; continue; fi
										break
									;;
									e|exit|back|menu)
										unset "$option1" "$option2" "$option3" "$option4" "$option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "$menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							while true; do
								echo "Search Options: "
								echo "[1]  --> Based On Port x"
								echo "[2]  --> Entries From Specific IP"
								echo "[3]  --> Search Malwarelists For IP"
								echo "[4]  --> Search Autobans"
								echo "[5]  --> Search Manualbans"
								echo
								printf "[1-5]: "
								read -r "menu4"
								echo
								case "$menu4" in
									1)
										option3="port"
										printf "[Port]: "
										read -r "option4"
										echo
										if ! echo "$option4" | Is_Port; then echo "$option4 Is Not A Valid Port"; echo; continue; fi
										break
									;;
									2)
										option3="ip"
										printf "[IP]: "
										read -r "option4"
										echo
										if ! echo "$option4" | Is_IP && ! echo "$option4" | Is_Range ; then echo "$option4 Is Not A Valid IP/Range"; echo; continue; fi
										break
									;;
									3)
										option3="malware"
										printf "[IP]: "
										read -r "option4"
										echo
										if ! echo "$option4" | Is_IP && ! echo "$option4" | Is_Range ; then echo "$option4 Is Not A Valid IP/Range"; echo; continue; fi
										break
									;;
									4)
										option3="autobans"
										break
									;;
									5)
										option3="manualbans"
										break
									;;
									e|exit|back|menu)
										unset "$option1" "$option2" "$option3" "$option4" "$option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "$menu4 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						3)
							option2="reset"
							break
						;;
						e|exit)
							unset "$option1" "$option2" "$option3" "$option4" "$option5"
							clear
							Load_Menu
							break
						;;
						*)
							echo "$menu2 Isn't An Option!"
							echo
						;;
					esac
				done
				break
			;;
			13)
				option1="install"
				break
			;;
			14)
				option1="uninstall"
				break
			;;
			e)
				echo "Exiting!"
				exit 0
			;;
			*)
				echo "$menu Isn't An Option!"
				echo
			;;
		esac
	done
}

if [ -z "$1" ]; then
	Load_Menu
fi

if [ -n "$option1" ]; then
	set "$option1" "$option2" "$option3" "$option4" "$option5"
fi

case "$1" in
	unban)
		Purge_Logs
		case "$2" in
			ip)
				if ! echo "$3" | Is_IP; then echo "$3 Is Not A Valid IP"; echo; exit 2; fi
				echo "Unbanning $3"
				ipset -D Blacklist "$3"
				sed -i "\\~$3 ~d" "${location}/skynet.log"
			;;
			range)
				if ! echo "$3" | Is_Range; then echo "$3  Is Not A Valid Range"; echo; exit 2; fi
				echo "Unbanning $3"
				ipset -D BlockedRanges "$3"
				sed -i "\\~$3 ~d" "${location}/skynet.log"
			;;
			domain)
				if [ -z "$3" ]; then echo "Domain Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				logger -st Skynet "[INFO] Removing $3 From Blacklist..."
				for ip in $(Domain_Lookup "$3"); do
					echo "Unbanning $ip"
					ipset -D Blacklist "$ip"
					sed -i "\\~$ip ~d" "${location}/skynet.log"
				done
			;;
			port)
				if ! echo "$3" | Is_Port; then echo "$3 Is Not A Valid Port"; echo; exit 2; fi
				logger -st Skynet "[INFO] Unbanning Autobans Issued On Traffic From Source/Destination Port $3..."
				grep -F "NEW" "${location}/skynet.log" | grep -F "PT=$3 " | grep -oE 'SRC=[0-9,\.]* ' | cut -c 5- | while IFS= read -r "ip"; do
					echo "Unbanning $ip"
					ipset -D Blacklist "$ip"
				done
				sed -i "/PT=${3} /d" "${location}/skynet.log"
			;;
			comment)
				if [ -z "$3" ]; then echo "Comment Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				echo "Removing Bans With Comment Containing ($3)"
				sed "\\~add Whitelist ~d;\\~$3~!d;s~ comment.*~~;s~add~del~g" "${location}/scripts/ipset.txt" | ipset restore -!
				sed "\\~add Whitelist ~d;\\~$3~!d;s~ comment.*~~" "${location}/scripts/ipset.txt" | cut -d' ' -f3 | while IFS= read -r "ip"; do
					echo "Unbanning $ip"
					sed -i "\\~$ip ~d" "${location}/skynet.log"
				done
			;;
			country)
				echo "Removing Previous Country Bans"
				sed '\~add Whitelist ~d;\~Country: ~!d;s~ comment.*~~;s~add~del~g' "${location}/scripts/ipset.txt" | ipset restore -!
			;;
			malware)
				echo "Removing Previous Malware Bans"
				sed '\~add Whitelist ~d;\~BanMalware~!d;s~ comment.*~~;s~add~del~g' "${location}/scripts/ipset.txt" | ipset restore -!
			;;
			autobans)
				grep -F "NEW" "${location}/skynet.log" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | tr -d " " | while IFS= read -r "ip"; do
					echo "Unbanning $ip"
					ipset -D Blacklist "$ip"
					sed -i "\\~$ip ~d" "${location}/skynet.log"
				done
			;;
			nomanual)
				sed -i '/Manual /!d' "${location}/skynet.log"
				ipset flush Blacklist
				ipset flush BlockedRanges
				sed '\~add Whitelist ~d;\~Manual[R]*Ban: ~!d' "${location}/scripts/ipset.txt" | ipset restore -!
				iptables -Z PREROUTING -t raw
			;;
			all)
				logger -st Skynet "[INFO] Removing All $(($(sed -n '1p' /tmp/counter.txt) + $(sed -n '2p' /tmp/counter.txt))) Entries From Blacklist..."
				ipset flush Blacklist
				ipset flush BlockedRanges
				iptables -Z PREROUTING -t raw
				true > "${location}/skynet.log"
			;;
			*)
				echo "Command Not Recognised, Please Try Again"
				echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
				echo; exit 2
			;;
		esac
		Save_IPSets
		echo
	;;

	ban)
		Purge_Logs
		case "$2" in
			ip)
				if ! echo "$3" | Is_IP; then echo "$3 Is Not A Valid IP"; echo; exit 2; fi
				if [ "${#4}" -gt "255" ]; then echo "$4 Is Not A Valid Comment. 255 Chars Max"; echo; exit 2; fi
				echo "Banning $3"
				desc="$4"
				if [ -z "$4" ]; then
					desc="$(date +"%b %d %T")"
				fi
				ipset -A Blacklist "$3" comment "ManualBan: $desc" && echo "$(date +"%b %d %T") Skynet: [Manual Ban] TYPE=Single SRC=$3 COMMENT=$4 " >> "${location}/skynet.log"
			;;
			range)
				if ! echo "$3" | Is_Range; then echo "$3 Is Not A Valid Range"; echo; exit 2; fi
				if [ "${#4}" -gt "255" ]; then echo "$4 Is Not A Valid Comment. 255 Chars Max"; echo; exit 2; fi
				echo "Banning $3"
				desc="$4"
				if [ -z "$4" ]; then
					desc="$(date +"%b %d %T")"
				fi
				ipset -A BlockedRanges "$3" comment "ManualRBan: $desc" && echo "$(date +"%b %d %T") Skynet: [Manual Ban] TYPE=Range SRC=$3 COMMENT=$4 " >> "${location}/skynet.log"
			;;
			domain)
				if [ -z "$3" ]; then echo "Domain Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				logger -st Skynet "[INFO] Adding $3 To Blacklist..."
				for ip in $(Domain_Lookup "$3"); do
					echo "Banning $ip"
					ipset -A Blacklist "$ip" comment "ManualBan: $3" && echo "$(date +"%b %d %T") Skynet: [Manual Ban] TYPE=Domain SRC=$ip Host=$3 " >> "${location}/skynet.log"
				done
			;;
			country)
				if [ -z "$3" ]; then echo "Country Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				echo "Removing Previous Country Bans"
				sed '\~add Whitelist ~d;\~Country: ~!d;s~ comment.*~~;s~add~del~g' "${location}/scripts/ipset.txt" | ipset restore -!
				echo "Banning Known IP Ranges For $3"
				echo "Downloading Lists"
				for country in $3; do
					/usr/sbin/curl -fs http://ipdeny.com/ipblocks/data/aggregated/"$country"-aggregated.zone >> /tmp/countrylist.txt
				done
				echo "Filtering IPv4 Ranges & Applying Blacklists"
				grep -F "/" /tmp/countrylist.txt | sed -n "s/\\r//;/^$/d;/^[0-9,\\.,\\/]*$/s/^/add BlockedRanges /p" | sed "s/$/& comment \"Country: $3\"/" | ipset restore -!
				rm -rf "/tmp/countrylist.txt"
			;;
			*)
				echo "Command Not Recognised, Please Try Again"
				echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
				echo; exit 2
			;;
		esac
		Save_IPSets
		echo
	;;

	banmalware)
		trap '' 2
		if [ -n "$2" ]; then
			listurl="$2"
			echo "Custom List Detected: $2"
		else
			listurl="https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/filter.list"
		fi
		/usr/sbin/curl -fs "$listurl" >/dev/null 2>&1 || { logger -st Skynet "[ERROR] 404 Error Detected - Stopping Banmalware" ; exit 1; }
		Check_Lock "$@"
		btime="$(date +%s)" && printf "Downloading filter.list 	"
		/usr/sbin/curl -fs "$listurl" -o /jffs/shared-Skynet-whitelist && $grn "[$(($(date +%s) - btime))s]"
		btime="$(date +%s)" && printf "Whitelisting Shared Domains 	"
		Whitelist_Extra
		Whitelist_VPN
		Whitelist_Shared >/dev/null 2>&1 && $grn "[$(($(date +%s) - btime))s]"
		btime="$(date +%s)" && printf "Consolidating Blacklist 	"
		mkdir -p /tmp/skynet
		cd /tmp/skynet || exit 1
		case "$(nvram get model)" in
			AC-86U) # AC86U Fork () Patch
				sync && echo 3 > /proc/sys/vm/drop_caches
				while IFS= read -r "domain"; do
					/usr/sbin/curl -fs "$domain" -O
				done < /jffs/shared-Skynet-whitelist
				wait
			;;
			*)
				while IFS= read -r "domain"; do
					/usr/sbin/curl -fs "$domain" -O &
				done < /jffs/shared-Skynet-whitelist
				wait
			;;
		esac
		cd /tmp/home/root || exit 1
		cat /tmp/skynet/* | sed -n "s/\\r//;/^$/d;/^[0-9,\\.,\\/]*$/p" | awk '!x[$0]++' | Filter_PrivateIP > /tmp/skynet/malwarelist.txt && $grn "[$(($(date +%s) - btime))s]"
		btime="$(date +%s)" && printf "Saving Changes 			"
		Save_IPSets >/dev/null 2>&1 && $grn "[$(($(date +%s) - btime))s]"
		btime="$(date +%s)" && printf "Removing Previous Malware Bans  "
		sed -i "\\~comment \"BanMalware\"~d" "${location}/scripts/ipset.txt"
		ipset flush Blacklist; ipset flush BlockedRanges
		ipset restore -! -f "${location}/scripts/ipset.txt" && $grn "[$(($(date +%s) - btime))s]"
		btime="$(date +%s)" && printf "Filtering IPv4 Addresses 	"
		grep -vF "/" /tmp/skynet/malwarelist.txt | awk '{print "add Blacklist " $1 " comment \"BanMalware\""}' >> "${location}/scripts/ipset.txt" && $grn "[$(($(date +%s) - btime))s]"
		btime="$(date +%s)" && printf "Filtering IPv4 Ranges 		"
		grep -F "/" /tmp/skynet/malwarelist.txt | awk '{print "add BlockedRanges " $1 " comment \"BanMalware\""}' >> "${location}/scripts/ipset.txt" && $grn "[$(($(date +%s) - btime))s]"
		btime="$(date +%s)" && printf "Applying Blacklists 		"
		ipset restore -! -f "${location}/scripts/ipset.txt" && $grn "[$(($(date +%s) - btime))s]"
		echo
		echo "For False Positive Website Bans Use; ( sh $0 whitelist domain URL )"
		rm -rf /tmp/skynet.lock
		rm -rf /tmp/skynet
		echo
	;;

	whitelist)
		Purge_Logs
		case "$2" in
			ip|range)
				if ! echo "$3" | Is_IP && ! echo "$3" | Is_Range ; then echo "$3 Is Not A Valid IP/Range"; echo; exit 2; fi
				if [ "${#4}" -gt "255" ]; then echo "$4 Is Not A Valid Comment. 255 Chars Max"; echo; exit 2; fi
				echo "Whitelisting $3"
				desc="$4"
				if [ -z "$4" ]; then
					desc="$(date +"%b %d %T")"
				fi
				ipset -A Whitelist "$3" comment "ManualWlist: $desc"
				ipset -q -D Blacklist "$3"
				ipset -q -D BlockedRanges "$3"
				sed -i "\\~$3 ~d" "${location}/skynet.log"
			;;
			domain)
				if [ -z "$3" ]; then echo "Domain Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				logger -st Skynet "[INFO] Adding $3 To Whitelist..."
				for ip in $(Domain_Lookup "$3"); do
					echo "Whitelisting $ip"
					ipset -A Whitelist "$ip" comment "ManualWlistD: $3"
					ipset -q -D Blacklist "$ip"
					sed -i "\\~$ip ~d" "${location}/skynet.log"
				done
			;;
			port)
				if ! echo "$3" | Is_Port; then echo "$3 Is Not A Valid Port"; echo; exit 2; fi
				logger -st Skynet "[INFO] Whitelisting Autobans Issued On Traffic From Port $3..."
				grep -F "NEW" "${location}/skynet.log" | grep -F "DPT=$3 " | grep -oE 'SRC=[0-9,\.]* ' | cut -c 5- | while IFS= read -r "ip"; do
					echo "Whitelisting $ip"
					ipset -A Whitelist "$ip" comment "ManualWlist: Port $3 Traffic"
					ipset -q -D Blacklist "$ip"
					sed -i "\\~$ip ~d" "${location}/skynet.log"
				done
			;;
			vpn)
				logger -st Skynet "[INFO] Updating VPN Whitelist..."
				Whitelist_VPN
			;;
			remove)
				case "$3" in
					entry)
						if ! echo "$4" | Is_IP && ! echo "$4" | Is_Range ; then echo "$4 Is Not A Valid IP/Range"; echo; exit 2; fi
						echo "Removing $4 From Whitelist"
						ipset -D Whitelist "$4"
					;;
					comment)
						if [ -z "$4" ]; then echo "Comment Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
						echo "Removing All Entries With Comment Matching \"$4\" From Whitelist"
						sed "\\~add Whitelist ~!d;\\~$4~!d;s~ comment.*~~;s~add~del~g" "${location}/scripts/ipset.txt" | ipset restore -!
					;;
					*)
						echo "Flushing Whitelist"
						ipset flush Whitelist
						echo "Adding Default Entries"
						true > "${location}/scripts/ipset.txt"
						Whitelist_Extra
						Whitelist_VPN
						Whitelist_Shared
					;;
				esac
			;;
			refresh)
				echo "Refreshing Shared Whitelist Files"
				Whitelist_Extra
				Whitelist_VPN
				Whitelist_Shared
			;;
			list)
				case "$3" in
					ips)
						sed '\~add Whitelist ~!d;\~ManualWlist:~!d;s~add Whitelist ~~' "${location}/scripts/ipset.txt"
					;;
					domains)
						sed '\~add Whitelist ~!d;\~ManualWlistD:~!d;s~add Whitelist ~~' "${location}/scripts/ipset.txt"
					;;
					*)
						sed '\~add Whitelist ~!d;s~add Whitelist ~~' "${location}/scripts/ipset.txt"
					;;
				esac
			;;
			*)
				echo "Command Not Recognised, Please Try Again"
				echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
				echo; exit 2
			;;
		esac
		Save_IPSets
		echo
	;;

	import)
		echo "This Function Extracts All IPs And Adds Them ALL To Blacklist"
		if [ -n "$2" ]; then
			Check_Lock "$@"
			echo "Custom List Detected: $2"
			/usr/sbin/curl -fs "$2" -o /tmp/iplist-unfiltered.txt  || { logger -st Skynet "[ERROR] 404 Error Detected - Stopping Import" ; exit 1; }
		else
			echo "URL Field Can't Be Empty - Please Try Again"
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
		echo
	;;

	deport)
		echo "This Function Extracts All IPs And Removes Them ALL From Blacklist"
		if [ -n "$2" ]; then
			Check_Lock "$@"
			echo "Custom List Detected: $2"
			/usr/sbin/curl -fs "$2" -o /tmp/iplist-unfiltered.txt  || { logger -st Skynet "[ERROR] 404 Error Detected - Stopping Deport" ; exit 1; }
		else
			echo "URL Field Can't Be Empty - Please Try Again"
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
		rm -rf /tmp/skynet.lock
		echo
	;;

	save)
		Check_Lock "$@"
		Unban_PrivateIP
		Purge_Logs
		Save_IPSets
		sed -i "\\~USER $(nvram get http_username) pid .*/jffs/scripts/firewall ~d" /tmp/syslog.log
		rm -rf /tmp/skynet.lock
		echo
	;;

	start)
		trap '' 2
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
		Whitelist_VPN
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
		trap '' 2
		remoteurl="https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh"
		/usr/sbin/curl -fs "$remoteurl" >/dev/null 2>&1 || { logger -st Skynet "[ERROR] 404 Error Detected - Stopping Update" ; exit 1; }
		localver="$(Filter_Version "$0")"
		remotever="$(/usr/sbin/curl -fs "$remoteurl" | Filter_Version)"
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
			/usr/sbin/curl -fs "$remoteurl" -o "$0" && logger -st Skynet "[INFO] Skynet Sucessfully Updated - Restarting Firewall"
			rm -rf /tmp/skynet.lock
			service restart_firewall
			exit 0
		fi
	;;

	debug)
		case "$2" in
			disable)
				logger -st Skynet "[INFO] Temporarily Disabling Debug Output..."
				Unload_DebugIPTables
				Purge_Logs
			;;
			watch)
				Purge_Logs
				trap 'echo; echo "Stopping Log Monitoring"; Purge_Logs' 2
				echo "Watching Logs For Debug Entries (ctrl +c) To Stop"
				echo
				tail -F /tmp/syslog.log | grep -F "BLOCKED"
			;;
			info)
				echo "Router Model; $(nvram get productid)"
				echo "Skynet Version; $(Filter_Version "$0") ($(Filter_Date "$0"))"
				echo "$(iptables --version) - ($iface @ $(nvram get lan_ipaddr))"
				ipset -v
				echo "FW Version; $(nvram get buildno)_$(nvram get extendno) ($(uname -v | awk '{print $5" "$6" "$9}')) ($(uname -r))"
				echo "Install Dir; $location ($(df -h $location | xargs | awk '{print $9}') Space Available)"
				echo "Boot Args; $(grep -F "Skynet" /jffs/scripts/firewall-start | cut -c 4- | cut -d '#' -f1)"
				if grep -qF "Country:" "$location/scripts/ipset.txt"; then echo "Banned Countries; $(grep -m1 -F "Country:" "$location/scripts/ipset.txt" | sed 's~.*Country: ~~;s~"~~')"; fi
				if [ -f "/tmp/skynet.lock" ] && [ -d "/proc/$(sed -n '2p' /tmp/skynet.lock)" ]; then $red "Lock File Detected ($(sed -n '1p' /tmp/skynet.lock)) (pid=$(sed -n '2p' /tmp/skynet.lock))"; else $grn "No Lock File Found"; fi
				echo
				printf "Checking Install Directory Write Permissions...		"
				if [ -w "$location" ]; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking Firewall-Start Entry...			"
				if grep -qF "Skynet" /jffs/scripts/firewall-start; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking OpenVPN-Event Entry...				"
				if grep -qF "Skynet" /jffs/scripts/openvpn-event; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking CronJobs...					"
				if cru l | grep -qF "Skynet"; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking IPSet Comment Support...			"
				if [ -f /lib/modules/"$(uname -r)"/kernel/net/netfilter/ipset/ip_set_hash_ipmac.ko ] || [ -d /lib/modules/4.1.27 ]; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking Log Level %s Settings...			" "$(nvram get message_loglevel)"
				if [ "$(nvram get message_loglevel)" -le "$(nvram get log_level)" ]; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking Autobanning Status...				"
				if iptables -C logdrop -i "$iface" -m state --state INVALID -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking Debug Mode Status...				"
				if iptables -t raw -C PREROUTING -i "$iface" -m set ! --match-set Whitelist src -m set --match-set Skynet src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking For Duplicate Rules In RAW...			"
				if [ "$(iptables-save -t raw | sort | uniq -d | grep -c " ")" = "0" ]; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking For Duplicate Rules In Filter...		"
				if [ "$(iptables-save -t filter | sort | uniq -d | grep -c " ")" = "0" ]; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking Skynet IPTable...				"
				if iptables -t raw -C PREROUTING -i "$iface" -m set ! --match-set Whitelist src -m set --match-set Skynet src -j DROP 2>/dev/null; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking Whitelist IPSet...				"
				if ipset -L -n Whitelist >/dev/null 2>&1; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking BlockedRanges IPSet...				"
				if ipset -L -n BlockedRanges >/dev/null 2>&1; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking Blacklist IPSet...				"
				if ipset -L -n Blacklist >/dev/null 2>&1; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking Skynet IPSet...				"
				if ipset -L -n Skynet >/dev/null 2>&1; then $grn "[Passed]"; else $red "[Failed]"; fi
			;;
			clean)
				echo "Cleaning Syslog Entries..."
				Purge_Logs
				sed -i "\\~Skynet: ~d" /tmp/syslog.log 2>/dev/null; sed -i "\\~Skynet: ~d" /tmp/syslog.log-1 2>/dev/null
				echo "Complete!"
				echo
				exit 0
			;;
			*)
				echo "Command Not Recognised, Please Try Again"
				echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
				echo; exit 2
			;;
		esac
		echo
	;;

	stats)
		Purge_Logs
		if ! grep -F "Skynet" /jffs/scripts/firewall-start | grep -qF "debug"; then
			echo
			$red "!!! Debug Mode Is Disabled !!!"
			$red "To Enable Use ( sh $0 install )"
			echo
		fi
		if [ -s "${location}/skynet.log" ]; then
			echo "Debug Data Detected in ${location}/skynet.log - $(du -h ${location}/skynet.log | awk '{print $1}')"
		else
			echo "No Debug Data Detected - Give This Time To Generate"
			exit 0
		fi
		echo "Monitoring From $(grep -m1 -E 'INBOUND|OUTBOUND' ${location}/skynet.log | awk '{print $1" "$2" "$3}') To $(grep -E 'INBOUND|OUTBOUND' ${location}/skynet.log | tail -1 | awk '{print $1" "$2" "$3}')"
		echo "$(grep -Ec ".*BOUND" ${location}/skynet.log) Block Events Detected"
		echo "$({ grep -F "INBOUND" ${location}/skynet.log | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- ; grep -F "OUTBOUND" ${location}/skynet.log | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- ; } | awk '!x[$0]++' | wc -l) Unique IPs"
		echo "$(grep -Fc "NEW BAN" ${location}/skynet.log) Autobans Issued"
		echo "$(grep -Fc "Manual Ban" ${location}/skynet.log) Manual Bans Issued"
		echo
		counter=10
		case "$2" in
			reset)
				sed -i '/BLOCKED - .*BOUND/d' "${location}/skynet.log"
				echo "$(awk '!x[$0]++' "${location}/skynet.log")" > "${location}/skynet.log"
				iptables -Z PREROUTING -t raw
				echo "Stat Data Reset"
			;;
			search)
				case "$3" in
					port)
						if ! echo "$4" | Is_Port; then echo "$4 Is Not A Valid Port"; echo; exit 2; fi
						if [ "$5" -eq "$5" ] 2>/dev/null; then counter="$5"; fi
						echo "Port $4 First Tracked On $(grep -m1 -F "PT=$4 " ${location}/skynet.log | awk '{print $1" "$2" "$3}')"
						echo "Port $4 Last Tracked On $(grep -F "PT=$4 " ${location}/skynet.log | tail -1 | awk '{print $1" "$2" "$3}')"
						echo "$(grep -Foc "PT=$4 " ${location}/skynet.log) Attempts Total"
						echo "$(grep -F "PT=$4 " ${location}/skynet.log | grep -oE ' SRC=[0-9,\.]* ' | awk '!x[$0]++' | wc -l) Unique IPs"
						echo "$(grep -F "PT=$4 " ${location}/skynet.log | grep -cF NEW) Autobans From This Port"
						echo
						$red "First Block Tracked On Port $4;"
						grep -m1 -F "PT=$4 " "${location}/skynet.log"
						echo
						$red "$counter Most Recent Blocks On Port $4;";
						grep -F "PT=$4 " "${location}/skynet.log" | tail -"$counter"
						echo
					;;
					ip)
						if ! echo "$4" | Is_IP && ! echo "$4" | Is_Range ; then echo "$4 Is Not A Valid IP/Range"; echo; exit 2; fi
						if [ "$5" -eq "$5" ] 2>/dev/null; then counter="$5"; fi
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
						$red "First Block Tracked From $4;"
						grep -m1 -F "=$4 " "${location}/skynet.log"
						echo
						$red "$counter Most Recent Blocks From $4;"
						grep -F "=$4 " "${location}/skynet.log" | tail -"$counter"
						echo
						$red "Top $counter Targeted Ports From $4 (Inbound);"
						grep -E "INBOUND.*SRC=$4 " "${location}/skynet.log" | grep -oE 'DPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://www.speedguide.net/port.php?port="$2}'
						echo
						$red "Top $counter Sourced Ports From $4 (Inbound);"
						grep -E "INBOUND.*SRC=$4 " "${location}/skynet.log" | grep -oE 'SPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://www.speedguide.net/port.php?port="$2}'
					;;
					malware)
						Check_Lock "$@"
						if ! echo "$4" | Is_IP && ! echo "$4" | Is_Range ; then echo "$4 Is Not A Valid IP/Range"; echo; exit 2; fi
						/usr/sbin/curl -fs https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/filter.list -o /jffs/shared-Skynet-whitelist
						mkdir -p /tmp/skynet
						cd /tmp/skynet || exit 1
						case "$(nvram get model)" in
							AC-86U) # AC86U Fork () Patch
								sync && echo 3 > /proc/sys/vm/drop_caches
								while IFS= read -r "domain"; do
									/usr/sbin/curl -fs "$domain" -O
								done < /jffs/shared-Skynet-whitelist
								wait
							;;
							*)
								while IFS= read -r "domain"; do
									/usr/sbin/curl -fs "$domain" -O &
								done < /jffs/shared-Skynet-whitelist
								wait
							;;
						esac
						cd /tmp/home/root || exit 1
						$red "Exact Matches;"
						grep -E "^$4$" /tmp/skynet/* | cut -d '/' -f4- | sed 's~:~ - ~g;s~^~https://iplists.firehol.org/files/~'
						echo;echo
						$red "Possible CIDR Matches;"
						grep -E "^$(echo "$4" | cut -d '.' -f1-3)..*/" /tmp/skynet/* | cut -d '/' -f4- | sed 's~:~ - ~g;s~^~https://iplists.firehol.org/files/~'
						echo
						rm -rf /tmp/skynet
						rm -rf /tmp/skynet.lock
					;;
					autobans)
						if [ "$4" -eq "$4" ] 2>/dev/null; then counter="$4"; fi
						echo "First Autoban Issued On $(grep -m1 -F "NEW BAN" ${location}/skynet.log | awk '{print $1" "$2" "$3}')"
						echo "Last Autoban Issued On $(grep -F "NEW BAN" ${location}/skynet.log | tail -1 | awk '{print $1" "$2" "$3}')"
						echo
						$red "First Autoban Issued;"
						grep -m1 -F "NEW BAN" "${location}/skynet.log"
						echo
						$red "$counter Most Recent Autobans;"
						grep -F "NEW BAN" "${location}/skynet.log" | tail -"$counter"
					;;
					manualbans)
						if [ "$4" -eq "$4" ] 2>/dev/null; then counter="$4"; fi
						echo "First Manual Ban Issued On $(grep -m1 -F "Manual Ban" ${location}/skynet.log | awk '{print $1" "$2" "$3}')"
						echo "Last Manual Ban Issued On $(grep -F "Manual Ban" ${location}/skynet.log | tail -1 | awk '{print $1" "$2" "$3}')"
						echo
						$red "First Manual Ban Issued;"
						grep -m1 -F "Manual Ban" "${location}/skynet.log"
						echo
						$red "$counter Most Recent Manual Bans;"
						grep -F "Manual Ban" "${location}/skynet.log" | tail -"$counter"
					;;
					*)
						echo "Command Not Recognised, Please Try Again"
						echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
						echo; exit 2
					;;
				esac
			;;
			*)
				if [ "$2" -eq "$2" ] 2>/dev/null; then
					counter="$2"
				elif [ "$3" -eq "$3" ] 2>/dev/null; then
					counter="$3"
				fi
				case "$2" in
					tcp)
						proto=TCP
					;;
					udp)
						proto=UDP
					;;
					icmp)
						proto=ICMP
					;;
				esac
				$red "Top $counter Targeted Ports (Inbound); (Torrent Clients May Cause Excess Hits In Debug Mode)"
				grep -E "INBOUND.*$proto" "${location}/skynet.log" | grep -oE 'DPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://www.speedguide.net/port.php?port="$2}'
				echo
				$red "Top $counter Source Ports (Inbound);"
				grep -E "INBOUND.*$proto" "${location}/skynet.log" | grep -oE 'SPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://www.speedguide.net/port.php?port="$2}'
				echo
				$red "Last $counter Unique Connections Blocked (Inbound);"
				grep -E "INBOUND.*$proto" "${location}/skynet.log" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | awk '!x[$0]++' | tail -"$counter" | sed '1!G;h;$!d' | awk '{print "https://otx.alienvault.com/indicator/ip/"$1}'
				echo
				$red "Last $counter Unique Connections Blocked (Outbound);"
				grep -E "OUTBOUND.*$proto" "${location}/skynet.log" | grep -vE 'DPT=80 |DPT=443 ' | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | awk '!x[$0]++' | tail -"$counter" | sed '1!G;h;$!d' | awk '{print "https://otx.alienvault.com/indicator/ip/"$1}'
				echo
				$red "Last $counter Autobans;"
				grep -E "NEW BAN.*$proto" "${location}/skynet.log" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | tail -"$counter" | sed '1!G;h;$!d' | awk '{print "https://otx.alienvault.com/indicator/ip/"$1}'
				echo
				$red "Last $counter Manual Bans;"
				grep -F "Manual Ban" "${location}/skynet.log" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | tail -"$counter" | sed '1!G;h;$!d' | awk '{print "https://otx.alienvault.com/indicator/ip/"$1}'
				echo
				$red "Last $counter Unique HTTP(s) Blocks (Outbound);"
				grep -E 'DPT=80 |DPT=443 ' "${location}/skynet.log" | grep -E "OUTBOUND.*$proto" | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | awk '!x[$0]++' | tail -"$counter" | sed '1!G;h;$!d' | awk '{print "https://otx.alienvault.com/indicator/ip/"$1}'
				echo
				$red "Top $counter HTTP(s) Blocks (Outbound);"
				grep -E 'DPT=80 |DPT=443 ' "${location}/skynet.log" | grep -E "OUTBOUND.*$proto" | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://otx.alienvault.com/indicator/ip/"$2}'
				echo
				$red "Top $counter Blocks (Inbound);"
				grep -E "INBOUND.*$proto" "${location}/skynet.log" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://otx.alienvault.com/indicator/ip/"$2}'
				echo
				$red "Top $counter Blocks (Outbound);"
				grep -E "OUTBOUND.*$proto" "${location}/skynet.log" | grep -vE 'DPT=80 |DPT=443 ' | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://otx.alienvault.com/indicator/ip/"$2}'
			;;
		esac
		echo
	;;

	install)
		Check_Lock "$@"
		if [ "$(ipset -v | grep -Fo v6)" != "v6" ]; then
			logger -st Skynet "[ERROR] IPSet Version Not Supported"
			rm -rf /tmp/skynet.lock
			exit 1
		fi
		if [ ! -f /lib/modules/"$(uname -r)"/kernel/net/netfilter/ipset/ip_set_hash_ipmac.ko ] && [ ! -d /lib/modules/4.1.27 ]; then
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
		if [ ! -f "/jffs/scripts/openvpn-event" ]; then
			echo "#!/bin/sh" > /jffs/scripts/openvpn-event
		elif [ -f "/jffs/scripts/openvpn-event" ] && ! head -1 /jffs/scripts/openvpn-event | grep -qE "^#!/bin/sh"; then
			sed -i '1s~^~#!/bin/sh\n~' /jffs/scripts/openvpn-event
		fi
		while true; do
			echo "Installing Skynet $(Filter_Version "$0")"
			echo "This Will Remove Any Old Install Arguements And Can Be Run Multiple Times"
			echo "[1] --> Vanilla -           Default Installation"
			echo "[2] --> NoAuto -            Default Installation Without Autobanning"
			echo "[3] --> Debug -             Default Installation With Debug Print For Extended Stat Reporting"
			echo "[4] --> NoAuto & Debug -    Default Installation With No Autobanning And Debug Print"
			echo
			echo "Please Select Installation Mode"
			printf "[1-4]: "
			read -r "mode1"
			echo
			case "$mode1" in
				1)
					echo "Vanilla Selected"
					set1="start"
					break
				;;
				2)
					echo "NoAuto Selected"
					set1="start noautoban"
					break
				;;
				3)
					echo "Debug Selected"
					set1="start debug"
					break
				;;
				4)
					echo "NoAuto Debug Selected"
					set1="start noautoban debug"
					break
				;;
				e)
					echo "Exiting!"
					exit 0
				;;
				*)
					echo "$mode1 Isn't An Option!"
					echo
				;;
			esac
		done
		echo
		echo
		while true; do
			echo "Would You Like To Enable Malwarelist Updating?"
			echo "[1] --> Yes (Daily)  - (Recommended)"
			echo "[2] --> Yes (Weekly)"
			echo "[3] --> No"
			echo
			echo "Please Select Option"
			printf "[1-3]: "
			read -r "mode2"
			echo
			case "$mode2" in
				1)
					echo "Malware List Updating Enabled & Scheduled For 2.25am Every Day"
					set2="banmalware"
					break
				;;
				2)
					echo "Malware List Updating Enabled & Scheduled For 2.25am Every Monday"
					set2="banmalwareweekly"
					break
				;;
				3)
					echo "Malware List Updating Disabled"
					break
				;;
				e)
					echo "Exiting!"
					exit 0
				;;
				*)
					echo "$mode2 Isn't An Option!"
					echo
				;;
			esac
		done
		echo
		echo
		while true; do
			echo "Would You Like To Enable Weekly Skynet Updating?"
			echo "[1] --> Yes  - (Recommended)"
			echo "[2] --> No"
			echo
			echo "Please Select Option"
			printf "[1-2]: "
			read -r "mode3"
			echo
			case "$mode3" in
				1)
					echo "Skynet Updating Enabled & Scheduled For 1.25am Every Monday"
					set3="autoupdate"
					break
				;;
				2)
					echo "Auto Updating Disabled"
					break
				;;
				e)
					echo "Exiting!"
					exit 0
				;;
				*)
					echo "$mode3 Isn't An Option!"
					echo
				;;
			esac
		done
		echo
		echo
		while true; do
			echo "Where Would You Like To Install Skynet?"
			echo "[1] --> JFFS"
			echo "[2] --> USB - (Recommended)"
			echo
			echo "Please Select Option"
			printf "[1-2]: "
			read -r "mode4"
			echo
			case "$mode4" in
				1)
					echo "JFFS Installation Selected"
					mkdir -p "/jffs/scripts"
					if [ -f "${location}/scripts/ipset.txt" ]; then mv "${location}/scripts/ipset.txt" "/jffs/scripts/"; fi
					if [ -f "${location}/skynet.log" ]; then mv "${location}/skynet.log" "/jffs/"; fi
					sed -i '\~ Skynet ~d' /jffs/scripts/firewall-start
					echo "sh /jffs/scripts/firewall $set1 $set2 $set3 # Skynet Firewall Addition" | tr -s " " >> /jffs/scripts/firewall-start
					break
				;;
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
					read -r "partitionNumber"
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
					break
				;;
				e)
					echo "Exiting!"
					exit 0
				;;
				*)
					echo "$mode4 Isn't An Option!"
					echo
				;;
			esac
		done
		sed -i '\~ Skynet ~d' /jffs/scripts/openvpn-event
		echo "sh /jffs/scripts/firewall whitelist vpn # Skynet Firewall Addition" >> /jffs/scripts/openvpn-event
		chmod +x /jffs/scripts/firewall
		chmod +x /jffs/scripts/firewall-start
		chmod +x /jffs/scripts/openvpn-event
		echo
		nvram commit
		if [ "$forcereboot" = "1" ]; then
			echo "Reboot Required To Complete Installation"
			printf "Press Enter To Confirm..."
			read -r "continue"
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
		read -r "continue"
		if [ "$continue" = "yes" ]; then
			echo "Uninstalling And Restarting Firewall"
			Unload_Cron
			Kill_Lock
			Unload_IPTables
			Unload_DebugIPTables
			Unload_IPSets
			sed -i '\~ Skynet ~d' /jffs/scripts/firewall-start
			sed -i '\~ Skynet ~d' /jffs/scripts/openvpn-event
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

Logging; echo