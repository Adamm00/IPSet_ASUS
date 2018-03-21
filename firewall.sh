#!/bin/sh
#############################################################################################################
#			         _____ _                     _             __  				    #
#			        / ____| |                   | |           / /  				    #
#			       | (___ | | ___   _ _ __   ___| |_  __   __/ /_  				    #
#			        \___ \| |/ / | | | '_ \ / _ \ __| \ \ / / '_ \ 				    #
#			        ____) |   <| |_| | | | |  __/ |_   \ V /| (_) |				    #
#			       |_____/|_|\_\\__, |_| |_|\___|\__|   \_/  \___/ 				    #
#			                     __/ |                             				    #
#			                    |___/                              				    #
#                                                     							    #
## - 21/03/2018 -		   Asus Firewall Addition By Adamm v6.0.3				    #
##				   https://github.com/Adamm00/IPSet_ASUS		                    #
#############################################################################################################


export PATH=/sbin:/bin:/usr/sbin:/usr/bin$PATH
clear
head -16 "$0"
export LC_ALL=C

retry=1
while [ "$(nvram get ntp_ready)" = "0" ] && [ "$retry" -lt "300" ]; do
	retry=$((retry+1))
	sleep 1
done
if [ "$retry" -ge "300" ]; then logger -st Skynet "[ERROR] NTP Failed To Start After 5 Minutes - Please Fix Immediately!"; exit 1; fi


red="printf \\e[1;31m%s\\e[0m\\n"
grn="printf \\e[1;32m%s\\e[0m\\n"
blue="printf \\e[1;36m%s\\e[0m\\n"
ylow="printf \\e[1;33m%s\\e[0m\\n"
stime="$(date +%s)"


skynetloc="$(grep -ow "skynetloc=.* # Skynet" /jffs/scripts/firewall-start | grep -vE "^#" | awk '{print $1}' | cut -c 11-)"
skynetcfg="${skynetloc}/skynet.cfg"
skynetlog="${skynetloc}/skynet.log"
skynetevents="${skynetloc}/events.log"
skynetipset="${skynetloc}/skynet.ipset"

if [ -z "$skynetloc" ] && tty >/dev/null 2>&1; then
	set "install"
fi


# Detect Location and Force Upgrade
if [ ! -f "$skynetcfg" ] && grep -E "sh /jffs/scripts/firewall start .*usb=.* # Skynet" /jffs/scripts/firewall-start | grep -qvE "^#"; then
	location="$(grep -ow "usb=.*" /jffs/scripts/firewall-start | grep -vE "^#" | awk '{print $1}' | cut -c 5-)/skynet"
	if [ -f "${location}/scripts/ipset.txt" ]; then
		forceupgrade="1"
		if ! echo "$@" | grep -wqE "install"; then
			logger -st Skynet "[ERROR] Legacy v5 Installation Detected - Please Run Installer Manually To Upgrade!"
			echo
			exit 0
		fi
	fi
elif [ ! -f "$skynetcfg" ] && grep -E "sh /jffs/scripts/firewall start.* # Skynet" /jffs/scripts/firewall-start | grep -v "usb=" | grep -v "skynetloc=" | grep -qvE "^#"; then
	location="/jffs"
	if [ -f "${location}/scripts/ipset.txt" ]; then
		forceupgrade="2"
		if ! echo "$@" | grep -wqE "install"; then
			logger -st Skynet "[ERROR] Legacy v5 Installation Detected - Please Run Installer Manually To Upgrade!"
			echo
			exit 0
		fi
	fi
fi


Check_Lock () {
		if [ -f "/tmp/skynet.lock" ] && [ -d "/proc/$(sed -n '2p' /tmp/skynet.lock)" ] && [ "$(sed -n '2p' /tmp/skynet.lock)" != "$$" ] ; then
			logger -st Skynet "[INFO] Lock File Detected ($(sed -n '1p' /tmp/skynet.lock)) (pid=$(sed -n '2p' /tmp/skynet.lock)) - Exiting (cpid=$$)"
			echo
			exit 1
		else
			echo "$@" > /tmp/skynet.lock
			echo "$$" >> /tmp/skynet.lock
		fi
}


if [ ! -d "$skynetloc" ] && ! echo "$@" | grep -wqE "(install|uninstall|disable|update|restart|info)"; then
	Check_Lock "$@"
	retry="1"
	if [ -z "$skynetloc" ]; then retry="11"; fi
	while [ ! -d "$skynetloc" ] && [ "$retry" -lt "11" ]; do
		logger -st Skynet "[INFO] USB Not Found - Sleeping For 10 Seconds ( Attempt $retry Of 10 )"
		retry=$((retry+1))
		sleep 10
	done
	if [ ! -d "$skynetloc" ] || [ ! -w "$skynetloc" ]; then
		logger -st Skynet "[ERROR] Problem With USB Install Location - Please Fix Immediately!"
		logger -st Skynet "[ERROR] When Fixed Run ( sh $0 restart )"
		echo
		exit 1
	fi
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
		if [ ! -f "$skynetcfg" ]; then
			logger -st Skynet "[ERROR] Configuration Not Detected - Please Use ( sh $0 install ) To Continue"
			exit 1
		fi

		conflicting_scripts="(IPSet_Block.sh|malware-filter|privacy-filter|ipBLOCKer.sh|ya-malware-block.sh|iblocklist-loader.sh|firewall-reinstate.sh)$"
		if /usr/bin/find /jffs /tmp/mnt | grep -qE "$conflicting_scripts"; then
			logger -st Skynet "[ERROR] $(/usr/bin/find /jffs /tmp/mnt | grep -E "$conflicting_scripts" | xargs) Detected - This Script Will Cause Conflicts! Please Uninstall It ASAP"
		fi

		if ! grep -F "swapon" /jffs/scripts/post-mount | grep -qvE "^#" && ! grep -F "swap" /jffs/configs/fstab 2>/dev/null | grep -qvE "^#"; then
			logger -st Skynet "[ERROR] Skynet Requires A SWAP File - Install One By Running ( $0 debug swap install )"
			exit 1
		fi

		localver="$(Filter_Version "$0")"

		if [ "$banmalwareupdate" = "daily" ]; then
			cru a Skynet_banmalware "25 2 * * * sh /jffs/scripts/firewall banmalware"
		elif [ "$banmalwareupdate" = "weekly" ]; then
			cru a Skynet_banmalware "25 2 * * Mon sh /jffs/scripts/firewall banmalware"
		fi

		if [ "$autoupdate" = "enabled" ]; then
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

		if [ -f "$(/usr/bin/find /mnt/*/adblocking/.config/ab-solution.cfg 2>/dev/null)" ]; then
			abcfg="$(find /mnt/*/adblocking/.config/ab-solution.cfg)"
			ablocation="$(dirname "$abcfg")"
			if ! grep -qE "hostsFileType=.*\\+" "$abcfg"; then
				if [ ! -f "${ablocation}/AddPlusHosts" ] && [ ! -f "${ablocation}/AddPlusHostsDismissed" ]; then
					touch "${ablocation}/AddPlusHosts"
				fi
			fi
		fi
}

Check_Files () {
		if [ ! -f "/jffs/scripts/firewall-start" ]; then
			echo "#!/bin/sh" > /jffs/scripts/firewall-start
		elif [ -f "/jffs/scripts/firewall-start" ] && ! head -1 /jffs/scripts/firewall-start | grep -qE "^#!/bin/sh"; then
			sed -i '1s~^~#!/bin/sh\n~' /jffs/scripts/firewall-start
		fi
		if [ ! -f "/jffs/scripts/services-stop" ]; then
			echo "#!/bin/sh" > /jffs/scripts/services-stop
		elif [ -f "/jffs/scripts/services-stop" ] && ! head -1 /jffs/scripts/services-stop | grep -qE "^#!/bin/sh"; then
			sed -i '1s~^~#!/bin/sh\n~' /jffs/scripts/services-stop
		fi
		if [ ! -f "/jffs/scripts/post-mount" ]; then
			echo "#!/bin/sh" > /jffs/scripts/post-mount
		elif [ -f "/jffs/scripts/post-mount" ] && ! head -1 /jffs/scripts/post-mount | grep -qE "^#!/bin/sh"; then
			sed -i '1s~^~#!/bin/sh\n~' /jffs/scripts/post-mount
		fi
		if [ "$1" = "verify" ] && ! grep -qF "# Skynet" /jffs/scripts/services-stop; then
			echo "sh /jffs/scripts/firewall save # Skynet Firewall Addition" >> /jffs/scripts/services-stop
		fi
}

Check_Status () {
		{ [ -f "$skynetipset" ] && ipset -L -n Skynet-Whitelist >/dev/null 2>&1 && iptables -t raw -C PREROUTING -i "$iface" -m set ! --match-set Skynet-Whitelist src -m set --match-set Skynet-Master src -j DROP >/dev/null 2>&1; } || 
		{ [ -f "$skynetipset" ] && ipset -L -n Skynet-Whitelist >/dev/null 2>&1 && iptables -t raw -C PREROUTING -i br0 -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j DROP >/dev/null 2>&1; }
}

Unload_IPTables () {
		iptables -D logdrop -m state --state NEW -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		ip6tables -D logdrop -m state --state NEW -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		iptables -t raw -D PREROUTING -i "$iface" -m set ! --match-set Skynet-Whitelist src -m set --match-set Skynet-Master src -j DROP 2>/dev/null
		iptables -t raw -D PREROUTING -i br0 -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null
		iptables -D logdrop -i "$iface" -m state --state INVALID -m recent --update --seconds 300 --hitcount 2 --name TRACKINVALID --rsource -j SET --add-set Skynet-Master src 2>/dev/null
		iptables -D logdrop -i "$iface" -m state --state INVALID -m recent --update --seconds 300 --hitcount 2 --name TRACKINVALID --rsource -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		iptables -D logdrop -i "$iface" -m recent --set --name TRACKINVALID --rsource 2>/dev/null
		iptables -D logdrop -i "$iface" -p tcp -m multiport --sports 80,443,143,993,110,995,25,465 -m state --state INVALID -j DROP 2>/dev/null
		iptables -D logdrop -i "$iface" -m set --match-set Skynet-Whitelist src -j ACCEPT 2>/dev/null
		iptables -D logdrop -p tcp --tcp-flags ALL RST,ACK -j ACCEPT 2>/dev/null
		iptables -D logdrop -p tcp --tcp-flags ALL RST -j ACCEPT 2>/dev/null
		iptables -D logdrop -p tcp --tcp-flags ALL FIN,ACK -j ACCEPT 2>/dev/null
		iptables -D logdrop -p tcp --tcp-flags ALL ACK,PSH,FIN -j ACCEPT 2>/dev/null
		iptables -D logdrop -p icmp --icmp-type 3 -j ACCEPT 2>/dev/null
		iptables -D logdrop -p icmp --icmp-type 11 -j ACCEPT 2>/dev/null
		iptables -D SSHBFP -m recent --update --seconds 60 --hitcount 4 --name SSH --rsource -j SET --add-set Skynet-Blacklist src 2>/dev/null
		iptables -D SSHBFP -m recent --update --seconds 60 --hitcount 4 --name SSH --rsource -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
}

Load_IPTables () {
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then
			iptables -t raw -I PREROUTING -i "$iface" -m set ! --match-set Skynet-Whitelist src -m set --match-set Skynet-Master src -j DROP 2>/dev/null
		fi
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
			iptables -t raw -I PREROUTING -i br0 -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null
		fi
		if [ "$autoban" = "enabled" ]; then
			iptables -I logdrop -p tcp --tcp-flags ALL RST,ACK -j ACCEPT 2>/dev/null
			iptables -I logdrop -p tcp --tcp-flags ALL RST -j ACCEPT 2>/dev/null
			iptables -I logdrop -p tcp --tcp-flags ALL FIN,ACK -j ACCEPT 2>/dev/null
			iptables -I logdrop -p tcp --tcp-flags ALL ACK,PSH,FIN -j ACCEPT 2>/dev/null
			iptables -I logdrop -p icmp --icmp-type 3 -j ACCEPT 2>/dev/null
			iptables -I logdrop -p icmp --icmp-type 11 -j ACCEPT 2>/dev/null
			iptables -I logdrop -i "$iface" -p tcp -m multiport --sports 80,443,143,993,110,995,25,465 -m state --state INVALID -j DROP 2>/dev/null
			iptables -I logdrop -i "$iface" -m set --match-set Skynet-Whitelist src -j ACCEPT 2>/dev/null
			pos1="$(($(iptables --line -nL logdrop | wc -l)-2))"
			iptables -I logdrop "$pos1" -i "$iface" -m state --state INVALID -m recent --update --seconds 300 --hitcount 2 --name TRACKINVALID --rsource -j SET --add-set Skynet-Master src 2>/dev/null
			iptables -I logdrop "$pos1" -i "$iface" -m state --state INVALID -m recent --update --seconds 300 --hitcount 2 --name TRACKINVALID --rsource -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
			iptables -I logdrop "$pos1" -i "$iface" -m recent --set --name TRACKINVALID --rsource 2>/dev/null
		fi
		if [ "$(nvram get sshd_enable)" = "1" ] && [ "$(nvram get sshd_bfp)" = "1" ]; then
			pos2="$(iptables --line -nL SSHBFP | grep -F "seconds: 60 hit_count: 4" | grep -F "logdrop" | awk '{print $1}')"
			iptables -I SSHBFP "$pos2" -m recent --update --seconds 60 --hitcount 4 --name SSH --rsource -j SET --add-set Skynet-Master src 2>/dev/null
			iptables -I SSHBFP "$pos2" -m recent --update --seconds 60 --hitcount 4 --name SSH --rsource -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		fi
}

Unload_DebugIPTables () {
		iptables -t raw -D PREROUTING -i "$iface" -m set ! --match-set Skynet-Whitelist src -m set --match-set Skynet-Master src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		iptables -t raw -D PREROUTING -i br0 -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
}

Load_DebugIPTables () {
		if [ "$debugmode" = "enabled" ]; then
			if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then
				pos3="$(iptables --line -nL PREROUTING -t raw | grep -F "Skynet-Master src" | grep -F "DROP" | awk '{print $1}')"
				iptables -t raw -I PREROUTING "$pos3" -i "$iface" -m set ! --match-set Skynet-Whitelist src -m set --match-set Skynet-Master src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
			fi
			if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
				pos4="$(iptables --line -nL PREROUTING -t raw | grep -F "Skynet-Master dst" | grep -F "DROP" | awk '{print $1}')"
				iptables -t raw -I PREROUTING "$pos4" -i br0 -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
			fi
		fi
}

Unload_IPSets () {
		ipset -q destroy Skynet-Master
		ipset -q destroy Skynet-Blacklist
		ipset -q destroy Skynet-BlockedRanges
		ipset -q destroy Skynet-Whitelist
}

Unload_Cron () {
		cru d Skynet_save
		cru d Skynet_banmalware
		cru d Skynet_autoupdate
		cru d Skynet_checkupdate
}

Is_IP () {
		grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
}

Is_Range () {
		grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'
}

Is_Port () {
		grep -qE '^[0-9]{1,5}$'
}

Domain_Lookup () {
		nslookup "$(echo "$1" | sed 's~http[s]*://~~;s~/.*~~')" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | awk 'NR>2'
}

Filter_Version () {
		if [ -n "$1" ]; then
			grep -m1 -oE 'v[0-9]{1,2}([.][0-9]{1,2})([.][0-9]{1,2})' "$1"
		else
			grep -m1 -oE 'v[0-9]{1,2}([.][0-9]{1,2})([.][0-9]{1,2})'
		fi
}

Filter_Date () {
		grep -m1 -oE '[0-9]{1,2}([/][0-9]{1,2})([/][0-9]{1,4})' "$1"
}

Filter_PrivateIP () {
		grep -vE '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)|(^22[4-9]\.)|(^23[0-9]\.)|(^255\.255\.255\.255)'
}

Filter_PrivateSRC () {
		grep -E '(SRC=127\.)|(SRC=10\.)|(SRC=172\.1[6-9]\.)|(SRC=172\.2[0-9]\.)|(SRC=172\.3[0-1]\.)|(SRC=192\.168\.)|(SRC=0.)|(SRC=169\.254\.)|(SRC=22[4-9]\.)|(SRC=23[0-9]\.)|(SRC=255\.255\.255\.255)'
}

Filter_PrivateDST () {
		grep -E '(DST=127\.)|(DST=10\.)|(DST=172\.1[6-9]\.)|(DST=172\.2[0-9]\.)|(DST=172\.3[0-1]\.)|(DST=192\.168\.)|(DST=0.)|(DST=169\.254\.)|(DST=22[4-9]\.)|(DST=23[0-9]\.)|(DST=255\.255\.255\.255)'
}

Save_IPSets () {
		if Check_Status; then
			echo "Saving Changes"
			{ ipset save Skynet-Whitelist; ipset save Skynet-Blacklist; ipset save Skynet-BlockedRanges; ipset save Skynet-Master; } > "$skynetipset" 2>/dev/null
		fi
}

Unban_PrivateIP () {
		grep -F "INBOUND" /tmp/syslog.log | Filter_PrivateSRC | grep -oE 'SRC=[0-9,\.]* ' | cut -c 5- | while IFS= read -r "ip"; do
			ipset -q -A Skynet-Whitelist "$ip" comment "PrivateIP"
			ipset -q -D Skynet-Blacklist "$ip"
			sed -i "/SRC=${ip} /d" /tmp/syslog.log
		done
		grep -F "OUTBOUND" /tmp/syslog.log | Filter_PrivateDST | grep -oE 'DST=[0-9,\.]* ' | cut -c 5- | while IFS= read -r "ip"; do
			ipset -q -A Skynet-Whitelist "$ip" comment "PrivateIP"
			ipset -q -D Skynet-Blacklist "$ip"
			sed -i "/DST=${ip} /d" /tmp/syslog.log
		done
}

Refresh_MWhitelist () {
		if grep -qE "Manual Whitelist.* TYPE=Domain" "$skynetevents"; then
			rm -rf /tmp/mwhitelist.list /tmp/mwhitelist2.list
			sed "\\~add Skynet-Whitelist ~!d;\\~ManualWlistD~!d;s~ comment.*~~;s~add~del~g" "$skynetipset" | ipset restore -!
			grep -E "Manual Whitelist.* TYPE=Domain" "$skynetevents" | while IFS= read -r "entry"; do
				url="$(echo "$entry" | awk '{print $9}')"
				echo "${url#*=}" >> /tmp/mwhitelist.list
			done
			sed -i "\\~\\[Manual Whitelist\\] TYPE=Domain~d;" "$skynetevents"
			awk '!x[$0]++' /tmp/mwhitelist.list | while IFS= read -r "website"; do
				for ip in $(Domain_Lookup "$website"); do
					echo "add Skynet-Whitelist $ip comment \"ManualWlistD: $website\"" >> /tmp/mwhitelist2.list && echo "$(date +"%b %d %T") Skynet: [Manual Whitelist] TYPE=Domain SRC=$ip Host=$website " >> "$skynetevents" &
				done
			done
			ipset restore -! -f "/tmp/mwhitelist2.list"
			rm -rf /tmp/mwhitelist.list /tmp/mwhitelist2.list
		fi
}

Refresh_MBans () {
		if grep -qE "Manual Ban.* TYPE=Domain" "$skynetevents"; then
			rm -rf /tmp/mbans.list /tmp/mbans2.list
			sed "\\~add Skynet-Blacklist ~!d;\\~ManualBanD~!d;s~ comment.*~~;s~add~del~g" "$skynetipset" | ipset restore -!
			grep -E "Manual Ban.* TYPE=Domain" "$skynetevents" | while IFS= read -r "entry"; do
				url="$(echo "$entry" | awk '{print $9}')"
				echo "${url#*=}" >> /tmp/mbans.list
			done
			sed -i "\\~\\[Manual Ban\\] TYPE=Domain~d;" "$skynetevents"
			awk '!x[$0]++' /tmp/mbans.list | while IFS= read -r "website"; do
				for ip in $(Domain_Lookup "$website"); do
					echo "add Skynet-Blacklist $ip comment \"ManualBanD: $website\"" >> /tmp/mbans2.list && echo "$(date +"%b %d %T") Skynet: [Manual Ban] TYPE=Domain SRC=$ip Host=$website " >> "$skynetevents" &
				done
			done
			ipset restore -! -f "/tmp/mbans2.list"
			rm -rf /tmp/mbans.list /tmp/mbans2.list
		fi
}

Whitelist_Extra () {
		{ sed '\~ManualWlistD: ~!d;s~.*ManualWlistD: ~~g;s~"~~g' "$skynetipset"
		echo "ipdeny.com"
		echo "speedguide.net"
		echo "otx.alienvault.com"
		echo "raw.githubusercontent.com"
		echo "iplists.firehol.org"
		echo "astrill.com"
		echo "strongpath.net"
		echo "snbforums.com"
		nvram get ntp_server0
		nvram get ntp_server1
		nvram get firmware_server; } | awk '!x[$0]++' > /jffs/shared-Skynet2-whitelist
}

Whitelist_CDN () {
		sed '\~add Skynet-Whitelist ~!d;\~CDN-Whitelist~!d;s~ comment.*~~;s~add~del~g' "$skynetipset" | ipset restore -!
		/usr/sbin/curl -fsL --retry 3 "https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/cdn.list" | dos2unix | sed -n "s/\\r//;/^$/d;/^[0-9,\\.,\\/]*$/p" | awk '!x[$0]++' > /tmp/cdn.list
		awk '{print "add Skynet-Whitelist " $1 " comment \"CDN-Whitelist\""}' /tmp/cdn.list | ipset restore -!
		rm -rf /tmp/cdn.list
}

Whitelist_VPN () {
		ipset -q -A Skynet-Whitelist "$(nvram get vpn_server1_sn)"/24 comment "nvram: vpn_server1_sn"
		ipset -q -A Skynet-Whitelist "$(nvram get vpn_server2_sn)"/24 comment "nvram: vpn_server2_sn"
		ipset -q -A Skynet-Whitelist "$(nvram get vpn_server_sn)"/24 comment "nvram: vpn_server_sn"
		ipset -q -A Skynet-Whitelist "$(nvram get vpn_client1_addr)"/24 comment "nvram: vpn_client1_addr"
		ipset -q -A Skynet-Whitelist "$(nvram get vpn_client2_addr)"/24 comment "nvram: vpn_client2_addr"
		ipset -q -A Skynet-Whitelist "$(nvram get vpn_client3_addr)"/24 comment "nvram: vpn_client3_addr"
		ipset -q -A Skynet-Whitelist "$(nvram get vpn_client4_addr)"/24 comment "nvram: vpn_client4_addr"
		ipset -q -A Skynet-Whitelist "$(nvram get vpn_client5_addr)"/24 comment "nvram: vpn_client5_addr"
		if [ -f "/dev/astrill/openvpn.conf" ]; then ipset -q -A Skynet-Whitelist "$(sed '\~remote ~!d;s~remote ~~' "/dev/astrill/openvpn.conf")"/24 comment "nvram: Astrill_VPN"; fi
}

Whitelist_Shared () {
		ipset -q -A Skynet-Whitelist "$(nvram get wan0_ipaddr)"/32 comment "nvram: wan0_ipaddr"
		ipset -q -A Skynet-Whitelist "$(nvram get lan_ipaddr)"/24 comment "nvram: lan_ipaddr"
		ipset -q -A Skynet-Whitelist "$(nvram get lan_netmask)"/24 comment "nvram: lan_netmask"
		ipset -q -A Skynet-Whitelist "$(nvram get wan_dns1_x)"/32 comment "nvram: wan_dns1_x"
		ipset -q -A Skynet-Whitelist "$(nvram get wan_dns2_x)"/32 comment "nvram: wan_dns2_x"
		ipset -q -A Skynet-Whitelist "$(nvram get wan0_dns1_x)"/32 comment "nvram: wan0_dns1_x"
		ipset -q -A Skynet-Whitelist "$(nvram get wan0_dns2_x)"/32 comment "nvram: wan0_dns2_x"
		ipset -q -A Skynet-Whitelist "$(nvram get wan_dns | awk '{print $1}')"/32 comment "nvram: wan_dns"
		ipset -q -A Skynet-Whitelist "$(nvram get wan_dns | awk '{print $2}')"/32 comment "nvram: wan_dns"
		ipset -q -A Skynet-Whitelist "$(nvram get wan0_dns | awk '{print $1}')"/32 comment "nvram: wan0_dns"
		ipset -q -A Skynet-Whitelist "$(nvram get wan0_dns | awk '{print $2}')"/32 comment "nvram: wan0_dns"
		ipset -q -A Skynet-Whitelist "$(nvram get wan0_xdns | awk '{print $1}')"/32 comment "nvram: wan0_xdns"
		ipset -q -A Skynet-Whitelist "$(nvram get wan0_xdns | awk '{print $2}')"/32 comment "nvram: wan0_xdns"
		ipset -q -A Skynet-Whitelist 192.30.252.0/22 comment "nvram: Github Content Server"
		ipset -q -A Skynet-Whitelist 192.168.1.0/24 comment "nvram: LAN Subnet"
		if [ -n "$(/usr/bin/find /jffs -name 'shared-*-whitelist')" ]; then
			echo "Whitelisting Shared Domains"
			sed '\~add Skynet-Whitelist ~!d;\~Shared-Whitelist~!d;s~ comment.*~~;s~add~del~g' "$skynetipset" | ipset restore -!
			grep -hvF "#" /jffs/shared-*-whitelist | sed 's~http[s]*://~~;s~/.*~~' | awk '!x[$0]++' | while IFS= read -r "domain"; do
				for ip in $(Domain_Lookup "$domain" 2> /dev/null); do
					ipset -q -A Skynet-Whitelist "$ip" comment "Shared-Whitelist: $domain"
				done &
			done
			wait
		fi
}

Manage_Device() {
		echo "Looking For Available Partitions..."
		i=1
		IFS="
		"
		for mounted in $(/bin/mount | grep -E "ext2|ext3|ext4|tfat|exfat" | awk '{print $3" - ("$1")"}') ; do
			echo "[$i]  --> $mounted"
			eval mounts$i="$(echo "$mounted" | awk '{print $1}')"
			i=$((i + 1))
		done
		unset IFS
		if [ $i = "1" ]; then
			echo "No Compatible Partitions Found - Exiting!"
			exit 1
		fi
		Select_Device(){
				echo
				echo "Please Enter Partition Number Or e To Exit"
				printf "[0-%s]: " "$((i - 1))"
				read -r "partitionNumber"
				echo
				if [ "$partitionNumber" = "e" ] || [ "$partitionNumber" = "exit" ]; then
					echo "Exiting!"
					echo
					exit 0
				elif [ -z "$partitionNumber" ] || [ "$partitionNumber" -gt $((i - 1)) ] 2>/dev/null || [ "$partitionNumber" = "0" ]; then
					echo "Invalid Partition Number!"
					Select_Device
				elif [ "$partitionNumber" -eq "$partitionNumber" ] 2>/dev/null;then
					true
				else
					echo "$partitionNumber Isn't An Option!"
					Select_Device
				fi
		}
		Select_Device
		device=""
		eval device=\$mounts"$partitionNumber"
		touch "${device}/rwtest"
		if [ ! -w "${device}/rwtest" ]; then
			echo "Writing To $device Failed - Exiting!"
			Manage_Device
		else
			rm -rf "${device}/rwtest"
		fi
}

Create_Swap() {
	while true; do
		echo "Select SWAP File Size:"
		echo "[1]  --> 256MB"
		echo "[2]  --> 512MB"
		echo "[3]  --> 1GB"
		echo "[4]  --> 2GB"
		echo
		echo "[e]  --> Exit Menu"
		echo
		printf "[1-4]: "
		read -r "menu"
		echo
		case "$menu" in
			1)
				swapsize=262144
				break
			;;
			2)
				swapsize=524288
				break
			;;
			3)
				swapsize=1048576
				break
			;;
			4)
				swapsize=2097152
				break
			;;
			e|exit)
				echo "Exiting!"
				echo
				exit 0
			;;
			*)
				echo "$menu Isn't An Option!"
				echo
			;;
		esac
	done
	if [ -f "${device}/myswap.swp" ]; then swapoff "${device}/myswap.swp" 2>/dev/null; rm -rf "${device}/myswap.swp"; fi
	if [ "$(df $device | xargs | awk '{print $11}')" -le "$swapsize" ]; then echo "Not Enough Free Space Available On $device"; Create_Swap; fi
	echo "Creating SWAP File..."
	dd if=/dev/zero of="${device}/myswap.swp" bs=1k count="$swapsize"
	mkswap "${device}/myswap.swp"
	swapon "${device}/myswap.swp"
	echo "swapon ${device}/myswap.swp # Skynet Firewall Addition" >> /jffs/scripts/post-mount
	echo "SWAP File Located At ${device}/myswap.swp"
	echo
}

Purge_Logs () {
		sed '\~BLOCKED -~!d' /tmp/syslog.log-1 /tmp/syslog.log 2>/dev/null >> "$skynetlog"
		sed -i '\~BLOCKED -~d' /tmp/syslog.log-1 /tmp/syslog.log 2>/dev/null
		if [ "$(du "$skynetlog" | awk '{print $1}')" -ge "7000" ]; then
			sed -i '\~BLOCKED - .*BOUND~d' "$skynetlog"
			sed -i '\~Skynet: \[Complete\]~d' "$skynetevents"
			if [ "$(du "$skynetlog" | awk '{print $1}')" -ge "3000" ]; then
				true > "$skynetlog"
			fi
		fi
		if [ "$(grep -c "Skynet: \\[Complete\\]" "/tmp/syslog.log" 2>/dev/null)" -gt "24" ] 2>/dev/null; then
			sed '\~Skynet: \[Complete\]~!d' /tmp/syslog.log-1 /tmp/syslog.log 2>/dev/null >> "$skynetevents"
			sed -i '\~Skynet: \[Complete\]~d' /tmp/syslog.log-1 /tmp/syslog.log 2>/dev/null
		fi
}

Logging () {
		oldips="$blacklist1count"
		oldranges="$blacklist2count"
		blacklist1count="$(grep -Foc "add Skynet-Black" "$skynetipset" 2> /dev/null)"
		blacklist2count="$(grep -Foc "add Skynet-Block" "$skynetipset" 2> /dev/null)"
		if iptables -t raw -C PREROUTING -i "$iface" -m set ! --match-set Skynet-Whitelist src -m set --match-set Skynet-Master src -j DROP 2>/dev/null; then
			hits1="$(iptables -xnvL -t raw | grep -Fv "LOG" | grep -F "Skynet-Master src" | awk '{print $1}')"
			hits2="$(iptables -xnvL -t raw | grep -Fv "LOG" | grep -F "Skynet-Master dst" | awk '{print $1}')"
		fi
		ftime="$(($(date +%s) - stime))"
		if [ "$1" = "minimal" ]; then
			$grn "$blacklist1count IPs / $blacklist2count Ranges Banned. $((blacklist1count - oldips)) New IPs / $((blacklist2count - oldranges)) New Ranges Banned. $hits1 Inbound / $hits2 Outbound Connections Blocked!"
		else
			logger -st Skynet "[Complete] $blacklist1count IPs / $blacklist2count Ranges Banned. $((blacklist1count - oldips)) New IPs / $((blacklist2count - oldranges)) New Ranges Banned. $hits1 Inbound / $hits2 Outbound Connections Blocked! [$1] [${ftime}s]"
		fi
}

Upgrade_v6 () {

	# Set Locations
	skynetloc="${device}/skynet"
	skynetcfg="${device}/skynet/skynet.cfg"
	skynetlog="${device}/skynet/skynet.log"
	skynetevents="${device}/skynet/events.log"
	skynetipset="${device}/skynet/skynet.ipset"

	# Rename/Move files
	mv "${location}/scripts/ipset.txt" "$skynetipset"
	mv "${location}/skynet.log" "$skynetlog"
	if [ "$forceupgrade" = "1" ]; then rm -rf "${location}/scripts"; fi

	# Convert ipset.txt
	sed -i 's~^create Whitelist ~create Skynet-Whitelist ~g' "$skynetipset"
	sed -i 's~^add Whitelist ~add Skynet-Whitelist ~g' "$skynetipset"
	sed -i 's~^create Blacklist ~create Skynet-Blacklist ~g' "$skynetipset"
	sed -i 's~^add Blacklist ~add Skynet-Blacklist ~g' "$skynetipset"
	sed -i 's~^create BlockedRanges ~create Skynet-BlockedRanges ~g' "$skynetipset"
	sed -i 's~^add BlockedRanges ~add Skynet-BlockedRanges ~g' "$skynetipset"
	sed -i 's~^create Skynet ~create Skynet-Master ~g' "$skynetipset"
	sed -i 's~^add Skynet Blacklist~add Skynet-Master Skynet-Blacklist~g' "$skynetipset"
	sed -i 's~^add Skynet BlockedRanges~add Skynet-Master Skynet-BlockedRanges~g' "$skynetipset"

	# Convert skynet.log
	sed '\~BLOCKED -~d' "$skynetlog" > "$skynetevents"
	sed -i '\~BLOCKED -~!d' "$skynetlog"

	# Convert countrylist and customlisturl
	countrylist="$(grep -m1 -F "Country:" "$skynetipset" | sed 's~.*Country: ~~;s~"~~')"
	customlisturl="$(grep -F "New Banmalware Filter" "$skynetevents" | sed 's~.*New Banmalware Filter.*URL=~~g')"
	sed -i '\~New Banmalware Filter~d' "$skynetevents"
}

Write_Config () {
	{ echo "## Generated By Skynet - Do Not Manually Edit ##"
	echo "## $(date +"%b %d %T") ##"
	echo
	echo "## Installer ##"
	echo "model=\"$model\""
	echo "localver=\"$localver\""
	echo "autoupdate=\"$autoupdate\""
	echo "autoban=\"$autoban\""
	echo "banmalwareupdate=\"$banmalwareupdate\""
	echo "forcebanmalwareupdate=\"$forcebanmalwareupdate\""
	echo "debugmode=\"$debugmode\""
	echo "filtertraffic=\"$filtertraffic\""
	echo
	echo "## Other ##"
	echo "blacklist1count=\"$blacklist1count\""
	echo "blacklist2count=\"$blacklist2count\""
	echo "customlisturl=\"$customlisturl\""
	echo "countrylist=\"$countrylist\""; } > "$skynetcfg"
}

####################################################################################################################################################
# -   unban / ban / banmalware / whitelist / import / deport / save / start / restart / disable / update / debug / stats / install / uninstall   - #
####################################################################################################################################################

Load_Menu () {
	. "$skynetcfg"
	echo "Router Model; $model"
	echo "Skynet Version; $localver ($(Filter_Date "$0"))"
	echo "$(iptables --version) - ($iface @ $(nvram get lan_ipaddr))"
	ipset -v
	echo "FW Version; $(nvram get buildno)_$(nvram get extendno) ($(uname -v | awk '{print $5" "$6" "$9}')) ($(uname -r))"
	echo "Install Dir; $skynetloc ($(df -h $skynetloc | xargs | awk '{print $11 " / " $9}') Space Available)"
	if grep -F "swapon" /jffs/scripts/post-mount 2>/dev/null | grep -qvE "^#"; then swaplocation="$(grep -o "swapon .*" /jffs/scripts/post-mount | grep -vE "^#" | awk '{print $2}')"; echo "SWAP File; $swaplocation ($(du -h "$swaplocation" | awk '{print $1}'))"; fi
	echo "Boot Args; $(grep -E "start.* # Skynet" /jffs/scripts/firewall-start 2>/dev/null | grep -vE "^#" | cut -c 4- | cut -d '#' -f1)"
	if [ -n "$countrylist" ]; then echo "Banned Countries; $countrylist"; fi
	if [ -f "/tmp/skynet.lock" ] && [ -d "/proc/$(sed -n '2p' /tmp/skynet.lock)" ]; then $red "Lock File Detected ($(sed -n '1p' /tmp/skynet.lock)) (pid=$(sed -n '2p' /tmp/skynet.lock))"; lockedwarning=1; fi
	if [ -n "$lockedwarning" ]; then $ylow "Locked Processes Generally Take 20-60s To Complete And May Result In Temporarily \"Failed\" Tests"; fi
	unset "lockedwarning"
	echo
	if ! grep -E "start.* # Skynet" /jffs/scripts/firewall-start 2>/dev/null | grep -qvE "^#"; then printf "Checking Firewall-Start Entry...			"; $red "[Failed]"; fi
	if ! iptables -t raw -C PREROUTING -i "$iface" -m set ! --match-set Skynet-Whitelist src -m set --match-set Skynet-Master src -j DROP 2>/dev/null && [ "$filtertraffic" != "outbound" ]; then printf "Checking Inbound Filter Rules...			"; $red "[Failed]"; nolog="1"; fi
	if ! iptables -t raw -C PREROUTING -i br0 -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null && [ "$filtertraffic" != "inbound" ]; then printf "Checking Outbound Filter Rules...			"; $red "[Failed]"; nolog="1"; fi
	if ! ipset -L -n Skynet-Whitelist >/dev/null 2>&1; then printf "Checking Whitelist IPSet...				"; $red "[Failed]"; nolog="1"; fi
	if ! ipset -L -n Skynet-BlockedRanges >/dev/null 2>&1; then printf "Checking BlockedRanges IPSet...				"; $red "[Failed]"; nolog="1"; fi
	if ! ipset -L -n Skynet-Blacklist >/dev/null 2>&1; then printf "Checking Blacklist IPSet...				"; $red "[Failed]"; nolog="1"; fi
	if ! ipset -L -n Skynet-Master >/dev/null 2>&1; then printf "Checking Skynet IPSet...				"; $red "[Failed]"; nolog="1"; fi
	if [ "$nolog" != "1" ]; then Logging minimal; fi
	unset "nolog"
	unset "option1" "option2" "option3" "option4" "option5"
	reloadmenu="1"
	Purge_Logs
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
		echo "[r]  --> Reload Menu"
		echo "[e]  --> Exit Menu"
		echo
		printf "[1-14]: "
		read -r "menu"
		echo
		case "$menu" in
			1)
				if ! Check_Status; then echo "Skynet Not Running - Aborting"; echo; Load_Menu; break; fi
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
							if ! echo "$option3" | Is_IP; then echo "$option3 Is Not A Valid IP"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						2)
							option2="range"
							echo "Input Range To Unban:"
							echo
							printf "[Range]: "
							read -r "option3"
							echo
							if ! echo "$option3" | Is_Range; then echo "$option3 Is Not A Valid Range"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						3)
							option2="domain"
							echo "Input Domain To Unban:"
							echo
							printf "[URL]: "
							read -r "option3"
							echo
							if [ -z "$option3" ]; then echo "URL Field Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						4)
							option2="port"
							echo "Remove Autobans Based On Port:"
							echo
							printf "[Port]: "
							read -r "option3"
							echo
							if ! echo "$option3" | Is_Port || [ "$option3" -gt "65535" ]; then echo "$option3 Is Not A Valid Port"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						5)
							option2="comment"
							echo "Remove Bans Matching Comment:"
							echo
							printf "[Comment]: "
							read -r "option3"
							echo
							if [ "${#option3}" -gt "255" ]; then echo "$option3 Is Not A Valid Comment. 255 Chars Max"; echo; unset "option2" "option3"; continue; fi
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
							unset "option1" "option2" "option3" "option4" "option5"
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
				if ! Check_Status; then echo "Skynet Not Running - Aborting"; echo; Load_Menu; break; fi
				option1="ban"
				while true; do
					echo "What Type Of Input Would You Like To Ban:"
					echo "[1]  --> IP"
					echo "[2]  --> Range"
					echo "[3]  --> Domain"
					echo "[4]  --> Country"
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
							if ! echo "$option3" | Is_IP; then echo "$option3 Is Not A Valid IP"; echo; unset "option2" "option3"; continue; fi
							echo "Input Comment For Ban:"
							echo
							printf "[Comment]: "
							read -r "option4"
							echo
							if [ "${#option4}" -gt "255" ]; then echo "$option4 Is Not A Valid Comment. 255 Chars Max"; echo; unset "option2" "option3" "option4"; continue; fi
							break
						;;
						2)
							option2="range"
							echo "Input Range To Ban:"
							echo
							printf "[Range]: "
							read -r "option3"
							echo
							if ! echo "$option3" | Is_Range; then echo "$option3 Is Not A Valid Range"; echo; unset "option2" "option3"; continue; fi
							echo "Input Comment For Ban:"
							echo
							printf "[Comment]: "
							read -r "option4"
							echo
							if [ "${#option4}" -gt "255" ]; then echo "$option3 Is Not A Valid Comment. 255 Chars Max"; echo; unset "option2" "option3" "option4"; continue; fi
							break
						;;
						3)
							option2="domain"
							echo "Input Domain To Ban:"
							echo
							printf "[URL]: "
							read -r "option3"
							echo
							if [ -z "$option3" ]; then echo "URL Field Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						4)
							option2="country"
							echo "Input Country Abbreviations To Ban:"
							echo
							printf "[Countries]: "
							read -r "option3"
							echo
							if [ -z "$option3" ]; then echo "Country Field Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						e|exit|back|menu)
							unset "option1" "option2" "option3" "option4" "option5"
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
				if ! Check_Status; then echo "Skynet Not Running - Aborting"; echo; Load_Menu; break; fi
				option1="banmalware"
				while true; do
					echo "Select Option:"
					echo "[1]  --> Update"
					echo "[2]  --> Change Filter List"
					echo "[3]  --> Reset Filter List"
					echo
					printf "[1-3]: "
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
							if [ -z "$option2" ]; then echo "URL Field Can't Be Empty - Please Try Again"; echo; unset "option2"; continue; fi
							break
						;;
						3)
							option2="reset"
							break
						;;
						e|exit|back|menu)
							unset "option1" "option2" "option3" "option4" "option5"
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
				if ! Check_Status; then echo "Skynet Not Running - Aborting"; echo; Load_Menu; break; fi
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
							if ! echo "$option3" | Is_IP && ! echo "$option3" | Is_Range ; then echo "$option3 Is Not A Valid IP/Range"; echo; unset "option2" "option3"; continue; fi
							echo "Input Comment For Whitelist:"
							echo
							printf "[Comment]: "
							read -r "option4"
							echo
							if [ "${#option4}" -gt "255" ]; then echo "$option4 Is Not A Valid Comment. 255 Chars Max"; echo; unset "option2" "option3" "option4"; continue; fi
							break
						;;
						2)
							option2="domain"
							echo "Input Domain To Whitelist:"
							echo
							printf "[URL]: "
							read -r "option3"
							echo
							if [ -z "$option3" ]; then echo "URL Field Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						3)
							option2="port"
							echo "Whitelist Autobans Based On Port:"
							echo
							printf "[Port]: "
							read -r "option3"
							echo
							if ! echo "$option3" | Is_Port || [ "$option3" -gt "65535" ]; then echo "$option3 Is Not A Valid Port"; echo; unset "option2" "option3"; continue; fi
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
										option3="all"
										break
									;;
									2)
										option3="entry"
										echo "Input IP Or Range To Remove:"
										echo
										printf "[IP/Range]: "
										read -r "option4"
										echo
										if ! echo "$option4" | Is_IP && ! echo "$option4" | Is_Range ; then echo "$option4 Is Not A Valid IP/Range"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									3)
										option3="comment"
										echo "Remove Entries Based On Comment:"
										echo
										printf "[Comment]: "
										read -r "option4"
										echo
										if [ "${#option4}" -gt "255" ]; then echo "$option4 Is Not A Valid Comment. 255 Chars Max"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
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
										unset "option1" "option2" "option3" "option4" "option5"
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
							unset "option1" "option2" "option3" "option4" "option5"
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
				if ! Check_Status; then echo "Skynet Not Running - Aborting"; echo; Load_Menu; break; fi
				option1="import"
				echo "Input URL/Local File To Import"
				echo
				printf "[File]: "
				read -r "option2"
				echo
				if [ -z "$option2" ]; then echo "File Field Can't Be Empty - Please Try Again"; echo; unset "option1" "option2"; continue; fi
				break
			;;
			6)
				if ! Check_Status; then echo "Skynet Not Running - Aborting"; echo; Load_Menu; break; fi
				option1="deport"
				echo "Input URL/Local File To Deport"
				echo
				printf "[File]: "
				read -r "option2"
				echo
				if [ -z "$option2" ]; then echo "File Field Can't Be Empty - Please Try Again"; echo; unset "option1" "option2"; continue; fi
				break
			;;
			7)
				if ! Check_Status; then echo "Skynet Not Running - Aborting"; echo; Load_Menu; break; fi
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
							unset "option1" "option2" "option3" "option4" "option5"
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
					echo "[5]  --> SWAP File Management"
					echo "[6]  --> Backup Skynet Files"
					echo "[7]  --> Restore Skynet Files"
					echo
					printf "[1-7]: "
					read -r "menu2"
					echo
					case "$menu2" in
						1)
							option2="disable"
							break
						;;
						2)
							option2="watch"
							while true; do
								echo "Select Watch Option:"
								echo "[1]  --> All"
								echo "[2]  --> IP"
								echo "[3]  --> Port"
								echo
								printf "[1-3]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										break
									;;
									2)
										option3="ip"
										printf "[IP]: "
										read -r "option4"
										echo
										if ! echo "$option4" | Is_IP; then echo "$option4 Is Not A Valid IP"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									3)
										option3="port"
										printf "[Port]: "
										read -r "option4"
										echo
										if ! echo "$option4" | Is_Port || [ "$option4" -gt "65535" ]; then echo "$option4 Is Not A Valid Port"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
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
							option2="info"
							break
						;;
						4)
							option2="clean"
							break
						;;
						5)
							option2="swap"
							while true; do
								echo "Select SWAP Option:"
								echo "[1]  --> Install"
								echo "[2]  --> Uninstall"
								echo
								printf "[1-2]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										option3="install"
										break
									;;
									2)
										option3="uninstall"
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
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
						6)
							option2="backup"
							break
						;;
						7)
							option2="restore"
							break
						;;
						e|exit|back|menu)
							unset "option1" "option2" "option3" "option4" "option5"
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
										if ! [ "$option3" -eq "$option3" ] 2>/dev/null; then echo "$option3 Isn't A Valid Number!"; echo; unset "option3" continue; fi
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break 2
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
										unset "option1" "option2" "option3" "option4" "option5"
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
								echo "Search Options: "
								echo "[1]  --> Based On Port x"
								echo "[2]  --> Entries From Specific IP"
								echo "[3]  --> Search Malwarelists For IP"
								echo "[4]  --> Search Autobans"
								echo "[5]  --> Search Manualbans"
								echo "[6]  --> Search For Outbound Entries From Local Device"
								echo "[7]  --> Hourly Reports"
								echo
								printf "[1-7]: "
								read -r "menu4"
								echo
								case "$menu4" in
									1)
										option3="port"
										printf "[Port]: "
										read -r "option4"
										echo
										if ! echo "$option4" | Is_Port || [ "$option4" -gt "65535" ]; then echo "$option4 Is Not A Valid Port"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									2)
										option3="ip"
										printf "[IP]: "
										read -r "option4"
										echo
										if ! echo "$option4" | Is_IP && ! echo "$option4" | Is_Range ; then echo "$option4 Is Not A Valid IP/Range"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									3)
										option3="malware"
										printf "[IP]: "
										read -r "option4"
										echo
										if ! echo "$option4" | Is_IP && ! echo "$option4" | Is_Range ; then echo "$option4 Is Not A Valid IP/Range"; echo; unset "option3" "option4"; continue; fi
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
									6)
										option3="device"
										printf "[Local IP]: "
										read -r "option4"
										echo
										if ! echo "$option4" | Is_IP; then echo "$option4 Is Not A Valid IP"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									7)
										option3="reports"
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break 2
									;;
									*)
										echo "$menu4 Isn't An Option!"
										echo
									;;
								esac
							done
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
										if [ -n "$option4" ]; then
											option5="10"
										else
											option4="10"
										fi
										break
									;;
									2)
										if [ -n "$option4" ]; then
											option5="20"
										else
											option4="20"
										fi
										break
									;;
									3)
										if [ -n "$option4" ]; then
											option5="50"
										else
											option4="50"
										fi
										break
									;;
									4)
										echo "Enter Custom Amount:"
										echo
										printf "[Number]: "
										read -r "optionx"
										echo
										if ! [ "$optionx" -eq "$optionx" ] 2>/dev/null; then echo "$optionx Isn't A Valid Number!"; echo; unset "optionx"; continue; fi
										if [ -n "$option4" ]; then
											option5="$optionx"
										else
											option4="$optionx"
										fi
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
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
						3)
							option2="reset"
							break
						;;
						e|exit)
							unset "option1" "option2" "option3" "option4" "option5"
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
			r|reload)
				clear
				Load_Menu
				break
			;;
			e|exit)
				echo "Exiting!"
				echo
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
	stime="$(date +%s)"
fi

if [ -f "$skynetcfg" ]; then
	. "$skynetcfg"
fi

case "$1" in
	unban)
		if ! Check_Status; then echo "Skynet Not Running - Aborting"; echo; exit 0; fi
		Check_Lock "$@"
		Purge_Logs
		case "$2" in
			ip)
				if ! echo "$3" | Is_IP; then echo "$3 Is Not A Valid IP"; echo; exit 2; fi
				echo "Unbanning $3"
				ipset -D Skynet-Blacklist "$3"
				sed -i "\\~\\(BLOCKED.*=$3 \\|Manual Ban.*=$3 \\)~d" "$skynetlog" "$skynetevents"
			;;
			range)
				if ! echo "$3" | Is_Range; then echo "$3  Is Not A Valid Range"; echo; exit 2; fi
				echo "Unbanning $3"
				ipset -D Skynet-BlockedRanges "$3"
				sed -i "\\~\\(BLOCKED.*=$3 \\|Manual Ban.*=$3 \\)~d" "$skynetlog" "$skynetevents"
			;;
			domain)
				if [ -z "$3" ]; then echo "Domain Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				logger -st Skynet "[INFO] Removing $3 From Blacklist..."
				for ip in $(Domain_Lookup "$3"); do
					echo "Unbanning $ip"
					ipset -D Skynet-Blacklist "$ip"
					sed -i "\\~\\(BLOCKED.*=$ip \\|Manual Ban.*=$ip \\)~d" "$skynetlog" "$skynetevents"
				done
			;;
			port)
				if ! echo "$3" | Is_Port || [ "$3" -gt "65535" ]; then echo "$3 Is Not A Valid Port"; echo;  exit 2; fi
				logger -st Skynet "[INFO] Unbanning Autobans Issued On Traffic From Source/Destination Port $3..."
				grep -F "NEW" "$skynetlog" | grep -F "PT=$3 " | grep -oE 'SRC=[0-9,\.]* ' | cut -c 5- | awk '{print "del Blacklist "$1}' | ipset restore -!
				sed -i "/PT=${3} /d" "$skynetlog"
			;;
			comment)
				if [ -z "$3" ]; then echo "Comment Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				echo "Removing Bans With Comment Containing ($3)"
				sed "\\~add Skynet-Whitelist ~d;\\~$3~!d;s~ comment.*~~;s~add~del~g" "$skynetipset" | ipset restore -!
				echo "Removing Old Logs - This May Take Awhile (To Skip Type ctrl+c)"
				trap 'break; echo' 2
				sed "\\~add Skynet-Whitelist ~d;\\~$3~!d;s~ comment.*~~" "$skynetipset" | cut -d' ' -f3 | while IFS= read -r "ip"; do
					sed -i "\\~\\(BLOCKED.*=$ip \\|Manual Ban.*=$ip \\)~d" "$skynetlog" "$skynetevents"
				done
			;;
			country)
				echo "Removing Previous Country Bans"
				sed '\~add Skynet-Whitelist ~d;\~Country: ~!d;s~ comment.*~~;s~add~del~g' "$skynetipset" | ipset restore -!
				unset "countrylist"
			;;
			malware)
				echo "Removing Previous Malware Bans"
				sed '\~add Skynet-Whitelist ~d;\~BanMalware~!d;s~ comment.*~~;s~add~del~g' "$skynetipset" | ipset restore -!
			;;
			autobans)
				grep -F "NEW" "$skynetlog" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | tr -d " " | awk '{print "del Blacklist "$1}' | ipset restore -!
				echo "Removing Old Logs - This May Take Awhile (To Skip Type ctrl+c)"
				trap 'break; echo' 2
				grep -F "NEW" "$skynetlog" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | tr -d " " | while IFS= read -r "ip"; do
					sed -i "\\~\\(BLOCKED.*=$ip \\|Manual Ban.*=$ip \\)~d" "$skynetlog" "$skynetevents"
				done
			;;
			nomanual)
				sed -i '\~Manual ~!d' "$skynetlog"
				ipset flush Skynet-Blacklist
				ipset flush Skynet-BlockedRanges
				sed '\~add Skynet-Whitelist ~d;\~Manual[R]*Ban: ~!d' "$skynetipset" | ipset restore -!
				iptables -Z PREROUTING -t raw
			;;
			all)
				logger -st Skynet "[INFO] Removing All $((blacklist1count + blacklist2count)) Entries From Blacklist..."
				ipset flush Skynet-Blacklist
				ipset flush Skynet-BlockedRanges
				iptables -Z PREROUTING -t raw
				true > "$skynetlog"
				sed -i '\~Manual Ban~d' "$skynetevents"

			;;
			*)
				echo "Command Not Recognized, Please Try Again"
				echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
				echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
				echo; exit 2
			;;
		esac
		Save_IPSets
		echo
	;;

	ban)
		if ! Check_Status; then echo "Skynet Not Running - Aborting"; echo; exit 0; fi
		Check_Lock "$@"
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
				ipset -A Skynet-Blacklist "$3" comment "ManualBan: $desc" && echo "$(date +"%b %d %T") Skynet: [Manual Ban] TYPE=Single SRC=$3 COMMENT=$desc " >> "$skynetevents"
			;;
			range)
				if ! echo "$3" | Is_Range; then echo "$3 Is Not A Valid Range"; echo; exit 2; fi
				if [ "${#4}" -gt "255" ]; then echo "$4 Is Not A Valid Comment. 255 Chars Max"; echo; exit 2; fi
				echo "Banning $3"
				desc="$4"
				if [ -z "$4" ]; then
					desc="$(date +"%b %d %T")"
				fi
				ipset -A Skynet-BlockedRanges "$3" comment "ManualRBan: $desc" && echo "$(date +"%b %d %T") Skynet: [Manual Ban] TYPE=Range SRC=$3 COMMENT=$desc " >> "$skynetevents"
			;;
			domain)
				if [ -z "$3" ]; then echo "Domain Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				logger -st Skynet "[INFO] Adding $3 To Blacklist..."
				for ip in $(Domain_Lookup "$3"); do
					echo "Banning $ip"
					ipset -A Skynet-Blacklist "$ip" comment "ManualBanD: $3" && echo "$(date +"%b %d %T") Skynet: [Manual Ban] TYPE=Domain SRC=$ip Host=$3 " >> "$skynetevents"
				done
			;;
			country)
				if [ -z "$3" ]; then echo "Country Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				if [ "${#3}" -gt "246" ]; then countrylist="Multiple Countries"; else countrylist="$3"; fi
				echo "Removing Previous Country Bans"
				sed '\~add Skynet-Whitelist ~d;\~Country: ~!d;s~ comment.*~~;s~add~del~g' "$skynetipset" | ipset restore -!
				echo "Banning Known IP Ranges For $3"
				echo "Downloading Lists"
				for country in $3; do
					/usr/sbin/curl -fsL --retry 3 http://ipdeny.com/ipblocks/data/aggregated/"$country"-aggregated.zone >> /tmp/countrylist.txt
				done
				echo "Filtering IPv4 Ranges & Applying Blacklists"
				grep -F "/" /tmp/countrylist.txt | sed -n "s/\\r//;/^$/d;/^[0-9,\\.,\\/]*$/s/^/add Skynet-BlockedRanges /p" | sed "s/$/& comment \"Country: $countrylist\"/" | ipset restore -!
				rm -rf "/tmp/countrylist.txt"
			;;
			*)
				echo "Command Not Recognized, Please Try Again"
				echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
				echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
				echo; exit 2
			;;
		esac
		Save_IPSets
		echo
	;;

	banmalware)
		if ! Check_Status; then echo "Skynet Not Running - Aborting"; echo; exit 0; fi
		trap '' 2
		Check_Lock "$@"
		Purge_Logs
		if [ "$2" = "reset" ]; then
			echo "Filter URL Reset"
			unset "customlisturl"
		fi
		if [ -n "$2" ] && [ "$2" != "reset" ]; then
			customlisturl="$2"
			listurl="$customlisturl"
			echo "Custom List Detected: $customlisturl"
		else
			if [ -n "$customlisturl" ]; then
				listurl="$customlisturl"
				echo "Custom List Detected: $customlisturl"
			else
				listurl="https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/filter.list"
			fi
		fi
		/usr/sbin/curl -fsL --retry 3 "$listurl" >/dev/null 2>&1 || { logger -st Skynet "[ERROR] 404 Error Detected - Stopping Banmalware" ; exit 1; }
		btime="$(date +%s)" && printf "Downloading filter.list 	"
		/usr/sbin/curl -fsL --retry 3 "$listurl" | dos2unix > /jffs/shared-Skynet-whitelist && $grn "[$(($(date +%s) - btime))s]"
		if [ "$(wc -l < /jffs/shared-Skynet-whitelist)" = "0" ]; then echo >> /jffs/shared-Skynet-whitelist; fi
		btime="$(date +%s)" && printf "Refreshing Whitelists		"
		Whitelist_Extra
		Whitelist_CDN
		Whitelist_VPN
		Whitelist_Shared >/dev/null 2>&1 && $grn "[$(($(date +%s) - btime))s]"
		btime="$(date +%s)" && printf "Consolidating Blacklist 	"
		mkdir -p /tmp/skynet
		cwd="$(pwd)"
		cd /tmp/skynet || exit 1
		while IFS= read -r "domain"; do
			/usr/sbin/curl -fsL --retry 3 "$domain" -O &
		done < /jffs/shared-Skynet-whitelist
		wait
		cd "$cwd" || exit 1
		dos2unix /tmp/skynet/*
		cat /tmp/skynet/* | sed -n "s/\\r//;/^$/d;/^[0-9,\\.,\\/]*$/p" | awk '!x[$0]++' | Filter_PrivateIP > /tmp/skynet/malwarelist.txt && $grn "[$(($(date +%s) - btime))s]"
		btime="$(date +%s)" && printf "Saving Changes 			"
		Save_IPSets >/dev/null 2>&1 && $grn "[$(($(date +%s) - btime))s]"
		btime="$(date +%s)" && printf "Removing Previous Malware Bans  "
		sed -i '\~comment \"BanMalware\"~d' "$skynetipset"
		ipset flush Skynet-Blacklist; ipset flush Skynet-BlockedRanges
		ipset restore -! -f "$skynetipset" && $grn "[$(($(date +%s) - btime))s]"
		btime="$(date +%s)" && printf "Filtering IPv4 Addresses 	"
		grep -vF "/" /tmp/skynet/malwarelist.txt | awk '{print "add Skynet-Blacklist " $1 " comment \"BanMalware\""}' >> "$skynetipset" && $grn "[$(($(date +%s) - btime))s]"
		btime="$(date +%s)" && printf "Filtering IPv4 Ranges 		"
		grep -F "/" /tmp/skynet/malwarelist.txt | awk '{print "add Skynet-BlockedRanges " $1 " comment \"BanMalware\""}' >> "$skynetipset" && $grn "[$(($(date +%s) - btime))s]"
		btime="$(date +%s)" && printf "Applying Blacklists 		"
		ipset restore -! -f "$skynetipset" && $grn "[$(($(date +%s) - btime))s]"
		unset "forcebanmalwareupdate"
		echo
		echo "For False Positive Website Bans Use; ( sh $0 whitelist domain URL )"
		rm -rf /tmp/skynet
		echo
	;;

	whitelist)
		if ! Check_Status; then echo "Skynet Not Running - Aborting"; echo; exit 0; fi
		Check_Lock "$@"
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
				ipset -A Skynet-Whitelist "$3" comment "ManualWlist: $desc" && sed -i "\\~=$3 ~d" "$skynetlog" "$skynetevents" && echo "$(date +"%b %d %T") Skynet: [Manual Whitelist] TYPE=Single SRC=$3 COMMENT=$desc " >> "$skynetevents"
				ipset -q -D Skynet-Blacklist "$3"
				ipset -q -D Skynet-BlockedRanges "$3"
			;;
			domain)
				if [ -z "$3" ]; then echo "Domain Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				logger -st Skynet "[INFO] Adding $3 To Whitelist..."
				for ip in $(Domain_Lookup "$3"); do
					echo "Whitelisting $ip"
					ipset -A Skynet-Whitelist "$ip" comment "ManualWlistD: $3" && sed -i "\\~=$ip ~d" "$skynetlog" "$skynetevents" && echo "$(date +"%b %d %T") Skynet: [Manual Whitelist] TYPE=Domain SRC=$ip Host=$3 " >> "$skynetevents"
					ipset -q -D Skynet-Blacklist "$ip"
				done
			;;
			port)
				if ! echo "$3" | Is_Port || [ "$3" -gt "65535" ]; then echo "$3 Is Not A Valid Port"; echo; exit 2; fi
				logger -st Skynet "[INFO] Whitelisting Autobans Issued On Traffic From Port $3..."
				grep -F "NEW" "$skynetlog" | grep -F "DPT=$3 " | grep -oE 'SRC=[0-9,\.]* ' | cut -c 5- | while IFS= read -r "ip"; do
					echo "Whitelisting $ip"
					ipset -A Skynet-Whitelist "$ip" comment "ManualWlist: Port $3 Traffic" && sed -i "\\~=$ip ~d" "$skynetlog" "$skynetevents" && echo "$(date +"%b %d %T") Skynet: [Manual Whitelist] TYPE=Port SRC=$ip Host=$3 " >> "$skynetevents"
					ipset -q -D Skynet-Blacklist "$ip"
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
						ipset -D Skynet-Whitelist "$4" && sed -i "\\~=$4 ~d" "$skynetlog" "$skynetevents"
					;;
					comment)
						if [ -z "$4" ]; then echo "Comment Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
						echo "Removing All Entries With Comment Matching \"$4\" From Whitelist"
						sed "\\~add Skynet-Whitelist ~!d;\\~$4~!d;s~ comment.*~~;s~add~del~g" "$skynetipset" | ipset restore -!
						sed "\\~add Skynet-Whitelist ~!d;\\~$4~!d" "$skynetipset" | awk '{print $3}' > /tmp/ip.list
						while read -r ip; do
							sed -i "\\~=$ip ~d" "$skynetlog"
						done < /tmp/ip.list
						rm -rf /tmp/ip.list
					;;
					all)
						echo "Flushing Whitelist"
						ipset flush Skynet-Whitelist
						echo "Adding Default Entries"
						true > "$skynetipset"
						sed -i "\\~Manual Whitelist~d" "$skynetevents"
						Whitelist_Extra
						Whitelist_CDN
						Whitelist_VPN
						Whitelist_Shared
					;;
					*)
						echo "Command Not Recognized, Please Try Again"
						echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
						echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
						echo; exit 2
					;;
				esac
			;;
			refresh)
				echo "Refreshing Shared Whitelist Files"
				Whitelist_Extra
				Whitelist_CDN
				Whitelist_VPN
				Whitelist_Shared
				Refresh_MWhitelist
			;;
			list)
				case "$3" in
					ips)
						sed '\~add Skynet-Whitelist ~!d;\~ManualWlist:~!d;s~add Skynet-Whitelist ~~' "$skynetipset"
					;;
					domains)
						sed '\~add Skynet-Whitelist ~!d;\~ManualWlistD:~!d;s~add Skynet-Whitelist ~~' "$skynetipset"
					;;
					*)
						sed '\~add Skynet-Whitelist ~!d;s~add Skynet-Whitelist ~~' "$skynetipset"
					;;
				esac
			;;
			*)
				echo "Command Not Recognized, Please Try Again"
				echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
				echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
				echo; exit 2
			;;
		esac
		Save_IPSets
		echo
	;;

	import)
		if ! Check_Status; then echo "Skynet Not Running - Aborting"; echo; exit 0; fi
		Check_Lock "$@"
		Purge_Logs
		echo "This Function Extracts All IPs And Adds Them ALL To Blacklist"
		if [ -f "$2" ]; then
			echo "Local Custom List Detected: $2"
			cp "$2" /tmp/iplist-unfiltered.txt
		elif [ -n "$2" ]; then
			echo "Remote Custom List Detected: $2"
			/usr/sbin/curl -fsL --retry 3 "$2" -o /tmp/iplist-unfiltered.txt || { logger -st Skynet "[ERROR] 404 Error Detected - Stopping Import"; exit 1; }
		else
			echo "URL Field Can't Be Empty - Please Try Again"
			exit 2
		fi
		dos2unix /tmp/iplist-unfiltered.txt
		if [ "$(grep -cE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' /tmp/iplist-unfiltered.txt)" = "0" ] && [ "$(grep -cE '^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$' /tmp/iplist-unfiltered.txt)" = "0" ]; then { logger -st Skynet "[ERROR] No Content Detected - Stopping Import"; rm -rf /tmp/iplist-unfiltered.txt /tmp/skynet.lock; exit 1; }; fi
		imptime="$(date +"%b %d %T")"
		echo "Filtering IPv4 Addresses"
		grep -oE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' /tmp/iplist-unfiltered.txt | Filter_PrivateIP | awk -v imptime="$imptime" '{print "add Skynet-Blacklist " $1 " comment \"Imported: " imptime "\""}' > /tmp/iplist-filtered.txt
		echo "Filtering IPv4 Ranges"
		grep -oE '^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$' /tmp/iplist-unfiltered.txt | Filter_PrivateIP | awk -v imptime="$imptime" '{print "add Skynet-BlockedRanges " $1 " comment \"Imported: " imptime "\""}' >> /tmp/iplist-filtered.txt
		echo "Adding IPs To Blacklist"
		ipset restore -! -f "/tmp/iplist-filtered.txt"
		rm -rf /tmp/iplist-unfiltered.txt /tmp/iplist-filtered.txt
		Save_IPSets
		echo
	;;

	deport)
		if ! Check_Status; then echo "Skynet Not Running - Aborting"; echo; exit 0; fi
		Check_Lock "$@"		
		Purge_Logs
		echo "This Function Extracts All IPs And Removes Them ALL From Blacklist"
		if [ -f "$2" ]; then
			echo "Local Custom List Detected: $2"
			cp "$2" /tmp/iplist-unfiltered.txt
		elif [ -n "$2" ]; then
			echo "Remote Custom List Detected: $2"
			/usr/sbin/curl -fsL --retry 3 "$2" -o /tmp/iplist-unfiltered.txt || { logger -st Skynet "[ERROR] 404 Error Detected - Stopping Deport"; exit 1; }
		else
			echo "URL Field Can't Be Empty - Please Try Again"
			exit 2
		fi
		dos2unix /tmp/iplist-unfiltered.txt
		if [ "$(grep -cE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' /tmp/iplist-unfiltered.txt)" = "0" ] && [ "$(grep -cE '^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$' /tmp/iplist-unfiltered.txt)" = "0" ]; then { logger -st Skynet "[ERROR] No Content Detected - Stopping Deport"; rm -rf /tmp/iplist-unfiltered.txt /tmp/skynet.lock; exit 1; }; fi
		echo "Filtering IPv4 Addresses"
		grep -oE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' /tmp/iplist-unfiltered.txt | Filter_PrivateIP | awk '{print "del Blacklist " $1}' > /tmp/iplist-filtered.txt
		echo "Filtering IPv4 Ranges"
		grep -oE '^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$' /tmp/iplist-unfiltered.txt | Filter_PrivateIP | awk '{print "del BlockedRanges " $1}' >> /tmp/iplist-filtered.txt
		echo "Removing IPs From Blacklist"
		ipset restore -! -f "/tmp/iplist-filtered.txt"
		rm -rf /tmp/iplist-unfiltered.txt /tmp/iplist-filtered.txt
		Save_IPSets
		echo
	;;

	save)
		if ! Check_Status; then echo "Skynet Not Running - Aborting"; echo; exit 0; fi
		Check_Lock "$@"
		Unban_PrivateIP
		Purge_Logs
		Save_IPSets
		sed -i "\\~USER $(nvram get http_username) pid .*/jffs/scripts/firewall ~d" /tmp/syslog.log
		echo
	;;

	start)
		trap '' 2
		Check_Lock "$@"
		logger -st Skynet "[INFO] Startup Initiated... ( $(echo "$@" | sed 's~start ~~g') )"
		Unload_Cron
		Check_Settings
		Check_Files "verify"
		cru a Skynet_save "0 * * * * sh /jffs/scripts/firewall save"
		modprobe xt_set
		if [ -f "$skynetipset" ]; then ipset restore -! -f "$skynetipset"; else logger -st Skynet "[INFO] Setting Up Skynet..."; touch "$skynetipset"; fi
		if ! ipset -L -n Skynet-Whitelist >/dev/null 2>&1; then ipset -q create Skynet-Whitelist hash:net comment; forcesave=1; fi
		if ! ipset -L -n Skynet-Blacklist >/dev/null 2>&1; then ipset -q create Skynet-Blacklist hash:ip --maxelem 500000 comment; forcesave=1; fi
		if ! ipset -L -n Skynet-BlockedRanges >/dev/null 2>&1; then ipset -q create Skynet-BlockedRanges hash:net --maxelem 200000 comment; forcesave=1; fi
		if ! ipset -L -n Skynet-Master >/dev/null 2>&1; then ipset -q create Skynet-Master list:set; ipset -q -A Skynet-Master Skynet-Blacklist; ipset -q -A Skynet-Master Skynet-BlockedRanges; forcesave=1; fi
		Unban_PrivateIP
		Purge_Logs
		sed '\~add Skynet-Whitelist ~!d;\~nvram: ~!d;s~ comment.*~~;s~add~del~g' "$skynetipset" | ipset restore -!
		Whitelist_Extra
		Whitelist_CDN
		Whitelist_VPN
		Whitelist_Shared
		Refresh_MWhitelist
		Refresh_MBans
		if [ -n "$forcesave" ]; then Save_IPSets; fi
		while [ "$(($(date +%s) - stime))" -lt "20" ]; do
			sleep 1
		done
		Unload_IPTables
		Unload_DebugIPTables
		Load_IPTables
		Load_DebugIPTables
		sed -i '\~DROP IN=~d' /tmp/syslog.log-1 /tmp/syslog.log 2>/dev/null
		if [ "$forcebanmalwareupdate" = "true" ]; then Write_Config; rm -rf "/tmp/skynet.lock"; exec "$0" banmalware; fi
	;;

	restart)
		Check_Lock "$@"
		Purge_Logs
		logger -st Skynet "[INFO] Restarting Skynet..."
		Unload_Cron
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
		Check_Lock "$@"
		logger -st Skynet "[INFO] Disabling Skynet..."
		Unload_Cron
		Save_IPSets
		echo "Unloading IPTables Rules"
		Unload_IPTables
		Unload_DebugIPTables
		echo "Unloading IPSets"
		Unload_IPSets
		Purge_Logs
		echo
		nolog="2"
	;;

	update)
		Check_Lock "$@"
		trap '' 2
		remoteurl="https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/firewall.sh"
		/usr/sbin/curl -fsL --retry 3 "$remoteurl" | grep -qF "Adamm" || { logger -st Skynet "[ERROR] 404 Error Detected - Stopping Update"; exit 1; }
		remotever="$(/usr/sbin/curl -fsL --retry 3 "$remoteurl" | Filter_Version)"
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
			logger -st Skynet "[INFO] New Version Detected - Updating To $remotever..."
			Save_IPSets >/dev/null 2>&1
			Unload_Cron
			Unload_IPTables
			Unload_DebugIPTables
			Unload_IPSets
			iptables -t raw -F
			/usr/sbin/curl -fsL --retry 3 "$remoteurl" -o "$0" && logger -st Skynet "[INFO] Skynet Sucessfully Updated - Restarting Firewall"
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
				trap 'echo; echo "Stopping Log Monitoring"; Purge_Logs' 2
				echo "Watching Logs For Debug Entries (ctrl +c) To Stop"
				echo
				Purge_Logs
				case "$3" in
					ip)
						if ! echo "$4" | Is_IP; then echo "$4 Is Not A Valid IP"; echo; exit 2; fi
						echo "Filtering Entries Involving IP $4"
						echo
						tail -F /tmp/syslog.log | while read -r logoutput; do if echo "$logoutput" | grep -qE "NEW BAN.*=$4 "; then $blue "$logoutput"; elif echo "$logoutput" | grep -qE "INBOUND.*=$4 "; then $ylow "$logoutput"; elif echo "$logoutput" | grep -qE "OUTBOUND.*=$4 "; then $red "$logoutput"; fi; done
					;;
					port)
						if ! echo "$4" | Is_Port || [ "$4" -gt "65535" ]; then echo "$4 Is Not A Valid Port"; echo; exit 2; fi
						echo "Filtering Entries Involving Port $4"
						echo
						tail -F /tmp/syslog.log | while read -r logoutput; do if echo "$logoutput" | grep -qE "NEW BAN.*PT=$4 "; then $blue "$logoutput"; elif echo "$logoutput" | grep -qE "INBOUND.*PT=$4 "; then $ylow "$logoutput"; elif echo "$logoutput" | grep -qE "OUTBOUND.*PT=$4 "; then $red "$logoutput"; fi; done
					;;
					*)
						tail -F /tmp/syslog.log | while read -r logoutput; do if echo "$logoutput" | grep -q "NEW BAN"; then $blue "$logoutput"; elif echo "$logoutput" | grep -q "INBOUND"; then $ylow "$logoutput"; elif echo "$logoutput" | grep -q "OUTBOUND"; then $red "$logoutput"; fi; done
					;;
				esac
				nocfg="1"
			;;
			info)
				echo "Router Model; $model"
				echo "Skynet Version; $localver ($(Filter_Date "$0"))"
				echo "$(iptables --version) - ($iface @ $(nvram get lan_ipaddr))"
				ipset -v
				echo "FW Version; $(nvram get buildno)_$(nvram get extendno) ($(uname -v | awk '{print $5" "$6" "$9}')) ($(uname -r))"
				echo "Install Dir; $skynetloc ($(df -h "$skynetloc" | xargs | awk '{print $11 " / " $9}') Space Available)"
				if grep -F "swapon" /jffs/scripts/post-mount 2>/dev/null | grep -qvE "^#"; then swaplocation="$(grep -o "swapon .*" /jffs/scripts/post-mount | grep -vE "^#" | awk '{print $2}')"; echo "SWAP File; $swaplocation ($(du -h "$swaplocation" | awk '{print $1}'))"; fi
				echo "Boot Args; $(grep -E "start.* # Skynet" /jffs/scripts/firewall-start | grep -vE "^#" | cut -c 4- | cut -d '#' -f1)"
				if [ -n "$countrylist" ]; then echo "Banned Countries; $countrylist"; fi
				if [ -f "/tmp/skynet.lock" ] && [ -d "/proc/$(sed -n '2p' /tmp/skynet.lock)" ]; then $red "Lock File Detected ($(sed -n '1p' /tmp/skynet.lock)) (pid=$(sed -n '2p' /tmp/skynet.lock))"; lockedwarning=1; else $grn "No Lock File Found"; fi
				if [ -n "$lockedwarning" ]; then $ylow "Locked Processes Generally Take 20-60s To Complete And May Result In Temporarily \"Failed\" Tests"; fi
				unset "lockedwarning"
				echo
				printf "Checking Install Directory Write Permissions...		"
				if [ -w "$skynetloc" ]; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking Firewall-Start Entry...			"
				if grep -E "start.* # Skynet" /jffs/scripts/firewall-start | grep -qvE "^#"; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking Services-Stop Entry...				"
				if grep -F "# Skynet" /jffs/scripts/services-stop | grep -qvE "^#"; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking CronJobs...					"
				if [ "$(cru l | grep -c "Skynet")" -ge "2" ]; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking IPSet Comment Support...			"
				if [ -f /lib/modules/"$(uname -r)"/kernel/net/netfilter/ipset/ip_set_hash_ipmac.ko ]; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking Log Level %s Settings...			" "$(nvram get message_loglevel)"
				if [ "$(nvram get message_loglevel)" -le "$(nvram get log_level)" ]; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking Autobanning Status...				"
				if iptables -C logdrop -i "$iface" -m recent --set --name TRACKINVALID --rsource 2>/dev/null && \
				iptables -C logdrop -i "$iface" -m state --state INVALID -m recent --update --seconds 300 --hitcount 2 --name TRACKINVALID --rsource -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null && \
				iptables -C logdrop -i "$iface" -m state --state INVALID -m recent --update --seconds 300 --hitcount 2 --name TRACKINVALID --rsource -j SET --add-set Skynet-Master src 2>/dev/null; then $grn "[Passed]"; elif [ "$autoban" = "disabled" ]; then $ylow "[Disabled]"; else $red "[Failed]"; fi
				printf "Checking For Duplicate Rules In RAW...			"
				if [ "$(iptables-save -t raw | sort | uniq -d | grep -c " ")" = "0" ]; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking For Duplicate Rules In Filter...		"
				if [ "$(iptables-save -t filter | grep -F "A logdrop" | sort | uniq -d | grep -c " ")" = "0" ]; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking Inbound Filter Rules...			"
				if iptables -t raw -C PREROUTING -i "$iface" -m set ! --match-set Skynet-Whitelist src -m set --match-set Skynet-Master src -j DROP 2>/dev/null; then $grn "[Passed]";	elif [ "$filtertraffic" = "outbound" ]; then $ylow "[Disabled]"; else $red "[Failed]"; fi
				printf "Checking Inbound Debug Rules				"
				if iptables -t raw -C PREROUTING -i "$iface" -m set ! --match-set Skynet-Whitelist src -m set --match-set Skynet-Master src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null; then $grn "[Passed]"; elif [ "$debugmode" = "disabled" ] || [ "$filtertraffic" = "outbound" ]; then $ylow "[Disabled]"; else $red "[Failed]"; fi
				printf "Checking Outbound Filter Rules...			"
				if iptables -t raw -C PREROUTING -i br0 -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null; then $grn "[Passed]"; elif [ "$filtertraffic" = "inbound" ]; then $ylow "[Disabled]"; else $red "[Failed]"; fi
				printf "Checking Outbound Debug Rules				"
				if iptables -t raw -C PREROUTING -i br0 -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null; then $grn "[Passed]"; elif [ "$debugmode" = "disabled" ] || [ "$filtertraffic" = "inbound" ]; then $ylow "[Disabled]"; else $red "[Failed]"; fi
				printf "Checking Whitelist IPSet...				"
				if ipset -L -n Skynet-Whitelist >/dev/null 2>&1; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking BlockedRanges IPSet...				"
				if ipset -L -n Skynet-BlockedRanges >/dev/null 2>&1; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking Blacklist IPSet...				"
				if ipset -L -n Skynet-Blacklist >/dev/null 2>&1; then $grn "[Passed]"; else $red "[Failed]"; fi
				printf "Checking Skynet IPSet...				"
				if ipset -L -n Skynet-Master >/dev/null 2>&1; then $grn "[Passed]"; else $red "[Failed]"; fi
				if [ -f "$(/usr/bin/find /mnt/*/adblocking/.config/ab-solution.cfg 2>/dev/null)" ]; then
					printf "Checking For AB-Solution Plus Content...		"
					abcfg="$(find /mnt/*/adblocking/.config/ab-solution.cfg)"
					ablocation="$(dirname "$abcfg")"
					if grep -qE "hostsFileType=.*\\+" "$abcfg"; then
						$grn "[Passed]"
					elif [ -f "${ablocation}/AddPlusHostsDismissed" ]; then
						$ylow "[Dismissed]"
					else
						$red "[Failed]"
					fi
				fi
				nocfg="1"
			;;
			clean)
				echo "Cleaning Syslog Entries..."
				Purge_Logs
				sed '\~Skynet: \[Complete\]~!d' /tmp/syslog.log-1 /tmp/syslog.log 2>/dev/null >> "$skynetevents"
				sed -i '\~Skynet: \[Complete\]~d' /tmp/syslog.log-1 /tmp/syslog.log 2>/dev/null
				echo "Complete!"
				echo
				nolog="2"
				nocfg="1"
			;;
			swap)
				case "$3" in
					install)
						Check_Lock "$@"
						Check_Files
						if ! grep -qF "swapon" /jffs/scripts/post-mount; then
							Manage_Device
							Create_Swap
							echo "Restarting Firewall Service"
							Save_IPSets >/dev/null 2>&1
							Unload_Cron
							Unload_IPTables
							Unload_DebugIPTables
							Unload_IPSets
							service restart_firewall
							exit 0
						else
							echo "Pre-existing SWAP File Detected - Exiting!"
						fi
					;;
					uninstall)
						if ! grep -qF "swapon" /jffs/scripts/post-mount 2>/dev/null; then echo "No SWAP File Detected - Exiting!"; exit 1; fi
						Check_Lock "$@"
						swaplocation="$(grep -o "swapon .*" /jffs/scripts/post-mount | awk '{print $2}')"
						echo "Removing SWAP File... ($swaplocation)"
						if [ -f "$swaplocation" ]; then
							Save_IPSets >/dev/null 2>&1
							swapoff "$swaplocation"
							rm -rf "$swaplocation"
							sed -i '\~swapon ~d' /jffs/scripts/post-mount
							echo "SWAP File Removed"
							echo "Restarting Firewall Service"
							Unload_Cron
							Unload_IPTables
							Unload_DebugIPTables
							Unload_IPSets
							service restart_firewall
							exit 0
						else
							echo "Unable To Remove Existing SWAP File - Please Remove Manually"
							echo
							exit 1
						fi
					;;
					*)
						echo "Command Not Recognized, Please Try Again"
						echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
						echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
						echo; exit 2
					;;
				esac
			;;
			backup)
				if ! Check_Status; then echo "Skynet Not Running - Aborting"; echo; exit 0; fi
				Check_Lock "$@"
				Purge_Logs
				echo "Backing Up Skynet Related Files..."
				echo
				Save_IPSets >/dev/null 2>&1
				tar -czvf "${skynetloc}/Skynet-Backup.tar.gz" -C "$skynetloc" skynet.ipset skynet.log events.log skynet.cfg
				echo
				echo "Backup Saved To ${skynetloc}/Skynet-Backup.tar.gz"
			;;
			restore)
				if ! Check_Status; then echo "Skynet Not Running - Aborting"; echo; exit 0; fi
				Check_Lock "$@"
				backuplocation="${skynetloc}/Skynet-Backup.tar.gz"
				if [ ! -f "$backuplocation" ]; then
					echo "Skynet Backup Doesn't Exist In Expected Path, Please Provide Location"
					echo
					printf "[Location]: "
					read -r "backuplocation"
					echo
					if [ ! -f "$backuplocation" ]; then
						echo "Skynet Backup Doesn't Exist In Specified Path - Exiting"
						echo
						exit 2
					fi
				fi
				echo "Restoring Skynet Backup..."
				echo
				Purge_Logs
				Unload_IPTables
				Unload_DebugIPTables
				Unload_IPSets
				tar -xzvf "$backuplocation" -C "$skynetloc"
				echo
				echo "Backup Restored"
				echo "Restarting Firewall Service"
				service restart_firewall
				exit 0
			;;
			*)
				echo "Command Not Recognized, Please Try Again"
				echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
				echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
				echo; exit 2
			;;
		esac
		echo
	;;

	stats)
		Purge_Logs
		nocfg="1"
		if [ "$debugmode" = "disabled" ]; then
			echo
			$red "!!! Debug Mode Is Disabled !!!"
			$red "To Enable Use ( sh $0 install )"
			echo
		fi
		if [ ! -s "$skynetlog" ] && [ ! -s "$skynetevents" ]; then
			echo "No Debug Data Detected - Give This Time To Generate"
			echo
			exit 0
		else
			echo "Debug Data Detected in $skynetlog - $(du -h "$skynetlog" | awk '{print $1}')"
		fi
		echo "Monitoring From $(grep -m1 -E 'INBOUND|OUTBOUND' "$skynetlog" | awk '{print $1" "$2" "$3}') To $(grep -E 'INBOUND|OUTBOUND' "$skynetlog" | tail -1 | awk '{print $1" "$2" "$3}')"
		echo "$(wc -l < "$skynetlog") Block Events Detected"
		echo "$({ grep -F "INBOUND" "$skynetlog" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- ; grep -F "OUTBOUND" "$skynetlog" | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- ; } | awk '!x[$0]++' | wc -l) Unique IPs"
		echo "$(grep -Fc "NEW BAN" "$skynetlog") Autobans Issued"
		echo "$(grep -Fc "Manual Ban" "$skynetevents") Manual Bans Issued"
		echo
		counter=10
		case "$2" in
			reset)
				sed -i '\~BLOCKED - .*BOUND~d' "$skynetlog"
				sed -i '\~Skynet: \[Complete\]~d' "$skynetevents"
				iptables -Z PREROUTING -t raw
				echo "Stat Data Reset"
			;;
			search)
				case "$3" in
					port)
						if ! echo "$4" | Is_Port || [ "$4" -gt "65535" ]; then echo "$4 Is Not A Valid Port"; echo; exit 2; fi
						if [ "$5" -eq "$5" ] 2>/dev/null; then counter="$5"; fi
						echo "Port $4 First Tracked On $(grep -m1 -F "PT=$4 " "$skynetlog" | awk '{print $1" "$2" "$3}')"
						echo "Port $4 Last Tracked On $(grep -F "PT=$4 " "$skynetlog" | tail -1 | awk '{print $1" "$2" "$3}')"
						echo "$(grep -Foc "PT=$4 " "$skynetlog") Attempts Total"
						echo "$(grep -F "PT=$4 " "$skynetlog" | grep -oE ' SRC=[0-9,\.]* ' | awk '!x[$0]++' | wc -l) Unique IPs"
						echo "$(grep -F "PT=$4 " "$skynetlog" | grep -cF NEW) Autobans From This Port"
						echo
						$red "First Block Tracked On Port $4;"
						grep -m1 -F "PT=$4 " "$skynetlog"
						echo
						$red "$counter Most Recent Blocks On Port $4;";
						grep -F "PT=$4 " "$skynetlog" | tail -"$counter"
						echo
					;;
					ip)
						if ! echo "$4" | Is_IP && ! echo "$4" | Is_Range ; then echo "$4 Is Not A Valid IP/Range"; echo; exit 2; fi
						if [ "$5" -eq "$5" ] 2>/dev/null; then counter="$5"; fi
						ipset test Skynet-Whitelist "$4" && found1=true
						ipset test Skynet-Blacklist "$4" && found2=true
						ipset test Skynet-BlockedRanges "$4" && found3=true
						echo
						if [ -n "$found1" ]; then $red "Whitelist Reason;"; grep -F "add Skynet-Whitelist $4 " "$skynetipset" | awk '{$1=$2=$3=$4=""; print $0}' | tr -s " "; echo; fi
						if [ -n "$found2" ]; then $red "Blacklist Reason;"; grep -F "add Skynet-Blacklist $4 " "$skynetipset" | awk '{$1=$2=$3=$4=""; print $0}' | tr -s " "; echo; fi
						if [ -n "$found3" ]; then $red "BlockedRanges Reason;"; grep -F "add Skynet-BlockedRanges $(echo "$4" | cut -d '.' -f1-3)." "$skynetipset" | awk '{$1=$2=$4=""; print $0}' | tr -s " "; fi
						echo
						echo "$4 First Tracked On $(grep -m1 -F "=$4 " "$skynetlog" | awk '{print $1" "$2" "$3}')"
						echo "$4 Last Tracked On $(grep -F "=$4 " "$skynetlog" | tail -1 | awk '{print $1" "$2" "$3}')"
						echo "$(grep -Foc "=$4 " "$skynetlog") Blocks Total"
						echo
						$red "Event Log Entries From $4;"
						grep -F "=$4 " "$skynetevents"
						echo
						$red "First Block Tracked From $4;"
						grep -m1 -F "=$4 " "$skynetlog"
						echo
						$red "$counter Most Recent Blocks From $4;"
						grep -F "=$4 " "$skynetlog" | tail -"$counter"
						echo
						$red "Top $counter Targeted Ports From $4 (Inbound);"
						grep -E "INBOUND.*SRC=$4 " "$skynetlog" | grep -oE 'DPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://www.speedguide.net/port.php?port="$2}'
						echo
						$red "Top $counter Sourced Ports From $4 (Inbound);"
						grep -E "INBOUND.*SRC=$4 " "$skynetlog" | grep -oE 'SPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://www.speedguide.net/port.php?port="$2}'
					;;
					malware)
						Check_Lock "$@"
						if ! echo "$4" | Is_IP && ! echo "$4" | Is_Range ; then echo "$4 Is Not A Valid IP/Range"; echo; exit 2; fi
						/usr/sbin/curl -fsL --retry 3 https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/filter.list -o /jffs/shared-Skynet-whitelist
						mkdir -p /tmp/skynet
						cwd="$(pwd)"
						cd /tmp/skynet || exit 1
						while IFS= read -r "domain"; do
							/usr/sbin/curl -fsL --retry 3 "$domain" -O &
						done < /jffs/shared-Skynet-whitelist
						wait
						dos2unix /tmp/skynet/*
						cd "$cwd" || exit 1
						$red "Exact Matches;"
						grep -E "^$4$" /tmp/skynet/[!"telemetry.list"]* | cut -d '/' -f4- | sed 's~:~ - ~g;s~^~https://iplists.firehol.org/files/~'
						grep -HE "^$4$" /tmp/skynet/telemetry.list | cut -d '/' -f4- | sed 's~:~ - ~g;s~^~https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/~'
						echo;echo
						$red "Possible CIDR Matches;"
						grep -E "^$(echo "$4" | cut -d '.' -f1-3)..*/" /tmp/skynet/[!"telemetry.list"]* | cut -d '/' -f4- | sed 's~:~ - ~g;s~^~https://iplists.firehol.org/files/~'
						grep -HE "^$(echo "$4" | cut -d '.' -f1-3)..*/" /tmp/skynet/telemetry.list | cut -d '/' -f4- | sed 's~:~ - ~g;s~^~https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/~'
						echo
						rm -rf /tmp/skynet
					;;
					autobans)
						if [ "$4" -eq "$4" ] 2>/dev/null; then counter="$4"; fi
						echo "First Autoban Issued On $(grep -m1 -F "NEW BAN" "$skynetlog" | awk '{print $1" "$2" "$3}')"
						echo "Last Autoban Issued On $(grep -F "NEW BAN" "$skynetlog" | tail -1 | awk '{print $1" "$2" "$3}')"
						echo
						$red "First Autoban Issued;"
						grep -m1 -F "NEW BAN" "$skynetlog"
						echo
						$red "$counter Most Recent Autobans;"
						grep -F "NEW BAN" "$skynetlog" | tail -"$counter"
					;;
					manualbans)
						if [ "$4" -eq "$4" ] 2>/dev/null; then counter="$4"; fi
						echo "First Manual Ban Issued On $(grep -m1 -F "Manual Ban" "$skynetevents" | awk '{print $1" "$2" "$3}')"
						echo "Last Manual Ban Issued On $(grep -F "Manual Ban" "$skynetevents" | tail -1 | awk '{print $1" "$2" "$3}')"
						echo
						$red "First Manual Ban Issued;"
						grep -m1 -F "Manual Ban" "$skynetevents"
						echo
						$red "$counter Most Recent Manual Bans;"
						grep -F "Manual Ban" "$skynetevents" | tail -"$counter"
					;;
					device)
						if ! echo "$4" | Is_IP; then echo "$4 Is Not A Valid IP"; echo; exit 2; fi
						if [ "$5" -eq "$5" ] 2>/dev/null; then counter="$5"; fi
						ipset test Skynet-Whitelist "$4" && found1=true
						ipset test Skynet-Blacklist "$4" && found2=true
						ipset test Skynet-BlockedRanges "$4" && found3=true
						echo
						if [ -n "$found1" ]; then $red "Whitelist Reason;"; grep -F "add Skynet-Whitelist $4 " "$skynetipset" | awk '{$1=$2=$3=$4=""; print $0}' | tr -s " "; echo; fi
						if [ -n "$found2" ]; then $red "Blacklist Reason;"; grep -F "add Skynet-Blacklist $4 " "$skynetipset" | awk '{$1=$2=$3=$4=""; print $0}' | tr -s " "; echo; fi
						if [ -n "$found3" ]; then $red "BlockedRanges Reason;"; grep -F "add Skynet-BlockedRanges $(echo "$4" | cut -d '.' -f1-3)." "$skynetipset" | awk '{$1=$2=$4=""; print $0}' | tr -s " "; fi
						echo
						echo "$4 First Tracked On $(grep -m1 -E "OUTBOUND.* SRC=$4 " "$skynetlog" | awk '{print $1" "$2" "$3}')"
						echo "$4 Last Tracked On $(grep -E "OUTBOUND.* SRC=$4 " "$skynetlog" | tail -1 | awk '{print $1" "$2" "$3}')"
						echo "$(grep -Eoc -E "OUTBOUND.* SRC=$4 " "$skynetlog") Blocks Total"
						echo
						$red "Device Name;"
						if grep -qF " $4 " "/var/lib/misc/dnsmasq.leases"; then grep -F " $4 " "/var/lib/misc/dnsmasq.leases" | awk '{print $4}'; else echo "No Name Found"; fi
						echo
						$red "First Block Tracked From $4;"
						grep -m1 -E "OUTBOUND.* SRC=$4 " "$skynetlog"
						echo
						$red "$counter Most Recent Blocks From $4;"
						grep -E "OUTBOUND.* SRC=$4 " "$skynetlog" | tail -"$counter"
					;;
					reports)
						if [ "$4" -eq "$4" ] 2>/dev/null; then counter="$4"; fi
						sed '\~Skynet: \[Complete\]~!d' /tmp/syslog.log-1 /tmp/syslog.log 2>/dev/null >> "$skynetevents"
						sed -i '\~Skynet: \[Complete\]~d' /tmp/syslog.log-1 /tmp/syslog.log 2>/dev/null
						echo "First Report Issued On $(grep -m1 -F "Skynet: [Complete]" "$skynetevents" | awk '{print $1" "$2" "$3}')"
						echo "Last Report Issued On $(grep -F "Skynet: [Complete]" "$skynetevents" | tail -1 | awk '{print $1" "$2" "$3}')"
						echo
						$red "First Report Issued;"
						grep -m1 -F "Skynet: [Complete]" "$skynetevents"
						echo
						$red "$counter Most Recent Reports;"
						grep -F "Skynet: [Complete]" "$skynetevents" | tail -"$counter"
					;;
					*)
						echo "Command Not Recognized, Please Try Again"
						echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
						echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
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
				grep -E "INBOUND.*$proto" "$skynetlog" | grep -oE 'DPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://www.speedguide.net/port.php?port="$2}'
				echo
				$red "Top $counter Source Ports (Inbound);"
				grep -E "INBOUND.*$proto" "$skynetlog" | grep -oE 'SPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://www.speedguide.net/port.php?port="$2}'
				echo
				$red "Last $counter Unique Connections Blocked (Inbound);"
				grep -E "INBOUND.*$proto" "$skynetlog" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | awk '!x[$0]++' | tail -"$counter" | sed '1!G;h;$!d' | awk '{print "https://otx.alienvault.com/indicator/ip/"$1}'
				echo
				$red "Last $counter Unique Connections Blocked (Outbound);"
				grep -E "OUTBOUND.*$proto" "$skynetlog" | grep -vE 'DPT=80 |DPT=443 ' | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | awk '!x[$0]++' | tail -"$counter" | sed '1!G;h;$!d' | awk '{print "https://otx.alienvault.com/indicator/ip/"$1}'
				echo
				$red "Last $counter Autobans;"
				grep -E "NEW BAN.*$proto" "$skynetlog" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | tail -"$counter" | sed '1!G;h;$!d' | awk '{print "https://otx.alienvault.com/indicator/ip/"$1}'
				echo
				$red "Last $counter Manual Bans;"
				grep -F "Manual Ban" "$skynetevents" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | tail -"$counter" | sed '1!G;h;$!d' | awk '{print "https://otx.alienvault.com/indicator/ip/"$1}'
				echo
				$red "Last $counter Unique HTTP(s) Blocks (Outbound);"
				grep -E 'DPT=80 |DPT=443 ' "$skynetlog" | grep -E "OUTBOUND.*$proto" | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | awk '!x[$0]++' | tail -"$counter" | sed '1!G;h;$!d' | awk '{print "https://otx.alienvault.com/indicator/ip/"$1}'
				echo
				$red "Top $counter HTTP(s) Blocks (Outbound);"
				grep -E 'DPT=80 |DPT=443 ' "$skynetlog" | grep -E "OUTBOUND.*$proto" | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://otx.alienvault.com/indicator/ip/"$2}'
				echo
				$red "Top $counter Blocks (Inbound);"
				grep -E "INBOUND.*$proto" "$skynetlog" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://otx.alienvault.com/indicator/ip/"$2}'
				echo
				$red "Top $counter Blocks (Outbound);"
				grep -E "OUTBOUND.*$proto" "$skynetlog" | grep -vE 'DPT=80 |DPT=443 ' | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1"x https://otx.alienvault.com/indicator/ip/"$2}'
				echo
				$red "Top $counter Blocked Devices (Outbound);"
				grep -E "OUTBOUND.*$proto" "$skynetlog" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{print $1 "x "$2}' > /tmp/skynetstats.txt
				awk '{print $2}' /tmp/skynetstats.txt | while IFS= read -r "localip"; do
					if grep -qF " $localip " "/var/lib/misc/dnsmasq.leases"; then
						sed -i "s~$localip$~$localip $(grep -F " $localip " "/var/lib/misc/dnsmasq.leases" | awk '{print $4}')~g" /tmp/skynetstats.txt
					else
						sed -i "s~$localip$~$localip (No Name Found)~g" /tmp/skynetstats.txt
					fi
				done
				cat /tmp/skynetstats.txt
				rm -rf /tmp/skynetstats.txt
			;;
		esac
		echo
	;;

	install)
		Check_Lock "$@"
		if [ "$(ipset -v | grep -Fo v6)" != "v6" ]; then
			logger -st Skynet "[ERROR] IPSet Version Not Supported"
			exit 1
		fi
		if [ ! -f /lib/modules/"$(uname -r)"/kernel/net/netfilter/ipset/ip_set_hash_ipmac.ko ]; then
			logger -st Skynet "[ERROR] IPSet Extensions Not Supported - Please Update To Latest Firmware"
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
		Check_Files
		echo "Installing Skynet $(Filter_Version "$0")"
		echo
		Manage_Device
		mkdir -p "${device}/skynet"
		echo
		while true; do
			echo "What Type Of Traffic Do You Want To Filter?"
			echo "[1]  --> All  - (Recommended)"
			echo "[2]  --> Inbound"
			echo "[3]  --> Outbound"
			echo
			echo "[e]  --> Exit Menu"
			echo
			echo "Please Select Option"
			printf "[1-3]: "
			read -r "mode1"
			echo
			case "$mode1" in
				1)
					echo "All Traffic Selected"
					filtertraffic="all"
					break
				;;
				2)
					echo "Inbound Traffic Selected"
					filtertraffic="inbound"
					break
				;;
				3)
					echo "Outbound Traffic Selected"
					filtertraffic="outbound"
					break
				;;
				e|exit)
					echo "Exiting!"
					echo
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
			echo "Would You Like To Enable Autobanning?"
			echo "Autobanning Uses The Routers SPI Firewall To Identify & Ban Malicious IP's"
			echo "[1]  --> Yes"
			echo "[2]  --> No"
			echo
			echo "[e]  --> Exit Menu"
			echo
			echo "Please Select Option"
			printf "[1-2]: "
			read -r "mode2"
			echo
			case "$mode2" in
				1)
					echo "Autobanning Enabled"
					autoban="enabled"
					break
				;;
				2)
					echo "Autobanning Disabled"
					autoban="disabled"
					break
				;;
				e|exit)
					echo "Exiting!"
					echo
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
			echo "Would You Like To Enable Debug Mode?"
			echo "Debug Mode Is Used For Generating Stats And Monitoring Blocked IP's"
			echo "[1]  --> Yes  - (Recommended)"
			echo "[2]  --> No"
			echo
			echo "[e]  --> Exit Menu"
			echo
			echo "Please Select Option"
			printf "[1-2]: "
			read -r "mode3"
			echo
			case "$mode3" in
				1)
					echo "Debug Mode Enabled"
					debugmode="enabled"
					break
				;;
				2)
					echo "Debug Mode Disabled"
					debugmode="disabled"
					break
				;;
				e|exit)
					echo "Exiting!"
					echo
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
			echo "Would You Like To Enable Automatic Malwarelist Updating?"
			echo "[1]  --> Yes (Daily)  - (Recommended)"
			echo "[2]  --> Yes (Weekly)"
			echo "[3]  --> No"
			echo
			echo "[e]  --> Exit Menu"
			echo
			echo "Please Select Option"
			printf "[1-3]: "
			read -r "mode4"
			echo
			case "$mode4" in
				1)
					echo "Malware List Updating Enabled & Scheduled For 2.25am Every Day"
					banmalwareupdate="daily"
					forcebanmalwareupdate="true"
					break
				;;
				2)
					echo "Malware List Updating Enabled & Scheduled For 2.25am Every Monday"
					banmalwareupdate="weekly"
					break
				;;
				3)
					echo "Malware List Updating Disabled"
					banmalwareupdate="disabled"
					forcebanmalwareupdate="true"
					break
				;;
				e|exit)
					echo "Exiting!"
					echo
					exit 0
				;;
				*)
					echo "$mode4 Isn't An Option!"
					echo
				;;
			esac
		done
		echo
		echo
		while true; do
			echo "Would You Like To Enable Weekly Skynet Updating?"
			echo "[1]  --> Yes  - (Recommended)"
			echo "[2]  --> No"
			echo
			echo "[e]  --> Exit Menu"
			echo
			echo "Please Select Option"
			printf "[1-2]: "
			read -r "mode5"
			echo
			case "$mode5" in
				1)
					echo "Skynet Updating Enabled & Scheduled For 1.25am Every Monday"
					autoupdate="enabled"
					break
				;;
				2)
					echo "Auto Updating Disabled"
					autoupdate="disabled"
					break
				;;
				e|exit)
					echo "Exiting!"
					echo
					exit 0
				;;
				*)
					echo "$mode5 Isn't An Option!"
					echo
				;;
			esac
		done
		echo
		echo
		if ! grep -F "swapon" /jffs/scripts/post-mount | grep -qvE "^#" && ! grep -F "swap" /jffs/configs/fstab 2>/dev/null | grep -qvE "^#"; then Create_Swap; fi
		if [ -n "$forceupgrade" ]; then Upgrade_v6; fi
		if [ -f "$skynetlog" ]; then mv "$skynetlog" "${device}/skynet/skynet.log"; fi
		if [ -f "$skynetevents" ]; then mv "$skynetevents" "${device}/skynet/events.log"; fi
		if [ -f "$skynetipset" ]; then mv "$skynetipset" "${device}/skynet/skynet.ipset"; fi
		if [ -f "${skynetloc}/Skynet-Backup.tar.gz" ]; then mv "${skynetloc}/Skynet-Backup.tar.gz" "${device}/skynet/Skynet-Backup.tar.gz"; fi
		if [ "$skynetloc" != "${device}/skynet" ]; then rm -rf "$skynetloc"; fi
		skynetloc="${device}/skynet"
		skynetcfg="${device}/skynet/skynet.cfg"
		touch "${device}/skynet/events.log"
		touch "${device}/skynet/skynet.log"
		[ -z "$(nvram get odmpid)" ] && model="$(nvram get productid)" || model="$(nvram get odmpid)"
		Write_Config
		cmdline="sh /jffs/scripts/firewall start skynetloc=${device}/skynet # Skynet Firewall Addition"
		if grep -E "sh /jffs/scripts/firewall .* # Skynet" /jffs/scripts/firewall-start 2>/dev/null | grep -qvE "^#"; then
			sed -i "s~sh /jffs/scripts/firewall .* # Skynet .*~$cmdline~" /jffs/scripts/firewall-start
		else
			echo "$cmdline" >> /jffs/scripts/firewall-start
		fi
		cmdline="sh /jffs/scripts/firewall save # Skynet Firewall Addition"
		if grep -E "sh /jffs/scripts/firewall .* # Skynet" /jffs/scripts/services-stop 2>/dev/null | grep -qvE "^#"; then
			sed -i "s~sh /jffs/scripts/firewall .* # Skynet .*~$cmdline~" /jffs/scripts/services-stop
		else
			echo "$cmdline" >> /jffs/scripts/services-stop
		fi
		chmod 0755 /jffs/scripts/*
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
		Write_Config
		service restart_firewall
		exit 0
	;;

	uninstall)
		echo "If You Were Experiencing Issues, Try Update Or Visit SNBForums/Github For Support"
		echo "https://github.com/Adamm00/IPSet_ASUS"
		echo
		while true; do
			echo "Are You Sure You Want To Uninstall?"
			echo
			echo "[1]  --> Yes"
			echo "[2]  --> No"
			echo
			echo "Please Select Option"
			printf "[1-2]: "
			read -r "continue"
			echo
			case "$continue" in
				1)
					if grep -E "swapon .* # Skynet" /jffs/scripts/post-mount 2>/dev/null | grep -qvE "^#"; then
						while true; do
							echo "Would You Like To Remove Skynet Generated Swap File?"
							echo "[1]  --> Yes"
							echo "[2]  --> No"
							echo
							echo "Please Select Option"
							printf "[1-2]: "
							read -r "removeswap"
							echo
							case "$removeswap" in
								1)
									echo "Removing Skynet Generated SWAP File..."
									swaplocation="$(grep -o "swapon .*" /jffs/scripts/post-mount | grep -vE "^#" | awk '{print $2}')"
									sed -i '\~ Skynet ~d' /jffs/scripts/post-mount
									swapoff "$swaplocation"
									rm -rf "$swaplocation"
									break
								;;
								2)
									break
								;;
								e|exit)
									echo "Exiting!"
									echo
									exit 0
								;;
								*)
									echo "$removeswap Isn't An Option!"
									echo
								;;
							esac
						done
					fi
					echo "Uninstalling Skynet And Restarting Firewall"
					Purge_Logs
					Unload_Cron
					Kill_Lock
					Unload_IPTables
					Unload_DebugIPTables
					Unload_IPSets
					nvram set fw_log_x=none
					sed -i '\~ Skynet ~d' /jffs/scripts/firewall-start /jffs/scripts/services-stop
					rm -rf "/jffs/shared-Skynet-whitelist" "/jffs/shared-Skynet2-whitelist" "/opt/bin/firewall" "$skynetloc" "/jffs/scripts/firewall" "/tmp/skynet.lock"
					iptables -t raw -F
					service restart_firewall
					exit 0
				;;
				2|e|exit)
					echo "Exiting!"
					echo
					exit 0
				;;
				*)
					echo "$continue Isn't An Option!"
					echo
				;;
			esac
		done
	;;

	*)
		echo "Command Not Recognized, Please Try Again"
		echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
		echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
		echo
	;;

esac

if [ "$nolog" != "2" ]; then Logging "$@"; echo; fi
if [ "$nocfg" != "1" ]; then Write_Config; fi
if [ -f "/tmp/skynet.lock" ] && [ "$$" = "$(sed -n '2p' /tmp/skynet.lock)" ]; then rm -rf "/tmp/skynet.lock"; fi
if [ -n "$reloadmenu" ]; then echo; echo; printf "Press Enter To Continue..."; read -r "continue"; exec "$0"; fi