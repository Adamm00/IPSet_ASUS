#!/bin/sh
#############################################################################################################
#                                                                                                           #
#                  ███████╗██╗  ██╗██╗   ██╗███╗   ██╗███████╗████████╗    ██╗   ██╗███████╗                #
#                  ██╔════╝██║ ██╔╝╚██╗ ██╔╝████╗  ██║██╔════╝╚══██╔══╝    ██║   ██║╚════██║                #
#                  ███████╗█████╔╝  ╚████╔╝ ██╔██╗ ██║█████╗     ██║       ██║   ██║    ██╔╝                #
#                  ╚════██║██╔═██╗   ╚██╔╝  ██║╚██╗██║██╔══╝     ██║       ╚██╗ ██╔╝   ██╔╝                 #
#                  ███████║██║  ██╗   ██║   ██║ ╚████║███████╗   ██║        ╚████╔╝    ██║                  #
#                  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝╚══════╝   ╚═╝         ╚═══╝     ╚═╝                  #
#                                                                                                           #
#                                 Router Firewall And Security Enhancements                                 #
#                             By Adamm -  https://github.com/Adamm00/IPSet_ASUS                             #
#                                            07/02/2024 - v7.5.8                                            #
#############################################################################################################


export PATH="/sbin:/bin:/usr/sbin:/usr/bin:$PATH"
printf '\033[?7l'
clear
sed -n '2,14p' "$0"
export LC_ALL=C
mkdir -p /tmp/skynet/lists
mkdir -p /jffs/addons/shared-whitelists

ntptimer="0"
while [ "$(nvram get ntp_ready)" = "0" ] && [ "$ntptimer" -lt "300" ] && ! echo "$1" | grep -qE "(uninstall|disable)"; do
	ntptimer="$((ntptimer + 1))"
	if [ "$ntptimer" = "60" ]; then echo; logger -st Skynet "[*] Waiting For NTP To Sync"; fi
	sleep 1
done
if [ "$ntptimer" -ge "300" ]; then logger -st Skynet "[*] NTP Failed To Start After 5 Minutes - Please Fix Immediately!"; echo; exit 1; fi

skynetloc="$(grep -ow "skynetloc=.* # Skynet" /jffs/scripts/firewall-start 2>/dev/null | grep -vE "^#" | awk '{print $1}' | cut -c 11-)"
skynetcfg="${skynetloc}/skynet.cfg"
skynetlog="${skynetloc}/skynet.log"
skynetevents="${skynetloc}/events.log"
skynetipset="${skynetloc}/skynet.ipset"
stime="$(date +%s)"

if [ -z "${skynetloc}" ] && tty >/dev/null 2>&1; then
	set "install"
fi

###############
#- Functions -#
###############

Kill_Lock() {
	if [ -f "/tmp/skynet.lock" ] && [ -d "/proc/$(sed -n '2p' /tmp/skynet.lock)" ]; then
		logger -st Skynet "[*] Killing Locked Processes ($(sed -n '1p' /tmp/skynet.lock)) (pid=$(sed -n '2p' /tmp/skynet.lock))"
		logger -st Skynet "[*] $(ps | awk -v pid="$(sed -n '2p' /tmp/skynet.lock)" '$1 == pid')"
		kill "$(sed -n '2p' /tmp/skynet.lock)"
		rm -rf /tmp/skynet.lock
		echo
	fi
}

Check_Lock() {
	if [ -f "/tmp/skynet.lock" ] && [ -d "/proc/$(sed -n '2p' /tmp/skynet.lock)" ] && [ "$(sed -n '2p' /tmp/skynet.lock)" != "$$" ]; then
		if [ "$(($(date +%s) - $(sed -n '3p' /tmp/skynet.lock)))" -gt "1800" ]; then
			Kill_Lock
		else
			logger -st Skynet "[*] Lock File Detected ($(sed -n '1p' /tmp/skynet.lock)) (pid=$(sed -n '2p' /tmp/skynet.lock)) - Exiting (cpid=$$)"
			echo; exit 1
		fi
	fi
	echo "$@" > /tmp/skynet.lock
	echo "$$" >> /tmp/skynet.lock
	date +%s >> /tmp/skynet.lock
	lockskynet="true"
}

if [ ! -d "${skynetloc}" ] && ! echo "$@" | grep -wqE "(install|uninstall|disable|update|restart|info)"; then
	Check_Lock "$@"
	usbtest="0"
	if [ -z "${skynetloc}" ]; then usbtest="10"; fi
	while [ ! -d "${skynetloc}" ] && [ "$usbtest" -le "10" ]; do
		usbtest="$((usbtest + 1))"
		logger -st Skynet "[*] USB Not Found - Sleeping For 10 Seconds ( Attempt $usbtest Of 10 )"
		sleep 10
	done
	if [ ! -d "${skynetloc}" ] || [ ! -w "${skynetloc}" ]; then
		logger -st Skynet "[*] Problem With USB Install Location - Please Fix Immediately!"
		logger -st Skynet "[*] To Change Install Location Run - ( sh $0 install )"
		echo; exit 1
	fi
fi

if [ "$(nvram get wan0_proto)" = "pppoe" ]; then
	iface="ppp0"
else
	iface="$(nvram get wan0_ifname)"
fi

Red() {
	printf -- '\033[1;31m%s\033[0m\n' "$1"
}

Grn() {
	printf -- '\033[1;32m%s\033[0m\n' "$1"
}

Blue() {
	printf -- '\033[1;36m%s\033[0m\n' "$1"
}

Ylow() {
	printf -- '\033[1;33m%s\033[0m\n' "$1"
}

Check_Swap() {
	grep -qF "file" "/proc/swaps"
}

Check_Settings() {
	if [ ! -f "$skynetcfg" ]; then
		logger -st Skynet "[*] Configuration File Not Detected - Please Use ( sh $0 install ) To Continue"
		echo; exit 1
	fi

	unset "swaplocation"
	if grep -qE "^swapon " /jffs/scripts/post-mount; then
		if Check_Swap; then
			swaplocation="$(grep -m1 -F "file" "/proc/swaps" | awk '{print $1}')"
			if [ "$(grep -E "^swapon " /jffs/scripts/post-mount | awk '{print $2}')" != "$swaplocation" ] && echo "$swaplocation" | grep -E "/..*/"; then
				logger -st Skynet "[*] Restoring Missing Swap File Entry ( $swaplocation )"
				sed -i '\~swapon ~d' /jffs/scripts/post-mount
				if [ "$(wc -l < /jffs/scripts/post-mount)" -lt "2" ]; then echo >> /jffs/scripts/post-mount; fi
				sed -i "2i swapon $swaplocation # Skynet" /jffs/scripts/post-mount
			fi
		else
			sleep 10
			swapon "$(grep -E "^swapon " /jffs/scripts/post-mount | awk '{print $2}')" 2>/dev/null
		fi
	else
		logger -st Skynet "[*] Scanning /tmp/mnt For Swap Files"
		findswap="$(find /tmp/mnt -name "myswap.swp")"
		if [ -n "$findswap" ] && [ -f "$findswap" ]; then
			logger -st Skynet "[*] Restoring Damaged Swap File Entry ( $findswap )"
			sed -i '\~swapon ~d' /jffs/scripts/post-mount
			if [ "$(wc -l < /jffs/scripts/post-mount)" -lt "2" ]; then echo >> /jffs/scripts/post-mount; fi
			sed -i "2i swapon $findswap # Skynet" /jffs/scripts/post-mount
			if ! Check_Swap; then swapon "$findswap"; fi
			swaplocation="$findswap"
		elif Check_Swap; then
			findswap="$(grep -m1 -F "file" "/proc/swaps" | awk '{print $1}')"
			if [ -n "$findswap" ] && [ -f "$findswap" ]; then
				logger -st Skynet "[*] Restoring Missing Swap File Entry ( $findswap )"
				sed -i '\~swapon ~d' /jffs/scripts/post-mount
				if [ "$(wc -l < /jffs/scripts/post-mount)" -lt "2" ]; then echo >> /jffs/scripts/post-mount; fi
				sed -i "2i swapon $findswap # Skynet" /jffs/scripts/post-mount
				swaplocation="$findswap"
			fi
		fi
	fi
	if [ -n "$swaplocation" ] && [ ! -f "$swaplocation" ]; then
		logger -st Skynet "[*] SWAP File Missing ( $swaplocation ) - Fix This By Running ( $0 debug swap uninstall ) Then ( $0 debug swap install )"
		echo; exit 1
	elif grep -m1 -qF "partition" "/proc/swaps"; then
		logger -st Skynet "[*] SWAP Partitions Not Supported - Please Use SWAP File"
		echo; exit 1
	elif [ -z "$swaplocation" ] && ! Check_Swap; then
		logger -st Skynet "[*] Skynet Requires A SWAP File - Install One By Running ( $0 debug swap install )"
		echo; exit 1
	fi

	if [ -n "$swaplocation" ] && [ "$(du "$swaplocation" | awk '{print $1}')" -lt "1048576" ]; then
		logger -st Skynet "[*] SWAP File Too Small - 1GB Minimum Required - Please Fix Immediately!"
	fi

	if [ "$(nvram get fw_log_x)" != "drop" ] && [ "$(nvram get fw_log_x)" != "both" ]; then
		nvram set fw_log_x=drop
		nvram commit
		restartfirewall="1"
	fi

	localver="$(Filter_Version < "$0")"

	if [ "$banmalwareupdate" = "daily" ]; then
		Load_Cron "banmalwaredaily"
	elif [ "$banmalwareupdate" = "weekly" ]; then
		Load_Cron "banmalwareweekly"
	fi

	if [ "$autoupdate" = "enabled" ]; then
		Load_Cron "autoupdate"
	else
		Load_Cron "checkupdate"
	fi

	if [ -d "/opt/bin" ] && [ ! -L "/opt/bin/firewall" ]; then
		ln -s /jffs/scripts/firewall /opt/bin
	fi

	if ! grep -F "sh /jffs/scripts/firewall" /jffs/configs/profile.add; then
		echo "alias firewall=\"sh /jffs/scripts/firewall\" # Skynet" >> /jffs/configs/profile.add
	fi

	if [ "$(nvram get jffs2_scripts)" != "1" ]; then
		nvram set jffs2_scripts=1
		nvram commit
		logger -st Skynet "[*] Custom JFFS Scripts Enabled - Please Manually Reboot To Apply Changes"
	fi

	if [ "$(nvram get fw_enable_x)" != "1" ]; then
		nvram set fw_enable_x=1
		nvram commit
		restartfirewall="1"
	fi

	if [ -f "/opt/var/log/dnsmasq.log" ]; then
		extendedstats="enabled"
	else
		extendedstats="disabled"
	fi

	if [ -z "$iotlogging" ]; then
		iotlogging="enabled"
	fi

	if ps | grep -F "/sbin/syslogd" | grep -qF "/jffs/syslog.log" && [ "$syslogloc" = "/tmp/syslog.log" ]; then
		syslogloc="/jffs/syslog.log" # Fix syslog location on newer random models
		syslog1loc="/jffs/syslog.log-1"
	fi
	if [ -f "/opt/bin/scribe" ] && [ ! -f "/opt/etc/syslog-ng.d/skynet" ] && [ -f "/opt/share/syslog-ng/examples/skynet" ]; then
		logger -st Skynet "[i] Installing Scribe Plugin"
		rm -rf "/opt/etc/syslog-ng.d/firewall" "/opt/etc/logrotate/firewall"
		cp -p "/opt/share/syslog-ng/examples/skynet" "/opt/etc/syslog-ng.d"
		syslogloc="$(grep -m1 "file(" "/opt/etc/syslog-ng.d/skynet" | awk -F "\"" '{print $2}')"
		killall -HUP syslog-ng
	elif [ -f "/opt/bin/scribe" ] && [ -f "/opt/etc/syslog-ng.d/skynet" ] && [ "$syslogloc" = "/tmp/syslog.log" ]; then
		syslogloc="$(grep -m1 "file(" "/opt/etc/syslog-ng.d/skynet" | awk -F "\"" '{print $2}')"
	fi

	if nvram get wan0_ipaddr | Is_PrivateIP; then
		logger -st Skynet "[*] Private WAN IP Detected $(nvram get wan0_ipaddr) - Please Put Your Modem In Bridge Mode / Disable CG-NAT"
	fi
}

Check_Connection() {
	livecheck="0"
	websites="google.com github.com snbforums.com"

	while [ "$livecheck" -lt 4 ]; do
		for website in $websites; do
			if ping -q -w3 -c1 "$website" >/dev/null 2>&1; then
				return 0
			fi
		done

		livecheck=$((livecheck + 1))
		if [ "$livecheck" -lt 4 ]; then
			echo "[*] Internet Connectivity Error"
			sleep 10
		else
			return 1
		fi
	done
}

Check_Files() {
	if [ ! -f "/jffs/scripts/firewall-start" ]; then
		echo "#!/bin/sh" > /jffs/scripts/firewall-start
		echo >> /jffs/scripts/firewall-start
	elif [ -f "/jffs/scripts/firewall-start" ] && ! head -1 /jffs/scripts/firewall-start | grep -qE "^#!/bin/sh"; then
		sed -i '1s~^~#!/bin/sh\n~' /jffs/scripts/firewall-start
	fi
	if [ ! -f "/jffs/scripts/services-stop" ]; then
		echo "#!/bin/sh" > /jffs/scripts/services-stop
		echo >> /jffs/scripts/services-stop
	elif [ -f "/jffs/scripts/services-stop" ] && ! head -1 /jffs/scripts/services-stop | grep -qE "^#!/bin/sh"; then
		sed -i '1s~^~#!/bin/sh\n~' /jffs/scripts/services-stop
	fi
	if [ ! -f "/jffs/scripts/service-event" ]; then
		echo "#!/bin/sh" > /jffs/scripts/service-event
		echo >> /jffs/scripts/service-event
	elif [ -f "/jffs/scripts/service-event" ] && ! head -1 /jffs/scripts/service-event | grep -qE "^#!/bin/sh"; then
		sed -i '1s~^~#!/bin/sh\n~' /jffs/scripts/service-event
	fi
	if ! grep -vE "^#" /jffs/scripts/service-event | grep -qF "sh /jffs/scripts/firewall debug genstats"; then
		cmdline="if [ \"\$1\" = \"start\" ] && [ \"\$2\" = \"SkynetStats\" ]; then sh /jffs/scripts/firewall debug genstats; fi # Skynet"
		sed -i '\~# Skynet~d' /jffs/scripts/service-event
		echo "$cmdline" >> /jffs/scripts/service-event
	fi
	if [ ! -f "/jffs/scripts/post-mount" ]; then
		echo "#!/bin/sh" > /jffs/scripts/post-mount
		echo >> /jffs/scripts/post-mount
	elif [ -f "/jffs/scripts/post-mount" ] && ! head -1 /jffs/scripts/post-mount | grep -qE "^#!/bin/sh"; then
		sed -i '1s~^~#!/bin/sh\n~' /jffs/scripts/post-mount
	fi
	if [ ! -f "/jffs/scripts/unmount" ]; then
		echo "#!/bin/sh" > /jffs/scripts/unmount
		echo >> /jffs/scripts/unmount
	elif [ -f "/jffs/scripts/unmount" ] && ! head -1 /jffs/scripts/unmount | grep -qE "^#!/bin/sh"; then
		sed -i '1s~^~#!/bin/sh\n~' /jffs/scripts/unmount
	fi
	if ! grep -qE "^swapoff " /jffs/scripts/unmount; then
		sed -i '\~swapoff ~d' /jffs/scripts/unmount
		echo "swapoff -a 2>/dev/null # Skynet" >> /jffs/scripts/unmount
	fi
	if ! grep -vE "^#" /jffs/scripts/services-stop | grep -qF "sh /jffs/scripts/firewall save"; then
		echo "sh /jffs/scripts/firewall save # Skynet" >> /jffs/scripts/services-stop
	fi
	if [ "$(wc -l < /jffs/scripts/post-mount)" -lt "2" ]; then echo >> /jffs/scripts/post-mount; fi
	chmod 755 "/jffs/scripts/firewall" "/jffs/scripts/firewall-start" "/jffs/scripts/services-stop" "/jffs/scripts/service-event" "/jffs/scripts/post-mount" "/jffs/scripts/unmount"
}

Check_Security() {
	if [ "$securemode" = "enabled" ]; then
		if [ "$(nvram get sshd_enable)" = "1" ] && [ "$(uname -o)" = "ASUSWRT-Merlin" ]; then
			logger -st Skynet "[!] Insecure Setting Detected - Disabling WAN SSH Access"
			nvram set sshd_enable="2"
			nvram commit
			restartfirewall="1"
		fi
		if [ "$(nvram get sshd_wan)" = "1" ] && [ "$(uname -o)" = "ASUSWRT-Merlin-LTS" ]; then
			logger -st Skynet "[!] Insecure Setting Detected - Disabling WAN SSH Access"
			nvram set sshd_wan="0"
			nvram commit
			restartfirewall="1"
		fi
		if [ "$(nvram get misc_http_x)" = "1" ]; then
			logger -st Skynet "[!] Insecure Setting Detected - Disabling WAN GUI Access"
			nvram set misc_http_x="0"
			nvram commit
			restartfirewall="1"
		fi
	fi
	if [ "$(nvram get pptpd_enable)" = "1" ] && nvram get pptpd_clientlist | grep -qE 'i[0-9]{7}|p[0-9]{7}'; then
		logger -st Skynet "[!] PPTP VPN Server Shows Signs Of Compromise - Investigate Immediately!"
		nvram set pptpd_enable="0"
		nvram set pptpd_broadcast="0"
		nvram commit
		echo "[i] Stopping PPTP Service"
		service stop_pptpd
		echo "[i] Restarting Samba Service"
		service restart_samba
		restartfirewall="1"
	fi
	if [ -e "/var/run/tor" ] || [ -e "/var/run/torrc" ] || [ -e "/var/run/tord" ] || [ -e "/var/run/vpnfilterm" ] || [ -e "/var/run/vpnfilterw" ]; then
		logger -st Skynet "[!] Suspected VPNFilter Malware Found - Investigate Immediately!"
		logger -st Skynet "[!] Caching Potential VPNFilter Malware: ${skynetloc}/vpnfilter.tar.gz"
		tar -czf "${skynetloc}/vpnfilter.tar.gz" "/var/run/tor" "/var/run/torrc" "/var/run/tord" "/var/run/vpnfilterm" "/var/run/vpnfilterw" >/dev/null 2>&1
		rm -rf "/var/run/tor" "/var/run/torrc" "/var/run/tord" "/var/run/vpnfilterm" "/var/run/vpnfilterw"
		restartfirewall="1"
	fi
	if [ -f "/jffs/chkupdate.sh" ] || [ -f "/tmp/update" ] || [ -f "/tmp/.update.log" ] || [ -f "/jffs/runtime.log" ] || grep -qF "upgrade.sh" "/jffs/scripts/openvpn-event" 2>/dev/null; then
		logger -st Skynet "[!] Warning! Router Malware Detected (chkupdate.sh) - Investigate Immediately!"
		grep -hoE '([0-9]{1,3}\.){3}[0-9]{1,3}' "/jffs/chkupdate.sh" "/tmp/update" "/tmp/.update.log" "/jffs/runtime.log" "/jffs/scripts/openvpn-event" 2>/dev/null | awk '!x[$0]++' | while IFS= read -r "ip"; do
			echo "add Skynet-Blacklist $ip comment \"Malware: chkupdate.sh\""
		done | ipset restore -!
	fi
	if [ -f "/jffs/updater" ] || [ -f "/jffs/p32" ] || [ -f "/tmp/pawns-cli" ] || [ -f "/tmp/updateservice" ] || nvram get "jffs2_exec" | grep -qF "/jffs/updater" || nvram get "script_usbmount" | grep -qF "/jffs/updater" || nvram get "script_usbumount" | grep -qF "/jffs/updater" || nvram get "vpn_server_custom" | grep -qF "/jffs/updater" || nvram get "vpn_server1_custom" | grep -qF "/jffs/updater" || cru l | grep -qF "/jffs/updater" 2>/dev/null; then
		logger -st Skynet "[!] Warning! Router Malware Detected (/jffs/updater) - Investigate Immediately!"
		logger -st Skynet "[!] Caching Potential Updater Malware: ${skynetloc}/malwareupdater.tar.gz"
		nvram savefile "/tmp/nvramoutput.txt"
		tar -czf "${skynetloc}/malwareupdater.tar.gz" "/jffs/updater" "/jffs/p32" "/tmp/pawns-cli" "/tmp/updateservice" "/tmp/nvramoutput.txt" "/root/.profile" >/dev/null 2>&1
		rm -rf "/jffs/updater" "/jffs/p32" "/tmp/pawns-cli" "/tmp/updateservice" "/tmp/nvramoutput.txt"
		echo > "/root/.profile"
		cru d updater
		nvram unset jffs2_exec
		nvram unset script_usbmount
		nvram unset script_usbumount
		nvram unset vpn_server_custom
		nvram unset vpn_server1_custom
		nvram set vpn_server_state=0
		nvram set vpn_server1_state=0
		nvram commit
		restartfirewall="1"
	fi
}

Clean_Temp() {
	rm -rf /tmp/skynet/*
	mkdir -p /tmp/skynet/lists
}

Unload_IPTables() {
	iptables -t raw -D PREROUTING -i wgs+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null
	iptables -t raw -D PREROUTING -i tun2+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null
	iptables -t raw -D PREROUTING -i "$iface" -m set ! --match-set Skynet-MasterWL src -m set --match-set Skynet-Master src -j DROP 2>/dev/null
	iptables -t raw -D PREROUTING -i br+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null
	iptables -t raw -D OUTPUT -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null
	iptables -D logdrop -m state --state NEW -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	ip6tables -D logdrop -m state --state NEW -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -D logdrop -m state --state NEW -m limit --limit 4/sec -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	ip6tables -D logdrop -m state --state NEW -m limit --limit 4/sec -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
}

Load_IPTables() {
	if [ "$(nvram get wgs_enable)" = "1" ]; then
		iptables -t raw -I PREROUTING -i wgs+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null
	fi
	if [ "$(nvram get vpn_server1_state)" != "0" ] || [ "$(nvram get vpn_server2_state)" != "0" ]; then
		iptables -t raw -I PREROUTING -i tun2+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null
	fi
	if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then
		iptables -t raw -I PREROUTING -i "$iface" -m set ! --match-set Skynet-MasterWL src -m set --match-set Skynet-Master src -j DROP 2>/dev/null
	fi
	if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
		iptables -t raw -I PREROUTING -i br+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null
		iptables -t raw -I OUTPUT -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null
	fi
}

Unload_LogIPTables() {
	iptables -t raw -D PREROUTING -i wgs+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -t raw -D PREROUTING -i tun2+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -t raw -D PREROUTING -i "$iface" -m set ! --match-set Skynet-MasterWL src -m set --match-set Skynet-Master src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -t raw -D PREROUTING -i br+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -t raw -D OUTPUT -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -D logdrop -m state --state NEW -j LOG --log-prefix "[BLOCKED - INVALID] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -D FORWARD -i br+ -m set --match-set Skynet-IOT src -j LOG --log-prefix "[BLOCKED - IOT] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
}

Load_LogIPTables() {
	if [ "$logmode" = "enabled" ]; then
		if [ "$(nvram get wgs_enable)" = "1" ]; then
			pos1="$(iptables --line -vnL PREROUTING -t raw | grep -F "Skynet-Master dst" | grep -F "DROP" | grep -F "wgs" | awk '{print $1}')"
			iptables -t raw -I PREROUTING "$pos1" -i wgs+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		fi
		if [ "$(nvram get vpn_server1_state)" != "0" ] || [ "$(nvram get vpn_server2_state)" != "0" ]; then
			pos2="$(iptables --line -vnL PREROUTING -t raw | grep -F "Skynet-Master dst" | grep -F "DROP" | grep -F "tun" | awk '{print $1}')"
			iptables -t raw -I PREROUTING "$pos2" -i tun2+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		fi
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then
			pos3="$(iptables --line -nL PREROUTING -t raw | grep -F "Skynet-Master src" | grep -F "DROP" | awk '{print $1}')"
			iptables -t raw -I PREROUTING "$pos3" -i "$iface" -m set ! --match-set Skynet-MasterWL src -m set --match-set Skynet-Master src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		fi
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
			pos4="$(iptables --line -vnL PREROUTING -t raw | grep -F "Skynet-Master dst" | grep -F "DROP" | grep -vF "tun" | grep -vF "wgs" | awk '{print $1}')"
			iptables -t raw -I PREROUTING "$pos4" -i br+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
			pos5="$(iptables --line -nL OUTPUT -t raw | grep -F "Skynet-Master dst" | grep -F "DROP" | awk '{print $1}')"
			iptables -t raw -I OUTPUT "$pos5" -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		fi
		if [ "$(nvram get fw_log_x)" = "drop" ] || [ "$(nvram get fw_log_x)" = "both" ] && [ "$loginvalid" = "enabled" ]; then
			pos6="$(iptables --line -nL logdrop | grep -F "DROP" | awk '{print $1}')"
			iptables -I logdrop "$pos6" -m state --state NEW -j LOG --log-prefix "[BLOCKED - INVALID] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		fi
		if [ "$iotblocked" = "enabled" ] && [ "$iotlogging" = "enabled" ]; then
			pos7="$(iptables --line -nL FORWARD | grep -F "Skynet-IOT" | grep -F "DROP" | awk '{print $1}')"
			iptables -I FORWARD "$pos7" -i br+ -m set --match-set Skynet-IOT src -j LOG --log-prefix "[BLOCKED - IOT] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		fi
	fi
}

Unload_IOTTables() {
	if [ "$iotblocked" = "enabled" ]; then
		iptables -D FORWARD -i br+ -m set --match-set Skynet-IOT src -o wgs+ -j ACCEPT 2>/dev/null
		iptables -D FORWARD -i br+ -m set --match-set Skynet-IOT src -o tun2+ -j ACCEPT 2>/dev/null
		iptables -D FORWARD -i br+ -m set --match-set Skynet-IOT src -j DROP 2>/dev/null
		if [ -n "$iotports" ]; then
			if [ "$iotproto" = "all" ] || [ "$iotproto" = "udp" ]; then
				iptables -D FORWARD -i br+ -m set --match-set Skynet-IOT src -o "$iface" -p udp -m udp -m multiport --dports "$iotports" -j ACCEPT 2>/dev/null
			fi
			if [ "$iotproto" = "all" ] || [ "$iotproto" = "tcp" ]; then
				iptables -D FORWARD -i br+ -m set --match-set Skynet-IOT src -o "$iface" -p tcp -m tcp -m multiport --dports "$iotports" -j ACCEPT 2>/dev/null
			fi
		else
			if [ "$iotproto" = "all" ] || [ "$iotproto" = "udp" ]; then
				iptables -D FORWARD -i br+ -m set --match-set Skynet-IOT src -o "$iface" -p udp -m udp --dport 123 -j ACCEPT 2>/dev/null
			fi
			if [ "$iotproto" = "all" ] || [ "$iotproto" = "tcp" ]; then
				iptables -D FORWARD -i br+ -m set --match-set Skynet-IOT src -o "$iface" -p tcp -m tcp --dport 123 -j ACCEPT 2>/dev/null
			fi
		fi
		iptables -D FORWARD -i br+ -m set --match-set Skynet-IOT src -o "$iface" -p icmp -j ACCEPT 2>/dev/null
	fi
}

Load_IOTTables() {
	if [ "$iotblocked" = "enabled" ]; then
		iptables -I FORWARD -i br+ -m set --match-set Skynet-IOT src -j DROP 2>/dev/null
		if [ "$(nvram get vpn_server1_state)" != "0" ] || [ "$(nvram get vpn_server2_state)" != "0" ]; then
			iptables -I FORWARD -i br+ -m set --match-set Skynet-IOT src -o tun2+ -j ACCEPT 2>/dev/null
		fi
		if [ "$(nvram get wgs_enable)" = "1" ]; then
			iptables -I FORWARD -i br+ -m set --match-set Skynet-IOT src -o wgs+ -j ACCEPT 2>/dev/null
		fi
		if [ -n "$iotports" ]; then
			if [ "$iotproto" = "all" ] || [ "$iotproto" = "udp" ]; then
				iptables -I FORWARD -i br+ -m set --match-set Skynet-IOT src -o "$iface" -p udp -m udp -m multiport --dports "$iotports" -j ACCEPT 2>/dev/null
			fi
			if [ "$iotproto" = "all" ] || [ "$iotproto" = "tcp" ]; then
				iptables -I FORWARD -i br+ -m set --match-set Skynet-IOT src -o "$iface" -p tcp -m tcp -m multiport --dports "$iotports" -j ACCEPT 2>/dev/null
			fi
		else
			if [ "$iotproto" = "all" ] || [ "$iotproto" = "udp" ]; then
				iptables -I FORWARD -i br+ -m set --match-set Skynet-IOT src -o "$iface" -p udp -m udp --dport 123 -j ACCEPT 2>/dev/null
			fi
			if [ "$iotproto" = "all" ] || [ "$iotproto" = "tcp" ]; then
				iptables -I FORWARD -i br+ -m set --match-set Skynet-IOT src -o "$iface" -p tcp -m tcp --dport 123 -j ACCEPT 2>/dev/null
			fi
		fi
		iptables -I FORWARD -i br+ -m set --match-set Skynet-IOT src -o "$iface" -p icmp -j ACCEPT 2>/dev/null
	fi
}

Check_IPSets() {
	ipset -L -n Skynet-MasterWL >/dev/null 2>&1 || fail="${fail}#1 "
	ipset -L -n Skynet-Blacklist >/dev/null 2>&1 || fail="${fail}#2 "
	ipset -L -n Skynet-BlockedRanges >/dev/null 2>&1 || fail="${fail}#3 "
	ipset -L -n Skynet-Master >/dev/null 2>&1 || fail="${fail}#4 "
	ipset -L -n Skynet-IOT >/dev/null 2>&1 || fail="${fail}#5 "
	if [ -n "$fail" ]; then return 1; fi
}

Check_IPTables() {
	if [ "$(nvram get wgs_enable)" = "1" ]; then
		iptables -t raw -C PREROUTING -i wgs+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null || fail="${fail}#6 "
	fi
	if [ "$(nvram get vpn_server1_state)" != "0" ] || [ "$(nvram get vpn_server2_state)" != "0" ]; then
		iptables -t raw -C PREROUTING -i tun2+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null || fail="${fail}#7 "
	fi
	if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then
		iptables -t raw -C PREROUTING -i "$iface" -m set ! --match-set Skynet-MasterWL src -m set --match-set Skynet-Master src -j DROP 2>/dev/null || fail="${fail}#8 "
	fi
	if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
		iptables -t raw -C PREROUTING -i br+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null || fail="${fail}#9 "
		iptables -t raw -C OUTPUT -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null || fail="${fail}#10 "
	fi
	if [ "$iotblocked" = "enabled" ]; then
		if [ "$(nvram get wgs_enable)" = "1" ]; then
			iptables -C FORWARD -i br+ -m set --match-set Skynet-IOT src -o wgs+ -j ACCEPT 2>/dev/null || fail="${fail}#11 "
		fi
		if [ "$(nvram get vpn_server1_state)" != "0" ] || [ "$(nvram get vpn_server2_state)" != "0" ]; then
			iptables -C FORWARD -i br+ -m set --match-set Skynet-IOT src -o tun2+ -j ACCEPT 2>/dev/null || fail="${fail}#12 "
		fi
		iptables -C FORWARD -i br+ -m set --match-set Skynet-IOT src -j DROP 2>/dev/null || fail="${fail}#13 "
		if [ -n "$iotports" ]; then
			if [ "$iotproto" = "all" ] || [ "$iotproto" = "udp" ]; then
				iptables -C FORWARD -i br+ -m set --match-set Skynet-IOT src -o "$iface" -p udp -m udp -m multiport --dports "$iotports" -j ACCEPT 2>/dev/null || fail="${fail}#14 "
			fi
			if [ "$iotproto" = "all" ] || [ "$iotproto" = "tcp" ]; then
				iptables -C FORWARD -i br+ -m set --match-set Skynet-IOT src -o "$iface" -p tcp -m tcp -m multiport --dports "$iotports" -j ACCEPT 2>/dev/null || fail="${fail}#15 "
			fi
		else
			if [ "$iotproto" = "all" ] || [ "$iotproto" = "udp" ]; then
				iptables -C FORWARD -i br+ -m set --match-set Skynet-IOT src -o "$iface" -p udp -m udp --dport 123 -j ACCEPT 2>/dev/null || fail="${fail}#16 "
			fi
			if [ "$iotproto" = "all" ] || [ "$iotproto" = "tcp" ]; then
				iptables -C FORWARD -i br+ -m set --match-set Skynet-IOT src -o "$iface" -p tcp -m tcp --dport 123 -j ACCEPT 2>/dev/null || fail="${fail}#17 "
			fi
		fi
	fi
	if [ "$logmode" = "enabled" ]; then
		if [ "$(nvram get vpn_server1_state)" != "0" ] || [ "$(nvram get vpn_server2_state)" != "0" ]; then
			iptables -t raw -C PREROUTING -i tun2+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null || fail="${fail}#18 "
		fi
		if [ "$(nvram get wgs_enable)" = "1" ]; then
			iptables -t raw -C PREROUTING -i wgs+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null || fail="${fail}#19 "
		fi
		if [ "$iotblocked" = "enabled" ] && [ "$iotlogging" = "enabled" ]; then
			iptables -C FORWARD -i br+ -m set --match-set Skynet-IOT src -j LOG --log-prefix "[BLOCKED - IOT] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null || fail="${fail}#20 "
		fi
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then
			iptables -t raw -C PREROUTING -i "$iface" -m set ! --match-set Skynet-MasterWL src -m set --match-set Skynet-Master src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null || fail="${fail}#21 "
		fi
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
			iptables -t raw -C PREROUTING -i br+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null || fail="${fail}#22 "
			iptables -t raw -C OUTPUT -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null || fail="${fail}#23 "
		fi
		if [ "$(nvram get fw_log_x)" = "drop" ] || [ "$(nvram get fw_log_x)" = "both" ] && [ "$loginvalid" = "enabled" ]; then
			iptables -C logdrop -m state --state NEW -j LOG --log-prefix "[BLOCKED - INVALID] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null || fail="${fail}#24 "
		fi
	fi
	if [ -n "$fail" ]; then return 1; fi
}

Unload_IPSets() {
	ipset -q destroy Skynet-Master
	ipset -q destroy Skynet-MasterWL
	ipset -q destroy Skynet-Blacklist
	ipset -q destroy Skynet-BlockedRanges
	ipset -q destroy Skynet-Whitelist
	ipset -q destroy Skynet-WhitelistDomains
	ipset -q destroy Skynet-IOT
}

Unload_Cron() {
	if [ -z "$1" ]; then set "all"; fi
	for cron in "$@"; do
		case "$cron" in
			save)
				cru d Skynet_save
			;;
			banmalware)
				cru d Skynet_banmalware
			;;
			autoupdate)
				cru d Skynet_autoupdate
			;;
			checkupdate)
				cru d Skynet_checkupdate
			;;
			genstats)
				cru d Skynet_genstats
			;;
			all)
				cru d Skynet_save
				cru d Skynet_banmalware
				cru d Skynet_autoupdate
				cru d Skynet_checkupdate
				cru d Skynet_genstats
			;;
			*)
				echo "[*] Error - No Cron Specified To Unload"
			;;
		esac
	done
}

Load_Cron() {
	if [ -z "$1" ]; then set "all"; fi
	for cron in "$@"; do
		case "$cron" in
			save)
				cru a Skynet_save "0 * * * * sh /jffs/scripts/firewall save"
			;;
			banmalwaredaily)
				hour=$(Generate_Random_Number 1 23)
				cru a Skynet_banmalware "25 $hour * * * sh /jffs/scripts/firewall banmalware"
			;;
			banmalwareweekly)
				hour=$(Generate_Random_Number 1 23)
				cru a Skynet_banmalware "25 $hour * * Mon sh /jffs/scripts/firewall banmalware"
			;;
			autoupdate)
				min=$(Generate_Random_Number 3 23)
				cru a Skynet_autoupdate "$min 1 * * Mon sh /jffs/scripts/firewall update"
			;;
			checkupdate)
				min=$(Generate_Random_Number 3 23)
				cru a Skynet_checkupdate "$min 1 * * Mon sh /jffs/scripts/firewall update check"
			;;
			genstats)
				min=$(Generate_Random_Number 28 57)
				cru a Skynet_genstats "$min */12 * * * sh /jffs/scripts/firewall debug genstats"
			;;
			*)
				echo "[*] Error - No Cron Specified To Load"
			;;
		esac
	done
}

Generate_Random_Number() {
	awk -v min="$1" -v max="$2" -v freq=1 'BEGIN{"tr -cd 0-9 </dev/urandom | head -c 6" | getline seed; srand(seed); for(i=0;i<freq;i++)print int(min+rand()*(max-min+1))}'
}

Is_IP() {
	grep -qE '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(32))?)$'
}

Is_Range() {
	grep -qE '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-1])){1})$'
}

Is_IPRange() {
	grep -qE '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)$'
}

Is_MAC() {
	grep -qE '^([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}$'
}

Is_Port() {
	grep -qE '^[0-9]{1,5}$'
}

Is_ASN() {
	grep -qiE '^AS[0-9]{1,6}$'
}

Strip_Domain() {
	sed 's~http[s]*://~~;s~/.*~~;s~www\.~~g;\~^$~d' | awk '!x[$0]++'
}

Domain_Lookup() {
	nslookup "$1" 2>/dev/null | awk '/^Address[[:space:]][0-9]*\:[[:space:]]/{if($3 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}/ && NR > 2)print $3}'
}

LAN_CIDR_Lookup() {
	if [ "$(echo "$1" | cut -c1-8)" = "192.168." ]; then
		echo "192.168.0.0/16"
	elif [ "$(echo "$1" | cut -c1-4)" = "172." ]; then
		echo "172.16.0.0/12"
	elif [ "$(echo "$1" | cut -c1-3)" = "10." ]; then
		echo "10.0.0.0/8"
	fi
}

Extended_DNSStats() {
	case "$1" in
		1)
			if [ "$lookupcountry" = "enabled" ]; then
				country="($(curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno) / $(tr -cd 0-9 </dev/urandom | head -c 20)" "https://api.db-ip.com/v2/free/${statdata}/countryCode/"))"
				if [ -z "$country" ]; then country="*"; fi
			fi
			banreason="$(grep -F " ${statdata} " "$skynetipset" | grep -m1 -vF "Skynet-Whitelist" | awk -F '"' '{print $2}')"
			if [ -z "$banreason" ]; then
				banreason="$(grep -E "$(echo "$statdata" | cut -d '.' -f1-3)\..*/" "$skynetipset" | grep -m1 -vF "Skynet-Whitelist" | awk -F '"' '{print $2}')*"
			fi
			if [ "${#banreason}" -gt "45" ]; then banreason="$(echo "$banreason" | cut -c 1-45)"; fi
			printf '%-15s %-4s | %-55s | %-45s | %-60s \n' "$statdata" "$country" "https://otx.alienvault.com/indicator/ip/${statdata}" "$banreason" "$(grep -F "$statdata" /tmp/skynet/skynetstats.txt | awk '{print $1}' | xargs)"
		;;
		2)
			hits="$(echo "$statdata" | awk '{print $1}')"
			ipaddr="$(echo "$statdata" | awk '{print $2}')"
			if [ "$lookupcountry" = "enabled" ]; then
				country="($(curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno) / $(tr -cd 0-9 </dev/urandom | head -c 20)" "https://api.db-ip.com/v2/free/${ipaddr}/countryCode/"))"
				if [ -z "$country" ]; then country="*"; fi
			fi
			banreason="$(grep -F " ${ipaddr} " "$skynetipset" | grep -m1 -vF "Skynet-Whitelist" | awk -F '"' '{print $2}')"
			if [ -z "$banreason" ]; then
				banreason="$(grep -E "$(echo "$ipaddr" | cut -d '.' -f1-3)\..*/" "$skynetipset" | grep -m1 -vF "Skynet-Whitelist" | awk -F '"' '{print $2}')*"
			fi
			if [ "${#banreason}" -gt "45" ]; then banreason="$(echo "$banreason" | cut -c 1-45)"; fi
			printf '%-10s | %-15s %-4s | %-55s | %-45s | %-60s\n' "${hits}x" "${ipaddr}" "${country}" "https://otx.alienvault.com/indicator/ip/${ipaddr}" "$banreason" "$(grep -F "$ipaddr" /tmp/skynet/skynetstats.txt | awk '{print $1}' | xargs)"
		;;
		*)
			echo "[*] Error - No Stats Specified To Load"
		;;
	esac
}

Display_Header() {
	case "$1" in
		1)
			printf '\n\n%-20s | %-55s | %-45s | %-60s\n' "--------------" "--------------" "--------------" "----------------------"
			printf '%-20s | %-55s | %-45s | %-60s\n' "| IP Address |" "| AlienVault |" "| Ban Reason |" "| Associated Domains |"
			printf '%-20s | %-55s | %-45s | %-60s\n\n' "--------------" "--------------" "--------------" "----------------------"
		;;
		2)
			printf '\n\n%-10s | %-20s | %-55s | %-45s | %-60s\n' "--------" "--------------" "--------------" "--------------" "----------------------"
			printf '%-10s | %-20s | %-55s | %-45s | %-60s\n' "| Hits |" "| IP Address |" "| AlienVault |" "| Ban Reason |" "| Associated Domains |"
			printf '%-10s | %-20s | %-55s | %-45s | %-60s\n\n' "--------" "--------------" "--------------" "--------------" "----------------------"
		;;
		3)
			printf '\n\n%-10s | %-10s | %-60s\n' "--------" "--------" "--------------"
			printf '%-10s | %-10s | %-60s\n' "| Hits |" "| Port |" "| SpeedGuide |"
			printf '%-10s | %-10s | %-60s\n\n' "--------" "--------" "--------------"
		;;
		4)
			printf '\n\n%-10s | %-16s | %-60s\n' "--------" "------------" "---------------"
			printf '%-10s | %-16s | %-60s\n' "| Hits |" "| Local IP |" "| Device Name |"
			printf '%-10s | %-16s | %-60s\n\n' "--------" "------------" "---------------"
		;;
		5)
			printf '\n\n%-20s | %-40s\n' "--------------" "---------"
			printf '%-20s | %-40s\n' "| IP Address |" "| List |"
			printf '%-20s | %-40s\n\n' "--------------" "---------"
		;;
		6)
			printf '\n\n%-40s | %-16s | %-20s | %-15s\n' "---------------" "------------" "---------------" "----------"
			printf '%-40s | %-16s | %-20s | %-15s\n' "| Device Name |" "| Local IP |" "| MAC Address |" "| Status |"
			printf '%-40s | %-16s | %-20s | %-15s\n\n' "---------------" "------------" "---------------" "----------"
		;;
		7)
			printf '\n\n%-35s | %-8s\n' "--------------------" "----------"
			printf '%-35s | %-8s\n' "| Test Description |" "| Result |"
			printf '%-35s | %-8s\n\n' "--------------------" "----------"
		;;
		8)
			printf '\n\n%-35s | %-8s\n' "-----------" "----------"
			printf '%-35s | %-8s\n' "| Setting |" "| Status |"
			printf '%-35s | %-8s\n\n' "----------" "----------"
		;;
		9)
			printf '\n\n=============================================================================================================\n\n\n'
		;;
		10)
			printf '\n=============================================================================================================\n\n\n'
		;;
		11)
			printf '%-10s | %-18s | %-10s | %-18s | %-10s | %-20s\n' "---------" "-------------" "---------" "------------------" "---------" "------------------"
			printf '%-10s | %-18s | %-10s | %-18s | %-10s | %-20s\n' "| Proto |" "| Source IP |" "| SPort |" "| Destination IP |" "| DPort |" "| Identification |"
			printf '%-10s | %-18s | %-10s | %-18s | %-10s | %-20s\n\n' "---------" "-------------" "---------" "------------------" "---------" "------------------"
		;;
		*)
			echo "[*] Error - No Header Specified To Load"
		;;
	esac
}

Display_Message() {
	btime="$(date +%s)"; printf "%-35s | " "$1"
}

Display_Result() {
	result="$(Grn "[$(($(date +%s) - btime))s]")"
	printf '%-8s\n' "$result"
}

Filter_Version() {
	grep -m1 -oE 'v[0-9]{1,2}([.][0-9]{1,2})([.][0-9]{1,2})'
}

Filter_Date() {
	grep -m1 -oE '[0-9]{1,2}([/][0-9]{1,2})([/][0-9]{1,4})'
}

Filter_IP() {
	grep -E '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9]))$'
}

Filter_IPLine() {
	grep -E '(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9]))([[:space:]]|$)'
}

Filter_OutIP() {
	grep -vE '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9]))$'
}

Is_PrivateIP() {
	grep -qE '^(0\.|10\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.|127\.|169\.254\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.0\.0\.|192\.0\.2\.|192\.168\.|198\.(1[8-9])\.|198\.51\.100\.|203\.0\.113\.|2(2[4-9]|[3-4][0-9]|5[0-5])\.)'
}

Filter_PrivateIP() {
	grep -vE '^(0\.|10\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.|127\.|169\.254\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.0\.0\.|192\.0\.2\.|192\.168\.|198\.(1[8-9])\.|198\.51\.100\.|203\.0\.113\.|2(2[4-9]|[3-4][0-9]|5[0-5])\.|8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1)'
}

Filter_PrivateSRC() {
	grep -E 'SRC=(0\.|10\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.|127\.|169\.254\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.0\.0\.|192\.0\.2\.|192\.168\.|198\.(1[8-9])\.|198\.51\.100\.|203\.0\.113\.|2(2[4-9]|[3-4][0-9]|5[0-5])\.)'
}

Filter_PrivateDST() {
	grep -E 'DST=(0\.|10\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.|127\.|169\.254\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.0\.0\.|192\.0\.2\.|192\.168\.|198\.(1[8-9])\.|198\.51\.100\.|203\.0\.113\.|2(2[4-9]|[3-4][0-9]|5[0-5])\.)'
}

Spinner_End() {
	if [ -f /tmp/skynet/spinstart ]; then
		pider="$(cat /tmp/skynet/spinstart)"
		rm -rf /tmp/skynet/spinstart
		if [ -d "/proc/$pider" ]; then kill "$pider"; fi
	fi
}

Spinner_Start() {
	Spinner_End
	touch "/tmp/skynet/spinstart"
	{ while [ -f "/tmp/skynet/spinstart" ]; do
		for c in \*-- -\*- --\*; do
			printf '\033[1;32m%s\033[0m\b\b\b' "$c"
			usleep 250000
		done
		printf '   \b\b\b'
	done; } &
	echo "$!" > /tmp/skynet/spinstart
}

Save_IPSets() {
	if Check_IPSets; then
		{ ipset save Skynet-Whitelist; ipset save Skynet-WhitelistDomains; ipset save Skynet-Blacklist; ipset save Skynet-BlockedRanges; ipset save Skynet-Master; ipset save Skynet-MasterWL; ipset save Skynet-IOT; } > "$skynetipset" 2>/dev/null
	fi
}

Unban_PrivateIP() {
	if [ "$unbanprivateip" = "enabled" ] && [ "$logmode" = "enabled" ]; then
		grep -F "INBOUND" "$syslogloc" | Filter_PrivateSRC | grep -oE 'SRC=[0-9,\.]*' | cut -c 5- | awk '!x[$0]++' | while IFS= read -r "ip"; do
			echo "add Skynet-Whitelist $ip comment \"Private IP\""
			echo "del Skynet-Blacklist $ip"
		done | ipset restore -!
		grep -F "OUTBOUND" "$syslogloc" | Filter_PrivateDST | grep -oE 'DST=[0-9,\.]*' | cut -c 5- | awk '!x[$0]++' | while IFS= read -r "ip"; do
			echo "add Skynet-Whitelist $ip comment \"Private IP\""
			echo "del Skynet-Blacklist $ip"
		done | ipset restore -!
	fi
}

Refresh_AiProtect() {
	if [ "$banaiprotect" = "enabled" ] && [ -s /jffs/.sys/AiProtectionMonitor/AiProtectionMonitor.db ]; then
		sed '\~add Skynet-Blacklist ~!d;\~BanAiProtect~!d;s~ comment.*~~;s~add~del~g' "$skynetipset" | ipset restore -!
		sqlite3 /jffs/.sys/AiProtectionMonitor/AiProtectionMonitor.db "SELECT src FROM monitor;" | awk '!x[$0]++' | Filter_IP | Filter_PrivateIP | awk '{printf "add Skynet-Blacklist %s comment \"BanAiProtect\"\n", $1 }' | ipset restore -!
		sqlite3 /jffs/.sys/AiProtectionMonitor/AiProtectionMonitor.db "SELECT dst FROM monitor;" | awk '!x[$0]++' | Filter_OutIP | grep -v ":" | while IFS= read -r "domain"; do
			for ip in $(Domain_Lookup "$domain" | Filter_PrivateIP); do
				echo "add Skynet-Blacklist $ip comment \"BanAiProtect: $domain\""
			done &
		done | ipset restore -!
	fi
}

Refresh_MBans() {
	if grep -qF "[Manual Ban] TYPE=Domain" "$skynetevents"; then
		awk '/\[Manual Ban\] TYPE=Domain/{if(!x[$9]++)print $9}' "$skynetevents" | sed 's~Host=~~g' > /tmp/skynet/mbans.list
		sed -i '\~\[Manual Ban\] TYPE=Domain~d;' "$skynetevents"
		sed '\~add Skynet-Blacklist ~!d;\~ManualBanD~!d;s~ comment.*~~;s~add~del~g' "$skynetipset" | ipset restore -!
		while IFS= read -r "domain"; do
			for ip in $(Domain_Lookup "$domain" | Filter_PrivateIP); do
				echo "add Skynet-Blacklist $ip comment \"ManualBanD: $domain\""
				echo "$(date +"%b %d %T") Skynet: [Manual Ban] TYPE=Domain SRC=$ip Host=$domain " >> "$skynetevents"
			done
		done < /tmp/skynet/mbans.list | ipset restore -!
		rm -rf /tmp/skynet/mbans.list
	fi
}

Refresh_MWhitelist() {
	if grep -qE "Manual Whitelist.* TYPE=Domain" "$skynetevents"; then
		awk '/Manual Whitelist.* TYPE=Domain/{if(!x[$9]++)print $9}' "$skynetevents" | sed 's~Host=~~g' > /tmp/skynet/mwhitelist.list
		sed -i '\~\[Manual Whitelist\] TYPE=Domain~d;' "$skynetevents"
		sed '\~add Skynet-Whitelist ~!d;\~ManualWlistD~!d;s~ comment.*~~;s~add~del~g' "$skynetipset" | ipset restore -!
		while IFS= read -r "domain"; do
			for ip in $(Domain_Lookup "$domain"); do
				echo "add Skynet-Whitelist $ip comment \"ManualWlistD: $domain\""
				echo "$(date +"%b %d %T") Skynet: [Manual Whitelist] TYPE=Domain SRC=$ip Host=$domain " >> "$skynetevents"
			done
		done < /tmp/skynet/mwhitelist.list | ipset restore -!
		cat /tmp/skynet/mwhitelist.list >> /jffs/addons/shared-whitelists/shared-Skynet2-whitelist
		rm -rf /tmp/skynet/mwhitelist.list
	fi
}

Whitelist_Extra() {
	echo "ipdeny.com
	ipapi.co
	api.db-ip.com
	api.bgpview.io
	asn.ipinfo.app
	speedguide.net
	otx.alienvault.com
	github.com
	raw.githubusercontent.com
	iplists.firehol.org
	astrill.com
	strongpath.net
	snbforums.com
	bin.entware.net
	nwsrv-ns1.asus.com
	$(nvram get "firmware_server")
	$(nvram get "ntp_server0")
	$(nvram get "ntp_server1")" | tr -d "\t" > /jffs/addons/shared-whitelists/shared-Skynet2-whitelist
}

Whitelist_CDN() {
	if [ "$cdnwhitelist" = "enabled" ]; then
		{
			# Apple AS714 | Akamai AS12222 AS16625 | HighWinds AS33438 AS20446 | Fastly AS54113 | GitHub AS36459
			printf "AS714\nAS12222\nAS16625\nAS33438\nAS20446\nAS54113\nAS36459" | xargs -I {} sh -c "curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors https://asn.ipinfo.app/api/text/list/{} | awk -v asn={} '/^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)([[:space:]]|$)/{printf \"add Skynet-Whitelist %s comment \\\"CDN-Whitelist: %s\\\"\\n\", \$1, asn }'"
			curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors https://www.cloudflare.com/ips-v4 | awk '/^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)([[:space:]]|$)/{printf "add Skynet-Whitelist %s comment \"CDN-Whitelist: CloudFlare\"\n", $1 }'
			curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors https://ip-ranges.amazonaws.com/ip-ranges.json | awk 'BEGIN{RS="(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\\/(1?[0-9]|2?[0-9]|3?[0-2]))?)"}{if(RT)printf "add Skynet-Whitelist %s comment \"CDN-Whitelist: Amazon\"\n", RT }'
			curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors https://api.github.com/meta | awk 'BEGIN{RS="(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\\/(1?[0-9]|2?[0-9]|3?[0-2]))?)"}{if(RT)printf "add Skynet-Whitelist %s comment \"CDN-Whitelist: Github\"\n", RT }'
			curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors https://endpoints.office.com/endpoints/worldwide?clientrequestid="$(awk '{printf "%s", $1}' /proc/sys/kernel/random/uuid)" | awk 'BEGIN{RS="(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\\/(1?[0-9]|2?[0-9]|3?[0-2]))?)"}{if(RT)printf "add Skynet-Whitelist %s comment \"CDN-Whitelist: Microsoft365\"\n", RT }'
		} | awk '!x[$0]++' > /tmp/skynet/cdnwhitelist.list
	fi
	sed '\~add Skynet-Whitelist ~!d;\~CDN-Whitelist~!d;s~ comment.*~~;s~add~del~g' "$skynetipset" | ipset restore -!
	if [ -f "/tmp/skynet/cdnwhitelist.list" ]; then
		awk '{print $0}' /tmp/skynet/cdnwhitelist.list | ipset restore -!
		rm -rf "/tmp/skynet/cdnwhitelist.list"
	fi
}

Whitelist_VPN() {
	echo "add Skynet-Whitelist $(nvram get vpn_server1_sn)/24 comment \"nvram: vpn_server1_sn\"
	add Skynet-Whitelist $(nvram get vpn_server2_sn)/24 comment \"nvram: vpn_server2_sn\"
	add Skynet-Whitelist $(nvram get vpn_server_sn)/24 comment \"nvram: vpn_server_sn\"
	add Skynet-Whitelist $(nvram get vpn_client1_addr)/24 comment \"nvram: vpn_client1_addr\"
	add Skynet-Whitelist $(nvram get vpn_client2_addr)/24 comment \"nvram: vpn_client2_addr\"
	add Skynet-Whitelist $(nvram get vpn_client3_addr)/24 comment \"nvram: vpn_client3_addr\"
	add Skynet-Whitelist $(nvram get vpn_client4_addr)/24 comment \"nvram: vpn_client4_addr\"
	add Skynet-Whitelist $(nvram get vpn_client5_addr)/24 comment \"nvram: vpn_client5_addr\"" | tr -d "\t" | Filter_IPLine | ipset restore -! 2>/dev/null
	if [ -f "/dev/astrill/openvpn.conf" ]; then ipset -q -A Skynet-Whitelist "$(sed '\~remote ~!d;s~remote ~~' "/dev/astrill/openvpn.conf")/24" comment "nvram: Astrill_VPN"; fi
}

Whitelist_Shared() {
	echo "add Skynet-Whitelist $(nvram get wan0_ipaddr) comment \"nvram: wan0_ipaddr\"
	add Skynet-Whitelist $(LAN_CIDR_Lookup "$(nvram get "lan_ipaddr")") comment \"nvram: lan_ipaddr\"
	add Skynet-Whitelist $(nvram get wan_dns1_x) comment \"nvram: wan_dns1_x\"
	add Skynet-Whitelist $(nvram get wan_dns2_x) comment \"nvram: wan_dns2_x\"
	add Skynet-Whitelist $(nvram get wan0_dns1_x) comment \"nvram: wan0_dns1_x\"
	add Skynet-Whitelist $(nvram get wan0_dns2_x) comment \"nvram: wan0_dns2_x\"
	add Skynet-Whitelist $(nvram get wan_dns | awk '{print $1}') comment \"nvram: wan_dns\"
	add Skynet-Whitelist $(nvram get wan_dns | awk '{print $2}') comment \"nvram: wan_dns\"
	add Skynet-Whitelist $(nvram get wan0_dns | awk '{print $1}') comment \"nvram: wan0_dns\"
	add Skynet-Whitelist $(nvram get wan0_dns | awk '{print $2}') comment \"nvram: wan0_dns\"
	add Skynet-Whitelist $(nvram get wan0_xdns | awk '{print $1}') comment \"nvram: wan0_xdns\"
	add Skynet-Whitelist $(nvram get wan0_xdns | awk '{print $2}') comment \"nvram: wan0_xdns\"
	add Skynet-Whitelist 192.30.252.0/22 comment \"nvram: Github Content Server\"
	add Skynet-Whitelist 127.0.0.0/8 comment \"nvram: Localhost\"" | tr -d "\t" | Filter_IPLine | ipset restore -! 2>/dev/null
	ipset flush Skynet-WhitelistDomains
	sed -i '\~# Skynet~d' /jffs/configs/dnsmasq.conf.add
	grep -hvF "#" /jffs/addons/shared-whitelists/shared-*-whitelist | Strip_Domain | xargs -n 20 | sed 's~^~ipset=/~g;s~ ~/~g;s~$~/Skynet-WhitelistDomains # Skynet~g' >> /jffs/configs/dnsmasq.conf.add
	chmod +x /jffs/configs/dnsmasq.conf.add
	service restart_dnsmasq >/dev/null 2>&1
	if [ "$(uname -o)" = "ASUSWRT-Merlin" ]; then dotvar="dnspriv_rulelist"; else dotvar="stubby_dns"; fi
	for ip in $(nvram get "$dotvar" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'); do
		echo "add Skynet-Whitelist $ip comment \"nvram: $dotvar\""
	done | ipset restore -!
	if [ -f "/jffs/dnscrypt/public-resolvers.md" ] && [ -f "/jffs/dnscrypt/relays.md" ]; then
		grep -hoE '^sdns:.*' /jffs/dnscrypt/public-resolvers.md /jffs/dnscrypt/relays.md | sed "s~'~~g;s~sdns://~~g;s~-~+~g;s~_~/~g" | while read -r stamp; do
			echo "${stamp}$(echo '====' | cut -c-$(($(printf '%s' "${stamp}" | wc -m) % 4)))" | openssl enc -base64 -d -A
		done | strings | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{printf "add Skynet-Whitelist %s comment \"nvram: DNSCrypt Stamp\"\n", $1 }' | ipset restore -!
	fi
	if [ -f "/opt/var/lib/unbound/root.hints" ]; then
		grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' /opt/var/lib/unbound/root.hints | while read -r roothint; do
			echo "add Skynet-Whitelist $roothint comment \"nvram: Root DNS Server\""
		done | ipset restore -!
	fi
	Strip_Domain < /jffs/addons/shared-whitelists/shared-Skynet2-whitelist | while IFS= read -r domain; do
		nslookup "$domain" 127.0.0.1 >/dev/null 2>&1
	done &
}

WriteStats_ToJS() {
	{
		echo "function ${3}() {"
		printf '\tdocument.getElementById("%s").innerHTML = "%s"\n' "$4" "$(if [ -f "$1" ]; then cat "$1"; else echo "$1"; fi)"
		echo "}"
		echo
	} >> "$2"
}

WriteData_ToJS() {
	inputfile="$1"
	outputfile="$2"
	shift 2
	i="0"
	for var in "$@"; do
		i="$((i + 1))"
		{
			echo "var $var;"
			echo "$var = [];"
			echo "${var}.unshift('$(awk -F "~" -v i="$i" '{printf t $i} {t=","}' "$inputfile" | sed "s~,~\\', \\'~g")');"
			echo
		} >> "$outputfile"
	done
}

Generate_Stats() {
	if nvram get rc_support | grep -qF "am_addons"; then
		if [ "$displaywebui" = "enabled" ]; then
			mkdir -p "${skynetloc}/webui/stats"
			true > "${skynetloc}/webui/stats.js"
			if [ -f "/opt/var/log/dnsmasq.log" ]; then
				grep -hE 'reply.* is ([0-9]{1,3}\.){3}[0-9]{1,3}$' /opt/var/log/dnsmasq* | awk '{printf "%s %s\n", $(NF-2), $NF}' | awk '!x[$0]++' | Strip_Domain > "${skynetloc}/webui/stats/skynetstats.txt"
			else
				touch "${skynetloc}/webui/stats/skynetstats.txt"
			fi

			if iptables -t raw -C PREROUTING -i "$iface" -m set ! --match-set Skynet-MasterWL src -m set --match-set Skynet-Master src -j DROP 2>/dev/null; then
				hits1="$(iptables -xnvL PREROUTING -t raw | grep -Fv "LOG" | grep -F "Skynet-Master src" | awk '{print $1}')"
			else
				hits1="0"
			fi
			if iptables -t raw -C PREROUTING -i br+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null; then
				hits2="$(($(iptables -xnvL PREROUTING -t raw | grep -Fv "LOG" | grep -F "Skynet-Master dst" | grep -vF "tun"| grep -vF "wgs" | awk '{print $1}') + $(iptables -xnvL OUTPUT -t raw | grep -Fv "LOG" | grep -F "Skynet-Master dst" | awk '{print $1}')))"
				if iptables -t raw -C PREROUTING -i wgs+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null; then
					hits2="$((hits2 + $(iptables -xnvL PREROUTING -t raw | grep -Fv "LOG" | grep -F "Skynet-Master dst" | grep -F "wgs" | awk '{print $1}')))"
				fi
				if iptables -t raw -C PREROUTING -i tun2+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null; then
					hits2="$((hits2 + $(iptables -xnvL PREROUTING -t raw | grep -Fv "LOG" | grep -F "Skynet-Master dst" | grep -F "tun" | awk '{print $1}')))"
				fi
			else
				hits2="0"
			fi

			WriteStats_ToJS "$blacklist1count" "${skynetloc}/webui/stats.js" "SetBLCount1" "blcount1"
			WriteStats_ToJS "$blacklist2count" "${skynetloc}/webui/stats.js" "SetBLCount2" "blcount2"
			WriteStats_ToJS "$hits1" "${skynetloc}/webui/stats.js" "SetHits1" "hits1"
			WriteStats_ToJS "$hits2" "${skynetloc}/webui/stats.js" "SetHits2" "hits2"
			WriteStats_ToJS "Monitoring From $(grep -m1 -F "BLOCKED -" "$skynetlog" | awk '{printf "%s %s %s\n", $1, $2, $3}') To $(grep -F "BLOCKED -" "$skynetlog" | tail -1 | awk '{printf "%s %s %s\n", $1, $2, $3}')" "${skynetloc}/webui/stats.js" "SetStatsDate" "statsdate"
			WriteStats_ToJS "Log Size - ($(du -h "$skynetlog" | awk '{print $1}')B)" "${skynetloc}/webui/stats.js" "SetStatsSize" "statssize"
			# Inbound Ports
			grep -F "INBOUND" "$skynetlog" | grep -oE 'DPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -10 | sed "s~^[ \t]*~~;s~ ~\~~g" > "${skynetloc}/webui/stats/iport.txt"
			WriteData_ToJS "${skynetloc}/webui/stats/iport.txt" "${skynetloc}/webui/stats.js" "DataInPortHits" "LabelInPortHits"
			# Source Ports
			grep -F "INBOUND" "$skynetlog" | grep -oE 'SPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -10 | sed "s~^[ \t]*~~;s~ ~\~~g" > "${skynetloc}/webui/stats/sport.txt"
			WriteData_ToJS "${skynetloc}/webui/stats/sport.txt" "${skynetloc}/webui/stats.js" "DataSPortHits" "LabelSPortHits"
			# last 10 Connections Blocked Inbound
			true > "${skynetloc}/webui/stats/liconn.txt"
			grep -F "INBOUND" "$skynetlog" | grep -oE ' SRC=[0-9,\.]*' | cut -c 6- | awk '{a[i++]=$0} END {for (j=i-1; j>=0;) print a[j--] }' | awk '!x[$0]++' | head -10 | while IFS= read -r "statdata"; do
				banreason="$(grep -F " ${statdata} " "$skynetipset" | grep -m1 -vF "Skynet-Whitelist" | awk -F '"' '{print $2}' | sed "s~BanMalware: ~~g")"
				if [ -z "$banreason" ]; then
					banreason="$(grep -E "$(echo "$statdata" | cut -d '.' -f1-3)\..*/" "$skynetipset" | grep -m1 -vF "Skynet-Whitelist" | awk -F '"' '{print $2}' | sed "s~BanMalware: ~~g")*"
				fi
				if [ "${#banreason}" -gt "45" ]; then banreason="$(echo "$banreason" | cut -c 1-45)"; fi
				alienvault="https://otx.alienvault.com/indicator/ip/${statdata}"
				if [ "$lookupcountry" = "enabled" ]; then country="$(curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno) / $(tr -cd 0-9 </dev/urandom | head -c 20)" "https://api.db-ip.com/v2/free/${statdata}/countryName/")"; else country="*"; fi
				if [ -z "$country" ]; then country="*"; fi
				assdomains="$(grep -F "$statdata" "${skynetloc}/webui/stats/skynetstats.txt" | awk '{print $1}' | xargs)"
				if [ -z "$assdomains" ]; then assdomains="*"; fi
				echo "$statdata~$banreason~$alienvault~$country~$assdomains" >> "${skynetloc}/webui/stats/liconn.txt"
			done
			WriteData_ToJS "${skynetloc}/webui/stats/liconn.txt" "${skynetloc}/webui/stats.js" "LabelInConn_IPs" "LabelInConn_BanReason" "LabelInConn_AlienVault" "LabelInConn_Country" "LabelInConn_AssDomains"
			# Last 10 Connections Blocked Outbound
			true > "${skynetloc}/webui/stats/loconn.txt"
			grep -F "OUTBOUND" "$skynetlog" | grep -vE 'DPT=80 |DPT=443 ' | grep -oE ' DST=[0-9,\.]*' | cut -c 6- | awk '{a[i++]=$0} END {for (j=i-1; j>=0;) print a[j--] }' | awk '!x[$0]++' | head -10 | while IFS= read -r "statdata"; do
				banreason="$(grep -F " ${statdata} " "$skynetipset" | grep -m1 -vF "Skynet-Whitelist" | awk -F '"' '{print $2}' | sed "s~BanMalware: ~~g")"
				if [ -z "$banreason" ]; then
					banreason="$(grep -E "$(echo "$statdata" | cut -d '.' -f1-3)\..*/" "$skynetipset" | grep -m1 -vF "Skynet-Whitelist" | awk -F '"' '{print $2}' | sed "s~BanMalware: ~~g")*"
				fi
				if [ "${#banreason}" -gt "45" ]; then banreason="$(echo "$banreason" | cut -c 1-45)"; fi
				alienvault="https://otx.alienvault.com/indicator/ip/${statdata}"
				if [ "$lookupcountry" = "enabled" ]; then country="$(curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno) / $(tr -cd 0-9 </dev/urandom | head -c 20)" "https://api.db-ip.com/v2/free/${statdata}/countryName/")"; else country="*"; fi
				if [ -z "$country" ]; then country="*"; fi
				assdomains="$(grep -F "$statdata" "${skynetloc}/webui/stats/skynetstats.txt" | awk '{print $1}' | xargs)"
				if [ -z "$assdomains" ]; then assdomains="*"; fi
				echo "$statdata~$banreason~$alienvault~$country~$assdomains" >> "${skynetloc}/webui/stats/loconn.txt"
			done
			WriteData_ToJS "${skynetloc}/webui/stats/loconn.txt" "${skynetloc}/webui/stats.js" "LabelOutConn_IPs" "LabelOutConn_BanReason" "LabelOutConn_AlienVault" "LabelOutConn_Country" "LabelOutConn_AssDomains"
			# Last 10 HTTP Connections Blocked Outbound
			true > "${skynetloc}/webui/stats/lhconn.txt"
			grep -E 'DPT=80 |DPT=443 ' "$skynetlog" | grep -F "OUTBOUND" | grep -oE ' DST=[0-9,\.]*' | cut -c 6- | awk '{a[i++]=$0} END {for (j=i-1; j>=0;) print a[j--] }' | awk '!x[$0]++' | head -10 | while IFS= read -r "statdata"; do
				banreason="$(grep -F " ${statdata} " "$skynetipset" | grep -m1 -vF "Skynet-Whitelist" | awk -F '"' '{print $2}' | sed "s~BanMalware: ~~g")"
				if [ -z "$banreason" ]; then
					banreason="$(grep -E "$(echo "$statdata" | cut -d '.' -f1-3)\..*/" "$skynetipset" | grep -m1 -vF "Skynet-Whitelist" | awk -F '"' '{print $2}' | sed "s~BanMalware: ~~g")*"
				fi
				if [ "${#banreason}" -gt "45" ]; then banreason="$(echo "$banreason" | cut -c 1-45)"; fi
				alienvault="https://otx.alienvault.com/indicator/ip/${statdata}"
				if [ "$lookupcountry" = "enabled" ]; then country="$(curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno) / $(tr -cd 0-9 </dev/urandom | head -c 20)" "https://api.db-ip.com/v2/free/${statdata}/countryName/")"; else country="*"; fi
				if [ -z "$country" ]; then country="*"; fi
				assdomains="$(grep -F "$statdata" "${skynetloc}/webui/stats/skynetstats.txt" | awk '{print $1}' | xargs)"
				if [ -z "$assdomains" ]; then assdomains="*"; fi
				echo "$statdata~$banreason~$alienvault~$country~$assdomains" >> "${skynetloc}/webui/stats/lhconn.txt"
			done
			WriteData_ToJS "${skynetloc}/webui/stats/lhconn.txt" "${skynetloc}/webui/stats.js" "LabelHTTPConn_IPs" "LabelHTTPConn_BanReason" "LabelHTTPConn_AlienVault" "LabelHTTPConn_Country" "LabelHTTPConn_AssDomains"
			# Top 10 HTTP Connections Blocked Outbound
			true > "${skynetloc}/webui/stats/thconn.txt"
			grep -E 'DPT=80 |DPT=443 ' "$skynetlog" | grep -F "OUTBOUND" | grep -oE ' DST=[0-9,\.]*' | cut -c 6- | sort -n | uniq -c | sort -nr | head -10 | while IFS= read -r "statdata"; do
				hits="$(echo "$statdata" | awk '{print $1}')"
				ipaddr="$(echo "$statdata" | awk '{print $2}')"
				if [ "$lookupcountry" = "enabled" ]; then country="$(curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno) / $(tr -cd 0-9 </dev/urandom | head -c 20)" "https://api.db-ip.com/v2/free/${ipaddr}/countryName/")"; else country="*"; fi
				if [ -z "$country" ]; then country="*"; fi
				echo "$hits~$ipaddr~$country" >> "${skynetloc}/webui/stats/thconn.txt"
			done
			WriteData_ToJS "${skynetloc}/webui/stats/thconn.txt" "${skynetloc}/webui/stats.js" "DataTHConnHits" "LabelTHConnHits_IPs" "LabelTHConnHits_Country"
			# Top 10 Inbound Connections Blocked
			true > "${skynetloc}/webui/stats/ticonn.txt"
			grep -F "INBOUND" "$skynetlog" | grep -oE ' SRC=[0-9,\.]*' | cut -c 6- | sort -n | uniq -c | sort -nr | head -10 | while IFS= read -r "statdata"; do
				hits="$(echo "$statdata" | awk '{print $1}')"
				ipaddr="$(echo "$statdata" | awk '{print $2}')"
				if [ "$lookupcountry" = "enabled" ]; then country="$(curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno) / $(tr -cd 0-9 </dev/urandom | head -c 20)" "https://api.db-ip.com/v2/free/${ipaddr}/countryName/")"; else country="*"; fi
				if [ -z "$country" ]; then country="*"; fi
				echo "$hits~$ipaddr~$country" >> "${skynetloc}/webui/stats/ticonn.txt"
			done
			WriteData_ToJS "${skynetloc}/webui/stats/ticonn.txt" "${skynetloc}/webui/stats.js" "DataTIConnHits" "LabelTIConnHits_IPs" "LabelTIConnHits_Country"
			# Top 10 Outbound Connections Blocked
			true > "${skynetloc}/webui/stats/toconn.txt"
			grep -F "OUTBOUND" "$skynetlog" | grep -vE 'DPT=80 |DPT=443 ' | grep -oE ' DST=[0-9,\.]*' | cut -c 6- | sort -n | uniq -c | sort -nr | head -10 | while IFS= read -r "statdata"; do
				hits="$(echo "$statdata" | awk '{print $1}')"
				ipaddr="$(echo "$statdata" | awk '{print $2}')"
				if [ "$lookupcountry" = "enabled" ]; then country="$(curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno) / $(tr -cd 0-9 </dev/urandom | head -c 20)" "https://api.db-ip.com/v2/free/${ipaddr}/countryName/")"; else country="*"; fi
				if [ -z "$country" ]; then country="*"; fi
				echo "$hits~$ipaddr~$country" >> "${skynetloc}/webui/stats/toconn.txt"
			done
			WriteData_ToJS "${skynetloc}/webui/stats/toconn.txt" "${skynetloc}/webui/stats.js" "DataTOConnHits" "LabelTOConnHits_IPs" "LabelTOConnHits_Country"
			# Top 10 Clients Blocked
			true > "${skynetloc}/webui/stats/tcconn.txt"
			true > "${skynetloc}/webui/stats/tcconn2.txt"
			grep -F "OUTBOUND" "$skynetlog" | grep -oE ' SRC=[0-9,\.]*' | cut -c 6- | sort -n | uniq -c | sort -nr | head -10 | sed "s~^[ \t]*~~;s~ ~\~~g" > "${skynetloc}/webui/stats/tcconn.txt"
			while IFS= read -r "line"; do
				ipaddr="$(echo "$line" | awk -F "~" '{print $2}')"
				macaddr="$(ip neigh | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3} ' | grep -F "$ipaddr " | awk '{print $5}')"
				Get_LocalName
				if [ "${#localname}" -gt "20" ]; then
					localname="$(echo "$localname" | cut -c 1-20)"
				fi
				echo "$line ($localname)" >> "${skynetloc}/webui/stats/tcconn2.txt"
			done < "${skynetloc}/webui/stats/tcconn.txt"
			WriteData_ToJS "${skynetloc}/webui/stats/tcconn2.txt" "${skynetloc}/webui/stats.js" "DataTCConnHits" "LabelTCConnHits"

			rm -rf "${skynetloc}/webui/stats"
		fi
	fi
}

Get_WebUI_Page() {
	if nvram get rc_support | grep -qF "am_addons" && [ "$displaywebui" = "enabled" ]; then
		MyPage="none"
		for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
			page="/www/user/user$i.asp"
			if [ -f "$page" ] && [ "$(md5sum < "$1")" = "$(md5sum < "$page")" ]; then
				MyPage="user$i.asp"
				return
			elif [ "$MyPage" = "none" ] && [ ! -f "$page" ]; then
				MyPage="user$i.asp"
			fi
		done
	fi
}

Install_WebUI_Page() {
	if [ "$logmode" = "enabled" ]; then
		if nvram get rc_support | grep -qF "am_addons"; then
			if [ "$displaywebui" = "enabled" ]; then
				Get_WebUI_Page "${skynetloc}/webui/skynet.asp"
				if [ "$MyPage" = "none" ]; then
					logger -t Skynet "[*] Unable To Mount Skynet Web Page - No Mount Points Avilable" && echo "[*] Unable To Mount Skynet Web Page - No Mount Points Avilable"
				else
					logger -t Skynet "[i] Mounting Skynet Web Page As $MyPage" && echo "[i] Mounting Skynet Web Page As $MyPage"
					cp -f "${skynetloc}/webui/skynet.asp" "/www/user/$MyPage"
					if [ "$(uname -o)" = "ASUSWRT-Merlin" ]; then
						if [ ! -f "/tmp/menuTree.js" ]; then
							cp -f "/www/require/modules/menuTree.js" "/tmp/"
						fi
						sed -i "\\~$MyPage~d" /tmp/menuTree.js
						sed -i "/url: \"Advanced_Firewall_Content.asp\", tabName:/a {url: \"$MyPage\", tabName: \"Skynet\"}," /tmp/menuTree.js
						umount /www/require/modules/menuTree.js 2>/dev/null
						mount -o bind /tmp/menuTree.js /www/require/modules/menuTree.js
					else
						MyPageTitle="$(echo "$MyPage" | sed 's~.asp~~g').title"
						echo "Skynet" > "/www/user/$MyPageTitle"
					fi
					mkdir -p "/www/user/skynet"
					ln -s "${skynetloc}/webui/chart.js" "/www/user/skynet/chart.js" 2>/dev/null
					ln -s "${skynetloc}/webui/chartjs-plugin-zoom.js" "/www/user/skynet/chartjs-plugin-zoom.js" 2>/dev/null
					ln -s "${skynetloc}/webui/hammerjs.js" "/www/user/skynet/hammerjs.js" 2>/dev/null
					ln -s "${skynetloc}/webui/stats.js" "/www/user/skynet/stats.js" 2>/dev/null
					Unload_Cron "genstats"
					Load_Cron "genstats"
				fi
			fi
		fi
	else
		logger -t Skynet "[*] WebUI Integration Requires Logging To Be Enabled"; echo "[*] WebUI Integration Requires Logging To Be Enabled"
	fi
}

Uninstall_WebUI_Page() {
	Get_WebUI_Page "${skynetloc}/webui/skynet.asp"
	if [ -n "$MyPage" ] && [ "$MyPage" != "none" ]; then
		if [ -f "/tmp/menuTree.js" ]; then
			sed -i "\\~$MyPage~d" /tmp/menuTree.js
			umount /www/require/modules/menuTree.js
			mount -o bind /tmp/menuTree.js /www/require/modules/menuTree.js
		else
			MyPageTitle="$(echo "$MyPage" | sed 's~.asp~~g').title"
			rm -rf "/www/user/$MyPageTitle"
		fi
		rm -rf "/www/user/$MyPage" "/www/user/skynet"
		Unload_Cron "genstats"
	fi
}

Download_File() {
	if [ "$(curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors "${remotedir}/${1}" | md5sum | awk '{print $1}')" != "$(md5sum "$2" 2>/dev/null | awk '{print $1}')" ] || [ "$3" = "-f" ]; then
		if curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors "${remotedir}/${1}" -o "$2"; then
			echo "[i] Updated $(echo "$1" | awk -F / '{print $NF}')"
		else
			logger -t Skynet "[*] Updating $(echo "$1" | awk -F / '{print $NF}') Failed"; echo "[*] Updating $(echo "$1" | awk -F / '{print $NF}') Failed"
		fi
	fi
}

Get_LocalName() {
	localname="$(nvram get custom_clientlist | grep -ioE "<.*>$macaddr" | awk -F ">" '{print $(NF-1)}' | tr -d '<')"
	if [ -z "$localname" ]; then localname="$(grep -F "$ipaddr " /var/lib/misc/dnsmasq.leases | awk '{print $4}')"; fi
	if [ -z "$localname" ] || [ "$localname" = "*" ]; then
		if [ -n "$macaddr" ]; then
			macaddr2="$(echo "$macaddr" | sed 'y/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/' | tr -d ':' | cut -c 1-6)"
			localname="$(grep "$macaddr2" /www/ajax/ouiDB.json | sed 's/.*"\([^"]*\)".*/\1/')" 
		fi
		if [ "$ipaddr" = "$(nvram get wan0_ipaddr)" ]; then localname="$model"; fi
		if [ "$ipaddr" = "$(nvram get wgs1_addr | cut -d'/' -f1)" ]; then localname="Wireguard VPN Server"; fi
		if [ "$ipaddr" = "$(nvram get vpn_server1_remote)" ] || [ "$ipaddr" = "$(nvram get vpn_server2_remote)" ]; then localname="OpenVPN Server"; fi
		if [ -z "$localname" ] || [ "$localname" = "*" ]; then localname="Unknown"; fi
	fi
	if [ "${#localname}" -gt "40" ]; then
		localname="$(echo "$localname" | cut -c 1-40)"
	fi
}

Manage_Device() {
	echo "Looking For Available Partitions"
	i="1"
	IFS="
	"
	for mounted in $(/bin/mount | grep -E "ext2|ext3|ext4|tfat|exfat" | awk '{printf "%s - (%s)\n", $3, $1}'); do
		echo "[$i]  --> $mounted"
		eval mounts$i="$(echo "$mounted" | awk '{print $1}')"
		i="$((i + 1))"
	done
	unset IFS
	if [ "$i" = "1" ]; then
		echo "[*] No Compatible ext* USB Partitions Found - Exiting!"
		echo; exit 1
	fi
	Select_Device() {
		echo
		echo "Please Enter Partition Number Or e To Exit"
		printf "[0-%s]: " "$((i - 1))"
		read -r "partitionNumber"
		echo
		if [ "$partitionNumber" = "e" ] || [ "$partitionNumber" = "exit" ]; then
			echo "[*] Exiting!"
			echo; exit 0
		elif [ -z "$partitionNumber" ] || [ "$partitionNumber" -gt "$((i - 1))" ] 2>/dev/null || [ "$partitionNumber" = "0" ]; then
			echo "[*] Invalid Partition Number!"
			Select_Device
		elif [ "$partitionNumber" -eq "$partitionNumber" ] 2>/dev/null; then
			true
		else
			echo "[*] $partitionNumber Isn't An Option!"
			Select_Device
		fi
	}
	Select_Device
	device=""
	eval device=\$mounts"$partitionNumber"
	touch "${device}/rwtest"
	if [ ! -w "${device}/rwtest" ]; then
		echo "[*] Writing To $device Failed - Exiting!"
		Manage_Device
	else
		rm -rf "${device}/rwtest"
	fi
}

Create_Swap() {
	while true; do
		echo "Select SWAP File Size:"
		echo "[1]  --> 1GB"
		echo "[2]  --> 2GB (Recommended)"
		echo
		echo "[e]  --> Exit Menu"
		echo
		printf "[1-2]: "
		read -r "menu"
		echo
		case "$menu" in
			1)
				swapsize=1048576
				break
			;;
			2)
				swapsize=2097152
				break
			;;
			e|exit)
				echo "[*] Exiting!"
				echo; exit 0
			;;
			*)
				echo "[*] $menu Isn't An Option!"
				echo
			;;
		esac
	done
	swaplocation="${device}/myswap.swp"
	if [ -f "$swaplocation" ]; then swapoff -a 2>/dev/null; rm -rf "$swaplocation"; fi
	if [ "$(df "$device" | xargs | awk '{print $11}')" -le "$swapsize" ]; then echo "[*] Not Enough Free Space Available On $device"; Create_Swap; fi
	echo "[i] Creating SWAP File"
	echo
	dd if=/dev/zero of="$swaplocation" bs=1k count="$swapsize"
	mkswap "$swaplocation"
	swapon "$swaplocation"
	sed -i '\~swapon ~d' /jffs/scripts/post-mount
	if [ "$(wc -l < /jffs/scripts/post-mount)" -lt "2" ]; then echo >> /jffs/scripts/post-mount; fi
	sed -i "2i swapon $swaplocation # Skynet" /jffs/scripts/post-mount
	if [ -f "/jffs/scripts/unmount" ] && ! grep -qE "^swapoff " /jffs/scripts/unmount; then
		sed -i '\~swapoff ~d' /jffs/scripts/unmount
		echo "swapoff -a 2>/dev/null # Skynet" >> /jffs/scripts/unmount
	fi
	echo
	echo "[i] SWAP File Located At $swaplocation"
	echo
}

Purge_Logs() {
	sed '\~BLOCKED -~!d' "$syslog1loc" "$syslogloc" 2>/dev/null >> "$skynetlog"
	sed -i '\~BLOCKED -~d' "$syslog1loc" "$syslogloc" 2>/dev/null
	if [ "$(du "$skynetlog" | awk '{print $1}')" -ge "10240" ] || [ "$1" = "force" ]; then
		Generate_Stats
		sed -i '\~BLOCKED -~d' "$skynetlog"
		sed -i '\~Skynet: \[#\] ~d' "$skynetevents"
		iptables -Z PREROUTING -t raw
		if [ "$(du "$skynetlog" | awk '{print $1}')" -ge "3000" ]; then
			true > "$skynetlog"
		fi
	fi
	if [ "$1" = "all" ] || [ "$(grep -cE "Skynet: [#] " "$syslogloc" 2>/dev/null)" -gt "24" ] 2>/dev/null; then
		sed '\~Skynet: \[#\] ~!d' "$syslog1loc" "$syslogloc" 2>/dev/null >> "$skynetevents"
		sed -i '\~Skynet: \[#\] ~d;\~Skynet: \[i\] ~d;\~Skynet: \[\*\] Lock ~d' "$syslog1loc" "$syslogloc" 2>/dev/null
	fi
	if [ -f "/opt/etc/syslog-ng.d/skynet" ]; then killall -HUP syslog-ng; fi
}

Print_Log() {
	oldips="$blacklist1count"
	oldranges="$blacklist2count"
	blacklist1count="$(grep -Foc "add Skynet-Black" "$skynetipset" 2> /dev/null)"
	blacklist2count="$(grep -Foc "add Skynet-Block" "$skynetipset" 2> /dev/null)"
	unset fail
	if Check_IPTables; then
		if [ "$filtertraffic" != "outbound" ]; then
			hits1="$(iptables -xnvL PREROUTING -t raw | grep -Fv "LOG" | grep -F "Skynet-Master src" | awk '{print $1}')"
		else
			hits1="0"
		fi
		if [ "$filtertraffic" != "inbound" ]; then
			hits2="$(($(iptables -xnvL PREROUTING -t raw | grep -Fv "LOG" | grep -F "Skynet-Master dst" | grep -vF "tun"| grep -vF "wgs" | awk '{print $1}') + $(iptables -xnvL OUTPUT -t raw | grep -Fv "LOG" | grep -F "Skynet-Master dst" | awk '{print $1}')))"
			if iptables -t raw -C PREROUTING -i wgs+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null; then
				hits2="$((hits2 + $(iptables -xnvL PREROUTING -t raw | grep -Fv "LOG" | grep -F "Skynet-Master dst" | grep -F "wgs" | awk '{print $1}')))"
			fi
			if iptables -t raw -C PREROUTING -i tun2+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null; then
				hits2="$((hits2 + $(iptables -xnvL PREROUTING -t raw | grep -Fv "LOG" | grep -F "Skynet-Master dst" | grep -F "tun" | awk '{print $1}')))"
			fi
		else
			hits2="0"
		fi
	fi
	ftime="$(($(date +%s) - stime))"
	if ! echo "$((blacklist1count - oldips))" | grep -qF "-"; then newips="+$((blacklist1count - oldips))"; else newips="$((blacklist1count - oldips))"; fi
	if ! echo "$((blacklist2count - oldranges))" | grep -qF "-"; then newranges="+$((blacklist2count - oldranges))"; else newranges="$((blacklist2count - oldranges))"; fi
	if [ "$1" = "minimal" ]; then
		Grn "$blacklist1count IPs (${newips}) -- $blacklist2count Ranges Banned (${newranges}) || $hits1 Inbound -- $hits2 Outbound Connections Blocked!"
	else
		logz="[#] $blacklist1count IPs (${newips}) -- $blacklist2count Ranges Banned (${newranges}) || $hits1 Inbound -- $hits2 Outbound Connections Blocked! [$1] [${ftime}s]"
		logger -t Skynet "$logz"; echo "$logz"
	fi
}

Write_Config() {
	{
		printf '%s\n' "################################################"
		printf '%s\n' "## Generated By Skynet - Do Not Manually Edit ##"
		printf '%-45s %s\n\n' "## $(date +"%b %d %T")" "##"
		printf '%s\n' "## Installer ##"
		printf '%s="%s"\n' "model" "$model"
		printf '%s="%s"\n' "localver" "$localver"
		printf '%s="%s"\n' "autoupdate" "$autoupdate"
		printf '%s="%s"\n' "banmalwareupdate" "$banmalwareupdate"
		printf '%s="%s"\n' "forcebanmalwareupdate" "$forcebanmalwareupdate"
		printf '%s="%s"\n' "logmode" "$logmode"
		printf '%s="%s"\n' "filtertraffic" "$filtertraffic"
		printf '%s="%s"\n' "swaplocation" "$swaplocation"
		printf '\n%s\n' "## Counters / Lists ##"
		printf '%s="%s"\n' "blacklist1count" "$blacklist1count"
		printf '%s="%s"\n' "blacklist2count" "$blacklist2count"
		printf '%s="%s"\n' "customlisturl" "$customlisturl"
		printf '%s="%s"\n' "customlist2url" "$customlist2url"
		printf '%s="%s"\n' "countrylist" "$countrylist"
		printf '%s="%s"\n' "excludelists" "$excludelists"
		printf '\n%s\n' "## Settings ##"
		printf '%s="%s"\n' "unbanprivateip" "$unbanprivateip"
		printf '%s="%s"\n' "loginvalid" "$loginvalid"
		printf '%s="%s"\n' "banaiprotect" "$banaiprotect"
		printf '%s="%s"\n' "securemode" "$securemode"
		printf '%s="%s"\n' "extendedstats" "$extendedstats"
		printf '%s="%s"\n' "fastswitch" "$fastswitch"
		printf '%s="%s"\n' "syslogloc" "$syslogloc"
		printf '%s="%s"\n' "syslog1loc" "$syslog1loc"
		printf '%s="%s"\n' "iotblocked" "$iotblocked"
		printf '%s="%s"\n' "iotlogging" "$iotlogging"
		printf '%s="%s"\n' "iotports" "$iotports"
		printf '%s="%s"\n' "iotproto" "$iotproto"
		printf '%s="%s"\n' "lookupcountry" "$lookupcountry"
		printf '%s="%s"\n' "cdnwhitelist" "$cdnwhitelist"
		printf '%s="%s"\n' "displaywebui" "$displaywebui"
		printf '\n%s\n' "################################################"
	} > "$skynetcfg"
}

##########
#- Menu -#
##########

Load_Menu() {
	. "$skynetcfg"
	Display_Header "9"
	echo "Router Model; $model"
	echo "Skynet Version; $localver ($(Filter_Date < "$0")) ($(md5sum "$0" | awk '{print $1}'))"
	echo "$(iptables --version) - ($iface @ $(nvram get lan_ipaddr))"
	ipset -v 2>/dev/null
	echo "IP Address; ($(if nvram get wan0_ipaddr | Is_PrivateIP; then Red "$(nvram get wan0_ipaddr)"; else nvram get wan0_ipaddr; fi))$(if [ "$(nvram get ipv6_service)" != "disabled" ]; then echo " - ($(nvram get ipv6_prefix)/$(nvram get ipv6_prefix_length))"; fi)"
	echo "FW Version; $(nvram get buildno)_$(nvram get extendno) ($(uname -v | awk '{printf "%s %s %s\n", $5, $6, $9}')) ($(uname -r))"
	echo "Install Dir; ${skynetloc} ($(df -h "${skynetloc}" | xargs | awk '{printf "%s / %s\n", $11, $9}') Space Available)"
	if [ -n "$swaplocation" ]; then
		echo "SWAP File; $swaplocation ($(du -h "$swaplocation" | awk '{print $1}'))"
		if [ "$(du "$swaplocation" | awk '{print $1}')" -lt "1048576" ]; then
			Red "SWAP File Too Small - 1GB Minimum Required - Please Fix Immediately!"
		fi
	fi
	if [ -n "$countrylist" ]; then echo "Banned Countries; $countrylist"; fi
	if [ -f "/tmp/skynet.lock" ] && [ -d "/proc/$(sed -n '2p' /tmp/skynet.lock)" ]; then
		echo
		Red "[*] Lock File Detected ($(sed -n '1p' /tmp/skynet.lock)) (pid=$(sed -n '2p' /tmp/skynet.lock))"
		Ylow '[*] Locked Processes Generally Take 1-2 Minutes To Complete And May Result In Temporarily "Failed" Tests'
	fi
	echo
	if ! Check_Connection >/dev/null 2>&1; then
		printf '%-35s | %-8s\n' "Internet-Connectivity" "$(Red "[Failed]")"
	fi
	if ! grep -E "start.* # Skynet" /jffs/scripts/firewall-start 2>/dev/null | grep -qvE "^#"; then
		printf '%-35s | %-8s\n' "Firewall-Start Entry" "$(Red "[Failed]")"
	fi
	if ! [ -w "${skynetloc}" ]; then
		printf '%-35s | %-8s\n' "Write Permission" "$(Red "[Failed]")"
	fi
	if ! Check_Swap; then
		printf '%-35s | %-8s\n' "SWAP" "$(Red "[Failed]")"
	fi
	if [ "$(cru l | grep -c "Skynet")" -lt "2" ]; then
		printf '%-35s | %-8s\n' "Cron Jobs" "$(Red "[Failed]")"
	fi
	if ! Check_IPSets; then
		printf '%-35s | %-8s\n' "IPSets" "$(Red "[Failed]")"; nolog="1"; unset fail
	fi
	if ! Check_IPTables; then
		printf '%-35s | %-8s\n' "IPTables Rules" "$(Red "[Failed]")"; nolog="1"; unset fail
	fi
	if [ "$fastswitch" = "enabled" ]; then
		Ylow "Fast Switch List Is Enabled!"
	fi
	if [ "$nolog" != "1" ]; then Print_Log "minimal"; fi
	unset "nolog"
	unset "option1" "option2" "option3" "option4" "option5"
	reloadmenu="1"
	Purge_Logs
	echo
	while true; do
		echo "Select Menu Option:"
		echo "[1]  --> Unban"
		echo "[2]  --> Ban"
		echo "[3]  --> Malware Blacklist"
		echo "[4]  --> Whitelist"
		echo "[5]  --> Import IP List"
		echo "[6]  --> Deport IP List"
		echo "[7]  --> Save"
		echo "[8]  --> Restart Skynet"
		echo "[9]  --> Temporarily Disable Skynet"
		echo "[10] --> Update Skynet"
		echo "[11] --> Settings"
		echo "[12] --> Debug Options"
		echo "[13] --> Stats"
		echo "[14] --> Install Skynet"
		echo "[15] --> Uninstall"
		echo
		echo "[r]  --> Reload Menu"
		echo "[e]  --> Exit Menu"
		echo
		printf "[1-15]: "
		read -r "menu"
		echo
		case "$menu" in
			1)
				if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; Load_Menu; break; fi
				option1="unban"
				while true; do
					echo "What Type Of Input Would You Like To Unban:"
					echo "[1]  --> IP"
					echo "[2]  --> Range"
					echo "[3]  --> Domain"
					echo "[4]  --> Comment"
					echo "[5]  --> Country"
					echo "[6]  --> ASN"
					echo "[7]  --> Malware Lists"
					echo "[8]  --> Non Manual Bans"
					echo "[9]  --> All"
					echo
					printf "[1-9]: "
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
							if ! echo "$option3" | Is_IP; then echo "[*] $option3 Is Not A Valid IP"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						2)
							option2="range"
							echo "Input Range To Unban:"
							echo
							printf "[Range]: "
							read -r "option3"
							echo
							if ! echo "$option3" | Is_Range; then echo "[*] $option3 Is Not A Valid Range"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						3)
							option2="domain"
							echo "Input Domain To Unban:"
							echo
							printf "[URL]: "
							read -r "option3"
							echo
							if [ -z "$option3" ]; then echo "[*] URL Field Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						4)
							option2="comment"
							echo "Remove Bans Matching Comment:"
							echo
							printf "[Comment]: "
							read -r "option3"
							echo
							if [ "${#option3}" -gt "255" ]; then echo "[*] $option3 Is Not A Valid Comment. 255 Chars Max"; echo; unset "option2" "option3"; continue; fi
							if [ -z "${option3}" ]; then echo "[*] Comment Field Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						5)
							option2="country"
							break
						;;
						6)
							option2="asn"
							echo "Input ASN To Unban:"
							echo
							printf "[ASN]: "
							read -r "option3"
							echo
							if ! echo "$option3" | Is_ASN; then echo "[*] $option3 Is Not A Valid ASN"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						7)
							option2="malware"
							break
						;;
						8)
							option2="nomanual"
							break
						;;
						9)
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
							echo "[*] $menu2 Isn't An Option!"
							echo
						;;
					esac
				done
				break
			;;
			2)
				if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; Load_Menu; break; fi
				option1="ban"
				while true; do
					echo "What Type Of Input Would You Like To Ban:"
					echo "[1]  --> IP"
					echo "[2]  --> Range"
					echo "[3]  --> Domain"
					echo "[4]  --> Country"
					echo "[5]  --> ASN"
					echo
					printf "[1-5]: "
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
							if ! echo "$option3" | Is_IP; then echo "[*] $option3 Is Not A Valid IP"; echo; unset "option2" "option3"; continue; fi
							echo "Input Comment For Ban:"
							echo
							printf "[Comment]: "
							read -r "option4"
							echo
							if [ "${#option4}" -gt "244" ]; then echo "[*] $option4 Is Not A Valid Comment. 244 Chars Max"; echo; unset "option2" "option3" "option4"; continue; fi
							break
						;;
						2)
							option2="range"
							echo "Input Range To Ban:"
							echo
							printf "[Range]: "
							read -r "option3"
							echo
							if ! echo "$option3" | Is_Range; then echo "[*] $option3 Is Not A Valid Range"; echo; unset "option2" "option3"; continue; fi
							echo "Input Comment For Ban:"
							echo
							printf "[Comment]: "
							read -r "option4"
							echo
							if [ "${#option4}" -gt "243" ]; then echo "[*] $option3 Is Not A Valid Comment. 243 Chars Max"; echo; unset "option2" "option3" "option4"; continue; fi
							break
						;;
						3)
							option2="domain"
							echo "Input Domain To Ban:"
							echo
							printf "[URL]: "
							read -r "option3"
							echo
							if [ -z "$option3" ]; then echo "[*] URL Field Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						4)
							option2="country"
							if [ -n "$countrylist" ]; then echo "Countries Currently Banned: (${countrylist})"; fi
							echo "Input Country Abbreviations To Ban:"
							echo
							printf "[Countries]: "
							read -r "option3"
							echo
							if [ -z "$option3" ]; then echo "[*] Country Field Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
							if echo "$option3" | grep -qF "\""; then echo "[*] Country Field Can't Include Quotes - Please Try Again"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						5)
							option2="asn"
							echo "Input ASN To Ban:"
							echo
							printf "[ASN]: "
							read -r "option3"
							echo
							if ! echo "$option3" | Is_ASN; then echo "[*] $option3 Is Not A Valid ASN"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						e|exit|back|menu)
							unset "option1" "option2" "option3" "option4" "option5"
							clear
							Load_Menu
							break
						;;
						*)
							echo "[*] $menu2 Isn't An Option!"
							echo
						;;
					esac
				done
				break
			;;
			3)
				if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; Load_Menu; break; fi
				option1="banmalware"
				while true; do
					echo "Select Option:"
					echo "[1]  --> Update"
					echo "[2]  --> Change Filter List"
					echo "[3]  --> Reset Filter List"
					echo "[4]  --> Exclude Individual Lists"
					echo "[5]  --> Reset Exclusion List"
					echo
					printf "[1-5]: "
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
							if [ -z "$option2" ]; then echo "[*] URL Field Can't Be Empty - Please Try Again"; echo; unset "option2"; continue; fi
							break
						;;
						3)
							option2="reset"
							break
						;;
						4)
							option2="exclude"
							echo "Input Names Of Lists To Exclude Seperated By Pipes"
							echo "Example - list1.ipset|list2.ipset|list3.ipset"
							echo
							printf "[Lists]: "
							read -r "option3"
							echo
							if [ -z "$option3" ]; then echo "[*] Exclusion List Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						5)
							option2="exclude"
							option3="reset"
							break
						;;
						e|exit|back|menu)
							unset "option1" "option2" "option3" "option4" "option5"
							clear
							Load_Menu
							break
						;;
						*)
							echo "[*] $menu2 Isn't An Option!"
							echo
						;;
					esac
				done
				break
			;;
			4)
				if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; Load_Menu; break; fi
				option1="whitelist"
				while true; do
					echo "Select Whitelist Option:"
					echo "[1]  --> IP/Range"
					echo "[2]  --> Domain"
					echo "[3]  --> ASN"
					echo "[4]  --> Refresh VPN Whitelist"
					echo "[5]  --> Remove Entries"
					echo "[6]  --> Refresh Entries"
					echo "[7]  --> View Entries"
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
							if ! echo "$option3" | Is_IPRange; then echo "[*] $option3 Is Not A Valid IP/Range"; echo; unset "option2" "option3"; continue; fi
							echo "Input Comment For Whitelist:"
							echo
							printf "[Comment]: "
							read -r "option4"
							echo
							if [ "${#option4}" -gt "242" ]; then echo "[*] $option4 Is Not A Valid Comment. 242 Chars Max"; echo; unset "option2" "option3" "option4"; continue; fi
							break
						;;
						2)
							option2="domain"
							echo "Input Domain To Whitelist:"
							echo
							printf "[URL]: "
							read -r "option3"
							echo
							if [ -z "$option3" ]; then echo "[*] URL Field Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						3)
							option2="asn"
							echo "Input ASN To Whitelist:"
							echo
							printf "[ASN]: "
							read -r "option3"
							echo
							if ! echo "$option3" | Is_ASN; then echo "[*] $option3 Is Not A Valid ASN"; echo; unset "option2" "option3"; continue; fi
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
										if ! echo "$option4" | Is_IPRange; then echo "[*] $option4 Is Not A Valid IP/Range"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									3)
										option3="comment"
										echo "Remove Entries Based On Comment:"
										echo
										printf "[Comment]: "
										read -r "option4"
										echo
										if [ "${#option4}" -gt "255" ]; then echo "[*] $option4 Is Not A Valid Comment. 255 Chars Max"; echo; unset "option3" "option4"; continue; fi
										if [ -z "${option4}" ]; then echo "[*] Comment Field Can't Be Empty - Please Try Again"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "[*] $menu3 Isn't An Option!"
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
							option2="view"
							while true; do
								echo "Select Entries To View:"
								echo "[1]  --> All"
								echo "[2]  --> Manually Added IPs"
								echo "[3]  --> Manually Added Domains"
								echo "[4]  --> Imported Entries"
								echo
								printf "[1-4]: "
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
									4)
										option3="imported"
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "[*] $menu3 Isn't An Option!"
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
							echo "[*] $menu2 Isn't An Option!"
							echo
						;;
					esac
				done
				break
			;;
			5)
				if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; Load_Menu; break; fi
				option1="import"
				while true; do
					echo "Select Where To Import List:"
					echo "[1]  --> Blacklist"
					echo "[2]  --> Whitelist"
					echo
					printf "[1-2]: "
					read -r "menu3"
					echo
					case "$menu3" in
						1)
							option2="blacklist"
							break
						;;
						2)
							option2="whitelist"
							break
						;;
						e|exit|back|menu)
							unset "option1" "option2" "option3" "option4" "option5"
							clear
							Load_Menu
							break
						;;
						*)
							echo "[*] $menu3 Isn't An Option!"
							echo
						;;
					esac
				done
				echo "Input URL/Local File To Import:"
				echo
				printf "[File]: "
				read -r "option3"
				echo
				if [ -z "$option3" ]; then echo "[*] File Field Can't Be Empty - Please Try Again"; echo; unset "option1" "option2" "option3"; continue; fi
				break
			;;
			6)
				if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; Load_Menu; break; fi
				option1="deport"
				while true; do
					echo "Select Where To Deport List From:"
					echo "[1]  --> Blacklist"
					echo "[2]  --> Whitelist"
					echo
					printf "[1-2]: "
					read -r "menu3"
					echo
					case "$menu3" in
						1)
							option2="blacklist"
							break
						;;
						2)
							option2="whitelist"
							break
						;;
						e|exit|back|menu)
							unset "option1" "option2" "option3" "option4" "option5"
							clear
							Load_Menu
							break
						;;
						*)
							echo "[*] $menu3 Isn't An Option!"
							echo
						;;
					esac
				done
				echo "Input URL/Local File To Deport"
				echo
				printf "[File]: "
				read -r "option3"
				echo
				if [ -z "$option3" ]; then echo "[*] File Field Can't Be Empty - Please Try Again"; echo; unset "option1" "option2" "option3"; continue; fi
				break
			;;
			7)
				if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; Load_Menu; break; fi
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
							echo "[*] $menu2 Isn't An Option!"
							echo
						;;
					esac
				done
				break
			;;
			11)
				option1="settings"
				while true; do
					echo "Select Setting To Toggle:"
					printf '%-35s | %-40s\n' "[1]  --> Skynet Auto-Updates" "$(if [ "$autoupdate" = "enabled" ]; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[2]  --> Malware List Auto-Updates" "$(if [ "$banmalwareupdate" = "daily" ] || [ "$banmalwareupdate" = "weekly" ]; then Grn "[$banmalwareupdate]"; else Red "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[3]  --> Logging" "$(if [ "$logmode" = "enabled" ]; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[4]  --> Filter Traffic" "$(Grn "[$filtertraffic]")"
					printf '%-35s | %-40s\n' "[5]  --> Unban PrivateIP" "$(if [ "$unbanprivateip" = "enabled" ]; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[6]  --> Log Invalid Packets" "$(if [ "$loginvalid" = "enabled" ]; then Grn "[Enabled]"; else Grn "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[7]  --> Import AiProtect Data" "$(if [ "$banaiprotect" = "enabled" ]; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[8]  --> Secure Mode" "$(if [ "$securemode" = "enabled" ]; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[9]  --> Fast Switch List" "$(if [ "$fastswitch" = "enabled" ]; then Ylow "[Enabled]"; else Grn "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[10] --> Syslog Location" "$(if { [ "$syslogloc" = "/tmp/syslog.log" ] && [ "$syslog1loc" = "/tmp/syslog.log-1" ]; } || { [ "$syslogloc" = "/jffs/syslog.log" ] && [ "$syslog1loc" = "/jffs/syslog.log-1" ]; } then Grn "[Default]"; else Ylow "[Custom]"; fi)"
					printf '%-35s | %-40s\n' "[11] --> IOT Blocking" "$(if [ "$iotblocked" != "enabled" ]; then Grn "[Disabled]"; else Ylow "[Enabled]"; fi)"
					printf '%-35s | %-40s\n' "[12] --> IOT Logging" "$(if [ "$iotlogging" != "enabled" ]; then Red "[Disabled]"; else Grn "[Enabled]"; fi)"
					printf '%-35s | %-40s\n' "[13] --> Stats Country Lookup" "$(if [ "$lookupcountry" = "enabled" ]; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[14] --> CDN Whitelisting" "$(if [ "$cdnwhitelist" = "enabled" ]; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[15] --> Display WebUI" "$(if [ "$displaywebui" = "enabled" ]; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
					echo
					printf "[1-15]: "
					read -r "menu2"
					echo
					case "$menu2" in
						1)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="autoupdate"
							while true; do
								echo "Select Skynet Autoupdate Option:"
								echo "[1]  --> Enable"
								echo "[2]  --> Disable"
								echo
								printf "[1-2]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										option3="enable"
										break
									;;
									2)
										option3="disable"
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "[*] $menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						2)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="banmalware"
							while true; do
								echo "Select Malware Blacklist Updating Frequency:"
								echo "[1]  --> Daily"
								echo "[2]  --> Weekly"
								echo "[3]  --> Disable"
								echo
								printf "[1-3]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										option3="daily"
										break
									;;
									2)
										option3="weekly"
										break
									;;
									3)
										option3="disable"
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "[*] $menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						3)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="logmode"
							while true; do
								echo "Select Logging Option:"
								echo "[1]  --> Enable"
								echo "[2]  --> Disable"
								echo
								printf "[1-2]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										option3="enable"
										break
									;;
									2)
										option3="disable"
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "[*] $menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						4)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="filter"
							while true; do
								echo "Select Filter Option:"
								echo "[1]  --> All Traffic"
								echo "[2]  --> Inbound"
								echo "[3]  --> Outbound"
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
										option3="inbound"
										break
									;;
									3)
										option3="outbound"
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "[*] $menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						5)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="unbanprivate"
							while true; do
								echo "Select Filter PrivateIP Option:"
								echo "[1]  --> Enable"
								echo "[2]  --> Disable"
								echo
								printf "[1-2]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										option3="enable"
										break
									;;
									2)
										option3="disable"
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "[*] $menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						6)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="loginvalid"
							while true; do
								echo "Select Invalid Packet Logging Option:"
								echo "[1]  --> Enable"
								echo "[2]  --> Disable"
								echo
								printf "[1-2]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										option3="enable"
										break
									;;
									2)
										option3="disable"
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "[*] $menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						7)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="banaiprotect"
							while true; do
								echo "Select Ban AiProtect Option:"
								echo "[1]  --> Enable"
								echo "[2]  --> Disable"
								echo
								printf "[1-2]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										option3="enable"
										break
									;;
									2)
										option3="disable"
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "[*] $menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						8)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="securemode"
							while true; do
								echo "Select Secure Mode Option:"
								echo "[1]  --> Enable"
								echo "[2]  --> Disable"
								echo
								printf "[1-2]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										option3="enable"
										break
									;;
									2)
										option3="disable"
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "[*] $menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						9)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option1="fs"
							while true; do
								echo "Select Fast Switch List Option:"
								echo "[1]  --> Enable"
								echo "[2]  --> Disable"
								echo
								printf "[1-2]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										echo "Input Custom Filter List URL:"
										printf "[URL]: "
										read -r "option2"
										echo
										if [ -z "$option2" ]; then echo "[*] URL Field Can't Be Empty - Please Try Again"; echo; unset "option2"; continue; fi
										break
										break
									;;
									2)
										option2="disable"
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "[*] $menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						10)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							while true; do
								echo "Select Syslog To Configure:"
								echo "[1]  --> syslog.log"
								echo "[2]  --> syslog.log-1"
								echo
								printf "[1-2]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										option2="syslog"
										while true; do
											echo "Select Syslog Location:"
											echo "[1]  --> Default"
											echo "[2]  --> Custom"
											echo
											printf "[1-2]: "
											read -r "menu3"
											echo
											case "$menu3" in
												1)
													option3="/tmp/syslog.log"
													break
												;;
												2)
													echo "Input Custom Syslog Location:"
													echo
													printf "[File]: "
													read -r "option3"
													echo
													if [ -z "$option3" ]; then echo "[*] File Field Can't Be Empty - Please Try Again"; echo; unset "option1" "option2" "option3"; continue; fi
													break
												;;
												e|exit|back|menu)
													unset "option1" "option2" "option3" "option4" "option5"
													clear
													Load_Menu
													break
												;;
												*)
													echo "[*] $menu3 Isn't An Option!"
													echo
												;;
											esac
										done
										break
										break
									;;
									2)
										option2="syslog1"
										while true; do
											echo "Select Syslog Location:"
											echo "[1]  --> Default"
											echo "[2]  --> Custom"
											echo
											printf "[1-2]: "
											read -r "menu3"
											echo
											case "$menu3" in
												1)
													option3="/tmp/syslog.log-1"
													break
												;;
												2)
													echo "Input Custom Syslog-1 Location:"
													echo
													printf "[File]: "
													read -r "option3"
													echo
													if [ -z "$option3" ]; then echo "[*] File Field Can't Be Empty - Please Try Again"; echo; unset "option1" "option2" "option3"; continue; fi
													break
												;;
												e|exit|back|menu)
													unset "option1" "option2" "option3" "option4" "option5"
													clear
													Load_Menu
													break
												;;
												*)
													echo "[*] $menu3 Isn't An Option!"
													echo
												;;
											esac
										done
										break
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "[*] $menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						11)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							while true; do
								option2="iot"
								echo "Select IOT Option:"
								echo "[1]  --> Unban Devices"
								echo "[2]  --> Ban Devices"
								echo "[3]  --> View Blocked Devices"
								echo "[4]  --> Add Custom Allowed Ports"
								echo "[5]  --> Reset Custom Port List"
								echo "[6]  --> Select Allowed Protocols"
								echo
								printf "[1-6]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										option3="unban"
										echo "Input Local IP(s) To Unban:"
										echo "Seperate Multiple Addresses With A Comma"
										echo
										printf "[IP]: "
										read -r "option4"
										echo
										if echo "$option4" | grep -q ","; then
											for ip in $(echo "$option4" | sed 's~,~ ~g'); do
													if ! echo "$ip" | Is_IPRange; then echo "[*] $ip Is Not A Valid IP/Range"; echo; unset "option3" "option4"; continue 2; fi
											done
										else
											if ! echo "$option4" | Is_IPRange; then echo "[*] $option4 Is Not A Valid IP/Range"; echo; unset "option3" "option4"; continue; fi
										fi
										break
									;;
									2)
										option3="ban"
										echo "Input Local IP(s) To Ban:"
										echo "Seperate Multiple Addresses With A Comma"
										echo
										printf "[IP]: "
										read -r "option4"
										echo
										if echo "$option4" | grep -q ","; then
											for ip in $(echo "$option4" | sed 's~,~ ~g'); do
													if ! echo "$ip" | Is_IPRange; then echo "[*] $ip Is Not A Valid IP/Range"; echo; unset "option3" "option4"; continue 2; fi
											done
										else
											if ! echo "$option4" | Is_IPRange; then echo "[*] $option4 Is Not A Valid IP/Range"; echo; unset "option3" "option4"; continue; fi
										fi
										break
									;;
									3)
										option3="view"
										break
									;;
									4)
										option3="ports"
										if [ -n "$iotports" ]; then echo "Current Custom Ports Allowed: $(Grn "$iotports")"; echo; fi
										echo "Input Custom Ports(s) To Allow:"
										echo "Seperate Multiple Ports With A Comma"
										echo
										printf "[Ports]: "
										read -r "option4"
										echo
										if echo "$option4" | grep -q ","; then
											for port in $(echo "$option4" | sed 's~,~ ~g'); do
													if ! echo "$port" | Is_Port; then echo "[*] $port Is Not A Valid Port"; echo; unset "option3" "option4"; continue 2; fi
											done
										else
											if ! echo "$option4" | Is_Port; then echo "[*] $port Is Not A Valid Port"; echo; unset "option3" "option4"; continue; fi
										fi
										break
									;;
									5)
										option3="ports"
										option4="reset"
									break
									;;
									6)
										while true; do
											option3="proto"
											echo "Select Port Protocol To Allow:"
											echo
											echo "[1]  --> UDP"
											echo "[2]  --> TCP"
											echo "[3]  --> Both"
											echo
											printf "[1-3]: "
											read -r "menu4"
											echo
											case "$menu4" in
												1)
													option4="udp"
													break
												;;
												2)
													option4="tcp"
													break
												;;
												3)
													option4="all"
													break
												;;
												e|exit|back|menu)
													unset "option1" "option2" "option3" "option4" "option5"
													clear
													Load_Menu
													break
												;;
												*)
													echo "[*] $menu4 Isn't An Option!"
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
										echo "[*] $menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						12)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="iotlogging"
							while true; do
								echo "Select IOT Logging Option:"
								echo "[1]  --> Enable"
								echo "[2]  --> Disable"
								echo
								printf "[1-2]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										option3="enable"
										break
									;;
									2)
										option3="disable"
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "[*] $menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						13)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="lookupcountry"
							while true; do
								echo "Select Country Lookup For Stats Option:"
								echo "[1]  --> Enable"
								echo "[2]  --> Disable"
								echo
								printf "[1-2]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										option3="enable"
										break
									;;
									2)
										option3="disable"
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "[*] $menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						14)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="cdnwhitelist"
							while true; do
								echo "Select CDN Whitelisting Option:"
								echo "[1]  --> Enable"
								echo "[2]  --> Disable"
								echo
								printf "[1-2]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										option3="enable"
										break
									;;
									2)
										option3="disable"
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "[*] $menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						15)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="webui"
							while true; do
								echo "Select WebUI Option:"
								echo "[1]  --> Enable"
								echo "[2]  --> Disable"
								echo
								printf "[1-2]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										option3="enable"
										break
									;;
									2)
										option3="disable"
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "[*] $menu3 Isn't An Option!"
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
							echo "[*] $menu Isn't An Option!"
							echo
						;;
					esac
				done
				break
			;;
			fs)
				option1="fs"
				break
			;;
			12)
				option1="debug"
				while true; do
					echo "Select Debug Option:"
					echo "[1]  --> Show Log Entries As They Appear"
					echo "[2]  --> Print Debug Info"
					echo "[3]  --> Cleanup Syslog Entries"
					echo "[4]  --> SWAP File Management"
					echo "[5]  --> Backup Skynet Files"
					echo "[6]  --> Restore Skynet Files"
					echo
					printf "[1-6]: "
					read -r "menu2"
					echo
					case "$menu2" in
						1)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
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
										if ! echo "$option4" | Is_IP; then echo "[*] $option4 Is Not A Valid IP"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									3)
										option3="port"
										printf "[Port]: "
										read -r "option4"
										echo
										if ! echo "$option4" | Is_Port || [ "$option4" -gt "65535" ]; then echo "[*] $option4 Is Not A Valid Port"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break
									;;
									*)
										echo "[*] $menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						2)
							option2="info"
							break
						;;
						3)
							option2="clean"
							break
						;;
						4)
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
										echo "[*] $menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						5)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="backup"
							break
						;;
						6)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
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
							echo "[*] $menu2 Isn't An Option!"
							echo
						;;
					esac
				done
				break
			;;
			13)
				option1="stats"
				while true; do
					echo "Select Stat Option:"
					echo "[1]  --> Display"
					echo "[2]  --> Search"
					echo "[3]  --> Remove"
					echo "[4]  --> Reset"
					echo
					printf "[1-4]: "
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
										if ! [ "$option3" -eq "$option3" ] 2>/dev/null; then echo "[*] $option3 Isn't A Valid Number!"; echo; unset "option3" continue; fi
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break 2
									;;
									*)
										echo "[*] $menu3 Isn't An Option!"
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
										echo "[*] $menu4 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						2)
							option2="search"
							while true; do
								echo "Search Options:"
								echo "[1]  --> Based On Port x"
								echo "[2]  --> Entries From Specific IP"
								echo "[3]  --> Search Malwarelists For IP"
								echo "[4]  --> Search Manualbans"
								echo "[5]  --> Search For Outbound Entries From Local Device"
								echo "[6]  --> Hourly Reports"
								echo "[7]  --> Invalid Packets"
								echo "[8]  --> Active Connections"
								echo "[9]  --> IOT Packets"
								echo
								printf "[1-9]: "
								read -r "menu4"
								echo
								case "$menu4" in
									1)
										option3="port"
										printf "[Port]: "
										read -r "option4"
										echo
										if ! echo "$option4" | Is_Port || [ "$option4" -gt "65535" ]; then echo "[*] $option4 Is Not A Valid Port"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									2)
										option3="ip"
										printf "[IP]: "
										read -r "option4"
										echo
										if ! echo "$option4" | Is_IPRange; then echo "[*] $option4 Is Not A Valid IP/Range"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									3)
										option3="malware"
										printf "[IP]: "
										read -r "option4"
										echo
										if ! echo "$option4" | Is_IPRange; then echo "[*] $option4 Is Not A Valid IP/Range"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									4)
										option3="manualbans"
										break
									;;
									5)
										option3="device"
										printf "[Local IP]: "
										read -r "option4"
										echo
										if ! echo "$option4" | Is_IP; then echo "[*] $option4 Is Not A Valid IP"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									6)
										option3="reports"
										break
									;;
									7)
										option3="invalid"
										break
									;;
									8)
										option3="connections"
										while true; do
											echo "Search Options:"
											echo "[1]  --> All Results"
											echo "[2]  --> Search By IP"
											echo "[3]  --> Search By Port"
											echo "[4]  --> Search By Protocol"
											echo "[5]  --> Search By Identification"
											echo
											printf "[1-5]: "
											read -r "menu5"
											echo
											case "$menu5" in
												1)
													break
												;;
												2)
													option4="ip"
													printf "[IP]: "
													read -r "option5"
													echo
													if ! echo "$option5" | Is_IP; then echo "[*] $option5 Is Not A Valid IP"; echo; unset "option4" "option5"; continue; fi
													break
												;;
												3)
													option4="port"
													printf "[Port]: "
													read -r "option5"
													echo
													if ! echo "$option5" | Is_Port || [ "$option5" -gt "65535" ]; then echo "[*] $option5 Is Not A Valid Port"; echo; unset "option4" "option5"; continue; fi
													break
												;;
												4)
													option4="proto"
													printf "[Protocol]: "
													read -r "option5"
													echo
													if [ "$option5" != "tcp" ] && [ "$option5" != "udp" ] && [ "$option5" != "icmp" ]; then echo "[*] $option5 Is Not A Valid Protocol"; echo; unset "option4" "option5"; continue; fi
													break
												;;
												5)
													option4="id"
													printf "[Identification]: "
													read -r "option5"
													echo
													break
												;;
												e|exit|back|menu)
													unset "option1" "option2" "option3" "option4" "option5"
													clear
													Load_Menu
													break
												;;
												*)
													echo "[*] $menu5 Isn't An Option!"
													echo
												;;
											esac
										done
										break
									;;
									9)
										option3="iot"
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break 2
									;;
									*)
										echo "[*] $menu4 Isn't An Option!"
										echo
									;;
								esac
							done
							if [ "$option3" != "connections" ]; then
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
											if ! [ "$optionx" -eq "$optionx" ] 2>/dev/null; then echo "[*] $optionx Isn't A Valid Number!"; echo; unset "optionx"; continue; fi
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
											echo "[*] $menu3 Isn't An Option!"
											echo
										;;
									esac
								done
							fi
							break
						;;
						3)
							option2="remove"
							while true; do
								echo "Search Options:"
								echo "[1]  --> Logs Containing Specific IP"
								echo "[2]  --> Logs Containing Specific Port"
								echo
								printf "[1-2]: "
								read -r "menu3"
								echo
								case "$menu3" in
									1)
										option3="ip"
										printf "[IP]: "
										read -r "option4"
										echo
										if ! echo "$option4" | Is_IP; then echo "[*] $option4 Is Not A Valid IP"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									2)
										option3="port"
										printf "[Port]: "
										read -r "option4"
										echo
										if ! echo "$option4" | Is_Port || [ "$option4" -gt "65535" ]; then echo "[*] $option4 Is Not A Valid Port"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									e|exit|back|menu)
										unset "option1" "option2" "option3" "option4" "option5"
										clear
										Load_Menu
										break 2
									;;
									*)
										echo "[*] $menu3 Isn't An Option!"
										echo
									;;
								esac
							done
							break
						;;
						4)
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
							echo "[*] $menu2 Isn't An Option!"
							echo
						;;
					esac
				done
				break
			;;
			14)
				option1="install"
				break
			;;
			15)
				option1="uninstall"
				break
			;;
			r|reload)
				clear
				Load_Menu
				break
			;;
			e|exit)
				echo "[*] Exiting!"
				echo; exit 0
			;;
			*)
				echo "[*] $menu Isn't An Option!"
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
	echo "[$] $0 $*" | tr -s " "
fi

trap 'Spinner_End' EXIT

if [ -f "$skynetcfg" ]; then
	. "$skynetcfg"
fi

Display_Header "9"

##############
#- Commands -#
##############


case "$1" in
	unban)
		Check_Lock "$@"
		if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
		Purge_Logs
		case "$2" in
			ip)
				if ! echo "$3" | Is_IP; then echo "[*] $3 Is Not A Valid IP"; echo; exit 2; fi
				echo "[i] Unbanning $3"
				ipset -D Skynet-Blacklist "$3"
				sed -i "\\~\\(BLOCKED.*=$3 \\|Manual Ban.*=$3 \\)~d" "$skynetlog" "$skynetevents"
			;;
			range)
				if ! echo "$3" | Is_Range; then echo "[*] $3 Is Not A Valid Range"; echo; exit 2; fi
				echo "[i] Unbanning $3"
				ipset -D Skynet-BlockedRanges "$3"
				sed -i "\\~\\(BLOCKED.*=$3 \\|Manual Ban.*=$3 \\)~d" "$skynetlog" "$skynetevents"
			;;
			domain)
				if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
				if [ -z "$3" ]; then echo "[*] Domain Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				domain="$(echo "$3" | Strip_Domain)"
				echo "[i] Removing $domain From Blacklist"
				for ip in $(Domain_Lookup "$domain"); do
					echo "[i] Unbanning $ip"
					ipset -D Skynet-Blacklist "$ip"
					sed -i "\\~\\(BLOCKED.*=$ip \\|Manual Ban.*=$ip \\)~d" "$skynetlog" "$skynetevents"
				done
			;;
			comment)
				if [ -z "$3" ]; then echo "[*] Comment Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				echo "[i] Removing Bans With Comment Containing ($3)"
				sed "\\~add Skynet-Whitelist ~d;\\~$3~!d;s~ comment.*~~;s~add~del~g" "$skynetipset" | ipset restore -!
				echo "[i] Removing Old Logs - This May Take Awhile (To Skip Type ctrl+c)"
				trap 'break; echo' 2
				sed "\\~add Skynet-Whitelist ~d;\\~$3~!d;s~ comment.*~~" "$skynetipset" | cut -d' ' -f3 | while IFS= read -r "ip"; do
					sed -i "\\~\\(BLOCKED.*=$ip \\|Manual Ban.*=$ip \\)~d" "$skynetlog" "$skynetevents"
				done
			;;
			country)
				echo "[i] Removing Previous Country Bans (${countrylist})"
				sed '\~add Skynet-Whitelist ~d;\~Country: ~!d;s~ comment.*~~;s~add~del~g' "$skynetipset" | ipset restore -!
				unset "countrylist"
			;;
			asn)
				if [ -z "$3" ]; then echo "[*] ASN Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				if ! echo "$3" | Is_ASN; then echo "[*] $3 Is Not A Valid ASN"; echo; exit 2; fi
				asnlist="$(echo "$3" | awk '{print toupper($0)}')"
				echo "[i] Removing Previous $asnlist Bans"
				sed "\~add Skynet-Whitelist ~d;\~$asnlist ~!d;s~ comment.*~~;s~add~del~g" "$skynetipset" | ipset restore -!
			;;
			malware)
				echo "[i] Removing Previous Malware Blacklist Entries"
				sed '\~add Skynet-Whitelist ~d;\~BanMalware~!d;s~ comment.*~~;s~add~del~g' "$skynetipset" | ipset restore -!
			;;
			nomanual)
				echo "[i] Removing All Non-Manual Bans"
				sed -i '\~Manual ~!d' "$skynetlog"
				ipset flush Skynet-Blacklist
				ipset flush Skynet-BlockedRanges
				sed '\~add Skynet-Whitelist ~d;\~Manual[R]*Ban: ~!d' "$skynetipset" | ipset restore -!
				iptables -Z PREROUTING -t raw
			;;
			all)
				echo "[i] Removing All $((blacklist1count + blacklist2count)) Entries From Blacklist"
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
		echo "[i] Saving Changes"
		Save_IPSets
	;;

	ban)
		Check_Lock "$@"
		if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
		if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
		Purge_Logs
		case "$2" in
			ip)
				if ! echo "$3" | Is_IP; then echo "[*] $3 Is Not A Valid IP"; echo; exit 2; fi
				if [ "${#4}" -gt "244" ]; then echo "[*] $4 Is Not A Valid Comment. 244 Chars Max"; echo; exit 2; fi
				echo "[i] Banning $3"
				desc="$4"
				if [ -z "$4" ]; then
					desc="$(date +"%b %d %T")"
				fi
				ipset -A Skynet-Blacklist "$3" comment "ManualBan: $desc" && echo "$(date +"%b %d %T") Skynet: [Manual Ban] TYPE=Single SRC=$3 COMMENT=$desc " >> "$skynetevents"
			;;
			range)
				if ! echo "$3" | Is_Range; then echo "[*] $3 Is Not A Valid Range"; echo; exit 2; fi
				if [ "${#4}" -gt "243" ]; then echo "[*] $4 Is Not A Valid Comment. 243 Chars Max"; echo; exit 2; fi
				echo "[i] Banning $3"
				desc="$4"
				if [ -z "$4" ]; then
					desc="$(date +"%b %d %T")"
				fi
				ipset -A Skynet-BlockedRanges "$3" comment "ManualRBan: $desc" && echo "$(date +"%b %d %T") Skynet: [Manual Ban] TYPE=Range SRC=$3 COMMENT=$desc " >> "$skynetevents"
			;;
			domain)
				if [ -z "$3" ]; then echo "[*] Domain Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				domain="$(echo "$3" | Strip_Domain)"
				echo "[i] Adding $domain To Blacklist"
				for ip in $(Domain_Lookup "$domain" | Filter_PrivateIP); do
					echo "[i] Banning $ip"
					ipset -A Skynet-Blacklist "$ip" comment "ManualBanD: $domain" && echo "$(date +"%b %d %T") Skynet: [Manual Ban] TYPE=Domain SRC=$ip Host=$domain " >> "$skynetevents"
				done
			;;
			country)
				if [ -z "$3" ]; then echo "[*] Country Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				if echo "$3" | grep -qF "\""; then echo "[*] Country Field Can't Include Quotes - Please Try Again"; echo; exit 2; fi
				countrylinklist="$(echo "$3" | awk '{print tolower($0)}')"
				if [ -n "$countrylist" ]; then
					echo "[i] Removing Previous Country Bans (${countrylist})"
					sed '\~add Skynet-Whitelist ~d;\~Country: ~!d;s~ comment.*~~;s~add~del~g' "$skynetipset" | ipset restore -!
				fi
				if [ "${#3}" -gt "246" ]; then countrylist="Multiple Countries"; else countrylist="$countrylinklist"; fi
				echo "[i] Banning Known IP Ranges For (${3})"
				echo "[i] Downloading Lists"
				for country in $countrylinklist; do
					curl -fskL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors https://ipdeny.com/ipblocks/data/aggregated/"$country"-aggregated.zone >> /tmp/skynet/countrylist.txt
				done
				echo "[i] Filtering IPv4 Ranges & Applying Blacklists"
				grep -F "/" /tmp/skynet/countrylist.txt | sed -n "/^[0-9,\\.,\\/]*$/s/^/add Skynet-BlockedRanges /;s/$/& comment \"Country: $countrylist\"/p" | ipset restore -!
				rm -rf "/tmp/skynet/countrylist.txt"
			;;
			asn)
				if [ -z "$3" ]; then echo "[*] ASN Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				if ! echo "$3" | Is_ASN; then echo "[*] $3 Is Not A Valid ASN"; echo; exit 2; fi
				asnlist="$(echo "$3" | awk '{print toupper($0)}')"
				echo "[i] Adding $asnlist To Blacklist"
				curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors "https://asn.ipinfo.app/api/text/list/$asnlist" | awk -v asn="$asnlist" '/^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)([[:space:]]|$)/{printf "add Skynet-BlockedRanges %s comment \"ASN: %s \"\n", $1, asn }' | awk '!x[$0]++' | ipset restore -!
			;;
			*)
				echo "Command Not Recognized, Please Try Again"
				echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
				echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
				echo; exit 2
			;;
		esac
		echo "[i] Saving Changes"
		Save_IPSets
	;;

	banmalware|fs)
		Check_Lock "$@"
		if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
		if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
		Spinner_Start
		Purge_Logs
		if [ "$2" = "disable" ] && [ "$fastswitch" = "disabled" ] && [ "$1" = "fs" ]; then
			echo "[*] Fast Switch List Already Disabled - Stopping Banmalware"
			echo; exit 1
		fi
		if [ "$fastswitch" = "enabled" ] && [ "$1" = "fs" ] && [ -z "$2" ] || [ "$2" = "disable" ]; then
			echo "[i] Fast Switch List Disabled"
			fastswitch="disabled"
			set "banmalware"
		fi
		if [ "$fastswitch" = "enabled" ] && [ "$1" = "banmalware" ]; then
			set "fs"
		fi
		if [ "$2" = "exclude" ]; then
			if [ "$3" = "reset" ] || [ -z "$3" ]; then
				echo "[i] Exclusion List Reset"
				unset "excludelists"
			else
				excludelists="$3"
			fi
			set "banmalware"
		fi
		if [ -n "$excludelists" ]; then echo "[i] Excluding Lists Matching The Words; $excludelists"; fi
		if [ "$2" = "reset" ]; then
			echo "[i] Filter URL Reset"
			unset "customlisturl"
		fi
		if [ -n "$2" ] && [ "$2" != "reset" ] && [ "$1" != "fs" ]; then
			customlisturl="$2"
			listurl="$customlisturl"
			echo "[i] Custom Filter Detected: $customlisturl"
		elif [ "$1" = "fs" ]; then
			if [ -z "$2" ] && [ -z "$customlist2url" ]; then
				logger -st Skynet "[*] Fast Switch List URL Not Configured - Stopping Banmalware"
				echo; exit 1
			else
				fastswitch="enabled"
				echo "[i] Fast Switch List Enabled"
				if [ -z "$customlist2url" ] || [ -n "$2" ]; then
					customlist2url="$2"
					listurl="$customlist2url"
				else
					listurl="$customlist2url"
				fi
				echo "[i] Custom Filter Detected: $customlist2url"
			fi
		else
			if [ -n "$customlisturl" ]; then
				listurl="$customlisturl"
				echo "[i] Custom Filter Detected: $customlisturl"
			else
				listurl="https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/filter.list"
			fi
		fi
		curl -fsSI "$listurl" >/dev/null || { echo "[*] Stopping Banmalware"; echo; exit 1; }
		Display_Message "[i] Downloading filter.list"
		if [ -n "$excludelists" ]; then
			curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors "$listurl" | dos2unix | grep -vE "($excludelists)" > /jffs/addons/shared-whitelists/shared-Skynet-whitelist && Display_Result
		else
			curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors "$listurl" | dos2unix > /jffs/addons/shared-whitelists/shared-Skynet-whitelist && Display_Result
		fi
		sed -i '\~^http[s]*://\|^www.~!d;' /jffs/addons/shared-whitelists/shared-Skynet-whitelist
		Display_Message "[i] Refreshing Whitelists"
		Whitelist_Extra
		Whitelist_VPN
		Spinner_End
		Whitelist_CDN
		Whitelist_Shared
		Refresh_MWhitelist
		Spinner_Start
		Display_Result
		Display_Message "[i] Consolidating Blacklist"
		mkdir -p "${skynetloc}/lists"
		cwd="$(pwd)"
		cd "${skynetloc}/lists" || exit 1
		awk -F / '{print $NF}' /jffs/addons/shared-whitelists/shared-Skynet-whitelist > /tmp/skynet/skynet.manifest
		while IFS= read -r "list"; do
			if [ ! -f "$list" ]; then
				rm -rf "${skynetloc}"/lists/*
				break
			fi
		done < /tmp/skynet/skynet.manifest
		awk -F/ '{print $0" -Oz "$NF}' /jffs/addons/shared-whitelists/shared-Skynet-whitelist | xargs "curl" -fsLZ
		dos2unix "${skynetloc}"/lists/* 2>/dev/null
		for file in *; do
			grep -qF "$file" /tmp/skynet/skynet.manifest || rm -rf "$file"
		done
		if ! grep -qE '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)$' "${skynetloc}"/lists/* 2>/dev/null; then
			result="$(Red "[$(($(date +%s) - btime))s]")"
			printf '%-8s\n' "$result"
			printf '%-35s\n' "[*] List Content Error Detected - Stopping Banmalware"
			nocfg="1"
			result="1"
		fi
		if [ "$result" != "1" ]; then
			awk '/^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)([[:space:]]|$)/{if(!x[$1]++)print $1 " " FILENAME}' -- * | Filter_PrivateIP > /tmp/skynet/malwarelist.txt
			cd "$cwd" || exit 1
			Display_Result
			Display_Message "[i] Filtering IPv4 Addresses"
			sed -i '\~comment \"BanMalware: ~d' "$skynetipset"
			awk '/^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(32))?)([[:space:]]|$)/{printf "add Skynet-Blacklist %s comment \"BanMalware: %s\"\n", $1, $2 }' /tmp/skynet/malwarelist.txt >> "$skynetipset"
			Display_Result
			Display_Message "[i] Filtering IPv4 Ranges"
			awk '/^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-1])){1})([[:space:]]|$)/{printf "add Skynet-BlockedRanges %s comment \"BanMalware: %s\"\n", $1, $2 }' /tmp/skynet/malwarelist.txt >> "$skynetipset"
			Display_Result
			Display_Message "[i] Applying New Blacklist"
			ipset flush Skynet-Blacklist; ipset flush Skynet-BlockedRanges
			ipset restore -! -f "$skynetipset" >/dev/null 2>&1
			Display_Result
			Display_Message "[i] Refreshing AiProtect Bans"
			Spinner_End
			Refresh_AiProtect
			Spinner_Start
			Display_Result
			Display_Message "[i] Saving Changes"
			Save_IPSets
			Display_Result
			unset "forcebanmalwareupdate"
			echo
			echo "[i] For Whitelisting Assistance -"
			echo "[i] https://www.snbforums.com/threads/release-skynet-router-firewall-security-enhancements.16798/#post-115872"
		fi
		Clean_Temp
	;;

	whitelist)
		Check_Lock "$@"
		if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
		Purge_Logs
		case "$2" in
			ip|range)
				if ! echo "$3" | Is_IPRange; then echo "[*] $3 Is Not A Valid IP/Range"; echo; exit 2; fi
				if [ "${#4}" -gt "242" ]; then echo "[*] $4 Is Not A Valid Comment. 242 Chars Max"; echo; exit 2; fi
				echo "[i] Whitelisting $3"
				desc="$4"
				if [ -z "$4" ]; then
					desc="$(date +"%b %d %T")"
				fi
				ipset -A Skynet-Whitelist "$3" comment "ManualWlist: $desc" && sed -i "\\~=$3 ~d" "$skynetlog" "$skynetevents" && echo "$(date +"%b %d %T") Skynet: [Manual Whitelist] TYPE=Single SRC=$3 COMMENT=$desc " >> "$skynetevents"
				ipset -q -D Skynet-Blacklist "$3"
				ipset -q -D Skynet-BlockedRanges "$3"
			;;
			domain)
				if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
				if [ -z "$3" ]; then echo "[*] Domain Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				domain="$(echo "$3" | Strip_Domain)"
				echo "[i] Adding $domain To Whitelist"
				for ip in $(Domain_Lookup "$domain"); do
					echo "[i] Whitelisting $ip"
					ipset -A Skynet-Whitelist "$ip" comment "ManualWlistD: $domain" && sed -i "\\~=$ip ~d" "$skynetlog" "$skynetevents" && echo "$(date +"%b %d %T") Skynet: [Manual Whitelist] TYPE=Domain SRC=$ip Host=$domain " >> "$skynetevents"
					ipset -q -D Skynet-Blacklist "$ip"
				done
				if [ "$?" = "1" ]; then echo "$domain" >> /jffs/addons/shared-whitelists/shared-Skynet2-whitelist; fi
			;;
			vpn)
				echo "[i] Updating VPN Whitelist"
				Whitelist_VPN
			;;
			asn)
				if [ -z "$3" ]; then echo "[*] ASN Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				if ! echo "$3" | Is_ASN; then echo "[*] $3 Is Not A Valid ASN"; echo; exit 2; fi
				asnlist="$(echo "$3" | awk '{print toupper($0)}')"
				echo "[i] Adding $asnlist To Whitelist"
				curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors "https://asn.ipinfo.app/api/text/list/$asnlist" | awk -v asn="$asnlist" '/^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)([[:space:]]|$)/{printf "add Skynet-Whitelist %s comment \"ASN: %s \"\n", $1, asn }'| awk '!x[$0]++' | ipset restore -!
			;;
			remove)
				case "$3" in
					entry)
						if ! echo "$4" | Is_IPRange; then echo "[*] $4 Is Not A Valid IP/Range"; echo; exit 2; fi
						echo "[i] Removing $4 From Whitelist"
						ipset -D Skynet-Whitelist "$4"
						sed -i "\\~=$4 ~d" "$skynetlog" "$skynetevents"
					;;
					comment)
						if [ -z "$4" ]; then echo "[*] Comment Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
						echo "[i] Removing All Entries With Comment Matching \"$4\" From Whitelist"
						sed "\\~add Skynet-Whitelist ~!d;\\~$4~!d;s~ comment.*~~;s~add~del~g" "$skynetipset" | ipset restore -!
						echo "[i] Removing Old Logs - This May Take Awhile (To Skip Type ctrl+c)"
						trap 'break; echo' 2
						sed "\\~add Skynet-Whitelist ~!d;\\~$4~!d" "$skynetipset" | cut -d' ' -f3 | while IFS= read -r "ip"; do
							sed -i "\\~=$ip ~d" "$skynetlog" "$skynetevents"
						done
					;;
					all)
						if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
						echo "[i] Flushing Whitelist"
						ipset flush Skynet-Whitelist
						echo "[i] Adding Default Entries"
						true > "$skynetipset"
						sed -i '\~Manual Whitelist~d' "$skynetevents"
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
				if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
				echo "[i] Refreshing Shared Whitelist Files"
				Whitelist_Extra
				Whitelist_CDN
				Whitelist_VPN
				Whitelist_Shared
				Refresh_MWhitelist
			;;
			view)
				case "$3" in
					ips)
						sed '\~add Skynet-Whitelist ~!d;\~ManualWlist:~!d;s~add Skynet-Whitelist ~~' "$skynetipset"
					;;
					domains)
						sed '\~add Skynet-Whitelist ~!d;\~ManualWlistD:~!d;s~add Skynet-Whitelist ~~' "$skynetipset"
					;;
					imported)
						sed '\~add Skynet-Whitelist ~!d;\~Imported:~!d;s~add Skynet-Whitelist ~~' "$skynetipset"
					;;
					*)
						sed '\~add Skynet-Whitelist ~!d;s~add Skynet-Whitelist ~~' "$skynetipset"
					;;
				esac
				echo
			;;
			*)
				echo "Command Not Recognized, Please Try Again"
				echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
				echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
				echo; exit 2
			;;
		esac
		echo "[i] Saving Changes"
		Save_IPSets
	;;

	import)
		Spinner_Start
		case "$2" in
			blacklist)
				Check_Lock "$@"
				if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
				if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
				Purge_Logs
				echo "[i] This Function Extracts All IPs And Adds Them ALL To Blacklist"
				if [ -f "$3" ]; then
					echo "[i] Local Custom List Detected: $3"
					grep -E '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)$' "$3" > /tmp/skynet/iplist-unfiltered.txt
				elif [ -n "$3" ]; then
					echo "[i] Remote Custom List Detected: $3"
					curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors "$3" | dos2unix | grep -E '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)$' > /tmp/skynet/iplist-unfiltered.txt || { echo "[*] 404 Error Detected - Stopping Import"; rm -rf /tmp/skynet/iplist-unfiltered.txt; echo; exit 1; }
				else
					echo "[*] URL/File Field Can't Be Empty - Please Try Again"
					echo; exit 2
				fi
				dos2unix /tmp/skynet/iplist-unfiltered.txt
				if ! Is_IPRange < /tmp/skynet/iplist-unfiltered.txt; then echo "[*] No Content Detected - Stopping Import"; rm -rf /tmp/skynet/iplist-unfiltered.txt; echo; exit 1; fi
				echo "[i] Processing List"
				if [ -n "$4" ] && [ "${#4}" -le "245" ]; then
					Filter_PrivateIP < /tmp/skynet/iplist-unfiltered.txt | awk -v desc="Imported: $4" '/^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(32))?)$/{printf "add Skynet-Blacklist %s comment \"%s\"\n", $1, desc }' > /tmp/skynet/iplist-filtered.txt
					Filter_PrivateIP < /tmp/skynet/iplist-unfiltered.txt | awk -v desc="Imported: $4" '/^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-1])){1})$/{printf "add Skynet-BlockedRanges %s comment \"%s\"\n", $1, desc }' >> /tmp/skynet/iplist-filtered.txt
				else
					imptime="$(date +"%b %d %T")"
					Filter_PrivateIP < /tmp/skynet/iplist-unfiltered.txt | awk -v desc="Imported: $imptime" '/^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(32))?)$/{printf "add Skynet-Blacklist %s comment \"%s\"\n", $1, desc }' > /tmp/skynet/iplist-filtered.txt
					Filter_PrivateIP < /tmp/skynet/iplist-unfiltered.txt | awk -v desc="Imported: $imptime" '/^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-1])){1})$/{printf "add Skynet-BlockedRanges %s comment \"%s\"\n", $1, desc }' >> /tmp/skynet/iplist-filtered.txt
				fi
				echo "[i] Adding IPs To Blacklist"
				ipset restore -! -f "/tmp/skynet/iplist-filtered.txt"
				rm -rf /tmp/skynet/iplist-unfiltered.txt /tmp/skynet/iplist-filtered.txt
				echo "[i] Saving Changes"
				Save_IPSets
			;;
			whitelist)
				Check_Lock "$@"
				if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
				if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
				Purge_Logs
				echo "[i] This Function Extracts All IPs And Adds Them ALL To Whitelist"
				if [ -f "$3" ]; then
					echo "[i] Local Custom List Detected: $3"
					grep -E '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)$' "$3" > /tmp/skynet/iplist-unfiltered.txt
				elif [ -n "$3" ]; then
					echo "[i] Remote Custom List Detected: $3"
					curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors "$3" | dos2unix | grep -E '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)$' > /tmp/skynet/iplist-unfiltered.txt || { echo "[*] 404 Error Detected - Stopping Import"; rm -rf /tmp/skynet/iplist-unfiltered.txt; echo; exit 1; }
				else
					echo "[*] URL/File Field Can't Be Empty - Please Try Again"
					echo; exit 2
				fi
				dos2unix /tmp/skynet/iplist-unfiltered.txt
				if ! Is_IPRange < /tmp/skynet/iplist-unfiltered.txt; then echo "[*] No Content Detected - Stopping Import"; rm -rf /tmp/skynet/iplist-unfiltered.txt; echo; exit 1; fi
				echo "[i] Processing List"
				if [ -n "$4" ] && [ "${#4}" -le "245" ]; then
					Filter_PrivateIP < /tmp/skynet/iplist-unfiltered.txt | awk -v desc="Imported: $4" '{printf "add Skynet-Whitelist %s comment \"%s\"\n", $1, desc }' > /tmp/skynet/iplist-filtered.txt
				else
					imptime="$(date +"%b %d %T")"
					Filter_PrivateIP < /tmp/skynet/iplist-unfiltered.txt | awk -v desc="Imported: $imptime" '{printf "add Skynet-Whitelist %s comment \"%s\"\n", $1, desc }' > /tmp/skynet/iplist-filtered.txt
				fi
				echo "[i] Adding IPs To Whitelist"
				ipset restore -! -f "/tmp/skynet/iplist-filtered.txt"
				rm -rf /tmp/skynet/iplist-unfiltered.txt /tmp/skynet/iplist-filtered.txt
				echo "[i] Saving Changes"
				Save_IPSets
			;;
			*)
				echo "Command Not Recognized, Please Try Again"
				echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
				echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
				echo; exit 2
			;;
		esac
	;;

	deport)
		Spinner_Start
		case "$2" in
			blacklist)
				Check_Lock "$@"
				if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
				if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
				Purge_Logs
				echo "[i] This Function Extracts All IPs And Removes Them ALL From Blacklist"
				if [ -f "$3" ]; then
					echo "[i] Local Custom List Detected: $3"
					grep -E '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)$' "$3" > /tmp/skynet/iplist-unfiltered.txt
				elif [ -n "$3" ]; then
					echo "[i] Remote Custom List Detected: $3"
					curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors "$3" | dos2unix | grep -E '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)$' > /tmp/skynet/iplist-unfiltered.txt || { echo "[*] 404 Error Detected - Stopping Import"; rm -rf /tmp/skynet/iplist-unfiltered.txt; echo; exit 1; }
				else
					echo "[*] URL/File Field Can't Be Empty - Please Try Again"
					echo; exit 2
				fi
				dos2unix /tmp/skynet/iplist-unfiltered.txt
				if ! Is_IPRange < /tmp/skynet/iplist-unfiltered.txt; then echo "[*] No Content Detected - Stopping Deport"; rm -rf /tmp/skynet/iplist-unfiltered.txt; echo; exit 1; fi
				echo "[i] Processing IPv4 Addresses"
				Filter_PrivateIP < /tmp/skynet/iplist-unfiltered.txt | awk '/^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(32))?)$/{printf "del Skynet-Blacklist %s\n", $1}' > /tmp/skynet/iplist-filtered.txt
				echo "[i] Processing IPv4 Ranges"
				Filter_PrivateIP < /tmp/skynet/iplist-unfiltered.txt | awk '/^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-1])){1})$/{printf "del Skynet-BlockedRanges %s\n", $1}' >> /tmp/skynet/iplist-filtered.txt
				echo "[i] Removing IPs From Blacklist"
				ipset restore -! -f "/tmp/skynet/iplist-filtered.txt"
				rm -rf /tmp/skynet/iplist-unfiltered.txt /tmp/skynet/iplist-filtered.txt
				echo "[i] Saving Changes"
				Save_IPSets
			;;
			whitelist)
				Check_Lock "$@"
				if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
				if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
				Purge_Logs
				echo "[i] This Function Extracts All IPs And Removes Them ALL From Whitelist"
				if [ -f "$3" ]; then
					echo "[i] Local Custom List Detected: $3"
					grep -E '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)$' "$3" > /tmp/skynet/iplist-unfiltered.txt
				elif [ -n "$3" ]; then
					echo "[i] Remote Custom List Detected: $3"
					curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors "$3" | dos2unix | grep -E '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)$' > /tmp/skynet/iplist-unfiltered.txt || { echo "[*] 404 Error Detected - Stopping Import"; rm -rf /tmp/skynet/iplist-unfiltered.txt; echo; exit 1; }
				else
					echo "[*] URL/File Field Can't Be Empty - Please Try Again"
					echo; exit 2
				fi
				dos2unix /tmp/skynet/iplist-unfiltered.txt
				if ! Is_IPRange < /tmp/skynet/iplist-unfiltered.txt; then echo "[*] No Content Detected - Stopping Deport"; rm -rf /tmp/skynet/iplist-unfiltered.txt; echo; exit 1; fi
				echo "[i] Processing IPv4 Addresses"
				Filter_PrivateIP < /tmp/skynet/iplist-unfiltered.txt | awk '{printf "del Skynet-Whitelist %s\n", $1}' > /tmp/skynet/iplist-filtered.txt
				echo "[i] Removing IPs From Whitelist"
				ipset restore -! -f "/tmp/skynet/iplist-filtered.txt"
				rm -rf /tmp/skynet/iplist-unfiltered.txt /tmp/skynet/iplist-filtered.txt
				echo "[i] Saving Changes"
				Save_IPSets
			;;
			*)
				echo "Command Not Recognized, Please Try Again"
				echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
				echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
				echo; exit 2
			;;
		esac
	;;

	save)
		Check_Lock "$@"
		if ! Check_IPSets || ! Check_IPTables; then
			logger -st Skynet "[*] Rule Integrity Violation - Restarting Firewall [ ${fail}]"
			unset fail
			restartfirewall="1"
			nolog="2"
		else
			Unban_PrivateIP
			Purge_Logs
			echo "[i] Saving Changes"
			Save_IPSets
			Check_Security
		fi
	;;

	start)
		Check_Lock "$@"
		logger -t Skynet "[i] Startup Initiated... ( $(echo "$@" | sed 's~start ~~g') )"; echo "[i] Startup Initiated... ( $(echo "$@" | sed 's~start ~~g') )"
		Unload_Cron "all"
		Check_Settings
		Check_Files "verify"
		Clean_Temp
		if ! Check_Connection; then logger -st Skynet "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
		Load_Cron "save"
		modprobe xt_set
		if [ -f "$skynetipset" ]; then ipset restore -! -f "$skynetipset"; else logger -st Skynet "[i] Setting Up Skynet"; touch "$skynetipset"; fi
		if ! ipset -L -n Skynet-Whitelist >/dev/null 2>&1; then ipset -q create Skynet-Whitelist hash:net hashsize 64 maxelem "$((65536 * 6))" comment; fi
		if ! ipset -L -n Skynet-WhitelistDomains >/dev/null 2>&1; then ipset -q create Skynet-WhitelistDomains hash:ip hashsize 64 maxelem "$((65536 * 8))" comment timeout 86400; fi
		if ! ipset -L -n Skynet-Blacklist >/dev/null 2>&1; then ipset -q create Skynet-Blacklist hash:ip hashsize 64 maxelem "$((65536 * 8))" comment; fi
		if ! ipset -L -n Skynet-BlockedRanges >/dev/null 2>&1; then ipset -q create Skynet-BlockedRanges hash:net hashsize 64 maxelem "$((65536 * 6))" comment; fi
		if ! ipset -L -n Skynet-Master >/dev/null 2>&1; then ipset -q create Skynet-Master list:set; ipset -q -A Skynet-Master Skynet-Blacklist; ipset -q -A Skynet-Master Skynet-BlockedRanges; fi
		if ! ipset -L -n Skynet-MasterWL >/dev/null 2>&1; then ipset -q create Skynet-MasterWL list:set; ipset -q -A Skynet-MasterWL Skynet-Whitelist; ipset -q -A Skynet-MasterWL Skynet-WhitelistDomains; fi
		if ! ipset -L -n Skynet-IOT >/dev/null 2>&1; then ipset -q create Skynet-IOT hash:net hashsize 64 maxelem "$((65536 * 6))" comment; fi
		Unban_PrivateIP
		Purge_Logs "all"
		Whitelist_Extra
		Whitelist_CDN
		sed '\~add Skynet-Whitelist ~!d;\~nvram: ~!d;s~ comment.*~~;s~add~del~g' "$skynetipset" | ipset restore -!
		Whitelist_VPN
		Whitelist_Shared
		Refresh_MWhitelist
		Refresh_MBans
		Refresh_AiProtect
		Check_Security
		echo "[i] Saving Changes"
		Save_IPSets
		Generate_Stats
		Install_WebUI_Page
		while [ "$(($(date +%s) - stime))" -lt "20" ]; do
			sleep 1
		done
		Unload_IPTables
		Unload_IOTTables
		Unload_LogIPTables
		Load_IPTables
		Load_IOTTables
		Load_LogIPTables
		sed -i '\~DROP IN=~d' "$syslog1loc" "$syslogloc" 2>/dev/null
		if [ "$forcebanmalwareupdate" = "true" ]; then Write_Config; rm -rf "/tmp/skynet.lock"; exec "$0" banmalware; fi
	;;

	restart)
		Check_Lock "$@"
		Purge_Logs
		echo "[i] Saving Changes"
		Save_IPSets
		echo "[i] Unloading Skynet Components"
		Unload_Cron "all"
		Unload_IPTables
		Unload_IOTTables
		Unload_LogIPTables
		Unload_IPSets
		Uninstall_WebUI_Page
		iptables -t raw -F
		logger -t Skynet "[i] Restarting Firewall Service"; echo "[i] Restarting Firewall Service"
		restartfirewall="1"
		nolog="2"
	;;

	disable)
		Check_Lock "$@"
		echo "[i] Saving Changes"
		Save_IPSets
		echo "[i] Unloading Skynet Components"
		Unload_Cron "all"
		Unload_IPTables
		Unload_IOTTables
		Unload_LogIPTables
		Unload_IPSets
		Uninstall_WebUI_Page
		logger -t Skynet "[i] Skynet Disabled"; echo "[i] Skynet Disabled"
		Purge_Logs "all"
		nolog="2"
	;;

	update)
		Check_Lock "$@"
		if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
		remotedir="https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master"
		remotever="$(curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors "${remotedir}/firewall.sh" | Filter_Version)"
		localmd5="$(md5sum "$0" | awk '{print $1}')"
		remotemd5="$(curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors "${remotedir}/firewall.sh" | md5sum | awk '{print $1}')"
		if [ "$localmd5" = "$remotemd5" ] && [ "$2" != "-f" ]; then
			logger -t Skynet "[i] Skynet Up To Date - $localver (${localmd5})"; echo "[i] Skynet Up To Date - $localver (${localmd5})"
			nolog="2"
		elif [ "$localmd5" != "$remotemd5" ] && [ "$2" = "check" ]; then
			logger -t Skynet "[i] Skynet Update Detected - $remotever (${remotemd5})"; echo "[i] Skynet Update Detected - $remotever (${remotemd5})"
			nolog="2"
		elif [ "$2" = "-f" ]; then
			echo "[i] Forcing Update"
		fi
		if [ "$localmd5" != "$remotemd5" ] || [ "$2" = "-f" ] && [ "$nolog" != "2" ]; then
			logger -t Skynet "[i] New Version Detected - Updating To $remotever (${remotemd5})"; echo "[i] New Version Detected - Updating To $remotever (${remotemd5})"
			echo "[i] Saving Changes"
			Save_IPSets
			echo "[i] Unloading Skynet Components"
			Unload_Cron "all"
			Unload_IPTables
			Unload_IOTTables
			Unload_LogIPTables
			Unload_IPSets
			iptables -t raw -F
			Uninstall_WebUI_Page
			mkdir -p "${skynetloc}/webui"
			Download_File "webui/chart.js" "${skynetloc}/webui/chart.js" "$2"
			Download_File "webui/chartjs-plugin-zoom.js" "${skynetloc}/webui/chartjs-plugin-zoom.js" "$2"
			Download_File "webui/hammerjs.js" "${skynetloc}/webui/hammerjs.js" "$2"
			Download_File "webui/skynet.asp" "${skynetloc}/webui/skynet.asp" "$2"
			Download_File "firewall.sh" "$0" "$2"
			logger -t Skynet "[i] Restarting Firewall Service"; echo "[i] Restarting Firewall Service"
			service restart_firewall
			echo; exit 0
		fi
	;;

	settings)
		case "$2" in
			autoupdate)
				case "$3" in
					enable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						autoupdate="enabled"
						Unload_Cron "checkupdate"
						Load_Cron "autoupdate"
						echo "[i] Skynet Auto-Updates Enabled"
					;;
					disable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						autoupdate="disabled"
						Unload_Cron "autoupdate"
						Load_Cron "checkupdate"
						echo "[i] Skynet Auto-Updates Disabled"
					;;
					*)
						echo "Command Not Recognized, Please Try Again"
						echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
						echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
						echo; exit 2
					;;
				esac
			;;
			banmalware)
				case "$3" in
					daily)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						banmalwareupdate="daily"
						forcebanmalwareupdate="true"
						Unload_Cron "banmalware"
						Load_Cron "banmalwaredaily"
						echo "[i] Daily Malware Blacklist Updates Enabled"
					;;
					weekly)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						banmalwareupdate="weekly"
						forcebanmalwareupdate="true"
						Unload_Cron "banmalware"
						Load_Cron "banmalwareweekly"
						echo "[i] Weekly Malware Blacklist Updates Enabled"
					;;
					disable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						banmalwareupdate="disabled"
						Unload_Cron "banmalware"
						echo "[i] Malware Blacklist Updates Disabled"
					;;
					*)
						echo "Command Not Recognized, Please Try Again"
						echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
						echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
						echo; exit 2
					;;
				esac
			;;
			logmode)
				case "$3" in
					enable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						logmode="enabled"
						Unload_LogIPTables
						Load_LogIPTables
						echo "[i] Logging Enabled"
					;;
					disable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						logmode="disabled"
						Unload_LogIPTables
						echo "[i] Logging Disabled"
					;;
					*)
						echo "Command Not Recognized, Please Try Again"
						echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
						echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
						echo; exit 2
					;;
				esac
			;;
			filter)
				case "$3" in
					all)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						filtertraffic="all"
						Unload_IPTables
						Unload_IOTTables
						Unload_LogIPTables
						Load_IPTables
						Load_IOTTables
						Load_LogIPTables
						echo "[i] Inbound & Outbound Filtering Enabled"

					;;
					inbound)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						filtertraffic="inbound"
						Unload_IPTables
						Unload_IOTTables
						Unload_LogIPTables
						Load_IPTables
						Load_IOTTables
						Load_LogIPTables
						echo "[i] Inbound Filtering Enabled"
					;;
					outbound)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						filtertraffic="outbound"
						Unload_IPTables
						Unload_IOTTables
						Unload_LogIPTables
						Load_IPTables
						Load_IOTTables
						Load_LogIPTables
						echo "[i] Outbound Filtering Enabled"
					;;
					*)
						echo "Command Not Recognized, Please Try Again"
						echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
						echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
						echo; exit 2
					;;
				esac
			;;
			unbanprivate)
				case "$3" in
					enable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						unbanprivateip="enabled"
						echo "[i] Unban Private IP Enabled"

					;;
					disable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						unbanprivateip="disabled"
						echo "[i] Unban Private IP Disabled"
					;;
					*)
						echo "Command Not Recognized, Please Try Again"
						echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
						echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
						echo; exit 2
					;;
				esac
			;;
			loginvalid)
				case "$3" in
					enable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						loginvalid="enabled"
						Unload_LogIPTables
						Load_LogIPTables
						echo "[i] Invalid IP Logging Enabled"
					;;
					disable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						loginvalid="disabled"
						Unload_LogIPTables
						Load_LogIPTables
						echo "[i] Invalid IP Logging Disabled"
					;;
					*)
						echo "Command Not Recognized, Please Try Again"
						echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
						echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
						echo; exit 2
					;;
				esac
			;;
			banaiprotect)
				case "$3" in
					enable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
						Purge_Logs
						banaiprotect="enabled"
						Refresh_AiProtect
						echo "[i] Import AiProtect Data Enabled"
					;;
					disable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						banaiprotect="disabled"
						sed '\~add Skynet-Blacklist ~!d;\~BanAiProtect~!d;s~ comment.*~~;s~add~del~g' "$skynetipset" | ipset restore -!
						echo "[i] Import AiProtect Data Disabled"
					;;
					*)
						echo "Command Not Recognized, Please Try Again"
						echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
						echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
						echo; exit 2
					;;
				esac
				echo "[i] Saving Changes"
				Save_IPSets
			;;
			securemode)
				case "$3" in
					enable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						securemode="enabled"
						Check_Security
						echo "[i] Secure Mode Enabled"
					;;
					disable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						securemode="disabled"
						echo "[i] Secure Mode Disabled"
					;;
					*)
						echo "Command Not Recognized, Please Try Again"
						echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
						echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
						echo; exit 2
					;;
				esac
			;;
			syslog)
				Check_Lock "$@"
				if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
				if [ -z "$3" ]; then echo "[*] Sysloc Location Not Specified - Exiting"; echo; exit 1; fi
				case "$3" in
					default)
						syslogloc="/tmp/syslog.log"
					;;
					*)
						syslogloc="$3"
					;;
				esac
				echo "[i] Syslog Location Set To $syslogloc"
			;;
			syslog1)
				Check_Lock "$@"
				if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
				if [ -z "$3" ]; then echo "[*] Syslog-1 Location Not Specified - Exiting"; echo; exit 1; fi
				case "$3" in
					default)
						syslog1loc="/tmp/syslog.log-1"
					;;
					*)
						syslog1loc="$3"
					;;
				esac
				echo "[i] Syslog-1 Location Set To $syslog1loc"
			;;
			iot)
				Check_Lock "$@"
				if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
				if [ -z "$3" ]; then echo "[*] Option Not Specified - Exiting"; echo; exit 1; fi
				case "$3" in
					unban)
						if [ -z "$4" ]; then echo "[*] Device(s) Not Specified - Exiting"; echo; exit 1; fi
						oldiotblocked="$(ipset -L -t Skynet-IOT | tail -1 | awk '{print $4}')"
						if echo "$4" | grep -q ","; then
							for ip in $(echo "$4" | sed 's~,~ ~g'); do
									if ! echo "$ip" | Is_IPRange; then
										echo "[*] $ip Is Not A Valid IP/Range"
										echo
									else
										ipset -D Skynet-IOT "$ip"
									fi
							done
						else
							if ! echo "$4" | Is_IPRange; then
								echo "[*] $4 Is Not A Valid IP/Range"
								echo
							else
								ipset -D Skynet-IOT "$4"
								sed -i "\\~BLOCKED - IOT.*=$4 ~d" "$skynetlog"
							fi
						fi
						if [ "$(ipset -L -t Skynet-IOT | tail -1 | awk '{print $4}')" -gt "0" ]; then
							iotblocked="enabled"
							if [ "$oldiotblocked" = "0" ]; then
								Load_IOTTables
								Unload_LogIPTables
								Load_LogIPTables
							fi
						else
							Unload_IOTTables
							Unload_LogIPTables
							iotblocked="disabled"
							Load_LogIPTables
						fi
					;;
					ban)
						if [ -z "$4" ]; then echo "[*] Device(s) Not Specified - Exiting"; echo; exit 1; fi
						oldiotblocked="$(ipset -L -t Skynet-IOT | tail -1 | awk '{print $4}')"
						desc="$(date +"%b %d %T")"
						if echo "$4" | grep -q ","; then
							for ip in $(echo "$4" | sed 's~,~ ~g'); do
									if ! echo "$ip" | Is_IPRange; then
										echo "[*] $ip Is Not A Valid IP/Range"
										echo
									else
										ipset -A Skynet-IOT "$ip" comment "IOTBan: $desc"
									fi
							done
						else
							if ! echo "$4" | Is_IPRange; then
								echo "[*] $4 Is Not A Valid IP/Range"
								echo
							else
								ipset -A Skynet-IOT "$4" comment "IOTBan: $desc"
							fi
						fi
						if [ "$(ipset -L -t Skynet-IOT | tail -1 | awk '{print $4}')" -gt "0" ]; then
							iotblocked="enabled"
							if [ "$oldiotblocked" = "0" ]; then
								Load_IOTTables
								Unload_LogIPTables
								Load_LogIPTables
							fi
						else
							Unload_IOTTables
							Unload_LogIPTables
							iotblocked="disabled"
							Load_LogIPTables
						fi
					;;
					view)
						Display_Header "6"
						ip neigh | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3} ' | sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 | while IFS= read -r "ip"; do
							ipaddr="$(echo "$ip" | awk '{print $1}')"
							macaddr="$(echo "$ip" | awk '{print $5}')"
							Get_LocalName
							state="$(echo "$ip" | awk '{print $6}')"
							if ! echo "$macaddr" | Is_MAC; then
								macaddr="Unknown"
								state="$(Red Offline)"
							fi
							if ipset test Skynet-IOT "$ipaddr" >/dev/null 2>&1; then
								state="$(Ylow Blocked)"
							else
								state="$(Grn Unblocked)"
							fi
							printf '%-40s | %-16s | %-20s | %-15s\n' "$localname" "$ipaddr" "$macaddr" "$state"
						done
						echo;echo
						echo "Allowed Traffic Protocols: $(Grn "$iotproto")"
						if [ -z "$iotports" ]; then
							echo "Allowed Ports: $(Grn 123)"
						else
							echo "Allowed Ports: $(Grn "123,${iotports}")"
						fi
					;;
					ports)
						if [ -z "$4" ]; then echo "[*] Ports(s) Not Specified - Exiting"; echo; exit 1; fi
						if [ "$4" != "reset" ]; then
							if echo "$4" | grep -q ","; then
								for port in $(echo "$4" | sed 's~,~ ~g'); do
										if ! echo "$port" | Is_Port; then
											echo "[*] $port Is Not A Valid Port - Exiting"
											echo
											exit 1
										fi
								done
							else
								if ! echo "$4" | Is_Port; then
									echo "[*] $4 Is Not A Valid Port"
									echo
									exit 1
								fi
							fi
						fi
						Unload_IOTTables
						Unload_LogIPTables
						if [ "$4" != "reset" ]; then
							iotports="$4"
						else
							iotports=""
						fi
						Load_IOTTables
						Load_LogIPTables
					;;
					proto)
					if [ -z "$4" ]; then echo "[*] Proto Not Specified - Exiting"; echo; exit 1; fi
					case "$4" in
						udp)
							Check_Lock "$@"
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							Purge_Logs
							Unload_IOTTables
							iotproto="udp"
							Load_IOTTables
							echo "[i] Allowing UDP Proto"
						;;
						tcp)
							Check_Lock "$@"
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							Purge_Logs
							Unload_IOTTables
							iotproto="tcp"
							Load_IOTTables
							echo "[i] Allowing TCP Proto"
						;;
						all)
							Check_Lock "$@"
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							Purge_Logs
							Unload_IOTTables
							iotproto="all"
							Load_IOTTables
							echo "[i] Allowing UDP & TCP Proto"
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
						echo "Command Not Recognized, Please Try Again"
						echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
						echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
						echo; exit 2
					;;
				esac
				if [ "$3" != "view" ]; then
					if [ "$iotblocked" = "enabled" ]; then
						echo "[i] IOT Blocking List Updated"
					else
						echo "[i] IOT Blocking List Cleared"
					fi
					echo "[i] Saving Changes"
					Save_IPSets
				fi
			;;
			iotlogging)
				case "$3" in
					enable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						iotlogging="enabled"
						Unload_LogIPTables
						Load_LogIPTables
						echo "[i] IOT Logging For Protected Devices Enabled"
					;;
					disable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						iotlogging="disabled"
						Unload_LogIPTables
						Load_LogIPTables
						echo "[i] IOT Logging For Protected Devices Disabled"
					;;
					*)
						echo "Command Not Recognized, Please Try Again"
						echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
						echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
						echo; exit 2
					;;
				esac
			;;
			lookupcountry)
				case "$3" in
					enable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						lookupcountry="enabled"
						echo "[i] Country Lookups For Stat Data Enabled"
					;;
					disable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						lookupcountry="disabled"
						echo "[i] Country Lookups For Stat Data Disabled"
					;;
					*)
						echo "Command Not Recognized, Please Try Again"
						echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
						echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
						echo; exit 2
					;;
				esac
			;;
			cdnwhitelist)
				case "$3" in
					enable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						cdnwhitelist="enabled"
						Whitelist_CDN
						echo "[i] CDN Whitelisting Enabled"
					;;
					disable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						cdnwhitelist="disabled"
						Whitelist_CDN
						echo "[i] CDN Whitelisting Disabled"
					;;
					*)
						echo "Command Not Recognized, Please Try Again"
						echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
						echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
						echo; exit 2
					;;
				esac
			;;
			webui)
				case "$3" in
					enable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						if nvram get rc_support | grep -qF "am_addons"; then
							displaywebui="enabled"
							Install_WebUI_Page
							echo "[i] WebUI Enabled"
							echo "[i] Generating Stats"
							Generate_Stats
						else
							echo "[*] Firmware Version Not Supported - Please Update To Use This Feature"
						fi
					;;
					disable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						Uninstall_WebUI_Page
						displaywebui="disabled"
						echo "[i] WebUI Disabled"
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
				echo "Command Not Recognized, Please Try Again"
				echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
				echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
				echo; exit 2
			;;
		esac
	;;

	debug)
		case "$2" in
			watch)
				Spinner_Start
				if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
				if [ "$logmode" = "disabled" ]; then echo "[*] Logging Is Disabled - Exiting!"; echo; exit 2; fi
				trap 'echo;echo; echo "[*] Stopping Log Monitoring"; Purge_Logs; Spinner_End' 2
				echo "[i] Watching Syslog For Log Entries (ctrl +c) To Stop"
				echo
				Purge_Logs
				case "$3" in
					ip)
						if ! echo "$4" | Is_IP; then echo "[*] $4 Is Not A Valid IP"; echo; exit 2; fi
						echo "[i] Filtering Entries Involving IP $4"
						echo
						tail -F "$syslogloc" | while read -r logoutput; do
							if echo "$logoutput" | grep -qE "INVALID.*=$4 "; then
								Blue "$logoutput"
								if [ "$extendedstats" = "enabled" ]; then
									domainlist="$(grep -E "reply.* is $(echo "$logoutput" | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | sed 's/.$//' | sed 's~\.~\\.~g')" /opt/var/log/dnsmasq* | awk '{print $(NF-2)}' | Strip_Domain | Filter_OutIP | xargs)"
									[ -n "$domainlist" ] && Blue "Associated Domain(s) - [$domainlist]"
								fi
							elif echo "$logoutput" | grep -qE "INBOUND.*=$4 "; then
								Ylow "$logoutput"
								if [ "$extendedstats" = "enabled" ]; then
									domainlist="$(grep -E "reply.* is $(echo "$logoutput" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | sed 's/.$//' | sed 's~\.~\\.~g')" /opt/var/log/dnsmasq* | awk '{print $(NF-2)}' | Strip_Domain | Filter_OutIP | xargs)"
									[ -n "$domainlist" ] && Red "Associated Domain(s) - [$domainlist]"
								fi
							elif echo "$logoutput" | grep -qE "OUTBOUND.*=$4 "; then
								Red "$logoutput"
								if [ "$extendedstats" = "enabled" ]; then
									domainlist="$(grep -E "reply.* is $(echo "$logoutput" | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | sed 's/.$//' | sed 's~\.~\\.~g')" /opt/var/log/dnsmasq* | awk '{print $(NF-2)}' | Strip_Domain | Filter_OutIP | xargs)"
									[ -n "$domainlist" ] && Red "Associated Domain(s) - [$domainlist]"
								fi
							elif echo "$logoutput" | grep -qE "IOT.*=$4 "; then
								Red "$logoutput"
								if [ "$extendedstats" = "enabled" ]; then
									domainlist="$(grep -E "reply.* is $(echo "$logoutput" | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | sed 's/.$//' | sed 's~\.~\\.~g')" /opt/var/log/dnsmasq* | awk '{print $(NF-2)}' | Strip_Domain | Filter_OutIP | xargs)"
									[ -n "$domainlist" ] && Red "Associated Domain(s) - [$domainlist]"
								fi
							fi
						done
					;;
					port)
						if ! echo "$4" | Is_Port || [ "$4" -gt "65535" ]; then echo "[*] $4 Is Not A Valid Port"; echo; exit 2; fi
						echo "[i] Filtering Entries Involving Port $4"
						echo
						tail -F "$syslogloc" | while read -r logoutput; do
							if echo "$logoutput" | grep -qE "INAVLID.*PT=$4 "; then
								Blue "$logoutput"
								if [ "$extendedstats" = "enabled" ]; then
									domainlist="$(grep -E "reply.* is $(echo "$logoutput" | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | sed 's/.$//' | sed 's~\.~\\.~g')" /opt/var/log/dnsmasq* | awk '{print $(NF-2)}' | Strip_Domain | Filter_OutIP | xargs)"
									[ -n "$domainlist" ] && Blue "Associated Domain(s) - [$domainlist]"
								fi
							elif echo "$logoutput" | grep -qE "INBOUND.*PT=$4 "; then
								Ylow "$logoutput"
								if [ "$extendedstats" = "enabled" ]; then
									domainlist="$(grep -E "reply.* is $(echo "$logoutput" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | sed 's/.$//' | sed 's~\.~\\.~g')" /opt/var/log/dnsmasq* | awk '{print $(NF-2)}' | Strip_Domain | Filter_OutIP | xargs)"
									[ -n "$domainlist" ] && Red "Associated Domain(s) - [$domainlist]"
								fi
							elif echo "$logoutput" | grep -qE "OUTBOUND.*PT=$4 "; then
								Red "$logoutput"
								if [ "$extendedstats" = "enabled" ]; then
									domainlist="$(grep -E "reply.* is $(echo "$logoutput" | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | sed 's/.$//' | sed 's~\.~\\.~g')" /opt/var/log/dnsmasq* | awk '{print $(NF-2)}' | Strip_Domain | Filter_OutIP | xargs)"
									[ -n "$domainlist" ] && Red "Associated Domain(s) - [$domainlist]"
								fi
							elif echo "$logoutput" | grep -qE "IOT.*PT=$4 "; then
								Red "$logoutput"
								if [ "$extendedstats" = "enabled" ]; then
									domainlist="$(grep -E "reply.* is $(echo "$logoutput" | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | sed 's/.$//' | sed 's~\.~\\.~g')" /opt/var/log/dnsmasq* | awk '{print $(NF-2)}' | Strip_Domain | Filter_OutIP | xargs)"
									[ -n "$domainlist" ] && Red "Associated Domain(s) - [$domainlist]"
								fi
							fi
						done
					;;
					*)
						tail -F "$syslogloc" | while read -r logoutput; do
							if echo "$logoutput" | grep -q "INVALID"; then
								Blue "$logoutput"
								if [ "$extendedstats" = "enabled" ]; then
									domainlist="$(grep -E "reply.* is $(echo "$logoutput" | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | sed 's/.$//' | sed 's~\.~\\.~g')" /opt/var/log/dnsmasq* | awk '{print $(NF-2)}' | Strip_Domain | Filter_OutIP | xargs)"
									[ -n "$domainlist" ] && Blue "Associated Domain(s) - [$domainlist]"
								fi
							elif echo "$logoutput" | grep -q "INBOUND"; then
								Ylow "$logoutput"
								if [ "$extendedstats" = "enabled" ]; then
									domainlist="$(grep -E "reply.* is $(echo "$logoutput" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6- | sed 's/.$//' | sed 's~\.~\\.~g')" /opt/var/log/dnsmasq* | awk '{print $(NF-2)}' | Strip_Domain | Filter_OutIP | xargs)"
									[ -n "$domainlist" ] && Red "Associated Domain(s) - [$domainlist]"
								fi
							elif echo "$logoutput" | grep -q "OUTBOUND"; then
								Red "$logoutput"
								if [ "$extendedstats" = "enabled" ]; then
									domainlist="$(grep -E "reply.* is $(echo "$logoutput" | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | sed 's/.$//' | sed 's~\.~\\.~g')" /opt/var/log/dnsmasq* | awk '{print $(NF-2)}' | Strip_Domain | Filter_OutIP | xargs)"
									[ -n "$domainlist" ] && Red "Associated Domain(s) - [$domainlist]"
								fi
							elif echo "$logoutput" | grep -q "IOT"; then
								Red "$logoutput"
								if [ "$extendedstats" = "enabled" ]; then
									domainlist="$(grep -E "reply.* is $(echo "$logoutput" | grep -oE ' DST=[0-9,\.]* ' | cut -c 6- | sed 's/.$//' | sed 's~\.~\\.~g')" /opt/var/log/dnsmasq* | awk '{print $(NF-2)}' | Strip_Domain | Filter_OutIP | xargs)"
									[ -n "$domainlist" ] && Red "Associated Domain(s) - [$domainlist]"
								fi
							fi
						done
					;;
				esac
				nocfg="1"
			;;
			info)
				echo "Router Model; $model"
				echo "Skynet Version; $localver ($(Filter_Date < "$0")) ($(md5sum "$0" | awk '{print $1}'))"
				echo "$(iptables --version) - ($iface @ $(nvram get lan_ipaddr))"
				ipset -v 2>/dev/null
				echo "IP Address; ($(if nvram get wan0_ipaddr | Is_PrivateIP; then Red "$(nvram get wan0_ipaddr)"; else nvram get wan0_ipaddr; fi))$(if [ "$(nvram get ipv6_service)" != "disabled" ]; then echo " - ($(nvram get ipv6_prefix)/$(nvram get ipv6_prefix_length))"; fi)"
				echo "FW Version; $(nvram get buildno)_$(nvram get extendno) ($(uname -v | awk '{printf "%s %s %s\n", $5, $6, $9}')) ($(uname -r))"
				echo "Install Dir; ${skynetloc} ($(df -h "${skynetloc}" | xargs | awk '{printf "%s / %s\n", $11, $9}') Space Available)"
				if [ -n "$swaplocation" ]; then
					echo "SWAP File; $swaplocation ($(du -h "$swaplocation" | awk '{print $1}'))"
					if [ "$(du "$swaplocation" | awk '{print $1}')" -lt "1048576" ]; then
						Red "SWAP File Too Small - 1GB Minimum Required - Please Fix Immediately!"
					fi
				fi
				if [ "$syslogloc" != "/tmp/syslog.log" ] || [ "$syslog1loc" != "/tmp/syslog.log-1" ]; then
					echo "Syslog Location; ($syslogloc) ($syslog1loc)"
				fi
				if [ -n "$countrylist" ]; then echo "Banned Countries; $countrylist"; fi
				echo "Uptime; $(uptime | awk -F'( |,|:)+' '{if ($7=="min") m=$6; else {if ($7~/^day/) {d=$6;h=$8;m=$9} else {h=$6;m=$7}}} {print d+0,"days,",h+0,"hours,",m+0,"minutes."}')"
				if grep -qF "MemAvailable" /proc/meminfo; then
					memavailable="$(($(grep -F "MemAvailable" /proc/meminfo | awk '{print $2}') / 1024))"
				else
					memavailable="$(($(grep -F "MemFree" /proc/meminfo | awk '{print $2}') / 1024))"
				fi
				echo "Ram Available; (${memavailable}M / $(($(grep -F "MemTotal" /proc/meminfo | awk '{print $2}') / 1024))M)"
				if [ -f "/tmp/skynet.lock" ] && [ -d "/proc/$(sed -n '2p' /tmp/skynet.lock)" ]; then
					echo
					Red "[*] Lock File Detected ($(sed -n '1p' /tmp/skynet.lock)) (pid=$(sed -n '2p' /tmp/skynet.lock))"
					Ylow '[*] Locked Processes Generally Take A Few Minutes To Complete And May Result In Temporarily "Failed" Tests'
				fi
				passedtests="0"
				totaltests="18"
				Display_Header "6"
				ip neigh | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3} ' | sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 | while IFS= read -r "ip"; do
					ipaddr="$(echo "$ip" | awk '{print $1}')"
					macaddr="$(echo "$ip" | awk '{print $5}')"
					Get_LocalName
					state="$(echo "$ip" | awk '{print $6}')"
					if ! echo "$macaddr" | Is_MAC; then
						macaddr="Unknown"
						state="$(Red Offline)"
					elif [ "$state" = "STALE" ]; then
						state="$(Grn Inactive)"
					elif [ "$state" = "REACHABLE" ]; then
						state="$(Grn Online)"
					else
						state="$(Grn "$state")"
					fi
					printf '%-40s | %-16s | %-20s | %-15s\n' "$localname" "$ipaddr" "$macaddr" "$state"
				done
				Display_Header "7"
				printf "%-35s | " "Internet-Connectivity"
				if Check_Connection >/dev/null 2>&1; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-8s\n' "$result"
				printf "%-35s | " "Write Permission"
				if [ -w "${skynetloc}" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-8s\n' "$result"
				printf "%-35s | " "Config File"
				if [ -f "${skynetcfg}" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-8s\n' "$result"
				printf "%-35s | " "Firewall-Start Entry"
				if grep -E "start.* # Skynet" /jffs/scripts/firewall-start | grep -qvE "^#"; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-8s\n' "$result"
				printf "%-35s | " "Services-Stop Entry"
				if grep -F "# Skynet" /jffs/scripts/services-stop | grep -qvE "^#"; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-8s\n' "$result"
				printf "%-35s | " "Service-Event Entry"
				if grep -F "# Skynet" /jffs/scripts/service-event | grep -qvE "^#"; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-8s\n' "$result"
				printf "%-35s | " "Profile.add Entry"
				if grep -F "# Skynet" /jffs/configs/profile.add | grep -qvE "^#"; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-8s\n' "$result"
				printf "%-35s | " "SWAP File"
				if Check_Swap; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-8s\n' "$result"
				printf "%-35s | " "Cron Jobs"
				if [ "$(cru l | grep -c "Skynet")" -ge "2" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-8s\n' "$result"
				printf "%-35s | " "NTP Sync"
				if [ "$(nvram get ntp_ready)" = "1" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-8s\n' "$result"
				printf "%-35s | " "IPSet Comment Support"
				if [ -f /lib/modules/"$(uname -r)"/kernel/net/netfilter/ipset/ip_set_hash_ipmac.ko ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-8s\n' "$result"
				printf "%-35s | " "Log Level $(nvram get message_loglevel) Settings"
				if [ "$(nvram get message_loglevel)" -le "$(nvram get log_level)" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-8s\n' "$result"
				printf "%-35s | " "Duplicate Rules In RAW"
				if [ "$(iptables-save -t raw | sort | uniq -d | grep -c " ")" = "0" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-8s\n' "$result"
				printf "%-35s | " "IPSets"
				if Check_IPSets; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-8s\n' "$result"
				printf "%-35s | " "IPTables Rules"
				if Check_IPTables; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-8s\n' "$result"
				if [ "$displaywebui" = "enabled" ]; then
					printf "%-35s | " "Local WebUI Files"
					[ -f "${skynetloc}/webui/chart.js" ] || localfail="${localfail}chart.js "
					[ -f "${skynetloc}/webui/chartjs-plugin-zoom.js" ] || localfail="${localfail}chartjs-plugin-zoom.js "
					[ -f "${skynetloc}/webui/hammerjs.js" ] || localfail="${localfail}hammerjs.js "
					[ -f "${skynetloc}/webui/skynet.asp" ] || localfail="${localfail}skynet.asp "
					[ -f "${skynetloc}/webui/stats.js" ] || localfail="${localfail}stats.js "
					if [ -z "$localfail" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
					printf '%-8s\n' "$result"
					printf "%-35s | " "Mounted WebUI Files"
					Get_WebUI_Page "${skynetloc}/webui/skynet.asp" 2>/dev/null
					[ -f "/www/user/skynet/chart.js" ] || mountedfail="${mountedfail}chart.js "
					[ -f "/www/user/skynet/chartjs-plugin-zoom.js" ] || mountedfail="${mountedfail}chartjs-plugin-zoom.js "
					[ -f "/www/user/skynet/hammerjs.js" ] || mountedfail="${mountedfail}hammerjs.js "
					[ -f "/www/user/${MyPage}" ] || mountedfail="${mountedfail}skynet.asp "
					[ -f "/www/user/skynet/stats.js" ] || mountedfail="${mountedfail}stats.js "
					if [ -z "$mountedfail" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
					printf '%-8s\n' "$result"
					printf "%-35s | " "MenuTree.js Entry"
					if grep -qF "Skynet" "/www/require/modules/menuTree.js"; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
					printf '%-8s\n' "$result"
				else
					totaltests="$((totaltests - 3))"
				fi
				Display_Header "8"
				printf '%-35s | %-8s\n' "Skynet Auto-Updates" "$(if [ "$autoupdate" = "enabled" ]; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
				printf '%-35s | %-8s\n' "Malware List Auto-Updates" "$(if [ "$banmalwareupdate" = "daily" ] || [ "$banmalwareupdate" = "weekly" ]; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
				printf '%-35s | %-8s\n' "Logging" "$(if [ "$logmode" = "enabled" ]; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
				printf '%-35s | %-8s\n' "Filter Traffic" "$(if [ "$filtertraffic" = "all" ]; then Grn "[Enabled]"; else Ylow "[Selective]"; fi)"
				printf '%-35s | %-8s\n' "Unban PrivateIP" "$(if [ "$unbanprivateip" = "enabled" ]; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
				printf '%-35s | %-8s\n' "Log Invalid Packets" "$(if [ "$loginvalid" = "enabled" ]; then Grn "[Enabled]"; else Grn "[Disabled]"; fi)"
				printf '%-35s | %-8s\n' "Import AiProtect Data" "$(if [ "$banaiprotect" = "enabled" ]; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
				printf '%-35s | %-8s\n' "Secure Mode" "$(if [ "$securemode" = "enabled" ]; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
				printf '%-35s | %-8s\n' "Fast Switch List" "$(if [ "$fastswitch" = "enabled" ]; then Ylow "[Enabled]"; else Grn "[Disabled]"; fi)"
				printf '%-35s | %-8s\n' "Syslog Location" "$(if { [ "$syslogloc" = "/tmp/syslog.log" ] && [ "$syslog1loc" = "/tmp/syslog.log-1" ]; } || { [ "$syslogloc" = "/jffs/syslog.log" ] && [ "$syslog1loc" = "/jffs/syslog.log-1" ]; } then Grn "[Default]"; else Ylow "[Custom]"; fi)"
				printf '%-35s | %-8s\n' "IOT Blocking" "$(if [ "$iotblocked" != "enabled" ]; then Grn "[Disabled]"; else Ylow "[Enabled]"; fi)"
				printf '%-35s | %-8s\n' "IOT Logging" "$(if [ "$iotlogging" != "enabled" ]; then Red "[Disabled]"; else Grn "[Enabled]"; fi)"
				printf '%-35s | %-8s\n' "Country Lookup For Stats" "$(if [ "$lookupcountry" = "enabled" ]; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
				printf '%-35s | %-8s\n' "CDN Whitelisting" "$(if [ "$cdnwhitelist" = "enabled" ]; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
				printf '%-35s | %-8s\n' "Display WebUI" "$(if [ "$displaywebui" = "enabled" ]; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
				printf '\n%-35s\n' "${passedtests}/${totaltests} Tests Sucessful"
				if [ -n "$fail" ]; then echo; echo "[*] Rule Integrity Violation - [ ${fail}]"; unset fail; fi
				if [ -n "$localfail" ]; then echo; echo "[*] Local File Missing - [ ${localfail}]"; fi
				if [ -n "$mountedfail" ]; then echo; echo "[*] Mounted File Missing - [ ${mountedfail}]"; fi
				if [ "$3" = "extended" ]; then echo; echo; cat "$skynetcfg"; fi
				nocfg="1"
			;;
			genstats)
				Check_Lock "$@"
				Purge_Logs "all"
				if nvram get rc_support | grep -qF "am_addons"; then
					if [ "$displaywebui" = "enabled" ]; then
						echo "[i] Generating Stats For WebUI"
						Generate_Stats
					else
						echo "[*] WebUI Is Currently Disabled - To Enable Use ( sh $0 settings webui enable )"
					fi
				fi
			;;
			clean)
				echo "[i] Cleaning Syslog Entries"
				Purge_Logs "all"
				sed -i '\~Skynet: \[%\] ~d' "$syslog1loc" "$syslogloc" 2>/dev/null
				echo "[i] Complete!"
				echo
				nolog="2"
				nocfg="1"
			;;
			swap)
				case "$3" in
					install)
						Check_Lock "$@"
						Check_Files
						swaplocation="$(grep -E "^swapon " /jffs/scripts/post-mount | awk '{print $2}')"
						findswap="$(find /tmp/mnt -name "myswap.swp")"
						if [ -z "$findswap" ]; then
							findswap="$(grep -m1 -F "file" "/proc/swaps" | awk '{print $1}')"
						fi
						if [ -z "$swaplocation" ] && [ -z "$findswap" ] && ! Check_Swap; then
							Manage_Device
							Create_Swap
							echo "[i] Saving Changes"
							Save_IPSets
							echo "[i] Unloading Skynet Components"
							Unload_Cron "all"
							Unload_IPTables
							Unload_IOTTables
							Unload_LogIPTables
							Unload_IPSets
							logger -t Skynet "[i] Restarting Firewall Service"; echo "[i] Restarting Firewall Service"
							restartfirewall="1"
							nolog="2"
						elif [ -z "$swaplocation" ] && [ -n "$findswap" ]; then
							echo "[*] Restoring Missing Swap File Entry ( $findswap )"
							sed -i '\~swapon ~d' /jffs/scripts/post-mount
							if [ "$(wc -l < /jffs/scripts/post-mount)" -lt "2" ]; then echo >> /jffs/scripts/post-mount; fi
							sed -i "2i swapon $findswap # Skynet" /jffs/scripts/post-mount
							swapon "$findswap" 2>/dev/null
							swaplocation="$findswap"
							echo "[i] Saving Changes"
							Save_IPSets
							echo "[i] Unloading Skynet Components"
							Unload_Cron "all"
							Unload_IPTables
							Unload_IOTTables
							Unload_LogIPTables
							Unload_IPSets
							logger -t Skynet "[i] Restarting Firewall Service"; echo "[i] Restarting Firewall Service"
							restartfirewall="1"
							nolog="2"
						elif [ -n "$swaplocation" ] && [ ! -f "$swaplocation" ]; then
							echo "[*] SWAP File Missing ( $swaplocation ) - Fix This By Running ( $0 debug swap uninstall ) Then ( $0 debug swap install )"
							nolog="2"
						else
							echo "[*] Pre-existing SWAP File Detected - Exiting!"
						fi
					;;
					uninstall)
						Check_Lock "$@"
						if ! grep -qE "^swapon " /jffs/scripts/post-mount; then
							findswap="$(find /tmp/mnt -name "myswap.swp")"
							if [ -n "$findswap" ]; then
								swaplocation="$findswap"
							elif [ -z "$findswap" ]; then
								findswap="$(grep -m1 -F "file" "/proc/swaps" | awk '{print $1}')"
								if [ -n "$findswap" ]; then
									swaplocation="$findswap"
								else
									echo "[*] No SWAP File Detected - Exiting!"; echo; exit 1
								fi
							fi
						else
							swaplocation="$(grep -E "^swapon " /jffs/scripts/post-mount | awk '{print $2}')"
						fi
						echo "[i] Saving Changes"
						Save_IPSets
						echo "[i] Unloading Skynet Components"
						Unload_Cron "all"
						Unload_IPTables
						Unload_IOTTables
						Unload_LogIPTables
						Unload_IPSets
						echo "[i] Removing SWAP File ($swaplocation)"
						if [ -f "$swaplocation" ]; then
							sed -i '\~swapon ~d' /jffs/scripts/post-mount
							sync; echo 3 > /proc/sys/vm/drop_caches
							swapoff -a
							if rm -rf "$swaplocation"; then echo "[i] SWAP File Removed"; else "[*] SWAP File Partially Removed - Please Inspect Manually"; fi
						else
							sed -i '\~swapon ~d' /jffs/scripts/post-mount
							echo "[*] SWAP File Partially Removed - Please Inspect Manually"
						fi
						sed -i '\~swapoff ~d' /jffs/scripts/unmount
						logger -t Skynet "[i] Restarting Firewall Service"; echo "[i] Restarting Firewall Service"
						restartfirewall="1"
						nolog="2"
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
				Check_Lock "$@"
				if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
				Purge_Logs
				echo "[i] Saving Changes"
				Save_IPSets
				echo "[i] Backing Up Skynet Related Files"
				echo
				tar -czvf "${skynetloc}/Skynet-Backup.tar.gz" -C "${skynetloc}" skynet.ipset skynet.log events.log skynet.cfg
				echo
				echo "[i] Backup Saved To ${skynetloc}/Skynet-Backup.tar.gz"
				echo "[i] Copy This File To A Safe Location"
			;;
			restore)
				Check_Lock "$@"
				if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
				backuplocation="${skynetloc}/Skynet-Backup.tar.gz"
				if [ ! -f "$backuplocation" ]; then
					echo "[*] Skynet Backup Doesn't Exist In Expected Path, Please Provide Location"
					echo
					printf "[Location]: "
					read -r "backuplocation"
					echo
					if [ ! -f "$backuplocation" ]; then
						echo "[*] Skynet Backup Doesn't Exist In Specified Path - Exiting"
						echo; exit 2
					fi
				fi
				echo "[i] Restoring Skynet Backup"
				echo
				Purge_Logs
				Unload_IPTables
				Unload_IOTTables
				Unload_LogIPTables
				Unload_IPSets
				tar -xzvf "$backuplocation" -C "${skynetloc}"
				echo
				echo "[i] Backup Restored"
				logger -t Skynet "[i] Restarting Firewall Service"; echo "[i] Restarting Firewall Service"
				restartfirewall="1"
				nolog="2"
			;;
			run)
				Check_Lock
				if grep -qE "^${3}()" "$0"; then
					printf '[i] Running Function %s()\n\n' "$3"
					"$3"
					printf '\n[i] Complete\n'
				else
					printf "%s() Doesn't Exist\\n" "$3"
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

	stats)
		Purge_Logs
		Spinner_Start
		nocfg="1"
		if [ "$logmode" = "disabled" ]; then
			echo
			Red "[*] !!! Logging Is Disabled !!!"
			Red "[*] To Enable Use ( sh $0 settings logmode enable )"
			echo
		fi
		if [ ! -s "$skynetlog" ] && [ ! -s "$skynetevents" ]; then
			echo "[*] No Logging Data Detected - Give This Time To Generate"
			echo; exit 0
		else
			echo "[i] Logging Data Detected in $skynetlog - $(du -h "$skynetlog" | awk '{print $1}')"
		fi
		echo "[i] Monitoring From $(grep -m1 -F "BLOCKED -" "$skynetlog" | awk '{printf "%s %s %s\n", $1, $2, $3}') To $(grep -F "BLOCKED -" "$skynetlog" | tail -1 | awk '{printf "%s %s %s\n", $1, $2, $3}')"
		echo "[i] $(wc -l < "$skynetlog") Block Events Detected"
		echo "[i] $({ grep -E 'INBOUND|INVALID' "$skynetlog" | grep -oE ' SRC=[0-9,\.]* ' | cut -c 6-; grep -F "OUTBOUND" "$skynetlog" | grep -oE ' DST=[0-9,\.]* ' | cut -c 6-; } | awk '!x[$0]++' | wc -l) Unique IPs"
		echo "[i] $(grep -Fc "Manual Ban" "$skynetevents") Manual Bans Issued"
		echo
		counter="10"
		case "$2" in
			reset)
				Purge_Logs "force"
				echo "[i] Stat Data Reset"
			;;
			remove)
				case "$3" in
					ip)
						if ! echo "$4" | Is_IP; then echo "[*] $4 Is Not A Valid IP"; echo; exit 2; fi
						logcount="$(grep -c "=$4 " "$skynetlog")"
						sed -i "\\~=$4 ~d" "$skynetlog"
						echo "[i] $logcount Log Entries Removed Containing IP $4"
					;;
					port)
						if ! echo "$4" | Is_Port || [ "$4" -gt "65535" ]; then echo "[*] $4 Is Not A Valid Port"; echo; exit 2; fi
						logcount="$(grep -c "PT=$4 " "$skynetlog")"
						sed -i "\\~=$4 ~d" "$skynetlog"
						echo "[i] $logcount Log Entries Removed Containing Port $4"
					;;
					*)
						echo "Command Not Recognized, Please Try Again"
						echo "For Help Check https://github.com/Adamm00/IPSet_ASUS#help"
						echo "For Common Issues Check https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
						echo; exit 2
					;;
				esac
			;;
			search)
				if [ "$extendedstats" = "enabled" ]; then
					grep -hE 'reply.* is ([0-9]{1,3}\.){3}[0-9]{1,3}$' /opt/var/log/dnsmasq* | awk '{printf "%s %s\n", $(NF-2), $NF}' | awk '!x[$0]++' | Strip_Domain > /tmp/skynet/skynetstats.txt
					printf '   \b\b\b'
				else
					touch "/tmp/skynet/skynetstats.txt"
				fi
				case "$3" in
					port)
						if ! echo "$4" | Is_Port || [ "$4" -gt "65535" ]; then echo "[*] $4 Is Not A Valid Port"; echo; exit 2; fi
						if [ "$5" -eq "$5" ] 2>/dev/null; then counter="$5"; fi
						echo "[i] Port $4 First Tracked On $(grep -m1 -F "PT=$4 " "$skynetlog" | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo "[i] Port $4 Last Tracked On $(grep -F "PT=$4 " "$skynetlog" | tail -1 | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo "[i] $(grep -Foc "PT=$4 " "$skynetlog") Attempts Total"
						echo "[i] $(grep -F "PT=$4 " "$skynetlog" | grep -oE ' SRC=[0-9,\.]* ' | awk '!x[$0]++' | wc -l) Unique IPs"
						echo
						Red "First Block Tracked On Port $4;"
						grep -m1 -F "PT=$4 " "$skynetlog"
						echo
						Red "$counter Most Recent Blocks On Port $4;"
						grep -F "PT=$4 " "$skynetlog" | tail -"$counter"
						echo
					;;
					ip)
						if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
						if ! echo "$4" | Is_IP; then echo "[*] $4 Is Not A Valid IP"; echo; exit 2; fi
						if [ "$5" -eq "$5" ] 2>/dev/null; then counter="$5"; fi
						ipset test Skynet-Whitelist "$4" && found1=true
						ipset test Skynet-Blacklist "$4" && found2=true
						ipset test Skynet-BlockedRanges "$4" && found3=true
						echo
						if [ -n "$found1" ]; then Red "Whitelist Reason;"; grep -F "add Skynet-Whitelist $(echo "$4" | cut -d '.' -f1-3)." "$skynetipset" | awk '{$1=$2=$4=""; print $0}' | tr -s " "; echo; fi
						if [ -n "$found2" ]; then Red "Blacklist Reason;"; grep -F "add Skynet-Blacklist $4 " "$skynetipset" | awk '{$1=$2=$3=$4=""; print $0}' | tr -s " "; echo; fi
						if [ -n "$found3" ]; then Red "BlockedRanges Reason;"; grep -F "add Skynet-BlockedRanges $(echo "$4" | cut -d '.' -f1-3)." "$skynetipset" | awk '{$1=$2=$4=""; print $0}' | tr -s " "; fi
						echo
						ip="$(echo "$4" | sed 's~\.~\\.~g')"
						if [ "$extendedstats" = "enabled" ] && grep -qE "reply.* is $ip" /opt/var/log/dnsmasq*; then
							Red "Associated Domain(s);"
							assdomains="$(grep -E "reply.* is $ip" /opt/var/log/dnsmasq* | awk '{print $(NF-2)}' | Strip_Domain | Filter_OutIP)"
							for domain in $assdomains; do
								if grep -qE " (www.)?${domain}$| (www.)?${domain} " /opt/share/diversion/list/blockinglist /opt/share/diversion/list/blacklist 2>/dev/null; then
									echo "$domain (Flagged By Diversion)"
								else
									echo "$domain"
								fi
							done
							echo; echo
						fi
						echo "[i] IP Location - $(curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno) / $(tr -cd 0-9 </dev/urandom | head -c 20)" "https://api.db-ip.com/v2/free/${4}/countryName/") ($(curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno) / $(tr -cd 0-9 </dev/urandom | head -c 20)" "https://ipapi.co/${4}/org/") / $(curl -fsL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno) / $(tr -cd 0-9 </dev/urandom | head -c 20)" "https://ipapi.co/${4}/asn/"))"
						echo
						echo "[i] $4 First Tracked On $(grep -m1 -F "=$4 " "$skynetlog" | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo "[i] $4 Last Tracked On $(grep -F "=$4 " "$skynetlog" | tail -1 | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo "[i] $(grep -Foc "=$4 " "$skynetlog") Blocks Total"
						echo
						Red "Event Log Entries From $4;"
						grep -F "=$4 " "$skynetevents"
						echo
						Red "First Block Tracked From $4;"
						grep -m1 -F "=$4 " "$skynetlog"
						echo
						Red "$counter Most Recent Blocks From $4;"
						grep -F "=$4 " "$skynetlog" | tail -"$counter"
						echo; echo
						Red "Top $counter Targeted Ports From $4 (Inbound);"
						Display_Header "3"
						grep -E "INBOUND.*SRC=$4 " "$skynetlog" | grep -oE 'DPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{printf "%-10s | %-10s | %-60s\n", $1 "x", $2, "https://www.speedguide.net/port.php?port=" $2 }'
						echo; echo
						Red "Top $counter Sourced Ports From $4 (Inbound);"
						Display_Header "3"
						grep -E "INBOUND.*SRC=$4 " "$skynetlog" | grep -oE 'SPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{printf "%-10s | %-10s | %-60s\n", $1 "x", $2, "https://www.speedguide.net/port.php?port=" $2 }'
						echo
					;;
					malware)
						Check_Lock "$@"
						if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
						if ! echo "$4" | Is_IPRange; then echo "[*] $4 Is Not A Valid IP/Range"; echo; exit 2; fi
						ip="$(echo "$4" | sed 's~\.~\\.~g')"
						if [ "$extendedstats" = "enabled" ] && grep -qE "reply.* is $ip" /opt/var/log/dnsmasq*; then
							Red "Associated Domain(s);"
							assdomains="$(grep -E "reply.* is $ip" /opt/var/log/dnsmasq* | awk '{print $(NF-2)}' | Strip_Domain | Filter_OutIP)"
							for domain in $assdomains; do
								if grep -qE " (www.)?${domain}$| (www.)?${domain} " /opt/share/diversion/list/blockinglist /opt/share/diversion/list/blacklist 2>/dev/null; then
									echo "$domain (Flagged By Diversion)"
								else
									echo "$domain"
								fi
							done
							echo; echo
						fi
						printf '   \b\b\b'
						Display_Header "10"
						Red "Exact Matches;"
						Display_Header "5"
						cwd="$(pwd)"
						cd "${skynetloc}/lists" || exit 1
						grep -HE "^$ip$" -- * | while IFS= read -r "list" && [ -n "$list" ]; do
							printf '%-20s | %-40s\n' "$(echo "$list" | cut -d ':' -f2-)" "$(grep -F "$(echo "$list" | cut -d ':' -f1)" /jffs/addons/shared-whitelists/shared-Skynet-whitelist)"
						done
						printf '   \b\b\b\n\n'
						Red "Possible CIDR Matches;"
						Display_Header "5"
						grep -HE "^$(echo "$ip" | cut -d '.' -f1-3)\..*/" -- * | while IFS= read -r "list" && [ -n "$list" ]; do
							printf '%-20s | %-40s\n' "$(echo "$list" | cut -d ':' -f2-)" "$(grep -F "$(echo "$list" | cut -d ':' -f1)" /jffs/addons/shared-whitelists/shared-Skynet-whitelist)"
						done
						printf '   \b\b\b'
						cd "$cwd" || exit 1
					;;
					manualbans)
						if [ "$4" -eq "$4" ] 2>/dev/null; then counter="$4"; fi
						echo "First Manual Ban Issued On $(grep -m1 -F "Manual Ban" "$skynetevents" | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo "Last Manual Ban Issued On $(grep -F "Manual Ban" "$skynetevents" | tail -1 | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo
						Red "First Manual Ban Issued;"
						grep -m1 -F "Manual Ban" "$skynetevents"
						echo
						Red "$counter Most Recent Manual Bans;"
						grep -F "Manual Ban" "$skynetevents" | tail -"$counter"
					;;
					device)
						if ! echo "$4" | Is_IP; then echo "[*] $4 Is Not A Valid IP"; echo; exit 2; fi
						if [ "$5" -eq "$5" ] 2>/dev/null; then counter="$5"; fi
						echo "[i] $4 First Tracked On $(grep -m1 -E "OUTBOUND.* SRC=$4 " "$skynetlog" | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo "[i] $4 Last Tracked On $(grep -E "OUTBOUND.* SRC=$4 " "$skynetlog" | tail -1 | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo "[i] $(grep -Eoc -E "OUTBOUND.* SRC=$4 " "$skynetlog") Blocks Total"
						echo
						Red "Device Name;"
						if grep -qF " $4 " "/var/lib/misc/dnsmasq.leases"; then grep -F " $4 " "/var/lib/misc/dnsmasq.leases" | awk '{print $4}'; else echo "Unknown"; fi
						echo
						Red "First Block Tracked From $4;"
						grep -m1 -E "OUTBOUND.* SRC=$4 " "$skynetlog"
						echo
						Red "$counter Most Recent Blocks From $4;"
						grep -E "OUTBOUND.* SRC=$4 " "$skynetlog" | tail -"$counter"
						echo; echo
						Red "Top $counter HTTP(s) Blocks (Outbound);"
						Display_Header "2"
						grep -E 'DPT=80 |DPT=443 ' "$skynetlog" | grep -E "OUTBOUND.*$proto" | grep -F "SRC=${4} " | grep -oE ' DST=[0-9,\.]*' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | while IFS= read -r "statdata"; do
							Extended_DNSStats "2"
						done
						echo; echo
						Red "Top $counter Blocks From (Outbound);"
						Display_Header "2"
						grep -E "OUTBOUND.*$proto" "$skynetlog" | grep -vE 'DPT=80 |DPT=443 ' | grep -F "SRC=${4} " | grep -oE ' DST=[0-9,\.]*' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | while IFS= read -r "statdata"; do
							Extended_DNSStats "2"
						done
					;;
					reports)
						if [ "$4" -eq "$4" ] 2>/dev/null; then counter="$4"; fi
						sed '\~Skynet: \[#\] ~!d' "$syslog1loc" "$syslogloc" 2>/dev/null >> "$skynetevents"
						sed -i '\~Skynet: \[#\] ~d' "$syslog1loc" "$syslogloc" 2>/dev/null
						echo "[i] First Report Tracked On $(grep -m1 -F "Skynet: [#] " "$skynetevents" | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo "[i] Last Report Tracked On $(grep -F "Skynet: [#] " "$skynetevents" | tail -1 | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo
						Red "First Report Tracked;"
						grep -m1 -F "Skynet: [#] " "$skynetevents"
						echo
						Red "$counter Most Recent Reports;"
						grep -F "Skynet: [#] " "$skynetevents" | tail -"$counter"
					;;
					invalid)
						if [ "$4" -eq "$4" ] 2>/dev/null; then counter="$4"; fi
						echo "[i] First Invalid Block Tracked On $(grep -m1 -F "BLOCKED - INVALID" "$skynetlog" | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo "[i] Last Invalid Block Tracked On $(grep -F "BLOCKED - INVALID" "$skynetlog" | tail -1 | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo
						Red "First Report Tracked;"
						grep -m1 -F "BLOCKED - INVALID" "$skynetlog"
						echo
						Red "$counter Most Recent Reports;"
						grep -F "BLOCKED - INVALID" "$skynetlog" | tail -"$counter"
					;;
					connections)
						if [ -f "/proc/bw_cte_dump" ] && [ -f "/tmp/bwdpi/bwdpi.app.db" ]; then
							Display_Header "11"
							while IFS= read -r "logs"; do
								mark="$(echo "$logs" | awk '{printf $8}' | sed 's~mark=~~g')"
								mark="$(printf '%d\n' "0x${mark}")"
								mark2="$(printf '%X\n' "$((mark & 0x3F0000))")"
								mark2="0x${mark2}"
								id="$(awk -v mark="$mark2" 'BEGIN {printf "%.3f\n", mark / 65535}' | sed 's~\..*~~g')"
								hex="$(printf '%X\n' "$((mark & 0xFFFF))")"
								cat="$(printf '%d\n' "0x${hex}")"
								proto="$(echo "$logs" | awk '{print $2}')"
								sourceip="$(echo "$logs" | awk '{print $3}' | cut -d '=' -f2)"
								if echo "$sourceip" | grep -q ":"; then sourceip="IPv6 Address"; fi
								destip="$(echo "$logs" | awk '{print $4}' | cut -d '=' -f2)"
								if echo "$destip" | grep -q ":"; then destip="IPv6 Address"; fi
								sport="$(echo "$logs" | awk '{print $5}' | cut -d '=' -f2)"
								dport="$(echo "$logs" | awk '{print $6}' | cut -d '=' -f2)"
								if [ "$cat" = "0" ] && [ "$id" = "0" ]; then
									reason="Unidentified"
								else
									reason="$(grep -E "^${id},${cat},0" "/tmp/bwdpi/bwdpi.app.db" | cut -d ',' -f4)"
								fi
								if [ "$4" = "ip" ] && [ -n "$5" ] && [ "$5" != "$sourceip" ] && [ "$5" != "$destip" ]; then
									true
								elif [ "$4" = "port" ] && [ -n "$5" ] && [ "$5" != "$sport" ] && [ "$5" != "$dport" ]; then
									true
								elif [ "$4" = "proto" ] && [ -n "$5" ] && [ "$5" != "$proto" ]; then
									true
								elif [ "$4" = "id" ] && [ -n "$5" ] && [ "$5" != "$reason" ]; then
									true
								else
									printf '%-10s | %-18s | %-10s | %-18s | %-10s | %-18s\n' "$proto" "$sourceip" "$sport" "$destip" "$dport" "$reason"
								fi
							done < /proc/bw_cte_dump
						else
							echo "Please Enable AiProtect To Use This Feature"
						fi
					;;
					iot)
						if [ "$4" -eq "$4" ] 2>/dev/null; then counter="$4"; fi
						echo "[i] First IOT Block Tracked On $(grep -m1 -F "BLOCKED - IOT" "$skynetlog" | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo "[i] Last IOT Block Tracked On $(grep -F "BLOCKED - IOT" "$skynetlog" | tail -1 | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo
						Red "First IOT Block Tracked;"
						grep -m1 -F "BLOCKED - IOT" "$skynetlog"
						echo
						Red "$counter Most Recent IOT Blocks;"
						grep -F "BLOCKED - IOT" "$skynetlog" | tail -"$counter"
						echo;echo
						Red "Top $counter IOT Blocks (Outbound);"
						Display_Header "2"
						grep -E "IOT.*$proto" "$skynetlog" | grep -oE ' DST=[0-9,\.]*' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | while IFS= read -r "statdata"; do
							Extended_DNSStats "2"
						done
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
						proto="TCP"
					;;
					udp)
						proto="UDP"
					;;
					icmp)
						proto="ICMP"
					;;
				esac
				if [ "$extendedstats" = "enabled" ]; then
					grep -hE 'reply.* is ([0-9]{1,3}\.){3}[0-9]{1,3}$' /opt/var/log/dnsmasq* | awk '{printf "%s %s\n", $(NF-2), $NF}' | awk '!x[$0]++' | Strip_Domain > /tmp/skynet/skynetstats.txt
					printf '   \b\b\b'
				else
					touch "/tmp/skynet/skynetstats.txt"
				fi
				Display_Header "10"
				Red "Top $counter Targeted Ports (Inbound);"
				Display_Header "3"
				grep -E "INBOUND.*$proto" "$skynetlog" | grep -oE 'DPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{printf "%-10s | %-10s | %-60s\n", $1 "x", $2, "https://www.speedguide.net/port.php?port=" $2 }'
				Display_Header "9"
				Red "Top $counter Attacker Source Ports (Inbound);"
				Display_Header "3"
				grep -E "INBOUND.*$proto" "$skynetlog" | grep -oE 'SPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{printf "%-10s | %-10s | %-60s\n", $1 "x", $2, "https://www.speedguide.net/port.php?port=" $2 }'
				Display_Header "9"
				Red "Last $counter Unique Connections Blocked (Inbound);"
				Display_Header "1"
				grep -E "INBOUND.*$proto" "$skynetlog" | grep -oE ' SRC=[0-9,\.]*' | cut -c 6- | awk '{a[i++]=$0} END {for (j=i-1; j>=0;) print a[j--] }' | awk '!x[$0]++' | head -"$counter" | while IFS= read -r "statdata"; do
					Extended_DNSStats "1"
				done
				Display_Header "9"
				Red "Last $counter Unique Connections Blocked (Outbound);"
				Display_Header "1"
				grep -E "OUTBOUND.*$proto" "$skynetlog" | grep -vE 'DPT=80 |DPT=443 ' | grep -oE ' DST=[0-9,\.]*' | cut -c 6- | awk '{a[i++]=$0} END {for (j=i-1; j>=0;) print a[j--] }' | awk '!x[$0]++' | head -"$counter" | while IFS= read -r "statdata"; do
					Extended_DNSStats "1"
				done
				if [ "$loginvalid" = "enabled" ]; then
					Display_Header "9"
					Red "Last $counter Unique Connections Blocked (Invalid);"
					Display_Header "1"
					grep -E "INVALID.*$proto" "$skynetlog" | grep -oE ' SRC=[0-9,\.]*' | cut -c 6- | awk '{a[i++]=$0} END {for (j=i-1; j>=0;) print a[j--] }' | awk '!x[$0]++' | head -"$counter" | while IFS= read -r "statdata"; do
						Extended_DNSStats "1"
					done
				fi
				Display_Header "9"
				Red "Last $counter Manual Bans;"
				Display_Header "1"
				grep -F "Manual Ban" "$skynetevents" | grep -oE ' SRC=[0-9,\.]*' | cut -c 6- | tail -"$counter" | awk '{a[i++]=$0} END {for (j=i-1; j>=0;) print a[j--] }' | while IFS= read -r "statdata"; do
					Extended_DNSStats "1"
				done
				Display_Header "9"
				Red "Last $counter Unique HTTP(s) Blocks (Outbound);"
				Display_Header "1"
				grep -E 'DPT=80 |DPT=443 ' "$skynetlog" | grep -E "OUTBOUND.*$proto" | grep -oE ' DST=[0-9,\.]*' | cut -c 6- | awk '{a[i++]=$0} END {for (j=i-1; j>=0;) print a[j--] }' | awk '!x[$0]++' | head -"$counter" | while IFS= read -r "statdata"; do
					Extended_DNSStats "1"
				done
				Display_Header "9"
				Red "Top $counter HTTP(s) Blocks (Outbound);"
				Display_Header "2"
				grep -E 'DPT=80 |DPT=443 ' "$skynetlog" | grep -E "OUTBOUND.*$proto" | grep -oE ' DST=[0-9,\.]*' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | while IFS= read -r "statdata"; do
					Extended_DNSStats "2"
				done
				Display_Header "9"
				Red "Top $counter Blocks (Inbound);"
				Display_Header "2"
				grep -E "INBOUND.*$proto" "$skynetlog" | grep -oE ' SRC=[0-9,\.]*' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | while IFS= read -r "statdata"; do
					Extended_DNSStats "2"
				done
				Display_Header "9"
				Red "Top $counter Blocks (Outbound);"
				Display_Header "2"
				grep -E "OUTBOUND.*$proto" "$skynetlog" | grep -vE 'DPT=80 |DPT=443 ' | grep -oE ' DST=[0-9,\.]*' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | while IFS= read -r "statdata"; do
					Extended_DNSStats "2"
				done
				if [ "$loginvalid" = "enabled" ]; then
					Display_Header "9"
					Red "Top $counter Blocks (Invalid);"
					Display_Header "2"
					grep -E "INVALID.*$proto" "$skynetlog" | grep -oE ' SRC=[0-9,\.]*' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | while IFS= read -r "statdata"; do
						Extended_DNSStats "2"
					done
				fi
				if [ "$iotblocked" = "enabled" ]; then
					Display_Header "9"
					Red "Top $counter IOT Blocks (Outbound);"
					Display_Header "2"
					grep -E "IOT.*$proto" "$skynetlog" | grep -oE ' DST=[0-9,\.]*' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | while IFS= read -r "statdata"; do
						Extended_DNSStats "2"
					done
				fi
				Display_Header "9"
				Red "Top $counter Blocked Devices (Outbound);"
				Display_Header "4"
				grep -E "OUTBOUND.*$proto" "$skynetlog" | grep -oE ' SRC=[0-9,\.]*' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | while IFS= read -r "statdata"; do
					hits="$(echo "$statdata" | awk '{print $1}')"
					ipaddr="$(echo "$statdata" | awk '{print $2}')"
					macaddr="$(ip neigh | grep -F "$ipaddr " | awk '{print $5}')"
					Get_LocalName
					printf '%-10s | %-16s | %-60s\n' "${hits}x" "${ipaddr}" "$localname"
				done
			;;
		esac
		rm -rf /tmp/skynet/skynetstats.txt
	;;

	install)
		Check_Lock "$@"
		if ! ipset -v 2>/dev/null | grep -qE 'v6|v7'; then
			echo "[*] IPSet Version Not Supported - Please Update To Latest Firmware"
			echo; exit 1
		fi
		if [ ! -f /lib/modules/"$(uname -r)"/kernel/net/netfilter/ipset/ip_set_hash_ipmac.ko ]; then
			echo "[*] IPSet Extensions Not Supported - Please Update To Latest Firmware"
			echo; exit 1
		fi
		if [ "$(nvram get jffs2_scripts)" != "1" ]; then
			nvram set jffs2_scripts=1
			nvram commit
			forcereboot=1
		fi
		if [ "$(nvram get fw_enable_x)" != "1" ]; then
			nvram set fw_enable_x=1
			nvram commit
		fi
		if [ "$(nvram get fw_log_x)" != "drop" ] && [ "$(nvram get fw_log_x)" != "both" ]; then
			nvram set fw_log_x=drop
			nvram commit
		fi
		if nvram get wan0_ipaddr | Is_PrivateIP; then
			echo "[*] Private IP Detected - Please Put Your Modem In Bridge Mode / Disable CG-NAT"
			echo
		fi
		echo "[i] Installing Skynet $(Filter_Version < "$0")"
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
					echo "[i] All Traffic Selected"
					filtertraffic="all"
					break
				;;
				2)
					echo "[i] Inbound Traffic Selected"
					filtertraffic="inbound"
					break
				;;
				3)
					echo "[i] Outbound Traffic Selected"
					filtertraffic="outbound"
					break
				;;
				e|exit)
					echo "[*] Exiting!"
					echo; exit 0
				;;
				*)
					echo "[*] $mode1 Isn't An Option!"
					echo
				;;
			esac
		done
		echo
		echo
		while true; do
			echo "Would You Like To Enable Logging?"
			echo "Logging Is Used For Generating Stats And Monitoring Blocked IP's"
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
					echo "[i] Logging Enabled"
					logmode="enabled"
					iotlogging="enabled"
					break
				;;
				2)
					echo "[i] Logging Disabled"
					logmode="disabled"
					iotlogging="disabled"
					break
				;;
				e|exit)
					echo "[*] Exiting!"
					echo; exit 0
				;;
				*)
					echo "[*] $mode3 Isn't An Option!"
					echo
				;;
			esac
		done
		echo
		echo
		while true; do
			echo "Would You Like To Enable Malware Blacklist Auto-Updates?"
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
					echo "[i] Malware Blacklist Updating Enabled & Scheduled Every Day"
					banmalwareupdate="daily"
					forcebanmalwareupdate="true"
					break
				;;
				2)
					echo "[i] Malware Blacklist Auto-Updates Enabled & Scheduled For Every Monday"
					banmalwareupdate="weekly"
					forcebanmalwareupdate="true"
					break
				;;
				3)
					echo "[i] Malware Blacklist Auto-Updates Disabled"
					banmalwareupdate="disabled"
					break
				;;
				e|exit)
					echo "[*] Exiting!"
					echo; exit 0
				;;
				*)
					echo "[*] $mode4 Isn't An Option!"
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
					echo "[i] Skynet Auto-Updates Enabled & Scheduled For 1.25am Every Monday"
					autoupdate="enabled"
					break
				;;
				2)
					echo "[i] Skynet Auto-Updates Disabled"
					autoupdate="disabled"
					break
				;;
				e|exit)
					echo "[*] Exiting!"
					echo; exit 0
				;;
				*)
					echo "[*] $mode5 Isn't An Option!"
					echo
				;;
			esac
		done
		echo
		Check_Files
		if ! grep -qE "^swapon " /jffs/scripts/post-mount; then Create_Swap; fi
		if [ -f "$skynetlog" ]; then mv "$skynetlog" "${device}/skynet/skynet.log"; fi
		if [ -f "$skynetevents" ]; then mv "$skynetevents" "${device}/skynet/events.log"; fi
		if [ -f "$skynetipset" ]; then mv "$skynetipset" "${device}/skynet/skynet.ipset"; fi
		if [ -f "${skynetloc}/Skynet-Backup.tar.gz" ]; then mv "${skynetloc}/Skynet-Backup.tar.gz" "${device}/skynet/Skynet-Backup.tar.gz"; fi
		if [ "${skynetloc}" != "${device}/skynet" ]; then rm -rf "${skynetloc}"; fi
		skynetloc="${device}/skynet"
		skynetcfg="${device}/skynet/skynet.cfg"
		touch "${device}/skynet/events.log"
		touch "${device}/skynet/skynet.log"
		remotedir="https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master"
		mkdir -p "${skynetloc}/webui"
		Download_File "webui/chart.js" "${skynetloc}/webui/chart.js"
		Download_File "webui/chartjs-plugin-zoom.js" "${skynetloc}/webui/chartjs-plugin-zoom.js"
		Download_File "webui/hammerjs.js" "${skynetloc}/webui/hammerjs.js"
		Download_File "webui/skynet.asp" "${skynetloc}/webui/skynet.asp"
		[ -z "$(nvram get odmpid)" ] && model="$(nvram get productid)" || model="$(nvram get odmpid)"
		if [ -z "$loginvalid" ]; then loginvalid="disabled"; fi
		if [ -z "$unbanprivateip" ]; then unbanprivateip="enabled"; fi
		if [ -z "$banaiprotect" ]; then banaiprotect="enabled"; fi
		if [ -z "$securemode" ]; then securemode="enabled"; fi
		if [ -z "$fastswitch" ]; then fastswitch="disabled"; fi
		if [ -z "$syslogloc" ]; then syslogloc="/tmp/syslog.log"; fi
		if [ -z "$syslog1loc" ]; then syslog1loc="/tmp/syslog.log-1"; fi
		if [ -z "$iotblocked" ]; then iotblocked="disabled"; fi
		if [ -z "$iotproto" ]; then iotproto="udp"; fi
		if [ -z "$lookupcountry" ]; then lookupcountry="enabled"; fi
		if [ -z "$cdnwhitelist" ]; then cdnwhitelist="enabled"; fi
		if [ -z "$displaywebui" ]; then displaywebui="enabled"; fi
		Write_Config
		cmdline="sh /jffs/scripts/firewall start skynetloc=${device}/skynet # Skynet"
		if grep -qE "^sh /jffs/scripts/firewall .* # Skynet" /jffs/scripts/firewall-start; then
			sed -i "s~sh /jffs/scripts/firewall .* # Skynet .*~$cmdline~" /jffs/scripts/firewall-start
		else
			echo "$cmdline" >> /jffs/scripts/firewall-start
		fi
		cmdline="sh /jffs/scripts/firewall save # Skynet"
		if grep -qE "^sh /jffs/scripts/firewall .* # Skynet" /jffs/scripts/services-stop; then
			sed -i "s~sh /jffs/scripts/firewall .* # Skynet .*~$cmdline~" /jffs/scripts/services-stop
		else
			echo "$cmdline" >> /jffs/scripts/services-stop
		fi
		Clean_Temp
		echo
		nvram commit
		if [ "$forcereboot" = "1" ]; then
			echo "[i] Reboot Required To Complete Installation"
			printf "[i] Press Enter To Confirm..."
			read -r "continue"
			service reboot
			exit 0
		fi
		Unload_Cron "all"
		Unload_IPTables
		Unload_IOTTables
		Unload_LogIPTables
		Unload_IPSets
		iptables -t raw -F
		echo "[i] Restarting Firewall Service To Complete Installation"
		restartfirewall="1"
		nolog="2"
	;;

	uninstall)
		echo "If You Were Experiencing Issues, Try Update Or Visit SNBForums/Github For Support"
		echo "https://github.com/Adamm00/IPSet_ASUS"
		echo
		while true; do
			echo "[!] Warning - This Will Delete All Files In The Skynet Directory"
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
					if grep -qE "^swapon .* # Skynet" /jffs/scripts/post-mount; then
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
									echo "[i] Removing Skynet Generated SWAP File"
									sed -i '\~ Skynet ~d' /jffs/scripts/post-mount /jffs/scripts/unmount
									sync; echo 3 > /proc/sys/vm/drop_caches
									swapoff -a
									rm -rf "$swaplocation"
									break
								;;
								2)
									break
								;;
								e|exit)
									echo "[*] Exiting!"
									echo; exit 0
								;;
								*)
									echo "[*] $removeswap Isn't An Option!"
									echo
								;;
							esac
						done
					fi
					echo "[i] Unloading Skynet Components"
					Purge_Logs "all"
					Unload_Cron "all"
					Kill_Lock
					Unload_IPTables
					Unload_IOTTables
					Unload_LogIPTables
					Unload_IPSets
					Uninstall_WebUI_Page
					nvram set fw_log_x=none
					nvram commit
					echo "[i] Deleting Skynet Files"
					sed -i '\~# Skynet~d' /jffs/scripts/firewall-start /jffs/scripts/services-stop /jffs/scripts/service-event /jffs/configs/profile.add /jffs/configs/dnsmasq.conf.add
					service restart_dnsmasq >/dev/null 2>&1
					rm -rf "/jffs/addons/shared-whitelists/shared-Skynet-whitelist" "/jffs/addons/shared-whitelists/shared-Skynet2-whitelist" "${skynetloc}" "/jffs/scripts/firewall" "/opt/bin/firewall" "/tmp/skynet.lock" "/tmp/skynet"
					if [ -f "/opt/etc/syslog-ng.d/skynet" ]; then
						rm -rf "/opt/etc/syslog-ng.d/skynet"
						cp -p "/opt/share/syslog-ng/examples/firewall" "/opt/etc/syslog-ng.d"
						cp -p "/opt/share/logrotate/examples/firewall" "/opt/etc/logrotate"
						killall -HUP syslog-ng
					fi
					iptables -t raw -F
					echo "[i] Restarting Firewall Service"
					service restart_firewall
					exit 0
				;;
				2|e|exit)
					echo "[*] Exiting!"
					echo; exit 0
				;;
				*)
					echo "[*] $continue Isn't An Option!"
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

Spinner_End
Display_Header "9"
if [ "$nolog" != "2" ]; then Print_Log "$@"; echo; fi
if [ "$nocfg" != "1" ]; then Write_Config; fi
if [ "$lockskynet" = "true" ]; then rm -rf "/tmp/skynet.lock"; fi
if [ "$restartfirewall" = "1" ]; then service restart_firewall; echo; fi
if [ -n "$reloadmenu" ]; then echo; echo; printf "[i] Press Enter To Continue..."; read -r "continue"; exec "$0"; fi
printf '\033[?7h'