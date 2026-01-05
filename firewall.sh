#!/bin/sh
#############################################################################################################
#                                                                                                           #
#                           ███████╗██╗  ██╗██╗   ██╗███╗   ██╗███████╗████████╗                            #
#                           ██╔════╝██║ ██╔╝╚██╗ ██╔╝████╗  ██║██╔════╝╚══██╔══╝                            #
#                           ███████╗█████╔╝  ╚████╔╝ ██╔██╗ ██║█████╗     ██║                               #
#                           ╚════██║██╔═██╗   ╚██╔╝  ██║╚██╗██║██╔══╝     ██║                               #
#                           ███████║██║  ██╗   ██║   ██║ ╚████║███████╗   ██║                               #
#                           ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝╚══════╝   ╚═╝                               #
#                                                                                                           #
#                                 Router Firewall And Security Enhancements                                 #
#                             By Adamm -  https://github.com/Adamm00/IPSet_ASUS                             #
#                                            05/01/2026 - v8.0.9                                            #
#############################################################################################################


export PATH="/sbin:/bin:/usr/sbin:/usr/bin:$PATH"
printf '\033[?7l'
clear
sed -n '2,14p' "$0"
export LC_ALL=C
mkdir -p /tmp/skynet/lists
mkdir -p /jffs/addons/shared-whitelists
skynetloc="$(grep -ow "skynetloc=.* # Skynet" /jffs/scripts/firewall-start 2>/dev/null | grep -vE "^#" | awk '{print $1}' | cut -c 11-)"
skynetcfg="${skynetloc}/skynet.cfg"
skynetlog="${skynetloc}/skynet.log"
skynetevents="${skynetloc}/events.log"
skynetipset="${skynetloc}/skynet.ipset"
LOCK_FILE="/tmp/skynet.lock"

# Default to the NVRAM’s WAN interface name, but if the protocol is PPPoE, override to ppp0
iface="$(nvram get wan0_ifname)"
[ "$(nvram get wan0_proto)" = "pppoe" ] && iface="ppp0"

trap 'Release_Lock' INT TERM EXIT

case "$1" in
	uninstall|disable) ;;  # Skip NTP check for these modes
	*)
		ntptimer="0"
		while [ "$(nvram get ntp_ready)" != "1" ] && [ "$ntptimer" -lt "300" ]; do
			ntptimer=$((ntptimer + 1))
			if [ "$ntptimer" -eq 60 ]; then
				echo
				Log info -s "Waiting for NTP to synchronize..."
			fi
			sleep 1
		done
		if [ "$ntptimer" -ge 300 ]; then
			Log error -s "NTP synchronization failed after 5 minutes. Please check your configuration!"
			echo
			exit 1
		fi
	;;
esac
stime="$(date +%s)"

# If we haven’t yet determined an install directory and the script is running in a real terminal,
# force the command to “install” so the installer logic kicks in automatically.
if [ -z "${skynetloc}" ] && tty >/dev/null 2>&1; then
	set "install"
fi

###############
#- Functions -#
###############

Check_Lock() {
	# Open FD 9 for locking
	exec 9<>"$LOCK_FILE"

	# Try non-blocking lock
	if ! flock -n 9; then
		locked_cmd=$(cut -d'|' -f1 "$LOCK_FILE" 2>/dev/null)
		locked_pid=$(cut -d'|' -f2 "$LOCK_FILE" 2>/dev/null)
		lock_timestamp=$(cut -d'|' -f3 "$LOCK_FILE" 2>/dev/null)
		current_time=$(date +%s)

		# Re-entrant lock handling
		if [ "$locked_pid" = "$$" ]; then
			return 0
		fi

		# If we have a non-empty PID and that process exists
		if [ -n "$locked_pid" ] && [ -d "/proc/$locked_pid" ]; then
			age=$(( current_time - lock_timestamp ))

			if [ "$age" -gt 1800 ] 2>/dev/null; then
				# Stale lock: kill and re-acquire
				if kill "$locked_pid" 2>/dev/null; then
					Log info -s "Killed stale Skynet process (pid=$locked_pid) after $age seconds"
				fi
				: > "$LOCK_FILE"
				if ! flock -n 9; then
					Log error -s "Lock acquisition failed after killing stale process - Exiting (pid=$locked_pid)"
					echo; exit 1
				fi
			else
				# Active lock held by running process
				Log error -s "Lock File Detected ($locked_cmd) (pid=$locked_pid, runtime=${age}s) - Exiting"
				echo; exit 1
			fi
		else
			# We *know* flock says the file is locked, but the metadata is missing
			# or corrupt. That usually means another Skynet instance is in the
			# middle of writing the lock line. Safer to just bail.
			Log error -s "Lock file busy but metadata invalid (pid='$locked_pid') - another Skynet instance is running - Exiting"
			echo; exit 1
		fi
	fi

	# We now hold the lock — record this invocation
	: > "$LOCK_FILE"
	echo "$0 $*|$$|$(date +%s)" >&9
}

Release_Lock() {
	[ ! -f "$LOCK_FILE" ] && exec 9>&- && return

	pid=$(cut -d'|' -f2 "$LOCK_FILE")

	[ "$pid" != "$$" ] && return

	# We own the lock
	exec 9>&-
	rm -f "$LOCK_FILE"
}

Find_Install_Dir() {
	# Skip for installer/info commands
	case "$1" in
		install|uninstall|disable|update|restart|info) return 0 ;;
	esac

	if [ ! -d "${skynetloc}" ] || [ ! -w "${skynetloc}" ]; then
		Check_Lock "$@"

		MAX_RETRIES=10
		attempt=1

		# Wait until skynetloc exists as a directory and is writable
		while [ "$attempt" -le "$MAX_RETRIES" ] && { [ ! -d "$skynetloc" ] || [ ! -w "$skynetloc" ]; }; do
			Log info -s "USB install directory not ready — sleeping 10s ($attempt/$MAX_RETRIES)"
			sleep 10
			attempt=$(( attempt + 1 ))
		done

		# Final verification
		if [ ! -d "$skynetloc" ] || [ ! -w "$skynetloc" ]; then
			Log error -s "Problem with USB install location — please fix immediately!"
			Log error -s "To change location run: sh $0 install"
			echo
			exit 1
		fi
	fi
}

# Prints in color if either stdout or stderr is a terminal, otherwise plain
Print_Colored() {
	# $1 = ANSI color code (e.g. "1;31"), $2 = text
	if [ -t 1 ] || [ -t 2 ]; then
		printf '\033[%sm%s\033[0m\n' "$1" "$2"
	else
		printf '%s\n' "$2"
	fi
}

# Specific wrappers
Red()   { Print_Colored '1;31' "$1"; }
Grn()   { Print_Colored '1;32' "$1"; }
Blue()  { Print_Colored '1;36' "$1"; }
Ylow()  { Print_Colored '1;33' "$1"; }

# Check if a swap file (not just partition) is active
Check_Swap() {
	grep -qsF "file" "/proc/swaps"
}

Check_Settings() {
	# Grab and set local version
	localver="$(Filter_Version < "$0")"
	
	# require config file
	if [ ! -f "$skynetcfg" ]; then
		Log error -s "Configuration File Not Detected - Please Use ( sh $0 install ) To Continue"
		echo; exit 1
	fi

	# SWAP Checks
	swaplocation="$(awk 'NR==2 { print $1 }' /proc/swaps)"

	if [ -z "$swaplocation" ] && ! Check_Swap; then
		Log error -s "Skynet Requires A SWAP File - Install One ( $0 debug swap install )"
		echo; exit 1
	fi

	if Check_Swap && [ -z "$(grep -E 'swapon [^#]+' /jffs/scripts/post-mount | cut -d ' ' -f2)" ]; then
		Log error -s "SWAPON Entry Missing - Fix This By Running ( $0 debug swap uninstall ) Then ( $0 debug swap install )"
		echo; exit 1
	fi

	if grep -q '^partition' /proc/swaps; then
		Log error -s "SWAP Partitions Not Supported - Please Use SWAP File"
		echo; exit 1
	fi

	# warn if too small (<1GB)
	swap_kb=$(du -k "$swaplocation" 2>/dev/null | awk '{print $1}') || swap_kb=0
	if [ "$swap_kb" -gt 0 ] && [ "$swap_kb" -lt 1048576 ]; then
		Log error -s "SWAP File Too Small (<1GB) - Please Fix Immediately!"
	fi

	# load banmalware and update cronjobs
	case "$banmalwareupdate" in
		daily)  
			Load_Cron banmalwaredaily 
		;;
		weekly) 
			Load_Cron banmalwareweekly 
		;;
	esac

	if Is_Enabled "$autoupdate"; then
		Load_Cron "autoupdate"
	else
		Load_Cron "checkupdate"
	fi

	# ensure firewall symlink & alias
	if [ -d "/opt/bin" ] && [ ! -L "/opt/bin/firewall" ]; then
		ln -s /jffs/scripts/firewall /opt/bin
	fi

	if ! grep -F "sh /jffs/scripts/firewall" /jffs/configs/profile.add; then
		echo "alias firewall=\"sh /jffs/scripts/firewall\" # Skynet" >> /jffs/configs/profile.add
	fi

	# enable jffs2_scripts & fw_enable_x
	if [ "$(nvram get jffs2_scripts)" != "1" ]; then
		nvram set jffs2_scripts=1
		nvram commit
		Log info -s "Custom JFFS Scripts Enabled - Please Manually Reboot To Apply Changes"
	fi

	if [ "$(nvram get fw_enable_x)" != "1" ]; then
		nvram set fw_enable_x=1
		nvram commit
		restartfirewall="1"
	fi

	case "$(nvram get fw_log_x)" in
		drop|both) 
		;;
		*) 
			nvram set fw_log_x=drop
			nvram commit
			restartfirewall=1
		;;
	esac

	# set syslog location on newer models that use /jffs
	pids=$(pidof syslogd) || pids=
	for pid in $pids; do
		exe_path=$(readlink "/proc/$pid/exe") || continue
		[ "$exe_path" != "/bin/busybox" ] && continue
		if grep -qF '/jffs/syslog.log' "/proc/$pid/cmdline"; then
			syslogloc="/jffs/syslog.log"
			syslog1loc="/jffs/syslog.log-1"
			break
		fi
	done

	# scribe plugin install
	if [ -f "/opt/bin/scribe" ] && [ ! -f "/opt/etc/syslog-ng.d/skynet" ] && [ -f "/opt/share/syslog-ng/examples/skynet" ]; then
		Log info -s "Installing Scribe Plugin"
		rm -rf "/opt/etc/syslog-ng.d/firewall" "/opt/etc/logrotate/firewall"
		cp -p "/opt/share/syslog-ng/examples/skynet" "/opt/etc/syslog-ng.d"
		syslogloc="$(grep -m1 "file(" "/opt/etc/syslog-ng.d/skynet" | awk -F '"' '{print $2}')"
		killall -HUP syslog-ng
	elif [ -f "/opt/bin/scribe" ] && [ -f "/opt/etc/syslog-ng.d/skynet" ] && [ "$syslogloc" = "/tmp/syslog.log" ]; then
		syslogloc="$(grep -m1 "file(" "/opt/etc/syslog-ng.d/skynet" | awk -F '"' '{print $2}')"
	fi

	if nvram get wan0_ipaddr | Is_PrivateIP; then
		Log error -s "Private WAN IP Detected $(nvram get wan0_ipaddr) - Please Put Your Modem In Bridge Mode / Disable CG-NAT"
	fi

	# Set default log size if not set
	if [ -z "$logsize" ]; then
		logsize="10"
	fi
}

Check_Connection() {
	# Usage:
	#   Check_Connection              # 1 attempt
	#   Check_Connection 5            # 5 attempts, 3s apart
	#   Check_Connection 5 10         # 5 attempts, 10s apart

	retries="${1:-1}"   # default: 1 attempt (backwards compatible)
	delay="${2:-3}"     # default: 3 seconds between attempts
	[ "$retries" -lt 1 ] && retries=1
	[ "$delay" -lt 1 ] && delay=1

	attempt=1
	while [ "$attempt" -le "$retries" ]; do
		# 1) Grab the numeric gateway IP from the routing table
		gw="$(route -n | awk '$1=="0.0.0.0"{print $2; exit}')"

		# 2) Quick ping gateway (1 s timeout) if we have a gateway
		if [ -n "$gw" ] && ping -c1 -W1 "$gw" >/dev/null 2>&1; then
			return 0
		fi

		# 3) Quick ping a reliable public IP (1 s timeout)
		if ping -c1 -W1 1.1.1.1 >/dev/null 2>&1; then
			return 0
		fi

		# 4) ARP fallback on the known $iface (1 s timeout) if we have a gateway
		if [ -n "$gw" ] && arping -c1 -w1 -I "$iface" "$gw" >/dev/null 2>&1; then
			return 0
		fi

		# If this wasn't the last attempt, wait and retry
		if [ "$attempt" -lt "$retries" ]; then
			sleep "$delay"
		fi

		attempt=$((attempt + 1))
	 done

	# Final failure: print a single message like the original function
	if [ -z "$gw" ]; then
		Log error -s "Connection Error Detected - Unable To Determine Gateway Or Reach Public IP"
	else
		Log error -s "Connection Error Detected - Unable To Reach Gateway ($gw) Or Public IP"
	fi

	return 1
}

Check_Files() {
	# 1) Ensure each script has a proper shebang
	for name in "$@"; do
		path="/jffs/scripts/$name"
		if [ ! -f "$path" ]; then
			echo '#!/bin/sh' > "$path"
			echo >> "$path"
		elif ! head -n1 "$path" | grep -q '^#!/bin/sh'; then
			sed -i '1s~^~#!/bin/sh\n~' "$path"
		fi
	done

	# service-event: inject debug‑genstats if missing
	if ! grep -vE '^#' /jffs/scripts/service-event | grep -qF 'sh /jffs/scripts/firewall debug genstats'; then
		sed -i '\~# Skynet~d' /jffs/scripts/service-event
		echo "if [ \"\$1\" = \"start\" ] && [ \"\$2\" = \"SkynetStats\" ]; then sh /jffs/scripts/firewall debug genstats; fi # Skynet" \
			>> /jffs/scripts/service-event
	fi

	# 3) unmount: ensure swapoff entry
	if ! grep -qE '^swapoff ' /jffs/scripts/unmount; then
		sed -i '\~swapoff ~d' /jffs/scripts/unmount
		echo 'swapoff -a 2>/dev/null # Skynet' >> /jffs/scripts/unmount
	fi

	# 4) services-stop: ensure firewall‑save alias
	if ! grep -vE '^#' /jffs/scripts/services-stop | grep -qF 'sh /jffs/scripts/firewall save'; then
		echo 'sh /jffs/scripts/firewall save # Skynet' >> /jffs/scripts/services-stop
	fi

	# 5) post-mount: ensure at least one blank line
	if [ "$(wc -l < /jffs/scripts/post-mount)" -lt 2 ]; then
		echo >> /jffs/scripts/post-mount
	fi

	# 6) final perms
	chmod 755 /jffs/scripts/firewall \
				/jffs/scripts/firewall-start \
				/jffs/scripts/services-stop \
				/jffs/scripts/service-event \
				/jffs/scripts/post-mount \
				/jffs/scripts/unmount
}

Check_Security() {
	if Is_Enabled "$securemode"; then
		# Disable WAN SSH Access for ASUSWRT-Merlin
		if [ "$(nvram get sshd_enable)" = "1" ] && [ "$(uname -o)" = "ASUSWRT-Merlin" ]; then
			Log error -s "Insecure Setting Detected - Disabling WAN SSH Access"
			nvram set sshd_enable="2"
			nvram commit
			restartfirewall="1"
		fi

		# Disable WAN SSH Access for ASUSWRT-Merlin-LTS
		if [ "$(nvram get sshd_wan)" = "1" ] && [ "$(uname -o)" = "ASUSWRT-Merlin-LTS" ]; then
			Log error -s "Insecure Setting Detected - Disabling WAN SSH Access"
			nvram set sshd_wan="0"
			nvram commit
			restartfirewall="1"
		fi

		# Disable WAN GUI Access
		if [ "$(nvram get misc_http_x)" = "1" ]; then
			Log error -s "Insecure Setting Detected - Disabling WAN GUI Access"
			nvram set misc_http_x="0"
			nvram commit
			restartfirewall="1"
		fi
	fi

	# Check for PPTP VPN compromise
	if [ "$(nvram get pptpd_enable)" = "1" ] && nvram get pptpd_clientlist | grep -qE 'i[0-9]{7}|p[0-9]{7}'; then
		Log error -s "PPTP VPN Server Shows Signs Of Compromise - Disabling Immediately!"
		nvram set pptpd_enable="0"
		nvram set pptpd_broadcast="0"
		nvram commit
		service stop_pptpd
		service restart_samba
		restartfirewall="1"
	fi

	# Detect and handle VPNFilter malware
	if [ -e "/var/run/tor" ] || [ -e "/var/run/torrc" ] || [ -e "/var/run/tord" ] || [ -e "/var/run/vpnfilterm" ] || [ -e "/var/run/vpnfilterw" ]; then
		Log error -s "Suspected VPNFilter Malware Found - Investigate Immediately!"
		Log error -s "Caching Potential VPNFilter Malware: ${skynetloc}/vpnfilter.tar.gz"
		tar -czf "${skynetloc}/vpnfilter.tar.gz" "/var/run/tor" "/var/run/torrc" "/var/run/tord" "/var/run/vpnfilterm" "/var/run/vpnfilterw" >/dev/null 2>&1
		rm -rf "/var/run/tor" "/var/run/torrc" "/var/run/tord" "/var/run/vpnfilterm" "/var/run/vpnfilterw"
		restartfirewall="1"
	fi

	# Detect chkupdate.sh malware
	if [ -f "/jffs/chkupdate.sh" ] || [ -f "/tmp/update" ] || [ -f "/tmp/.update.log" ] || [ -f "/jffs/runtime.log" ] || grep -qsF "upgrade.sh" "/jffs/scripts/openvpn-event"; then
		Log error -s "Warning! Router Malware Detected (chkupdate.sh) - Investigate Immediately!"
		grep -hoE '([0-9]{1,3}\.){3}[0-9]{1,3}' "/jffs/chkupdate.sh" "/tmp/update" "/tmp/.update.log" "/jffs/runtime.log" "/jffs/scripts/openvpn-event" 2>/dev/null | awk '!x[$0]++' | while IFS= read -r ip; do
			echo "add Skynet-Blacklist $ip comment \"Malware: chkupdate.sh\""
		done | ipset restore -!
	fi

	# Detect updater malware
	if [ -f "/jffs/updater" ] || [ -f "/jffs/p32" ] || [ -f "/tmp/pawns-cli" ] || [ -f "/tmp/updateservice" ] || nvram get "jffs2_exec" | grep -qF "/jffs/updater" || nvram get "script_usbmount" | grep -qF "/jffs/updater" || nvram get "script_usbumount" | grep -qF "/jffs/updater" || nvram get "vpn_server_custom" | grep -qF "/jffs/updater" || nvram get "vpn_server1_custom" | grep -qF "/jffs/updater" || cru l | grep -qF "/jffs/updater"; then
		Log error -s "Warning! Router Malware Detected (/jffs/updater) - Investigate Immediately!"
		Log error -s "Caching Potential Updater Malware: ${skynetloc}/malwareupdater.tar.gz"
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

IPSet_Wrapper() {
	mode="$1"       # add | del | import | flush | deport
	setname="$2"
	input="$3"      # IP, file, or -
	filtermode="$4"   # --filtermode or auto-detect
	comment="$5"

	# Validate allowed sets
	case "$setname" in
		Skynet-Whitelist|Skynet-Blacklist|Skynet-IOT|Skynet-BlockedRanges) ;;
		*) echo "[✘] Invalid IPSet: $setname" >&2; return 1 ;;
	esac

	# Validate mode
	case "$mode" in
		add|del|import|flush|deport) ;;
		*) echo "[✘] Invalid mode: $mode" >&2; return 1 ;;
	esac

	# Fast flush path
	if [ "$mode" = "flush" ]; then
		ipset flush "$setname"
		return 0
	fi

	# Input source
	if [ "$input" = "-" ]; then
		data="$(cat)"
	elif [ -f "$input" ]; then
		data="$(cat "$input")"
	else
		data="$input"
	fi

	#  Auto-detect if input is raw ipset format (restore-ready)
	if [ "$mode" = "import" ] && echo "$data" | head -n 1 | grep -qE '^(add|del) '; then
		echo "$data" | ipset restore -!
		return 0
	fi

	#  Filter unless disabled
	case "$filtermode" in
		nofilter) 
		;;  # Skip all filtering
		skip-filter-ip) 
			data="$(echo "$data" | Filter_PrivateIP)" 
		;;
		*) 		
			data="$(echo "$data" | Filter_IP | Filter_PrivateIP)" 
		;;
	esac

	#  DEPORT: selective delete only
	if [ "$mode" = "deport" ]; then
		echo "$data" | awk -v set="$setname" '{ printf "del %s %s\n", set, $1 }' | ipset restore -!
		return 0
	fi

	#  ADD / DEL / IMPORT
	echo "$data" | awk -v mode="$mode" -v set="$setname" -v comment="$comment" '
	{
		ip = $1
		if (mode == "add" || mode == "import") {
			if (comment != "")
				printf "add %s %s comment \"%s\"\n", set, ip, comment
			else
				printf "add %s %s\n", set, ip
		} else if (mode == "del") {
			printf "del %s %s\n", set, ip
		}
	}' | ipset restore -!
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
	if Is_Enabled "$logmode"; then
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
		if [ "$(nvram get fw_log_x)" = "drop" ] || [ "$(nvram get fw_log_x)" = "both" ] && Is_Enabled "$loginvalid"; then
			pos6="$(iptables --line -nL logdrop | grep -F "DROP" | awk '{print $1}')"
			iptables -I logdrop "$pos6" -m state --state NEW -j LOG --log-prefix "[BLOCKED - INVALID] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		fi
		if Is_Enabled "$iotblocked" && Is_Enabled "$iotlogging"; then
			pos7="$(iptables --line -nL FORWARD | grep -F "Skynet-IOT" | grep -F "DROP" | awk '{print $1}')"
			iptables -I FORWARD "$pos7" -i br+ -m set --match-set Skynet-IOT src -j LOG --log-prefix "[BLOCKED - IOT] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		fi
	fi
}

Unload_IOTTables() {
	if Is_Enabled "$iotblocked"; then
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
	if Is_Enabled "$iotblocked"; then
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
	raw_rules=$(iptables-save -t raw)
	filter_rules=$(iptables-save -t filter)

	#6: WireGuard DROP
	if [ "$(nvram get wgs_enable)" = "1" ]; then
		echo "$raw_rules" | grep -Fq -- '-A PREROUTING -i wgs+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP' || fail="${fail}#6 "
	fi

	#7: OpenVPN DROP
	if [ "$(nvram get vpn_server1_state)" != "0" ] || [ "$(nvram get vpn_server2_state)" != "0" ]; then
		echo "$raw_rules" | grep -Fq -- '-A PREROUTING -i tun2+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP' || fail="${fail}#7 "
	fi

	#8: Inbound on $iface
	if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then
		echo "$raw_rules" | grep -Fq -- "-A PREROUTING -i $iface -m set ! --match-set Skynet-MasterWL src -m set --match-set Skynet-Master src -j DROP" || fail="${fail}#8 "
	fi

	#9 & #10: Outbound on br+ and OUTPUT
	if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
		echo "$raw_rules" | grep -Fq -- '-A PREROUTING -i br+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP' || fail="${fail}#9 "
		echo "$raw_rules" | grep -Fq -- '-A OUTPUT -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP' || fail="${fail}#10 "
	fi

	#11–17: IOT blocking
	if Is_Enabled "$iotblocked"; then
		if [ "$(nvram get wgs_enable)" = "1" ]; then
			echo "$filter_rules" | grep -Fq -- '-A FORWARD -i br+ -o wgs+ -m set --match-set Skynet-IOT src -j ACCEPT' || fail="${fail}#11 "
		fi
		if [ "$(nvram get vpn_server1_state)" != "0" ] || [ "$(nvram get vpn_server2_state)" != "0" ]; then
			echo "$filter_rules" | grep -Fq -- '-A FORWARD -i br+ -o tun2+ -m set --match-set Skynet-IOT src -j ACCEPT' || fail="${fail}#12 "
		fi
		echo "$filter_rules" | grep -Fq -- '-A FORWARD -i br+ -m set --match-set Skynet-IOT src -j DROP' || fail="${fail}#13 "
		if [ -n "$iotports" ]; then
			if [ "$iotproto" = "all" ] || [ "$iotproto" = "udp" ]; then
				echo "$filter_rules" | grep -Fq -- "-A FORWARD -i br+ -m set --match-set Skynet-IOT src -o $iface -p udp -m udp -m multiport --dports $iotports -j ACCEPT" || fail="${fail}#14 "
			fi
			if [ "$iotproto" = "all" ] || [ "$iotproto" = "tcp" ]; then
				echo "$filter_rules" | grep -Fq -- "-A FORWARD -i br+ -m set --match-set Skynet-IOT src -o $iface -p tcp -m tcp -m multiport --dports $iotports -j ACCEPT" || fail="${fail}#15 "
			fi
		else
			if [ "$iotproto" = "all" ] || [ "$iotproto" = "udp" ]; then
				echo "$filter_rules" | grep -Fq -- "-A FORWARD -i br+ -o $iface -p udp -m set --match-set Skynet-IOT src -m udp --dport 123 -j ACCEPT" || fail="${fail}#16 "
			fi
			if [ "$iotproto" = "all" ] || [ "$iotproto" = "tcp" ]; then
				echo "$filter_rules" | grep -Fq -- "-A FORWARD -i br+ -o $iface -p tcp -m set --match-set Skynet-IOT src -m tcp --dport 123 -j ACCEPT" || fail="${fail}#17 "
			fi
		fi
	fi

	#18–24: LOG rules
	if Is_Enabled "$logmode"; then
		#18: OpenVPN LOG
		if { [ "$(nvram get vpn_server1_state)" != "0" ] || [ "$(nvram get vpn_server2_state)" != "0" ]; }; then
			echo "$raw_rules" \
			| grep -Fq -- '-A PREROUTING -i tun2+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] "' || fail="${fail}#18 "
		fi

		#19: WireGuard LOG
		if [ "$(nvram get wgs_enable)" = "1" ]; then
			echo "$raw_rules" \
			| grep -Fq -- '-A PREROUTING -i wgs+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] "' || fail="${fail}#19 "
		fi

		#20: IoT LOG
		if Is_Enabled "$iotblocked" && Is_Enabled "$iotlogging"; then
			echo "$filter_rules" \
			| grep -Fq -- '-A FORWARD -i br+ -m set --match-set Skynet-IOT src -j LOG --log-prefix "[BLOCKED - IOT] "' || fail="${fail}#20 "
		fi

		#21: Inbound LOG
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then
			echo "$raw_rules" \
			| grep -Fq -- "-A PREROUTING -i $iface -m set ! --match-set Skynet-MasterWL src -m set --match-set Skynet-Master src -j LOG --log-prefix \"[BLOCKED - INBOUND] \"" || fail="${fail}#21 "
		fi

		#22: Outbound PREROUTING LOG
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
			echo "$raw_rules" \
			| grep -Fq -- '-A PREROUTING -i br+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] "' || fail="${fail}#22 "
		fi

		#23: Outbound OUTPUT LOG
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
			echo "$raw_rules" \
			| grep -Fq -- '-A OUTPUT -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] "' || fail="${fail}#23 "
		fi

		#24: Invalid LOG
		if [ "$(nvram get fw_log_x)" != "off" ] && Is_Enabled "$loginvalid"; then
			echo "$filter_rules" \
			| grep -Fq -- '-A logdrop -m state --state NEW -j LOG --log-prefix "[BLOCKED - INVALID] "' || fail="${fail}#24 "
		fi
	fi

	[ -n "$fail" ] && return 1 || return 0
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
	# If no argument or "all", reset $@ to the full list
	if [ -z "$1" ] || [ "$1" = "all" ]; then
		set -- "save" "banmalware" "autoupdate" "checkupdate" "genstats"
	fi

	for job in "$@"; do
		case "$job" in
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
			*)
				echo "[*] Warning: Unknown Cron Job '$job'"
			;;
		esac
	done
}

Load_Cron() {
	for job in "$@"; do
		case "$job" in
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
				echo "[*] Warning: Unknown Cron Job '$job'"
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

Is_Numeric() {
	case "$1" in
		*[!0-9]*) return 1 ;;  # If any non-digit, fail
		"")       return 1 ;;  # If empty, fail
		*)        return 0 ;;  # Otherwise, success
	esac
}

Strip_Domain() {
	sed 's~http[s]*://~~;s~/.*~~;s~www\.~~g;\~^$~d' | awk '!x[$0]++'
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

Generate_Ban_Stats() {
	case "$1" in
		1)
			if Is_Enabled "$lookupcountry"; then
				country="$(curl -fsSL --retry 3 --max-time 6 -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno)" "https://api.db-ip.com/v2/free/${statdata}/countryCode/" 2>/dev/null | grep -E '^[A-Z]{2}$' || echo '**')"
			fi
			# banreason: single AWK for both blacklist and CIDR, star only on CIDR
			banreason="$(
				grep -E '^add Skynet-(Blacklist|BlockedRanges) ' "$skynetipset" |
				awk -v ip="$statdata" '
					function trim(s) { sub(/^ +| +$/, "", s); return s }
					function do_print(cidr) {
					pos = index($0, "comment \"")
					if (pos) {
						s = substr($0, pos+9); sub(/"$/, "", s)
						printf "%s", trim(s)
						if (cidr) printf "*"
						printf "\n"
					}
					}
					BEGIN { split(ip,A,"."); ipn=A[1]*16777216 + A[2]*65536 + A[3]*256 + A[4] }
					# exact blacklist
					$1=="add" && $2=="Skynet-Blacklist" && $3==ip { do_print(0); exit }
					# CIDR ranges
					$1=="add" && $2=="Skynet-BlockedRanges" {
					split($3,P,"/"); net=P[1]; prefix=P[2]
					split(net,B,"."); netn=B[1]*16777216 + B[2]*65536 + B[3]*256 + B[4]
					if (prefix==32 && ipn==netn)              { do_print(0); exit }
					else if (prefix==24 && A[1]==B[1]&&A[2]==B[2]&&A[3]==B[3]) { do_print(1); exit }
					else if (prefix==16 && A[1]==B[1]&&A[2]==B[2])           { do_print(1); exit }
					else if (prefix==8  && A[1]==B[1])                       { do_print(1); exit }
					else {
						sh=32-prefix; div=1
						for(i=0;i<sh;i++) div*=2
						if (int(ipn/div)==int(netn/div)) { do_print(1); exit }
					}
					}
				'
			)"
			[ -z "$banreason" ] && ! ipset -q test Skynet-Blacklist "$ipaddr" && ! ipset -q test Skynet-BlockedRanges "$ipaddr" && banreason="No Longer Blacklisted"
			[ "${#banreason}" -gt 45 ] && banreason="$(printf '%s' "$banreason" | cut -c1-45)"
			printf '%-15s %-4s | %-55s | %-45s | %-60s \n' "$statdata" "$country" "https://otx.alienvault.com/indicator/ip/${statdata}" "$banreason" "$(grep -F "$statdata" /tmp/skynet/skynetstats.txt | awk '{print $1}' | xargs)"
		;;
		2)
			hits="$(echo "$statdata" | awk '{print $1}')"
			ipaddr="$(echo "$statdata" | awk '{print $2}')"
			if Is_Enabled "$lookupcountry"; then
				country="$(curl -fsSL --retry 3 --max-time 6 -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno)" "https://api.db-ip.com/v2/free/${ipaddr}/countryCode/" 2>/dev/null | grep -E '^[A-Z]{2}$' || echo '**')"
			fi
			# banreason: single AWK for both blacklist and CIDR, star only on CIDR
			banreason="$(
				grep -E '^add Skynet-(Blacklist|BlockedRanges) ' "$skynetipset" |
				awk -v ip="$ipaddr" '
					function trim(s) { sub(/^ +| +$/, "", s); return s }
					function do_print(cidr) {
					pos = index($0, "comment \"")
					if (pos) {
						s = substr($0, pos+9); sub(/"$/, "", s)
						printf "%s", trim(s)
						if (cidr) printf "*"
						printf "\n"
					}
					}
					BEGIN { split(ip,A,"."); ipn=A[1]*16777216 + A[2]*65536 + A[3]*256 + A[4] }
					# exact blacklist
					$1=="add" && $2=="Skynet-Blacklist" && $3==ip { do_print(0); exit }
					# CIDR ranges
					$1=="add" && $2=="Skynet-BlockedRanges" {
					split($3,P,"/"); net=P[1]; prefix=P[2]
					split(net,B,"."); netn=B[1]*16777216 + B[2]*65536 + B[3]*256 + B[4]
					if (prefix==32 && ipn==netn)              { do_print(0); exit }
					else if (prefix==24 && A[1]==B[1]&&A[2]==B[2]&&A[3]==B[3]) { do_print(1); exit }
					else if (prefix==16 && A[1]==B[1]&&A[2]==B[2])           { do_print(1); exit }
					else if (prefix==8  && A[1]==B[1])                       { do_print(1); exit }
					else {
						sh=32-prefix; div=1
						for(i=0;i<sh;i++) div*=2
						if (int(ipn/div)==int(netn/div)) { do_print(1); exit }
					}
					}
				'
			)"
			[ -z "$banreason" ] && ! ipset -q test Skynet-Blacklist "$ipaddr" && ! ipset -q test Skynet-BlockedRanges "$ipaddr" && banreason="No Longer Blacklisted"
			[ "${#banreason}" -gt 45 ] && banreason="$(printf '%s' "$banreason" | cut -c1-45)"
			printf '%-10s | %-15s %-4s | %-55s | %-45s | %-60s\n' "${hits}x" "$ipaddr" "$country" "https://otx.alienvault.com/indicator/ip/${ipaddr}" "$banreason" "$(grep -F "$ipaddr" /tmp/skynet/skynetstats.txt | awk '{print $1}' | xargs)"
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
			printf '╔══════════════════════════════════════════╦══════════════════╦══════════════════════╦══════════════════════╗\n'
			printf '║ %-40s ║ %-16s ║ %-20s ║ %-20s ║\n' "Device Name" "Local IP" "MAC Address" "Status"
			printf '╠══════════════════════════════════════════╬══════════════════╬══════════════════════╬══════════════════════╣\n'
		;;
		7)
			printf '╔═══════════════════════════════════╦═══════════════════════════════════════════════════════════════════════╗\n'
			printf '║ %-33s ║ %-69s ║\n' "Test Description" "Result"
			printf '╠═══════════════════════════════════╬═══════════════════════════════════════════════════════════════════════╣\n'
		;;
		8)
			printf '╔═══════════════════════════════════╦═══════════════════════════════════════════════════════════════════════╗\n'
			printf '║ %-33s ║ %-69s ║\n' "Setting" "Status"
			printf '╠═══════════════════════════════════╬═══════════════════════════════════════════════════════════════════════╣\n'
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

Command_Not_Recognized() {
	Ylow "Command Not Recognized, Please Try Again"
	Ylow "For Help:   https://github.com/Adamm00/IPSet_ASUS#help"
	Ylow "Common Issues: https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
	echo
	exit 2
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

Domain_Lookup() {
	domain="$1"
	timeout="$2"
	result_file="/tmp/skynet/ns.$$.$(echo "$domain" | tr -c 'A-Za-z0-9' '_').tmp"

	(
		if [ -n "$3" ]; then
			nslookup "$domain" "$3" > "$result_file" 2>/dev/null
		else
			nslookup "$domain" > "$result_file" 2>/dev/null
		fi
	) &
	lookup_pid=$!
	( sleep "$timeout"; kill "$lookup_pid" 2>/dev/null ) &
	watchdog_pid=$!

	wait "$lookup_pid" 2>/dev/null
	kill "$watchdog_pid" 2>/dev/null

	if [ -s "$result_file" ]; then
		awk -v q="$domain" '
			BEGIN {
				# normalise query: strip trailing dot if present
				gsub(/\.$/, "", q)
				in_query = 0
			}

			# When we hit the Name: line that matches the query,
			# start treating subsequent Address lines as belonging
			# to this lookup (including CNAME target blocks).
			/^Name:[[:space:]]*/ {
				name = $2
				gsub(/\.$/, "", name)
				if (!in_query && name == q)
					in_query = 1
				next
			}

			# Only process Address lines once we are "inside" the
			# query section. This skips the Server: block entirely.
			in_query && /Address/ {
				for (i = 1; i <= NF; i++) {
					if ($i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/)
						print $i
				}
			}
		' "$result_file"
	fi

	rm -f "$result_file"
}

Save_IPSets() {
	if Check_IPSets; then
		{ ipset save Skynet-Whitelist; ipset save Skynet-WhitelistDomains; ipset save Skynet-Blacklist; ipset save Skynet-BlockedRanges; ipset save Skynet-Master; ipset save Skynet-MasterWL; ipset save Skynet-IOT; } > "$skynetipset" 2>/dev/null
	fi
}

Unban_PrivateIP() {
	if Is_Enabled "$unbanprivateip" && Is_Enabled "$logmode"; then
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
	if Is_Enabled "$banaiprotect" && [ -s /jffs/.sys/AiProtectionMonitor/AiProtectionMonitor.db ]; then

		# Remove previous AiProtect entries
		sed '\~add Skynet-Blacklist ~!d;\~BanAiProtect~!d;s~ comment.*~~;s~add~del~g' "$skynetipset" | ipset restore -!

		# Add static IPs from SRC field
		sqlite3 /jffs/.sys/AiProtectionMonitor/AiProtectionMonitor.db "SELECT src FROM monitor;" \
			| awk '!x[$0]++' \
			| Filter_IP | Filter_PrivateIP \
			| awk '{printf "add Skynet-Blacklist %s comment \"BanAiProtect\"\n", $1 }' \
			| ipset restore -!

		# Collect DST domain resolutions in parallel, write directly to ipset
		(
			sqlite3 /jffs/.sys/AiProtectionMonitor/AiProtectionMonitor.db "SELECT dst FROM monitor;" \
				| awk '!x[$0]++' | Filter_OutIP | grep -v ":" \
				| while IFS= read -r domain; do
					{
						for ip in $(Domain_Lookup "$domain" 3 | Filter_PrivateIP); do
							echo "add Skynet-Blacklist $ip comment \"BanAiProtect: $domain\""
						done
					} &
				done
			wait
		) | ipset restore -!

	fi
}


Refresh_MBans() {
	if grep -qF "[Manual Ban] TYPE=Domain" "$skynetevents"; then
		awk '/\[Manual Ban\] TYPE=Domain/{if(!x[$9]++)print $9}' "$skynetevents" | sed 's~Host=~~g' > /tmp/skynet/mbans.list
		sed -i '\~\[Manual Ban\] TYPE=Domain~d;' "$skynetevents"
		sed '\~add Skynet-Blacklist ~!d;\~ManualBanD~!d;s~ comment.*~~;s~add~del~g' "$skynetipset" | ipset restore -!
		while IFS= read -r "domain"; do
		{
			for ip in $(Domain_Lookup "$domain" 3 | Filter_PrivateIP); do
				echo "add Skynet-Blacklist $ip comment \"ManualBanD: $domain\""
				echo "$(date +"%b %e %T") Skynet: [Manual Ban] TYPE=Domain SRC=$ip Host=$domain " >> "$skynetevents"
			done
		} &
		done < /tmp/skynet/mbans.list | ipset restore -!
		wait
		rm -rf /tmp/skynet/mbans.list
	fi
}

Refresh_MWhitelist() {
	if grep -qE "Manual Whitelist.* TYPE=Domain" "$skynetevents"; then
		awk '/Manual Whitelist.* TYPE=Domain/{if(!x[$9]++)print $9}' "$skynetevents" | sed 's~Host=~~g' > /tmp/skynet/mwhitelist.list
		sed -i '\~\[Manual Whitelist\] TYPE=Domain~d;' "$skynetevents"
		sed '\~add Skynet-Whitelist ~!d;\~ManualWlistD~!d;s~ comment.*~~;s~add~del~g' "$skynetipset" | ipset restore -!
		while IFS= read -r domain; do
			{
				for ip in $(Domain_Lookup "$domain" 3 | Filter_PrivateIP); do
					echo "add Skynet-Whitelist $ip comment \"ManualWlistD: $domain\""
					echo "$(date +"%b %e %T") Skynet: [Manual Whitelist] TYPE=Domain SRC=$ip Host=$domain " >> "$skynetevents"
				done
			} &
		done < /tmp/skynet/mwhitelist.list | ipset restore -!
		wait
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
	if Is_Enabled "$cdnwhitelist"; then
		{
			# Apple AS714 | Akamai AS12222 AS16625 | HighWinds AS33438 AS20446 | Fastly AS54113 | GitHub AS36459
			printf "AS714\nAS12222\nAS16625\nAS33438\nAS20446\nAS54113\nAS36459" | xargs -I {} sh -c "curl -fsSL --retry 3 --max-time 6 https://asn.ipinfo.app/api/text/list/{} | awk -v asn={} '/^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)([[:space:]]|$)/{printf \"add Skynet-Whitelist %s comment \\\"CDN-Whitelist: %s\\\"\\n\", \$1, asn }'"
			curl -fsSL --retry 3 --max-time 6 https://www.cloudflare.com/ips-v4 | awk '/^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)([[:space:]]|$)/{printf "add Skynet-Whitelist %s comment \"CDN-Whitelist: CloudFlare\"\n", $1 }'
			curl -fsSL --retry 3 --max-time 6 https://ip-ranges.amazonaws.com/ip-ranges.json | awk 'BEGIN{RS="(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\\/(1?[0-9]|2?[0-9]|3?[0-2]))?)"}{if(RT)printf "add Skynet-Whitelist %s comment \"CDN-Whitelist: Amazon\"\n", RT }'
			curl -fsSL --retry 3 --max-time 6 https://api.github.com/meta | awk 'BEGIN{RS="(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\\/(1?[0-9]|2?[0-9]|3?[0-2]))?)"}{if(RT)printf "add Skynet-Whitelist %s comment \"CDN-Whitelist: Github\"\n", RT }'
			curl -fsSL --retry 3 --max-time 6 https://endpoints.office.com/endpoints/worldwide?clientrequestid="$(awk '{printf "%s", $1}' /proc/sys/kernel/random/uuid)" | awk 'BEGIN{RS="(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\\/(1?[0-9]|2?[0-9]|3?[0-2]))?)"}{if(RT)printf "add Skynet-Whitelist %s comment \"CDN-Whitelist: Microsoft365\"\n", RT }'
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
	chmod 644 /jffs/configs/dnsmasq.conf.add
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
		Domain_Lookup "$domain" 3 127.0.0.1 >/dev/null 2>&1
	done &
	wait
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

show_stats_block() {
	# Arguments:
	# $1 = source         ("log" or "events")
	# $2 = pattern        (e.g. "IOT.*$proto")
	# $3 = field          ("SRC", "DST", or "" for full line)
	# $4 = title          (display title)
	# $5 = method         ("head" or "tail")
	# $6 = count          (number of entries)
	# $7 = header_id      (passed to Display_Header)
	# $8 = stats_mode     (passed to Generate_Ban_Stats)
	case "$1" in
		events) source_file=$skynetevents ;;
		*)      source_file=$skynetlog ;;
	esac

	pattern=$2
	field=$3
	title=$4
	method=$5
	count=$6
	header=${7:-1}
	stats_mode=${8:-1}

	Display_Header "9"
	Red "$title"
	Display_Header "$header"

	awk -v pat="$pattern" -v fld="$field=" -v mode="$stats_mode" -v mth="$method" '
		$0 ~ pat {
		pos = index($0, fld)
		if (fld != "" && pos > 0) {
			val = substr($0, pos + length(fld))
			sub(/[ ,].*/, "", val)
		} else if (fld == "") {
			val = $0
		} else {
			next
		}

		if (mode == 2) {
			hits[val]++
		} else {
			if (!(val in seen)) {
			order[++n] = val
			seen[val] = 1
			}
		}
		}
		END {
		if (mode == 2) {
			for (ip in hits) {
			printf "%7d %s\n", hits[ip], ip
			}
		} else {
			if (mth == "head") {
			for (i = n; i >= 1 && i > n - 1000; i--) print order[i]
			} else {
			for (i = 1; i <= n; i++) print order[i]
			}
		}
		}
	' "$source_file" | {
		if [ "$stats_mode" -eq 2 ]; then
			sort -nr | head -n "$count"
		else
			head -n "$count"
		fi
	} | while IFS= read -r statdata; do
		Generate_Ban_Stats "$stats_mode"
	done
}

Show_Associated_Domains() {
	if Is_Enabled "$extendedstats"; then
		# $1 = IP to search
		loghits="$(grep -E "reply.* is $1" /opt/var/log/dnsmasq* 2>/dev/null)"
		if [ -n "$loghits" ]; then
			Red "Associated Domain(s);"
			assdomains="$(echo "$loghits" | awk '{print $(NF-2)}' | Strip_Domain | Filter_OutIP | sort -u)"
			diversion_lists="$(cat /opt/share/diversion/list/blockinglist /opt/share/diversion/list/blacklist 2>/dev/null)"
			echo "$assdomains" | while IFS= read -r domain; do
				if printf '%s\n' "$diversion_lists" | grep -qE " (www\.)?${domain}$| (www\.)?${domain} "; then
					echo "$domain (Flagged By Diversion)"
				else
					echo "$domain"
				fi
			done
			echo;echo
		fi
	fi
}

Is_Enabled() {
	# $1 = variable value
	[ "$1" = "enabled" ]
}

Log() {
	# initialize defaults
	opt_s=0
	tag="Skynet"
	prefix=""

	# parse flags and level keywords
	while [ "$#" -gt 0 ]; do
		case "$1" in
		-s)
			# log to syslog and stderr
			opt_s=1
			shift
			;;
		-t)
			# custom syslog tag
			shift
			if [ "$#" -gt 0 ]; then
				tag="$1"
				shift
			fi
			;;
		info)
			prefix="[i] "
			shift
			;;
		error)
			prefix="[✘] "
			shift
			;;
		*)
			break
			;;
		esac
	done

	# finalize message
	msg="$prefix$*"

	if [ "$opt_s" -eq 1 ]; then
		# logger -s echoes to stderr
		logger -s -t "$tag" "$msg"
	else
		logger -t "$tag" "$msg"
		echo "$msg"
	fi
}

Run_Stats() {
		Purge_Logs
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
		fi
		printf '╔═════════════════════ Logging ═════════════════════════════════════════════════════════════════════════════╗\n'
		printf '║ %-20s │ %-82s ║\n' "Syslog Locations" "$syslogloc $syslog1loc"
		printf '║ %-20s │ %-82s ║\n' "Skynet Log"       "${skynetlog}"
		SZ="$(du -h "${skynetlog}" | awk '{print $1}')"
		printf '║ └── %-16s │ %-82s ║\n' "Used/Total" "$SZ / ${logsize}MB"
		Generate_Blocked_Events
		printf '║ %-20s │ %-82s ║\n' "Manual Bans"       "$(grep -Fc "Manual Ban" "$skynetevents")"
		printf '║ %-20s │ %-84s ║\n' "Monitor Span"      "$(grep -m1 -F "BLOCKED -" "$skynetlog" | awk '{printf "%s %s %s\n", $1, $2, $3}') → $(grep -F "BLOCKED -" "$skynetlog" | tail -1 | awk '{printf "%s %s %s\n", $1, $2, $3}')"
		printf '╚══════════════════════╧════════════════════════════════════════════════════════════════════════════════════╝\n\n\n'
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
						Command_Not_Recognized
					;;
				esac
			;;
			search)
				if Is_Enabled "$extendedstats"; then
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
						echo;echo
						Red "First Block Tracked On Port $4;"
						grep -m1 -F "PT=$4 " "$skynetlog"
						echo;echo
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
						echo;echo
						if [ -n "$found1" ]; then Red "Whitelist Reason;"; grep -F "add Skynet-Whitelist $(echo "$4" | cut -d '.' -f1-3)." "$skynetipset" | awk '{$1=$2=$4=""; print $0}' | tr -s " "; echo;echo; fi
						if [ -n "$found2" ] || [ -n "$found3" ]; then
							Red "Ban Reasons;"
							grep -E '^add Skynet-(Blacklist|BlockedRanges) ' "$skynetipset" | awk -v ip="$4" '
							function trim(s)      { sub(/^ +| +$/, "", s); return s }
							function do_print(suffix) {
								pos = index($0, "comment \"")
								if (pos) {
									s = substr($0, pos+9)
									sub(/"$/, "", s)
									print trim(s) suffix
								}
							}
							BEGIN {
								split(ip, A, ".")
								ipn = A[1]*16777216 + A[2]*65536 + A[3]*256 + A[4]
							}
							{
								setname = $2
								if (setname == "Skynet-Blacklist") {
									if ($3 == ip) do_print(" [" ip "]")
								} else {
									split($3, P, "/")
									net = P[1]; prefix = P[2] + 0
									split(net, B, ".")
									netn = B[1]*16777216 + B[2]*65536 + B[3]*256 + B[4]
									suffix = " [" net "/" prefix "]"
									if      (prefix==24 && A[1]==B[1] && A[2]==B[2] && A[3]==B[3]) do_print(suffix)
									else if (prefix==16 && A[1]==B[1] && A[2]==B[2])              do_print(suffix)
									else if (prefix==8  && A[1]==B[1])                            do_print(suffix)
									else {
										sh = 32 - prefix
										div = 1
										for(i=0;i<sh;i++) div *= 2
										if (int(ipn/div) == int(netn/div)) do_print(suffix)
									}
								}
							}
							'
						fi
						echo;echo
						ip="$(echo "$4" | sed 's~\.~\\.~g')"
						Show_Associated_Domains "$ip"
						if Is_Enabled "$lookupcountry"; then
							country="$(curl -fsSL --retry 3 --max-time 6 -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno)" "https://api.db-ip.com/v2/free/${4}/countryCode/" 2>/dev/null | grep -E '^[A-Z]{2}$' || echo '**')"
							echo "[i] IP Location - $country"
							echo
						fi
						echo "[i] $4 First Tracked On $(grep -m1 -F "=$4 " "$skynetlog" | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo "[i] $4 Last Tracked On $(grep -F "=$4 " "$skynetlog" | tail -1 | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo "[i] $(grep -Foc "=$4 " "$skynetlog") Blocks Total"
						echo;echo
						Red "Event Log Entries From $4;"
						grep -F "=$4 " "$skynetevents"
						echo;echo
						Red "First Block Tracked From $4;"
						grep -m1 -F "=$4 " "$skynetlog"
						echo;echo
						Red "$counter Most Recent Blocks From $4;"
						grep -F "=$4 " "$skynetlog" | tail -"$counter"
						echo;echo
						Red "Top $counter Targeted Ports From $4 (Inbound);"
						Display_Header "3"
						grep -E "INBOUND.*SRC=$4 " "$skynetlog" | grep -oE 'DPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{printf "%-10s | %-10s | %-60s\n", $1 "x", $2, "https://www.speedguide.net/port.php?port=" $2 }'
						echo;echo
						Red "Top $counter Sourced Ports From $4 (Inbound);"
						Display_Header "3"
						grep -E "INBOUND.*SRC=$4 " "$skynetlog" | grep -oE 'SPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{printf "%-10s | %-10s | %-60s\n", $1 "x", $2, "https://www.speedguide.net/port.php?port=" $2 }'
						echo
					;;
					domain)
						if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
						if [ -z "$4" ]; then echo "[*] Domain Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
						domain="$(echo "$4" | Strip_Domain)"
						for ip in $(Domain_Lookup "$domain" 3); do
							ipset test Skynet-Whitelist "$ip" && found1=true
							ipset test Skynet-Blacklist "$ip" && found2=true
							ipset test Skynet-BlockedRanges "$ip" && found3=true
							echo
							if [ -n "$found1" ]; then Red "Whitelist Reason;"; grep -F "add Skynet-Whitelist $(echo "$ip" | cut -d '.' -f1-3)." "$skynetipset" | awk '{$1=$2=$4=""; print $0}' | tr -s " "; echo; fi
							if [ -n "$found2" ] || [ -n "$found3" ]; then
								Red "Ban Reasons;"
								grep -E '^add Skynet-(Blacklist|BlockedRanges) ' "$skynetipset" | awk -v ip="$ip" '
								function trim(s)      { sub(/^ +| +$/, "", s); return s }
								function do_print(suffix) {
									pos = index($0, "comment \"")
									if (pos) {
										s = substr($0, pos+9)
										sub(/"$/, "", s)
										print trim(s) suffix
									}
								}
								BEGIN {
									split(ip, A, ".")
									ipn = A[1]*16777216 + A[2]*65536 + A[3]*256 + A[4]
								}
								{
									setname = $2
									if (setname == "Skynet-Blacklist") {
										if ($3 == ip) do_print(" [" ip "]")
									} else {
										split($3, P, "/")
										net = P[1]; prefix = P[2] + 0
										split(net, B, ".")
										netn = B[1]*16777216 + B[2]*65536 + B[3]*256 + B[4]
										suffix = " [" net "/" prefix "]"
										if      (prefix==24 && A[1]==B[1] && A[2]==B[2] && A[3]==B[3]) do_print(suffix)
										else if (prefix==16 && A[1]==B[1] && A[2]==B[2])              do_print(suffix)
										else if (prefix==8  && A[1]==B[1])                            do_print(suffix)
										else {
											sh = 32 - prefix
											div = 1
											for(i=0;i<sh;i++) div *= 2
											if (int(ipn/div) == int(netn/div)) do_print(suffix)
										}
									}
								}
								'
							fi
							echo
							ip2="$(echo "$ip" | sed 's~\.~\\.~g')"
							Show_Associated_Domains "$ip2"
							echo;echo
							if [ -n "$found2" ] || [ -n "$found3" ]; then
								if Is_Enabled "$lookupcountry"; then
									country="$(curl -fsSL --retry 3 --max-time 6 -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno)" "https://api.db-ip.com/v2/free/${ip}/countryCode/" 2>/dev/null | grep -E '^[A-Z]{2}$' || echo '**')"
								fi
								echo "[i] $ip First Tracked On $(grep -m1 -F "=$ip " "$skynetlog" | awk '{printf "%s %s %s\n", $1, $2, $3}')"
								echo "[i] $ip Last Tracked On $(grep -F "=$ip " "$skynetlog" | tail -1 | awk '{printf "%s %s %s\n", $1, $2, $3}')"
								echo "[i] $(grep -Foc "=$ip " "$skynetlog") Blocks Total"
								echo;echo
								Red "Event Log Entries From $ip;"
								grep -F "=$ip " "$skynetevents"
								echo;echo
								Red "First Block Tracked From $ip;"
								grep -m1 -F "=$ip " "$skynetlog"
								echo;echo
								Red "$counter Most Recent Blocks From $ip;"
								grep -F "=$ip " "$skynetlog" | tail -"$counter"
								echo;echo
								Red "Top $counter Targeted Ports From $ip (Inbound);"
								Display_Header "3"
								grep -E "INBOUND.*SRC=$ip " "$skynetlog" | grep -oE 'DPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{printf "%-10s | %-10s | %-60s\n", $1 "x", $2, "https://www.speedguide.net/port.php?port=" $2 }'
								echo;echo
								Red "Top $counter Sourced Ports From $ip (Inbound);"
								Display_Header "3"
								grep -E "INBOUND.*SRC=$ip " "$skynetlog" | grep -oE 'SPT=[0-9]{1,5}' | cut -c 5- | sort -n | uniq -c | sort -nr | head -"$counter" | awk '{printf "%-10s | %-10s | %-60s\n", $1 "x", $2, "https://www.speedguide.net/port.php?port=" $2 }'
								echo
							fi
							echo
						done
						if [ "$5" -eq "$5" ] 2>/dev/null; then counter="$5"; fi
					;;
					malware)
						Check_Lock "$@"
						if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
						if ! echo "$4" | Is_IPRange; then echo "[*] $4 Is Not A Valid IP/Range"; echo; exit 2; fi
						ip="$(echo "$4" | sed 's~\.~\\.~g')"
						Show_Associated_Domains "$ip"
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
						echo;echo
						Red "First Manual Ban Issued;"
						grep -m1 -F "Manual Ban" "$skynetevents"
						echo;echo
						Red "$counter Most Recent Manual Bans;"
						grep -F "Manual Ban" "$skynetevents" | tail -"$counter"
					;;
					device)
						if ! echo "$4" | Is_IP; then echo "[*] $4 Is Not A Valid IP"; echo; exit 2; fi
						if [ "$5" -eq "$5" ] 2>/dev/null; then counter="$5"; fi
						echo "[i] $4 First Tracked On $(grep -m1 -E "OUTBOUND.* SRC=$4 " "$skynetlog" | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo "[i] $4 Last Tracked On $(grep -E "OUTBOUND.* SRC=$4 " "$skynetlog" | tail -1 | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo "[i] $(grep -Eoc -E "OUTBOUND.* SRC=$4 " "$skynetlog") Blocks Total"
						echo;echo
						Red "Device Name;"
						if grep -qF " $4 " "/var/lib/misc/dnsmasq.leases"; then grep -F " $4 " "/var/lib/misc/dnsmasq.leases" | awk '{print $4}'; else echo "Unknown"; fi
						echo;echo
						Red "First Block Tracked From $4;"
						grep -m1 -E "OUTBOUND.* SRC=$4 " "$skynetlog"
						echo;echo
						Red "$counter Most Recent Blocks From $4;"
						grep -E "OUTBOUND.* SRC=$4 " "$skynetlog" | tail -"$counter"
						echo;echo
						Red "Top $counter HTTP(s) Blocks (Outbound);"
						Display_Header "2"
						grep -E 'DPT=80 |DPT=443 ' "$skynetlog" | grep -E "OUTBOUND.*$proto" | grep -F "SRC=${4} " | grep -oE ' DST=[0-9,\.]*' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | while IFS= read -r "statdata"; do
							Generate_Ban_Stats "2"
						done
						echo;echo
						Red "Top $counter Blocks From (Outbound);"
						Display_Header "2"
						grep -E "OUTBOUND.*$proto" "$skynetlog" | grep -vE 'DPT=80 |DPT=443 ' | grep -F "SRC=${4} " | grep -oE ' DST=[0-9,\.]*' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | while IFS= read -r "statdata"; do
							Generate_Ban_Stats "2"
						done
					;;
					reports)
						if [ "$4" -eq "$4" ] 2>/dev/null; then counter="$4"; fi
						sed '\~Skynet: \[#\] ~!d' "$syslog1loc" "$syslogloc" 2>/dev/null >> "$skynetevents"
						sed -i '\~Skynet: \[#\] ~d' "$syslog1loc" "$syslogloc" 2>/dev/null
						echo "[i] First Report Tracked On $(grep -m1 -F "Skynet: [#] " "$skynetevents" | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo "[i] Last Report Tracked On $(grep -F "Skynet: [#] " "$skynetevents" | tail -1 | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo;echo
						Red "First Report Tracked;"
						grep -m1 -F "Skynet: [#] " "$skynetevents"
						echo;echo
						Red "$counter Most Recent Reports;"
						grep -F "Skynet: [#] " "$skynetevents" | tail -"$counter"
					;;
					invalid)
						if [ "$4" -eq "$4" ] 2>/dev/null; then counter="$4"; fi
						echo "[i] First Invalid Block Tracked On $(grep -m1 -F "BLOCKED - INVALID" "$skynetlog" | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo "[i] Last Invalid Block Tracked On $(grep -F "BLOCKED - INVALID" "$skynetlog" | tail -1 | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo;echo
						Red "First Report Tracked;"
						grep -m1 -F "BLOCKED - INVALID" "$skynetlog"
						echo;echo
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
						echo;echo
						Red "First IOT Block Tracked;"
						grep -m1 -F "BLOCKED - IOT" "$skynetlog"
						echo;echo
						Red "$counter Most Recent IOT Blocks;"
						grep -F "BLOCKED - IOT" "$skynetlog" | tail -"$counter"
						echo;echo
						Red "Top $counter IOT Blocks (Outbound);"
						Display_Header "2"
						grep -E "IOT.*$proto" "$skynetlog" | grep -oE ' DST=[0-9,\.]*' | cut -c 6- | sort -n | uniq -c | sort -nr | head -"$counter" | while IFS= read -r "statdata"; do
							Generate_Ban_Stats "2"
						done
					;;
					*)
						Command_Not_Recognized
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
				if Is_Enabled "$extendedstats"; then
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
				show_stats_block "log" "INBOUND.*$proto" "SRC" "Last $counter Unique Connections Blocked (Inbound)" "head" "$counter" "1" "1"
				show_stats_block "log" "OUTBOUND.*$proto" "DST" "Last $counter Unique Connections Blocked (Outbound)" "head" "$counter" "1" "1"
				if Is_Enabled "$loginvalid"; then
					show_stats_block "log" "INVALID.*$proto" "SRC" "Last $counter Unique Connections Blocked (Invalid)" "head" "$counter" "1" "1"
				fi
				show_stats_block "events" "Manual Ban" "SRC" "Last $counter Manual Bans" "tail" "$counter" "1" "1"
				show_stats_block "log" "(DPT=80|DPT=443).*OUTBOUND.*$proto" "DST" "Last $counter Unique HTTP(s) Blocks (Outbound)" "head" "$counter" "1" "1"
				show_stats_block "log" "(DPT=80|DPT=443).*OUTBOUND.*$proto" "DST" "Top $counter HTTP(s) Blocks (Outbound)" "head" "$counter" "2" "2"
				show_stats_block "log" "INBOUND.*$proto" "SRC" "Top $counter Blocks (Inbound)" "head" "$counter" "2" "2"
				show_stats_block "log" "OUTBOUND.*$proto" "DST" "Top $counter Blocks (Outbound)" "head" "$counter" "2" "2"
				if Is_Enabled "$loginvalid"; then
					show_stats_block "log" "INVALID.*$proto" "SRC" "Top $counter Blocks (Invalid)" "head" "$counter" "2" "2"
				fi
				if Is_Enabled "$iotblocked"; then
					show_stats_block "log" "IOT.*$proto" "DST" "Top $counter IOT Blocks (Outbound)" "head" "$counter" "2" "2"
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
}

Generate_Stats() {
	if nvram get rc_support | grep -qF "am_addons"; then
		if Is_Enabled "$displaywebui"; then
			mkdir -p "${skynetloc}/webui/stats"
			true > "${skynetloc}/webui/stats.js"
			if Is_Enabled "$extendedstats" && [ -f "/opt/var/log/dnsmasq.log" ]; then
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
				banreason="$(
					grep -E '^add Skynet-(Blacklist|BlockedRanges) ' "$skynetipset" |
					awk -v ip="$statdata" '
						function trim(s) { sub(/^ +| +$/, "", s); return s }
						function do_print(cidr) {
						pos = index($0, "comment \"")
						if (pos) {
							s = substr($0, pos+9); sub(/"$/, "", s)
							printf "%s", trim(s)
							if (cidr) printf "*"
							printf "\n"
						}
						}
						BEGIN { split(ip,A,"."); ipn=A[1]*16777216 + A[2]*65536 + A[3]*256 + A[4] }
						# exact blacklist
						$1=="add" && $2=="Skynet-Blacklist" && $3==ip { do_print(0); exit }
						# CIDR ranges
						$1=="add" && $2=="Skynet-BlockedRanges" {
						split($3,P,"/"); net=P[1]; prefix=P[2]
						split(net,B,"."); netn=B[1]*16777216 + B[2]*65536 + B[3]*256 + B[4]
						if (prefix==32 && ipn==netn)              { do_print(0); exit }
						else if (prefix==24 && A[1]==B[1]&&A[2]==B[2]&&A[3]==B[3]) { do_print(1); exit }
						else if (prefix==16 && A[1]==B[1]&&A[2]==B[2])           { do_print(1); exit }
						else if (prefix==8  && A[1]==B[1])                       { do_print(1); exit }
						else {
							sh=32-prefix; div=1
							for(i=0;i<sh;i++) div*=2
							if (int(ipn/div)==int(netn/div)) { do_print(1); exit }
						}
						}
					'
				)"
				if [ -z "$banreason" ]; then
					banreason="$(grep -E "$(echo "$statdata" | cut -d '.' -f1-3)\..*/" "$skynetipset" | grep -m1 -vF "Skynet-Whitelist" | awk -F '"' '{print $2}' | sed "s~BanMalware: ~~g")*"
				fi
				if [ "${#banreason}" -gt "45" ]; then banreason="$(echo "$banreason" | cut -c 1-45)"; fi
				alienvault="https://otx.alienvault.com/indicator/ip/${statdata}"
				if Is_Enabled "$lookupcountry"; then
					country="$(curl -fsSL --retry 3 --max-time 6 -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno)" "https://api.db-ip.com/v2/free/${statdata}/countryCode/" 2>/dev/null | grep -E '^[A-Z]{2}$' || echo '**')"
				fi
				assdomains="$(grep -F "$statdata" "${skynetloc}/webui/stats/skynetstats.txt" | awk '{print $1}' | xargs)"
				if [ -z "$assdomains" ]; then assdomains="*"; fi
				echo "$statdata~$banreason~$alienvault~$country~$assdomains" >> "${skynetloc}/webui/stats/liconn.txt"
			done
			WriteData_ToJS "${skynetloc}/webui/stats/liconn.txt" "${skynetloc}/webui/stats.js" "LabelInConn_IPs" "LabelInConn_BanReason" "LabelInConn_AlienVault" "LabelInConn_Country" "LabelInConn_AssDomains"
			# Last 10 Connections Blocked Outbound
			true > "${skynetloc}/webui/stats/loconn.txt"
			grep -F "OUTBOUND" "$skynetlog" | grep -vE 'DPT=80 |DPT=443 ' | grep -oE ' DST=[0-9,\.]*' | cut -c 6- | awk '{a[i++]=$0} END {for (j=i-1; j>=0;) print a[j--] }' | awk '!x[$0]++' | head -10 | while IFS= read -r "statdata"; do
				banreason="$(
					grep -E '^add Skynet-(Blacklist|BlockedRanges) ' "$skynetipset" |
					awk -v ip="$statdata" '
						function trim(s) { sub(/^ +| +$/, "", s); return s }
						function do_print(cidr) {
						pos = index($0, "comment \"")
						if (pos) {
							s = substr($0, pos+9); sub(/"$/, "", s)
							printf "%s", trim(s)
							if (cidr) printf "*"
							printf "\n"
						}
						}
						BEGIN { split(ip,A,"."); ipn=A[1]*16777216 + A[2]*65536 + A[3]*256 + A[4] }
						# exact blacklist
						$1=="add" && $2=="Skynet-Blacklist" && $3==ip { do_print(0); exit }
						# CIDR ranges
						$1=="add" && $2=="Skynet-BlockedRanges" {
						split($3,P,"/"); net=P[1]; prefix=P[2]
						split(net,B,"."); netn=B[1]*16777216 + B[2]*65536 + B[3]*256 + B[4]
						if (prefix==32 && ipn==netn)              { do_print(0); exit }
						else if (prefix==24 && A[1]==B[1]&&A[2]==B[2]&&A[3]==B[3]) { do_print(1); exit }
						else if (prefix==16 && A[1]==B[1]&&A[2]==B[2])           { do_print(1); exit }
						else if (prefix==8  && A[1]==B[1])                       { do_print(1); exit }
						else {
							sh=32-prefix; div=1
							for(i=0;i<sh;i++) div*=2
							if (int(ipn/div)==int(netn/div)) { do_print(1); exit }
						}
						}
					'
				)"
				if [ -z "$banreason" ]; then
					banreason="$(grep -E "$(echo "$statdata" | cut -d '.' -f1-3)\..*/" "$skynetipset" | grep -m1 -vF "Skynet-Whitelist" | awk -F '"' '{print $2}' | sed "s~BanMalware: ~~g")*"
				fi
				if [ "${#banreason}" -gt "45" ]; then banreason="$(echo "$banreason" | cut -c 1-45)"; fi
				alienvault="https://otx.alienvault.com/indicator/ip/${statdata}"
				if Is_Enabled "$lookupcountry"; then
					country="$(curl -fsSL --retry 3 --max-time 6 -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno)" "https://api.db-ip.com/v2/free/${statdata}/countryCode/" 2>/dev/null | grep -E '^[A-Z]{2}$' || echo '**')"
				fi
				assdomains="$(grep -F "$statdata" "${skynetloc}/webui/stats/skynetstats.txt" | awk '{print $1}' | xargs)"
				if [ -z "$assdomains" ]; then assdomains="*"; fi
				echo "$statdata~$banreason~$alienvault~$country~$assdomains" >> "${skynetloc}/webui/stats/loconn.txt"
			done
			WriteData_ToJS "${skynetloc}/webui/stats/loconn.txt" "${skynetloc}/webui/stats.js" "LabelOutConn_IPs" "LabelOutConn_BanReason" "LabelOutConn_AlienVault" "LabelOutConn_Country" "LabelOutConn_AssDomains"
			# Last 10 HTTP Connections Blocked Outbound
			true > "${skynetloc}/webui/stats/lhconn.txt"
			grep -E 'DPT=80 |DPT=443 ' "$skynetlog" | grep -F "OUTBOUND" | grep -oE ' DST=[0-9,\.]*' | cut -c 6- | awk '{a[i++]=$0} END {for (j=i-1; j>=0;) print a[j--] }' | awk '!x[$0]++' | head -10 | while IFS= read -r "statdata"; do
				banreason="$(
					grep -E '^add Skynet-(Blacklist|BlockedRanges) ' "$skynetipset" |
					awk -v ip="$statdata" '
						function trim(s) { sub(/^ +| +$/, "", s); return s }
						function do_print(cidr) {
						pos = index($0, "comment \"")
						if (pos) {
							s = substr($0, pos+9); sub(/"$/, "", s)
							printf "%s", trim(s)
							if (cidr) printf "*"
							printf "\n"
						}
						}
						BEGIN { split(ip,A,"."); ipn=A[1]*16777216 + A[2]*65536 + A[3]*256 + A[4] }
						# exact blacklist
						$1=="add" && $2=="Skynet-Blacklist" && $3==ip { do_print(0); exit }
						# CIDR ranges
						$1=="add" && $2=="Skynet-BlockedRanges" {
						split($3,P,"/"); net=P[1]; prefix=P[2]
						split(net,B,"."); netn=B[1]*16777216 + B[2]*65536 + B[3]*256 + B[4]
						if (prefix==32 && ipn==netn)              { do_print(0); exit }
						else if (prefix==24 && A[1]==B[1]&&A[2]==B[2]&&A[3]==B[3]) { do_print(1); exit }
						else if (prefix==16 && A[1]==B[1]&&A[2]==B[2])           { do_print(1); exit }
						else if (prefix==8  && A[1]==B[1])                       { do_print(1); exit }
						else {
							sh=32-prefix; div=1
							for(i=0;i<sh;i++) div*=2
							if (int(ipn/div)==int(netn/div)) { do_print(1); exit }
						}
						}
					'
				)"
				if [ -z "$banreason" ]; then
					banreason="$(grep -E "$(echo "$statdata" | cut -d '.' -f1-3)\..*/" "$skynetipset" | grep -m1 -vF "Skynet-Whitelist" | awk -F '"' '{print $2}' | sed "s~BanMalware: ~~g")*"
				fi
				if [ "${#banreason}" -gt "45" ]; then banreason="$(echo "$banreason" | cut -c 1-45)"; fi
				alienvault="https://otx.alienvault.com/indicator/ip/${statdata}"
				if Is_Enabled "$lookupcountry"; then
					country="$(curl -fsSL --retry 3 --max-time 6 -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno)" "https://api.db-ip.com/v2/free/${statdata}/countryCode/" 2>/dev/null | grep -E '^[A-Z]{2}$' || echo '**')"
				fi
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
				if Is_Enabled "$lookupcountry"; then
					country="$(curl -fsSL --retry 3 --max-time 6 -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno)" "https://api.db-ip.com/v2/free/${ipaddr}/countryCode/" 2>/dev/null | grep -E '^[A-Z]{2}$' || echo '**')"
				fi
				echo "$hits~$ipaddr~$country" >> "${skynetloc}/webui/stats/thconn.txt"
			done
			WriteData_ToJS "${skynetloc}/webui/stats/thconn.txt" "${skynetloc}/webui/stats.js" "DataTHConnHits" "LabelTHConnHits_IPs" "LabelTHConnHits_Country"
			# Top 10 Inbound Connections Blocked
			true > "${skynetloc}/webui/stats/ticonn.txt"
			grep -F "INBOUND" "$skynetlog" | grep -oE ' SRC=[0-9,\.]*' | cut -c 6- | sort -n | uniq -c | sort -nr | head -10 | while IFS= read -r "statdata"; do
				hits="$(echo "$statdata" | awk '{print $1}')"
				ipaddr="$(echo "$statdata" | awk '{print $2}')"
				if Is_Enabled "$lookupcountry"; then country="$(curl -fsSL --retry 3 --max-time 6 -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno) / $(tr -cd 0-9 </dev/urandom | head -c 20)" "https://api.db-ip.com/v2/free/${ipaddr}/countryName/")"; else country="*"; fi
				if [ -z "$country" ]; then country="*"; fi
				echo "$hits~$ipaddr~$country" >> "${skynetloc}/webui/stats/ticonn.txt"
			done
			WriteData_ToJS "${skynetloc}/webui/stats/ticonn.txt" "${skynetloc}/webui/stats.js" "DataTIConnHits" "LabelTIConnHits_IPs" "LabelTIConnHits_Country"
			# Top 10 Outbound Connections Blocked
			true > "${skynetloc}/webui/stats/toconn.txt"
			grep -F "OUTBOUND" "$skynetlog" | grep -vE 'DPT=80 |DPT=443 ' | grep -oE ' DST=[0-9,\.]*' | cut -c 6- | sort -n | uniq -c | sort -nr | head -10 | while IFS= read -r "statdata"; do
				hits="$(echo "$statdata" | awk '{print $1}')"
				ipaddr="$(echo "$statdata" | awk '{print $2}')"
				if Is_Enabled "$lookupcountry"; then
					country="$(curl -fsSL --retry 3 --max-time 6 -A "ASUSWRT-Merlin $model v$(nvram get buildno)_$(nvram get extendno)" "https://api.db-ip.com/v2/free/${ipaddr}/countryCode/" 2>/dev/null | grep -E '^[A-Z]{2}$' || echo '**')"
				fi
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

Generate_Blocked_Events() {
	unique_ip_count="$(awk '
		/INBOUND|INVALID/ {
			for (i = 1; i <= NF; i++)
				if ($i ~ /^SRC=/) {
					split($i, ip, "=")
					if (ip[2] ~ /^[0-9.]+$/) seen[ip[2]]++
					break
				}
		}
		/OUTBOUND/ {
			for (i = 1; i <= NF; i++)
				if ($i ~ /^DST=/) {
					split($i, ip, "=")
					if (ip[2] ~ /^[0-9.]+$/) seen[ip[2]]++
					break
				}
		}
		END { print length(seen) }
	' "$skynetlog")"
	printf '║ %-20s │ %-82s ║\n' "Block Events" "$(wc -l < "$skynetlog") ($unique_ip_count Unique IPs)"
}

Get_WebUI_Page() {
	if nvram get rc_support | grep -qF "am_addons" && Is_Enabled "$displaywebui"; then
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
	if Is_Enabled "$logmode"; then
		if nvram get rc_support | grep -qF "am_addons"; then
			if Is_Enabled "$displaywebui"; then
				Get_WebUI_Page "${skynetloc}/webui/skynet.asp"
				if [ "$MyPage" = "none" ]; then
					Log error "Unable To Mount Skynet Web Page - No Mount Points Avilable"
				else
					Log info "Mounting Skynet Web Page As $MyPage"
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
		Log error "WebUI Integration Requires Logging To Be Enabled"
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
	file="$1"
	dest="$2"
	force="$3"

	fullurl="${remotedir}/${file}"
	filename="$(basename "$file")"

	# Only re-download if file changed or forced
	remote_md5="$(curl -fsSL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors "$fullurl" | md5sum | awk '{print $1}')"
	local_md5="$(md5sum "$dest" 2>/dev/null | awk '{print $1}')"

	if [ "$remote_md5" != "$local_md5" ] || [ "$force" = "-f" ]; then
		if curl -fsSL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors "$fullurl" -o "$dest"; then
			echo "[i] Updated $filename"
		else
			Log error "Failed to update $filename"
		fi
	else
		echo "[i] No change to $filename (MD5 matched)"
	fi
}

Get_LocalName() {
	localname=""
	
	# Check custom client list for MAC address
	if [ -n "$macaddr" ]; then
		localname="$(nvram get custom_clientlist | grep -ioE "<.*>$macaddr" | sed -E 's/.*<([^>]+)>[^<]*$/\1/; s/[^a-zA-Z0-9.-]//g')"
	fi
	
	# Fallback to dnsmasq leases
	if [ -z "$localname" ]; then
		localname="$(grep -F "$ipaddr " /var/lib/misc/dnsmasq.leases | awk '{print $4}')"
	fi
	
	# If no name found, check OUI DB for MAC address
	if [ -z "$localname" ] || [ "$localname" = "*" ]; then
		if [ -n "$macaddr" ]; then
			macaddr2=$(echo "$macaddr" | tr -d ':' | cut -c1-6 | tr 'abcdef' 'ABCDEF')
			localname=$(grep -m1 "$macaddr2" /www/ajax/ouiDB.json | cut -d\" -f4)
		fi
		# Additional checks for specific cases	
		if [ -z "$localname" ]; then
			case "$ipaddr" in
				"$(nvram get wan0_ipaddr)")
					localname="$model"
				;;
				"$(nvram get wgs1_addr | cut -d'/' -f1)")
					localname="Wireguard VPN Server"
				;;
				"$(nvram get vpn_server1_remote)" | "$(nvram get vpn_server2_remote)")
					localname="OpenVPN Server"
				;;
				*)
					localname="Unknown"
				;;
			esac
		fi
	fi
	
	# Truncate name if too long
	if [ "${#localname}" -gt 40 ]; then
		localname="$(echo "$localname" | cut -c 1-40)"
	fi
}

Manage_Device() {
	echo "[i] Looking for available partitions"

	# Build $@ = list of mountpoints whose fs is ext2/3/4, vfat, exfat or ntfs
	set --
	while read -r _ mnt fs _; do
		case "$fs" in
			ext2|ext3|ext4|tfat|exfat)
				set -- "$@" "$mnt"
				;;
		esac
	done < /proc/mounts

	# If none found, bail out
	if [ $# -eq 0 ]; then
		echo "[*] No compatible USB partitions found - exiting!"
		echo
		exit 1
	fi

	# Display numbered list
	idx=0
	for m in "$@"; do
		idx=$((idx + 1))
		echo "[$idx] --> $m"
	done

	# Prompt loop
	while :; do
		echo
		echo "Please enter partition number or 'e' to exit"
		printf "[1-%d]: " "$idx"
		read -r partitionNumber
		echo

		case "$partitionNumber" in
			e|exit)
				echo "[*] Exiting!"
				echo
				exit 0
			;;
			''|*[!0-9]*|0)
				echo "[*] Invalid partition number!"
			;;
			*)
				if [ "$partitionNumber" -ge 1 ] && [ "$partitionNumber" -le "$idx" ]; then
					choice=0
					for m in "$@"; do
						choice=$((choice + 1))
						if [ "$choice" -eq "$partitionNumber" ]; then
							device="$m"
							break
						fi
					done

					# Test writability
					if ! touch "$device/rwtest" 2>/dev/null; then
						echo "[*] Writing to $device failed - try another"
						continue
					else
						rm -f "$device/rwtest"
						break
					fi
				else
					echo "[*] Invalid partition number!"
				fi
			;;
		esac
	done
}

Create_Swap() {
	# 1) Ask for swap‐file size
	while :; do
		Show_Menu "Select SWAP File Size:" \
			"1GB" \
			"2GB (Recommended)" \
			"Exit"
		Prompt_Input "1-2" menu
		case "${menu:?}" in
			1)
				swapsize_kb=1048576
				break
			;;
			2)
				swapsize_kb=2097152
				break
			;;
			e|exit)
				echo "[*] Exiting!"
				echo
				exit 0
			;;
			*)
				Invalid_Option "$menu"
			;;
		esac
	done

	swaplocation="${device}/myswap.swp"

	# 2) Remove any existing swap file
	if [ -f "$swaplocation" ]; then
		swapoff -a 2>/dev/null
		rm -f "$swaplocation"
	fi

	# 3) Check free space in KB on the chosen device
	avail_kb=$(df -k "$device" | awk 'NR==2 {print $4}')
	avail_mb=$(( avail_kb / 1024 ))
	if [ -z "$avail_kb" ] || [ "$avail_kb" -lt "$swapsize_kb" ]; then
		echo "[*] Not enough free space on $device (${avail_mb}MB available)"
		echo
		return 1
	fi

	# 4) Create, enable swap
	swapsize_mb=$(( swapsize_kb / 1024 ))
	echo "[i] Creating ${swapsize_mb}MB swap file at $swaplocation"
	echo
	dd if=/dev/zero bs=1k count="$swapsize_kb" of="$swaplocation" 2>/dev/null
	mkswap "$swaplocation"
	swapon "$swaplocation"

	# 5) Ensure post-mount script will re-enable it on reboot
	sed -i '\~swapon ~d' /jffs/scripts/post-mount
	sed -i "2i [ -f \"\$1/myswap.swp\" ] && swapon \$1/myswap.swp # Skynet" /jffs/scripts/post-mount

	# 6) Ensure unmount script will turn it off
	if [ -f /jffs/scripts/unmount ] && ! grep -q '^swapoff ' /jffs/scripts/unmount; then
		echo 'swapoff -a 2>/dev/null # Skynet' >> /jffs/scripts/unmount
	fi

	# 7) Done!
	echo
	echo "[i] Swap file created at $swaplocation"
	echo
}

Return_To_Menu() {
	unset "option1" "option2" "option3" "option4" "option5"
	clear
	Load_Menu
}

Invalid_Option() {
	echo "[*] $1 Isn't An Option!"
	echo
}

Ensure_Running() {
	if ! Check_IPSets || ! Check_IPTables; then
		echo "[*] Skynet Not Running - Exiting"
		echo
		Load_Menu
		return 1   # indicate failure
	fi
	return 0       # Skynet is running
}

Prompt_Input() {
	printf "[%s]: " "$1"
	read -r "$2"
	echo
}

Prompt_Typed() {
	varname="$1"
	label="${2:-$varname}"
	prompt_text="${3:-}"

	# Only echo if we've been given extra prompt text
	[ -n "$prompt_text" ] && echo "$prompt_text"

	# Print the label (falls back to the var name)
	printf "[%s]: " "$label"
	read -r "${varname?}"
}

Show_Menu() {
	# usage: Show_Menu "Title" "Opt1" "Opt2" ... ["Exit"]
	title=$1; shift
	echo "$title"

	exit_label=""
	count=$#
	idx=1

	for opt in "$@"; do
		# if last arg is literally "Exit", capture it
		if [ "$idx" -eq "$count" ] && [ "$opt" = "Exit" ]; then
			exit_label=$opt
		else
			if [ "$idx" -lt 10 ]; then
				echo "[$idx]  --> $opt"
			else
				echo "[$idx] --> $opt"
			fi
			idx=$((idx+1))
		fi
	done

	# print the [e] Exit line if provided
	if [ -n "$exit_label" ]; then
		echo
		echo "[e]  --> $exit_label"
	fi

	echo
}

Purge_Logs() {
	# Extract all BLOCKED lines into skynetlog, then delete them from source
	sed '\~BLOCKED -~!d' "$syslog1loc" "$syslogloc" 2>/dev/null >> "$skynetlog"
	sed -i '\~BLOCKED -~d' "$syslog1loc" "$syslogloc" 2>/dev/null

	# Ensure skynetlog isn’t too large (or force), run stats, and truncate if still big
	log_kb=$(du -k "$skynetlog" 2>/dev/null | cut -f1) || log_kb=0
	log_kb=${log_kb:-0}
	log_kb_limit="$((logsize * 1024))"
	if [ "$log_kb" -ge "$log_kb_limit" ] || [ "$1" = "force" ]; then
		Generate_Stats
		sed -i '/BLOCKED -/d' "$skynetlog" 2>/dev/null
		sed -i '/Skynet: \[#\] /d' "$skynetevents" 2>/dev/null
		iptables -Z PREROUTING -t raw
		log_kb=$(du -k "$skynetlog" 2>/dev/null | cut -f1) || log_kb=0
		log_kb=${log_kb:-0}
		[ "$log_kb" -ge 3000 ] && : > "$skynetlog"
	fi

	# Move numbered Skynet event lines into events.log, then purge info and lock entries
	count_events=$(grep -c 'Skynet: \[#\]' "$syslogloc" 2>/dev/null) || count_events=0
	count_events=${count_events:-0}
	if [ "$1" = "all" ] || [ "$count_events" -gt 24 ]; then
		sed -n '/Skynet: \[#\] /p' "$syslog1loc" "$syslogloc" 2>/dev/null >> "$skynetevents"
		sed -i '
			/Skynet: \[i\] /{
				/Startup Initiated/!{
					/Restarting Firewall Service/!d
				}
			}
			/Skynet: \[#\] /d
			/Skynet: \[\*\] Lock /d
		' "$syslog1loc" "$syslogloc" 2>/dev/null
	fi

	# If more than three startup banners exist, remove them all so only the next one appears
	start_count=$(grep -c 'Skynet: \[i\] Startup Initiated' "$syslogloc" 2>/dev/null) || start_count=0
	start_count=${start_count:-0}
	if [ "$start_count" -gt 3 ]; then
		sed -i '/Skynet: \[i\] Startup Initiated/d' "$syslog1loc" "$syslogloc" 2>/dev/null
	fi

	# If more than three restart banners exist, remove them all so only the next one appears
	restart_count=$(grep -c 'Skynet: \[i\] Restarting Firewall Service' "$syslogloc" 2>/dev/null) || restart_count=0
	restart_count=${restart_count:-0}
	if [ "$restart_count" -gt 3 ]; then
		sed -i '/Skynet: \[i\] Restarting Firewall Service/d' "$syslog1loc" "$syslogloc" 2>/dev/null
	fi

	# Reload syslog-ng only if configured
	[ -f "/opt/etc/syslog-ng.d/skynet" ] && killall -HUP syslog-ng 2>/dev/null
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
		# Only print log to terminal
		Grn "$blacklist1count IPs (${newips}) -- $blacklist2count Ranges Banned (${newranges}) || $hits1 Inbound -- $hits2 Outbound Connections Blocked!"
	else
		# Print log to terminal and syslog
		logz="[#] $blacklist1count IPs (${newips}) -- $blacklist2count Ranges Banned (${newranges}) || $hits1 Inbound -- $hits2 Outbound Connections Blocked! [$1] [${ftime}s]"
		logger -t Skynet "$logz"; echo "$logz"
	fi
}

Write_Config() {
	{
		printf '%s\n' "################################################"
		printf '%s\n' "## Generated By Skynet - Do Not Manually Edit ##"
		printf '%-45s %s\n\n' "## $(date +"%b %e %T")" "##"
		printf '%s\n' "## Installer ##"
		printf '%s="%s"\n' "model" "$model"
		printf '%s="%s"\n' "localver" "$localver"
		printf '%s="%s"\n' "swaplocation" "$swaplocation"
		printf '\n%s\n' "## Counters / Lists ##"
		printf '%s="%s"\n' "blacklist1count" "$blacklist1count"
		printf '%s="%s"\n' "blacklist2count" "$blacklist2count"
		printf '%s="%s"\n' "customlisturl" "$customlisturl"
		printf '%s="%s"\n' "customlist2url" "$customlist2url"
		printf '%s="%s"\n' "countrylist" "$countrylist"
		printf '%s="%s"\n' "excludelists" "$excludelists"
		printf '\n%s\n' "## Settings ##"
		printf '%s="%s"\n' "autoupdate" "$autoupdate"
		printf '%s="%s"\n' "banmalwareupdate" "$banmalwareupdate"
		printf '%s="%s"\n' "forcebanmalwareupdate" "$forcebanmalwareupdate"
		printf '%s="%s"\n' "logmode" "$logmode"
		printf '%s="%s"\n' "loginvalid" "$loginvalid"
		printf '%s="%s"\n' "logsize" "$logsize"
		printf '%s="%s"\n' "filtertraffic" "$filtertraffic"
		printf '%s="%s"\n' "unbanprivateip" "$unbanprivateip"
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
	printf '╔═════════════════════ System ══════════════════════════════════════════════════════════════════════════════╗\n'
	printf '║ %-20s │ %-82s ║\n' "Router Model"   "$(nvram get productid)"
	printf '║ %-20s │ %-82s ║\n' "Skynet Version" "$localver ($(Filter_Date < "$0"))"
	printf '║ └── %-16s │ %-82s ║\n' "Hash" "$(md5sum "$0" | awk "{print \$1}")"
	printf '║ %-20s │ %-82s ║\n' "Install Dir"    "${skynetloc}"
	printf '║ %-20s │ %-82s ║\n' "FW Version"     "$(uname -o) v$(nvram get buildno)_$(nvram get extendno) (Kernel $(uname -r)) ($(uname -v | awk "{printf \"%s %s %s\n\", \$5,\$6,\$9}"))"
	printf '║ %-20s │ %-82s ║\n' "iptables"       "$(iptables --version)"
	printf '║ %-20s │ %-82s ║\n' "ipset"          "$(ipset -v 2>/dev/null | head -n1)"
	printf '║ %-20s │ %-82s ║\n' "Public IP"      "$(if nvram get wan0_ipaddr | Is_PrivateIP; then Red "$(nvram get wan0_ipaddr)"; else nvram get wan0_ipaddr; fi)"
	printf '║ %-20s │ %-82s ║\n' "WAN Info"       "${iface} - $(nvram get wan0_proto)"
	if [ -n "$countrylist" ]; then
		countries="$countrylist"
		if [ "${#countries}" -gt 82 ]; then
			countries="$(printf '%.81s+' "$countries")"
		fi
		printf '║ %-20s │ %-82s ║\n' "Banned Countries" "$countries"
	fi
	[ -n "$customlisturl" ] && printf '║ %-20s │ %-82s ║\n' "Custom Filter URL" "$customlisturl"
	printf '╚══════════════════════╧════════════════════════════════════════════════════════════════════════════════════╝\n\n\n'
	if [ -f "$LOCK_FILE" ] && ! flock -n 9 9<"$LOCK_FILE"; then
		locked_cmd=$(cut -d'|' -f1 "$LOCK_FILE")
		locked_pid=$(cut -d'|' -f2 "$LOCK_FILE")
		lock_timestamp=$(cut -d'|' -f3 "$LOCK_FILE")

		if [ -n "$locked_pid" ] && [ -d "/proc/$locked_pid" ]; then
			current_time=$(date +%s)
			runtime=$(( current_time - lock_timestamp ))
			Red "[*] Lock File Detected ($locked_cmd) (pid=$locked_pid, runtime=${runtime}s)"
			Ylow '[*] Locked Processes Generally Take 1-2 Minutes To Complete And May Result In Temporarily "Failed" Tests'
			echo;echo
		fi
	fi
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
	if Is_Enabled "$fastswitch"; then
		Ylow "Fast Switch List Is Enabled!"
	fi
	if [ "$nolog" != "1" ]; then Print_Log "minimal"; fi
	unset "nolog"
	unset "option1" "option2" "option3" "option4" "option5"
	reloadmenu="1"
	Purge_Logs
	echo;echo
	while true; do
		Show_Menu "Select Menu Option" \
			"Unban" \
			"Ban" \
			"Malware Blacklist" \
			"Whitelist" \
			"Import IP List" \
			"Deport IP List" \
			"Save" \
			"Restart Skynet" \
			"Temporarily Disable Skynet" \
			"Update Skynet" \
			"Settings" \
			"Debug Options" \
			"Stats" \
			"Install Skynet" \
			"Uninstall" \
			"Exit"
		Prompt_Input "1-15" menu
		case "$menu" in
			1)
				if ! Ensure_Running; then break; fi
				option1="unban"
				while true; do
					Show_Menu "What Type Of Input Would You Like To Unban" \
						"IP" \
						"Range" \
						"Domain" \
						"Comment" \
						"Country" \
						"ASN" \
						"Malware Lists" \
						"Non Manual Bans" \
						"All" \
						"Exit"
					Prompt_Input "1-9" menu2
					case "$menu2" in
						1)
							option2="ip"
							Prompt_Typed "option3" "IP" "Input IP To Ban:"
							if ! echo "$option3" | Is_IP; then echo "[*] $option3 Is Not A Valid IP"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						2)
							option2="range"
							Prompt_Typed "option3" "Range" "Input Range To Unban:"
							if ! echo "$option3" | Is_Range; then echo "[*] $option3 Is Not A Valid Range"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						3)
							option2="domain"
							Prompt_Typed "option3" "URL" "Input Domain To Unban:"
							if [ -z "$option3" ]; then echo "[*] URL Field Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						4)
							option2="comment"
							Prompt_Typed "option3" "Comment" "Remove Bans Matching Comment:"
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
							Prompt_Typed "option3" "ASN" "Input ASN To Unban:"
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
							Return_To_Menu
							break
						;;
						*)
							Invalid_Option "$menu2"
						;;
					esac
				done
				break
			;;
			2)
				if ! Ensure_Running; then break; fi
				option1="ban"
				while true; do
					Show_Menu "What Type Of Input Would You Like To Ban:" \
						"IP" \
						"Range" \
						"Domain" \
						"Country" \
						"ASN" \
						"Exit"
					Prompt_Input "1-5" menu2
					case "$menu2" in
						1)
							option2="ip"
							Prompt_Typed "option3" "IP" "Input IP To Ban:"
							if ! echo "$option3" | Is_IP; then echo "[*] $option3 Is Not A Valid IP"; echo; unset "option2" "option3"; continue; fi
							Prompt_Typed "option4" "Comment" "Input Comment For Ban:"
							if [ "${#option4}" -gt "244" ]; then echo "[*] $option4 Is Not A Valid Comment. 244 Chars Max"; echo; unset "option2" "option3" "option4"; continue; fi
							break
						;;
						2)
							option2="range"
							Prompt_Typed "option3" "Range" "Input Range To Ban:"
							if ! echo "$option3" | Is_Range; then echo "[*] $option3 Is Not A Valid Range"; echo; unset "option2" "option3"; continue; fi
							Prompt_Typed "option4" "Comment" "Input Comment For Ban:"
							if [ "${#option4}" -gt "243" ]; then echo "[*] $option4 Is Not A Valid Comment. 243 Chars Max"; echo; unset "option2" "option3" "option4"; continue; fi
							break
						;;
						3)
							option2="domain"
							Prompt_Typed "option3" "URL" "Input Domain To Ban:"
							if [ -z "$option3" ]; then echo "[*] URL Field Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						4)
							option2="country"
							if [ -n "$countrylist" ]; then echo "Countries Currently Banned: (${countrylist})"; fi
							Prompt_Typed "option3" "Countries" "Input Country Abbreviations To Ban:"
							if [ -z "$option3" ]; then echo "[*] Country Field Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
							if echo "$option3" | grep -qF "\""; then echo "[*] Country Field Can't Include Quotes - Please Try Again"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						5)
							option2="asn"
							Prompt_Typed "option3" "ASN" "Input ASN To Ban:"
							if ! echo "$option3" | Is_ASN; then echo "[*] $option3 Is Not A Valid ASN"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						e|exit|back|menu)
							Return_To_Menu
							break
						;;
						*)
							Invalid_Option "$menu2"
						;;
					esac
				done
				break
			;;
			3)
				if ! Ensure_Running; then break; fi
				option1="banmalware"
				while true; do
					Show_Menu "Select Option:" \
						"Update" \
						"Change Filter List" \
						"Reset Filter List" \
						"Exclude Individual Lists" \
						"Reset Exclusion List" \
						"Exit"
					Prompt_Input "1-5" menu2
					case "$menu2" in
						1)
							break
						;;
						2)
							Prompt_Typed "option2" "URL" "Input Custom Filter List URL:"
							if [ -z "$option2" ]; then echo "[*] URL Field Can't Be Empty - Please Try Again"; echo; unset "option2"; continue; fi
							break
						;;
						3)
							option2="reset"
							break
						;;
						4)
							option2="exclude"
							Prompt_Typed "option3" "Lists" "Input Names Of Lists To Exclude Seperated By Pipes Example - list1.ipset|list2.ipset|list3.ipset"
							if [ -z "$option3" ]; then echo "[*] Exclusion List Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						5)
							option2="exclude"
							option3="reset"
							break
						;;
						e|exit|back|menu)
							Return_To_Menu
							break
						;;
						*)
							Invalid_Option "$menu2"
						;;
					esac
				done
				break
			;;
			4)
				if ! Ensure_Running; then break; fi
				option1="whitelist"
				while true; do
					Show_Menu "Select Whitelist Option:" \
						"IP/Range" \
						"Domain" \
						"ASN" \
						"Refresh VPN Whitelist" \
						"Remove Entries" \
						"Refresh Entries" \
						"View Entries" \
						"Exit"
					Prompt_Input "1-7" menu2
					case "$menu2" in
						1)
							option2="ip"
							Prompt_Typed "option3" "IP/Range" "Input IP Or Range To Whitelist:"
							if ! echo "$option3" | Is_IPRange; then echo "[*] $option3 Is Not A Valid IP/Range"; echo; unset "option2" "option3"; continue; fi
							Prompt_Typed "option4" "Comment" "Input Comment For Whitelist:"
							if [ "${#option4}" -gt "242" ]; then echo "[*] $option4 Is Not A Valid Comment. 242 Chars Max"; echo; unset "option2" "option3" "option4"; continue; fi
							break
						;;
						2)
							option2="domain"
							Prompt_Typed "option3" "URL" "Input Domain To Whitelist:"
							if [ -z "$option3" ]; then echo "[*] URL Field Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
							break
						;;
						3)
							option2="asn"
							Prompt_Typed "option3" "ASN" "Input ASN To Whitelist:"
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
								Show_Menu "Remove From Whitelist:" \
									"All Non-Default Entries" \
									"IP/Range" \
									"Entries Matching Comment" \
									"Exit"
								Prompt_Input "1-3" menu3
								case "${menu3:?}" in
									1)
										option3="all"
										break
									;;
									2)
										option3="entry"
										Prompt_Typed "option4" "IP/Range" "Input IP Or Range To Remove:"
										if ! echo "$option4" | Is_IPRange; then echo "[*] $option4 Is Not A Valid IP/Range"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									3)
										option3="comment"
										Prompt_Typed "option4" "Comment" "Remove Entries Based On Comment:"
										if [ "${#option4}" -gt "255" ]; then echo "[*] $option4 Is Not A Valid Comment. 255 Chars Max"; echo; unset "option3" "option4"; continue; fi
										if [ -z "${option4}" ]; then echo "[*] Comment Field Can't Be Empty - Please Try Again"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									e|exit|back|menu)
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
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
								Show_Menu "Select Entries To View:" \
									"All" \
									"Manually Added IPs" \
									"Manually Added Domains" \
									"Imported Entries" \
									"Exit"
								Prompt_Input "1-4" menu3
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
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
									;;
								esac
							done
							break
						;;
						e|exit|back|menu)
							Return_To_Menu
							break
						;;
						*)
							Invalid_Option "$menu2"
						;;
					esac
				done
				break
			;;
			5)
				if ! Ensure_Running; then break; fi
				option1="import"
				while true; do
					Show_Menu "Select Where To Import List:" \
						"Blacklist" \
						"Whitelist" \
						"Exit"
					Prompt_Input "1-2" menu3
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
							Return_To_Menu
							break
						;;
						*)
							Invalid_Option "$menu3"
						;;
					esac
				done
				Prompt_Typed "option3" "File" "Input URL/Local File To Import:"
				if [ -z "$option3" ]; then echo "[*] File Field Can't Be Empty - Please Try Again"; echo; unset "option1" "option2" "option3"; continue; fi
				break
			;;
			6)
				if ! Ensure_Running; then break; fi
				option1="deport"
				while true; do
					Show_Menu "Select Where To Deport List From:" \
						"Blacklist" \
						"Whitelist" \
						"Exit"
					Prompt_Input "1-2" menu3
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
							Return_To_Menu
							break
						;;
						*)
							Invalid_Option "$menu3"
						;;
					esac
				done
				Prompt_Typed "option3" "File" "Input URL/Local File To Deport"
				if [ -z "$option3" ]; then echo "[*] File Field Can't Be Empty - Please Try Again"; echo; unset "option1" "option2" "option3"; continue; fi
				break
			;;
			7)
				if ! Ensure_Running; then break; fi
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
				Show_Menu "Select Update Option:" \
					"Check For And Install Any New Updates" \
					"Check For Updates Only" \
					"Force Update Even If No Updates Detected" \
					"Exit"
				Prompt_Input "1-3" menu2
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
							Return_To_Menu
							break
						;;
						*)
							Invalid_Option "$menu2"
						;;
					esac
				done
				break
			;;
			11)
				option1="settings"
				while true; do
					echo "Select Setting To Toggle:"
					printf '%-35s | %-40s\n' "[1]  --> Skynet Auto-Updates" "$(if Is_Enabled "$autoupdate"; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[2]  --> Malware List Auto-Updates" "$(if [ "$banmalwareupdate" = "daily" ] || [ "$banmalwareupdate" = "weekly" ]; then Grn "[$banmalwareupdate]"; else Red "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[3]  --> Logging" "$(if Is_Enabled "$logmode"; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[4]  --> Log Invalid Packets" "$(if Is_Enabled "$loginvalid"; then Grn "[Enabled]"; else Grn "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[5]  --> Log Size" "$(Grn "[${logsize}MB]")"
					printf '%-35s | %-40s\n' "[6]  --> Filter Traffic" "$(Grn "[$filtertraffic]")"
					printf '%-35s | %-40s\n' "[7]  --> Unban PrivateIP" "$(if Is_Enabled "$unbanprivateip"; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[8]  --> Import AiProtect Data" "$(if Is_Enabled "$banaiprotect"; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[9]  --> Secure Mode" "$(if Is_Enabled "$securemode"; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[10] --> Extended Stats" "$(if Is_Enabled "$extendedstats"; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[11] --> Fast Switch List" "$(if Is_Enabled "$fastswitch"; then Ylow "[Enabled]"; else Grn "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[12] --> Syslog Location" "$(if { [ "$syslogloc" = "/tmp/syslog.log" ] && [ "$syslog1loc" = "/tmp/syslog.log-1" ]; } || { [ "$syslogloc" = "/jffs/syslog.log" ] && [ "$syslog1loc" = "/jffs/syslog.log-1" ]; } then Grn "[Default]"; else Ylow "[Custom]"; fi)"
					printf '%-35s | %-40s\n' "[13] --> IOT Blocking" "$(if [ "$iotblocked" != "enabled" ]; then Grn "[Disabled]"; else Ylow "[Enabled]"; fi)"
					printf '%-35s | %-40s\n' "[14] --> IOT Logging" "$(if [ "$iotlogging" != "enabled" ]; then Red "[Disabled]"; else Grn "[Enabled]"; fi)"
					printf '%-35s | %-40s\n' "[15] --> Stats Country Lookup" "$(if Is_Enabled "$lookupcountry"; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[16] --> CDN Whitelisting" "$(if Is_Enabled "$cdnwhitelist"; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
					printf '%-35s | %-40s\n' "[17] --> Display WebUI" "$(if Is_Enabled "$displaywebui"; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
					echo
					printf "[1-17]: "
					read -r "menu2"
					echo
					case "$menu2" in
						1)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="autoupdate"
							while true; do
								Show_Menu "Select Skynet Autoupdate Option:" \
									"Enable" \
									"Disable" \
									"Exit"
								Prompt_Input "1-2" menu3
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
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
									;;
								esac
							done
							break
						;;
						2)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="banmalware"
							while true; do
								Show_Menu "Select Malware Blacklist Updating Frequency:" \
									"Daily" \
									"Weekly" \
									"Disable" \
									"Exit"
								Prompt_Input "1-3" menu3
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
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
									;;
								esac
							done
							break
						;;
						3)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="logmode"
							while true; do
							Show_Menu "Select Logging Option" \
								"Enable" \
								"Disable" \
								"Exit"
							Prompt_Input "1-2" menu3
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
									Return_To_Menu
									break
								;;
								*)
									Invalid_Option "$menu3"
								;;
							esac
							done
							break
						;;
						4)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="loginvalid"
							while true; do
								Show_Menu "Select Invalid Packet Logging Option" \
									"Enable" \
									"Disable" \
									"Exit"
								Prompt_Input "1-2" menu3
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
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
									;;
								esac
							done
							break
						;;
						5)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="logsize"
							while true; do
								Show_Menu "Select Log Size Option" \
									"10MB" \
									"Custom" \
									"Exit"
								Prompt_Input "1-2" menu3
								case "$menu3" in
									1)
										option3="10"
										break
									;;
									2)
										Prompt_Typed "option3" "Size" "Input Custom Log Size (in MB):"
										if ! Is_Numeric "$option3"; then echo;echo "[*] $option3 Is Not A Valid Size"; echo; unset "option3"; continue; fi
										if [ "$option3" -lt 10 ]; then echo;echo "[*] $option3 Is Not A Valid Size - Must Be At Least 10MB"; echo; unset "option3"; continue; fi
										break
									;;
									e|exit|back|menu)
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
									;;
								esac
							done
							break
						;;
						6)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="filter"
							while true; do
							Show_Menu "Select Traffic Filter" \
								"All - (Recommended)" \
								"Inbound" \
								"Outbound" \
								"Exit"
							Prompt_Input "1-3" menu3
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
									Return_To_Menu
									break
								;;
								*)
									Invalid_Option "$menu3"
								;;
							esac
							done
							break
						;;
						7)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="unbanprivate"
							while true; do
								Show_Menu "Select Filter PrivateIP Option" \
									"Enable" \
									"Disable" \
									"Exit"
								Prompt_Input "1-2" menu3
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
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
									;;
								esac
							done
							break
						;;
						8)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="banaiprotect"
							while true; do
								Show_Menu "Select Ban AiProtect Option" \
									"Enable" \
									"Disable" \
									"Exit"
								Prompt_Input "1-2" menu3
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
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
									;;
								esac
							done
							break
						;;
						9)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="securemode"
							while true; do
								Show_Menu "Select Secure Mode Option" \
									"Enable" \
									"Disable" \
									"Exit"
								Prompt_Input "1-2" menu3
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
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
									;;
								esac
							done
							break
						;;
						10)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="extendedstats"
							while true; do
								Show_Menu "Select Extended Stats Option" \
									"Enable" \
									"Disable" \
									"Exit"
								Prompt_Input "1-2" menu3
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
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
									;;
								esac
							done
							break
						;;
						11)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option1="fs"
							while true; do
								Show_Menu "Select Fast Switch List Option" \
									"Enable" \
									"Disable" \
									"Exit"
								Prompt_Input "1-2" menu3
								case "$menu3" in
									1)
										Prompt_Typed "option2" "URL" "Input Custom Filter List URL:"
										if [ -z "$option2" ]; then echo "[*] URL Field Can't Be Empty - Please Try Again"; echo; unset "option2"; continue; fi
										break
									;;
									2)
										option3="disable"
										break
									;;
									e|exit|back|menu)
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
									;;
								esac
							done
							break
						;;
						12)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							while true; do
								Show_Menu "Select Syslog To Configure:" \
									"syslog.log" \
									"syslog.log-1" \
									"Exit"
								Prompt_Input "1-2" menu3
								case "$menu3" in
									1)
										option2="syslog"
										while true; do
											Show_Menu "Select Syslog Location:" \
												"Default" \
												"Custom" \
												"Exit"
											Prompt_Input "1-2" menu3
											case "$menu3" in
												1)
													option3="/tmp/syslog.log"
													break
												;;
												2)
													Prompt_Typed "option3" "File" "Input Custom Syslog Location:"
													if [ -z "$option3" ]; then echo "[*] File Field Can't Be Empty - Please Try Again"; echo; unset "option1" "option2" "option3"; continue; fi
													break
												;;
												e|exit|back|menu)
													Return_To_Menu
													break
												;;
												*)
													Invalid_Option "$menu3"
												;;
											esac
										done
										break
										break
									;;
									2)
										option2="syslog1"
										while true; do
											Show_Menu "Select Syslog Location:" \
												"Default" \
												"Custom" \
												"Exit"
											Prompt_Input "1-2" menu3
											case "$menu3" in
												1)
													option3="/tmp/syslog.log-1"
													break
												;;
												2)
													Prompt_Typed "option3" "File" "Input Custom Syslog-1 Location:"
													if [ -z "$option3" ]; then echo "[*] File Field Can't Be Empty - Please Try Again"; echo; unset "option1" "option2" "option3"; continue; fi
													break
												;;
												e|exit|back|menu)
													Return_To_Menu
													break
												;;
												*)
													Invalid_Option "$menu3"
												;;
											esac
										done
										break
										break
									;;
									e|exit|back|menu)
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
									;;
								esac
							done
							break
						;;
						13)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							while true; do
								option2="iot"
								Show_Menu "Select IOT Option:" \
									"Unban Devices" \
									"Ban Devices" \
									"View Blocked Devices" \
									"Add Custom Allowed Ports" \
									"Reset Custom Port List" \
									"Select Allowed Protocols" \
									"Exit"
								Prompt_Input "1-6" menu3
								case "$menu3" in
									1)
										option3="unban"
										Prompt_Typed "option4" "IP" "Input Local IP(s) To Unban: Seperate Multiple Addresses With A Comma"
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
										Prompt_Typed "option4" "IP" "Input Local IP(s) To Ban: Seperate Multiple Addresses With A Comma"
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
										Prompt_Typed "option4" "Ports" "Input Custom Ports(s) To Allow: Seperate Multiple Ports With A Comma"
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
											Show_Menu "Select Port Protocol To Allow:" \
												"UDP" \
												"TCP" \
												"Both" \
												"Exit"
											Prompt_Input "1-3" menu4
											case "${menu4:?}" in
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
													Return_To_Menu
													break
												;;
												*)
													Invalid_Option "$menu4"
												;;
											esac
										done
										break
									;;
									e|exit|back|menu)
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
									;;
								esac
							done
							break
						;;
						14)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="iotlogging"
							while true; do
								Show_Menu "Select IOT Logging Option" \
									"Enable" \
									"Disable" \
									"Exit"
								Prompt_Input "1-2" menu3
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
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
									;;
								esac
							done
							break
						;;
						15)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="lookupcountry"
							while true; do
								Show_Menu "Select Country Lookup For Stats Option:" \
									"Enable" \
									"Disable" \
									"Exit"
								Prompt_Input "1-2" menu3
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
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
									;;
								esac
							done
							break
						;;
						16)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="cdnwhitelist"
							while true; do
								Show_Menu "Select CDN Whitelisting Option:" \
									"Enable" \
									"Disable" \
									"Exit"
								Prompt_Input "1-2" menu3
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
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
									;;
								esac
							done
							break
						;;
						17)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="webui"
							while true; do
								Show_Menu "Select WebUI Option:" \
									"Enable" \
									"Disable" \
									"Exit"
								Prompt_Input "1-2" menu3
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
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
									;;
								esac
							done
							break
						;;
						e|exit|back|menu)
							Return_To_Menu
							break
						;;
						*)
							Invalid_Option "$menu"
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
					Show_Menu "Select Debug Option:" \
						"Show Log Entries As They Appear" \
						"Print Debug Info" \
						"Cleanup Syslog Entries" \
						"SWAP File Management" \
						"Backup Skynet Files" \
						"Restore Skynet Files" \
						"Exit"
					Prompt_Input "1-6" menu2
					case "$menu2" in
						1)
							if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
							option2="watch"
							while true; do
								Show_Menu "Select Watch Option:" \
									"All" \
									"IP" \
									"Port" \
									"Exit"
								Prompt_Input "1-3" menu3
								case "$menu3" in
									1)
										break
									;;
									2)
										option3="ip"
										Prompt_Typed "option4" "IP"
										if ! echo "$option4" | Is_IP; then echo "[*] $option4 Is Not A Valid IP"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									3)
										option3="port"
										Prompt_Typed "option4" "Port"
										if ! echo "$option4" | Is_Port || [ "$option4" -gt "65535" ]; then echo "[*] $option4 Is Not A Valid Port"; echo; unset "option3" "option4"; continue; fi
										break
									;;
									e|exit|back|menu)
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
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
								Show_Menu "Select SWAP Option:" \
									"Install" \
									"Uninstall" \
									"Exit"
								Prompt_Input "1-2" menu3
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
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
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
							Return_To_Menu
							break
						;;
						*)
							Invalid_Option "$menu2"
						;;
					esac
				done
				break
			;;
			13)
				option1="stats"
				while true; do
					Show_Menu "Select Stat Option:" \
						"Display" \
						"Search" \
						"Remove" \
						"Reset" \
						"Exit"
					Prompt_Input "1-4" menu2
					case "$menu2" in
						1)
							while true; do
								Show_Menu "Show Top x Results:" \
									"10" \
									"20" \
									"50" \
									"Custom" \
									"Exit"
								Prompt_Input "1-4" menu3
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
										Prompt_Input "Number" option3
										if ! [ "$option3" -eq "$option3" ] 2>/dev/null; then
											echo "[*] $option3 Isn't A Valid Number!"
											echo
											unset option3
											continue
										fi
										break
									;;
									e|exit|back|menu)
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
									;;
								esac
							done
							while true; do
								Show_Menu "Show Packet Type:" \
									"All" \
									"TCP" \
									"UDP" \
									"ICMP" \
									"Exit"
								Prompt_Input "1-4" menu4
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
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu4"
									;;
								esac
							done
							break
						;;
						2)
							option2="search"
							while true; do
								Show_Menu "Search Options:" \
									"Based On Port x" \
									"Entries From Specific IP" \
									"Entries From Specific Domain" \
									"Search Malwarelists For IP" \
									"Search Manualbans" \
									"Search For Outbound Entries From Local Device" \
									"Hourly Reports" \
									"Invalid Packets" \
									"Active Connections" \
									"IOT Packets" \
									"Exit"
								Prompt_Input "1-10" menu4
								case "$menu4" in
									1)
										option3="port"
										Prompt_Input "Port" option4
										if ! echo "$option4" | Is_Port || [ "$option4" -gt 65535 ]; then
											echo "[*] $option4 Is Not A Valid Port"
											echo
											unset option3 option4
											continue
										fi
										break
									;;
									2)
										option3="ip"
										Prompt_Input "IP" option4
										if ! echo "$option4" | Is_IP; then
											echo "[*] $option4 Is Not A Valid IP"
											echo
											unset option3 option4
											continue
										fi
										break
									;;
									3)
										option3="domain"
										Prompt_Input "Domain" option4
										if [ -z "$option4" ]; then
											echo "[*] Domain Field Can't Be Empty - Please Try Again"
											echo
											unset option3 option4
											continue
										fi
										break
									;;
									4)
										option3="malware"
										Prompt_Input "IP" option4
										if ! echo "$option4" | Is_IPRange; then
											echo "[*] $option4 Is Not A Valid IP/Range"
											echo
											unset option3 option4
											continue
										fi
										break
									;;
									5)
										option3="manualbans"
										break
									;;
									6)
										option3="device"
										Prompt_Input "Local IP" option4
										if ! echo "$option4" | Is_IP; then
											echo "[*] $option4 Is Not A Valid IP"
											echo
											unset option3 option4
											continue
										fi
										break
									;;
									7)
										option3="reports"
										break
									;;
									8)
										option3="invalid"
										break
									;;
									9)
										option3="connections"
										while true; do
											Show_Menu "Search Options:" \
												"All Results" \
												"Search By IP" \
												"Search By Port" \
												"Search By Protocol" \
												"Search By Identification" \
												"Exit"
											Prompt_Input "1-5" menu5
											case "${menu5:?}" in
												1)
													break
												;;
												2)
													option4="ip"
													Prompt_Typed "option5" "IP"
													if ! echo "$option5" | Is_IP; then echo "[*] $option5 Is Not A Valid IP"; echo; unset "option4" "option5"; continue; fi
													break
												;;
												3)
													option4="port"
													Prompt_Typed "option5" "Port"
													if ! echo "$option5" | Is_Port || [ "$option5" -gt "65535" ]; then echo "[*] $option5 Is Not A Valid Port"; echo; unset "option4" "option5"; continue; fi
													break
												;;
												4)
													option4="proto"
													Prompt_Typed "option5" "Protocol"
													if [ "$option5" != "tcp" ] && [ "$option5" != "udp" ] && [ "$option5" != "icmp" ]; then echo "[*] $option5 Is Not A Valid Protocol"; echo; unset "option4" "option5"; continue; fi
													break
												;;
												5)
													option4="id"
													Prompt_Typed "option5" "Identification"
													break
												;;
												e|exit|back|menu)
													Return_To_Menu
													break
												;;
												*)
													Invalid_Option "$menu5"
												;;
											esac
										done
										break
									;;
									10)
										option3="iot"
										break
									;;
									e|exit|back|menu)
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu4"
									;;
								esac
							done
							if [ "$option3" != "connections" ]; then
								while true; do
									Show_Menu "Show Top x Results:" \
										"10" \
										"20" \
										"50" \
										"Custom" \
										"Exit"
									Prompt_Input "1-4" menu3
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
											Prompt_Typed optionx "Number" "Enter Custom Amount:"
											if ! [ "${optionx:?}" -eq "$optionx" ] 2>/dev/null; then echo "[*] $optionx Isn't A Valid Number!"; echo; unset "optionx"; continue; fi
											if [ -n "$option4" ]; then
												option5="$optionx"
											else
												option4="$optionx"
											fi
											break
										;;
										e|exit|back|menu)
											Return_To_Menu
											break
										;;
										*)
											Invalid_Option "$menu3"
										;;
									esac
								done
							fi
							break
						;;
						3)
							option2="remove"
							while true; do
								Show_Menu "Search Options:" \
									"Logs Containing Specific IP" \
									"Logs Containing Specific Port" \
									"Exit"
								Prompt_Input "1-2" menu3
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
										Return_To_Menu
										break
									;;
									*)
										Invalid_Option "$menu3"
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
							Invalid_Option "$menu2"
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
				Invalid_Option "$menu"
			;;
		esac
	done
}

Find_Install_Dir "$@"

# Load saved defaults from the config file if it exists
if [ -f "$skynetcfg" ]; then
	. "$skynetcfg"
fi

# Display the interactive menu when no command argument is provided
if [ -z "$1" ]; then
	Load_Menu
fi

# If the menu set any option variables, rebuild the script’s positional parameters to match those menu choices,
if [ -n "$option1" ]; then
	# Clear existing args before appending new ones
	set --
	for opt in "$option1" "$option2" "$option3" "$option4" "$option5"; do
		[ -n "$opt" ] && set -- "$@" "$opt"
	done
	stime="$(date +%s)"
	echo "[$] $0 $*"
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
				IPSet_Wrapper del Skynet-Blacklist "$3" nofilter
				sed -i "\\~\\(BLOCKED.*=$3 \\|Manual Ban.*=$3 \\)~d" "$skynetlog" "$skynetevents"
			;;
			range)
				if ! echo "$3" | Is_Range; then echo "[*] $3 Is Not A Valid Range"; echo; exit 2; fi
				echo "[i] Unbanning $3"
				IPSet_Wrapper del Skynet-BlockedRanges "$3" nofilter
				sed -i "\\~\\(BLOCKED.*=$3 \\|Manual Ban.*=$3 \\)~d" "$skynetlog" "$skynetevents"
			;;
			domain)
				if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
				if [ -z "$3" ]; then echo "[*] Domain Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				domain="$(echo "$3" | Strip_Domain)"
				echo "[i] Removing $domain From Blacklist"
				for ip in $(Domain_Lookup "$domain" 3); do
					echo "[i] Unbanning $ip"
					IPSet_Wrapper del Skynet-Blacklist "$ip" nofilter
					sed -i "\\~\\(BLOCKED.*=$ip \\|Manual Ban.*=$ip \\)~d" "$skynetlog" "$skynetevents"
				done
			;;
			comment)
				if [ -z "$3" ]; then echo "[*] Comment Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				echo "[i] Removing Bans With Comment Containing ($3)"
				sed "\\~add Skynet-Whitelist ~d;\\~$3~!d;s~ comment.*~~;s~add~del~g" "$skynetipset" | ipset restore -!
				echo "[i] Removing Old Logs - This May Take Awhile (To Skip Type ctrl+c)"
				trap 'echo;echo;echo "[*] Interrupted"; break' INT
				sed "\\~add Skynet-Whitelist ~d;\\~$3~!d;s~ comment.*~~" "$skynetipset" | cut -d' ' -f3 | while IFS= read -r "ip"; do
					sed -i "\\~\\(BLOCKED.*=$ip \\|Manual Ban.*=$ip \\)~d" "$skynetlog" "$skynetevents"
				done
				trap 'Release_Lock' INT TERM EXIT
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
				Command_Not_Recognized
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
					desc="$(date +"%b %e %T")"
				fi
				IPSet_Wrapper add Skynet-Blacklist "$3" nofilter "ManualBan: $desc"
				echo "$(date +"%b %e %T") Skynet: [Manual Ban] TYPE=Single SRC=$3 COMMENT=$desc " >> "$skynetevents"
			;;
			range)
				if ! echo "$3" | Is_Range; then echo "[*] $3 Is Not A Valid Range"; echo; exit 2; fi
				if [ "${#4}" -gt "243" ]; then echo "[*] $4 Is Not A Valid Comment. 243 Chars Max"; echo; exit 2; fi
				echo "[i] Banning $3"
				desc="$4"
				if [ -z "$4" ]; then
					desc="$(date +"%b %e %T")"
				fi
				IPSet_Wrapper add Skynet-BlockedRanges "$3" nofilter "ManualRBan: $desc" 
				echo "$(date +"%b %e %T") Skynet: [Manual Ban] TYPE=Range SRC=$3 COMMENT=$desc " >> "$skynetevents"
			;;
			domain)
				if [ -z "$3" ]; then echo "[*] Domain Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				domain="$(echo "$3" | Strip_Domain)"
				echo "[i] Adding $domain To Blacklist"
				for ip in $(Domain_Lookup "$domain" 3 | Filter_PrivateIP); do
					echo "[i] Banning $ip"
					IPSet_Wrapper add Skynet-Blacklist "$ip" nofilter "ManualBanD: $domain"
					echo "$(date +"%b %e %T") Skynet: [Manual Ban] TYPE=Domain SRC=$ip Host=$domain " >> "$skynetevents"
				done
			;;
			country)
				# Require at least one argument after "country"
				if [ -z "$3" ]; then echo "[*] Country Field Can't Be Empty - Please Try Again"; echo; exit 2; fi

				# Build raw country string from $3 onwards (so quotes aren't required)
				country_raw=""
				i=3
				while [ "$i" -le "$#" ]; do
					eval "arg=\${$i}"
					if [ -n "$arg" ]; then
						if [ -z "$country_raw" ]; then
							country_raw=$arg
						else
							country_raw="$country_raw $arg"
						fi
					fi
					i=$((i + 1))
				done

				# Disallow quotes in the combined country string
				if printf '%s\n' "$country_raw" | grep -qF '"'; then
					echo "[*] Country Field Can't Include Quotes - Please Try Again"
					echo
					exit 2
				fi

				# Normalise to lowercase and keep only 2-letter country codes
				countrylinklist="$(
					printf '%s\n' "$country_raw" |
					awk '
						{
							for (i = 1; i <= NF; i++) {
								code = tolower($i)
								if (code ~ /^[a-z][a-z]$/) {
									if (out != "") {
										out = out " "
									}
									out = out code
								}
							}
						}
						END {
							if (out != "") {
								print out
							}
						}
					'
				)"

				# No valid codes left after filtering
				if [ -z "$countrylinklist" ]; then
					echo "[✘] No valid 2-letter country codes detected - Please Try Again"
					echo
					exit 2
				fi

				# Remove any previous country bans (anything with "Country:" comment)
				if [ -n "$countrylist" ]; then
					echo "[i] Removing Previous Country Bans (${countrylist})"
					sed '\~add Skynet-Whitelist ~d;\~Country: ~!d;s~ comment.*~~;s~add~del~g' "$skynetipset" | ipset restore -!
				fi

				# For logging / other uses, keep the filtered list as-is
				countrylist="$countrylinklist"

				echo "[i] Banning Known IP Ranges For (${countrylist})"
				echo "[i] Downloading Lists, Filtering IPv4 Ranges & Applying Blacklists"

				for country in $countrylist; do
					curl -fskL --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors \
						"https://ipdeny.com/ipblocks/data/aggregated/${country}-aggregated.zone" \
					| grep -F "/" \
					| sed -n "/^[0-9,\\.,\\/]*$/s/^/add Skynet-BlockedRanges /;s/$/& comment \"Country: ${country}\"/p" \
					| ipset restore -!
				done
			;;
			asn)
				if [ -z "$3" ]; then echo "[*] ASN Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				if ! echo "$3" | Is_ASN; then echo "[*] $3 Is Not A Valid ASN"; echo; exit 2; fi
				asnlist="$(echo "$3" | awk '{print toupper($0)}')"
				echo "[i] Adding $asnlist To Blacklist"
				curl -fsSL --retry 3 --max-time 6 "https://asn.ipinfo.app/api/text/list/$asnlist" | awk -v asn="$asnlist" '/^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)([[:space:]]|$)/{printf "add Skynet-BlockedRanges %s comment \"ASN: %s \"\n", $1, asn }' | awk '!x[$0]++' | ipset restore -!
			;;
			*)
				Command_Not_Recognized
			;;
		esac
		echo "[i] Saving Changes"
		Save_IPSets
	;;

	banmalware|fs)
		Check_Lock "$@"
		if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
		if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
		Purge_Logs
		if [ "$2" = "disable" ] && [ "$fastswitch" = "disabled" ] && [ "$1" = "fs" ]; then
			echo "[*] Fast Switch List Already Disabled - Stopping Banmalware"
			echo; exit 1
		fi
		if Is_Enabled "$fastswitch" && [ "$1" = "fs" ] && [ -z "$2" ] || [ "$2" = "disable" ]; then
			echo "[i] Fast Switch List Disabled"
			fastswitch="disabled"
			set "banmalware"
		fi
		if Is_Enabled "$fastswitch" && [ "$1" = "banmalware" ]; then
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
				Log error -s "Fast Switch List URL Not Configured - Stopping Banmalware"
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
			curl -fsSL --retry 3 --max-time 6 "$listurl" | dos2unix | grep -vE "($excludelists)" > /jffs/addons/shared-whitelists/shared-Skynet-whitelist && Display_Result
		else
			curl -fsSL --retry 3 --max-time 6 "$listurl" | dos2unix > /jffs/addons/shared-whitelists/shared-Skynet-whitelist && Display_Result
		fi
		sed -i '\~^http[s]*://\|^www.~!d;' /jffs/addons/shared-whitelists/shared-Skynet-whitelist
		Display_Message "[i] Refreshing Whitelists"
		Whitelist_Extra
		Whitelist_VPN
		Whitelist_CDN
		Whitelist_Shared
		Refresh_MWhitelist
		Display_Result
		Display_Message "[i] Start Blacklist Consolidation"
		echo

		rm -rf "${skynetloc}"/lists/*
		mkdir -p "${skynetloc}/lists"
		cwd="$(pwd)"
		cd "${skynetloc}/lists" || exit 1

		# Build manifest: "url filename" (dedupe URLs, auto-suffix duplicate basenames)
		awk '
			NF == 0 { next }

			{
				# Strip trailing CR if present (CRLF safety)
				sub("\r$", "", $0)
				url = $0

				# Basic URL sanity: only keep http/https URLs
				if (url !~ /^https?:\/\/.*/) {
					next
				}

				# Skip exact duplicate URL lines
				if (seen[url]++) {
					next
				}

				n = split(url, parts, "/")
				name = parts[n]
				if (name == "") {
					next
				}

				count[name]++
				if (count[name] > 1) {
					# Same basename from another URL → suffix .1, .2, ...
					printf "%s %s.%d\n", url, name, count[name] - 1
				} else {
					printf "%s %s\n", url, name
				}
			}
		' /jffs/addons/shared-whitelists/shared-Skynet-whitelist > /tmp/skynet/skynet.manifest

		# Download all feeds in parallel
		while IFS=' ' read -r url list || [ -n "$url" ]; do
			(
				[ -n "$url" ] || exit 0
				curl -fsLZ --retry 2 --connect-timeout 5 --max-time 15 "$url" \
					-o "${skynetloc}/lists/$list" 2>/dev/null \
				&& echo "[✔] Downloaded $url" || echo "[✘] Failed to fetch: $url"
			) &
		done < /tmp/skynet/skynet.manifest
		wait

		# Clean and validate downloads
		dos2unix "${skynetloc}/lists/"* 2>/dev/null
		for file in "${skynetloc}/lists/"*; do
			basefile="$(basename "$file")"
			if ! grep -qF "$basefile" /tmp/skynet/skynet.manifest; then
				rm -f "$file"
			fi
		done

		sed -i '\~comment \"BanMalware: ~d' "$skynetipset"
		if [ -d "${skynetloc}/lists" ] && ls "${skynetloc}/lists/"* 1>/dev/null 2>&1; then
			if ! awk '
				BEGIN { valid_entries=0 }
				{
					# Match IPv4 with optional CIDR mask
					if ($1 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?([[:space:]]|$)/) {
						ip = $1
						src = FILENAME
						gsub(".*/", "", src)

						# Skip non-routable / private / special ranges that shouldn t be blacklisted
						# 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10 (CGNAT), 127.0.0.0/8, 169.254.0.0/16,
						# 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16,
						# 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24,
						# 224.0.0.0–255.255.255.255 (multicast / reserved)
						if (ip ~ /^0\./ ||
							ip ~ /^10\./ ||
							ip ~ /^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./ ||
							ip ~ /^127\./ ||
							ip ~ /^169\.254\./ ||
							ip ~ /^172\.1[6-9]\./ ||
							ip ~ /^172\.2[0-9]\./ ||
							ip ~ /^172\.3[0-1]\./ ||
							ip ~ /^192\.0\.0\./ ||
							ip ~ /^192\.0\.2\./ ||
							ip ~ /^192\.168\./ ||
							ip ~ /^198\.(1[8-9])\./ ||
							ip ~ /^198\.51\.100\./ ||
							ip ~ /^203\.0\.113\./ ||
							ip ~ /^2(2[4-9]|[3-4][0-9]|5[0-5])\./) {
							next
						}

						# De-duplicate on IP/CIDR
						if (!x[ip]++) {
							valid_entries++
							# Single host or /32 → Skynet-Blacklist
							if (ip ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}\/32$/ || ip !~ /\//) {
								print "add Skynet-Blacklist " ip " comment \"BanMalware: " src "\""
							}
							# Network ranges (/0–/31) → Skynet-BlockedRanges
							else if (ip ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-1])$/) {
								print "add Skynet-BlockedRanges " ip " comment \"BanMalware: " src "\""
							}
						}
					}
				}
				END {
					if (valid_entries == 0) exit 1
				}
			' "${skynetloc}/lists/"* >> "$skynetipset"; then
				result="$(Red "[$(($(date +%s) - btime))s]")"
				printf '%-8s\n' "$result"
				printf '%-35s\n' "[✘] No usable malware entries found in feeds"
				nocfg="1"
			fi
		else
			printf '%-35s\n' "[✘] No malware feeds found — skipping consolidation"
			nocfg="1"
		fi
		printf "%-35s | " "[i] Finish Blacklist Consolidation"
		Display_Result
		Display_Message "[i] Applying New Blacklist"
		ipset flush Skynet-Blacklist; ipset flush Skynet-BlockedRanges
		ipset restore -! -f "$skynetipset" >/dev/null 2>&1
		Display_Result
		Display_Message "[i] Refreshing AiProtect Bans"
		Refresh_AiProtect
		Display_Result
		Display_Message "[i] Saving Changes"
		Save_IPSets
		Display_Result
		forcebanmalwareupdate="disabled"
		echo
		echo "[i] For Whitelisting Assistance -"
		echo "[i] https://www.snbforums.com/threads/release-skynet-router-firewall-security-enhancements.16798/#post-115872"
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
					desc="$(date +"%b %e %T")"
				fi
				IPSet_Wrapper add Skynet-Whitelist "$3" nofilter "ManualWlist: $desc"
				sed -i "\\~=$3 ~d" "$skynetlog" "$skynetevents" && echo "$(date +"%b %e %T") Skynet: [Manual Whitelist] TYPE=Single SRC=$3 COMMENT=$desc " >> "$skynetevents"
				ipset -q -D Skynet-Blacklist "$3"
				ipset -q -D Skynet-BlockedRanges "$3"
			;;
			domain)
				if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
				if [ -z "$3" ]; then echo "[*] Domain Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
				domain="$(echo "$3" | Strip_Domain)"
				echo "[i] Adding $domain To Whitelist"
				for ip in $(Domain_Lookup "$domain" 3); do
					echo "[i] Whitelisting $ip"
					IPSet_Wrapper add Skynet-Whitelist "$ip" nofilter "ManualWlistD: $domain"
					sed -i "\\~=$ip ~d" "$skynetlog" "$skynetevents" && echo "$(date +"%b %e %T") Skynet: [Manual Whitelist] TYPE=Domain SRC=$ip Host=$domain " >> "$skynetevents"
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
				curl -fsSL --retry 3 --max-time 6 "https://asn.ipinfo.app/api/text/list/$asnlist" | awk -v asn="$asnlist" '/^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)([[:space:]]|$)/{printf "add Skynet-Whitelist %s comment \"ASN: %s \"\n", $1, asn }'| awk '!x[$0]++' | ipset restore -!
			;;
			remove)
				case "$3" in
					entry)
						if ! echo "$4" | Is_IPRange; then echo "[*] $4 Is Not A Valid IP/Range"; echo; exit 2; fi
						echo "[i] Removing $4 From Whitelist"
						IPSet_Wrapper del Skynet-Whitelist "$4" nofilter
						sed -i "\\~=$4 ~d" "$skynetlog" "$skynetevents"
					;;
					comment)
						if [ -z "$4" ]; then echo "[*] Comment Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
						echo "[i] Removing All Entries With Comment Matching \"$4\" From Whitelist"
						sed "\\~add Skynet-Whitelist ~!d;\\~$4~!d;s~ comment.*~~;s~add~del~g" "$skynetipset" | ipset restore -!
						echo "[i] Removing Old Logs - This May Take Awhile (To Skip Type ctrl+c)"
						trap 'echo;echo;echo "[*] Interrupted"; break' INT
						sed "\\~add Skynet-Whitelist ~!d;\\~$4~!d" "$skynetipset" | cut -d' ' -f3 | while IFS= read -r "ip"; do
							sed -i "\\~=$ip ~d" "$skynetlog" "$skynetevents"
						done
						trap 'Release_Lock' INT TERM EXIT
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
						Command_Not_Recognized
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
				Command_Not_Recognized
			;;
		esac
		echo "[i] Saving Changes"
		Save_IPSets
	;;

	import)
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
					curl -fsSL --retry 3 --max-time 6 "$3" | dos2unix | grep -E '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)$' > /tmp/skynet/iplist-unfiltered.txt || { echo "[*] 404 Error Detected - Stopping Import"; rm -rf /tmp/skynet/iplist-unfiltered.txt; echo; exit 1; }
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
					imptime="$(date +"%b %e %T")"
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
					curl -fsSL --retry 3 --max-time 6 "$3" | dos2unix | grep -E '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)$' > /tmp/skynet/iplist-unfiltered.txt || { echo "[*] 404 Error Detected - Stopping Import"; rm -rf /tmp/skynet/iplist-unfiltered.txt; echo; exit 1; }
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
					imptime="$(date +"%b %e %T")"
					Filter_PrivateIP < /tmp/skynet/iplist-unfiltered.txt | awk -v desc="Imported: $imptime" '{printf "add Skynet-Whitelist %s comment \"%s\"\n", $1, desc }' > /tmp/skynet/iplist-filtered.txt
				fi
				echo "[i] Adding IPs To Whitelist"
				ipset restore -! -f "/tmp/skynet/iplist-filtered.txt"
				rm -rf /tmp/skynet/iplist-unfiltered.txt /tmp/skynet/iplist-filtered.txt
				echo "[i] Saving Changes"
				Save_IPSets
			;;
			*)
				Command_Not_Recognized
			;;
		esac
	;;

	deport)
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
					curl -fsSL --retry 3 --max-time 6 "$3" | dos2unix | grep -E '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)$' > /tmp/skynet/iplist-unfiltered.txt || { echo "[*] 404 Error Detected - Stopping Import"; rm -rf /tmp/skynet/iplist-unfiltered.txt; echo; exit 1; }
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
					curl -fsSL --retry 3 --max-time 6 "$3" | dos2unix | grep -E '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)$' > /tmp/skynet/iplist-unfiltered.txt || { echo "[*] 404 Error Detected - Stopping Import"; rm -rf /tmp/skynet/iplist-unfiltered.txt; echo; exit 1; }
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
				Command_Not_Recognized
			;;
		esac
	;;

	save)
		Check_Lock "$@"
		if ! Check_IPSets || ! Check_IPTables; then
			Log error -s "Rule Integrity Violation - Restarting Firewall [ ${fail}]"
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
		Log info "Startup Initiated... ( $(echo "$@" | sed 's~start ~~g') )"
		Unload_Cron "all"
		Check_Settings
		Check_Files firewall-start services-stop service-event post-mount unmount
		Clean_Temp
		if ! Check_Connection 10 5; then echo; exit 1; fi
		Load_Cron "save"
		modprobe xt_set
		if [ -f "$skynetipset" ]; then ipset restore -! -f "$skynetipset"; else Log info -s "Setting Up Skynet"; touch "$skynetipset"; fi
		if ! ipset -L -n Skynet-Whitelist >/dev/null 2>&1; then ipset -q create Skynet-Whitelist hash:net hashsize 64 maxelem "$((65536 * 6))" comment; fi
		if ! ipset -L -n Skynet-WhitelistDomains >/dev/null 2>&1; then ipset -q create Skynet-WhitelistDomains hash:ip hashsize 64 maxelem "$((65536 * 8))" comment timeout 86400; fi
		if ! ipset -L -n Skynet-Blacklist >/dev/null 2>&1; then ipset -q create Skynet-Blacklist hash:ip hashsize 64 maxelem "$((65536 * 16))" comment; fi
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
		unset "nolog"
		sed -i '\~DROP IN=~d' "$syslog1loc" "$syslogloc" 2>/dev/null
		if Is_Enabled "$forcebanmalwareupdate"; then
			Write_Config
			Release_Lock
			# force a summary now, before we trigger banmalware
			Print_Log "$@"
			# then run banmalware as a child (not via exec)
			"$0" banmalware
			exit 0
		fi
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
		Log info "Restarting Firewall Service"
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
		Log info "Skynet Disabled"
		Purge_Logs "all"
		nolog="2"
	;;

	update)
		Check_Lock "$@"
		if ! Check_Connection; then echo "[*] Connection Error Detected - Exiting"; echo; exit 1; fi
		remotedir="https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master"
		remotever="$(curl -fsL --retry 3 --max-time 6 "$remotedir/firewall.sh" | Filter_Version)"
		localmd5="$(md5sum "$0" | awk '{print $1}')"
		remotemd5="$(curl -fsL --retry 3 --max-time 6 "${remotedir}/firewall.sh" | md5sum | awk '{print $1}')"
		if [ "$localmd5" = "$remotemd5" ] && [ "$2" != "-f" ]; then
			Log info "Skynet Up To Date - $localver (${localmd5})"
			nolog="2"
		elif [ "$localmd5" != "$remotemd5" ] && [ "$2" = "check" ]; then
			Log info "Skynet Update Detected - $remotever (${remotemd5})"
			nolog="2"
		elif [ "$2" = "-f" ]; then
			echo "[i] Forcing Update"
		fi
		if [ "$localmd5" != "$remotemd5" ] || [ "$2" = "-f" ] && [ "$nolog" != "2" ]; then
			Log info "New Version Detected - Updating To $remotever (${remotemd5})"
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
			Log info "Restarting Firewall Service"
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
						Command_Not_Recognized
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
						forcebanmalwareupdate="enabled"
						Unload_Cron "banmalware"
						Load_Cron "banmalwaredaily"
						echo "[i] Daily Malware Blacklist Updates Enabled"
					;;
					weekly)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						banmalwareupdate="weekly"
						forcebanmalwareupdate="enabled"
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
						Command_Not_Recognized
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
						Command_Not_Recognized
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
						Command_Not_Recognized
					;;
				esac
			;;
			logsize)
				case "$3" in
					10)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						logsize="10"
						Purge_Logs
						echo "[i] Log Size Set To 10MB"
					;;
					*)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						if Is_Numeric "$3"; then
							if [ "$3" -lt 10 ]; then 
								echo "[*] $3 Is Not A Valid Size - Must Be At Least 10MB"
							else
								logsize="$3"
								Purge_Logs
								echo "[i] Log Size Set To ${logsize}MB"
							fi
						else
							echo "[*] $3 Is Not A Valid Size - Must Be Numeric"
							Command_Not_Recognized
						fi
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
						Command_Not_Recognized
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
						Command_Not_Recognized
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
						Command_Not_Recognized
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
						Command_Not_Recognized
					;;
				esac
			;;
			extendedstats)
				case "$3" in
					enable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						extendedstats="enabled"
						Check_Security
						echo "[i] Extended Stats Enabled"
					;;
					disable)
						Check_Lock "$@"
						if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
						Purge_Logs
						extendedstats="disabled"
						echo "[i] Extended Stats Disabled"
					;;
					*)
						Command_Not_Recognized
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
										IPSet_Wrapper del Skynet-IOT "$ip" nofilter
									fi
							done
						else
							if ! echo "$4" | Is_IPRange; then
								echo "[*] $4 Is Not A Valid IP/Range"
								echo
							else
								IPSet_Wrapper del Skynet-IOT "$4" nofilter
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
						desc="$(date +"%b %e %T")"
						if echo "$4" | grep -q ","; then
							for ip in $(echo "$4" | sed 's~,~ ~g'); do
									if ! echo "$ip" | Is_IPRange; then
										echo "[*] $ip Is Not A Valid IP/Range"
										echo
									else
										IPSet_Wrapper add Skynet-IOT "$ip" nofilter "IOTBan: $desc"
									fi
							done
						else
							if ! echo "$4" | Is_IPRange; then
								echo "[*] $4 Is Not A Valid IP/Range"
								echo
							else
								IPSet_Wrapper add Skynet-IOT "$4" nofilter "IOTBan: $desc"
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
							Command_Not_Recognized
						;;
					esac
					;;
					*)
						Command_Not_Recognized
					;;
				esac
				if [ "$3" != "view" ]; then
					if Is_Enabled "$iotblocked"; then
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
						Command_Not_Recognized
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
						Command_Not_Recognized
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
						Command_Not_Recognized
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
						Command_Not_Recognized
					;;
				esac
			;;
			*)
				Command_Not_Recognized
			;;
		esac
	;;

	debug)
		case "$2" in
			watch)
				if ! Check_IPSets || ! Check_IPTables; then echo "[*] Skynet Not Running - Exiting"; echo; exit 1; fi
				if [ "$logmode" = "disabled" ]; then echo "[*] Logging Is Disabled - Exiting!"; echo; exit 2; fi
				trap 'echo;echo;echo "[*] Interrupted"; break; Purge_Logs' INT
				echo "[i] Watching Syslog For Log Entries (ctrl +c) To Stop"
				echo
				Purge_Logs
				case "$3" in
					ip)
						if ! echo "$4" | Is_IP; then echo "[*] $4 Is Not A Valid IP"; echo; exit 2; fi
						echo "[i] Filtering Entries Involving IP $4"
						echo

						tail -F "$syslogloc" | while IFS= read -r logoutput; do
							case "$logoutput" in
								*INVALID*"=$4 "*)
									Blue "$logoutput"
									ip_field="DST"
								;;
								*INBOUND*"=$4 "*)
									Ylow "$logoutput"
									ip_field="SRC"
								;;
								*OUTBOUND*"=$4 "*)
									Red "$logoutput"
									ip_field="DST"
								;;
								*IOT*"=$4 "*)
									Red "$logoutput"
									ip_field="DST"
								;;
								*)
									# Not a matching IP / class we care about
									continue
								;;
							esac

							# Skip heavier work if extended stats are disabled
							Is_Enabled "$extendedstats" || continue

							# Extract SRC=/DST= purely with shell parameter expansion
							case "$ip_field" in
								SRC)
									tmp=${logoutput#* SRC=}
								;;
								DST)
									tmp=${logoutput#* DST=}
								;;
								*)
									continue
								;;
							esac

							# If the token wasn't found, bail out
							[ "$tmp" = "$logoutput" ] && continue

							# Trim at next space, then strip any trailing comma
							tmp=${tmp%% *}
							ip=${tmp%%,*}

							[ -z "$ip" ] && continue

							# Look up associated domains from the recent tail of dnsmasq logs
							# Hard-coded to last 100 lines to cap CPU work
							domainlist="$(
								tail -n 100 /opt/var/log/dnsmasq.log 2>/dev/null |
								awk -v ip="$ip" '
									/reply / && index($0, " is " ip) { print $(NF-2) }
								' | Strip_Domain | Filter_OutIP | xargs
							)"

							[ -n "$domainlist" ] && Red "Associated Domain(s) - [$domainlist]"
						done
					;;
					port)
						if ! echo "$4" | Is_Port || [ "$4" -gt "65535" ]; then echo "[*] $4 Is Not A Valid Port"; echo; exit 2; fi
						echo "[i] Filtering Entries Involving Port $4"
						echo

						tail -F "$syslogloc" | while IFS= read -r logoutput; do
							case "$logoutput" in
								*INVALID*"PT=$4 "*)
									Blue "$logoutput"
									ip_field="DST"
								;;
								*INBOUND*"PT=$4 "*)
									Ylow "$logoutput"
									ip_field="SRC"
								;;
								*OUTBOUND*"PT=$4 "*)
									Red "$logoutput"
									ip_field="DST"
								;;
								*IOT*"PT=$4 "*)
									Red "$logoutput"
									ip_field="DST"
								;;
								*)
									# Not a matching port / class we care about
									continue
								;;
							esac

							# Skip heavier work if extended stats are disabled
							Is_Enabled "$extendedstats" || continue

							# Extract SRC=/DST= purely with shell parameter expansion
							case "$ip_field" in
								SRC)
									tmp=${logoutput#* SRC=}
								;;
								DST)
									tmp=${logoutput#* DST=}
								;;
								*)
									continue
								;;
							esac

							# If the token wasn't found, bail out
							[ "$tmp" = "$logoutput" ] && continue

							# Trim at next space, then strip any trailing comma
							tmp=${tmp%% *}
							ip=${tmp%%,*}

							[ -z "$ip" ] && continue

							# Look up associated domains from the recent tail of dnsmasq logs
							# Hard-coded to last 100 lines to cap CPU work
							domainlist="$(
								tail -n 100 /opt/var/log/dnsmasq.log 2>/dev/null |
								awk -v ip="$ip" '
									/reply / && index($0, " is " ip) { print $(NF-2) }
								' | Strip_Domain | Filter_OutIP | xargs
							)"

							[ -n "$domainlist" ] && Red "Associated Domain(s) - [$domainlist]"
						done
					;;
					*)
						tail -F "$syslogloc" | while IFS= read -r logoutput; do
							case "$logoutput" in
								*INVALID*)
									Blue "$logoutput"
									ip_field="DST"
								;;
								*INBOUND*)
									Ylow "$logoutput"
									ip_field="SRC"
								;;
								*OUTBOUND*)
									Red "$logoutput"
									ip_field="DST"
								;;
								*IOT*)
									Red "$logoutput"
									ip_field="DST"
								;;
								*)
									# Not a Skynet block we care about
									continue
								;;
							esac

							# Skip heavier work if extended stats are disabled
							Is_Enabled "$extendedstats" || continue

							# Extract SRC=/DST= purely with shell parameter expansion
							case "$ip_field" in
								SRC)
									tmp=${logoutput#* SRC=}
								;;
								DST)
									tmp=${logoutput#* DST=}
								;;
								*)
									continue
								;;
							esac

							# If the token wasn't found, bail out
							[ "$tmp" = "$logoutput" ] && continue

							# Trim at next space, then strip any trailing comma
							tmp=${tmp%% *}
							ip=${tmp%%,*}

							[ -z "$ip" ] && continue

							# Look up associated domains from the recent tail of dnsmasq logs
							# Hard-coded to last 100 lines to cap CPU work
							domainlist="$(
								tail -n 100 /opt/var/log/dnsmasq.log 2>/dev/null |
								awk -v ip="$ip" '
									/reply / && index($0, " is " ip) { print $(NF-2) }
								' | Strip_Domain | Filter_OutIP | xargs
							)"

							[ -n "$domainlist" ] && Red "Associated Domain(s) - [$domainlist]"
						done
					;;
				esac
				trap 'Release_Lock' INT TERM EXIT
				nocfg="1"
			;;
			info)
				if [ -f "$LOCK_FILE" ] && ! flock -n 9 9<"$LOCK_FILE"; then
					locked_cmd=$(cut -d'|' -f1 "$LOCK_FILE")
					locked_pid=$(cut -d'|' -f2 "$LOCK_FILE")
					lock_timestamp=$(cut -d'|' -f3 "$LOCK_FILE")

					if [ -n "$locked_pid" ] && [ -d "/proc/$locked_pid" ]; then
						current_time=$(date +%s)
						runtime=$(( current_time - lock_timestamp ))

						echo
						Red "[*] Lock File Detected ($locked_cmd) (pid=$locked_pid, runtime=${runtime}s)"
						Ylow '[*] Locked Processes Generally Take 1-2 Minutes To Complete And May Result In Temporarily "Failed" Tests'
					fi
				fi
				printf '╔═════════════════════ System ══════════════════════════════════════════════════════════════════════════════╗\n'
				printf '║ %-20s │ %-82s ║\n' "Router Model"   "$(nvram get productid)"
				printf '║ %-20s │ %-82s ║\n' "Skynet Version" "$localver ($(Filter_Date < "$0"))"
				printf '║ └── %-16s │ %-82s ║\n' "Hash" "$(md5sum "$0" | awk "{print \$1}")"
				printf '║ %-20s │ %-82s ║\n' "FW Version"     "$(uname -o) v$(nvram get buildno)_$(nvram get extendno) (Kernel $(uname -r)) ($(uname -v | awk "{printf \"%s %s %s\n\", \$5,\$6,\$9}"))"
				printf '║ %-20s │ %-82s ║\n' "iptables"       "$(iptables --version)"
				printf '║ %-20s │ %-82s ║\n' "ipset"          "$(ipset -v 2>/dev/null | head -n1)"
				printf '║ %-20s │ %-82s ║\n' "Public IP"      "$(if nvram get wan0_ipaddr | Is_PrivateIP; then Red "$(nvram get wan0_ipaddr)"; else nvram get wan0_ipaddr; fi)"
				printf '║ %-20s │ %-82s ║\n' "WAN Info"       "${iface} - $(nvram get wan0_proto)"
				printf '╚══════════════════════╧════════════════════════════════════════════════════════════════════════════════════╝\n\n\n'
				printf '╔═════════════════════ Storage ═════════════════════════════════════════════════════════════════════════════╗\n'
				printf '║ %-20s │ %-82s ║\n' "Install Dir"    "${skynetloc}"
				UA="$(df -h "$skynetloc" | awk 'NR==2{print $3 " / " $2}')"
				printf '║ └── %-16s │ %-82s ║\n' "Used/Total" "$UA"
				if [ -n "$swaplocation" ]; then
					printf '║ %-20s │ %-82s ║\n' "SWAP File" "$swaplocation"
					SZ="$(du -h "$swaplocation" | awk '{print $1}')"
					printf '║ └── %-16s │ %-82s ║\n' "Size" "$SZ"
				fi
				printf '╚══════════════════════╧════════════════════════════════════════════════════════════════════════════════════╝\n\n\n'
				printf '╔═════════════════════ Runtime ═════════════════════════════════════════════════════════════════════════════╗\n'
				printf '║ %-20s │ %-82s ║\n' "Uptime"        "$(uptime | awk -F'( |,|:)+' '{ if ($7=="min") m=$6; else if ($7~/^day/) {d=$6;h=$8;m=$9} else {h=$6;m=$7} } {print d+0,"days,",h+0,"hours,",m+0,"minutes."}')"
				if grep -qF "MemAvailable" /proc/meminfo; then
					memavailable=$(( $(awk '/MemAvailable/ {print $2}' /proc/meminfo) /1024 ))
				else
					memavailable=$(( $(awk '/MemFree/     {print $2}' /proc/meminfo) /1024 ))
				fi
				totalmem=$(( $(awk '/MemTotal/     {print $2}' /proc/meminfo) /1024 ))
				printf '║ %-20s │ %-82s ║\n' "RAM Used/Total" "(${memavailable}M / ${totalmem}M)"
				printf '╚══════════════════════╧════════════════════════════════════════════════════════════════════════════════════╝\n\n\n'
				printf '╔═════════════════════ Logging ═════════════════════════════════════════════════════════════════════════════╗\n'
				printf '║ %-20s │ %-82s ║\n' "Syslog Locations" "$syslogloc $syslog1loc"
				printf '║ %-20s │ %-82s ║\n' "Skynet Log"       "${skynetlog}"
				SZ="$(du -h "${skynetlog}" | awk '{print $1}')"
				printf '║ └── %-16s │ %-82s ║\n' "Used/Total" "$SZ / ${logsize}MB"
				if [ -n "$countrylist" ]; then
					countries="$countrylist"
					if [ "${#countries}" -gt 82 ]; then
						countries="$(printf '%.81s+' "$countries")"
					fi
					printf '║ %-20s │ %-82s ║\n' "Banned Countries" "$countries"
				fi
				[ -n "$customlisturl" ] && printf '║ %-20s │ %-82s ║\n' "Custom Filter URL" "$customlisturl"
				Generate_Blocked_Events
				printf '║ %-20s │ %-84s ║\n' "Monitor Span"      "$(grep -m1 -F "BLOCKED -" "$skynetlog" | awk '{printf "%s %s %s\n", $1, $2, $3}') → $(grep -F "BLOCKED -" "$skynetlog" | tail -1 | awk '{printf "%s %s %s\n", $1, $2, $3}')"
				printf '╚══════════════════════╧════════════════════════════════════════════════════════════════════════════════════╝\n\n\n'
				passedtests="0"
				totaltests="18"
				Display_Header "6"
				ip neigh \
				| grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3} ' \
				| sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 \
				| while IFS= read -r ip; do
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

					printf '║ %-40s ║ %-16s ║ %-20s ║ %-31s ║\n' \
						"$localname" "$ipaddr" "$macaddr" "$state"
					done
				printf '╚══════════════════════════════════════════╩══════════════════╩══════════════════════╩══════════════════════╝\n\n\n'
				Display_Header "7"
				printf "║ %-33s ║ " "Internet-Connectivity"
				if Check_Connection >/dev/null 2>&1; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-80s ║\n' "$result"
				printf "║ %-33s ║ " "Public IP Address"
				if [ ! "$(nvram get wan0_ipaddr | Is_PrivateIP)" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-80s ║\n' "$result"
				printf "║ %-33s ║ " "Write Permission"
				if [ -w "${skynetloc}" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-80s ║\n' "$result"
				printf "║ %-33s ║ " "Config File"
				if [ -f "${skynetcfg}" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-80s ║\n' "$result"
				printf "║ %-33s ║ " "Firewall-Start Entry"
				if grep -E "start.* # Skynet" /jffs/scripts/firewall-start | grep -qvE "^#"; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-80s ║\n' "$result"
				printf "║ %-33s ║ " "Services-Stop Entry"
				if grep -F "# Skynet" /jffs/scripts/services-stop | grep -qvE "^#"; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-80s ║\n' "$result"
				printf "║ %-33s ║ " "Service-Event Entry"
				if grep -F "# Skynet" /jffs/scripts/service-event | grep -qvE "^#"; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-80s ║\n' "$result"
				printf "║ %-33s ║ " "Profile.add Entry"
				if grep -F "# Skynet" /jffs/configs/profile.add | grep -qvE "^#"; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-80s ║\n' "$result"
				printf "║ %-33s ║ " "SWAP File"
				if Check_Swap; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-80s ║\n' "$result"
				printf "║ %-33s ║ " "Cron Jobs"
				if [ "$(cru l | grep -c "Skynet")" -ge "2" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-80s ║\n' "$result"
				printf "║ %-33s ║ " "NTP Sync"
				if [ "$(nvram get ntp_ready)" = "1" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-80s ║\n' "$result"
				printf "║ %-33s ║ " "Log Level $(nvram get message_loglevel) Settings"
				if [ "$(nvram get message_loglevel)" -le "$(nvram get log_level)" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-80s ║\n' "$result"
				printf "║ %-33s ║ " "Duplicate Rules In RAW"
				if [ "$(iptables-save -t raw | sort | uniq -d | grep -c " ")" = "0" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-80s ║\n' "$result"
				printf "║ %-33s ║ " "IPSets"
				if Check_IPSets; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-80s ║\n' "$result"
				printf "║ %-33s ║ " "IPTables Rules"
				if Check_IPTables; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
				printf '%-80s ║\n' "$result"
				if Is_Enabled "$displaywebui"; then
					printf "║ %-33s ║ " "Local WebUI Files"
					[ -f "${skynetloc}/webui/chart.js" ] || localfail="${localfail}chart.js "
					[ -f "${skynetloc}/webui/chartjs-plugin-zoom.js" ] || localfail="${localfail}chartjs-plugin-zoom.js "
					[ -f "${skynetloc}/webui/hammerjs.js" ] || localfail="${localfail}hammerjs.js "
					[ -f "${skynetloc}/webui/skynet.asp" ] || localfail="${localfail}skynet.asp "
					[ -f "${skynetloc}/webui/stats.js" ] || localfail="${localfail}stats.js "
					if [ -z "$localfail" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
					printf '%-80s ║\n' "$result"
					printf "║ %-33s ║ " "Mounted WebUI Files"
					Get_WebUI_Page "${skynetloc}/webui/skynet.asp" 2>/dev/null
					[ -f "/www/user/skynet/chart.js" ] || mountedfail="${mountedfail}chart.js "
					[ -f "/www/user/skynet/chartjs-plugin-zoom.js" ] || mountedfail="${mountedfail}chartjs-plugin-zoom.js "
					[ -f "/www/user/skynet/hammerjs.js" ] || mountedfail="${mountedfail}hammerjs.js "
					[ -f "/www/user/${MyPage}" ] || mountedfail="${mountedfail}skynet.asp "
					[ -f "/www/user/skynet/stats.js" ] || mountedfail="${mountedfail}stats.js "
					if [ -z "$mountedfail" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
					printf '%-80s ║\n' "$result"
					printf "║ %-33s ║ " "MenuTree.js Entry"
					if grep -qF "Skynet" "/www/require/modules/menuTree.js"; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
					printf '%-80s ║\n' "$result"
				else
					totaltests="$((totaltests - 3))"
				fi
				printf '╠═══════════════════════════════════╩═══════════════════════════════════════════════════════════════════════╣\n'
				printf '║ %-105s ║\n' "${passedtests}/${totaltests} Tests Sucessful"
				printf '╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n\n\n'
				Display_Header "8"
				printf '║ %-33s ║ %-80s ║\n' "Skynet Auto-Updates" "$(if Is_Enabled "$autoupdate"; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
				printf '║ %-33s ║ %-80s ║\n' "Malware List Auto-Updates" "$(if [ "$banmalwareupdate" = "daily" ] || [ "$banmalwareupdate" = "weekly" ]; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
				printf '║ %-33s ║ %-80s ║\n' "Logging" "$(if Is_Enabled "$logmode"; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
				printf '║ %-33s ║ %-80s ║\n' "Filter Traffic" "$(if [ "$filtertraffic" = "all" ]; then Grn "[Enabled]"; else Ylow "[Selective]"; fi)"
				printf '║ %-33s ║ %-80s ║\n' "Unban PrivateIP" "$(if Is_Enabled "$unbanprivateip"; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
				printf '║ %-33s ║ %-80s ║\n' "Log Invalid Packets" "$(if Is_Enabled "$loginvalid"; then Grn "[Enabled]"; else Grn "[Disabled]"; fi)"
				printf '║ %-33s ║ %-80s ║\n' "Log Size" "$(Grn "[${logsize}MB]")"
				printf '║ %-33s ║ %-80s ║\n' "Import AiProtect Data" "$(if Is_Enabled "$banaiprotect"; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
				printf '║ %-33s ║ %-80s ║\n' "Secure Mode" "$(if Is_Enabled "$securemode"; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
				printf '║ %-33s ║ %-80s ║\n' "Extended Stats" "$(if Is_Enabled "$extendedstats"; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
				printf '║ %-33s ║ %-80s ║\n' "Fast Switch List" "$(if Is_Enabled "$fastswitch"; then Ylow "[Enabled]"; else Grn "[Disabled]"; fi)"
				printf '║ %-33s ║ %-80s ║\n' "Syslog Location" "$(if { [ "$syslogloc" = "/tmp/syslog.log" ] && [ "$syslog1loc" = "/tmp/syslog.log-1" ]; } || { [ "$syslogloc" = "/jffs/syslog.log" ] && [ "$syslog1loc" = "/jffs/syslog.log-1" ]; } then Grn "[Default]"; else Ylow "[Custom]"; fi)"
				printf '║ %-33s ║ %-80s ║\n' "IOT Blocking" "$(if [ "$iotblocked" != "enabled" ]; then Grn "[Disabled]"; else Ylow "[Enabled]"; fi)"
				printf '║ %-33s ║ %-80s ║\n' "IOT Logging" "$(if [ "$iotlogging" != "enabled" ]; then Red "[Disabled]"; else Grn "[Enabled]"; fi)"
				printf '║ %-33s ║ %-80s ║\n' "Country Lookup For Stats" "$(if Is_Enabled "$lookupcountry"; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
				printf '║ %-33s ║ %-80s ║\n' "CDN Whitelisting" "$(if Is_Enabled "$cdnwhitelist"; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
				printf '║ %-33s ║ %-80s ║\n' "Display WebUI" "$(if Is_Enabled "$displaywebui"; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
				printf '╚═══════════════════════════════════╩═══════════════════════════════════════════════════════════════════════╝\n'
				if [ -n "$fail" ]; then echo;echo "[*] Rule Integrity Violation - [ ${fail}]"; unset fail; fi
				if [ -n "$localfail" ]; then echo;echo "[*] Local File Missing - [ ${localfail}]"; fi
				if [ -n "$mountedfail" ]; then echo;echo "[*] Mounted File Missing - [ ${mountedfail}]"; fi
				if [ "$3" = "extended" ]; then echo;echo; cat "$skynetcfg"; fi
				nocfg="1"
			;;
			genstats)
				Check_Lock "$@"
				Purge_Logs "all"
				if nvram get rc_support | grep -qF "am_addons"; then
					if Is_Enabled "$displaywebui"; then
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
						Check_Files firewall-start services-stop service-event post-mount unmount
						swaplocation="$(awk 'NR==2 { print $1 }' /proc/swaps)"
						if [ -z "$swaplocation" ] && ! Check_Swap; then
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
							Log info "Restarting Firewall Service"
							restartfirewall="1"
							nolog="2"
						else
							echo "[*] Pre-existing SWAP File Detected - Exiting!"
						fi
					;;
					uninstall)
						Check_Lock "$@"
						if ! grep -qF "swapon " /jffs/scripts/post-mount; then
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
							swaplocation="$(awk 'NR==2 { print $1 }' /proc/swaps)"
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
						fi
						sed -i '\~swapoff ~d' /jffs/scripts/unmount
						Log info "Restarting Firewall Service"
						restartfirewall="1"
						nolog="2"
					;;
					*)
						Command_Not_Recognized
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
					Prompt_Typed "backuplocation" "Location" "[*] Skynet Backup Doesn't Exist In Expected Path, Please Provide Location"
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
				Log info "Restarting Firewall Service"
				restartfirewall="1"
				nolog="2"
			;;
			run)
				Check_Lock "$@"
				func="$3"
				# Shift off “run” and the sub‐command name, leaving any extra args in $@
				shift 3

				# Verify the function exists in this script
				if grep -qE "^[[:space:]]*${func}[[:space:]]*\(\)" "$0"; then
					# Show what we're invoking, including any follow‐up args
					if [ $# -gt 0 ]; then
						echo "[i] Running function ${func}() with args: $*"
					else
						echo "[i] Running function ${func}()"
					fi
					echo

					# Call it with those args
					if "$func" "$@"; then
						echo
						echo "[i] ${func}() completed successfully"
					else
						code=$?
						echo
						echo "[!] ${func}() failed with exit code $code"
					fi
				else
					echo "[!] Function ${func}() does not exist"
				fi
			;;
			*)
				Command_Not_Recognized
			;;
		esac
	;;

	stats)
		Run_Stats "$@"
	;;

	install)
		Check_Lock "$@"
		if ! ipset -v 2>/dev/null | grep -qE 'v6|v7'; then
			echo "[*] IPSet Version Not Supported - Please Update To Latest Firmware"
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
			Show_Menu "Please Select Traffic Filter Mode" \
				"All - (Recommended)" \
				"Inbound" \
				"Outbound" \
				"Exit"
			Prompt_Input "1-3" mode1
			case "${mode1:?}" in
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
					Invalid_Option "$mode1"
				;;
			esac
		done
		echo
		echo
		while true; do
			Show_Menu "Enable Logging (Used For Generating Stats And Monitoring Blocked IP's)" \
				"Yes - (Recommended)" \
				"No" \
				"Exit"
			Prompt_Input "1-2" mode3
			case "${mode3:?}" in
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
				e|exit|back|menu)
					echo "[*] Exiting!"
					echo; exit 0
				;;
				*)
					Invalid_Option "$mode3"
				;;
			esac
		done
		echo
		echo
		while true; do
			Show_Menu "Enable Malware Blacklist Auto-Updates?" \
				"Yes (Daily) - (Recommended)" \
				"Yes (Weekly)" \
				"No" \
				"Exit"
			Prompt_Input "1-3" mode4
			case "${mode4:?}" in
				1)
					echo "[i] Malware Blacklist Updating Enabled & Scheduled Every Day"
					banmalwareupdate="daily"
					forcebanmalwareupdate="enabled"
					break
				;;
				2)
					echo "[i] Malware Blacklist Auto-Updates Enabled & Scheduled For Every Monday"
					banmalwareupdate="weekly"
					forcebanmalwareupdate="enabled"
					break
				;;
				3)
					echo "[i] Malware Blacklist Auto-Updates Disabled"
					banmalwareupdate="disabled"
					break
				;;
				e|exit|back|menu)
					echo "[*] Exiting!"
					echo
					exit 0
				;;
				*)
					Invalid_Option "$mode4"
				;;
			esac
		done
		echo
		echo
		while true; do
			Show_Menu "Enable Weekly Skynet Auto-Update?" \
				"Yes - (Recommended)" \
				"No" \
				"Exit"
			Prompt_Input "1-2" mode5
			case "${mode5:?}" in
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
				e|exit|back|menu)
					echo "[*] Exiting!"
					echo
					exit 0
				;;
				*)
					Invalid_Option "$mode5"
				;;
			esac
		done
		echo
		Check_Files firewall-start services-stop service-event post-mount unmount
		if ! grep -qF "swapon " /jffs/scripts/post-mount; then Create_Swap; fi
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
		if [ -z "$logsize" ]; then logsize="10"; fi
		if [ -z "$unbanprivateip" ]; then unbanprivateip="enabled"; fi
		if [ -z "$banaiprotect" ]; then banaiprotect="enabled"; fi
		if [ -z "$securemode" ]; then securemode="enabled"; fi
		if [ -z "$extendedstats" ]; then extendedstats="enabled"; fi
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
			Prompt_Typed "continue" "i" "[i] Reboot Required To Complete Installation"
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
			Show_Menu "Warning - This Will Delete All Files In The Skynet Directory. Are You Sure You Want To Uninstall?" \
				"Yes" \
				"No" \
				"Exit"
			Prompt_Input "1-2" continue
			case "$continue" in
				1)
					if grep -qE "swapon .* # Skynet" /jffs/scripts/post-mount; then
						while true; do
							Show_Menu "Would You Like To Remove Skynet Generated Swap File?" \
								"Yes" \
								"No" \
								"Exit"
							Prompt_Input "1-2" removeswap
							case "${removeswap:?}" in
								1)
									echo "[i] Removing Skynet Generated SWAP File"
									sed -i '\~# Skynet~d' /jffs/scripts/post-mount /jffs/scripts/unmount
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
									Invalid_Option "$removeswap"
								;;
							esac
						done
					fi
					echo "[i] Unloading Skynet Components"
					Purge_Logs "all"
					Unload_Cron "all"
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
					Invalid_Option "$continue"
				;;
			esac
		done
	;;
	*)
		Ylow "Command Not Recognized, Please Try Again"
		Ylow "For Help:   https://github.com/Adamm00/IPSet_ASUS#help"
		Ylow "Common Issues: https://github.com/Adamm00/IPSet_ASUS/wiki#common-issues"
	;;
esac

Display_Header "9"
if [ "$nolog" != "2" ]; then Print_Log "$@"; echo; fi
if [ "$nocfg" != "1" ]; then Write_Config; fi
if [ "$restartfirewall" = "1" ]; then service restart_firewall; echo; fi
if [ -n "$reloadmenu" ]; then Release_Lock; echo;echo; printf "[i] Press Enter To Continue..."; read -r "continue"; exec "$0"; fi
printf '\033[?7h'