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
#                                           29/08/2026 - v8.2.0                                             #
#############################################################################################################


export PATH="/sbin:/bin:/usr/sbin:/usr/bin:$PATH"
export LC_ALL=C

#########################
#- Runtime And Logging -#
#########################

# Invoked by the EXIT trap.
# shellcheck disable=SC2329
Cleanup_Runtime() {
	cleanupstatus="$?"
	# A domain update retains the previous sets until its registry, cache and
	# dnsmasq state are committed. Restore that complete state on an unexpected
	# exit before removing any temporary IPSet used by the transaction.
	if [ "${domaintransactionactive:-0}" = "1" ]; then
		trap - 0 INT TERM
		domaintransactionactive="0"
		domainrollbackcleanup="1"
		Rollback_Domain_Rule_Update || cleanupstatus="1"
		domainrollbackcleanup="0"
		trap - 0 INT TERM
	fi
	# Keep the pre-restore files until the restored policy and integrations pass.
	# Domain rollback runs first so it cannot overwrite the recovered registry.
	if [ "${backuprestoreactive:-0}" = "1" ]; then
		trap - 0 INT TERM
		Rollback_Backup_Restore || cleanupstatus="1"
		trap - 0 INT TERM
	fi
	# Uncommitted feed membership must not leave proposed cache bindings behind.
	# Retain recovery data if an I/O failure prevents restoring those records.
	if [ "${feedselectiontransactionactive:-0}" = "1" ]; then
		trap - 0 INT TERM
		if ! Restore_Managed_Feed_Selection; then
			feedrollbackpreserve="1"
			cleanupstatus="1"
			Log error -s "Failed To Restore Malware Source Metadata - Recovery Files Retained ($TMP_DIR)"
		fi
	fi
	# Every exit path restores terminal line wrapping, including validation errors,
	# signals and read-only commands that return before the main footer.
	if [ -t 1 ] || [ -t 2 ]; then printf '\033[?7h'; fi
	case "$TMP_DIR" in
		/tmp/skynet/tmp.[0-9]*)
			if [ "${feedrollbackpreserve:-0}" != "1" ] && [ "${malwarerollbackpreserve:-0}" != "1" ]; then rm -rf "$TMP_DIR"; fi
		;;
	esac
	case "$backuprestoredir" in
		"${skynetloc}/.restore.$$")
			[ "${backuprestorepreserve:-0}" = "1" ] || rm -rf "$backuprestoredir"
		;;
	esac
	[ -z "$backuptmp" ] || rm -f "$backuptmp"
	[ -z "$iotlogtmp" ] || rm -f "$iotlogtmp"
	for tempfile in "$settingstmp" "$statstmp" "$downloadtmp" "$configtmp" "$saveipsettmp" "$malwareipsettmp" "$hooktmp" "$listmanifesttmp" "$feedstatustmp" "$countrymanifesttmp" "$countryfailedtmp" "$filterpublishtmp" "$dnsmasqtmp" "$dnsmasqrestore" "$sharedwhitelisttmp" "$clientouifile" "$debugneighbors" "$iotviewneighbors" "$updatetmp" "$updatewebuitmp" "$updatefirewallbackup" "$updatewebuibackup" "$actionqueue" "$actionpublishtmp" "$actioncompacttmp" "$actiontrimtmp" "$actionfailedtmp" "$ruleregistrytmp" "$ruleregistryrestore" "$rulestagefile" "$rulerecords" "$rulerecordssorted" "$ruleindexstage" "$ruleindextmp" "$rulemigrationstatetmp" "$maintenancestatustmp" "$domainmanifeststage" "$domaincachetmp"; do
		[ -n "$tempfile" ] && rm -f "$tempfile"
	done
	for cleanupipset in $cleanupipsets; do
		Destroy_IPSets "$cleanupipset"
	done
	for cleanupsidecar in $rulemigrationpublished; do
		[ -n "$cleanupsidecar" ] && rm -f "$cleanupsidecar"
	done
	if [ -n "$skynetloc" ]; then
		rm -f "${skynetloc}/lists/"*.tmp."$$" "${skynetloc}/lists/".*.tmp."$$"
		rm -f "${skynetloc}/lists/rules/"*.tmp."$$" "${skynetloc}/lists/rules/".*.tmp."$$"
	fi
	Release_Log_Lock
	Release_Firewall_Lock
	Release_Lock
	rmdir /tmp/skynet 2>/dev/null
	return "$cleanupstatus"
}

# Invoked by the INT/TERM traps.
# shellcheck disable=SC2317,SC2329 # Called indirectly by the signal trap.
Handle_Cleanup_Signal() {
	trap - 0
	Cleanup_Runtime
	exit 1
}

Set_Cleanup_Traps() {
	trap Handle_Cleanup_Signal INT TERM
	trap Cleanup_Runtime 0
}

Log() {
	# initialize defaults
	logstderr="0"
	logtag="Skynet"
	logprefix=""

	# parse flags and level keywords
	while [ "$#" -gt 0 ]; do
		case "$1" in
		-s)
			# log to syslog and stderr
			logstderr="1"
			shift
			;;
		-t)
			# custom syslog tag
			shift
			if [ "$#" -gt 0 ]; then
				logtag="$1"
				shift
			fi
			;;
		info)
			logprefix="[i] "
			shift
			;;
		error)
			logprefix="[✘] "
			shift
			;;
		*)
			break
			;;
		esac
	done

	# finalize message
	logmessage="$logprefix$*"

	if ! Time_Is_Ready; then
		# Keep pre-NTP diagnostics visible without persisting incorrect timestamps.
		if [ "$logstderr" = "1" ]; then printf '%s\n' "$logmessage" >&2
		else printf '%s\n' "$logmessage"; fi
	elif [ "$logstderr" = "1" ]; then
		# logger -s echoes to stderr
		logger -s -t "$logtag" "$logmessage"
	else
		logger -t "$logtag" "$logmessage"
		echo "$logmessage"
	fi
	unset "logstderr" "logtag" "logprefix" "logmessage"
}

Time_Is_Ready() {
	[ "$(nvram get ntp_ready)" = "1" ]
}

Uptime_Seconds() {
	# Kernel uptime measures elapsed work independently of NTP clock corrections.
	read -r commanduptime _commandidle < /proc/uptime || return 1
	printf '%s\n' "${commanduptime%%.*}"
}

Wait_For_Time() {
	ntptimer="0"
	while ! Time_Is_Ready && [ "$ntptimer" -lt "300" ]; do
		ntptimer=$((ntptimer + 1))
		if [ "$ntptimer" -eq 60 ]; then
			echo
			echo "[i] Waiting For NTP To Synchronize..."
		fi
		sleep 1
	done
	if ! Time_Is_Ready; then unset "ntptimer"; return 1; fi
	unset "ntptimer"
	return 0
}

Require_Time() {
	Time_Is_Ready && return 0
	echo "[*] Router Time Is Not Synchronized - Please Try Again Shortly"
	echo
	exit 1
}

Mark_Time_Dependent_State_Pending() {
	: > "$TIME_PENDING" && chmod 600 "$TIME_PENDING"
}

Mark_Durable_State_Pending() {
	: > "$DURABLE_PENDING" && chmod 600 "$DURABLE_PENDING"
}

Record_Maintenance_Status() {
	maintenancestatustmp="${MAINTENANCE_STATUS}.tmp.$$"
	if Time_Is_Ready; then maintenancestatusepoch="$(date +%s)"; else maintenancestatusepoch="0"; fi
	printf 'M1\t%s\t%s\t%s\n' "$maintenancestatusepoch" "$1" "$2" > "$maintenancestatustmp" \
		&& chmod 600 "$maintenancestatustmp" && mv -f "$maintenancestatustmp" "$MAINTENANCE_STATUS"
}

Time_Dependent_State_Pending() {
	[ -f "$TIME_PENDING" ]
}

Rule_Migration_Complete() {
	[ -f "$RULE_MIGRATION_STATE" ] && [ ! -L "$RULE_MIGRATION_STATE" ] \
		&& [ "$(sed -n '1p' "$RULE_MIGRATION_STATE" 2>/dev/null)" = "R2" ]
}

Publish_Rule_Migration_Complete() {
	rulemigrationstatetmp="${RULE_MIGRATION_STATE}.tmp.$$"
	printf 'R2\n' > "$rulemigrationstatetmp" && chmod 600 "$rulemigrationstatetmp" \
		&& mv -f "$rulemigrationstatetmp" "$RULE_MIGRATION_STATE"
}

Check_Lock() {
	# FD 9 owns the flock for this process. The file content is diagnostic
	# metadata only: command|pid|start_epoch.
	[ "$state_lock_held" = "1" ] && return 0
	[ ! -L "$LOCK_FILE" ] && { [ ! -e "$LOCK_FILE" ] || [ -f "$LOCK_FILE" ]; } || return 1
	exec 9<>"$LOCK_FILE"
	chmod 600 "$LOCK_FILE"

	# Never queue interactive commands behind a long-running update.
	if ! flock -n 9; then
		IFS='|' read -r locked_cmd locked_pid lock_timestamp < "$LOCK_FILE"
		lockcurrenttime="$(date +%s)"

		# Re-entrant lock handling
		if [ "$locked_pid" = "$$" ]; then
			unset "locked_cmd" "locked_pid" "lock_timestamp" "lockcurrenttime"
			return 0
		fi

		# flock ownership is authoritative. Metadata is retained for diagnostics only;
		# a long-running feed or statistics job must never be killed by another command.
		if [ -n "$locked_pid" ] && [ -d "/proc/$locked_pid" ]; then
			lockage=$((lockcurrenttime - lock_timestamp))
			Log error -s "Lock File Detected ($locked_cmd) (pid=$locked_pid, runtime=${lockage}s) - Exiting"
			if [ "$1" = "webui" ]; then
				settingsresult="busy"
				nocfg="1"
				Generate_WebUI_Settings
				return 1
			fi
			echo
			exit 1
		else
			# A locked file without valid metadata is treated as an active owner.
			Log error -s "Lock file busy but metadata invalid (pid='$locked_pid') - another Skynet instance is running - Exiting"
			if [ "$1" = "webui" ]; then
				settingsresult="busy"
				nocfg="1"
				Generate_WebUI_Settings
				return 1
			fi
			echo
			exit 1
		fi
	fi

	# Record command, PID and acquisition time after the lock is acquired.
	: > "$LOCK_FILE"
	echo "$0 $*|$$|$(date +%s)" > "$LOCK_FILE"
	state_lock_held="1"
	unset "locked_cmd" "locked_pid" "lock_timestamp" "lockcurrenttime" "lockage"
}

Wait_For_Lock() {
	# Lifecycle events queue behind the current state transaction, then re-check
	# live state. Interactive commands continue to fail quickly through Check_Lock.
	[ "$state_lock_held" = "1" ] && return 0
	[ ! -L "$LOCK_FILE" ] && { [ ! -e "$LOCK_FILE" ] || [ -f "$LOCK_FILE" ]; } || return 1
	exec 9<>"$LOCK_FILE"
	chmod 600 "$LOCK_FILE"
	if [ "$1" = "maintenance" ]; then
		# BusyBox flock has no timeout option. Sleep between attempts and never
		# leave an hourly invocation queued indefinitely behind another command.
		lockwaitattempts="0"
		while ! flock -n 9; do
			if [ "$lockwaitattempts" -ge 30 ]; then
				exec 9>&-
				Record_Maintenance_Status deferred state-lock || return 1
				Log info "Maintenance Deferred - Skynet Busy After 60 Seconds"
				return 1
			fi
			sleep 2
			lockwaitattempts=$((lockwaitattempts + 1))
		done
		unset lockwaitattempts
	else
		flock 9 || { exec 9>&-; return 1; }
	fi
	printf '%s|%s|%s\n' "$0 $*" "$$" "$(date +%s)" > "$LOCK_FILE" || {
		flock -u 9 2>/dev/null
		exec 9>&-
		return 1
	}
	state_lock_held="1"
}

Read_Active_Lock() {
	# Diagnostics only: report an active lock without acquiring or changing it.
	[ -f "$LOCK_FILE" ] && ! flock -n 9 9<"$LOCK_FILE" || return 1
	IFS='|' read -r lockstatuscommand lockstatuspid lockstatusepoch < "$LOCK_FILE" || return 1
	case "$lockstatusepoch" in ""|*[!0-9]*) return 1 ;; esac
	[ -n "$lockstatuspid" ] && [ -d "/proc/$lockstatuspid" ] || return 1
	lockstatusruntime="$(($(date +%s) - lockstatusepoch))"
}

Release_Lock() {
	[ "$state_lock_held" = "1" ] || return 0

	IFS='|' read -r _lockcommand lockownerpid _locktimestamp < "$LOCK_FILE"

	if [ "$lockownerpid" != "$$" ]; then
		unset "_lockcommand" "lockownerpid" "_locktimestamp"
		return
	fi

	# Only the recorded owner may release the lock file.
	: > "$LOCK_FILE"
	flock -u 9 2>/dev/null
	exec 9>&-
	state_lock_held="0"
	unset "_lockcommand" "lockownerpid" "_locktimestamp"
}

Acquire_Firewall_Lock() {
	[ "$firewall_lock_held" = "1" ] && return 0
	[ ! -L "$FIREWALL_LOCK" ] && { [ ! -e "$FIREWALL_LOCK" ] || [ -f "$FIREWALL_LOCK" ]; } || return 1
	exec 8<>"$FIREWALL_LOCK"
	chmod 600 "$FIREWALL_LOCK"
	flock 8 || { exec 8>&-; return 1; }
	firewall_lock_held="1"
}

Release_Firewall_Lock() {
	[ "$firewall_lock_held" = "1" ] || return 0
	flock -u 8 2>/dev/null
	exec 8>&-
	firewall_lock_held="0"
}

Acquire_Log_Lock() {
	[ "$log_lock_held" = "1" ] && return 0
	[ ! -L "$LOG_LOCK" ] && { [ ! -e "$LOG_LOCK" ] || [ -f "$LOG_LOCK" ]; } || return 1
	exec 7<>"$LOG_LOCK"
	chmod 600 "$LOG_LOCK"
	flock 7 || { exec 7>&-; return 1; }
	log_lock_held="1"
}

Release_Log_Lock() {
	[ "$log_lock_held" = "1" ] || return 0
	flock -u 7 2>/dev/null
	exec 7>&-
	log_lock_held="0"
}

Find_Install_Dir() {
	# Skip for installer/info commands
	case "$1" in
		install|uninstall|disable|update|restart|info) return 0 ;;
	esac

	if [ ! -d "${skynetloc}" ] || [ ! -w "${skynetloc}" ]; then
		case "$1" in
			start|persist|maintenance) Wait_For_Lock "$@" || return 1 ;;
			*) Check_Lock "$@" || return 1 ;;
		esac

		installretries="10"
		installattempt="1"

		# Wait until skynetloc exists as a directory and is writable
		while [ "$installattempt" -le "$installretries" ] && { [ ! -d "$skynetloc" ] || [ ! -w "$skynetloc" ]; }; do
			Log info -s "USB install directory not ready — sleeping 10s ($installattempt/$installretries)"
			sleep 10
			installattempt=$((installattempt + 1))
		done

		# Final verification
		if [ ! -d "$skynetloc" ] || [ ! -w "$skynetloc" ]; then
			Log error -s "Problem with USB install location — please fix immediately!"
			Log error -s "To change location run: sh $0 install"
			echo
			exit 1
		fi
		unset "installretries" "installattempt"
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

Swap_Required() {
	# Kernel reservations reduce usable RAM below the advertised capacity. This
	# separates 2GB-class routers from 1GB models without a model-name allowlist.
	awk '/^MemTotal:/ { found=1; exit $2 >= 1572864 } END { if (!found) exit 0 }' /proc/meminfo
}

Addon_API_Supported() {
	if [ "$addonsupportchecked" != "1" ]; then
		case "$(nvram get rc_support)" in
			*am_addons*) addonsupported="1" ;;
			*) addonsupported="0" ;;
		esac
		addonsupportchecked="1"
	fi
	[ "$addonsupported" = "1" ]
}

Validate_Syslog_Path() {
	# Log files may not exist until the next write or rotation; their directory must.
	[ "${#1}" -le 512 ] && [ -d "${1%/*}/" ] && [ ! -d "$1" ] \
		&& printf '%s\n' "$1" | awk 'NR != 1 || $0 !~ /^\/[A-Za-z0-9_.\/ ()+-]+$/ {bad=1} END {exit bad}'
}

Resolve_Syslog_Sources() {
	[ "$syslogmode" = "auto" ] || return 0
	syslogdetected=""
	# Scribe owns its filter configuration. Read only a literal destination from
	# its installed Skynet handler, and only while syslog-ng is running.
	if pidof syslog-ng >/dev/null 2>&1 && [ -f /opt/etc/syslog-ng.d/skynet ]; then
		syslogdetected="$(awk '
			/^[[:space:]]*#/ {next}
			match($0, /file[[:space:]]*\("[^"]+"/) {
				path=substr($0, RSTART, RLENGTH); sub(/^[^"]*"/, "", path); sub(/"$/, "", path)
				print path; exit
			}' /opt/etc/syslog-ng.d/skynet)"
	fi
	if ! Validate_Syslog_Path "$syslogdetected"; then
		syslogdetected=""
		for syslogpid in $(pidof syslogd); do
			# /proc arguments are NUL-separated, not a shell command string.
			syslogdetected="$(tr '\000' '\n' 2>/dev/null < "/proc/$syslogpid/cmdline" | awk '
				output {print; exit}
				$0 == "-O" {output=1; next}
				/^-O\// {print substr($0, 3); exit}
			')"
			Validate_Syslog_Path "$syslogdetected" && break
			syslogdetected=""
		done
	fi
	[ -n "$syslogdetected" ] || syslogdetected="/tmp/syslog.log"
	# Resolve Merlin's /tmp -> /jffs aliases before any in-place log cleanup.
	syslogresolved="$(readlink -f "$syslogdetected" 2>/dev/null)" || syslogresolved="$syslogdetected"
	if Validate_Syslog_Path "$syslogresolved" && Validate_Syslog_Path "${syslogresolved}-1"; then
		syslogloc="$syslogresolved"
		syslog1loc="${syslogresolved}-1"
	fi
	unset "syslogdetected" "syslogresolved" "syslogpid"
}

Check_Settings() {
	# Grab and set local version
	localver="$(Filter_Version < "$0")"
	
	# require config file
	if [ ! -f "$skynetcfg" ]; then
		Log error -s "Configuration File Not Detected - Please Use ( sh $0 install ) To Continue"
		return 1
	fi

	# SWAP Checks
	swaplocation="$(awk 'NR==2 { print $1 }' /proc/swaps)"

	if Swap_Required && ! Check_Swap; then
		Log error -s "Skynet Requires A SWAP File - Install One ( $0 debug swap install )"
		return 1
	fi

	if Swap_Required && Check_Swap && [ -z "$(grep -E 'swapon [^#]+' /jffs/scripts/post-mount | cut -d ' ' -f2)" ]; then
		Log error -s "SWAPON Entry Missing - Fix This By Running ( $0 debug swap uninstall ) Then ( $0 debug swap install )"
		return 1
	fi

	if grep -q '^partition' /proc/swaps; then
		Log error -s "SWAP Partitions Not Supported - Please Use SWAP File"
		return 1
	fi

	# warn if too small (<1GB)
	swap_kb=$(awk '$2 == "file" {total += $3} END {print total + 0}' /proc/swaps)
	if [ "$swap_kb" -gt 0 ] && [ "$swap_kb" -lt 1048576 ]; then
		Log error -s "SWAP File Too Small (<1GB) - Please Fix Immediately!"
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

	if nvram get wan0_ipaddr | Is_PrivateIP; then
		Log error -s "Private WAN IP Detected $(nvram get wan0_ipaddr) - Please Put Your Modem In Bridge Mode / Disable CG-NAT"
	fi

	# Set default log size if not set
	if [ -z "$logsize" ]; then
		logsize="10"
	fi
	if [ -z "$iotlogging" ]; then
		iotlogging="enabled"
	fi
}

#######################
#- Network Transfers -#
#######################

Check_Connection() {
	# Usage:
	#   Check_Connection              # 1 attempt
	#   Check_Connection 5            # 5 attempts, 3s apart
	#   Check_Connection 5 10         # 5 attempts, 10s apart

	connectionretries="${1:-1}"
	connectiondelay="${2:-3}"
	[ "$connectionretries" -lt 1 ] && connectionretries=1
	[ "$connectiondelay" -lt 1 ] && connectiondelay=1

	connectionattempt=1
	while [ "$connectionattempt" -le "$connectionretries" ]; do
		# Read the numeric gateway IP from the routing table.
		connectiongateway="$(route -n | awk '$1=="0.0.0.0"{print $2; exit}')"

		# Test the gateway with a one-second timeout when available.
		if [ -n "$connectiongateway" ] && ping -c1 -W1 "$connectiongateway" >/dev/null 2>&1; then
			return 0
		fi

		# Test a public IPv4 address with a one-second timeout.
		if ping -c1 -W1 1.1.1.1 >/dev/null 2>&1; then
			return 0
		fi

		# Fall back to an ARP probe on the WAN interface.
		if [ -n "$connectiongateway" ] && arping -c1 -w1 -I "$iface" "$connectiongateway" >/dev/null 2>&1; then
			return 0
		fi

		# Delay only when another attempt remains.
		if [ "$connectionattempt" -lt "$connectionretries" ]; then
			sleep "$connectiondelay"
		fi

		connectionattempt=$((connectionattempt + 1))
	done

	# Report one concise error after every retry has failed.
	if [ -z "$connectiongateway" ]; then
		Log error -s "Connection Error Detected - Unable To Determine Gateway Or Reach Public IP"
	else
		Log error -s "Connection Error Detected - Unable To Reach Gateway ($connectiongateway) Or Public IP"
	fi

	return 1
}

Require_Connection() {
	Check_Connection || { echo; exit 1; }
}

Curl_Fetch() {
	# Curl's standard retry policy covers timeouts and transient HTTP responses.
	# Do not retry every error: permanent HTTP failures such as GitHub's rate-limit
	# 403 must return immediately so callers can retain their validated data.
	if curl -fsSL --proto '=http,https' --proto-redir '=http,https' \
		--retry 3 --connect-timeout 5 --max-time 60 --retry-delay 1 "$@" 2>/dev/null; then
		return 0
	fi
	Log error -s "Download Failed - Check Connection Or URL"
	return 1
}

Curl_Lookup() {
	curl -fsSL --retry 1 --connect-timeout 2 --max-time 6 --retry-delay 1 "$@"
}

Start_Background_Jobs() {
	backgroundpids=""
	backgroundjobs="0"
}

Wait_Background_Job_Slot() {
	# Keep the configured number of workers busy without waiting for an entire
	# fixed batch when only one job is slow. Capture $! before running any command.
	backgroundpid="$!"
	backgroundlimit="${1:-4}"
	backgroundpids="${backgroundpids:+$backgroundpids }$backgroundpid"
	backgroundjobs=$((backgroundjobs + 1))
	while [ "$backgroundjobs" -ge "$backgroundlimit" ]; do
		backgroundrunning=""
		backgroundjobs="0"
		for backgroundpid in $backgroundpids; do
			if kill -0 "$backgroundpid" 2>/dev/null; then
				backgroundrunning="${backgroundrunning:+$backgroundrunning }$backgroundpid"
				backgroundjobs=$((backgroundjobs + 1))
			else
				wait "$backgroundpid" 2>/dev/null
			fi
		done
		backgroundpids="$backgroundrunning"
		if [ "$backgroundjobs" -ge "$backgroundlimit" ]; then
			usleep 100000 2>/dev/null || sleep 1
		fi
	done
}

Wait_Background_Jobs() {
	for backgroundpid in $backgroundpids; do
		wait "$backgroundpid" 2>/dev/null
	done
	Start_Background_Jobs
}

##################
#- Threat Feeds -#
##################

Build_Threat_Feed_Manifest() {
	# Resolve every filter URL before applying exclusions. Collision suffixes are
	# therefore stable when a source is disabled and later re-enabled.
	awk -v excluded="$3" -v previous="$4" '
		BEGIN {
			OFS = "\t"
			split(excluded, values, " ")
			for (i in values) skip[tolower(values[i])] = 1
			if (previous != "") {
				while ((readstatus = getline line < previous) > 0) {
					split(line, old, "\t")
					previous_name[old[2]] = old[1]
					used_name[tolower(old[1])] = 1
				}
				close(previous)
				if (readstatus < 0) exit 1
			}
		}
		{
			sub(/\r$/, "")
			if ($0 == "" || $0 ~ /^[[:space:]]*#/) next
			if (NF != 1) { invalid = 1; next }
			url = $1
			if (url !~ /^https?:\/\//) { invalid = 1; next }
			if (seen_url[url]++) next

			clean_url = url
			sub(/[?#].*$/, "", clean_url)
			count = split(clean_url, parts, "/")
			name = parts[count]
			gsub(/[^A-Za-z0-9._-]/, "_", name)
			# Hidden names are omitted by the consolidation glob and overlap internal
			# cache files; countries and rules hold authoritative component data. Keep room
			# for collision suffixes and per-process temporary extensions.
			if (name == "" || name ~ /^\./ || tolower(name) ~ /^(countries|rules)$/) { invalid = 1; next }
			if (length(name) > 120) name = substr(name, 1, 120)

			raw_name = name
			name = raw_name
			suffix = 0
			# A natural basename such as foo.1 can collide with the suffix generated
			# for a preceding duplicate foo. Test every final case-folded name so all
			# cache, result and status paths remain unique.
			if (url in previous_name) name = previous_name[url]
			else while (tolower(name) in used_name) name = raw_name "." ++suffix
			used_name[tolower(name)] = 1

			state = (tolower(name) in skip) ? "excluded" : "enabled"
			print name, url, state
		}
		END { if (invalid) exit 1 }
	' "$1" > "$2"
}

Validate_Managed_Feed_Selection() {
	# Membership is authoritative; cache bindings and source health may be absent.
	# Names remain stable across removals, disabling and template replacements.
	awk -F '\t' '
		NF != 3 || $1 !~ /^[A-Za-z0-9_-][A-Za-z0-9._-]*$/ || length($1) > 128 ||
		tolower($1) ~ /^(countries|rules)$/ || $2 !~ /^https?:\/\/[^\/[:space:]]+/ || $2 ~ /[[:space:]]/ ||
		$3 !~ /^(enabled|excluded)$/ { invalid = 1; next }
		{ if (names[tolower($1)]++ || urls[$2]++) invalid = 1; if ($3 == "enabled") enabled++ }
		END { exit invalid || !NR || !enabled }' "$1"
}

Read_Managed_Feed_Selection() {
	if [ -f "${skynetloc}/lists/.selection" ]; then
		Validate_Managed_Feed_Selection "${skynetloc}/lists/.selection" \
			&& cp -f "${skynetloc}/lists/.selection" "$1"
		return "$?"
	fi
	[ -s "${skynetloc}/lists/.sources" ] || return 3
	# Recover all known sources, including disabled ones, without a network call.
	awk -F '\t' -v OFS='\t' -v excluded="$excludelists" '
		BEGIN { split(excluded, values, " "); for (i in values) skip[tolower(values[i])] = 1 }
		{ print $1, $2, (tolower($1) in skip) ? "excluded" : "enabled" }
	' "${skynetloc}/lists/.sources" > "$1" && Validate_Managed_Feed_Selection "$1"
}

Publish_Managed_Feed_Selection() {
	[ "$feedselectionchanged" = "1" ] || return 0
	feedselectiontmp="${skynetloc}/lists/.selection.tmp.$$"
	if cp -f "$feedselectioncandidate" "$feedselectiontmp" && chmod 600 "$feedselectiontmp" \
		&& mv -f "$feedselectiontmp" "${skynetloc}/lists/.selection"; then
		feedselectionpublished="1"
		return 0
	fi
	rm -f "$feedselectiontmp"
	return 1
}

Restore_Managed_Feed_Selection() {
	[ "$feedselectionchanged" = "1" ] || return 0
	feedrestorestatus="0"
	for feedrestorefile in selection manifest sources; do
		[ "$feedrestorefile" != "selection" ] || [ "$feedselectionpublished" = "1" ] || continue
		feedrestoretarget="${skynetloc}/lists/.$feedrestorefile"
		feedrestorebackup="$TMP_DIR/feed-previous.$feedrestorefile"
		if [ -f "$feedrestorebackup" ]; then
			cp -f "$feedrestorebackup" "${feedrestoretarget}.tmp.$$" \
				&& mv -f "${feedrestoretarget}.tmp.$$" "$feedrestoretarget" || feedrestorestatus="1"
		else
			rm -f "$feedrestoretarget" || feedrestorestatus="1"
		fi
	done
	if [ "$feedrestorestatus" = "0" ]; then
		# Only names absent before the request can be new orphan caches. Never
		# delete a pre-existing file or prune against a partially restored manifest.
		if [ ! -r "$feednewcachelist" ]; then return 1; fi
		while IFS= read -r feednewcachename; do
			case "$feednewcachename" in ""|.*|*[!A-Za-z0-9._-]*) feedrestorestatus="1"; break ;; esac
			rm -f "${skynetloc}/lists/$feednewcachename" || feedrestorestatus="1"
		done < "$feednewcachelist"
	fi
	if [ "$feedrestorestatus" = "0" ]; then
		feedselectionpublished="0"
		feedselectiontransactionactive="0"
		unset "feedrollbackpreserve"
	fi
	return "$feedrestorestatus"
}

Prune_Threat_Feed_Caches() {
	# Validate the complete binding manifest before selecting obsolete files.
	# An unreadable or malformed manifest must never look like an empty cache.
	feedcachecandidates="$TMP_DIR/feed-cache-candidates.$$"
	feedcacheunused="$TMP_DIR/feed-cache-unused.$$"
	printf '%s\n' "${skynetloc}/lists/"* > "$feedcachecandidates" || return 1
	if ! awk -v manifest="${skynetloc}/lists/.manifest" '
		BEGIN {
			while ((status = getline line < manifest) > 0) {
				if (split(line, fields, " ") != 2 || fields[1] !~ /^https?:\/\// ||
					fields[2] !~ /^[A-Za-z0-9_-][A-Za-z0-9._-]*$/) exit 1
				keep[fields[2]] = 1; entries++
			}
			close(manifest)
			if (status < 0 || !entries) exit 1
		}
		{ name = $0; sub(/.*\//, "", name); if (!(name in keep)) print }
	' "$feedcachecandidates" > "$feedcacheunused"; then
		rm -f "$feedcachecandidates" "$feedcacheunused"
		return 1
	fi
	feedcachestatus="0"
	while IFS= read -r feedcachefile; do
		[ ! -f "$feedcachefile" ] || rm -f "$feedcachefile" || feedcachestatus="1"
	done < "$feedcacheunused"
	rm -f "$feedcachecandidates" "$feedcacheunused"
	return "$feedcachestatus"
}

Validate_Threat_Feed_Selection() {
	# Resolve exclusions against the final, collision-safe filenames. Validate the
	# complete request before publishing the source list or starting downloads.
	awk -F '\t' -v excluded="$2" '
		BEGIN {
			split(excluded, values, " ")
			for (i in values) requested[tolower(values[i])] = values[i]
		}
		{ available[tolower($1)] = 1 }
		END {
			for (name in requested) {
				if (name in available) continue
				missing = missing (missing == "" ? "" : " ") requested[name]
			}
			if (missing != "") {
				print missing
				exit 1
			}
		}' "$1"
}

Restore_Threat_Feed_Selection() {
	# The source hostnames are whitelisted before downloads. Restore the previous
	# shared list if the update later fails so the saved selection remains active.
	[ "$feedfilterpublished" = "1" ] || return 0
	if [ "$feedfilterhadold" = "1" ] && [ -s "$feedfilterbackup" ]; then
		cp -f "$feedfilterbackup" /jffs/addons/shared-whitelists/shared-Skynet-whitelist || return 1
	else
		rm -f /jffs/addons/shared-whitelists/shared-Skynet-whitelist
	fi
	Whitelist_Shared >/dev/null 2>&1
}

Format_Threat_Feed_Time() {
	case "$1" in
		""|0|*[!0-9]*) printf '%s\n' "Never" ;;
		*) date -d "@$1" '+%d/%m/%Y %H:%M:%S' 2>/dev/null || printf '%s\n' "$1" ;;
	esac
}

Print_Threat_Feed_Status() {
	feedstatusfile="${skynetloc}/lists/.sources"
	echo "[i] Malware List Schedule - $banmalwareupdate"
	echo "[i] Last Successful Update - $(Format_Threat_Feed_Time "$banmalwarelastupdated")"
	if [ -n "$customlisturl" ]; then
		echo "[i] Filter List - $customlisturl"
	else
		echo "[i] Filter List - Skynet Default"
	fi
	if [ ! -s "$feedstatusfile" ]; then
		echo "[i] Source Details - Available After The Next Malware Update"
		return 0
	fi
	awk -F '\t' '
		$4 == "current" { current++ }
		$4 == "cached" { cached++ }
		$4 == "failed" { failed++ }
		$4 == "excluded" { excluded++ }
		END {
			printf "[i] Sources - %d Total / %d Current / %d Cached / %d Failed / %d Excluded\n",
				NR, current + 0, cached + 0, failed + 0, excluded + 0
		}' "$feedstatusfile"
}

Build_Threat_Feed_Action_Summary() {
	awk -F '\t' '
		$3 == "enabled" && $4 == "current" {current++}
		$3 == "enabled" && $4 == "cached" {cached++}
		$3 == "excluded" || $4 == "excluded" {excluded++}
		END {
			if (!current && !cached) exit 1
			printf "%d source%s: %d current", current + cached, current + cached == 1 ? "" : "s", current + 0
			if (cached) printf ", %d cached", cached
			if (excluded) printf ", %d excluded", excluded
		}
	' "${skynetloc}/lists/.sources"
}

Print_Threat_Feed_Sources() {
	feedstatusfile="${skynetloc}/lists/.sources"
	if [ ! -s "$feedstatusfile" ]; then
		echo "[i] Source Details Available After The Next Malware Update"
		return 0
	fi
	printf '%-34s | %-9s | %-9s | %-19s | %-19s\n' "Source" "Entries" "State" "Last Success" "Content Changed"
	printf '%-34s-+-%-9s-+-%-9s-+-%-19s-+-%-19s\n' "----------------------------------" "---------" "---------" "-------------------" "-------------------"
	feedtab="$(printf '\t')"
	while IFS="$feedtab" read -r feedname feedurl feedenabled feedstate feedentries feedchecked feedsuccess feedhash feedchanged; do
		printf '%-34s | %-9s | %-9s | %-19s | %-19s\n' "$feedname" "$feedentries" "$feedstate" \
			"$(Format_Threat_Feed_Time "$feedsuccess")" "$(Format_Threat_Feed_Time "$feedchanged")"
		printf '  %s\n' "$feedurl"
	done < "$feedstatusfile"
}

Write_Threat_Feed_Result() {
	# A result becomes a worker completion record only after the complete write.
	feedresultstage="${1}.tmp"
	if [ -L "$feedresultstage" ] || { [ -e "$feedresultstage" ] && [ ! -f "$feedresultstage" ]; }; then
		rm -f "$feedresultstage"
		return 1
	fi
	if printf '%s\t%s\t%s\n' "$2" "$3" "$4" > "$feedresultstage" \
		&& mv -f "$feedresultstage" "$1"; then return 0; fi
	rm -f "$feedresultstage"
	return 1
}

Read_Threat_Feed_Result() {
	# Require one complete TSV record. Parse tabs explicitly because IFS read
	# collapses empty fields, which could otherwise hide a truncated timestamp.
	[ -f "$1" ] && [ ! -L "$1" ] || return 1
	{
		IFS= read -r feedresultrow || return 1
		feedresulttail=""
		IFS= read -r feedresulttail && return 1
		[ -z "$feedresulttail" ] || return 1
	} < "$1" || return 1
	case "$feedresultrow" in *"$feedtab"*"$feedtab"*) ;; *) return 1 ;; esac
	feedstate="${feedresultrow%%"$feedtab"*}"
	feedresultrow="${feedresultrow#*"$feedtab"}"
	feedresultchecked="${feedresultrow%%"$feedtab"*}"
	feedresultsuccess="${feedresultrow#*"$feedtab"}"
	case "$feedstate" in current|downloaded|cached|failed) ;; *) return 1 ;; esac
	case "$feedresultchecked" in ""|*[!0-9]*) return 1 ;; esac
	case "$feedresultsuccess" in ""|*[!0-9]*) return 1 ;; esac
	unset "feedresultrow" "feedresulttail"
}

Publish_Threat_Feed_Status() {
	# Merge the requested source selection, background-job results and parser
	# counts into one complete status snapshot, then publish it atomically. The
	# Tab-separated contract is name, URL, enabled state, result state, usable
	# entries, last check, last successful check, content hash and content-change
	# epoch. New columns are appended so older seven-column snapshots still load.
	feedmanifest="$1"
	feedcounts="$2"
	feedstatusfile="${skynetloc}/lists/.sources"
	feedstatustmp="${feedstatusfile}.tmp.$$"
	feedtab="$(printf '\t')"
	feedoldfile="/dev/null"
	[ ! -s "$feedstatusfile" ] || feedoldfile="$feedstatusfile"
	# Join metadata once. A non-empty hash placeholder preserves TSV positions
	# through shell read, which otherwise collapses adjacent whitespace fields.
	if ! feedstatusdata="$(awk -F '\t' '
		FILENAME == ARGV[1] { if (!($1 in counts)) counts[$1] = $2; next }
		FILENAME == ARGV[2] { key = $1 SUBSEP $2; if (!(key in previous)) previous[key] = $0; next }
		{
			if (NF != 3 || $1 == "" || $2 == "" || $3 !~ /^(enabled|excluded)$/) { invalid = 1; next }
			key = $1 SUBSEP $2; split(previous[key], old, "\t")
			printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", $1, $2, $3,
				counts[$1] == "" ? 0 : counts[$1], old[6] == "" ? 0 : old[6],
				old[7] == "" ? 0 : old[7], old[8] == "" ? "-" : old[8], old[9] == "" ? 0 : old[9]
			entries++
		}
		END { if (invalid || !entries) exit 1 }
	' "$feedcounts" "$feedoldfile" "$feedmanifest")"; then
		unset "feedstatusdata"
		return 1
	fi
	# Buffer compact metadata to avoid repeated USB appends. Feed content stays on disk.
	if ! feedstatusoutput="$(while IFS="$feedtab" read -r feedname feedurl feedenabled feedentries feedpublishchecked feedsuccess feedoldhash feedoldchanged; do
		feedpublishstate="excluded"
		if [ "$feedenabled" = "enabled" ]; then
			feedresult="$TMP_DIR/feed.${feedname}.result"
			Read_Threat_Feed_Result "$feedresult" || return 1
			[ "$feedstate" != "downloaded" ] || return 1
			feedpublishstate="$feedstate"
			feedpublishchecked="$feedresultchecked"
			feedsuccess="$feedresultsuccess"
		fi
		case "$feedentries" in ""|*[!0-9]*) feedentries="0" ;; esac
		case "$feedpublishchecked" in ""|*[!0-9]*) feedpublishchecked="0" ;; esac
		case "$feedsuccess" in ""|*[!0-9]*) feedsuccess="0" ;; esac
		feedhash=""
		if [ -e "${skynetloc}/lists/$feedname" ]; then
			feedhash="$(sha256sum "${skynetloc}/lists/$feedname")" \
				|| return 1
			feedhash="${feedhash%% *}"
		fi
		feedchanged="$feedoldchanged"
		if [ -n "$feedhash" ] && [ "$feedhash" != "$feedoldhash" ]; then
			feedchanged="$(date -r "${skynetloc}/lists/$feedname" +%s 2>/dev/null || printf '%s' "$feedpublishchecked")"
		elif [ -z "$feedhash" ]; then
			feedchanged="0"
		fi
		case "$feedchanged" in ""|*[!0-9]*) feedchanged="0" ;; esac
		printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
			"$feedname" "$feedurl" "$feedenabled" "$feedpublishstate" "$feedentries" "$feedpublishchecked" "$feedsuccess" "$feedhash" "$feedchanged" || return 1
	done <<EOF
$feedstatusdata
EOF
	)"; then
		unset "feedstatusdata" "feedstatusoutput"
		return 1
	fi
	unset "feedstatusdata"
	if [ -L "$feedstatustmp" ] || { [ -e "$feedstatustmp" ] && [ ! -f "$feedstatustmp" ]; }; then
		unset "feedstatusoutput"
		rm -f "$feedstatustmp"
		return 1
	fi
	if printf '%s\n' "$feedstatusoutput" > "$feedstatustmp" \
		&& mv -f "$feedstatustmp" "$feedstatusfile"; then
		unset "feedstatusoutput"
		return 0
	fi
	unset "feedstatusoutput"
	rm -f "$feedstatustmp"
	return 1
}

Build_Malware_Restore() {
	# Parse every retained source once. Counts remain per source while duplicate
	# addresses are emitted only once across the enabled source set.
	awk -v manifest="$1" -v counts="$3" '
		BEGIN {
			printf "%s", "" > counts
			while ((readstatus = getline line < manifest) > 0) {
				split(line, fields, "\t")
				enabled[fields[1]] = fields[3]
			}
			close(manifest)
			if (readstatus < 0) exit 1
			reserve(ipv4(0,0,0,0), ipv4(0,255,255,255))
			reserve(ipv4(10,0,0,0), ipv4(10,255,255,255))
			reserve(ipv4(100,64,0,0), ipv4(100,127,255,255))
			reserve(ipv4(127,0,0,0), ipv4(127,255,255,255))
			reserve(ipv4(169,254,0,0), ipv4(169,254,255,255))
			reserve(ipv4(172,16,0,0), ipv4(172,31,255,255))
			reserve(ipv4(192,0,0,0), ipv4(192,0,0,255))
			reserve(ipv4(192,0,2,0), ipv4(192,0,2,255))
			reserve(ipv4(192,168,0,0), ipv4(192,168,255,255))
			reserve(ipv4(198,18,0,0), ipv4(198,19,255,255))
			reserve(ipv4(198,51,100,0), ipv4(198,51,100,255))
			reserve(ipv4(203,0,113,0), ipv4(203,0,113,255))
			reserve(ipv4(224,0,0,0), ipv4(255,255,255,255))
		}
		function ipv4(a, b, c, d) { return (((a * 256) + b) * 256 + c) * 256 + d }
		function reserve(start, end) { blocked_start[++blocked_count] = start; blocked_end[blocked_count] = end }
		function usable(value, part_count, prefix, octet_count, first, second, third, fourth, block, start, end, checkidx) {
			part_count = split(value, address_parts, "/")
			if (part_count > 2) return ""
			prefix = part_count == 2 ? address_parts[2] : 32
			if (prefix !~ /^[0-9]+$/ || prefix < 1 || prefix > 32) return ""
			octet_count = split(address_parts[1], octets, ".")
			if (octet_count != 4) return ""
			for (i = 1; i <= 4; i++) {
				if (octets[i] !~ /^[0-9]+$/ || octets[i] < 0 || octets[i] > 255) return ""
			}
			first = octets[1] + 0
			second = octets[2] + 0
			third = octets[3] + 0
			fourth = octets[4] + 0
			if (first == 0 || first == 10 || first == 127 || first >= 224) return ""
			if (first == 100 && second >= 64 && second <= 127) return ""
			if (first == 169 && second == 254) return ""
			if (first == 172 && second >= 16 && second <= 31) return ""
			if (first == 192 && second == 168) return ""
			if (first == 192 && second == 0 && (third == 0 || third == 2)) return ""
			if (first == 198 && (second == 18 || second == 19)) return ""
			if (first == 198 && second == 51 && third == 100) return ""
			if (first == 203 && second == 0 && third == 113) return ""
			if (prefix == 32) return sprintf("%d.%d.%d.%d", first, second, third, fourth)
			# CIDR host bits are normalized before de-duplication. Check the whole
			# interval, not only its first address, against non-public networks.
			block = 2 ^ (32 - prefix)
			start = int(ipv4(first, second, third, fourth) / block) * block
			end = start + block - 1
			for (checkidx = 1; checkidx <= blocked_count; checkidx++)
				if (start <= blocked_end[checkidx] && end >= blocked_start[checkidx]) return ""
			first = int(start / 16777216); start -= first * 16777216
			second = int(start / 65536); start -= second * 65536
			third = int(start / 256); fourth = start - third * 256
			return sprintf("%d.%d.%d.%d/%d", first, second, third, fourth, prefix)
		}
		FNR == 1 {
			source = FILENAME
			sub(".*/", "", source)
			# Only per-source counts need this map; cross-source ownership uses
			# global_seen. Reuse the memory when moving to the next source.
			for (value in source_seen) delete source_seen[value]
		}
		{
			value = usable($1)
			if (value == "") next
			if (value in source_seen) next
			source_seen[value] = 1
			source_count[source]++
			if (enabled[source] != "enabled" || global_seen[value]++) next
			valid_entries++
			if (value !~ /\// || value ~ /\/32$/)
				print "add Skynet-Blacklist " value " comment \"BanMalware: " source "\""
			else
				print "add Skynet-BlockedRanges " value " comment \"BanMalware: " source "\""
		}
		END {
			for (source in enabled) print source "\t" (source_count[source] + 0) > counts
			if (close(counts) || valid_entries == 0) exit 1
		}' "$TMP_DIR/feed-files/"* > "$2"
}

Extract_IPList() {
	# Keep only complete IPv4 or CIDR lines. The octet branches enforce 0-255
	# and the optional prefix branch enforces /0-/32.
	dos2unix < "$1" | grep -E '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)$' > "$2"
}

Normalize_Public_IPList() {
	# Canonicalise provider CIDRs and reject any network that overlaps private,
	# reserved or non-routable IPv4 space. A /0 response is therefore never usable.
	awk '
		function power(base, exponent, result) { result = 1; while (exponent-- > 0) result *= base; return result }
		function ipv4(a, b, c, d) { return (((a * 256) + b) * 256 + c) * 256 + d }
		function reserve(start, end) { blocked_start[++blocked_count] = start; blocked_end[blocked_count] = end }
		BEGIN {
			reserve(ipv4(0,0,0,0), ipv4(0,255,255,255))
			reserve(ipv4(10,0,0,0), ipv4(10,255,255,255))
			reserve(ipv4(100,64,0,0), ipv4(100,127,255,255))
			reserve(ipv4(127,0,0,0), ipv4(127,255,255,255))
			reserve(ipv4(169,254,0,0), ipv4(169,254,255,255))
			reserve(ipv4(172,16,0,0), ipv4(172,31,255,255))
			reserve(ipv4(192,0,0,0), ipv4(192,0,0,255))
			reserve(ipv4(192,0,2,0), ipv4(192,0,2,255))
			reserve(ipv4(192,168,0,0), ipv4(192,168,255,255))
			reserve(ipv4(198,18,0,0), ipv4(198,19,255,255))
			reserve(ipv4(198,51,100,0), ipv4(198,51,100,255))
			reserve(ipv4(203,0,113,0), ipv4(203,0,113,255))
			reserve(ipv4(224,0,0,0), ipv4(255,255,255,255))
		}
		{
			parts = split($1, address, "/"); octets = split(address[1], octet, ".")
			if (parts > 2 || octets != 4) next
			prefix = parts == 2 ? address[2] : 32
			if (prefix !~ /^[0-9]+$/ || prefix < 1 || prefix > 32) next
			value = ipv4(octet[1], octet[2], octet[3], octet[4])
			block = power(2, 32 - prefix); start = int(value / block) * block; end = start + block - 1
			blocked = 0
			for (i = 1; i <= blocked_count; i++) if (start <= blocked_end[i] && end >= blocked_start[i]) { blocked = 1; break }
			if (blocked) next
			first = int(start / 16777216); start -= first * 16777216
			second = int(start / 65536); start -= second * 65536
			third = int(start / 256); fourth = start - third * 256
			result = sprintf("%d.%d.%d.%d", first, second, third, fourth)
			if (parts == 2) result = result "/" prefix
			if (!seen[result]++) print result
		}
	' "$1" > "$2"
}

Download_IPList() {
	iplistdownload="$TMP_DIR/iplist-download"
	if ! Curl_Fetch -o "$iplistdownload" "$1"; then
		rm -f "$iplistdownload"
		return 1
	fi
	Extract_IPList "$iplistdownload" "$TMP_DIR/iplist-unfiltered.txt"
	ipliststatus="$?"
	rm -f "$iplistdownload"
	return "$ipliststatus"
}

Build_IPList_Restore() {
	# The input has already passed Extract_IPList. Filter private/reserved space
	# once, then classify a bare address or /32 as a host and every other CIDR
	# as a range so imported list membership remains deterministic.
	iplistaction="$1"
	iplisttarget="$2"
	iplistdescription="$3"
	Filter_PrivateIP < "$4" | awk -v action="$iplistaction" -v target="$iplisttarget" -v desc="$iplistdescription" '
		{
			value = $1
			if (target == "whitelist") setname = "Skynet-Whitelist"
			else if (index(value, "/") && value !~ /\/32$/) setname = "Skynet-BlockedRanges"
			else setname = "Skynet-Blacklist"
			if (action == "add") printf "add %s %s comment \"%s\"\n", setname, value, desc
			else printf "del %s %s\n", setname, value
		}' > "$5"
}

Refresh_Registered_ASN_Rules() {
	# Refresh every registered ASN into one staged registry and publish the
	# combined ban/whitelist policy only after all sources validate.
	asnrefreshmap="$TMP_DIR/asn-refresh-map.$$"
	asnrefreshchanged="0"
	asnrefreshcandidate="${skynetrules}.tmp.$$"
	true > "$asnrefreshmap" || return 1
	mkdir -p "$rulesdatadir" || return 1
	while IFS="$(printf '\t')" read -r _asnversion asnrefreshid asnrefreshtarget asnrefreshtype asnrefreshvalue \
		_asncomment asnrefreshstate _asncreated _asnexpires _asnolddata; do
		[ "$asnrefreshtype:$asnrefreshstate" = "asn:enabled" ] || continue
		asnrefreshraw="$TMP_DIR/asn-${asnrefreshvalue}.$$"
		asnrefreshvalidated="${asnrefreshraw}.validated"
		asnrefreshpublic="${asnrefreshraw}.public"
		if ! Curl_Fetch -o "$asnrefreshraw" "https://asn.ipinfo.app/api/text/list/$asnrefreshvalue" \
			|| ! Extract_IPList "$asnrefreshraw" "$asnrefreshvalidated" \
			|| ! Normalize_Public_IPList "$asnrefreshvalidated" "$asnrefreshpublic" \
			|| [ ! -s "$asnrefreshpublic" ]; then
			rm -f "$TMP_DIR"/asn-*.$$* "$asnrefreshmap" "$asnrefreshcandidate"
			Prune_Unreferenced_Rule_Data
			return 1
		fi
		asnrefreshhash="$(sha256sum "$asnrefreshpublic" 2>/dev/null | awk '{print $1}')"
		[ -n "$asnrefreshhash" ] || { rm -f "$TMP_DIR"/asn-*.$$* "$asnrefreshmap"; Prune_Unreferenced_Rule_Data; return 1; }
		asnrefreshdata="asn-${asnrefreshtarget}-${asnrefreshvalue}-${asnrefreshhash}.list"
		asnrefreshtargetfile="$rulesdatadir/$asnrefreshdata"
		asnrefreshtmp="${asnrefreshtargetfile}.tmp.$$"
		if ! cp -f "$asnrefreshpublic" "$asnrefreshtmp" || ! chmod 600 "$asnrefreshtmp" \
			|| ! mv -f "$asnrefreshtmp" "$asnrefreshtargetfile"; then
			rm -f "$asnrefreshtmp" "$TMP_DIR"/asn-*.$$* "$asnrefreshmap" "$asnrefreshcandidate"
			Prune_Unreferenced_Rule_Data
			return 1
		fi
		printf '%s\t%s\n' "$asnrefreshid" "$asnrefreshdata" >> "$asnrefreshmap" \
			|| { Prune_Unreferenced_Rule_Data; return 1; }
	done < "$skynetrules"
	rm -f "$TMP_DIR"/asn-*.$$*
	[ -s "$asnrefreshmap" ] || { rm -f "$asnrefreshmap"; return 0; }
	awk -F '\t' -v map="$asnrefreshmap" '
		BEGIN { while ((getline < map) > 0) data[$1] = $2; close(map) }
		$1 == "R2" && $2 in data {$10 = data[$2]}
		{print $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5 "\t" $6 "\t" $7 "\t" $8 "\t" $9 "\t" $10}
	' "$skynetrules" > "$asnrefreshcandidate" \
		|| { rm -f "$asnrefreshmap" "$asnrefreshcandidate"; Prune_Unreferenced_Rule_Data; return 1; }
	rm -f "$asnrefreshmap"
	if cmp -s "$asnrefreshcandidate" "$skynetrules"; then rm -f "$asnrefreshcandidate"; return 0; fi
	if Apply_Rule_Registry_Candidate "$asnrefreshcandidate"; then asnrefreshchanged="1"; return 0; fi
	Prune_Unreferenced_Rule_Data
	return 1
}

Validate_Rule_Registry() {
	# R2 is the authoritative policy format. IPSet comments are deliberately not
	# part of the key, so overlapping logical rules remain independently removable.
	rulevalidatefile="$1"
	[ -f "$rulevalidatefile" ] || return 1
	rulevalidateaddresses="$TMP_DIR/registry-addresses.$$"
	rulevalidatedomains="$TMP_DIR/registry-domains.$$"
	rulevalidatenormalized="$TMP_DIR/registry-normalized.$$"
	: > "$rulevalidateaddresses" && : > "$rulevalidatedomains" || return 1
	# Structural checks collect typed values for the existing batch validators.
	# Canonical comparison rejects host bits and alternate spellings of a key.
	awk -F '\t' -v addresses="$rulevalidateaddresses" -v domains="$rulevalidatedomains" '
		NF != 10 || $1 != "R2" || $2 !~ /^r[0-9]+(-[0-9]+)?$/ \
			|| ($3 != "ban" && $3 != "whitelist") \
			|| ($4 != "ip" && $4 != "range" && $4 != "domain" && $4 != "asn" && $4 != "import") \
			|| $5 == "" || $6 !~ /^C/ || ($7 != "enabled" && $7 != "disabled") \
			|| $8 !~ /^[0-9]+$/ || $9 !~ /^[0-9]+$/ || $10 == "" { exit 1 }
		{
			if (seen_id[$2]++) exit 1
			if ($4 != "import") {
				key = $3 SUBSEP $4 SUBSEP tolower($5)
				if (seen_key[key]++) exit 1
			}
			if ($9 != 0 && ($3 != "ban" || ($4 != "ip" && $4 != "range"))) exit 1
			if (($4 == "asn" || $4 == "import") && ($10 == "-" || $10 !~ /^[A-Za-z0-9._-]+$/)) exit 1
			if ($4 != "asn" && $4 != "import" && $10 != "-") exit 1
			if (length($6) > 243 || index($6, "\\") || index($6, "\"") || $6 ~ /[[:cntrl:]]/) exit 1
			if ($4 == "ip" && index($5, "/")) exit 1
			if ($4 == "range" && !index($5, "/")) exit 1
			if ($4 == "ip" || $4 == "range") print $5 > addresses
			else if ($4 == "domain") print $5 > domains
			else if ($4 == "asn" && $5 !~ /^AS[0-9]{1,6}$/) exit 1
			else if ($4 == "import" && $5 !~ /^[A-Za-z0-9._-]+$/) exit 1
		}
	' "$rulevalidatefile"
	rulevalidatestatus="$?"
	if [ "$rulevalidatestatus" = "0" ] && [ -s "$rulevalidateaddresses" ]; then
		Normalize_IPSet_Entries any < "$rulevalidateaddresses" > "$rulevalidatenormalized" \
			&& cmp -s "$rulevalidateaddresses" "$rulevalidatenormalized" || rulevalidatestatus="1"
	fi
	if [ "$rulevalidatestatus" = "0" ] && [ -s "$rulevalidatedomains" ]; then
		Normalize_Domain_Input canonical < "$rulevalidatedomains" > "$rulevalidatenormalized" \
			&& cmp -s "$rulevalidatedomains" "$rulevalidatenormalized" || rulevalidatestatus="1"
	fi
	rm -f "$rulevalidateaddresses" "$rulevalidatedomains" "$rulevalidatenormalized"
	return "$rulevalidatestatus"
}

Validate_Legacy_Rule_Registry() {
	[ -f "$1" ] || return 1
	awk -F '\t' '
		NF != 7 || $1 != "R1" || ($2 != "ban" && $2 != "whitelist") \
			|| ($3 != "ip" && $3 != "range" && $3 != "domain" && $3 != "asn") \
			|| $4 == "" || $5 !~ /^C/ || ($6 != "enabled" && $6 != "disabled") \
			|| $7 !~ /^[0-9]+$/ { exit 1 }
		{ key = $2 SUBSEP $3 SUBSEP tolower($4); if (seen[key]++) exit 1 }
	' "$1"
}

New_Rule_ID() {
	# The checksum keeps IDs compact on BusyBox. The numeric suffix resolves the
	# unlikely collision and is retained permanently once the row is published.
	ruleidsource="$1|$2|$3|$4|$$"
	ruleidbase="$(printf '%s\n' "$ruleidsource" | sha256sum | awk '{print substr($1, 1, 8)}')"
	[ "${#ruleidbase}" = "8" ] || return 1
	case "$ruleidbase" in *[!0-9a-f]*) return 1 ;; esac
	ruleidbase="$(printf '%u' "0x$ruleidbase")" || return 1
	ruleid="r$ruleidbase"
	ruleidsuffix="0"
	while awk -F '\t' -v id="$ruleid" '($1 == "R2" && $2 == id) || $4 == id {found=1} END {exit !found}' \
		"${5:-$skynetrules}" ${6:+"$6"} 2>/dev/null; do
		ruleidsuffix=$((ruleidsuffix + 1))
		ruleid="r${ruleidbase}-${ruleidsuffix}"
	done
	unset "ruleidsource" "ruleidbase" "ruleidsuffix"
}

Append_R2_Rule() {
	ruleappendfile="$1"
	ruleappendtarget="$2"
	ruleappendtype="$3"
	ruleappendvalue="$4"
	ruleappendcomment="$5"
	ruleappendstate="$6"
	ruleappendcreated="$7"
	ruleappendexpires="$8"
	ruleappenddata="$9"
	if awk -F '\t' -v target="$ruleappendtarget" -v type="$ruleappendtype" -v value="$ruleappendvalue" \
		'$1 == "R2" && $3 == target && $4 == type && tolower($5) == tolower(value) {found=1} END {exit !found}' "$ruleappendfile" 2>/dev/null; then
		return 0
	fi
	New_Rule_ID "$ruleappendtarget" "$ruleappendtype" "$ruleappendvalue" "$ruleappendcreated" "$ruleappendfile" || return 1
	printf 'R2\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$ruleid" "$ruleappendtarget" "$ruleappendtype" \
		"$ruleappendvalue" "$ruleappendcomment" "$ruleappendstate" "$ruleappendcreated" "$ruleappendexpires" "$ruleappenddata" >> "$ruleappendfile"
}

Initialize_Rule_Registry() {
	# Legacy comments are read once during the R2 migration. Normal rule handling
	# uses stable registry IDs and never treats an IPSet comment as ownership.
	if [ -f "$skynetrules" ] && Validate_Rule_Registry "$skynetrules"; then
		# An empty legacy registry may still have comment-owned rules in the saved
		# sets. Only the completed migration marker makes that empty state final.
		if [ -s "$skynetrules" ] || Rule_Migration_Complete; then return 0; fi
	fi
	if [ -e "$skynetrules" ] && ! Validate_Legacy_Rule_Registry "$skynetrules"; then
		Log error -s "Invalid Rule Registry - Existing File Retained"
		return 1
	fi
	ruleregistrysource="$skynetipset"
	ruleregistrytmp="${skynetrules}.tmp.$$"
	rulemigrationdir="$TMP_DIR/rules-migration.$$"
	rulemigrationsource="$TMP_DIR/rules-legacy.$$"
	mkdir -p "$rulesdatadir" "$rulemigrationdir" || return 1
	true > "$ruleregistrytmp" || return 1
	if [ ! -s "$ruleregistrysource" ]; then
		ruleregistrysource="$TMP_DIR/rules-ipset.$$"
		{ ipset save Skynet-Blacklist \
			&& ipset save Skynet-BlockedRanges \
			&& ipset save Skynet-Whitelist; } > "$ruleregistrysource" 2>/dev/null \
			|| { rm -f "$ruleregistrysource"; return 1; }
	fi
	if Time_Is_Ready; then ruleregistryepoch="$(date +%s)"; else ruleregistryepoch="0"; fi
	if [ -f "$skynetrules" ]; then
		while IFS="$(printf '\t')" read -r _ruleversion ruletarget ruletype rulevalue rulecomment rulestate rulecreated; do
			rulecomment="C$(printf '%s\n' "${rulecomment#C}" | sed 's/["\\]/ /g' | cut -c 1-242)"
			ruledata="-"
			if [ "$ruletype" = "asn" ]; then
				ruledatawork="$rulemigrationdir/asn-${ruletarget}-${rulevalue}.work"
				awk -v expected="$rulevalue" -v target="$ruletarget" '$1 == "add" {
					if (($2 == "Skynet-Whitelist" ? "whitelist" : "ban") != target) next
					position=index($0,"comment \""); if (!position) next
					comment=substr($0,position+9); sub(/\"$/, "", comment)
					if (index(comment, "ASN: ") != 1) next
					value=substr(comment,6); sub(/[[:space:]].*$/, "", value)
					if (toupper(value) == expected) print $3
				}' "$ruleregistrysource" | awk '!seen[$0]++' > "$ruledatawork"
				[ -s "$ruledatawork" ] || { rm -f "$ruledatawork"; continue; }
				ruledatahash="$(sha256sum "$ruledatawork" 2>/dev/null | awk '{print $1}')"
				[ -n "$ruledatahash" ] || return 1
				ruledata="asn-${ruletarget}-${rulevalue}-${ruledatahash}.list"
				mv -f "$ruledatawork" "$rulemigrationdir/$ruledata" || return 1
			fi
			Append_R2_Rule "$ruleregistrytmp" "$ruletarget" "$ruletype" "$rulevalue" "$rulecomment" "$rulestate" "$rulecreated" 0 "$ruledata" || return 1
		done < "$skynetrules"
	fi
	awk -v created="$ruleregistryepoch" '
		function saved_comment(line, position, value) {
			position = index(line, "comment \"")
			if (!position) return ""
			value = substr(line, position + 9)
			sub(/\"$/, "", value)
			return value
		}
		function emit(target, type, value, detail, key) {
			if (type == "ip") sub(/\/32$/, "", value)
			key = target SUBSEP type SUBSEP tolower(value)
			if (value == "") return
			gsub(/[[:cntrl:]]/, " ", detail)
			gsub(/[\\"]/, " ", detail)
			detail = substr(detail, 1, 242)
			if (key in seen) return
			seen[key] = 1
			printf "%s\t%s\t%s\tC%s\tenabled\t%s\n", target, type, value, detail, created
		}
		$1 == "add" {
			comment = saved_comment($0)
			if (index(comment, "ManualBanD: ") == 1) {
				value = substr(comment, 13); emit("ban", "domain", tolower(value), ""); next
			}
			if (index(comment, "ManualWlistD: ") == 1) {
				value = substr(comment, 15); emit("whitelist", "domain", tolower(value), ""); next
			}
			if (index(comment, "ASN: AS") == 1) {
				value = substr(comment, 6); sub(/[[:space:]].*$/, "", value)
				target = $2 == "Skynet-Whitelist" ? "whitelist" : "ban"
				emit(target, "asn", toupper(value), ""); next
			}
			if (index(comment, "ManualBan: ") == 1) {
				emit("ban", "ip", $3, substr(comment, 12)); next
			}
			if (index(comment, "ManualRBan: ") == 1) {
				emit("ban", "range", $3, substr(comment, 13)); next
			}
			if (index(comment, "ManualWlist: ") == 1) {
				type = index($3, "/") && $3 !~ /\/32$/ ? "range" : "ip"
				emit("whitelist", type, $3, substr(comment, 14))
			}
		}
	' "$ruleregistrysource" > "$rulemigrationsource" || return 1
	while IFS="$(printf '\t')" read -r ruletarget ruletype rulevalue rulecomment rulestate rulecreated; do
		[ -n "$ruletarget" ] || continue
		ruledata="-"
		if [ "$ruletype" = "asn" ]; then
			ruledatawork="$rulemigrationdir/asn-${ruletarget}-${rulevalue}.work"
			awk -v expected="$rulevalue" -v target="$ruletarget" '$1 == "add" {
				if (($2 == "Skynet-Whitelist" ? "whitelist" : "ban") != target) next
				position=index($0,"comment \""); if (!position) next
				comment=substr($0,position+9); sub(/\"$/, "", comment)
				if (index(comment, "ASN: ") != 1) next
				value=substr(comment,6); sub(/[[:space:]].*$/, "", value)
				if (toupper(value) == expected) print $3
			}' "$ruleregistrysource" | awk '!seen[$0]++' > "$ruledatawork"
			[ -s "$ruledatawork" ] || { rm -f "$ruledatawork"; continue; }
			ruledatahash="$(sha256sum "$ruledatawork" 2>/dev/null | awk '{print $1}')"
			[ -n "$ruledatahash" ] || return 1
			ruledata="asn-${ruletarget}-${rulevalue}-${ruledatahash}.list"
			if [ ! -f "$rulemigrationdir/$ruledata" ]; then mv -f "$ruledatawork" "$rulemigrationdir/$ruledata" || return 1; else rm -f "$ruledatawork"; fi
		fi
		Append_R2_Rule "$ruleregistrytmp" "$ruletarget" "$ruletype" "$rulevalue" "$rulecomment" "$rulestate" "$rulecreated" 0 "$ruledata" || return 1
	done < "$rulemigrationsource"

	# Legacy imports had no registry rows. Preserve each distinguishable target and
	# exact comment as one group with immutable normalized membership.
	awk '
		$1 == "add" {
			position=index($0,"comment \""); if (!position) next
			comment=substr($0,position+9); sub(/\"$/, "", comment)
			if (index(comment,"Imported: ") != 1) next
			target=$2 == "Skynet-Whitelist" ? "whitelist" : "ban"
			print target "\t" comment
		}' "$ruleregistrysource" | awk -F '\t' '!seen[$1 SUBSEP $2]++' > "$rulemigrationdir/imports"
	ruleimportnumber="0"
	while IFS="$(printf '\t')" read -r ruletarget rulelegacycomment; do
		[ -n "$ruletarget" ] || continue
		ruleimportnumber=$((ruleimportnumber + 1))
		rulevalue="legacy-import-$ruleimportnumber"
		ruledatawork="$rulemigrationdir/import-${rulevalue}.work"
		awk -v target="$ruletarget" -v expected="$rulelegacycomment" '$1 == "add" {
			position=index($0,"comment \""); if (!position) next
			comment=substr($0,position+9); sub(/\"$/, "", comment)
			rowtarget=$2 == "Skynet-Whitelist" ? "whitelist" : "ban"
			if (rowtarget == target && comment == expected) print $3
		}' "$ruleregistrysource" | awk '!seen[$0]++' > "$ruledatawork" || return 1
		[ -s "$ruledatawork" ] || return 1
		ruledatahash="$(sha256sum "$ruledatawork" 2>/dev/null | awk '{print $1}')"
		[ -n "$ruledatahash" ] || return 1
		ruledata="import-${rulevalue}-${ruledatahash}.list"
		mv -f "$ruledatawork" "$rulemigrationdir/$ruledata" || return 1
		Append_R2_Rule "$ruleregistrytmp" "$ruletarget" import "$rulevalue" "C${rulelegacycomment#Imported: }" enabled "$ruleregistryepoch" 0 "$ruledata" || return 1
	done < "$rulemigrationdir/imports"

	rulemigrationstatus="0"
	rulemigrationpublished=""
	for rulemigrationfile in "$rulemigrationdir"/*.list; do
		[ -f "$rulemigrationfile" ] || continue
		rulemigrationtarget="$rulesdatadir/$(basename "$rulemigrationfile")"
		if [ -f "$rulemigrationtarget" ] || [ -L "$rulemigrationtarget" ] || [ -d "$rulemigrationtarget" ]; then
			if [ ! -f "$rulemigrationtarget" ] || [ -L "$rulemigrationtarget" ] \
				|| ! cmp -s "$rulemigrationfile" "$rulemigrationtarget"; then rulemigrationstatus="1"; break; fi
			continue
		fi
		rulemigrationtmp="${rulemigrationtarget}.tmp.$$"
		if ! cp -f "$rulemigrationfile" "$rulemigrationtmp" || ! chmod 600 "$rulemigrationtmp" \
			|| ! mv -f "$rulemigrationtmp" "$rulemigrationtarget"; then
			rulemigrationstatus="1"
			break
		fi
		rulemigrationpublished="${rulemigrationpublished}${rulemigrationpublished:+ }$rulemigrationtarget"
	done
	if [ "$rulemigrationstatus" != "0" ] || ! Validate_Rule_Registry "$ruleregistrytmp" \
		|| ! chmod 600 "$ruleregistrytmp" || ! mv -f "$ruleregistrytmp" "$skynetrules"; then
		rm -f "$ruleregistrytmp"
		for rulemigrationtarget in $rulemigrationpublished; do rm -f "$rulemigrationtarget"; done
		[ "$ruleregistrysource" = "$skynetipset" ] || rm -f "$ruleregistrysource"
		return 1
	fi
	rulemigrationpublished=""
	[ "$ruleregistrysource" = "$skynetipset" ] || rm -f "$ruleregistrysource"
	return 0
}

Stage_Rule_Registry_Request() {
	# Request rows contain type, normalized value, optional sidecar basename and
	# optional C-prefixed comment. The prefix preserves empty comments in ash read.
	# Existing IDs and creation times survive edits; expiry is always absolute.
	rulestageaction="$1"
	rulestagetarget="$2"
	rulestagerequest="$3"
	Validate_IPSet_Comment "$4" 242 || return 2
	rulestagecomment="$4"
	rulestageexpires="${5:-0}"
	rulestagefile="${skynetrules}.tmp.$$"
	rulestageprepared="$TMP_DIR/rules-prepared.$$"
	rulestagestatusfile="$TMP_DIR/rules-stage-status.$$"
	case "$rulestageaction:$rulestagetarget" in add:ban|add:whitelist|remove:ban|remove:whitelist) ;; *) return 2 ;; esac
	case "$rulestageexpires" in ""|*[!0-9]*) return 2 ;; esac
	[ "$rulestageaction" != "add" ] || Time_Is_Ready || return 2
	[ -s "$rulestagerequest" ] || return 2
	rulestagecomment="C$rulestagecomment"
	if Time_Is_Ready; then rulestageepoch="$(date +%s)"; else rulestageepoch="0"; fi
	true > "$rulestageprepared" && true > "$rulestagestatusfile" || return 1
	while IFS="$(printf '\t')" read -r rulerequesttype rulerequestvalue rulerequestdata rulerequestcomment; do
		[ -n "$rulerequesttype" ] && [ -n "$rulerequestvalue" ] || return 2
		rulerequestdata="${rulerequestdata:--}"
		rulerequestcomment="${rulerequestcomment:-$rulestagecomment}"
		case "$rulerequestcomment" in C*) ;; *) return 2 ;; esac
		Validate_IPSet_Comment "${rulerequestcomment#C}" 242 || return 2
		rulerequestid="$(awk -F '\t' -v target="$rulestagetarget" -v type="$rulerequesttype" -v value="$rulerequestvalue" \
			'$1 == "R2" && $3 == target && $4 == type && tolower($5) == tolower(value) {print $2; exit}' "$skynetrules")"
		if [ -z "$rulerequestid" ]; then
			New_Rule_ID "$rulestagetarget" "$rulerequesttype" "$rulerequestvalue" "$rulestageepoch" "$skynetrules" "$rulestageprepared" || return 1
			rulerequestid="$ruleid"
		fi
		printf '%s\t%s\t%s\t%s\t%s\n' "$rulerequesttype" "$rulerequestvalue" "$rulerequestdata" "$rulerequestid" "$rulerequestcomment" >> "$rulestageprepared" || return 1
	done < "$rulestagerequest"
	awk -F '\t' -v action="$rulestageaction" -v target="$rulestagetarget" \
		-v created="$rulestageepoch" -v expires="$rulestageexpires" \
		-v requests="$rulestageprepared" -v statusfile="$rulestagestatusfile" -v now="$rulestageepoch" '
		BEGIN {
			while ((getline < requests) > 0) {
				key = $1 SUBSEP tolower($2)
				wanted[key] = $2
				types[key] = $1
				data[key] = $3
				ids[key] = $4
				details[key] = $5
				order[++count] = key
			}
			close(requests)
		}
		{
			if ($1 == "R2" && $9 > 0 && $9 <= now) {changed++; next}
			key = $4 SUBSEP tolower($5)
			if ($3 == target && key in wanted) {
				found[key] = 1
				if (action == "remove") {changed++; next}
				if (expires > 0 && $9 == 0) {
					permanent++
					print
					next
				}
				old = $6 SUBSEP $7 SUBSEP $9 SUBSEP $10
				if (details[key] != "C") $6 = details[key]
				$7 = "enabled"
				$9 = expires
				if (data[key] != "-") $10 = data[key]
				if (old != $6 SUBSEP $7 SUBSEP $9 SUBSEP $10) changed++
			}
			print $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5 "\t" $6 "\t" $7 "\t" $8 "\t" $9 "\t" $10
		}
		END {
			if (action == "remove") {
				for (key in wanted) if (!found[key]) missing = 1
				exit missing ? 2 : 0
			}
			for (i = 1; i <= count; i++) {
				key = order[i]
				if (!found[key]++) {
					printf "R2\t%s\t%s\t%s\t%s\t%s\tenabled\t%s\t%s\t%s\n", ids[key], target, types[key], wanted[key], details[key], created, expires, data[key]
					changed++
				}
			}
			print "changed\t" changed + 0 > statusfile
			print "permanent\t" permanent + 0 >> statusfile
		}
	' "$skynetrules" > "$rulestagefile"
	rulestagestatus="$?"
	if [ "$rulestagestatus" != "0" ]; then
		rm -f "$rulestagefile"
		return "$rulestagestatus"
	fi
	rulestagechanged="$(awk -F '\t' '$1 == "changed" {print $2}' "$rulestagestatusfile")"
	rulestagepermanent="$(awk -F '\t' '$1 == "permanent" {print $2}' "$rulestagestatusfile")"
	rulestagechanged="${rulestagechanged:-0}"
	rulestagepermanent="${rulestagepermanent:-0}"
	Validate_Rule_Registry "$rulestagefile"
}

Stage_Rule_Registry() {
	# Stage a complete single-type add/remove request without changing live state.
	rulestagetype="$3"
	rulestagevalues="$4"
	rulestagerequest="$TMP_DIR/rules-request.$$"
	case "$rulestagetype" in ip|range|domain|asn) ;; *) return 2 ;; esac
	[ -n "$rulestagevalues" ] || return 2
	# shellcheck disable=SC2086 # Values are validated atomic list members.
	printf '%s\n' $rulestagevalues | awk -v type="$rulestagetype" 'NF && !seen[tolower($0)]++ {print type "\t" $0 "\t-"}' > "$rulestagerequest" || return 1
	Stage_Rule_Registry_Request "$1" "$2" "$rulestagerequest" "$5" "${6:-0}"
	rulestagestatus="$?"
	rm -f "$rulestagerequest"
	return "$rulestagestatus"
}

Stage_Rule_Registry_Clear() {
	rulestagetarget="$1"
	case "$rulestagetarget" in ban|whitelist) ;; *) return 2 ;; esac
	rulestagefile="${skynetrules}.tmp.$$"
	awk -F '\t' -v target="$rulestagetarget" '$1 == "R2" && $3 == target {next} {print}' \
		"$skynetrules" > "$rulestagefile"
	rulestagestatus="$?"
	if [ "$rulestagestatus" = "0" ] && Validate_Rule_Registry "$rulestagefile"; then return 0; fi
	rm -f "$rulestagefile"
	[ "$rulestagestatus" != "0" ] && return "$rulestagestatus"
	return 1
}

Stage_Rule_Registry_Remove_ID() {
	ruleremoveid="$1"
	printf '%s\n' "$ruleremoveid" | grep -qE '^r[0-9]+(-[0-9]+)?$' || return 2
	rulestagefile="${skynetrules}.tmp.$$"
	ruleremoverow="$(awk -F '\t' -v id="$ruleremoveid" '$1 == "R2" && $2 == id {print; exit}' "$skynetrules")"
	[ -n "$ruleremoverow" ] || return 2
	if ! awk -F '\t' -v id="$ruleremoveid" '$1 == "R2" && $2 == id {next} {print}' "$skynetrules" > "$rulestagefile" \
		|| ! Validate_Rule_Registry "$rulestagefile"; then rm -f "$rulestagefile"; return 1; fi
	IFS="$(printf '\t')" read -r _ruleremoveversion ruleremoveid ruleremovetarget ruleremovetype ruleremovevalue ruleremovecomment _ruleremovestate _ruleremovecreated _ruleremoveexpires _ruleremovedata <<EOF
$ruleremoverow
EOF
}

Remove_Registered_Rule_ID() {
	Stage_Rule_Registry_Remove_ID "$1" || return "$?"
	if [ "$ruleremovetype" = "domain" ]; then
		Update_Domain_Rules "$rulestagefile" cached
	else
		Apply_Rule_Registry_Candidate "$rulestagefile" remove
	fi
}

Publish_Staged_Rule_Registry() {
	[ -n "$rulestagefile" ] && [ -f "$rulestagefile" ] || return 1
	[ ! -L "$skynetrules" ] || return 1
	ruleregistrybackup="$TMP_DIR/rules-old.$$"
	cp -f "$skynetrules" "$ruleregistrybackup" 2>/dev/null || return 1
	if chmod 600 "$rulestagefile" && mv -f "$rulestagefile" "$skynetrules"; then
		rulestagefile=""
		return 0
	fi
	rm -f "$rulestagefile"
	return 1
}

Require_Rule_Registry() {
	Validate_Rule_Registry "$skynetrules" && return 0
	echo "[*] Rule Registry Is Unavailable Or Invalid - No Changes Made"
	echo
	exit 1
}

Ensure_User_IPSets() {
	# R2 sets are compiled from the registry. Recreate an incompatible schema
	# instead of preserving metadata or relative timeout options from older builds.
	for useripset in Skynet-UserBans Skynet-TemporaryBans Skynet-UserWhitelist; do
		if ipset -n list 2>/dev/null | grep -qxF "$useripset"; then
			if [ "$useripset" = "Skynet-TemporaryBans" ]; then useripsetmode="temporary"; else useripsetmode="permanent"; fi
			if ! Compiled_IPSet_Schema_Is_Valid "$useripset" "$useripsetmode"; then
				ipset -q del Skynet-Master "$useripset" 2>/dev/null
				ipset -q del Skynet-MasterWL "$useripset" 2>/dev/null
				ipset -q destroy "$useripset" 2>/dev/null || return 1
			fi
		fi
	done
	Ensure_IPSet Skynet-UserBans hash:net hashsize 64 maxelem "$((65536 * 6))" || return 1
	Ensure_IPSet Skynet-TemporaryBans hash:net hashsize 64 maxelem 65536 timeout 0 || return 1
	Ensure_IPSet Skynet-UserWhitelist hash:net hashsize 64 maxelem "$((65536 * 6))" || return 1
	Update_IPSet add Skynet-Master Skynet-UserBans || return 1
	Update_IPSet add Skynet-Master Skynet-TemporaryBans || return 1
	Update_IPSet add Skynet-MasterWL Skynet-UserWhitelist || return 1
}

Compiled_IPSet_Schema_Is_Valid() {
	compiledsetname="$1"
	compiledsetmode="$2"
	compiledsetcreate="$(Read_IPSet_Schema "$compiledsetname")" || return 1
	case "$compiledsetcreate" in "create $compiledsetname hash:net "*) ;; *) return 1 ;; esac
	case " $compiledsetcreate " in *" comment "*|*" counters "*|*" skbinfo "*) return 1 ;; esac
	case "$compiledsetmode: $compiledsetcreate " in
		temporary:*" timeout 0"*) return 0 ;;
		temporary:*) return 1 ;;
		permanent:*" timeout "*) return 1 ;;
		permanent:*) return 0 ;;
		*) return 1 ;;
	esac
}

Validate_Rule_Data_File() {
	[ -s "$1" ] && [ ! -L "$1" ] || return 1
	# Validate the complete sidecar in one pass. Comparing canonical output also
	# rejects host bits, leading zeroes and whitespace without a process per entry.
	ruledatanormalized="$TMP_DIR/rule-data-normalized.$$"
	ruledatacompare="$TMP_DIR/rule-data-compare.$$"
	Normalize_IPSet_Entries any < "$1" > "$ruledatanormalized" \
		&& sed '/^$/d; s~/32$~~' "$1" > "$ruledatacompare" \
		&& cmp -s "$ruledatanormalized" "$ruledatacompare"
	ruledatastatus="$?"
	rm -f "$ruledatanormalized" "$ruledatacompare"
	return "$ruledatastatus"
}

Validate_Rule_Data_Reference() {
	ruledatatype="$1"
	ruledataname="$2"
	ruledatafile="$3"
	case "$ruledatatype" in
		asn) printf '%s\n' "$ruledataname" | grep -qE '^asn-(ban|whitelist)-AS[0-9]{1,6}-[0-9a-f]{64}\.list$' || return 1 ;;
		import) printf '%s\n' "$ruledataname" | grep -qE '^import-[A-Za-z0-9._-]+-[0-9a-f]{64}\.list$' || return 1 ;;
		*) return 1 ;;
	esac
	ruledataexpected="${ruledataname%.list}"
	ruledataexpected="${ruledataexpected##*-}"
	[ "$(sha256sum "$ruledatafile" 2>/dev/null | awk '{print $1}')" = "$ruledataexpected" ]
}

Prune_Unreferenced_Rule_Data() {
	# ASN and import sidecars are immutable. Files not referenced by the committed
	# registry cannot affect policy. Read ownership once and refuse cleanup if the
	# registry cannot be read, rather than treating an I/O error as an unused file.
	ruleprunecandidates="$TMP_DIR/rule-data-candidates.$$"
	rulepruneunused="$TMP_DIR/rule-data-unused.$$"
	printf '%s\n' "$rulesdatadir"/asn-*.list "$rulesdatadir"/import-*.list > "$ruleprunecandidates" || return 1
	if ! awk -F '\t' -v registry="$skynetrules" '
		BEGIN {
			while ((status = getline line < registry) > 0) {
				if (split(line, field, "\t") != 10 || field[1] != "R2") exit 1
				used[field[10]] = 1
			}
			close(registry)
			if (status < 0) exit 1
		}
		{ name = $0; sub(/.*\//, "", name); if (!(name in used)) print }
	' "$ruleprunecandidates" > "$rulepruneunused"; then
		rm -f "$ruleprunecandidates" "$rulepruneunused"
		return 1
	fi
	ruleprunedatastatus="0"
	while IFS= read -r rulesidecar; do
		[ -e "$rulesidecar" ] || continue
		rm -f "$rulesidecar" || ruleprunedatastatus="1"
	done < "$rulepruneunused"
	rm -f "$ruleprunecandidates" "$rulepruneunused"
	return "$ruleprunedatastatus"
}

Validate_Compiled_Rule_Data() {
	# Immutable sidecars are shared by reason and set compilation. Reuse successful
	# validation only within one state-locked transaction, never across requests.
	if [ "${rulevalidationactive:-0}" = "1" ]; then
		case " $rulevalidatedfiles " in *" $2 "*) return 0 ;; esac
	fi
	Validate_Rule_Data_File "$3" && Validate_Rule_Data_Reference "$1" "$2" "$3" || return 1
	if [ "${rulevalidationactive:-0}" = "1" ]; then
		rulevalidatedfiles="${rulevalidatedfiles}${rulevalidatedfiles:+ }$2"
	fi
	return 0
}

Build_Rule_Reason_Index() {
	# R2I rows expand logical ownership once when policy changes. Statistics can
	# then join reasons without reopening every ASN and import sidecar.
	ruleindexregistry="$1"
	ruleindexstage="$TMP_DIR/rule-reasons.$$"
	ruleindexhash="$(Rule_Reason_Index_Hash "$ruleindexregistry")"
	[ -n "$ruleindexhash" ] || return 1
	printf 'R2I\t%s\n' "$ruleindexhash" > "$ruleindexstage" || return 1
	while IFS="$(printf '\t')" read -r _ruleindexversion ruleindexid ruleindextarget ruleindextype ruleindexvalue \
		ruleindexcomment ruleindexstate _ruleindexcreated ruleindexexpires ruleindexdata; do
		[ "$ruleindexstate" = "enabled" ] || continue
		ruleindexreason="${ruleindexcomment#C}"
		case "$ruleindextype" in
			ip|range)
				[ -n "$ruleindexreason" ] || ruleindexreason="Manual Rule"
				printf 'R2I\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$ruleindextarget" "$ruleindextype" \
					"$ruleindexvalue" "$ruleindexreason" "$ruleindexid" "$ruleindexexpires" "$ruleindexvalue" >> "$ruleindexstage" || return 1
			;;
			asn|import)
				ruleindexfile="$rulesdatadir/$ruleindexdata"
				Validate_Compiled_Rule_Data "$ruleindextype" "$ruleindexdata" "$ruleindexfile" || return 1
				if [ -z "$ruleindexreason" ]; then
					if [ "$ruleindextype" = "asn" ]; then ruleindexreason="ASN: $ruleindexvalue"; else ruleindexreason="Imported Rule"; fi
				fi
				awk -v target="$ruleindextarget" -v reason="$ruleindexreason" -v id="$ruleindexid" \
					-v expires="$ruleindexexpires" -v value="$ruleindexvalue" 'NF {
						sub(/\/32$/, "")
						type = index($0, "/") ? "range" : "ip"
						printf "R2I\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", target, type, $0, reason, id, expires, value
					}' "$ruleindexfile" >> "$ruleindexstage" || return 1
			;;
		esac
	done < "$ruleindexregistry"
}

Rule_Reason_Index_Hash() {
	# Domain ownership is resolved through its own manifest and never appears in
	# the compact address index. Excluding those rows avoids needless rebuilds.
	awk -F '\t' '$1 == "R2" && $7 == "enabled" && ($4 == "ip" || $4 == "range" || $4 == "asn" || $4 == "import")' "$1" 2>/dev/null \
		| sha256sum 2>/dev/null | awk '{print $1}'
}

Rule_Reason_Index_Is_Current() {
	[ -s "$RULE_REASON_INDEX" ] && [ ! -L "$RULE_REASON_INDEX" ] || return 1
	ruleindexexpected="$(Rule_Reason_Index_Hash "$skynetrules")"
	[ -n "$ruleindexexpected" ] \
		&& [ "$(awk -F '\t' 'NR == 1 && $1 == "R2I" {print $2}' "$RULE_REASON_INDEX")" = "$ruleindexexpected" ]
}

Prepare_User_Rule_Sets() {
	# Compile logical owners into disposable sets. Publishing uses compatible swaps,
	# so no partially built user policy becomes visible to the firewall.
	rulecompilefile="$1"
	rulecompilenow="$2"
	rulecompilebanset="Skynet-UserBans-Tmp"
	rulecompiletempset="Skynet-TemporaryBans-Tmp"
	rulecompilewhitelistset="Skynet-UserWhitelist-Tmp"
	rulecompilerestore="$TMP_DIR/rules-compile.$$"
	rulecompiledeadlines="$TMP_DIR/rules-deadlines.$$"
	cleanupipsets="${cleanupipsets}${cleanupipsets:+ }$rulecompilebanset $rulecompiletempset $rulecompilewhitelistset"
	Destroy_IPSets "$rulecompilebanset" "$rulecompiletempset" "$rulecompilewhitelistset"
	if ! ipset -q create "$rulecompilebanset" hash:net hashsize 64 maxelem "$((65536 * 6))" \
		|| ! ipset -q create "$rulecompiletempset" hash:net hashsize 64 maxelem 65536 timeout 0 \
		|| ! ipset -q create "$rulecompilewhitelistset" hash:net hashsize 64 maxelem "$((65536 * 6))" \
		|| ! true > "$rulecompilerestore" || ! true > "$rulecompiledeadlines"; then
		Destroy_IPSets "$rulecompilebanset" "$rulecompiletempset" "$rulecompilewhitelistset"
		return 1
	fi
	while IFS="$(printf '\t')" read -r _ruleversion _ruleid ruletarget ruletype rulevalue _rulecomment rulestate _rulecreated ruleexpires ruledateref; do
		[ "$rulestate" = "enabled" ] || continue
		case "$ruletype" in
			ip|range)
				if [ "$ruletarget" = "whitelist" ]; then
					printf 'add %s %s\n' "$rulecompilewhitelistset" "$rulevalue" >> "$rulecompilerestore" || return 1
			elif [ "$ruleexpires" = "0" ]; then
					printf 'add %s %s\n' "$rulecompilebanset" "$rulevalue" >> "$rulecompilerestore" || return 1
			elif [ "$rulecompilenow" -gt "0" ] && [ "$ruleexpires" -gt "$rulecompilenow" ]; then
				printf '%s\t%s\n' "$rulevalue" "$ruleexpires" >> "$rulecompiledeadlines" || return 1
			fi
			;;
			asn|import)
				ruledatafile="$rulesdatadir/$ruledateref"
				Validate_Compiled_Rule_Data "$ruletype" "$ruledateref" "$ruledatafile" || return 1
				if [ "$ruletarget" = "ban" ]; then rulecompiledataset="$rulecompilebanset"; else rulecompiledataset="$rulecompilewhitelistset"; fi
				# Restore -! already tolerates duplicate owners; stream validated data
				# without holding another full copy of the import in an AWK table.
				awk -v setname="$rulecompiledataset" 'NF {printf "add %s %s\n", setname, $0}' "$ruledatafile" >> "$rulecompilerestore" || return 1
			;;
		esac
	done < "$rulecompilefile"
	if ! ipset restore -! < "$rulecompilerestore" 2>/dev/null; then
		Destroy_IPSets "$rulecompilebanset" "$rulecompiletempset" "$rulecompilewhitelistset"
		return 1
	fi
	# Calculate remaining lifetimes after large imports have finished compiling
	# and restoring, so that work cannot extend an absolute expiry deadline.
	if [ -s "$rulecompiledeadlines" ]; then
		awk -F '\t' -v now="$(date +%s)" -v setname="$rulecompiletempset" '$2 > now {
			printf "add %s %s timeout %d\n", setname, $1, $2 - now
		}' "$rulecompiledeadlines" > "$rulecompilerestore" \
			&& ipset restore -! < "$rulecompilerestore" 2>/dev/null || return 1
	fi
	return 0
}

Publish_User_Rule_Sets() {
	# After each swap the temporary name holds the previous live set, allowing the
	# complete three-set transaction to be reversed before returning a failure.
	if ! ipset swap "$rulecompilebanset" Skynet-UserBans 2>/dev/null; then return 1; fi
	if ! ipset swap "$rulecompiletempset" Skynet-TemporaryBans 2>/dev/null; then
		ipset swap "$rulecompilebanset" Skynet-UserBans 2>/dev/null
		return 1
	fi
	if ! ipset swap "$rulecompilewhitelistset" Skynet-UserWhitelist 2>/dev/null; then
		ipset swap "$rulecompiletempset" Skynet-TemporaryBans 2>/dev/null
		ipset swap "$rulecompilebanset" Skynet-UserBans 2>/dev/null
		return 1
	fi
	return 0
}

Rollback_User_Rule_Sets() {
	ipset swap "$rulecompilewhitelistset" Skynet-UserWhitelist 2>/dev/null
	ipset swap "$rulecompiletempset" Skynet-TemporaryBans 2>/dev/null
	ipset swap "$rulecompilebanset" Skynet-UserBans 2>/dev/null
}

Migrate_Legacy_IPSet_Ownership() {
	# R2 owns user policy. Remove only entries recovered from the documented legacy
	# prefixes; unrelated and unclassified effective entries remain base state.
	legacysnapshot="$TMP_DIR/rules-legacy-sets.$$"
	legacyrestore="$TMP_DIR/rules-legacy-restore.$$"
	legacyblacklist="Skynet-Blacklist-Legacy"
	legacyranges="Skynet-BlockedRanges-Legacy"
	legacywhitelist="Skynet-Whitelist-Legacy"
	{ ipset save Skynet-Blacklist && ipset save Skynet-BlockedRanges && ipset save Skynet-Whitelist; } > "$legacysnapshot" 2>/dev/null || return 1
	if ! grep -qE 'comment "(ManualBan|ManualRBan|ManualWlist|ManualBanD|ManualWlistD|ASN|Imported): ' "$legacysnapshot"; then return 0; fi
	Destroy_IPSets "$legacyblacklist" "$legacyranges" "$legacywhitelist"
	if ! ipset -q create "$legacyblacklist" hash:ip hashsize 64 maxelem "$((65536 * 16))" comment \
		|| ! ipset -q create "$legacyranges" hash:net hashsize 64 maxelem "$((65536 * 6))" comment \
		|| ! ipset -q create "$legacywhitelist" hash:net hashsize 64 maxelem "$((65536 * 6))" comment; then
		Destroy_IPSets "$legacyblacklist" "$legacyranges" "$legacywhitelist"
		return 1
	fi
	awk -v blacklist="$legacyblacklist" -v ranges="$legacyranges" -v whitelist="$legacywhitelist" -v registry="$skynetrules" '
		BEGIN {
			while ((getline line < registry) > 0) {
				split(line, field, "\t")
				if (field[1] != "R2") continue
				owned[field[3] SUBSEP field[4] SUBSEP tolower(field[5])] = 1
				if (field[4] == "import") imported[field[3] SUBSEP "Imported: " substr(field[6], 2)] = 1
			}
			close(registry)
		}
		$1 == "add" {
			position = index($0, "comment \"")
			comment = position ? substr($0, position + 9) : ""
			sub(/\"$/, "", comment)
			target = $2 == "Skynet-Whitelist" ? "whitelist" : "ban"
			type = ""; value = $3
			if (index(comment, "ManualBan: ") == 1) type = "ip"
			else if (index(comment, "ManualRBan: ") == 1) type = "range"
			else if (index(comment, "ManualWlist: ") == 1) type = index(value, "/") && value !~ /\/32$/ ? "range" : "ip"
			else if (index(comment, "ManualBanD: ") == 1) { type = "domain"; value = substr(comment, 13) }
			else if (index(comment, "ManualWlistD: ") == 1) { type = "domain"; value = substr(comment, 15) }
			else if (index(comment, "ASN: ") == 1) { type = "asn"; value = substr(comment, 6); sub(/[[:space:]].*$/, "", value) }
			if (type == "ip") sub(/\/32$/, "", value)
			if ((target SUBSEP type SUBSEP tolower(value)) in owned || (target SUBSEP comment) in imported) next
			if ($2 == "Skynet-Blacklist") $2 = blacklist
			else if ($2 == "Skynet-BlockedRanges") $2 = ranges
			else if ($2 == "Skynet-Whitelist") $2 = whitelist
			else next
			print
		}
	' "$legacysnapshot" > "$legacyrestore" || return 1
	if [ -s "$legacyrestore" ] && ! ipset restore -! < "$legacyrestore" 2>/dev/null; then
		Destroy_IPSets "$legacyblacklist" "$legacyranges" "$legacywhitelist"
		return 1
	fi
	trap '' INT TERM
	if ! ipset swap "$legacyblacklist" Skynet-Blacklist 2>/dev/null; then
		Set_Cleanup_Traps; Destroy_IPSets "$legacyblacklist" "$legacyranges" "$legacywhitelist"; return 1
	fi
	if ! ipset swap "$legacyranges" Skynet-BlockedRanges 2>/dev/null; then
		ipset swap "$legacyblacklist" Skynet-Blacklist 2>/dev/null
		Set_Cleanup_Traps; Destroy_IPSets "$legacyblacklist" "$legacyranges" "$legacywhitelist"; return 1
	fi
	if ! ipset swap "$legacywhitelist" Skynet-Whitelist 2>/dev/null; then
		ipset swap "$legacyranges" Skynet-BlockedRanges 2>/dev/null
		ipset swap "$legacyblacklist" Skynet-Blacklist 2>/dev/null
		Set_Cleanup_Traps; Destroy_IPSets "$legacyblacklist" "$legacyranges" "$legacywhitelist"; return 1
	fi
	if ! Save_IPSets; then
		ipset swap "$legacywhitelist" Skynet-Whitelist 2>/dev/null
		ipset swap "$legacyranges" Skynet-BlockedRanges 2>/dev/null
		ipset swap "$legacyblacklist" Skynet-Blacklist 2>/dev/null
		Set_Cleanup_Traps
		Destroy_IPSets "$legacyblacklist" "$legacyranges" "$legacywhitelist"
		return 1
	fi
	Set_Cleanup_Traps
	Destroy_IPSets "$legacyblacklist" "$legacyranges" "$legacywhitelist"
	return 0
}

Apply_Rule_Registry_Candidate() {
	rulecandidate="$1"
	ruleregistrybackup=""
	ruleapplymode="${2:-normal}"
	case "$ruleapplymode" in normal|startup|remove) ;; *) return 2 ;; esac
	if ! Time_Is_Ready && [ "$ruleapplymode" = "normal" ]; then return 2; fi
	Validate_Rule_Registry "$rulecandidate" || return 1
	Ensure_User_IPSets || return 1
	rulevalidationactive="1"
	rulevalidatedfiles=""
	if ! Build_Rule_Reason_Index "$rulecandidate"; then
		unset "rulevalidationactive" "rulevalidatedfiles"
		return 1
	fi
	if Time_Is_Ready; then rulecompilenow="$(date +%s)"; else rulecompilenow="0"; fi
	if ! Prepare_User_Rule_Sets "$rulecandidate" "$rulecompilenow"; then
		unset "rulevalidationactive" "rulevalidatedfiles"
		rm -f "$ruleindexstage"
		return 1
	fi
	unset "rulevalidationactive" "rulevalidatedfiles"
	trap '' INT TERM
	if ! Publish_User_Rule_Sets; then
		Set_Cleanup_Traps
		Destroy_IPSets "$rulecompilebanset" "$rulecompiletempset" "$rulecompilewhitelistset"
		rm -f "$ruleindexstage"
		return 1
	fi
	if [ "$rulecandidate" != "$skynetrules" ]; then
		rulestagefile="$rulecandidate"
		if ! Publish_Staged_Rule_Registry; then
			Rollback_User_Rule_Sets
			Set_Cleanup_Traps
			Destroy_IPSets "$rulecompilebanset" "$rulecompiletempset" "$rulecompilewhitelistset"
			rm -f "$ruleindexstage"
			return 1
		fi
	fi
	ruleindextmp="${RULE_REASON_INDEX}.tmp.$$"
	if ! cp -f "$ruleindexstage" "$ruleindextmp" || ! chmod 600 "$ruleindextmp" \
		|| ! mv -f "$ruleindextmp" "$RULE_REASON_INDEX"; then
		Rollback_User_Rule_Sets
		if [ -f "$ruleregistrybackup" ]; then
			ruleregistryrestore="${skynetrules}.tmp.$$"
			if ! cp -f "$ruleregistrybackup" "$ruleregistryrestore" || ! chmod 600 "$ruleregistryrestore" \
				|| ! mv -f "$ruleregistryrestore" "$skynetrules"; then Log error -s "Failed To Restore Rule Registry"; fi
		fi
		Set_Cleanup_Traps
		Destroy_IPSets "$rulecompilebanset" "$rulecompiletempset" "$rulecompilewhitelistset"
		rm -f "$ruleindexstage" "$ruleindextmp"
		return 1
	fi
	Set_Cleanup_Traps
	Destroy_IPSets "$rulecompilebanset" "$rulecompiletempset" "$rulecompilewhitelistset"
	rm -f "$ruleindexstage"
	[ "${defer_rule_data_prune:-0}" = "1" ] || Prune_Unreferenced_Rule_Data
	Time_Is_Ready || Mark_Time_Dependent_State_Pending || return 1
	nocfg="1"
	return 0
}

Apply_Complete_Rule_Registry_Candidate() {
	# User and domain sets have separate atomic publishers. Retain the old registry
	# and immutable sidecars until both publishers accept the same logical policy.
	completecandidate="$1"
	completeapplymode="${2:-normal}"
	completeold="$TMP_DIR/rules-complete-old.$$"
	cp -f "$skynetrules" "$completeold" || return 1
	defer_rule_data_prune="1"
	if ! Apply_Rule_Registry_Candidate "$completecandidate" "$completeapplymode"; then
		defer_rule_data_prune="0"
		rm -f "$completeold"
		Prune_Unreferenced_Rule_Data
		return 1
	fi
	if Update_Domain_Rules "$skynetrules" cached; then
		defer_rule_data_prune="0"
		rm -f "$completeold"
		Prune_Unreferenced_Rule_Data
		return 0
	fi

	completerestore="${skynetrules}.tmp.$$"
	completerollback="0"
	if ! cp -f "$completeold" "$completerestore" \
		|| ! Apply_Rule_Registry_Candidate "$completerestore" remove; then
		Log error -s "Failed To Restore User Rule Registry"
		completerollback="1"
	elif ! Update_Domain_Rules "$skynetrules" cached; then
		Log error -s "Failed To Restore Domain Rule Policy"
		completerollback="1"
	fi
	defer_rule_data_prune="0"
	rm -f "$completeold" "$completerestore"
	Prune_Unreferenced_Rule_Data
	[ "$completerollback" = "0" ] || Log error -s "Rule Registry Rollback Requires Manual Inspection"
	return 1
}

Apply_Registered_Manual_Rules() {
	# Commit registry intent, live IPSet members and persistent IPSet state as one
	# transaction. Whitelist precedence is enforced by the master rule; an existing
	# ban is retained so removing the whitelist restores the original policy.
	registeredaction="$1"
	registeredtarget="$2"
	registeredtype="$3"
	registeredcomment="$4"
	registeredvalues="$5"
	registeredexpires="${6:-0}"
	case "$registeredtarget:$registeredtype" in
		ban:ip|ban:range|whitelist:ip|whitelist:range) ;;
		*) return 2 ;;
	esac
	for registeredvalue in $registeredvalues; do
		registerednormalized="$(Normalize_IPSet_Entry "$registeredtype" "$registeredvalue")" || return 2
		[ "$registerednormalized" = "$registeredvalue" ] || return 2
	done
	Apply_Registered_Address_Rules "$registeredaction" "$registeredtarget" "$registeredvalues" "$registeredcomment" "$registeredexpires"
}

Apply_Registered_Address_Rules() {
	registeredaction="$1"
	registeredtarget="$2"
	registeredvalues="$3"
	registeredcomment="$4"
	registeredexpires="${5:-0}"
	registeredrequest="$TMP_DIR/registered-addresses.$$"
	true > "$registeredrequest" || return 1
	for registeredvalue in $registeredvalues; do
		if printf '%s\n' "$registeredvalue" | Is_IP; then
			registeredtype="ip"
		elif printf '%s\n' "$registeredvalue" | Is_Range; then
			registeredtype="range"
		else
			return 2
		fi
		registerednormalized="$(Normalize_IPSet_Entry "$registeredtype" "$registeredvalue")" || return 2
		[ "$registerednormalized" = "$registeredvalue" ] || return 2
		printf '%s\t%s\n' "$registeredtype" "$registeredvalue" >> "$registeredrequest" || return 1
	done
	if [ -n "$6" ]; then
		# Optional WebUI comment map must match the complete validated address batch.
		registeredannotated="$TMP_DIR/registered-comments.$$"
		awk -F '\t' -v comments="$6" '
			BEGIN {
				while ((getline line < comments) > 0) {
					if (split(line, field, "\t") != 2 || field[1] in detail) {invalid=1; break}
					detail[field[1]]=field[2]; count++
				}
				close(comments)
			}
			{ if (!($2 in detail) || seen[$2]++) invalid=1; print $0 "\t-\t" detail[$2]; rows++ }
			END {exit invalid || rows != count ? 2 : 0}
		' "$registeredrequest" > "$registeredannotated" || return 2
		mv -f "$registeredannotated" "$registeredrequest" || return 1
	fi
	Stage_Rule_Registry_Request "$registeredaction" "$registeredtarget" "$registeredrequest" "$registeredcomment" "$registeredexpires" || return "$?"
	if [ "$registeredaction" = "add" ] && [ "$rulestagechanged" = "0" ]; then
		rm -f "$rulestagefile"
		return 0
	fi
	if [ "$registeredaction" = "remove" ]; then
		Apply_Rule_Registry_Candidate "$rulestagefile" remove
	else
		Apply_Rule_Registry_Candidate "$rulestagefile"
	fi
}

Apply_Registered_ASN_Rules() {
	registeredaction="$1"
	registeredtarget="$2"
	registeredvalues="$3"
	case "$registeredaction:$registeredtarget" in add:ban|add:whitelist|remove:ban|remove:whitelist) ;; *) return 2 ;; esac
	if [ "$registeredaction" = "remove" ]; then
		Stage_Rule_Registry remove "$registeredtarget" asn "$registeredvalues" "" || return "$?"
		Apply_Rule_Registry_Candidate "$rulestagefile" remove
		return "$?"
	fi
	Time_Is_Ready || return 1
	registeredrequest="$TMP_DIR/asn-rule-request.$$"
	true > "$registeredrequest" || return 1
	mkdir -p "$rulesdatadir" || return 1
	for registeredvalue in $registeredvalues; do
		asnraw="$TMP_DIR/asn-${registeredvalue}.$$"
		asnvalidated="${asnraw}.validated"
		asnpublic="${asnraw}.public"
		if ! Curl_Fetch -o "$asnraw" "https://asn.ipinfo.app/api/text/list/$registeredvalue" \
			|| ! Extract_IPList "$asnraw" "$asnvalidated" \
			|| ! Normalize_Public_IPList "$asnvalidated" "$asnpublic" \
			|| [ ! -s "$asnpublic" ]; then
			rm -f "$TMP_DIR"/asn-*.$$*
			Prune_Unreferenced_Rule_Data
			return 1
		fi
		asnhash="$(sha256sum "$asnpublic" 2>/dev/null | awk '{print $1}')"
		[ -n "$asnhash" ] || { Prune_Unreferenced_Rule_Data; return 1; }
		asndata="asn-${registeredtarget}-${registeredvalue}-${asnhash}.list"
		asntarget="$rulesdatadir/$asndata"
		asntmp="${asntarget}.tmp.$$"
		if ! cp -f "$asnpublic" "$asntmp" || ! chmod 600 "$asntmp" || ! mv -f "$asntmp" "$asntarget"; then
			rm -f "$asntmp" "$TMP_DIR"/asn-*.$$*
			Prune_Unreferenced_Rule_Data
			return 1
		fi
		printf 'asn\t%s\t%s\n' "$registeredvalue" "$asndata" >> "$registeredrequest" \
			|| { Prune_Unreferenced_Rule_Data; return 1; }
	done
	rm -f "$TMP_DIR"/asn-*.$$*
	Stage_Rule_Registry_Request add "$registeredtarget" "$registeredrequest" "" 0
	registeredstatus="$?"
	if [ "$registeredstatus" != "0" ]; then Prune_Unreferenced_Rule_Data; return "$registeredstatus"; fi
	if ! Apply_Rule_Registry_Candidate "$rulestagefile"; then Prune_Unreferenced_Rule_Data; return 1; fi
	for asnsidecar in "$rulesdatadir"/asn-*.list; do
		[ -f "$asnsidecar" ] || continue
		awk -F '\t' -v data="${asnsidecar##*/}" '$1 == "R2" && $10 == data {found=1} END {exit !found}' "$skynetrules" \
			|| rm -f "$asnsidecar"
	done
	return 0
}

Apply_Registered_Import() {
	importtarget="$1"
	importsource="$2"
	importcomment="$3"
	importrestore="$4"
	case "$importtarget" in ban|whitelist) ;; *) return 2 ;; esac
	Time_Is_Ready || return 1
	importentries="$TMP_DIR/import-entries.$$"
	awk '$1 == "add" {print $3}' "$importrestore" | awk 'NF && !seen[$0]++' > "$importentries" || return 1
	Validate_Rule_Data_File "$importentries" || return 1
	importhash="$(sha256sum "$importentries" 2>/dev/null | awk '{print $1}')"
	New_Rule_ID "$importtarget" import "$importsource" "$(date +%s)" || return 1
	importid="$ruleid"
	importdata="import-${importid}-${importhash}.list"
	importdatatarget="$rulesdatadir/$importdata"
	importdatatmp="${importdatatarget}.tmp.$$"
	mkdir -p "$rulesdatadir" || return 1
	if ! cp -f "$importentries" "$importdatatmp" || ! chmod 600 "$importdatatmp" \
		|| ! mv -f "$importdatatmp" "$importdatatarget"; then rm -f "$importdatatmp"; return 1; fi
	importrequest="$TMP_DIR/import-request.$$"
	printf 'import\t%s\t%s\n' "$importid" "$importdata" > "$importrequest" \
		|| { Prune_Unreferenced_Rule_Data; return 1; }
	Stage_Rule_Registry_Request add "$importtarget" "$importrequest" "$importcomment" 0
	importstatus="$?"
	if [ "$importstatus" != "0" ]; then Prune_Unreferenced_Rule_Data; return "$importstatus"; fi
	if Apply_Rule_Registry_Candidate "$rulestagefile"; then return 0; fi
	Prune_Unreferenced_Rule_Data
	return 1
}

############################
#- Installation Integrity -#
############################

Publish_Skynet_Hook() {
	# Replace Skynet-owned lines beside the live hook, then publish atomically.
	# Other addons retain their entries even when upgrading older Skynet hooks.
	hookpath="$1"
	hookline="$2"
	hooktmp="${hookpath}.tmp.$$"
	if {
		sed '\~# Skynet~d' "$hookpath"
		printf '%s\n' "$hookline"
	} > "$hooktmp" && chmod 755 "$hooktmp" && mv -f "$hooktmp" "$hookpath"; then
		unset "hookpath" "hookline" "hooktmp"
		return 0
	fi
	rm -f "$hooktmp"
	unset "hookpath" "hookline" "hooktmp"
	return 1
}

Check_Skynet_Hook() {
	grep -Fxq "$2" "$1" 2>/dev/null
}

Maintain_Script_Hooks() {
	# Ensure each script has a proper shebang.
	for name in "$@"; do
		path="/jffs/scripts/$name"
		if [ ! -f "$path" ]; then
			{ echo '#!/bin/sh'; echo; } > "$path" || return 1
		elif ! head -n1 "$path" | grep -q '^#!/bin/sh'; then
			sed -i '1s~^~#!/bin/sh\n~' "$path" || return 1
		fi
	done

	# Keep one canonical startup line for the current installation location.
	if [ -n "$skynetloc" ]; then
		firewallstarthook="sh /jffs/scripts/firewall start skynetloc=${skynetloc} # Skynet"
		if ! Check_Skynet_Hook /jffs/scripts/firewall-start "$firewallstarthook"; then
			Publish_Skynet_Hook /jffs/scripts/firewall-start "$firewallstarthook" || return 1
		fi
		unset "firewallstarthook"
	fi

	# Replace every older Skynet service-event entry with one dispatcher. Build
	# beside the live hook so an interrupted write leaves the original intact.
	serviceeventhook="case \"\$1:\$2\" in start:Skynet*) sh /jffs/scripts/firewall webui \"\$2\" ;; esac # Skynet"
	if ! Check_Skynet_Hook /jffs/scripts/service-event "$serviceeventhook"; then
		Publish_Skynet_Hook /jffs/scripts/service-event "$serviceeventhook" || return 1
	fi
	unset "serviceeventhook"

	Maintain_Swap_Hook || return 1

	# Archive correctly timed logs and persist changed base state during shutdown.
	servicesstophook='sh /jffs/scripts/firewall persist # Skynet'
	if ! Check_Skynet_Hook /jffs/scripts/services-stop "$servicesstophook"; then
		Publish_Skynet_Hook /jffs/scripts/services-stop "$servicesstophook" || return 1
	fi
	unset "servicesstophook"

	# Keep post-mount ready for the swap entry.
	if [ "$(wc -l < /jffs/scripts/post-mount)" -lt 2 ]; then
		echo >> /jffs/scripts/post-mount || return 1
	fi

	# Apply the required hook permissions.
	chmod 755 /jffs/scripts/firewall \
				/jffs/scripts/firewall-start \
				/jffs/scripts/services-stop \
				/jffs/scripts/service-event \
				/jffs/scripts/post-mount \
				/jffs/scripts/unmount || return 1
}

Clean_Legacy_WebUI_Files() {
	rm -rf "${skynetloc}/webui/stats" \
		"${skynetloc}/webui/hammerjs.js" \
		"${skynetloc}/webui/chartjs-plugin-zoom.js" \
		"${skynetloc}/webui/chart.js"
	rm -f "/www/user/skynet/hammerjs.js" \
		"/www/user/skynet/chartjs-plugin-zoom.js" \
		"/www/user/skynet/chart.js"
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

	# Known compromise accounts use i/p followed by exactly seven digits.
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
		securityrestore="$TMP_DIR/security-malware.$$"
		grep -hoE '([0-9]{1,3}\.){3}[0-9]{1,3}' "/jffs/chkupdate.sh" "/tmp/update" "/tmp/.update.log" "/jffs/runtime.log" "/jffs/scripts/openvpn-event" 2>/dev/null \
			| Filter_IP | awk '!seen[$0]++ {printf "add Skynet-Blacklist %s comment \"Malware: chkupdate.sh\"\n", $0}' > "$securityrestore"
		if [ -s "$securityrestore" ]; then
			ipset restore -! < "$securityrestore" || { rm -f "$securityrestore"; return 1; }
			Mark_Durable_State_Pending || { rm -f "$securityrestore"; return 1; }
		fi
		rm -f "$securityrestore"
	fi

	# Detect updater malware
	if [ -f "/jffs/updater" ] || [ -f "/jffs/p32" ] || [ -f "/tmp/pawns-cli" ] || [ -f "/tmp/updateservice" ] || nvram get "jffs2_exec" | grep -qF "/jffs/updater" || nvram get "script_usbmount" | grep -qF "/jffs/updater" || nvram get "script_usbumount" | grep -qF "/jffs/updater" || nvram get "vpn_server_custom" | grep -qF "/jffs/updater" || nvram get "vpn_server1_custom" | grep -qF "/jffs/updater" || cru l | grep -qF "/jffs/updater"; then
		Log error -s "Warning! Router Malware Detected (/jffs/updater) - Investigate Immediately!"
		Log error -s "Caching Potential Updater Malware: ${skynetloc}/malwareupdater.tar.gz"
		nvram savefile "$TMP_DIR/nvramoutput.txt"
		tar -czf "${skynetloc}/malwareupdater.tar.gz" "/jffs/updater" "/jffs/p32" "/tmp/pawns-cli" "/tmp/updateservice" "$TMP_DIR/nvramoutput.txt" "/root/.profile" >/dev/null 2>&1
		rm -rf "/jffs/updater" "/jffs/p32" "/tmp/pawns-cli" "/tmp/updateservice" "$TMP_DIR/nvramoutput.txt"
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

Clean_Stale_Temp() {
	# A PID suffix identifies the owner. Only remove work belonging to a process
	# that no longer exists, so concurrent Skynet commands retain their files.
	for tempdir in /tmp/skynet/tmp.*; do
		[ -d "$tempdir" ] || continue
		temppid="${tempdir##*.}"
		[ "$temppid" = "$$" ] && continue
		[ -d "/proc/$temppid" ] || rm -rf "$tempdir"
	done
	if [ -n "$skynetloc" ]; then
		for tempfile in "${skynetloc}/lists/"*.tmp.* "${skynetloc}/lists/".*.tmp.* "${skynetloc}/lists/countries/.manifest.tmp."* "${skynetloc}/lists/rules/"*.tmp.* "${skynetloc}/lists/rules/".*.tmp.* "${skynetloc}/skynet.cfg.tmp."* "${skynetloc}/skynet.ipset.tmp."* "${skynetloc}/skynet.rules.tmp."* "${skynetloc}/events.log.tmp."* "${skynetloc}/events.log.compact."* "${skynetloc}/events.log.trim."* "${skynetloc}/webui/settings.js.tmp."* "${skynetloc}/webui/skynet.asp.tmp."* "${skynetloc}/webui/skynet.asp.old."* "${skynetloc}/webui/stats.js.tmp."* "$0.tmp."* "$0.old."*; do
			[ -f "$tempfile" ] || continue
			temppid="${tempfile##*.}"
			[ "$temppid" = "$$" ] && continue
			[ -d "/proc/$temppid" ] || rm -f "$tempfile"
		done
	fi
	for tempfile in /jffs/scripts/firewall-start.tmp.* /jffs/scripts/services-stop.tmp.* /jffs/scripts/service-event.tmp.* /jffs/addons/shared-whitelists/shared-Skynet-whitelist.tmp.*; do
		[ -f "$tempfile" ] || continue
		temppid="${tempfile##*.}"
		[ "$temppid" = "$$" ] && continue
		[ -d "/proc/$temppid" ] || rm -f "$tempfile"
	done
	legacy_pid="$(cut -d'|' -f2 "$LOCK_FILE" 2>/dev/null)"
	if [ -z "$legacy_pid" ] || [ "$legacy_pid" = "$$" ] || [ ! -d "/proc/$legacy_pid" ]; then
		[ -n "$skynetloc" ] && rm -rf "${skynetloc}/webui/stats"
		rm -rf /tmp/skynet/lists
		rm -f /tmp/skynet/asn.* /tmp/skynet/cdn-whitelist.* /tmp/skynet/country.* \
			/tmp/skynet/filter.list.* /tmp/skynet/iplist-* /tmp/skynet/malware.* \
			/tmp/skynet/mbans.list /tmp/skynet/mwhitelist.list /tmp/skynet/ns.*.tmp \
			/tmp/skynet/shared-Skynet-whitelist.* /tmp/skynet/skynet.manifest \
			/tmp/skynet/skynetstats.txt /tmp/skynet/update.*
	fi
}

############################
#- Firewall And IPSet Core -#
############################

Ensure_IPSet() {
	ipset -q -! create "$@" && return
	Log error -s "Failed To Create IPSet ($1)"
	return 1
}

Destroy_IPSets() {
	destroyipsetstatus="0"
	for destroyipset in "$@"; do
		if ! ipset -q destroy "$destroyipset" 2>/dev/null; then
			# Missing sets need no cleanup. A referenced or otherwise undeletable
			# live set must not be reported as successfully unloaded.
			destroyipsetnames="$(ipset -n list 2>/dev/null)" || { destroyipsetstatus="1"; continue; }
			if printf '%s\n' "$destroyipsetnames" | grep -qxF "$destroyipset"; then destroyipsetstatus="1"; fi
		fi
	done
	unset "destroyipset" "destroyipsetnames"
	return "$destroyipsetstatus"
}

Update_IPSet() {
	# The nofilter path delegates entry validation directly to IPSet.
	ipsetaction="$1"
	ipsetname="$2"
	ipsetentry="$3"
	ipsetcomment="$4"

	case "$ipsetaction" in
		add|del) ;;
		*) Log error -s "Invalid IPSet Action ($ipsetaction)"; return 1 ;;
	esac
	case "$ipsetname" in
		Skynet-Whitelist|Skynet-WhitelistDomains|Skynet-UserWhitelist|Skynet-Blacklist|Skynet-BlacklistDomains|Skynet-BlockedRanges|Skynet-UserBans|Skynet-TemporaryBans|Skynet-IOT|Skynet-Master|Skynet-MasterWL) ;;
		*) Log error -s "Invalid IPSet ($ipsetname)"; return 1 ;;
	esac
	if [ -z "$ipsetentry" ]; then
		Log error -s "IPSet Entry Can't Be Empty"
		return 1
	fi
	if ! Validate_IPSet_Comment "$ipsetcomment" 255; then
		Log error -s "IPSet Comment Contains Invalid Characters Or Is Too Long"
		return 1
	fi

	if [ "$ipsetaction" = "add" ] && [ -n "$ipsetcomment" ]; then
		ipset -q -! add "$ipsetname" "$ipsetentry" comment "$ipsetcomment" && return
	elif ipset -q -! "$ipsetaction" "$ipsetname" "$ipsetentry"; then
		return
	fi
	Log error -s "Failed To $ipsetaction $ipsetentry In $ipsetname"
	return 1
}

IP_Is_Whitelisted() {
	ipset -q test Skynet-Whitelist "$1" 2>/dev/null \
		|| ipset -q test Skynet-WhitelistDomains "$1" 2>/dev/null \
		|| ipset -q test Skynet-UserWhitelist "$1" 2>/dev/null
}

IP_Is_Banned() {
	for bancheckset in Skynet-Blacklist Skynet-BlockedRanges Skynet-BlacklistDomains \
		Skynet-UserBans Skynet-TemporaryBans; do
		ipset -q test "$bancheckset" "$1" 2>/dev/null && return 0
	done
	return 1
}

Ban_Value_Is_Covered() {
	# IPSet tests are sufficient for one address. A removed CIDR is reported as
	# covered only when another active range contains the complete network.
	case "$1" in
		ip) IP_Is_Banned "$2" ;;
		range)
			{ ipset save Skynet-BlockedRanges; ipset save Skynet-UserBans; ipset save Skynet-TemporaryBans; } 2>/dev/null | awk -v requested="$2" '
				function ip_number(value, octets) {
					split(value, octets, ".")
					return octets[1] * 16777216 + octets[2] * 65536 + octets[3] * 256 + octets[4]
				}
				function divisor(prefix, value, position) {
					value = 1
					for (position = prefix; position < 32; position++) value *= 2
					return value
				}
				BEGIN {
					split(requested, wanted, "/")
					wanted_prefix = wanted[2] + 0
					wanted_ip = ip_number(wanted[1])
				}
				$1 == "add" {
					split($3, candidate, "/")
					candidate_prefix = candidate[2] == "" ? 32 : candidate[2] + 0
					if (candidate_prefix <= wanted_prefix) {
						network_size = divisor(candidate_prefix)
						if (int(wanted_ip / network_size) == int(ip_number(candidate[1]) / network_size)) found = 1
					}
				}
				END {exit !found}
			'
		;;
		*) return 1 ;;
	esac
}

Get_IPSet_Entries() {
	awk -v setname="$1" -v comment="$2" '
		$1 == "add" && $2 == setname && $4 == "comment" {
			entrycomment = $0
			sub(/^[^"]*"/, "", entrycomment)
			sub(/"$/, "", entrycomment)
			if (index(entrycomment, comment)) print
		}
	' "$skynetipset"
}

Remove_IPSet_Entries() {
	ipsetremoveentries="$TMP_DIR/ipset-remove-entries.$$"
	ipsetremovefile="$TMP_DIR/ipset-remove.$$"
	ipsetremovesnapshot="$TMP_DIR/ipset-remove-snapshot.$$"
	if ! ipset save "$1" > "$ipsetremovesnapshot" 2>/dev/null \
		|| ! Get_IPSet_Entries "$1" "$2" > "$ipsetremoveentries" \
		|| ! awk '{ printf "del %s %s\n", $2, $3 }' "$ipsetremoveentries" > "$ipsetremovefile"; then
		rm -f "$ipsetremoveentries" "$ipsetremovefile" "$ipsetremovesnapshot"
		return 1
	fi
	if [ ! -s "$ipsetremovefile" ] || Apply_IPSet_File "$ipsetremovefile" "$ipsetremovesnapshot"; then
		rm -f "$ipsetremoveentries" "$ipsetremovefile" "$ipsetremovesnapshot"
		return 0
	fi
	rm -f "$ipsetremoveentries" "$ipsetremovefile" "$ipsetremovesnapshot"
	Log error -s "Failed To Remove $2 Entries From $1"
	return 1
}

Prepare_Automatic_Ban_Removal() {
	# Automatic address and range sets are one persistence unit. Build one strict
	# transaction so a failed member cannot leave only half the policy changed.
	automaticbanmode="$1"
	automaticbanmatch="$2"
	automaticbansnapshot="$TMP_DIR/automatic-bans-old.$$"
	automaticbanremove="$TMP_DIR/automatic-bans-remove.$$"
	{ ipset save Skynet-Blacklist && ipset save Skynet-BlockedRanges; } \
		> "$automaticbansnapshot" 2>/dev/null || return 1
	awk -v mode="$automaticbanmode" -v expected="$automaticbanmatch" '
		$1 == "add" {
			if (mode == "all") {print "del " $2 " " $3; next}
			position = index($0, "comment \"")
			if (!position) next
			comment = substr($0, position + 9)
			sub(/"$/, "", comment)
			if (index(comment, expected)) print "del " $2 " " $3
		}
	' "$automaticbansnapshot" > "$automaticbanremove" || return 1
}

Restore_Automatic_Bans() {
	automaticbanrestorestatus="0"
	Restore_IPSet_Snapshot Skynet-Blacklist "$automaticbansnapshot" || automaticbanrestorestatus="1"
	Restore_IPSet_Snapshot Skynet-BlockedRanges "$automaticbansnapshot" || automaticbanrestorestatus="1"
	return "$automaticbanrestorestatus"
}

Remove_Automatic_Bans() {
	Prepare_Automatic_Ban_Removal "$1" "$2" || return 1
	if [ -s "$automaticbanremove" ] && ! Apply_IPSet_File "$automaticbanremove" "$automaticbansnapshot"; then
		rm -f "$automaticbansnapshot" "$automaticbanremove"
		return 1
	fi
	if Save_IPSets; then
		rm -f "$automaticbansnapshot" "$automaticbanremove"
		return 0
	fi
	Restore_Automatic_Bans || Log error -s "Failed To Restore Automatic Bans"
	rm -f "$automaticbansnapshot" "$automaticbanremove"
	return 1
}

Clear_All_Bans() {
	# Base sources and logical owners commit together. The old registry and both
	# automatic sets remain available until the reduced snapshot is durable.
	allbanregistryold="$TMP_DIR/rules-all-old.$$"
	cp -f "$skynetrules" "$allbanregistryold" || return 1
	Stage_Rule_Registry_Clear ban
	allbanstatus="$?"
	if [ "$allbanstatus" != "0" ]; then rm -f "$allbanregistryold"; return "$allbanstatus"; fi
	allbanregistrycandidate="$rulestagefile"
	Prepare_Automatic_Ban_Removal all "" \
		|| { rm -f "$allbanregistryold" "$allbanregistrycandidate"; return 1; }
	if [ -s "$automaticbanremove" ] && ! Apply_IPSet_File "$automaticbanremove" "$automaticbansnapshot"; then
		rm -f "$allbanregistryold" "$allbanregistrycandidate" "$automaticbansnapshot" "$automaticbanremove"
		return 1
	fi
	if Apply_Complete_Rule_Registry_Candidate "$allbanregistrycandidate" remove; then
		if Save_IPSets; then
			rm -f "$allbanregistryold" "$automaticbansnapshot" "$automaticbanremove"
			return 0
		fi
	fi
	Restore_Automatic_Bans || Log error -s "Failed To Restore Automatic Bans"
	allbanregistryrestore="${skynetrules}.tmp.$$"
	if cp -f "$allbanregistryold" "$allbanregistryrestore"; then
		Apply_Complete_Rule_Registry_Candidate "$allbanregistryrestore" remove \
			|| Log error -s "Failed To Restore User Ban Registry"
	fi
	Save_IPSets || Log error -s "Failed To Persist Restored Ban Data"
	rm -f "$allbanregistryold" "$allbanregistrycandidate" "$allbanregistryrestore" \
		"$automaticbansnapshot" "$automaticbanremove"
	return 1
}

Delete_All_IPTables_Rules() {
	# Reconciliation removes every exact Skynet duplicate left by repeated Merlin
	# firewall events. The command fails normally when no matching rule remains.
	iptablescommand="$1"
	shift
	while "$iptablescommand" "$@" 2>/dev/null; do :; done
	unset "iptablescommand"
	return 0
}

Delete_Skynet_Chain_Rules() {
	# Delete matching rules by descending line number so stale interface, port or
	# protocol variants cannot survive a configuration change.
	deleteruletable="$1"
	deleterulechain="$2"
	deleterulesignature="$3"
	deleteruleinventory="$TMP_DIR/iptables-chain.$$"
	deleterulematches="$TMP_DIR/iptables-matches.$$"
	deleterulefile="$TMP_DIR/iptables-delete.$$"
	if ! iptables -t "$deleteruletable" -vnL "$deleterulechain" --line-numbers > "$deleteruleinventory" 2>/dev/null \
		|| ! awk -v signature="$deleterulesignature" 'index($0, signature) {print $1}' \
			"$deleteruleinventory" > "$deleterulematches" \
		|| ! sort -rn "$deleterulematches" > "$deleterulefile"; then
		rm -f "$deleteruleinventory" "$deleterulematches" "$deleterulefile"
		return 1
	fi
	deleterulestatus="0"
	while IFS= read -r deleterulenumber; do
		case "$deleterulenumber" in ""|*[!0-9]*) deleterulestatus="1"; continue ;; esac
		iptables -t "$deleteruletable" -D "$deleterulechain" "$deleterulenumber" 2>/dev/null \
			|| deleterulestatus="1"
	done < "$deleterulefile"
	rm -f "$deleteruleinventory" "$deleterulematches" "$deleterulefile"
	return "$deleterulestatus"
}

Purge_Skynet_IPTables_Rules() {
	purgerulestatus="0"
	Delete_Skynet_Chain_Rules raw PREROUTING Skynet-Master || purgerulestatus="1"
	Delete_Skynet_Chain_Rules raw OUTPUT Skynet-Master || purgerulestatus="1"
	Delete_Skynet_Chain_Rules filter FORWARD Skynet-IOT || purgerulestatus="1"
	Delete_Skynet_Chain_Rules filter logdrop '[BLOCKED - INVALID]' || purgerulestatus="1"
	return "$purgerulestatus"
}

Unload_IPTables() {
	Delete_All_IPTables_Rules iptables -t raw -D PREROUTING -i wgs+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP
	Delete_All_IPTables_Rules iptables -t raw -D PREROUTING -i tun2+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP
	Delete_All_IPTables_Rules iptables -t raw -D PREROUTING -i "$iface" -m set ! --match-set Skynet-MasterWL src -m set --match-set Skynet-Master src -j DROP
	Delete_All_IPTables_Rules iptables -t raw -D PREROUTING -i br+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP
	Delete_All_IPTables_Rules iptables -t raw -D OUTPUT -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP
	return 0
}

Load_IPTables() {
	loadrulestatus="0"
	if [ "$(nvram get wgs_enable)" = "1" ]; then
		iptables -t raw -I PREROUTING -i wgs+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null || loadrulestatus="1"
	fi
	if [ "$(nvram get vpn_server1_state)" != "0" ] || [ "$(nvram get vpn_server2_state)" != "0" ]; then
		iptables -t raw -I PREROUTING -i tun2+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null || loadrulestatus="1"
	fi
	if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then
		iptables -t raw -I PREROUTING -i "$iface" -m set ! --match-set Skynet-MasterWL src -m set --match-set Skynet-Master src -j DROP 2>/dev/null || loadrulestatus="1"
	fi
	if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
		iptables -t raw -I PREROUTING -i br+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null || loadrulestatus="1"
		iptables -t raw -I OUTPUT -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null || loadrulestatus="1"
	fi
	if [ "$loadrulestatus" = "0" ]; then return 0; fi
	Unload_IPTables
	return 1
}

Unload_LogIPTables() {
	Delete_All_IPTables_Rules iptables -t raw -D PREROUTING -i wgs+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options
	Delete_All_IPTables_Rules iptables -t raw -D PREROUTING -i tun2+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options
	Delete_All_IPTables_Rules iptables -t raw -D PREROUTING -i "$iface" -m set ! --match-set Skynet-MasterWL src -m set --match-set Skynet-Master src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options
	Delete_All_IPTables_Rules iptables -t raw -D PREROUTING -i br+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options
	Delete_All_IPTables_Rules iptables -t raw -D OUTPUT -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options
	Delete_All_IPTables_Rules iptables -D logdrop -m state --state NEW -j LOG --log-prefix "[BLOCKED - INVALID] " --log-tcp-sequence --log-tcp-options --log-ip-options
	Delete_All_IPTables_Rules iptables -D logdrop -m state --state INVALID -j LOG --log-prefix "[BLOCKED - INVALID] " --log-tcp-sequence --log-tcp-options --log-ip-options
	Delete_All_IPTables_Rules iptables -D FORWARD -i br+ -m set --match-set Skynet-IOT src -j LOG --log-prefix "[BLOCKED - IOT] " --log-tcp-sequence --log-tcp-options --log-ip-options
	Delete_All_IPTables_Rules iptables -D FORWARD -i br+ ! -o br+ -m set --match-set Skynet-IOT src -j LOG --log-prefix "[BLOCKED - IOT] " --log-tcp-sequence --log-tcp-options --log-ip-options
	return 0
}

Load_LogIPTables() {
	loadlogstatus="0"
	Time_Is_Ready || return 0
	if Is_Enabled "$logmode" && Time_Is_Ready; then
		if [ "$(nvram get wgs_enable)" = "1" ]; then
			pos1="$(iptables --line -vnL PREROUTING -t raw | grep -F "Skynet-Master dst" | grep -F "DROP" | grep -F "wgs" | awk '{print $1}')"
			iptables -t raw -I PREROUTING "$pos1" -i wgs+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null || loadlogstatus="1"
		fi
		if [ "$(nvram get vpn_server1_state)" != "0" ] || [ "$(nvram get vpn_server2_state)" != "0" ]; then
			pos2="$(iptables --line -vnL PREROUTING -t raw | grep -F "Skynet-Master dst" | grep -F "DROP" | grep -F "tun" | awk '{print $1}')"
			iptables -t raw -I PREROUTING "$pos2" -i tun2+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null || loadlogstatus="1"
		fi
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then
			pos3="$(iptables --line -nL PREROUTING -t raw | grep -F "Skynet-Master src" | grep -F "DROP" | awk '{print $1}')"
			iptables -t raw -I PREROUTING "$pos3" -i "$iface" -m set ! --match-set Skynet-MasterWL src -m set --match-set Skynet-Master src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null || loadlogstatus="1"
		fi
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
			pos4="$(iptables --line -vnL PREROUTING -t raw | grep -F "Skynet-Master dst" | grep -F "DROP" | grep -vF "tun" | grep -vF "wgs" | awk '{print $1}')"
			iptables -t raw -I PREROUTING "$pos4" -i br+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null || loadlogstatus="1"
			pos5="$(iptables --line -nL OUTPUT -t raw | grep -F "Skynet-Master dst" | grep -F "DROP" | awk '{print $1}')"
			iptables -t raw -I OUTPUT "$pos5" -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null || loadlogstatus="1"
		fi
		if { [ "$(nvram get fw_log_x)" = "drop" ] || [ "$(nvram get fw_log_x)" = "both" ]; } && Is_Enabled "$loginvalid"; then
			# Match the target column, not Merlin's preceding LOG prefix "DROP".
			pos6="$(iptables --line -nL logdrop | awk '$2 == "DROP" {print $1; exit}')"
			iptables -I logdrop "$pos6" -m state --state INVALID -j LOG --log-prefix "[BLOCKED - INVALID] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null || loadlogstatus="1"
		fi
		if Is_Enabled "$iotblocked" && Is_Enabled "$iotlogging"; then
			pos7="$(iptables --line -nL FORWARD | grep -F "Skynet-IOT" | grep -F "DROP" | awk '{print $1}')"
			iptables -I FORWARD "$pos7" -i br+ ! -o br+ -m set --match-set Skynet-IOT src -j LOG --log-prefix "[BLOCKED - IOT] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null || loadlogstatus="1"
		fi
	fi
	if [ "$loadlogstatus" = "0" ]; then return 0; fi
	Unload_LogIPTables
	return 1
}

Update_IOT_Rule() {
	# Adds are idempotent. Deletes remove every duplicate left by older releases
	# or interrupted firewall reloads.
	iotruleaction="$1"
	shift
	case "$iotruleaction" in
		add)
			iptables -C "$@" 2>/dev/null || iptables -I "$@" 2>/dev/null
		;;
		del)
			while iptables -C "$@" 2>/dev/null; do
				iptables -D "$@" 2>/dev/null || return 1
			done
		;;
		*) return 1 ;;
	esac
}

Apply_IOT_Rule() {
	# Missing rules are expected while unloading, but are recorded so callers
	# can decide whether the previous layout was fully removed.
	Update_IOT_Rule "$@" && return 0
	if [ "$iotrulesaction" = "del" ]; then
		iotrulesstatus="1"
		return 0
	fi
	return 1
}

Apply_IOT_Rules() {
	# iptables -I reverses insertion order: install DROP first, then exceptions,
	# leaving VPN and allowed-port rules above the final DROP rule. LAN bridge
	# traffic continues through Merlin's own access controls without an ACCEPT.
	iotrulesaction="$1"
	iotrulesstatus="0"
	case "$iotports" in
		"") iotportmode="default"; iotportcsv="123" ;;
		none) iotportmode="none"; iotportcsv="" ;;
		*) iotportmode="custom"; iotportcsv="$(List_To_CSV "$iotports")" ;;
	esac

	Apply_IOT_Rule "$iotrulesaction" FORWARD -i br+ ! -o br+ -m set --match-set Skynet-IOT src -j DROP || return 1
	if [ "$iotrulesaction" = "del" ] || [ "$(nvram get vpn_server1_state)" != "0" ] || [ "$(nvram get vpn_server2_state)" != "0" ]; then
		Apply_IOT_Rule "$iotrulesaction" FORWARD -i br+ -m set --match-set Skynet-IOT src -o tun2+ -j ACCEPT || return 1
	fi
	if [ "$iotrulesaction" = "del" ] || [ "$(nvram get wgs_enable)" = "1" ]; then
		Apply_IOT_Rule "$iotrulesaction" FORWARD -i br+ -m set --match-set Skynet-IOT src -o wgs+ -j ACCEPT || return 1
	fi
	if [ "$iotportmode" = "custom" ]; then
		if [ "$iotproto" = "all" ] || [ "$iotproto" = "udp" ]; then
			Apply_IOT_Rule "$iotrulesaction" FORWARD -i br+ -m set --match-set Skynet-IOT src -o "$iface" -p udp -m udp -m multiport --dports "$iotportcsv" -j ACCEPT || return 1
		fi
		if [ "$iotproto" = "all" ] || [ "$iotproto" = "tcp" ]; then
			Apply_IOT_Rule "$iotrulesaction" FORWARD -i br+ -m set --match-set Skynet-IOT src -o "$iface" -p tcp -m tcp -m multiport --dports "$iotportcsv" -j ACCEPT || return 1
		fi
	elif [ "$iotportmode" = "default" ]; then
		# UDP/123 keeps isolated device clocks synchronized. Correct time is needed
		# for certificates, secure connections and scheduled device activity.
		Apply_IOT_Rule "$iotrulesaction" FORWARD -i br+ -m set --match-set Skynet-IOT src -o "$iface" -p udp -m udp --dport 123 -j ACCEPT || return 1
	fi
	return "$iotrulesstatus"
}

Unload_IOT_Rules() {
	Delete_Skynet_Chain_Rules filter FORWARD Skynet-IOT
}

Load_IOT_Rules() {
	Is_Enabled "$iotblocked" || return 0
	if Apply_IOT_Rules add; then
		return 0
	fi
	Apply_IOT_Rules del 2>/dev/null
	return 1
}

Unload_Skynet_Firewall_Rules() {
	# Lifecycle commands hold the state lock before calling this helper. The short
	# firewall lock prevents a simultaneous Merlin event from rebuilding the rules.
	Acquire_Firewall_Lock || return 1
	unloadrulesstatus="0"
	Unload_LogIPTables || unloadrulesstatus="1"
	Unload_IOT_Rules || unloadrulesstatus="1"
	Unload_IPTables || unloadrulesstatus="1"
	Release_Firewall_Lock
	return "$unloadrulesstatus"
}

Revalidate_IOT_Connections() {
	# Retire only selected devices' source-NAT connections after a
	# policy change. This evicts established accelerated WAN sessions while local
	# connections remain intact. Allowed WAN services reconnect normally.
	Is_Enabled "$iotblocked" || return 0
	iotflowentries="${1:-}"
	if [ "$#" -eq 0 ]; then
		iotflowsnapshot="$TMP_DIR/iot-flows.$$"
		if ! ipset save Skynet-IOT > "$iotflowsnapshot" 2>/dev/null; then rm -f "$iotflowsnapshot"; return 1; fi
		iotflowentries="$(awk '$1 == "add" {print $3}' "$iotflowsnapshot")" \
			|| { rm -f "$iotflowsnapshot"; return 1; }
		rm -f "$iotflowsnapshot"
	fi
	[ -n "$iotflowentries" ] || return 0
	for iotflowentry in $iotflowentries; do
		printf '%s\n' "$iotflowentry" | Is_IPRange || return 1
	done
	if ! type conntrack >/dev/null 2>&1; then
		Log error -s "Unable To Revalidate IoT WAN Connections - Native Conntrack Unavailable"
		return 1
	fi
	for iotflowentry in $iotflowentries; do
		if iotflowresult="$(LC_ALL=C conntrack -D -f ipv4 -s "$iotflowentry" --src-nat 2>&1 >/dev/null)"; then continue
		else iotflowstatus="$?"; fi
		# conntrack returns 1 when no matching sessions exist. Accept only its
		# complete single-line zero-entry summary, never a separate error message.
		case "$iotflowresult" in
			*'
'*) ;;
			'conntrack v'*' (conntrack-tools): 0 flow entries have been deleted.')
				[ "$iotflowstatus" = "1" ] && continue
			;;
		esac
		Log error -s "Failed To Revalidate IoT WAN Connections ($iotflowentry)"
		return 1
	done
	return 0
}

Set_IOT_Blocking() {
	# Rule replacement is transactional. Restore the saved switch and rule set
	# if the new layout cannot be installed.
	[ "$1" = "$iotblocked" ] && return 0
	iotoldblocked="$iotblocked"
	Purge_Logs
	Acquire_Firewall_Lock || return 1
	Unload_LogIPTables
	if ! Unload_IOT_Rules; then
		Load_IOT_Rules || Log error -s "Failed To Restore IoT Firewall Rules"
		Load_LogIPTables || Log error -s "Failed To Restore IoT Logging Rules"
		Release_Firewall_Lock
		return 1
	fi
	iotblocked="$1"
	if ! Load_IOT_Rules; then
		Unload_IOT_Rules
		iotblocked="$iotoldblocked"
		Load_IOT_Rules || Log error -s "Failed To Restore IoT Firewall Rules"
		Load_LogIPTables || Log error -s "Failed To Restore IoT Logging Rules"
		Log error -s "Failed To Update IoT Firewall Rules - Previous Rules Restored"
		Release_Firewall_Lock
		return 1
	fi
	if ! Load_LogIPTables || ! Revalidate_IOT_Connections; then
		Unload_IOT_Rules 2>/dev/null
		iotblocked="$iotoldblocked"
		Load_IOT_Rules || Log error -s "Failed To Restore IoT Firewall Rules"
		Load_LogIPTables || Log error -s "Failed To Restore IoT Logging Rules"
		Log error -s "Failed To Update IoT Enforcement - Previous Rules Restored"
		Release_Firewall_Lock
		return 1
	fi
	Release_Firewall_Lock
	return 0
}

Set_IOT_Rule_Options() {
	# Ports are stored as a space-separated list and converted to the comma form
	# required by iptables multiport only while constructing rules.
	iotnewports="$1"
	iotnewproto="$2"
	[ "$iotnewports:$iotnewproto" = "$iotports:$iotproto" ] && return 0
	iotoldports="$iotports"
	iotoldproto="$iotproto"
	Purge_Logs
	Acquire_Firewall_Lock || return 1
	Unload_LogIPTables
	if ! Unload_IOT_Rules; then
		Load_IOT_Rules || Log error -s "Failed To Restore IoT Firewall Rules"
		Load_LogIPTables || Log error -s "Failed To Restore IoT Logging Rules"
		Release_Firewall_Lock
		return 1
	fi
	iotports="$iotnewports"
	iotproto="$iotnewproto"
	if ! Load_IOT_Rules; then
		Unload_IOT_Rules
		iotports="$iotoldports"
		iotproto="$iotoldproto"
		Load_IOT_Rules || Log error -s "Failed To Restore IoT Firewall Rules"
		Load_LogIPTables || Log error -s "Failed To Restore IoT Logging Rules"
		Log error -s "Failed To Update IoT Rule Options - Previous Rules Restored"
		Release_Firewall_Lock
		return 1
	fi
	if ! Load_LogIPTables || ! Revalidate_IOT_Connections; then
		Unload_IOT_Rules 2>/dev/null
		iotports="$iotoldports"
		iotproto="$iotoldproto"
		Load_IOT_Rules || Log error -s "Failed To Restore IoT Firewall Rules"
		Load_LogIPTables || Log error -s "Failed To Restore IoT Logging Rules"
		Log error -s "Failed To Update IoT Enforcement - Previous Rules Restored"
		Release_Firewall_Lock
		return 1
	fi
	Release_Firewall_Lock
	return 0
}

Check_IPSets() {
	# Failure numbers are stable diagnostic identifiers shared with debug info.
	fail="$(ipset -n list 2>/dev/null | awk '
		$0 == "Skynet-MasterWL" { found1 = 1 }
		$0 == "Skynet-Blacklist" { found2 = 1 }
		$0 == "Skynet-BlockedRanges" { found3 = 1 }
		$0 == "Skynet-Master" { found4 = 1 }
		$0 == "Skynet-IOT" { found5 = 1 }
		$0 == "Skynet-Whitelist" { found6 = 1 }
		$0 == "Skynet-WhitelistDomains" { found7 = 1 }
		$0 == "Skynet-BlacklistDomains" { found8 = 1 }
		$0 == "Skynet-UserBans" { found9 = 1 }
		$0 == "Skynet-TemporaryBans" { found10 = 1 }
		$0 == "Skynet-UserWhitelist" { found11 = 1 }
		END {
			if (!found1) printf "#1 "
			if (!found2) printf "#2 "
			if (!found3) printf "#3 "
			if (!found4) printf "#4 "
			if (!found5) printf "#5 "
			if (!found6) printf "#6 "
			if (!found7) printf "#7 "
			if (!found8) printf "#8 "
			if (!found9) printf "#9 "
			if (!found10) printf "#10 "
			if (!found11) printf "#11 "
		}
	')"
	[ -z "$fail" ] || return 1
	for checkset in Skynet-Blacklist Skynet-BlockedRanges Skynet-Whitelist Skynet-IOT \
		Skynet-BlacklistDomains Skynet-WhitelistDomains Skynet-UserBans Skynet-UserWhitelist \
		Skynet-TemporaryBans Skynet-Master Skynet-MasterWL; do
		Expected_IPSet_Schema_Is_Valid "$checkset" || { fail="#schema:$checkset "; return 1; }
	done
	for checkset in Skynet-Blacklist Skynet-BlockedRanges Skynet-BlacklistDomains Skynet-UserBans Skynet-TemporaryBans; do
		ipset -q test Skynet-Master "$checkset" || { fail="#master:$checkset "; return 1; }
	done
	for checkset in Skynet-Whitelist Skynet-WhitelistDomains Skynet-UserWhitelist; do
		ipset -q test Skynet-MasterWL "$checkset" || { fail="#master:$checkset "; return 1; }
	done
	return 0
}

Check_Expected_IPTables_Rule() {
	# Stage exact serialized rules for one comparison against both table dumps.
	# LOG extensions are emitted in this order by Merlin's iptables-save.
	case "$4" in
		*' -j LOG '*) set -- "$1" "$2" "$3" "$4 --log-tcp-sequence --log-tcp-options --log-ip-options" ;;
	esac
	checkexpectedrules="${checkexpectedrules}${checkexpectedrules:+
}$1	$2	$3	$4"
}

Check_IPTables() {
	# Compare the exact iptables-save representation so similarly named rules
	# from another addon cannot satisfy Skynet integrity checks.
	fail=""
	checkexpectedrules=""
	checkrawrules="$TMP_DIR/iptables.raw"
	checkfilterrules="$TMP_DIR/iptables.filter"
	checkwgs="$(nvram get wgs_enable)"
	checkvpn1="$(nvram get vpn_server1_state)"
	checkvpn2="$(nvram get vpn_server2_state)"
	checkfwlog="$(nvram get fw_log_x)"
	if ! iptables-save -t raw > "$checkrawrules" 2>/dev/null \
		|| ! iptables-save -t filter > "$checkfilterrules" 2>/dev/null; then
		rm -f "$checkrawrules" "$checkfilterrules"
		fail="#iptables-save "
		return 1
	fi
	checkrawduplicates=""

	checkwgsexpected="0"; [ "$checkwgs" = "1" ] && checkwgsexpected="1"
	checkvpnexpected="0"; { [ "$checkvpn1" != "0" ] || [ "$checkvpn2" != "0" ]; } && checkvpnexpected="1"
	checkinboundexpected="0"; { [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; } && checkinboundexpected="1"
	checkoutboundexpected="0"; { [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; } && checkoutboundexpected="1"
	checkiotexpected="0"; Is_Enabled "$iotblocked" && checkiotexpected="1"
	checklogexpected="0"; Is_Enabled "$logmode" && Time_Is_Ready && checklogexpected="1"

	Check_Expected_IPTables_Rule "$checkrawrules" 6 "$checkwgsexpected" '-A PREROUTING -i wgs+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP'
	Check_Expected_IPTables_Rule "$checkrawrules" 7 "$checkvpnexpected" '-A PREROUTING -i tun2+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP'
	Check_Expected_IPTables_Rule "$checkrawrules" 8 "$checkinboundexpected" "-A PREROUTING -i $iface -m set ! --match-set Skynet-MasterWL src -m set --match-set Skynet-Master src -j DROP"
	Check_Expected_IPTables_Rule "$checkrawrules" 9 "$checkoutboundexpected" '-A PREROUTING -i br+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP'
	Check_Expected_IPTables_Rule "$checkrawrules" 10 "$checkoutboundexpected" '-A OUTPUT -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP'

	checkiotwgs="0"; [ "$checkiotexpected:$checkwgsexpected" = "1:1" ] && checkiotwgs="1"
	checkiotvpn="0"; [ "$checkiotexpected:$checkvpnexpected" = "1:1" ] && checkiotvpn="1"
	Check_Expected_IPTables_Rule "$checkfilterrules" 11 "$checkiotwgs" '-A FORWARD -i br+ -o wgs+ -m set --match-set Skynet-IOT src -j ACCEPT'
	Check_Expected_IPTables_Rule "$checkfilterrules" 12 "$checkiotvpn" '-A FORWARD -i br+ -o tun2+ -m set --match-set Skynet-IOT src -j ACCEPT'
	Check_Expected_IPTables_Rule "$checkfilterrules" 13 "$checkiotexpected" '-A FORWARD -i br+ ! -o br+ -m set --match-set Skynet-IOT src -j DROP'
	checkiotudp="0"; checkiottcp="0"; checkiotntp="0"; checkiotports=""
	if [ "$checkiotexpected" = "1" ]; then
		case "$iotports" in
			"") checkiotntp="1" ;;
			none) ;;
			*)
				checkiotports="$(List_To_CSV "$iotports")"
				{ [ "$iotproto" = "all" ] || [ "$iotproto" = "udp" ]; } && checkiotudp="1"
				{ [ "$iotproto" = "all" ] || [ "$iotproto" = "tcp" ]; } && checkiottcp="1"
			;;
		esac
	fi
	Check_Expected_IPTables_Rule "$checkfilterrules" 14 "$checkiotudp" "-A FORWARD -i br+ -o $iface -p udp -m set --match-set Skynet-IOT src -m udp -m multiport --dports $checkiotports -j ACCEPT"
	Check_Expected_IPTables_Rule "$checkfilterrules" 15 "$checkiottcp" "-A FORWARD -i br+ -o $iface -p tcp -m set --match-set Skynet-IOT src -m tcp -m multiport --dports $checkiotports -j ACCEPT"
	Check_Expected_IPTables_Rule "$checkfilterrules" 16 "$checkiotntp" "-A FORWARD -i br+ -o $iface -p udp -m set --match-set Skynet-IOT src -m udp --dport 123 -j ACCEPT"

	checklogvpn="0"; [ "$checklogexpected:$checkvpnexpected" = "1:1" ] && checklogvpn="1"
	checklogwgs="0"; [ "$checklogexpected:$checkwgsexpected" = "1:1" ] && checklogwgs="1"
	checklogiot="0"; if [ "$checklogexpected:$checkiotexpected" = "1:1" ] && Is_Enabled "$iotlogging"; then checklogiot="1"; fi
	checkloginbound="0"; [ "$checklogexpected:$checkinboundexpected" = "1:1" ] && checkloginbound="1"
	checkoutboundlog="0"; [ "$checklogexpected:$checkoutboundexpected" = "1:1" ] && checkoutboundlog="1"
	checkloginvalid="0"; if [ "$checklogexpected" = "1" ] && { [ "$checkfwlog" = "drop" ] || [ "$checkfwlog" = "both" ]; } && Is_Enabled "$loginvalid"; then checkloginvalid="1"; fi
	Check_Expected_IPTables_Rule "$checkrawrules" 18 "$checklogvpn" '-A PREROUTING -i tun2+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] "'
	Check_Expected_IPTables_Rule "$checkrawrules" 19 "$checklogwgs" '-A PREROUTING -i wgs+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] "'
	Check_Expected_IPTables_Rule "$checkfilterrules" 20 "$checklogiot" '-A FORWARD -i br+ ! -o br+ -m set --match-set Skynet-IOT src -j LOG --log-prefix "[BLOCKED - IOT] "'
	Check_Expected_IPTables_Rule "$checkrawrules" 21 "$checkloginbound" "-A PREROUTING -i $iface -m set ! --match-set Skynet-MasterWL src -m set --match-set Skynet-Master src -j LOG --log-prefix \"[BLOCKED - INBOUND] \""
	Check_Expected_IPTables_Rule "$checkrawrules" 22 "$checkoutboundlog" '-A PREROUTING -i br+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] "'
	Check_Expected_IPTables_Rule "$checkrawrules" 23 "$checkoutboundlog" '-A OUTPUT -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] "'
	Check_Expected_IPTables_Rule "$checkfilterrules" 24 "$checkloginvalid" '-A logdrop -m state --state INVALID -j LOG --log-prefix "[BLOCKED - INVALID] "'

	checkrawexpected="$((checkwgsexpected + checkvpnexpected + checkinboundexpected + checkoutboundexpected + checkoutboundexpected \
		+ checklogwgs + checklogvpn + checkloginbound + checkoutboundlog + checkoutboundlog))"
	checkiotexpectedtotal="$((checkiotwgs + checkiotvpn + checkiotexpected + checkiotudp + checkiottcp + checkiotntp + checklogiot))"
	fail="$(printf '%s\n' "$checkexpectedrules" | awk -F '\t' -v raw="$checkrawrules" \
		-v expectedraw="$checkrawexpected" -v expectediot="$checkiotexpectedtotal" -v expectedinvalid="$checkloginvalid" '
		FILENAME != "-" {
			if (index($0, "Skynet-Master") || index($0, "Skynet-IOT") || index($0, "[BLOCKED -")) {
				if (seen[FILENAME, $0]++) duplicate=1
				position[FILENAME, $0]=FNR
				if (index($0, "Skynet-IOT")) {
					if ($0 ~ / -j DROP$/) iotdrop=FNR
					if ($0 ~ / -j LOG /) iotlog=FNR
				}
				if (FILENAME == raw && index($0, "Skynet-Master")) rawcount++
				if (FILENAME != raw && index($0, "Skynet-IOT")) iotcount++
				if (FILENAME != raw && index($0, "[BLOCKED - INVALID]")) invalidcount++
			}
			next
		}
		{
			if (seen[$1, $4] + 0 != $3) printf "#%s ", $2
			if ($3 != 1) next
			if (index($4, " -j LOG ")) {
				drop=$4; sub(/ -j LOG .*/, " -j DROP", drop)
				if (position[$1, drop] && position[$1, $4] >= position[$1, drop]) printf "#order:%s ", $2
			}
			if (index($4, "Skynet-IOT") && $4 ~ / -j ACCEPT$/ \
				&& (position[$1, $4] >= iotdrop || (iotlog && position[$1, $4] >= iotlog))) printf "#order:%s ", $2
		}
		END {
			if (rawcount + 0 != expectedraw) printf "#25 "
			if (iotcount + 0 != expectediot) printf "#26 "
			if (invalidcount + 0 != expectedinvalid) printf "#27 "
			if (duplicate) printf "#duplicate "
		}' "$checkrawrules" "$checkfilterrules" -)" || fail="#iptables-check "
	if [ "$1" = "duplicates" ]; then
		case "$fail" in *'#duplicate '*) checkrawduplicates="1" ;; *) checkrawduplicates="0" ;; esac
	fi
	unset checkexpectedrules

	rm -f "$checkrawrules" "$checkfilterrules"
	[ -z "$fail" ]
}

Read_IPSet_Schema() {
	# Terse headers describe the schema without dumping every live member.
	ipset list -t "$1" 2>/dev/null | awk -v name="$1" '
		/^Type: / { type = $2 }
		/^Header: / { sub(/^Header: /, ""); header = $0 }
		END { if (type == "") exit 1; print "create " name " " type " " header }'
}

Expected_IPSet_Schema_Is_Valid() {
	expectedset="$1"
	expectedcreate="$(Read_IPSet_Schema "$expectedset")" || return 1
	expectedpadded=" $expectedcreate "
	case "$expectedset:$expectedcreate" in
		Skynet-Whitelist:"create Skynet-Whitelist hash:net "*|Skynet-BlockedRanges:"create Skynet-BlockedRanges hash:net "*|Skynet-IOT:"create Skynet-IOT hash:net "*)
			case "$expectedpadded" in *" comment "*) ;; *) return 1 ;; esac
			case "$expectedpadded" in *" timeout "*) return 1 ;; esac
		;;
		Skynet-Blacklist:"create Skynet-Blacklist hash:ip "*)
			case "$expectedpadded" in *" comment "*) ;; *) return 1 ;; esac
			case "$expectedpadded" in *" timeout "*) return 1 ;; esac
		;;
		Skynet-WhitelistDomains:"create Skynet-WhitelistDomains hash:ip "*|Skynet-BlacklistDomains:"create Skynet-BlacklistDomains hash:ip "*)
			case "$expectedpadded" in *" comment "*) ;; *) return 1 ;; esac
			case "$expectedpadded" in *" timeout 86400 "*) ;; *) return 1 ;; esac
		;;
		Skynet-Master:"create Skynet-Master list:set "*|Skynet-MasterWL:"create Skynet-MasterWL list:set "*) ;;
		Skynet-UserBans:*|Skynet-UserWhitelist:*) Compiled_IPSet_Schema_Is_Valid "$expectedset" permanent || return 1 ;;
		Skynet-TemporaryBans:*) Compiled_IPSet_Schema_Is_Valid "$expectedset" temporary || return 1 ;;
		*) return 1 ;;
	esac
	case "$expectedpadded" in *" counters "*|*" skbinfo "*) return 1 ;; esac
	return 0
}

Existing_IPSet_Schemas_Are_Compatible() {
	for expectedset in Skynet-Whitelist Skynet-WhitelistDomains Skynet-Blacklist Skynet-BlacklistDomains \
		Skynet-BlockedRanges Skynet-Master Skynet-MasterWL Skynet-IOT \
		Skynet-UserBans Skynet-TemporaryBans Skynet-UserWhitelist; do
		ipset -n list 2>/dev/null | grep -qxF "$expectedset" || continue
		Expected_IPSet_Schema_Is_Valid "$expectedset" || return 1
	done
}

Create_IPSet_Topology() {
	Ensure_IPSet Skynet-Whitelist hash:net hashsize 64 maxelem "$((65536 * 6))" comment || return 1
	Ensure_IPSet Skynet-WhitelistDomains hash:ip hashsize 64 maxelem "$((65536 * 8))" comment timeout 86400 || return 1
	Ensure_IPSet Skynet-Blacklist hash:ip hashsize 64 maxelem "$((65536 * 16))" comment || return 1
	Ensure_IPSet Skynet-BlacklistDomains hash:ip hashsize 64 maxelem "$((65536 * 8))" comment timeout 86400 || return 1
	Ensure_IPSet Skynet-BlockedRanges hash:net hashsize 64 maxelem "$((65536 * 6))" comment || return 1
	Ensure_IPSet Skynet-Master list:set || return 1
	Ensure_IPSet Skynet-MasterWL list:set || return 1
	Ensure_IPSet Skynet-IOT hash:net hashsize 64 maxelem "$((65536 * 6))" comment || return 1
	Ensure_User_IPSets || return 1
	Update_IPSet add Skynet-Master Skynet-Blacklist || return 1
	Update_IPSet add Skynet-Master Skynet-BlacklistDomains || return 1
	Update_IPSet add Skynet-Master Skynet-BlockedRanges || return 1
	Update_IPSet add Skynet-MasterWL Skynet-Whitelist || return 1
	Update_IPSet add Skynet-MasterWL Skynet-WhitelistDomains || return 1
}

Restore_Previous_IPSet_Topology() {
	Unload_IPSets
	if [ -s "$topologysnapshot" ]; then
		ipset restore -! < "$topologysnapshot" 2>/dev/null || return 1
	fi
	Purge_Skynet_IPTables_Rules
	Load_IPTables && Load_IOT_Rules && Load_LogIPTables
}

Rebuild_IPSet_Topology() {
	# A cold start may inherit sets created by an older schema. Preserve the live
	# topology in RAM, rebuild the current sets, then restore only authoritative
	# base members; compiled and domain sets are populated from R2 immediately after.
	topologysnapshot="$TMP_DIR/ipset-topology-old.$$"
	topologyrestore="$TMP_DIR/ipset-topology-base.$$"
	true > "$topologysnapshot" || return 1
	for topologyset in Skynet-Whitelist Skynet-WhitelistDomains Skynet-Blacklist Skynet-BlacklistDomains \
		Skynet-BlockedRanges Skynet-IOT Skynet-UserBans Skynet-TemporaryBans Skynet-UserWhitelist \
		Skynet-Master Skynet-MasterWL; do
		ipset -n list 2>/dev/null | grep -qxF "$topologyset" || continue
		ipset save "$topologyset" >> "$topologysnapshot" 2>/dev/null || return 1
	done
	awk '$1 == "add" && ($2 == "Skynet-Whitelist" || $2 == "Skynet-Blacklist" || $2 == "Skynet-BlockedRanges" || $2 == "Skynet-IOT")' \
		"$topologysnapshot" > "$topologyrestore" || return 1

	Acquire_Firewall_Lock || return 1
	Purge_Skynet_IPTables_Rules || { Release_Firewall_Lock; return 1; }
	Unload_IPSets
	if ! Create_IPSet_Topology \
		|| { [ -s "$topologyrestore" ] && ! ipset restore -! < "$topologyrestore" 2>/dev/null; }; then
		Restore_Previous_IPSet_Topology || Log error -s "Failed To Restore Previous IPSet Topology"
		Release_Firewall_Lock
		return 1
	fi
	Release_Firewall_Lock
	return 0
}

Ensure_IPSet_Topology() {
	if ! Existing_IPSet_Schemas_Are_Compatible; then
		Log info -s "Updating IPSet Schema"
		Rebuild_IPSet_Topology || return 1
	fi
	Create_IPSet_Topology
}

Reconcile_Firewall_Rules() {
	# Merlin has already rebuilt its base firewall. Serialize only the short rule
	# inspection and repair; no state, network or presentation work occurs here.
	Acquire_Firewall_Lock || return 1
	if Check_IPTables; then
		Release_Firewall_Lock
		return 0
	fi
	Purge_Skynet_IPTables_Rules || { Release_Firewall_Lock; return 1; }
	if ! Load_IPTables || ! Load_IOT_Rules; then
		Release_Firewall_Lock
		return 1
	fi
	if Time_Is_Ready; then
		Load_LogIPTables || { Release_Firewall_Lock; return 1; }
	else
		Unload_LogIPTables
	fi
	Check_IPTables
	reconcilestatus="$?"
	Release_Firewall_Lock
	return "$reconcilestatus"
}

Activate_Time_Dependent_State() {
	# Absolute temporary-rule deadlines and packet logging become safe only after
	# NTP has supplied a trustworthy wall clock.
	Time_Is_Ready || return 1
	Apply_Rule_Registry_Candidate "$skynetrules" || return 1
	Reconcile_Firewall_Rules || return 1
	rm -f "$TIME_PENDING"
}

Require_Running() {
	if ! Check_IPSets || ! Check_IPTables; then
		Log error -s "Skynet Not Running - Exiting"
		echo
		exit 1
	fi
}

Unload_IPSets() {
	Destroy_IPSets \
		Skynet-Master Skynet-MasterWL Skynet-Blacklist Skynet-BlockedRanges \
		Skynet-Whitelist Skynet-WhitelistDomains Skynet-BlacklistDomains \
		Skynet-UserBans Skynet-TemporaryBans Skynet-UserWhitelist Skynet-IOT
}

Unload_Cron() {
	# If no argument or "all", reset $@ to the full list
	if [ -z "$1" ] || [ "$1" = "all" ]; then
		set -- "save" "maintenance" "banmalware" "autoupdate" "checkupdate" "genstats" "rules"
	fi

	cronstatus="0"
	for job in "$@"; do
		case "$job" in
			save)
				cru d Skynet_save || cronstatus="1"
			;;
			maintenance)
				cru d Skynet_maintenance || cronstatus="1"
			;;
			banmalware)
				cru d Skynet_banmalware || cronstatus="1"
			;;
			autoupdate)
				cru d Skynet_autoupdate || cronstatus="1"
			;;
			checkupdate)
				cru d Skynet_checkupdate || cronstatus="1"
			;;
			genstats)
				cru d Skynet_genstats || cronstatus="1"
			;;
			rules)
				cru d Skynet_rules || cronstatus="1"
			;;
			*)
				echo "[*] Warning: Unknown Cron Job '$job'"
			;;
		esac
		done
	[ "$cronstatus" = "0" ]
}

Load_Cron() {
	cronstatus="0"
	for job in "$@"; do
		case "$job" in
			maintenance)
				min=$(Generate_Random_Number 0 59)
				cru a Skynet_maintenance "$min * * * * SKYNET_ACTION_ORIGIN=cron sh /jffs/scripts/firewall maintenance" || cronstatus="1"
			;;
			banmalwaredaily)
				hour=$(Generate_Random_Number 1 23)
				cru a Skynet_banmalware "25 $hour * * * sh /jffs/scripts/firewall banmalware" || cronstatus="1"
			;;
			banmalwareweekly)
				hour=$(Generate_Random_Number 1 23)
				cru a Skynet_banmalware "25 $hour * * Mon sh /jffs/scripts/firewall banmalware" || cronstatus="1"
			;;
			autoupdate)
				min=$(Generate_Random_Number 3 23)
				cru a Skynet_autoupdate "$min 1 * * Mon sh /jffs/scripts/firewall update" || cronstatus="1"
			;;
			checkupdate)
				min=$(Generate_Random_Number 3 23)
				cru a Skynet_checkupdate "$min 1 * * Mon sh /jffs/scripts/firewall update check" || cronstatus="1"
			;;
			genstats)
				Is_Enabled "$logmode" || continue
				min=$(Generate_Random_Number 28 57)
				cru a Skynet_genstats "$min 11,23 * * * sh /jffs/scripts/firewall debug genstats" || cronstatus="1"
			;;
			rules)
				min=$(Generate_Random_Number 0 59)
				cru a Skynet_rules "$min 0,6,12,18 * * * SKYNET_ACTION_ORIGIN=cron sh /jffs/scripts/firewall rules refresh" || cronstatus="1"
			;;
			*)
				echo "[*] Warning: Unknown Cron Job '$job'"
			;;
		esac
		done
	[ "$cronstatus" = "0" ]
}

Generate_Random_Number() {
	awk -v min="$1" -v max="$2" -v freq=1 'BEGIN{"tr -cd 0-9 </dev/urandom | head -c 6" | getline seed; srand(seed); for(i=0;i<freq;i++)print int(min+rand()*(max-min+1))}'
}

############################
#- Validation And Parsing -#
############################

# These predicates read one value from stdin. Each IPv4 octet is constrained
# to 0-255; the functions differ only in CIDR policy and whether the whole line
# must match. Is_IP permits a host or /32, Is_Range requires /0-/31,
# Is_IPRange permits either, and Contains_IPRange searches within other text.
Is_IP() {
	grep -qE '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(32))?)$'
}

Is_Range() {
	grep -qE '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-1])){1})$'
}

Is_IPRange() {
	grep -qE '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)$'
}

Normalize_IPSet_Entry() {
	printf '%s\n' "$2" | Normalize_IPSet_Entries "$1"
}

Normalize_IPSet_Entries() {
	# IPSet canonicalises networks to their network address. Do the same before a
	# value becomes a registry key so equivalent CIDRs cannot create two owners.
	# The any mode validates complete sidecars, allowing blank separator lines.
	case "$1" in ip|range|any) ;; *) return 1 ;; esac
	awk -v expected="$1" '
		BEGIN {
			blocks[32] = 1
			for (i = 31; i >= 0; i--) blocks[i] = blocks[i + 1] * 2
		}
		expected == "any" && $0 == "" { next }
		{
			parts = split($0, address, "/")
			if (parts > 2) exit 1
			octets = split(address[1], octet, ".")
			if (octets != 4) exit 1
			for (i = 1; i <= 4; i++) {
				if (octet[i] !~ /^[0-9]+$/ || octet[i] < 0 || octet[i] > 255) exit 1
			}
			prefix = parts == 2 ? address[2] : 32
			if (prefix !~ /^[0-9]+$/ || prefix < 0 || prefix > 32) exit 1
			if (expected == "ip" && prefix != 32) exit 1
			if (expected == "range" && (parts != 2 || prefix == 32)) exit 1
			value = (((octet[1] * 256) + octet[2]) * 256 + octet[3]) * 256 + octet[4]
			block = blocks[prefix + 0]
			value = int(value / block) * block
			first = int(value / 16777216); value -= first * 16777216
			second = int(value / 65536); value -= second * 65536
			third = int(value / 256); fourth = value - third * 256
			count++
			if (prefix == 32) printf "%d.%d.%d.%d\n", first, second, third, fourth
			else printf "%d.%d.%d.%d/%d\n", first, second, third, fourth, prefix
		}
		END { if (!count) exit 1 }'
}

Contains_IPRange() {
	grep -qE '(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)'
}

Is_MAC() {
	grep -qE '^([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}$'
}

Is_Port() {
	awk 'NR == 1 && $0 ~ /^[0-9]{1,5}$/ && $0 >= 1 && $0 <= 65535 { valid = 1 }
		END { exit valid ? 0 : 1 }'
}

Is_ASN() {
	grep -qiE '^AS[0-9]{1,6}$'
}

Normalize_ASN_Arguments() {
	[ "$#" -gt "0" ] || return 1
	for asninput in "$@"; do
		printf '%s\n' "$asninput" | Is_ASN || return 1
	done
	printf '%s\n' "$@" | awk '
		{
			value = toupper($0)
			if (!seen[value]++) {
				if (output != "") output = output " "
				output = output value
			}
		}
		END { if (output == "") exit 1; print output }'
}

Is_Numeric() {
	case "$1" in
		*[!0-9]*) return 1 ;;  # If any non-digit, fail
		"")       return 1 ;;  # If empty, fail
		*)        return 0 ;;  # Otherwise, success
	esac
}

Normalize_List() {
	# Canonical list format is unique, space-separated values in supplied order.
	# Commas and pipes remain accepted only to migrate older configuration data;
	# leading, trailing or repeated delimiters are rejected as empty values.
	[ "$#" -gt "0" ] || return 1
	for listvalue in "$@"; do
		case "$listvalue" in
			""|,*|\|*|*,|*\||*,,*|*\|\|*) return 1 ;;
		esac
	done
	printf '%s\n' "$@" | awk '
		{
			gsub(/[|,]/, " ")
			for (i = 1; i <= NF; i++) {
				if (!seen[$i]++) {
					if (output != "") output = output " "
					output = output $i
				}
			}
		}
		END {
			if (output == "") exit 1
			print output
		}'
}

Normalize_Arguments_From() {
	# $1 is the one-based position of the first list value in the original
	# command. Forward every remaining positional argument to Normalize_List.
	listskip="$1"
	shift
	while [ "$listskip" -gt "1" ]; do
		[ "$#" -gt "0" ] || return 1
		shift
		listskip=$((listskip - 1))
	done
	Normalize_List "$@"
}

Is_Country_Code() {
	# Country blocking accepts the ISO-style codes exposed by the WebUI picker.
	# Checking locally prevents a provider alias from becoming saved configuration.
	supportedcountrycodes=" ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bl bm bn bo bq br bs bt bv bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg eh er es et fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sj sk sl sm sn so sr ss st sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug um us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw "
	case "$supportedcountrycodes" in
		*" $1 "*) return 0 ;;
		*) return 1 ;;
	esac
}

Validate_IPSet_Entry_Type() {
	case "$1" in
		ip) printf '%s\n' "$2" | Is_IP ;;
		range) printf '%s\n' "$2" | Is_Range ;;
		iprange) printf '%s\n' "$2" | Is_IPRange ;;
		*) return 1 ;;
	esac
}

Parse_IPSet_Entry_Arguments() {
	# Parse one or more positional IPSet entries before any live change occurs.
	# A literal "comment" separates a batch from its single quoted comment:
	#   firewall ban ip 1.1.1.1 8.8.8.8 comment "Manual block"
	parseentrytype="$1"
	parsecommentlimit="$2"
	shift 2
	parsedentries=""
	parsedcomment=""
	parsederror=""
	parsecommentmode="0"

	if [ "$#" -eq "0" ]; then
		parsederror="Entry Field Can't Be Empty"
		return 1
	fi

	for parseentryvalue in "$@"; do
		if [ "$parseentryvalue" = "comment" ] && [ "$parsecommentmode" = "0" ]; then
			[ -n "$parsedentries" ] || { parsederror="Entry Field Can't Be Empty"; return 1; }
			parsecommentmode="1"
			continue
		fi
		case "$parsecommentmode" in
			0)
				parsenormalized="$(Normalize_IPSet_Entry "$parseentrytype" "$parseentryvalue")"
				if [ -z "$parsenormalized" ] || [ "$parsenormalized" != "${parseentryvalue%/32}" ]; then
					parsederror="$parseentryvalue Is Not A Valid IP/Range. Use ( comment \"text\" ) After All Entries"
					return 1
				fi
				parsedentries="${parsedentries}${parsedentries:+ }$parsenormalized"
			;;
			1)
				[ -n "$parseentryvalue" ] || { parsederror="Comment Field Can't Be Empty"; return 1; }
				parsedcomment="$parseentryvalue"
				parsecommentmode="2"
			;;
			*)
				parsederror="Only One Quoted Comment Can Follow The Comment Separator"
				return 1
			;;
		esac
	done

	if [ "$parsecommentmode" = "1" ]; then
		parsederror="Comment Field Can't Be Empty"
		return 1
	fi
	if ! Validate_IPSet_Comment "$parsedcomment" "$parsecommentlimit"; then
		parsederror="Comment Contains Invalid Characters Or Is Too Long. ${parsecommentlimit} Chars Max"
		return 1
	fi
	parsedentries="$(Normalize_List "$parsedentries")" || { parsederror="Entry Field Can't Be Empty"; return 1; }
	return 0
}

Parse_Ban_Arguments() {
	# Values precede the optional timeout and comment clauses. Keeping one strict
	# order makes every batch fully valid before the registry or IPSet is changed.
	parseentrytype="$1"
	parsecommentlimit="$2"
	shift 2
	parsedentries=""
	parsedcomment=""
	parsedtimeout=""
	parsedtimeoutseconds="0"
	parsedexpires="0"
	parsederror=""
	parsemode="entries"
	[ "$#" -gt "0" ] || { parsederror="Entry Field Can't Be Empty"; return 1; }
	while [ "$#" -gt "0" ]; do
		parsevalue="$1"
		shift
		case "$parsemode:$parsevalue" in
			entries:timeout)
				[ -n "$parsedentries" ] || { parsederror="Entry Field Can't Be Empty"; return 1; }
				[ "$#" -gt "0" ] || { parsederror="Timeout Value Can't Be Empty"; return 1; }
				parsedtimeout="$1"
				shift
				case "$parsedtimeout" in
					15m) parsedtimeoutseconds="900" ;;
					1h) parsedtimeoutseconds="3600" ;;
					6h) parsedtimeoutseconds="21600" ;;
					24h) parsedtimeoutseconds="86400" ;;
					7d) parsedtimeoutseconds="604800" ;;
					*) parsederror="Timeout Must Be 15m, 1h, 6h, 24h Or 7d"; return 1 ;;
				esac
				parsemode="after-timeout"
			;;
			entries:comment|after-timeout:comment)
				[ -n "$parsedentries" ] || { parsederror="Entry Field Can't Be Empty"; return 1; }
				[ "$#" -eq "1" ] && [ -n "$1" ] || { parsederror="One Quoted Comment Must Follow The Comment Separator"; return 1; }
				parsedcomment="$1"
				shift
				parsemode="done"
			;;
			entries:*)
				parsenormalized="$(Normalize_IPSet_Entry "$parseentrytype" "$parsevalue")"
				if [ -z "$parsenormalized" ] || [ "$parsenormalized" != "${parsevalue%/32}" ]; then
					parsederror="$parsevalue Is Not A Valid IP/Range"
					return 1
				fi
				case " $parsedentries " in *" $parsenormalized "*) ;; *) parsedentries="${parsedentries}${parsedentries:+ }$parsenormalized" ;; esac
			;;
			*) parsederror="Use Values, Optional Timeout, Then Optional Comment"; return 1 ;;
		esac
	done
	[ -n "$parsedentries" ] || { parsederror="Entry Field Can't Be Empty"; return 1; }
	Validate_IPSet_Comment "$parsedcomment" "$parsecommentlimit" \
		|| { parsederror="Comment Contains Invalid Characters Or Is Too Long. ${parsecommentlimit} Chars Max"; return 1; }
	if [ "$parsedtimeoutseconds" -gt "0" ]; then
		Time_Is_Ready || { parsederror="Temporary Rules Require Synchronized Router Time"; return 1; }
		parsedexpires="$(($(date +%s) + parsedtimeoutseconds))"
	fi
	return 0
}

Validate_IPSet_Comment() {
	# Restore files quote comments directly. Backslashes, quotes, control bytes or
	# embedded newlines could alter AWK -v parsing or create another restore line.
	case "$1" in
		*\\*|*\"*) return 1 ;;
	esac
	[ "${#1}" -le "$2" ] || return 1
	printf '%s\n' "$1" | awk 'NR > 1 || /[[:cntrl:]]/ { invalid = 1 } END { exit invalid }'
}

List_To_CSV() {
	printf '%s\n' "$1" | awk '{$1 = $1; gsub(/ /, ","); print}'
}

List_To_Lines() {
	# Canonical internal lists are space-separated; consumers that require one
	# value per record use this conversion after the list has been validated.
	printf '%s\n' "$1" | tr ' ' '\n'
}

IPSet_Entry_Count() {
	# Terse mode avoids serialising every member merely to read the header count.
	# Stopped diagnostics allow absent sets; publication requires a successful read.
	if ! ipsetcountdata="$(ipset list -t "$1" 2>/dev/null)"; then
		[ "$2" != "strict" ] || return 1
		printf '0\n'
		return 0
	fi
	printf '%s\n' "$ipsetcountdata" | awk -F ': ' -v mode="$2" '
		/^Number of entries:/ && $2 ~ /^[0-9]+$/ { print $2; found = 1; exit }
		END { if (!found) { if (mode == "strict") exit 1; print 0 } }'
}

Update_Block_Counts() {
	# User and temporary policy share hash:net sets, so classify their saved
	# members while retaining the established IP and range totals in the UI.
	blockcountautomatic="$(IPSet_Entry_Count Skynet-Blacklist "$1")" || return 1
	blockcountdomains="$(IPSet_Entry_Count Skynet-BlacklistDomains "$1")" || return 1
	blockcountips="$((blockcountautomatic + blockcountdomains))"
	blockcountranges="$(IPSet_Entry_Count Skynet-BlockedRanges "$1")" || return 1
	blockcountwork="$TMP_DIR/block-counts.$$"
	if ! { ipset save Skynet-UserBans && ipset save Skynet-TemporaryBans; } > "$blockcountwork" 2>/dev/null; then
		rm -f "$blockcountwork"
		[ "$1" != "strict" ] || return 1
		: > "$blockcountwork" || return 1
	fi
	blockcountuser="$(awk '
		$1 == "add" {
			if (index($3, "/") && $3 !~ /\/32$/) ranges++
			else ips++
		}
		END {print ips + 0, ranges + 0}
	' "$blockcountwork")" || { rm -f "$blockcountwork"; return 1; }
	rm -f "$blockcountwork"
	blockcountuser="${blockcountuser:-0 0}"
	blacklist1count="$((blockcountips + ${blockcountuser%% *}))"
	blacklist2count="$((blockcountranges + ${blockcountuser#* }))"
}

Update_IPSet_Batch() {
	# Callers validate every entry before reaching this worker. Snapshot the
	# complete target set, build one restore transaction, and roll back the set
	# if ipset rejects any member of the batch.
	batchaction="$1"
	batchset="$2"
	batchcomment="$3"
	shift 3
	batchlist="$(Normalize_List "$@")" || return 1
	batchfile="$TMP_DIR/ipset-batch.$$"
	batchsnapshot="$TMP_DIR/ipset-snapshot.$$"

	case "$batchaction:$batchset" in
		add:Skynet-Whitelist|add:Skynet-Blacklist|add:Skynet-BlockedRanges|add:Skynet-IOT|\
		del:Skynet-Whitelist|del:Skynet-Blacklist|del:Skynet-BlockedRanges|del:Skynet-IOT) ;;
		*) Log error -s "Invalid Batched IPSet Operation ($batchaction $batchset)"; return 1 ;;
	esac
	if ! Validate_IPSet_Comment "$batchcomment" 255; then
		Log error -s "IPSet Comment Contains Invalid Characters Or Is Too Long"
		return 1
	fi

	if ! ipset save "$batchset" > "$batchsnapshot" 2>/dev/null; then
		rm -f "$batchfile" "$batchsnapshot"
		Log error -s "Failed To Snapshot IPSet ($batchset)"
		return 1
	fi
	if ! true > "$batchfile"; then
		rm -f "$batchfile" "$batchsnapshot"
		return 1
	fi
	# Entries have already been restricted to atomic IPSet values.
	# shellcheck disable=SC2086
	set -- $batchlist
	for batchentry in "$@"; do
		if awk -v setname="$batchset" -v entry="$batchentry" \
			'$1 == "add" && $2 == setname && $3 == entry { found = 1; exit } END { exit !found }' "$batchsnapshot"; then
			[ "$batchaction" = "add" ] && continue
		else
			[ "$batchaction" = "del" ] && continue
		fi
		if [ "$batchaction" = "add" ]; then
			printf 'add %s %s comment "%s"\n' "$batchset" "$batchentry" "$batchcomment" >> "$batchfile"
		else
			printf 'del %s %s\n' "$batchset" "$batchentry" >> "$batchfile"
		fi
	done

	if [ ! -s "$batchfile" ]; then
		rm -f "$batchfile" "$batchsnapshot"
		return 0
	fi
	if ipset restore < "$batchfile"; then
		batchenforced="0"
		if [ "$batchaction:$batchset" = "add:Skynet-IOT" ]; then
			batchiotentries="$(awk '$1 == "add" {print $3}' "$batchfile")" \
				&& Revalidate_IOT_Connections "$batchiotentries" || batchenforced="1"
		fi
		if [ "$batchenforced" = "0" ]; then
			rm -f "$batchfile" "$batchsnapshot"
			return 0
		fi
	fi

	if ipset flush "$batchset" 2>/dev/null && ipset restore -! < "$batchsnapshot" 2>/dev/null; then
		batchrollback="Previous Entries Restored"
	else
		batchrollback="Rollback Failed - Manual Recovery Required"
	fi
	rm -f "$batchfile" "$batchsnapshot"
	Log error -s "Failed To Update IPSet ($batchset) - $batchrollback"
	return 1
}

# Apply a prepared add/del file containing only Skynet data sets. Every affected
# set is restored together if any operation fails. An internal caller may supply
# a current snapshot it already needed, avoiding a second full IPSet export.
Apply_IPSet_File() {
	ipsetfile="$1"
	ipsetsnapshot="$2"
	ipsetsnapshotowned="0"
	ipseteffective="$TMP_DIR/ipset-file-effective.$$"
	ipsetrollback="$TMP_DIR/ipset-file-rollback.$$"
	ipsetnames="$(awk '
		$1 != "add" && $1 != "del" { exit 1 }
		$2 != "Skynet-Blacklist" && $2 != "Skynet-BlockedRanges" && $2 != "Skynet-Whitelist" { exit 1 }
		NF < 3 { exit 1 }
		!seen[$2]++ { output = output (output == "" ? "" : " ") $2 }
		END { if (NR == 0) exit 1; print output }
	' "$ipsetfile")" || return 1
	if [ -n "$ipsetsnapshot" ]; then
		[ -s "$ipsetsnapshot" ] || return 1
	else
		ipsetsnapshot="$TMP_DIR/ipset-file-snapshot.$$"
		ipsetsnapshotowned="1"
		true > "$ipsetsnapshot" || return 1
		for ipsetname in $ipsetnames; do
			if ! ipset save "$ipsetname" >> "$ipsetsnapshot" 2>/dev/null; then
				rm -f "$ipsetsnapshot"
				return 1
			fi
		done
	fi
	# Remove no-op additions and deletions against the snapshot first. The
	# remaining restore can then run in strict mode and expose any failed member.
	awk '
		NR == FNR {
			if ($1 == "add") present[$2 SUBSEP $3] = 1
			next
		}
		$1 == "add" {
			key = $2 SUBSEP $3
			if (!(key in present)) { print; present[key] = 1 }
			next
		}
		$1 == "del" {
			key = $2 SUBSEP $3
			if (key in present) { print; delete present[key] }
		}
	' "$ipsetsnapshot" "$ipsetfile" > "$ipseteffective" || {
		[ "$ipsetsnapshotowned" = "0" ] || rm -f "$ipsetsnapshot"
		rm -f "$ipseteffective"
		return 1
	}
	if [ ! -s "$ipseteffective" ] || ipset restore < "$ipseteffective"; then
		[ "$ipsetsnapshotowned" = "0" ] || rm -f "$ipsetsnapshot"
		rm -f "$ipseteffective"
		return 0
	fi
	for ipsetname in $ipsetnames; do
		ipset flush "$ipsetname" 2>/dev/null
	done
	if ! awk '$1 == "add"' "$ipsetsnapshot" > "$ipsetrollback" \
		|| ! ipset restore < "$ipsetrollback" 2>/dev/null; then
		Log error -s "Failed To Fully Restore IPSet Data"
	fi
	[ "$ipsetsnapshotowned" = "0" ] || rm -f "$ipsetsnapshot"
	rm -f "$ipseteffective" "$ipsetrollback"
	Log error -s "Failed To Apply IPSet File - Previous Entries Restored"
	return 1
}

Replace_Range_IPSet_Entries() {
	# Build a complete replacement beside the live range set, excluding entries
	# identified by one fixed comment marker and adding the prepared replacement.
	# The single IPSet swap is atomic, so interruption cannot expose a partial set.
	rangereplacemarker="$1"
	rangereplaceinput="$2"
	rangereplacetmp="Skynet-Ranges-Tmp"
	cleanupipsets="${cleanupipsets}${cleanupipsets:+ }${rangereplacetmp}"
	rangereplacesnapshot="$TMP_DIR/range-replace-old.$$"
	rangereplacerestore="$TMP_DIR/range-replace-new.$$"

	if ! ipset save Skynet-BlockedRanges > "$rangereplacesnapshot" 2>/dev/null \
		|| ! awk -v marker="$rangereplacemarker" -v target="$rangereplacetmp" '
			$1 == "add" && $2 == "Skynet-BlockedRanges" && !index($0, marker) {
				$2 = target
				print
			}' "$rangereplacesnapshot" > "$rangereplacerestore" \
		|| ! awk -v target="$rangereplacetmp" '
			$1 != "add" || $2 != "Skynet-BlockedRanges" || NF < 3 { invalid = 1; exit }
			{ $2 = target; print }
			END { if (invalid || NR == 0) exit 1 }
		' "$rangereplaceinput" >> "$rangereplacerestore"; then
		rm -f "$rangereplacesnapshot" "$rangereplacerestore"
		return 1
	fi

	Destroy_IPSets "$rangereplacetmp"
	if ! ipset -q create "$rangereplacetmp" hash:net hashsize 64 maxelem "$((65536 * 6))" comment \
		|| ! ipset restore -! < "$rangereplacerestore"; then
		Destroy_IPSets "$rangereplacetmp"
		rm -f "$rangereplacesnapshot" "$rangereplacerestore"
		return 1
	fi

	trap '' INT TERM
	if ! ipset swap "$rangereplacetmp" Skynet-BlockedRanges; then
		Destroy_IPSets "$rangereplacetmp"
		Set_Cleanup_Traps
		rm -f "$rangereplacesnapshot" "$rangereplacerestore"
		return 1
	fi
	Destroy_IPSets "$rangereplacetmp"
	Set_Cleanup_Traps
	rm -f "$rangereplacesnapshot" "$rangereplacerestore"
}

Strip_Domain() {
	# Normalize URLs with one process. Only a leading www label is discarded;
	# embedded "www." text remains part of the hostname.
	awk '{
		value = tolower($0)
		sub(/^[[:space:]]*/, "", value)
		if (value ~ /^#/) next
		sub(/^https?:\/\//, "", value)
		sub(/\/.*/, "", value)
		sub(/^www\./, "", value)
		if (value != "" && !seen[value]++) print value
	}' "$@"
}

Normalize_Domain_Input() {
	# Validate already stripped values in one AWK pass. Single mode rejects the
	# complete input when invalid; list mode skips invalid values and de-duplicates
	# their final DNS form before any network work begins. Canonical mode validates
	# registry rows without de-duplicating ownership across different targets.
	awk -v mode="$1" '
		{
			value = tolower($0)
			sub(/\.$/, "", value)
			if (mode == "canonical") sub(/^www\./, "", value)
			lines++
			valid = length(value) >= 1 && length(value) <= 253
			count = split(value, labels, ".")
			for (i = 1; i <= count; i++) {
				if (length(labels[i]) < 1 || length(labels[i]) > 63 ||
					labels[i] !~ /^[a-z0-9-]+$/ ||
					substr(labels[i], 1, 1) == "-" ||
					substr(labels[i], length(labels[i]), 1) == "-") valid = 0
			}
			if (!valid) {
				invalid = 1
				next
			}
			if (mode == "canonical") print value
			else if (mode == "single") output = value
			else if (!seen[value]++) print value
		}
		END {
			if (mode == "canonical" && invalid) exit 1
			if (mode == "single") {
				if (invalid || lines != 1) exit 1
				print output
			}
		}'
}

Normalize_Domain() {
	# Accept one hostname or URL and emit one safe lowercase DNS name.
	printf '%s\n' "$1" | Strip_Domain | Normalize_Domain_Input single
}

Normalize_Domain_List() {
	# Batch equivalent used before bounded lookup pools.
	Strip_Domain "$@" | Normalize_Domain_Input list
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

########################
#- Output And Commands -#
########################

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

Display_Settings_Category() {
	settingsdividerleft="═══════════════════════════════════"
	settingsdividerright="${settingsdividerleft}${settingsdividerleft}═"
	if [ "$2" != "first" ]; then
		printf '╠%s╬%s╣\n' "$settingsdividerleft" "$settingsdividerright"
	fi
	# Keep ANSI bytes outside the padded field so terminal colour never shifts
	# the table borders. Redirected debug output remains plain text.
	if [ -t 1 ] || [ -t 2 ]; then
		printf '║ \033[1;36m%-33s\033[0m ║ %-69s ║\n' "$1" ""
	else
		printf '║ %-33s ║ %-69s ║\n' "$1" ""
	fi
	printf '╠%s╬%s╣\n' "$settingsdividerleft" "$settingsdividerright"
	unset "settingsdividerleft" "settingsdividerright"
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

# Match addresses Skynet must never treat as public threats: unspecified,
# RFC1918, CGNAT, loopback, link-local, documentation, benchmark, multicast and
# reserved space.
Is_PrivateIP() {
	grep -qE '^(0\.|10\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.|127\.|169\.254\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.0\.0\.|192\.0\.2\.|192\.168\.|198\.(1[8-9])\.|198\.51\.100\.|203\.0\.113\.|2(2[4-9]|[3-4][0-9]|5[0-5])\.)'
}

Filter_PrivateIP() {
	grep -vE '^(0\.|10\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.0\.0\.|192\.0\.2\.|192\.168\.|198\.(1[8-9])\.|198\.51\.100\.|203\.0\.113\.|2(2[4-9]|[3-4][0-9]|5[0-5])\.)'
}

#############################
#- Lists And Whitelisting -#
#############################

Domain_Lookup() {
	# BusyBox nslookup includes the DNS server address before the answer. Track the
	# matching Name section so only answers for the requested CNAME chain escape.
	# A watchdog provides the timeout missing from older Merlin nslookup builds.
	# Status 3 means the resolver completed without a usable IPv4 answer. Older
	# BusyBox builds report other empty and failed replies identically, so those
	# remain transient and may use a recent validated cache.
	lookupdomain="$1"
	lookuptimeout="$2"
	lookupid="${4:-single}"
	case "$lookupid" in *[!A-Za-z0-9_-]*) return 1 ;; esac
	lookupresultfile="$TMP_DIR/ns.$(printf '%s' "$lookupdomain" | tr -c 'A-Za-z0-9' '_').$lookupid"
	lookupanswerfile="${lookupresultfile}.answers"

	(
		if [ -n "$3" ]; then
			nslookup "$lookupdomain" "$3" > "$lookupresultfile" 2>&1
		else
			nslookup "$lookupdomain" > "$lookupresultfile" 2>&1
		fi
	) &
	lookuppid=$!
	( sleep "$lookuptimeout"; kill "$lookuppid" 2>/dev/null ) &
	lookupwatchdogpid=$!

	wait "$lookuppid" 2>/dev/null
	lookupstatus="$?"
	kill "$lookupwatchdogpid" 2>/dev/null
	wait "$lookupwatchdogpid" 2>/dev/null

	# Some BusyBox builds return a failure status after printing usable answers.
	# Parsed IPv4 output is authoritative; an empty answer set still fails below.
	if [ -s "$lookupresultfile" ]; then
		awk -v q="$lookupdomain" '
			BEGIN {
				# normalise query: strip trailing dot if present
				gsub(/\.$/, "", q)
				in_query = 0
			}

			# A matching Name section owns its following Address records,
			# including CNAME target blocks.
			/^Name:[[:space:]]*/ {
				name = $2
				gsub(/\.$/, "", name)
				if (!in_query && name == q)
					in_query = 1
				next
			}

			# Address records outside the query section belong to the DNS server block.
			in_query && /Address/ {
				for (i = 1; i <= NF; i++) {
					if ($i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/)
						print $i
				}
			}
		' "$lookupresultfile" | Filter_IP | awk '!seen[$0]++' > "$lookupanswerfile"
	fi

	if [ -s "$lookupanswerfile" ]; then
		cat "$lookupanswerfile"
		lookupstatus="$?"
	elif [ "$lookupstatus" = "0" ]; then
		lookupstatus="3"
	else
		lookupstatus="1"
	fi
	rm -f "$lookupresultfile" "$lookupanswerfile"
	return "$lookupstatus"
}

Resolve_Normalized_Domain_IP_List() {
	# The caller has already passed the hostname through Normalize_Domain or its
	# batch equivalent. A second immediate attempt absorbs transient DNS timeouts.
	# Two completed empty replies retain status 3. Indistinguishable resolver
	# errors remain transient and never retire a cached address early.
	domainresolveinput="$1"
	case "$2" in all|public) ;; *) return 1 ;; esac
	domainresolveattempt="0"
	domainresolveips=""
	domainresolvenegative="0"
	domainresolvetransient="0"
	while [ "$domainresolveattempt" -lt "2" ]; do
		domainresolveattempt=$((domainresolveattempt + 1))
		if [ -n "$3" ]; then
			domainlookupips="$(Domain_Lookup "$domainresolveinput" 3 "$3" "$4")"
		else
			domainlookupips="$(Domain_Lookup "$domainresolveinput" 3 "" "$4")"
		fi
		domainlookupstatus="$?"
		if [ "$domainlookupstatus" = "0" ] && [ -n "$domainlookupips" ]; then
			domainresolveips="$domainlookupips"
			break
		fi
		[ "$domainlookupstatus" = "3" ] && domainresolvenegative="1" || domainresolvetransient="1"
	done
	if [ -z "$domainresolveips" ]; then
		[ "$domainresolvenegative" = "1" ] && [ "$domainresolvetransient" = "0" ] && return 3
		return 1
	fi
	if [ "$2" = "public" ]; then
		domainresolveips="$(printf '%s\n' "$domainresolveips" | Filter_PrivateIP)"
		[ -n "$domainresolveips" ] || return 3
	fi
	Normalize_List "$domainresolveips"
}

Resolve_Domain_IP_List() {
	# Public command paths validate one value here; bulk workers normalise their
	# complete input once and call Resolve_Normalized_Domain_IP_List directly.
	domainresolveinput="$(Normalize_Domain "$1")" || return 1
	Resolve_Normalized_Domain_IP_List "$domainresolveinput" "$2" "$3"
}

Normalize_Domain_Rule_IPs() {
	# Dynamic domain sets store hosts only. Ban rules exclude private and reserved
	# answers; whitelist rules may intentionally reference local destinations.
	if [ "$1" = "ban" ]; then
		Filter_IP | Filter_PrivateIP | sort -u
	else
		Filter_IP | sort -u
	fi
}

Extract_Legacy_Domain_IPs() {
	domainlegacytarget="$1"
	domainlegacyvalue="$2"
	if [ "$domainlegacytarget" = "ban" ]; then
		domainlegacyset="Skynet-Blacklist"
		domainlegacyprefix="ManualBanD: "
	else
		domainlegacyset="Skynet-Whitelist"
		domainlegacyprefix="ManualWlistD: "
	fi
	ipset save "$domainlegacyset" 2>/dev/null | awk -v expected="$domainlegacyprefix$domainlegacyvalue" '
		$1 == "add" {
			position = index($0, "comment \"")
			if (!position) next
			comment = substr($0, position + 9)
			sub(/\"$/, "", comment)
			if (comment == expected) print $3
		}
	' | Normalize_Domain_Rule_IPs "$domainlegacytarget"
}

Validate_Domain_Rule_Cache() {
	[ -s "$1" ] && [ ! -L "$1" ] || return 1
	domaincachevalidated="$TMP_DIR/domain-cache-validate.$$"
	Normalize_Domain_Rule_IPs "$2" < "$1" > "$domaincachevalidated" || { rm -f "$domaincachevalidated"; return 1; }
	cmp -s "$domaincachevalidated" "$1"
	domaincachestatus="$?"
	rm -f "$domaincachevalidated"
	return "$domaincachestatus"
}

Validate_Bound_Domain_Rule_Cache() {
	# Fallback data must still match the count and checksum recorded for the same
	# logical rule. A merely well-formed but replaced cache is never trusted.
	Validate_Domain_Rule_Cache "$1" "$2" || return 1
	[ "$(wc -l < "$1" | tr -d ' ')" = "$3" ] || return 1
	case "$4" in
		[0-9]*-[0-9]*)
			type cksum >/dev/null 2>&1 || return 0
			[ "$(cksum "$1" | awk '{print $1 "-" $2}')" = "$4" ]
		;;
		*) [ "$(sha256sum "$1" 2>/dev/null | awk '{print $1}')" = "$4" ] ;;
	esac
}

Validate_Rule_Status_Manifest() {
	# D2 rows bind each logical domain to its observed state and validated cache.
	# D1 is accepted during upgrade and rewritten on the next reconciliation.
	domainvalidatefile="$1"
	domainvalidatecache="$2"
	[ -f "$domainvalidatefile" ] || return 1
	awk -F '\t' '
		$1 == "D1" {
			if (NF != 10 || ($2 != "ban" && $2 != "whitelist") || $3 == "" \
				|| ($4 != "current" && $4 != "cached" && $4 != "failed") \
				|| $5 !~ /^[0-9]+$/ || $6 !~ /^[0-9]+$/ || $7 !~ /^[0-9]+$/ \
				|| $8 !~ /^[0-9]+$/ || $9 !~ /^[0-9]+-[0-9]+$/ \
				|| $10 !~ /^domain\.[0-9]+\.[0-9]+-[0-9]+\.list$/) exit 1
		}
		$1 == "D2" {
			if (NF != 11 || ($2 != "ban" && $2 != "whitelist") || $3 == "" \
				|| $4 !~ /^(current|cached|empty|expired|failed)$/ \
				|| $5 !~ /^[0-9]+$/ || $6 !~ /^[0-9]+$/ || $7 !~ /^[0-9]+$/ \
				|| $8 !~ /^[0-9]+$/ || $9 !~ /^[0-9]+$/ || $9 > 2) exit 1
			if ($4 == "current" || $4 == "cached") {
				if ($5 < 1 || $7 < 1 || $10 !~ /^[0-9a-f]+$/ || length($10) != 64 \
					|| $11 !~ /^domain\.[0-9a-f]+\.[0-9a-f]+\.list$/) exit 1
				parts = split($11, cache, ".")
				if (parts != 4 || length(cache[2]) != 16 || length(cache[3]) != 64) exit 1
			} else if ($5 != 0 || $10 != "-" || $11 != "-") exit 1
		}
		$1 != "D1" && $1 != "D2" { exit 1 }
		{ key = $2 SUBSEP tolower($3); if (seen[key]++) exit 1 }
	' "$domainvalidatefile" || return 1
	while IFS="$(printf '\t')" read -r domainvalidateversion domainvalidatetarget domainvalidatedomain domainvalidatestate domainvalidatecount _domainchecked _domainsuccess _domainchanged domainvalidatefield9 domainvalidatefield10 domainvalidatefield11; do
		[ "$(Normalize_Domain "$domainvalidatedomain" 2>/dev/null)" = "$domainvalidatedomain" ] || return 1
		[ -n "$domainvalidatecache" ] || continue
		if [ "$domainvalidateversion" = "D1" ]; then
			domainvalidatehash="$domainvalidatefield9"
			domainvalidatecachefile="$domainvalidatefield10"
		else
			domainvalidatehash="$domainvalidatefield10"
			domainvalidatecachefile="$domainvalidatefield11"
			case "$domainvalidatestate" in empty|expired|failed) continue ;; esac
			domainvalidatekey="$(printf '%s:%s\n' "$domainvalidatetarget" "$domainvalidatedomain" | sha256sum | awk '{print substr($1, 1, 16)}')"
			[ "$domainvalidatecachefile" = "domain.${domainvalidatekey}.${domainvalidatehash}.list" ] || return 1
		fi
		[ -f "$domainvalidatecache/$domainvalidatecachefile" ] || return 1
		Validate_Domain_Rule_Cache "$domainvalidatecache/$domainvalidatecachefile" "$domainvalidatetarget" || return 1
		[ "$(wc -l < "$domainvalidatecache/$domainvalidatecachefile" | tr -d ' ')" = "$domainvalidatecount" ] || return 1
		if [ "$domainvalidateversion" = "D1" ]; then
			# D1 used the optional cksum utility. Where unavailable, its normalized
			# cache and recorded count are accepted once and rewritten as D2.
			if type cksum >/dev/null 2>&1; then
				[ "$(cksum "$domainvalidatecache/$domainvalidatecachefile" | awk '{print $1 "-" $2}')" = "$domainvalidatehash" ] || return 1
			fi
		else
			[ "$(sha256sum "$domainvalidatecache/$domainvalidatecachefile" 2>/dev/null | awk '{print $1}')" = "$domainvalidatehash" ] || return 1
		fi
	done < "$domainvalidatefile"
}

Prepare_Domain_Rule_Update() {
	# Resolve each logical domain once and compile complete ban/whitelist unions.
	# One completed empty lookup is treated as provisional; a second consecutive
	# empty lookup retires the old addresses. Scheduled refreshes bound stale
	# fallback to 24 hours; startup restores any validated content-bound cache.
	domainregistryfile="$1"
	domainupdatemode="$2"
	rulecachedir="${skynetloc}/lists/rules"
	domainstagedir="$TMP_DIR/domain-cache.$$"
	domainworklist="$TMP_DIR/domain-work.$$"
	domainworkstate="$TMP_DIR/domain-work-state.$$"
	domainmanifeststage="${rulestatusmanifest}.tmp.$$"
	domainbanfile="$TMP_DIR/domain-ban.$$"
	domainwhitelistfile="$TMP_DIR/domain-whitelist.$$"
	if [ -e "$rulecachedir" ]; then
		[ -d "$rulecachedir" ] && [ ! -L "$rulecachedir" ] || return 1
	else
		mkdir -p "$rulecachedir" || return 1
	fi
	mkdir -m 700 "$domainstagedir" || return 1
	awk -F '\t' '$1 == "R2" && $4 == "domain" && $7 == "enabled" {printf "%d~%s~%s\n", ++count, $3, $5}' \
		"$domainregistryfile" > "$domainworklist" || return 1
	if Time_Is_Ready; then domainnow="$(date +%s)"; else domainnow="0"; fi
	domainupdatefailed=""
	case "$domainupdatemode" in required|refresh|cached|startup) ;; *) return 1 ;; esac
	domainmanifestinput="$rulestatusmanifest"
	if [ -f "$rulestatusmanifest" ]; then
		Validate_Rule_Status_Manifest "$rulestatusmanifest" "" || return 1
	else
		domainmanifestinput="$TMP_DIR/domain-manifest-empty.$$"
		true > "$domainmanifestinput" || return 1
	fi
	# Load prior health once. This avoids scanning the complete manifest for each
	# domain as the registry grows.
	awk -v status="$domainmanifestinput" '
		BEGIN {
			while ((getline line < status) > 0) {
				n = split(line, field, "\t")
				if (field[1] != "D1" && field[1] != "D2") continue
				key = field[2] SUBSEP tolower(field[3])
				found[key] = 1; state[key] = field[4]; count[key] = field[5]; check[key] = field[6]; success[key] = field[7]
				changed[key] = field[8]
				if (field[1] == "D2") { misses[key] = field[9]; hash[key] = field[10]; cache[key] = field[11] }
				else { misses[key] = 0; hash[key] = field[9]; cache[key] = field[10] }
			}
			close(status)
		}
		{
			n = split($0, work, "~"); key = work[2] SUBSEP tolower(work[3])
			printf "%s~%s~%s~%d~%s~%s~%s~%s~%s~%s~%s~%s\n", work[1], work[2], work[3], \
				found[key] + 0, state[key], count[key] + 0, check[key] + 0, success[key] + 0, changed[key] + 0, \
				misses[key] + 0, hash[key], cache[key]
		}
	' "$domainworklist" > "$domainworkstate" || return 1
	Start_Background_Jobs
	while IFS='~' read -r domainworkerid domainworktarget domainworkvalue _domainoldfound _domainoldstate _domainoldcount _domainoldcheck _domainoldsuccess _domainoldchanged _domainoldmisses _domainoldhash _domainoldcache; do
		[ -n "$domainworkvalue" ] || continue
		(
			domainworkerraw="$TMP_DIR/domain-result.${domainworkerid}.raw"
			domainworkerstate="failed"
			if [ "$domainupdatemode" = "required" ] || [ "$domainupdatemode" = "refresh" ]; then
				if [ "$domainworktarget" = "ban" ]; then domainworkscope="public"; else domainworkscope="all"; fi
				Resolve_Normalized_Domain_IP_List "$domainworkvalue" "$domainworkscope" "" "$domainworkerid" > "$domainworkerraw"
				domainworkerstatus="$?"
				if [ "$domainworkerstatus" = "0" ] \
					&& tr ' ' '\n' < "$domainworkerraw" | Normalize_Domain_Rule_IPs "$domainworktarget" > "$TMP_DIR/domain-result.${domainworkerid}.ips" \
					&& [ -s "$TMP_DIR/domain-result.${domainworkerid}.ips" ]; then
					domainworkerstate="current"
				elif [ "$domainworkerstatus" = "3" ]; then
					domainworkerstate="empty"
				fi
			fi
			rm -f "$domainworkerraw"
			printf '%s\n' "$domainworkerstate" > "$TMP_DIR/domain-result.${domainworkerid}.state"
		) &
		Wait_Background_Job_Slot 4
	done < "$domainworkstate"
	Wait_Background_Jobs
	true > "$domainmanifeststage" && true > "$domainbanfile" && true > "$domainwhitelistfile" || return 1
	while IFS='~' read -r domainworkerid domainworktarget domainworkvalue domainoldfound domainoldstate domainoldcount domainoldcheck domainoldsuccess domainoldchanged domainoldmisses domainoldhash domainoldcache; do
		domainresultstate="$(sed -n '1p' "$TMP_DIR/domain-result.${domainworkerid}.state" 2>/dev/null)"
		domainresultips="$TMP_DIR/domain-result.${domainworkerid}.ips"
		case "$domainoldcheck:$domainoldsuccess:$domainoldchanged:$domainoldmisses" in *[!0-9:]*|*::*|:*) domainoldcheck="0"; domainoldsuccess="0"; domainoldchanged="0"; domainoldmisses="0" ;; esac
		domainresultcheck="$domainnow"
		[ "$domainresultcheck" -gt "0" ] || domainresultcheck="$domainoldcheck"
		domaincachecandidate=""
		domaincachefresh="0"
		if { [ "$domainoldstate" = "current" ] || [ "$domainoldstate" = "cached" ]; } \
			&& [ -n "$domainoldcache" ] && [ "$domainoldcache" != "-" ] \
			&& Validate_Bound_Domain_Rule_Cache "$rulecachedir/$domainoldcache" "$domainworktarget" "$domainoldcount" "$domainoldhash"; then
			domaincachecandidate="$rulecachedir/$domainoldcache"
		elif [ "$domainoldfound" = "0" ] && ! Rule_Migration_Complete \
			&& Extract_Legacy_Domain_IPs "$domainworktarget" "$domainworkvalue" > "$domainresultips" \
			&& [ -s "$domainresultips" ]; then
			domaincachecandidate="$domainresultips"
			domainoldsuccess="$domainnow"
			domainoldchanged="$domainnow"
			domainoldfound="1"
		fi
		if [ -n "$domaincachecandidate" ]; then
			if [ "$domainupdatemode" = "startup" ]; then
				domaincachefresh="1"
			elif [ "$domainoldsuccess" -gt "0" ] 2>/dev/null \
				&& [ "$domainoldsuccess" -le "$domainnow" ] 2>/dev/null \
				&& [ "$((domainnow - domainoldsuccess))" -le "$domaincachegrace" ] 2>/dev/null; then
				domaincachefresh="1"
			fi
		fi
		domainresultmisses="$domainoldmisses"
		case "$domainresultstate" in
			current)
				domainresultmisses="0"
			;;
			empty)
				domainresultmisses=$((domainoldmisses + 1))
				if [ "$domainupdatemode" = "required" ] && [ "$domainoldfound" = "0" ]; then
					domainupdatefailed="${domainupdatefailed}${domainupdatefailed:+ }$domainworkvalue"
					continue
				elif [ "$domainresultmisses" -lt "$domainemptythreshold" ] && [ "$domaincachefresh" = "1" ]; then
					[ "$domaincachecandidate" = "$domainresultips" ] || cp -f "$domaincachecandidate" "$domainresultips" || return 1
					domainresultstate="cached"
				else
					true > "$domainresultips" || return 1
					domainresultstate="empty"
				fi
			;;
			*)
				domainresultmisses="0"
				if [ "$domaincachefresh" = "1" ]; then
					[ "$domaincachecandidate" = "$domainresultips" ] || cp -f "$domaincachecandidate" "$domainresultips" || return 1
					domainresultstate="cached"
			elif [ "$domainupdatemode" = "required" ] && [ "$domainoldfound" = "0" ]; then
					domainupdatefailed="${domainupdatefailed}${domainupdatefailed:+ }$domainworkvalue"
					continue
			else
					true > "$domainresultips" || return 1
					[ "$domainoldsuccess" -gt "0" ] 2>/dev/null && domainresultstate="expired" || domainresultstate="failed"
				fi
			;;
		esac
		if [ "$domainresultstate" = "current" ]; then
			Validate_Domain_Rule_Cache "$domainresultips" "$domainworktarget" || return 1
			domainresulthash="$(sha256sum "$domainresultips" 2>/dev/null | awk '{print $1}')"
			domainresultkey="$(printf '%s:%s\n' "$domainworktarget" "$domainworkvalue" | sha256sum | awk '{print substr($1, 1, 16)}')"
			domaincachefile="domain.${domainresultkey}.${domainresulthash}.list"
			cp -f "$domainresultips" "$domainstagedir/$domaincachefile" || return 1
			domainresultcount="$(wc -l < "$domainresultips" | tr -d ' ')"
			domainresultsuccess="$domainnow"
			if [ "$domainresulthash" = "$domainoldhash" ]; then domainresultchanged="$domainoldchanged"; else domainresultchanged="$domainnow"; fi
		elif [ "$domainresultstate" = "cached" ]; then
			Validate_Domain_Rule_Cache "$domainresultips" "$domainworktarget" || return 1
			domainresulthash="$(sha256sum "$domainresultips" 2>/dev/null | awk '{print $1}')"
			domainresultkey="$(printf '%s:%s\n' "$domainworktarget" "$domainworkvalue" | sha256sum | awk '{print substr($1, 1, 16)}')"
			domaincachefile="domain.${domainresultkey}.${domainresulthash}.list"
			cp -f "$domainresultips" "$domainstagedir/$domaincachefile" || return 1
			domainresultcount="$(wc -l < "$domainresultips" | tr -d ' ')"
			domainresultsuccess="$domainoldsuccess"
			domainresultchanged="$domainoldchanged"
			[ "$domainresultchanged" != "0" ] || domainresultchanged="$domainnow"
		else
			domainresultcount="0"
			domainresultsuccess="$domainoldsuccess"
			domainresulthash="-"
			domaincachefile="-"
			if [ "$domainoldstate:$domainoldhash" = "$domainresultstate:-" ]; then domainresultchanged="$domainoldchanged"; else domainresultchanged="$domainnow"; fi
		fi
		printf 'D2\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
			"$domainworktarget" "$domainworkvalue" "$domainresultstate" "$domainresultcount" "$domainresultcheck" \
			"$domainresultsuccess" "$domainresultchanged" "$domainresultmisses" "$domainresulthash" "$domaincachefile" >> "$domainmanifeststage" || return 1
		if [ "$domainworktarget" = "ban" ]; then
			[ ! -s "$domainresultips" ] || cat "$domainresultips" >> "$domainbanfile" || return 1
		else
			[ ! -s "$domainresultips" ] || cat "$domainresultips" >> "$domainwhitelistfile" || return 1
		fi
	done < "$domainworkstate"
	[ -z "$domainupdatefailed" ] || return 1
	sort -u "$domainbanfile" > "${domainbanfile}.dedup" && mv -f "${domainbanfile}.dedup" "$domainbanfile" || return 1
	sort -u "$domainwhitelistfile" > "${domainwhitelistfile}.dedup" && mv -f "${domainwhitelistfile}.dedup" "$domainwhitelistfile" || return 1
	Validate_Rule_Status_Manifest "$domainmanifeststage" "$domainstagedir" || return 1
	return 0
}

Restore_Domain_Rule_Sets() {
	[ -s "$domainsetsnapshot" ] || return 1
	domainsetrestore="$TMP_DIR/domain-sets-restore.$$"
	domainsetrestorelist="${1:-Skynet-Blacklist Skynet-BlockedRanges Skynet-Whitelist Skynet-BlacklistDomains Skynet-WhitelistDomains}"
	awk -v sets="$domainsetrestorelist" '
		BEGIN {split(sets, wanted, " "); for (i in wanted) include[wanted[i]] = 1}
		$1 == "add" && ($2 in include)
	' "$domainsetsnapshot" > "$domainsetrestore" || return 1
	domainsetstatus="0"
	for domainset in $domainsetrestorelist; do
		grep -qF "create $domainset " "$domainsetsnapshot" || continue
		ipset flush "$domainset" 2>/dev/null || domainsetstatus="1"
	done
	[ ! -s "$domainsetrestore" ] || ipset restore -! < "$domainsetrestore" 2>/dev/null || domainsetstatus="1"
	return "$domainsetstatus"
}

Rollback_Domain_Rule_Update() {
	trap '' INT TERM
	domaintransactionactive="0"
	domainrollbackstatus="0"
	if [ "${domainbanswapped:-0}" = "1" ] || [ "${domainwhitelistswapped:-0}" = "1" ]; then
		domainswaprestored="1"
	else
		domainswaprestored="0"
	fi
	if [ "${domainbanswapped:-0}" = "1" ]; then
		ipset swap "$domainbantmp" Skynet-BlacklistDomains 2>/dev/null || domainswaprestored="0"
		domainbanswapped="0"
	fi
	if [ "${domainwhitelistswapped:-0}" = "1" ]; then
		ipset swap "$domainwhitelisttmp" Skynet-WhitelistDomains 2>/dev/null || domainswaprestored="0"
		domainwhitelistswapped="0"
	fi
	if [ "${domainswapactive:-0}" = "1" ]; then
		Destroy_IPSets "$domainbantmp" "$domainwhitelisttmp"
		domainswapactive="0"
	fi
	if [ "$domainswaprestored" != "1" ] && [ "${domainsetsmodified:-0}" = "1" ]; then
		Restore_Domain_Rule_Sets || { Log error -s "Failed To Restore Domain Rule Sets"; domainrollbackstatus="1"; }
	elif [ "${domainbasechanged:-0}" = "1" ]; then
		Restore_Domain_Rule_Sets "Skynet-Blacklist Skynet-BlockedRanges Skynet-Whitelist" \
			|| { Log error -s "Failed To Restore Legacy Domain Entries"; domainrollbackstatus="1"; }
	fi
	if [ -d "$domaincacheold" ]; then
		for domaincacheoldfile in "$domaincacheold"/domain.*.list; do
			[ -f "$domaincacheoldfile" ] || continue
			domaincachetarget="$rulecachedir/${domaincacheoldfile##*/}"
			domaincachetmp="${domaincachetarget}.tmp.$$"
			cp -f "$domaincacheoldfile" "$domaincachetmp" && chmod 600 "$domaincachetmp" \
				&& mv -f "$domaincachetmp" "$domaincachetarget" || domainrollbackstatus="1"
		done
	fi
	ruleregistryrestore="${skynetrules}.tmp.$$"
	if ! cp -f "$domainregistryold" "$ruleregistryrestore" || ! chmod 600 "$ruleregistryrestore" \
		|| ! mv -f "$ruleregistryrestore" "$skynetrules"; then
		Log error -s "Failed To Restore Rule Registry"
		domainrollbackstatus="1"
	fi
	if [ -f "$domainmanifestold" ]; then
		domainmanifestrestore="${rulestatusmanifest}.tmp.$$"
		if ! cp -f "$domainmanifestold" "$domainmanifestrestore" || ! chmod 600 "$domainmanifestrestore" \
			|| ! mv -f "$domainmanifestrestore" "$rulestatusmanifest"; then
			Log error -s "Failed To Restore Rule Health"
			domainrollbackstatus="1"
		fi
	else
		rm -f "$rulestatusmanifest" || domainrollbackstatus="1"
	fi
	for domaincachetarget in $domainpublishedcaches; do rm -f "$domaincachetarget"; done
	Publish_Domain_Dnsmasq_Config || { Log error -s "Failed To Restore Domain DNS Rules"; domainrollbackstatus="1"; }
	if [ "${domainbasechanged:-0}" = "1" ]; then
		Save_IPSets || { Log error -s "Failed To Persist Restored Domain Rules"; domainrollbackstatus="1"; }
	fi
	[ "${domainrollbackcleanup:-0}" = "1" ] || Set_Cleanup_Traps
	return "$domainrollbackstatus"
}

Apply_Domain_Rule_Update() {
	# Swap both dynamic sets, publish cache/registry state, then persist. Temporary
	# sets retain the exact previous members until the complete transaction commits.
	domainregistrycandidate="$1"
	domainsetsnapshot="$TMP_DIR/domain-sets-old.$$"
	domainmanifestold="$TMP_DIR/domain-manifest-old.$$"
	domainregistryold="$TMP_DIR/domain-registry-old.$$"
	domaincacheold="$TMP_DIR/domain-cache-old.$$"
	domainpublishedcaches=""
	domainlegacyneeded="0"
	domainsetsmodified="0"
	{ ipset save Skynet-BlacklistDomains \
		&& ipset save Skynet-WhitelistDomains; } > "$domainsetsnapshot" 2>/dev/null || return 1
	grep -q '^create Skynet-BlacklistDomains ' "$domainsetsnapshot" \
		&& grep -q '^create Skynet-WhitelistDomains ' "$domainsetsnapshot" || return 1
	if ! Rule_Migration_Complete && grep -qE 'comment "Manual(BanD|WlistD): ' "$skynetipset" 2>/dev/null; then
		domainlegacyneeded="1"
		{ ipset save Skynet-Blacklist \
			&& ipset save Skynet-BlockedRanges \
			&& ipset save Skynet-Whitelist; } >> "$domainsetsnapshot" 2>/dev/null || return 1
		grep -q '^create Skynet-Blacklist ' "$domainsetsnapshot" \
			&& grep -q '^create Skynet-BlockedRanges ' "$domainsetsnapshot" \
			&& grep -q '^create Skynet-Whitelist ' "$domainsetsnapshot" || return 1
	fi
	domainliveban="$TMP_DIR/domain-live-ban.$$"
	domainlivewhitelist="$TMP_DIR/domain-live-whitelist.$$"
	awk '$1 == "add" && $2 == "Skynet-BlacklistDomains" {print $3}' "$domainsetsnapshot" | sort -u > "$domainliveban" || return 1
	awk '$1 == "add" && $2 == "Skynet-WhitelistDomains" {print $3}' "$domainsetsnapshot" | sort -u > "$domainlivewhitelist" || return 1
	if cmp -s "$domainliveban" "$domainbanfile" && cmp -s "$domainlivewhitelist" "$domainwhitelistfile"; then
		domainmembershipchanged="0"
	else
		domainmembershipchanged="1"
	fi
	domainbasechanged="0"
	domainswapactive="0"
	domainbanswapped="0"
	domainwhitelistswapped="0"
	cp -f "$skynetrules" "$domainregistryold" || return 1
	[ ! -f "$rulestatusmanifest" ] || cp -f "$rulestatusmanifest" "$domainmanifestold" || return 1
	mkdir -m 700 "$domaincacheold" || return 1
	if [ -s "$domainmanifestold" ]; then
		awk -F '\t' '$1 == "D1" {print $10} $1 == "D2" && $11 != "-" {print $11}' "$domainmanifestold" | while IFS= read -r domainoldcachefile; do
			[ -f "$rulecachedir/$domainoldcachefile" ] || continue
			cp -f "$rulecachedir/$domainoldcachefile" "$domaincacheold/$domainoldcachefile" || exit 1
		done || return 1
	fi
	domainbanrestore="$TMP_DIR/domain-ban-restore.$$"
	domainwhitelistrestore="$TMP_DIR/domain-whitelist-restore.$$"
	if [ "$domainmembershipchanged" = "0" ] && [ "$domainlegacyneeded" = "0" ]; then
		# Identical unions only need their live timeouts renewed. Registry and cache
		# publication remain transactional, but no set rebuild or persistence write
		# is needed when membership did not change.
		awk '{printf "add Skynet-BlacklistDomains %s timeout 86400 comment \"DomainRule\"\n", $1}' "$domainbanfile" > "$domainbanrestore" || return 1
		awk '{printf "add Skynet-WhitelistDomains %s timeout 86400 comment \"DomainRule\"\n", $1}' "$domainwhitelistfile" > "$domainwhitelistrestore" || return 1
		[ ! -s "$domainbanrestore" ] || ipset restore -! < "$domainbanrestore" || return 1
		[ ! -s "$domainwhitelistrestore" ] || ipset restore -! < "$domainwhitelistrestore" || return 1
	else
		domainbantmp="Skynet-BlacklistDomains-Tmp"
		domainwhitelisttmp="Skynet-WhitelistDomains-Tmp"
		cleanupipsets="${cleanupipsets}${cleanupipsets:+ }$domainbantmp $domainwhitelisttmp"
		Destroy_IPSets "$domainbantmp" "$domainwhitelisttmp"
		ipset -q create "$domainbantmp" hash:ip hashsize 64 maxelem "$((65536 * 8))" comment timeout 86400 || return 1
		ipset -q create "$domainwhitelisttmp" hash:ip hashsize 64 maxelem "$((65536 * 8))" comment timeout 86400 || return 1
		awk -v setname="$domainbantmp" '{printf "add %s %s timeout 86400 comment \"DomainRule\"\n", setname, $1}' "$domainbanfile" > "$domainbanrestore" || return 1
		awk -v setname="$domainwhitelisttmp" '{printf "add %s %s timeout 86400 comment \"DomainRule\"\n", setname, $1}' "$domainwhitelistfile" > "$domainwhitelistrestore" || return 1
		[ ! -s "$domainbanrestore" ] || ipset restore -! < "$domainbanrestore" || return 1
		[ ! -s "$domainwhitelistrestore" ] || ipset restore -! < "$domainwhitelistrestore" || return 1
		trap '' INT TERM
		if ! ipset swap "$domainbantmp" Skynet-BlacklistDomains; then
			Set_Cleanup_Traps
			return 1
		fi
		domainbanswapped="1"
		domainswapactive="1"
		domaintransactionactive="1"
		domainsetsmodified="1"
		if ! ipset swap "$domainwhitelisttmp" Skynet-WhitelistDomains; then
			Rollback_Domain_Rule_Update || Log error -s "Failed To Restore Dynamic Domain Sets"
			return 1
		fi
		domainwhitelistswapped="1"
	fi
	domaintransactionactive="1"
	domainlegacyremove="$TMP_DIR/domain-legacy-remove.$$"
	awk '
		$1 == "add" && ($2 == "Skynet-Blacklist" || $2 == "Skynet-Whitelist") \
			&& ($0 ~ /comment "ManualBanD: / || $0 ~ /comment "ManualWlistD: /) {
			print "del " $2 " " $3
		}
	' "$domainsetsnapshot" > "$domainlegacyremove" || { Rollback_Domain_Rule_Update; return 1; }
	if [ -s "$domainlegacyremove" ]; then
		Apply_IPSet_File "$domainlegacyremove" || { Rollback_Domain_Rule_Update; return 1; }
		domainbasechanged="1"
	fi
	for domaincachecandidate in "$domainstagedir"/domain.*.list; do
		[ -f "$domaincachecandidate" ] || continue
		domaincachetarget="$rulecachedir/${domaincachecandidate##*/}"
		[ ! -L "$domaincachetarget" ] || { Rollback_Domain_Rule_Update; return 1; }
		domaincachetmp="${domaincachetarget}.tmp.$$"
		[ -f "$domaincachetarget" ] || domainpublishedcaches="${domainpublishedcaches}${domainpublishedcaches:+ }$domaincachetarget"
		if ! cp -f "$domaincachecandidate" "$domaincachetmp" || ! chmod 600 "$domaincachetmp" \
			|| ! mv -f "$domaincachetmp" "$domaincachetarget"; then
			Rollback_Domain_Rule_Update
			return 1
		fi
	done
	if [ -L "$rulestatusmanifest" ] || ! chmod 600 "$domainmanifeststage" || ! mv -f "$domainmanifeststage" "$rulestatusmanifest"; then
		Rollback_Domain_Rule_Update
		return 1
	fi
	if [ "$domainregistrycandidate" != "$skynetrules" ]; then
		rulestagefile="$domainregistrycandidate"
		if ! Publish_Staged_Rule_Registry; then
			Rollback_Domain_Rule_Update
			return 1
		fi
	fi
	if ! Publish_Domain_Dnsmasq_Config; then
		Rollback_Domain_Rule_Update
		return 1
	fi
	# Domain members are restored from their own cache; only migration can change
	# automatic base state and require an IPSet snapshot here.
	if [ "$domainbasechanged" = "1" ] && ! Save_IPSets; then
		Rollback_Domain_Rule_Update
		return 1
	fi
	[ "$domainswapactive" != "1" ] || Destroy_IPSets "$domainbantmp" "$domainwhitelisttmp"
	domainswapactive="0"
	domainbanswapped="0"
	domainwhitelistswapped="0"
	domaintransactionactive="0"
	Set_Cleanup_Traps
	nocfg="1"
	# Content-addressed caches not referenced by the committed manifest are stale.
	for domaincachetarget in "$rulecachedir"/domain.*.list; do
		[ -f "$domaincachetarget" ] || continue
		awk -F '\t' -v cache="${domaincachetarget##*/}" '($1 == "D1" && $10 == cache) || ($1 == "D2" && $11 == cache) {found = 1} END {exit !found}' "$rulestatusmanifest" \
			|| rm -f "$domaincachetarget"
	done
	return 0
}

Update_Domain_Rules() {
	domainregistrycandidate="$1"
	domainupdatemode="$2"
	Prepare_Domain_Rule_Update "$domainregistrycandidate" "$domainupdatemode" || return 1
	Apply_Domain_Rule_Update "$domainregistrycandidate"
}

Clear_Registered_Rules() {
	# Remove one logical policy without touching automatic blacklist or whitelist
	# sources. Compiled sets are regenerated from the remaining R2 owners.
	registeredtarget="$1"
	Stage_Rule_Registry_Clear "$registeredtarget" || return "$?"
	registeredclearcandidate="$rulestagefile"
	Apply_Complete_Rule_Registry_Candidate "$registeredclearcandidate" remove || return 1
	nocfg="1"
	return 0
}

Save_IPSets() {
	# The snapshot is offline base state only. Compiled rule, domain, temporary and
	# master sets are rebuilt from their authoritative stores during initialization.
	# Sorting members makes the comparison independent of IPSet insertion order.
	saveipsetraw="$TMP_DIR/skynet.ipset.raw.$$"
	saveipsetadds="$TMP_DIR/skynet.ipset.adds.$$"
	saveipsetwork="$TMP_DIR/skynet.ipset"
	saveipsettmp="${skynetipset}.tmp.$$"
	if ! { ipset save Skynet-Whitelist && ipset save Skynet-Blacklist \
		&& ipset save Skynet-BlockedRanges && ipset save Skynet-IOT; } > "$saveipsetraw" 2>/dev/null \
		|| [ ! -s "$saveipsetraw" ] \
		|| ! awk -v entries="$saveipsetadds" '
			BEGIN { printf "%s", "" > entries }
			$1 == "create" { creates++; print; next }
			$1 == "add" { print > entries; next }
			{ invalid = 1; exit 1 }
			END { if (close(entries) || invalid || creates != 4) exit 1 }
		' "$saveipsetraw" > "$saveipsetwork" \
		|| ! rm -f "$saveipsetraw" \
		|| ! LC_ALL=C sort -k2,2 -k3,3 "$saveipsetadds" >> "$saveipsetwork" \
		|| [ ! -s "$saveipsetwork" ]; then
		rm -f "$saveipsetraw" "$saveipsetadds" "$saveipsetwork" "$saveipsettmp"
		Log error "Failed To Save IPSet Data - Existing File Retained"
		return 1
	fi
	rm -f "$saveipsetraw" "$saveipsetadds"
	if cmp -s "$saveipsetwork" "$skynetipset" 2>/dev/null; then
		rm -f "$saveipsetwork"
		rm -f "$DURABLE_PENDING"
		return 0
	fi
	if cp -f "$saveipsetwork" "$saveipsettmp" && chmod 600 "$saveipsettmp" \
		&& mv -f "$saveipsettmp" "$skynetipset"; then
		rm -f "$saveipsetwork"
		rm -f "$DURABLE_PENDING"
		return 0
	fi
	rm -f "$saveipsetwork" "$saveipsettmp"
	Log error "Failed To Save IPSet Data - Existing File Retained"
	return 1
}

Require_Save_IPSets() {
	Save_IPSets && return 0
	echo "[*] Failed To Save Changes"
	echo
	exit 1
}

Apply_Blacklist_File() {
	# Build the new IP and range sets off-line, then swap both into service. Signals
	# are deferred across the two swaps so they behave as one logical replacement.
	blacklisttempset="Skynet-Blacklist-Tmp"
	rangestempset="Skynet-BlockedRanges-Tmp"
	cleanupipsets="${cleanupipsets}${cleanupipsets:+ }${blacklisttempset} ${rangestempset}"
	blacklistrestore="$TMP_DIR/blacklist.restore"
	rangesrestore="$TMP_DIR/ranges.restore"
	Destroy_IPSets "$blacklisttempset" "$rangestempset"
	if [ ! -s "$1" ] \
		|| ! sed -n "s/^add Skynet-Blacklist /add $blacklisttempset /p" "$1" > "$blacklistrestore" \
		|| ! sed -n "s/^add Skynet-BlockedRanges /add $rangestempset /p" "$1" > "$rangesrestore" \
		|| ! ipset -q create "$blacklisttempset" hash:ip hashsize 64 maxelem "$((65536 * 16))" comment \
		|| ! ipset -q create "$rangestempset" hash:net hashsize 64 maxelem "$((65536 * 6))" comment \
		|| ! ipset restore < "$blacklistrestore" \
		|| ! ipset restore < "$rangesrestore"; then
		Destroy_IPSets "$blacklisttempset" "$rangestempset"
		rm -f "$blacklistrestore" "$rangesrestore"
		return 1
	fi
	rm -f "$blacklistrestore" "$rangesrestore"

	trap '' INT TERM
	if ! ipset swap "$blacklisttempset" Skynet-Blacklist; then
		Destroy_IPSets "$blacklisttempset" "$rangestempset"
		Set_Cleanup_Traps
		return 1
	fi
	if ! ipset swap "$rangestempset" Skynet-BlockedRanges; then
		if ipset swap "$blacklisttempset" Skynet-Blacklist 2>/dev/null; then
			Destroy_IPSets "$blacklisttempset" "$rangestempset"
		else
			# The temporary blacklist still contains the recoverable previous set.
			cleanupipsets="$(printf '%s\n' "$cleanupipsets" | awk -v keep="$blacklisttempset" '{for (i=1;i<=NF;i++) if ($i != keep) output=output (output==""?"":" ") $i} END {print output}')"
			Destroy_IPSets "$rangestempset"
			Log error -s "Blacklist Rollback Failed - Previous Set Retained As $blacklisttempset"
		fi
		Set_Cleanup_Traps
		return 1
	fi
	Destroy_IPSets "$blacklisttempset" "$rangestempset"
	Set_Cleanup_Traps
}

Whitelist_Blocked_Private_IPs() {
	Time_Is_Ready || return 0
	if Is_Enabled "$unbanprivateip" && Is_Enabled "$logmode"; then
		privateipfile="$TMP_DIR/private-whitelist.$$"
		# Extract inbound sources and outbound destinations in one syslog pass. The
		# prefix test mirrors Filter_PrivateIP's reserved IPv4 definition.
		awk '
			function private_ip(ip) {
				return ip ~ /^(0\.|10\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.0\.0\.|192\.0\.2\.|192\.168\.|198\.(1[8-9])\.|198\.51\.100\.|203\.0\.113\.|2(2[4-9]|[3-4][0-9]|5[0-5])\.)/
			}
			/INBOUND/ { field = "SRC=" }
			/OUTBOUND/ { field = "DST=" }
			!field { next }
			{
				for (i = 1; i <= NF; i++) {
					if (index($i, field) != 1) continue
					ip = substr($i, length(field) + 1)
					sub(/,.*/, "", ip)
					if (private_ip(ip) && !seen[ip]++) {
						printf "add Skynet-Whitelist %s comment \"Private IP\"\n", ip
						printf "del Skynet-Blacklist %s\n", ip
					}
					break
				}
				field = ""
			}
		' "${1:-$syslogloc}" > "$privateipfile" || { rm -f "$privateipfile"; return 1; }
		if [ -s "$privateipfile" ]; then
			Apply_IPSet_File "$privateipfile" || { rm -f "$privateipfile"; return 1; }
			Mark_Durable_State_Pending || { rm -f "$privateipfile"; return 1; }
		fi
		rm -f "$privateipfile"
	fi
}

Cleanup_AiProtect_Temp() {
	rm -f "$aiprotectfile" "$aiprotectold" "$aiprotectrecords" "$aiprotectschema" \
		"$aiprotectdomainsraw" "$aiprotectdomains" "$aiprotectmanifest" \
		"$aiprotectcachetmp" "$aiprotectoldmap" "$TMP_DIR"/aiprotect-result.*
}

Resolve_AiProtect_Domains() {
	# Cache contract: domain~latest event~last successful check~positive|negative
	# ~IPv4 list~last failed check. A newer event bypasses both TTLs. Failed
	# refreshes retain a previous positive mapping and are retried weekly instead
	# of on every malware update; older five-field caches load with no failure time.
	aiprotectcache="${skynetloc}/lists/.aiprotect"
	aiprotectcachetmp="${aiprotectcache}.tmp.$$"
	aiprotectmanifest="$TMP_DIR/aiprotect-manifest.$$"
	aiprotectoldmap="$TMP_DIR/aiprotect-old-map.$$"
	aiprotectnow="$(date +%s)"
	aiprotectid="0"
	mkdir -p "${skynetloc}/lists" || return 1
	true > "$aiprotectmanifest" || return 1
	awk '
		index($0, "BanAiProtect: ") {
			domain = $0
			sub(/^.*BanAiProtect: /, "", domain)
			sub(/".*$/, "", domain)
			if (domain != "") {
				if (ips[domain] == "") ips[domain] = $3
				else ips[domain] = ips[domain] " " $3
			}
		}
		END { for (domain in ips) print domain "~" ips[domain] }
	' "$aiprotectold" > "$aiprotectoldmap" || return 1

	Start_Background_Jobs
	while IFS= read -r aiprotectdomain; do
		[ -n "$aiprotectdomain" ] || continue
		aiprotectid="$((aiprotectid + 1))"
		aiprotectevent="$(awk -F '|' -v domain="$aiprotectdomain" '
			$1 == "D" {
				value = tolower($2)
				sub(/^www\./, "", value)
				if (value == domain && $3 > newest) newest = $3
			}
			END { print newest + 0 }
		' "$aiprotectrecords")"
		aiprotectoldline="$(awk -F '~' -v domain="$aiprotectdomain" '$1 == domain {print; exit}' "$aiprotectcache" 2>/dev/null)"
		aiprotectrefresh="1"
		if [ -n "$aiprotectoldline" ]; then
			IFS='~' read -r _aiprotectdomain aiprotectoldevent aiprotectoldchecked aiprotectoldstate aiprotectoldips aiprotectoldfailure <<EOF
$aiprotectoldline
EOF
			case "$aiprotectoldevent" in ""|*[!0-9]*) aiprotectoldevent="0" ;; esac
			case "$aiprotectoldchecked" in ""|*[!0-9]*) aiprotectoldchecked="0" ;; esac
			case "$aiprotectoldfailure" in ""|*[!0-9]*) aiprotectoldfailure="0" ;; esac
			if [ "$aiprotectevent" -le "$aiprotectoldevent" ]; then
				case "$aiprotectoldstate" in
					positive)
						if [ "$aiprotectoldfailure" -gt "$aiprotectoldchecked" ] \
							&& [ "$((aiprotectnow - aiprotectoldfailure))" -lt 604800 ]; then
							aiprotectrefresh="0"
						elif [ "$((aiprotectnow - aiprotectoldchecked))" -lt 86400 ]; then
							aiprotectrefresh="0"
						fi
					;;
					negative) [ "$((aiprotectnow - aiprotectoldchecked))" -lt 604800 ] && aiprotectrefresh="0" ;;
				esac
			fi
		fi
		printf '%s~%s~%s~%s\n' "$aiprotectid" "$aiprotectdomain" "$aiprotectevent" "$aiprotectrefresh" >> "$aiprotectmanifest"
		if [ "$aiprotectrefresh" = "1" ]; then
			(
				aiprotectresolved="$(Resolve_Normalized_Domain_IP_List "$aiprotectdomain" public)" || aiprotectresolved=""
				if [ -n "$aiprotectresolved" ]; then
					printf 'positive~%s\n' "$aiprotectresolved"
				else
					printf 'negative~\n'
				fi > "$TMP_DIR/aiprotect-result.${aiprotectid}"
			) &
			Wait_Background_Job_Slot 4
		fi
	done < "$aiprotectdomains"
	Wait_Background_Jobs

	true > "$aiprotectcachetmp" || return 1
	while IFS='~' read -r aiprotectid aiprotectdomain aiprotectevent aiprotectrefresh; do
		aiprotectoldline="$(awk -F '~' -v domain="$aiprotectdomain" '$1 == domain {print; exit}' "$aiprotectcache" 2>/dev/null)"
		aiprotectoldevent="0"
		aiprotectoldchecked="0"
		aiprotectoldstate=""
		aiprotectoldips=""
		aiprotectoldfailure="0"
		if [ -n "$aiprotectoldline" ]; then
			IFS='~' read -r _aiprotectdomain aiprotectoldevent aiprotectoldchecked aiprotectoldstate aiprotectoldips aiprotectoldfailure <<EOF
$aiprotectoldline
EOF
		elif aiprotectoldips="$(awk -F '~' -v domain="$aiprotectdomain" '$1 == domain {print $2; exit}' "$aiprotectoldmap")" \
			&& [ -n "$aiprotectoldips" ]; then
			aiprotectoldstate="positive"
		fi

		aiprotectstate="$aiprotectoldstate"
		aiprotectips="$aiprotectoldips"
		aiprotectchecked="$aiprotectoldchecked"
		aiprotectfailure="$aiprotectoldfailure"
		if [ "$aiprotectrefresh" = "1" ]; then
			aiprotectresultstate="negative"
			aiprotectresultips=""
			if [ -s "$TMP_DIR/aiprotect-result.${aiprotectid}" ]; then
				IFS='~' read -r aiprotectresultstate aiprotectresultips < "$TMP_DIR/aiprotect-result.${aiprotectid}"
			fi
			if [ "$aiprotectresultstate" = "positive" ] && [ -n "$aiprotectresultips" ]; then
				aiprotectstate="positive"
				aiprotectips="$aiprotectresultips"
				aiprotectchecked="$aiprotectnow"
				aiprotectfailure="0"
			elif [ "$aiprotectoldstate" != "positive" ] || [ -z "$aiprotectoldips" ]; then
				aiprotectstate="negative"
				aiprotectips=""
				aiprotectchecked="$aiprotectnow"
				aiprotectfailure="0"
			else
				aiprotectfailure="$aiprotectnow"
			fi
		fi
		case "$aiprotectchecked" in ""|*[!0-9]*) aiprotectchecked="0" ;; esac
		case "$aiprotectfailure" in ""|*[!0-9]*) aiprotectfailure="0" ;; esac
		printf '%s~%s~%s~%s~%s~%s\n' "$aiprotectdomain" "$aiprotectevent" "$aiprotectchecked" "$aiprotectstate" "$aiprotectips" "$aiprotectfailure" >> "$aiprotectcachetmp" || return 1
		if [ "$aiprotectstate" = "positive" ]; then
			for ip in $aiprotectips; do
				printf 'add Skynet-Blacklist %s comment "BanAiProtect: %s"\n' "$ip" "$aiprotectdomain" >> "$aiprotectfile" || return 1
			done
		fi
	done < "$aiprotectmanifest"
}

Refresh_AiProtect() {
	if Is_Enabled "$banaiprotect" && [ -s /jffs/.sys/AiProtectionMonitor/AiProtectionMonitor.db ]; then
		# SQLite grouping reduces thousands of repeated rows to the values Skynet
		# consumes while retaining each domain's newest event for cache invalidation.
		# The live snapshot also supplies Apply_IPSet_File's rollback, avoiding a
		# second export of the complete blacklist.
		aiprotectfile="$TMP_DIR/aiprotect-update.$$"
		aiprotectold="$TMP_DIR/aiprotect-old.$$"
		aiprotectrecords="$TMP_DIR/aiprotect-records.$$"
		aiprotectschema="$TMP_DIR/aiprotect-schema.$$"
		aiprotectdomainsraw="$TMP_DIR/aiprotect-domains.raw"
		aiprotectdomains="$TMP_DIR/aiprotect-domains.list"
		if ! ipset save Skynet-Blacklist > "$aiprotectold" 2>/dev/null; then
			Cleanup_AiProtect_Temp
			return 1
		fi
		if ! awk '
			$1 == "add" && $2 == "Skynet-Blacklist" && index($0, "BanAiProtect") {
				printf "del Skynet-Blacklist %s\n", $3
			}' "$aiprotectold" > "$aiprotectfile"; then
			Cleanup_AiProtect_Temp
			return 1
		fi
		if ! sqlite3 -separator '|' /jffs/.sys/AiProtectionMonitor/AiProtectionMonitor.db 'PRAGMA table_info(monitor);' > "$aiprotectschema" \
			|| ! awk -F '|' '$2 == "timestamp" {timestamp=1} $2 == "src" {src=1} $2 == "dst" {dst=1} END {exit !(timestamp && src && dst)}' "$aiprotectschema" \
			|| ! sqlite3 -separator '|' /jffs/.sys/AiProtectionMonitor/AiProtectionMonitor.db '
			SELECT "S", src, MAX(timestamp) FROM monitor GROUP BY src
			UNION ALL
			SELECT "D", lower(dst), MAX(timestamp) FROM monitor GROUP BY lower(dst);
		' > "$aiprotectrecords"; then
			Cleanup_AiProtect_Temp
			return 1
		fi
		awk -F '|' '$1 == "S" { print $2 }' "$aiprotectrecords" | Filter_IP | Filter_PrivateIP \
			| awk '{printf "add Skynet-Blacklist %s comment \"BanAiProtect\"\n", $1 }' >> "$aiprotectfile"
		if ! awk '
			function is_ipv4(value, part, count, i) {
				count = split(value, part, ".")
				if (count != 4) return 0
				for (i = 1; i <= 4; i++) {
					if (part[i] !~ /^[0-9]+$/ || part[i] < 0 || part[i] > 255) return 0
				}
				return 1
			}
			BEGIN { FS = "|" }
			$1 == "D" {
				value = $2
				if (index(value, ":") == 0 && !is_ipv4(value)) print value
			}
		' "$aiprotectrecords" > "$aiprotectdomainsraw" \
			|| ! Normalize_Domain_List "$aiprotectdomainsraw" > "$aiprotectdomains"; then
			Cleanup_AiProtect_Temp
			return 1
		fi
		Resolve_AiProtect_Domains || { Cleanup_AiProtect_Temp; return 1; }
		if [ -s "$aiprotectfile" ] && ! Apply_IPSet_File "$aiprotectfile" "$aiprotectold"; then
			Cleanup_AiProtect_Temp
			return 1
		fi
		if [ -n "$aiprotectcachetmp" ] && ! mv -f "$aiprotectcachetmp" "$aiprotectcache"; then
			Log error -s "Failed To Save AiProtection Lookup Cache"
		fi
		Cleanup_AiProtect_Temp
	fi
}


Restore_IPSet_Snapshot() {
	ipsetrestorefile="$TMP_DIR/ipset-restore.$$"
	awk '$1 == "add"' "$2" > "$ipsetrestorefile" \
		|| { rm -f "$ipsetrestorefile"; return 1; }
	if ipset flush "$1" 2>/dev/null \
		&& { [ ! -s "$ipsetrestorefile" ] || ipset restore < "$ipsetrestorefile" 2>/dev/null; }; then
		rm -f "$ipsetrestorefile"
		return 0
	fi
	rm -f "$ipsetrestorefile"
	return 1
}

Whitelist_Extra() {
	sharedwhitelist="/jffs/addons/shared-whitelists/shared-Skynet2-whitelist"
	sharedwhitelisttmp="${sharedwhitelist}.tmp.$$"
	{
		printf '%s\n' \
			"ipdeny.com" \
			"ipapi.co" \
			"api.db-ip.com" \
			"api.bgpview.io" \
			"asn.ipinfo.app" \
			"speedguide.net" \
			"otx.alienvault.com" \
			"github.com" \
			"raw.githubusercontent.com" \
			"iplists.firehol.org" \
			"astrill.com" \
			"strongpath.net" \
			"snbforums.com" \
			"bin.entware.net" \
			"nwsrv-ns1.asus.com"
		printf '%s\n' "$(nvram get firmware_server)"
		printf '%s\n' "$(nvram get ntp_server0)"
		printf '%s\n' "$(nvram get ntp_server1)"
	} > "$sharedwhitelisttmp" || { rm -f "$sharedwhitelisttmp"; return 1; }
	if [ -f "$sharedwhitelist" ] && cmp -s "$sharedwhitelisttmp" "$sharedwhitelist"; then
		rm -f "$sharedwhitelisttmp"
	else
		if ! chmod 644 "$sharedwhitelisttmp" || ! mv -f "$sharedwhitelisttmp" "$sharedwhitelist"; then
			rm -f "$sharedwhitelisttmp"
			return 1
		fi
	fi
}

Fetch_CDN_Whitelist() {
	cdnworkerid="$1"
	cdnworkerlabel="$2"
	cdnworkerformat="$3"
	cdnworkerurl="$4"
	cdnworkerbase="$TMP_DIR/cdn-whitelist.${cdnworkerid}"
	cdnworkerraw="${cdnworkerbase}.raw"
	cdnworkervalues="${cdnworkerbase}.values"
	cdnworkeroutput="${cdnworkerbase}.restore"
	cdnworkerstatus="${cdnworkerbase}.status"
	cdnworkerparsed="0"
	rm -f "$cdnworkerraw" "$cdnworkervalues" "$cdnworkeroutput" "$cdnworkerstatus"

	if Curl_Fetch -o "$cdnworkerraw" "$cdnworkerurl" 2>/dev/null && Contains_IPRange < "$cdnworkerraw"; then
		case "$cdnworkerformat" in
			lines)
				awk '/^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)([[:space:]]|$)/ { print $1 }' \
					"$cdnworkerraw" > "$cdnworkervalues"
			;;
			embedded)
				# POSIX AWK has no RT variable. Repeatedly consume each matched IPv4
				# token so JSON providers retain the old embedded-data behaviour.
				awk -v label="$cdnworkerlabel" '{
					line = $0
					pattern = "(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(/(1?[0-9]|2?[0-9]|3?[0-2]))?)"
					while (match(line, pattern)) {
						value = substr(line, RSTART, RLENGTH)
						print value
						line = substr(line, RSTART + RLENGTH)
					}
				}' "$cdnworkerraw" > "$cdnworkervalues"
			;;
		esac
		if [ -s "$cdnworkervalues" ]; then
			Filter_PrivateIP < "$cdnworkervalues" | awk -v label="$cdnworkerlabel" '!seen[$1]++ {
				printf "add Skynet-Whitelist %s comment \"CDN-Whitelist: %s\"\n", $1, label
			}' > "$cdnworkeroutput" && [ -s "$cdnworkeroutput" ] && cdnworkerparsed="1"
		fi
	fi
	rm -f "$cdnworkerraw" "$cdnworkervalues"
	if [ "$cdnworkerparsed" = "1" ] && [ -s "$cdnworkeroutput" ]; then
		printf 'current\n' > "$cdnworkerstatus"
		return 0
	fi
	rm -f "$cdnworkeroutput"
	printf 'failed\n' > "$cdnworkerstatus"
	return 1
}

Whitelist_CDN() {
	if Is_Enabled "$cdnwhitelist"; then
		# Fetch providers concurrently, but assemble their validated results in the
		# original provider order. Any failure retains every existing dynamic CDN
		# entry; the four static resolver addresses remain available.
		cdnlist="$TMP_DIR/cdn-whitelist"
		cdnmanifest="${cdnlist}.sources"
		cdnsnapshot="${cdnlist}.old"
		cdnrestore="${cdnlist}.restore"
		cdntransaction="${cdnlist}.transaction"
		cdncurrent="${cdnlist}.current"
		cdnwanted="${cdnlist}.wanted"
		cdnstatus="0"
		cdnresult="updated"
		cdnfailedsource=""
		cdntab="$(printf '\t')"
		IFS= read -r officeuuid < /proc/sys/kernel/random/uuid || officeuuid="$$"
		{
			printf '1\tAS714\tlines\thttps://asn.ipinfo.app/api/text/list/AS714\n'
			printf '2\tAS12222\tlines\thttps://asn.ipinfo.app/api/text/list/AS12222\n'
			printf '3\tAS16625\tlines\thttps://asn.ipinfo.app/api/text/list/AS16625\n'
			printf '4\tAS33438\tlines\thttps://asn.ipinfo.app/api/text/list/AS33438\n'
			printf '5\tAS20446\tlines\thttps://asn.ipinfo.app/api/text/list/AS20446\n'
			printf '6\tAS54113\tlines\thttps://asn.ipinfo.app/api/text/list/AS54113\n'
			printf '7\tAS36459\tlines\thttps://asn.ipinfo.app/api/text/list/AS36459\n'
			printf '8\tCloudFlare\tlines\thttps://www.cloudflare.com/ips-v4\n'
			printf '9\tAmazon\tembedded\thttps://ip-ranges.amazonaws.com/ip-ranges.json\n'
			printf '10\tGitHub\tembedded\thttps://api.github.com/meta\n'
			printf '11\tMicrosoft365\tembedded\thttps://endpoints.office.com/endpoints/worldwide?clientrequestid=%s\n' "$officeuuid"
		} > "$cdnmanifest" || return 1

		Start_Background_Jobs
		while IFS="$cdntab" read -r cdnid cdnlabel cdnformat cdnurl; do
			Fetch_CDN_Whitelist "$cdnid" "$cdnlabel" "$cdnformat" "$cdnurl" &
			Wait_Background_Job_Slot 4
		done < "$cdnmanifest"
		Wait_Background_Jobs
		true > "$cdnlist" || return 1
		while IFS="$cdntab" read -r cdnid cdnlabel cdnformat cdnurl; do
			cdnstate=""
			[ ! -s "${cdnlist}.${cdnid}.status" ] || IFS= read -r cdnstate < "${cdnlist}.${cdnid}.status"
			if [ "$cdnstate" != "current" ] \
				|| ! cat "${cdnlist}.${cdnid}.restore" >> "$cdnlist"; then
				cdnstatus="1"
				cdnresult="source"
				cdnfailedsource="$cdnlabel"
				break
			fi
		done < "$cdnmanifest"

		printf '%s\n' \
			'add Skynet-Whitelist 8.8.8.8 comment "CDN-Whitelist: GoogleDNS"' \
			'add Skynet-Whitelist 8.8.4.4 comment "CDN-Whitelist: GoogleDNS"' \
			'add Skynet-Whitelist 1.1.1.1 comment "CDN-Whitelist: CloudFlareDNS"' \
			'add Skynet-Whitelist 1.0.0.1 comment "CDN-Whitelist: CloudFlareDNS"' >> "$cdnlist"

		if [ "$cdnstatus" = "0" ]; then
			if ipset save Skynet-Whitelist > "$cdnsnapshot" 2>/dev/null \
				&& awk '!x[$3]++' "$cdnlist" > "$cdnrestore" \
				&& [ -s "$cdnrestore" ]; then
				# Compare canonical entry keys rather than IPSet hash order or comments.
				# A /32 and its host form are equivalent once loaded into hash:net.
				awk '/CDN-Whitelist:/ { entry=$3; sub(/\/32$/, "", entry); print entry }' "$cdnsnapshot" | sort -u > "$cdncurrent"
				awk '{ entry=$3; sub(/\/32$/, "", entry); print entry }' "$cdnrestore" | sort -u > "$cdnwanted"
				if cmp -s "$cdncurrent" "$cdnwanted"; then
					cdnresult="current"
				else
					if sed '\~^add Skynet-Whitelist ~!d;\~CDN-Whitelist~!d;s~ comment.*~~;s~add~del~' "$cdnsnapshot" > "$cdntransaction" \
						&& cat "$cdnrestore" >> "$cdntransaction" \
						&& Apply_IPSet_File "$cdntransaction" "$cdnsnapshot"; then
						cdnresult="updated"
					else
						cdnstatus="1"
						cdnresult="apply"
					fi
				fi
			else
				cdnstatus="1"
				cdnresult="apply"
			fi
		fi
		rm -f "$cdnlist" "${cdnlist}."*
		[ "$cdnstatus" = "0" ]
	else
		Remove_IPSet_Entries Skynet-Whitelist "CDN-Whitelist" || return 1
	fi
}

Netmask_To_Prefix() {
	# Accept only contiguous dotted IPv4 netmasks.
	printf '%s\n' "$1" | awk -F '.' '
		NF != 4 { exit 1 }
		{
			for (i = 1; i <= 4; i++) {
				if ($i == 255) bits = 8
				else if ($i == 254) bits = 7
				else if ($i == 252) bits = 6
				else if ($i == 248) bits = 5
				else if ($i == 240) bits = 4
				else if ($i == 224) bits = 3
				else if ($i == 192) bits = 2
				else if ($i == 128) bits = 1
				else if ($i == 0) bits = 0
				else exit 1
				if (zero && bits != 0) exit 1
				if (bits != 8) zero = 1
				prefix += bits
			}
			print prefix
		}'
}

Whitelist_VPN() {
	# Build VPN whitelist entries from Merlin's NVRAM. OpenVPN server pools use
	# their configured netmask and remote client endpoints use a /24 network.
	vpnentries="$TMP_DIR/vpn-entries.$$"
	vpnvalidated="$TMP_DIR/vpn-validated.$$"
	vpnrestore="$TMP_DIR/vpn-restore.$$"
	vpnsnapshot="$TMP_DIR/vpn-snapshot.$$"
	true > "$vpnentries" || return 1
	# Enabled server pools are authoritative before their interfaces exist. Use
	# their real netmasks; generic vpn_server keys support older Merlin builds.
	for vpnserver in vpn_server1 vpn_server2; do
		vpnstate="$(nvram get "${vpnserver}_state")"
		[ "$vpnstate" != "0" ] || continue
		vpnsubnet="$(nvram get "${vpnserver}_sn")"
		vpnnetmask="$(nvram get "${vpnserver}_nm")"
		if [ -z "$vpnsubnet" ] && [ "$vpnserver" = "vpn_server1" ]; then
			vpnserver="vpn_server"
			vpnstate="$(nvram get "${vpnserver}_state")"
			[ "$vpnstate" != "0" ] || continue
			vpnsubnet="$(nvram get "${vpnserver}_sn")"
			vpnnetmask="$(nvram get "${vpnserver}_nm")"
		fi
		vpnprefix="$(Netmask_To_Prefix "$vpnnetmask" 2>/dev/null)" || vpnprefix=""
		[ -n "$vpnsubnet" ] && [ -n "$vpnprefix" ] \
			&& printf '%s/%s~nvram: %s\n' "$vpnsubnet" "$vpnprefix" "$vpnserver" >> "$vpnentries"
	done

	# Merlin's resolved endpoint is authoritative. Hostnames are not treated as
	# client networks and startup never performs network lookups for VPN policy.
	for vpnclient in vpn_client1 vpn_client2 vpn_client3 vpn_client4 vpn_client5; do
		vpnendpoint="$(nvram get "${vpnclient}_rip")"
		if ! printf '%s\n' "$vpnendpoint" | Filter_IP >/dev/null; then
			vpnaddress="$(nvram get "${vpnclient}_addr")"
			printf '%s\n' "$vpnaddress" | Filter_IP >/dev/null || continue
			vpnendpoint="$vpnaddress"
		fi
		List_To_Lines "$vpnendpoint" | while IFS= read -r vpnaddress; do
			[ -n "$vpnaddress" ] || continue
			printf '%s.0/24~nvram: %s_addr\n' "${vpnaddress%.*}" "$vpnclient" >> "$vpnentries"
		done
	done
	if [ "$(nvram get wgc_enable)" = "1" ]; then
		vpnendpoint="$(nvram get wgc_ep_addr)"
		printf '%s\n' "$vpnendpoint" | Filter_IP >/dev/null || vpnendpoint=""
		List_To_Lines "$vpnendpoint" | while IFS= read -r vpnaddress; do
			[ -n "$vpnaddress" ] || continue
			printf '%s.0/24~nvram: wgc_ep_addr\n' "${vpnaddress%.*}" >> "$vpnentries"
		done
	fi
	if [ -f "/dev/astrill/openvpn.conf" ]; then
		vpnendpoint="$(awk '$1 == "remote" {print $2; exit}' /dev/astrill/openvpn.conf)"
		printf '%s\n' "$vpnendpoint" | Filter_IP >/dev/null || vpnendpoint=""
		List_To_Lines "$vpnendpoint" | while IFS= read -r vpnaddress; do
			[ -n "$vpnaddress" ] || continue
			printf '%s.0/24~nvram: Astrill_VPN\n' "${vpnaddress%.*}" >> "$vpnentries"
		done
	fi

	# Validate the complete NVRAM result before taking a live snapshot or
	# deleting an old VPN entry. One malformed network aborts the whole refresh.
	vpninvalid="0"
	true > "$vpnvalidated" || { rm -f "$vpnentries" "$vpnrestore" "$vpnsnapshot"; return 1; }
	while IFS='~' read -r vpnnetwork vpnsource; do
		[ -n "$vpnnetwork" ] || continue
		if [ "$vpnnetwork" = "0.0.0.0/0" ] || [ -z "$vpnsource" ] \
			|| ! printf '%s\n' "$vpnnetwork" | Is_IPRange; then
			vpninvalid="1"
			break
		fi
		printf '%s~%s\n' "$vpnnetwork" "$vpnsource" >> "$vpnvalidated" || { vpninvalid="1"; break; }
	done < "$vpnentries"
	if [ "$vpninvalid" = "1" ]; then
		Log error -s "Invalid VPN NVRAM Network Detected - Existing Entries Retained"
		rm -f "$vpnentries" "$vpnvalidated" "$vpnrestore" "$vpnsnapshot"
		return 1
	fi
	awk -F '~' '!seen[$1]++ {print}' "$vpnvalidated" > "$vpnentries" \
		|| { rm -f "$vpnentries" "$vpnvalidated" "$vpnrestore" "$vpnsnapshot"; return 1; }

	ipset save Skynet-Whitelist > "$vpnsnapshot" 2>/dev/null || { rm -f "$vpnentries" "$vpnvalidated" "$vpnrestore" "$vpnsnapshot"; return 1; }
	awk '
		$1 == "add" && $2 == "Skynet-Whitelist" && (index($0, "VPN-Whitelist:") || index($0, "nvram: vpn_")) {
			print "del Skynet-Whitelist " $3
		}' "$vpnsnapshot" > "$vpnrestore" || { rm -f "$vpnentries" "$vpnvalidated" "$vpnrestore" "$vpnsnapshot"; return 1; }
	awk -F '~' '!seen[$1]++ {print}' "$vpnentries" | while IFS='~' read -r vpnnetwork vpnsource; do
		printf 'add Skynet-Whitelist %s comment "VPN-Whitelist: %s"\n' "$vpnnetwork" "$vpnsource"
	done >> "$vpnrestore"
	if [ -s "$vpnrestore" ] && ! Apply_IPSet_File "$vpnrestore" "$vpnsnapshot"; then
		rm -f "$vpnentries" "$vpnvalidated" "$vpnrestore" "$vpnsnapshot"
		return 1
	fi
	rm -f "$vpnentries" "$vpnvalidated" "$vpnrestore" "$vpnsnapshot"
}

Publish_Domain_Dnsmasq_Config() {
	Validate_Rule_Registry "$skynetrules" || return 1
	# Merlin's dnsmasq adds current answers for the configured domain and all of
	# its subdomains to the matching dynamic IPSet. Rows are grouped to keep the
	# persistent custom configuration compact.
	dnsmasqfile="/jffs/configs/dnsmasq.conf.add"
	dnsmasqtmp="${dnsmasqfile}.tmp.$$"
	dnsmasqbackup="$TMP_DIR/dnsmasq.conf.add.old.$$"
	dnsmasqrestore="${dnsmasqfile}.restore.$$"
	dnsmasqwhitelist="$TMP_DIR/dnsmasq-whitelist.$$"
	dnsmasqblacklist="$TMP_DIR/dnsmasq-blacklist.$$"
	dnsmasqcandidates="$TMP_DIR/dnsmasq-candidates.$$"
	[ ! -L "$dnsmasqfile" ] || return 1
	dnsmasqhadfile="0"
	if [ -f "$dnsmasqfile" ]; then
		dnsmasqhadfile="1"
		sed '\~# Skynet~d' "$dnsmasqfile" > "$dnsmasqtmp" || return 1
	else
		true > "$dnsmasqtmp" || return 1
	fi
	true > "$dnsmasqcandidates" || return 1
	for dnsmasqshared in /jffs/addons/shared-whitelists/shared-*-whitelist; do
		[ -f "$dnsmasqshared" ] || continue
		case "${dnsmasqshared##*/}" in shared-Skynet-whitelist|shared-Skynet2-whitelist) continue ;; esac
		Strip_Domain "$dnsmasqshared" >> "$dnsmasqcandidates" 2>/dev/null || {
			rm -f "$dnsmasqtmp" "$dnsmasqwhitelist" "$dnsmasqblacklist" "$dnsmasqcandidates"
			return 1
		}
	done
	awk -F '\t' '$1 == "R2" && $3 == "whitelist" && $4 == "domain" && $7 == "enabled" {print $5}' "$skynetrules" >> "$dnsmasqcandidates" 2>/dev/null \
		|| { rm -f "$dnsmasqtmp" "$dnsmasqwhitelist" "$dnsmasqblacklist" "$dnsmasqcandidates"; return 1; }
	true > "$dnsmasqwhitelist" || return 1
	while IFS= read -r dnsmasqdomain; do
		dnsmasqdomain="$(Normalize_Domain "$dnsmasqdomain" 2>/dev/null)" || continue
		printf '%s\n' "$dnsmasqdomain" >> "$dnsmasqwhitelist" || return 1
	done < "$dnsmasqcandidates"
	if ! sort -u "$dnsmasqwhitelist" > "${dnsmasqwhitelist}.sorted" \
		|| ! mv -f "${dnsmasqwhitelist}.sorted" "$dnsmasqwhitelist"; then
		rm -f "$dnsmasqtmp" "$dnsmasqwhitelist" "${dnsmasqwhitelist}.sorted" "$dnsmasqblacklist" "$dnsmasqcandidates"
		return 1
	fi
	awk -F '\t' '$1 == "R2" && $3 == "ban" && $4 == "domain" && $7 == "enabled" {print $5}' "$skynetrules" 2>/dev/null \
		| awk 'NF && !seen[tolower($0)]++ {print tolower($0)}' > "$dnsmasqblacklist" \
		|| { rm -f "$dnsmasqtmp" "$dnsmasqwhitelist" "$dnsmasqblacklist" "$dnsmasqcandidates"; return 1; }
	for dnsmasqset in Skynet-WhitelistDomains Skynet-BlacklistDomains; do
		if [ "$dnsmasqset" = "Skynet-WhitelistDomains" ]; then dnsmasqsource="$dnsmasqwhitelist"; else dnsmasqsource="$dnsmasqblacklist"; fi
		awk -v setname="$dnsmasqset" '
			NF {
				line = line (count == 0 ? "ipset=/" : "/") $0
				count++
				if (count == 20) {
					print line "/" setname " # Skynet"
					line = ""
					count = 0
				}
			}
			END { if (count) print line "/" setname " # Skynet" }
		' "$dnsmasqsource" >> "$dnsmasqtmp" \
			|| { rm -f "$dnsmasqtmp" "$dnsmasqwhitelist" "$dnsmasqblacklist" "$dnsmasqcandidates"; return 1; }
	done
	rm -f "$dnsmasqwhitelist" "$dnsmasqblacklist" "$dnsmasqcandidates"
	if [ -f "$dnsmasqfile" ] && cmp -s "$dnsmasqtmp" "$dnsmasqfile"; then
		rm -f "$dnsmasqtmp"
		return 0
	fi
	# Validate the complete candidate before replacing the live custom file. If
	# dnsmasq rejects the published file, restore its exact previous contents.
	dnsmasqpublished="0"
	if { [ "$dnsmasqhadfile" = "0" ] || cp -f "$dnsmasqfile" "$dnsmasqbackup"; } \
		&& dnsmasq --test --conf-file="$dnsmasqtmp" >/dev/null 2>&1 \
		&& chmod 644 "$dnsmasqtmp" && mv -f "$dnsmasqtmp" "$dnsmasqfile" \
		&& dnsmasqpublished="1" && service restart_dnsmasq >/dev/null 2>&1; then
		dnsmasqtmp=""
		return 0
	else
		if [ "$dnsmasqpublished" = "1" ] && [ "$dnsmasqhadfile" = "1" ]; then
			if ! cp -f "$dnsmasqbackup" "$dnsmasqrestore" || ! chmod 644 "$dnsmasqrestore" \
				|| ! mv -f "$dnsmasqrestore" "$dnsmasqfile"; then
				Log error -s "Failed To Restore DNS Configuration"
			fi
		elif [ "$dnsmasqpublished" = "1" ]; then
			rm -f "$dnsmasqfile"
		fi
		[ "$dnsmasqpublished" != "1" ] || service restart_dnsmasq >/dev/null 2>&1 || true
		rm -f "$dnsmasqtmp" "$dnsmasqrestore"
		return 1
	fi
}

Whitelist_Shared() {
	# NVRAM stores these as whitespace-separated resolver pairs.
	# shellcheck disable=SC2046
	set -- $(nvram get wan_dns)
	sharedwandns1="${1:-}"
	sharedwandns2="${2:-}"
	# shellcheck disable=SC2046
	set -- $(nvram get wan0_dns)
	sharedwan0dns1="${1:-}"
	sharedwan0dns2="${2:-}"
	# shellcheck disable=SC2046
	set -- $(nvram get wan0_xdns)
	sharedwan0xdns1="${1:-}"
	sharedwan0xdns2="${2:-}"
	echo "add Skynet-Whitelist $(nvram get wan0_ipaddr) comment \"nvram: wan0_ipaddr\"
	add Skynet-Whitelist $(LAN_CIDR_Lookup "$(nvram get "lan_ipaddr")") comment \"nvram: lan_ipaddr\"
	add Skynet-Whitelist $(nvram get wan_dns1_x) comment \"nvram: wan_dns1_x\"
	add Skynet-Whitelist $(nvram get wan_dns2_x) comment \"nvram: wan_dns2_x\"
	add Skynet-Whitelist $(nvram get wan0_dns1_x) comment \"nvram: wan0_dns1_x\"
	add Skynet-Whitelist $(nvram get wan0_dns2_x) comment \"nvram: wan0_dns2_x\"
	add Skynet-Whitelist $sharedwandns1 comment \"nvram: wan_dns\"
	add Skynet-Whitelist $sharedwandns2 comment \"nvram: wan_dns\"
	add Skynet-Whitelist $sharedwan0dns1 comment \"nvram: wan0_dns\"
	add Skynet-Whitelist $sharedwan0dns2 comment \"nvram: wan0_dns\"
	add Skynet-Whitelist $sharedwan0xdns1 comment \"nvram: wan0_xdns\"
	add Skynet-Whitelist $sharedwan0xdns2 comment \"nvram: wan0_xdns\"
	add Skynet-Whitelist 192.30.252.0/22 comment \"nvram: GitHub Content Server\"
	add Skynet-Whitelist 127.0.0.0/8 comment \"nvram: Localhost\"" | tr -d "\t" | Filter_IPLine | ipset restore -! 2>/dev/null

	Publish_Domain_Dnsmasq_Config || return 1
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
		grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' /opt/var/lib/unbound/root.hints \
			| awk '{printf "add Skynet-Whitelist %s comment \"nvram: Root DNS Server\"\n", $1 }' | ipset restore -!
	fi
}

#############################
#- Statistics And WebUI Data -#
#############################

Escape_JS() {
	# Generated data is embedded inside single-quoted JavaScript strings. Escape
	# backslashes and quotes here so log content cannot break the output script.
	awk '
		BEGIN { quote = sprintf("%c", 39); first = 1 }
		function escape(value, i, char, output) {
			output = ""
			for (i = 1; i <= length(value); i++) {
				char = substr(value, i, 1)
				if (char == "\\") output = output "\\\\"
				else if (char == quote) output = output "\\" quote
				else if (char != "\r") output = output char
			}
			return output
		}
		{
			if (!first) printf "\\n"
			printf "%s", escape($0)
			first = 0
		}
	'
}

Write_Stats_ToJS() {
	if [ -f "$1" ]; then
		jsvalue="$(Escape_JS < "$1")" || return 1
	else
		jsvalue="$(printf '%s' "$1" | Escape_JS)" || return 1
	fi
	printf "function %s() {\n\tdocument.getElementById(\"%s\").innerHTML = '%s'\n}\n\n" "$3" "$4" "$jsvalue" >> "$2"
}

Write_Data_ToJS() {
	# Input rows use '~' as an internal delimiter. Each requested variable maps
	# to the next column. One awk process emits every array while the input is in
	# memory, avoiding a separate file scan and process for every column.
	jsinputfile="$1"
	jsoutputfile="$2"
	shift 2
	jsvars=""
	for jsvar in "$@"; do
		jsvars="${jsvars}${jsvars:+~}${jsvar}"
	done
	[ -n "$jsvars" ] || return 0
	awk -F "~" -v names="$jsvars" '
		BEGIN {
			quote = sprintf("%c", 39)
			columns = split(names, variable, "~")
		}
		function escape(value, j, char, output) {
			output = ""
			for (j = 1; j <= length(value); j++) {
				char = substr(value, j, 1)
				if (char == "\\") output = output "\\\\"
				else if (char == quote) output = output "\\" quote
				else if (char != "\r") output = output char
			}
			return output
		}
		{
			for (column = 1; column <= columns; column++)
				value[column, NR] = escape($column)
		}
		END {
			for (column = 1; column <= columns; column++) {
				print "var " variable[column] ";"
				print variable[column] " = [];"
				printf "%s.unshift(", variable[column]
				if (NR == 0) printf "%s%s", quote, quote
				for (row = 1; row <= NR; row++) {
					if (row > 1) printf ", "
					printf "%s%s%s", quote, value[column, row], quote
				}
				print ");\n"
			}
		}
	' "$jsinputfile" >> "$jsoutputfile" || return 1
	unset "jsvars" "jsvar"
}

Build_Stats_Log_Index() {
	# Parse the block log once into small purpose-specific indexes. This avoids
	# rescanning the full router log for every CLI table and WebUI chart.
	statsindexsource="$1"
	statsindexpath="$2"
	statsindexproto="$3"
	for statsindexfile in inbound-src inbound-dpt inbound-spt outbound-src outbound-dst outbound-all-dst outbound-http-dst invalid-src iot-dst activity span summary; do
		true > "${statsindexpath}/${statsindexfile}.txt" || return 1
	done

	awk -v path="$statsindexpath" -v proto="$statsindexproto" -v today="$(date '+%b %e')" -v hour="$(date '+%H')" '
		# Values in kernel logs end at the next space or comma.
		function field_value(field, position, value) {
			position = index($0, " " field "=")
			if (!position) return ""
			value = substr($0, position + length(field) + 2)
			sub(/[ ,].*/, "", value)
			return value
		}
		BEGIN { hour += 0 }
		{
			if ($0 !~ /\[BLOCKED - (INBOUND|OUTBOUND|INVALID|IOT)\]/) next
			{
				events++
				stamp = $1 " " $2 " " $3
				if (first == "") first = stamp
				last = stamp
				if ($0 ~ /\[BLOCKED - (INBOUND|INVALID)\]/) summaryvalue = field_value("SRC")
				else if ($0 ~ /\[BLOCKED - OUTBOUND\]/) summaryvalue = field_value("DST")
				else summaryvalue = ""
				if (summaryvalue ~ /^[0-9.]+$/) unique[summaryvalue] = 1
			}
			if (proto != "" && index($0, "PROTO=" proto " ") == 0) next
			if ($0 ~ /\[BLOCKED - INBOUND\]/) {
				if ((value = field_value("SRC")) != "") print value >> path "/inbound-src.txt"
				if ((value = field_value("DPT")) != "") print value >> path "/inbound-dpt.txt"
				if ((value = field_value("SPT")) != "") print value >> path "/inbound-spt.txt"
			} else if ($0 ~ /\[BLOCKED - OUTBOUND\]/) {
				if ((value = field_value("SRC")) != "") print value >> path "/outbound-src.txt"
				if ((value = field_value("DST")) != "") {
					print value >> path "/outbound-all-dst.txt"
					if (field_value("DPT") ~ /^(80|443)$/) print value >> path "/outbound-http-dst.txt"
					else print value >> path "/outbound-dst.txt"
				}
			} else if ($0 ~ /\[BLOCKED - INVALID\]/) {
				if ((value = field_value("SRC")) != "") print value >> path "/invalid-src.txt"
			} else if ($0 ~ /\[BLOCKED - IOT\]/) {
				if ((value = field_value("DST")) != "") print value >> path "/iot-dst.txt"
			}

			if (substr($0, 1, 6) == today) {
				loghour = substr($0, 8, 2) + 0
				if ($0 ~ /\[BLOCKED - INBOUND\]/) inbound[loghour]++
				else if ($0 ~ /\[BLOCKED - OUTBOUND\]/) outbound[loghour]++
				else if ($0 ~ /\[BLOCKED - INVALID\]/) invalid[loghour]++
				else if ($0 ~ /\[BLOCKED - IOT\]/) iot[loghour]++
			}
		}
		END {
			for (value in unique) uniquecount++
			for (i = 0; i <= hour; i++)
				printf "%02d:00~%d~%d~%d~%d\n", i, inbound[i] + 0, outbound[i] + 0, invalid[i] + 0, iot[i] + 0 > path "/activity.txt"
			if (first != "") print first " To " last > path "/span.txt"
			print events + 0 "~" uniquecount + 0 "~" first "~" last > path "/summary.txt"
		}
	' "$statsindexsource"
}

Extract_Stats_Values() {
	# $1 = source, $2 = include pattern, $3 = exclude pattern
	# $4 = field, $5 = recent/oldest/top, $6 = result limit
	# "top" counts every value; the other modes de-duplicate while retaining
	# chronological or reverse-chronological order.
	statsextractsource="$1"
	statsextractinclude="$2"
	statsextractexclude="$3"
	statsextractfield="$4"
	statsextractmode="$5"
	statsextractlimit="$6"
	statsextracttmp="$TMP_DIR/stats-extract.$$"
	statsextractstatus="0"
	if [ -n "$statsextractfield" ]; then
		statsextractfield="${statsextractfield}="
	fi

	awk -v matchpattern="$statsextractinclude" -v skippattern="$statsextractexclude" -v field="$statsextractfield" -v mode="$statsextractmode" -v limit="$statsextractlimit" '
		BEGIN {
			if (mode != "top" && limit <= 0) exit
			mode = mode == "top" ? 1 : (mode == "oldest" ? 2 : 0)
		}
		$0 ~ matchpattern && (skippattern == "" || $0 !~ skippattern) {
			position = index($0, field)
			if (field != "" && position > 0) {
				value = substr($0, position + length(field))
				sub(/[ ,].*/, "", value)
			} else if (field == "") {
				value = $0
			} else {
				next
			}

			if (!mode) values[++entries] = value
			else if (mode == 1) hits[value]++
			else {
				# The first requested unique values are final; do not retain or scan
				# the remaining history once this result is complete.
				if (!(value in seen)) {
					print value
					seen[value] = 1
					if (++output >= limit) exit
				}
			}
		}
		END {
			if (mode == 1) {
				for (value in hits) printf "%7d %s\n", hits[value], value
			} else if (!mode) {
				for (i = entries; i >= 1 && output < limit; i--) {
					value = values[i]
					if (!(value in seen)) {
						print value
						seen[value] = 1
						output++
					}
				}
			}
		}
	' "$statsextractsource" > "$statsextracttmp" || statsextractstatus="1"
	# Check each stage independently; POSIX pipelines only return the last status.
	if [ "$statsextractstatus" = "0" ]; then
		if [ "$statsextractmode" = "top" ]; then
			sort -nr "$statsextracttmp" > "$statsextracttmp.sorted" \
				&& head -n "$statsextractlimit" "$statsextracttmp.sorted" || statsextractstatus="1"
		else
			cat "$statsextracttmp" || statsextractstatus="1"
		fi
	fi
	rm -f "$statsextracttmp" "$statsextracttmp.sorted"
	return "$statsextractstatus"
}

Print_Stats_IPSet_Reasons() {
	# Print every matching saved reason for one IP. IPv4 addresses are converted to
	# numbers so exact entries and arbitrary CIDR prefixes use the same comparison.
	statsdetailip="$1"
	statsdetailmode="$2"
	statsdetailsource="${3:-$skynetipset}"
	case "$statsdetailmode" in whitelist|ban) ;; *) return 1 ;; esac

	awk -v ip="$statsdetailip" -v mode="$statsdetailmode" '
		function ip_number(value, octets) {
			split(value, octets, ".")
			return octets[1] * 16777216 + octets[2] * 65536 + octets[3] * 256 + octets[4]
		}
		function contains_ip(entry, cidr, prefix, divisor, i) {
			split(entry, cidr, "/")
			prefix = cidr[2] == "" ? 32 : cidr[2] + 0
			if (prefix < 0 || prefix > 32) return 0
			divisor = 1
			for (i = 0; i < 32 - prefix; i++) divisor *= 2
			return int(ipnumber / divisor) == int(ip_number(cidr[1]) / divisor)
		}
		function print_reason(entry, position, reason) {
			position = index($0, "comment \"")
			if (!position) return
			reason = substr($0, position + 9)
			sub(/"$/, "", reason)
			sub(/^ +/, "", reason)
			sub(/ +$/, "", reason)
			printf "%s [%s]\n", reason, entry
		}
		BEGIN { ipnumber = ip_number(ip) }
		$1 == "add" {
			if (mode == "whitelist" && $2 != "Skynet-Whitelist") next
			if (mode == "ban" && $2 != "Skynet-Blacklist" && $2 != "Skynet-BlockedRanges") next
			if (contains_ip($3)) print_reason($3)
		}
	' "$statsdetailsource"
	statsdetailstatus="$?"
	statsdetailreasonindex=""
	if Rule_Reason_Index_Is_Current; then statsdetailreasonindex="$RULE_REASON_INDEX"
	elif Build_Rule_Reason_Index "$skynetrules"; then statsdetailreasonindex="$ruleindexstage"; fi
	if [ -n "$statsdetailreasonindex" ]; then
		awk -F '\t' -v ip="$statsdetailip" -v target="$statsdetailmode" -v now="$(date +%s)" '
			function ip_number(value, octets) {
				split(value, octets, ".")
				return octets[1] * 16777216 + octets[2] * 65536 + octets[3] * 256 + octets[4]
			}
			function contains_ip(entry, cidr, prefix, divisor, i) {
				split(entry, cidr, "/"); prefix = cidr[2] == "" ? 32 : cidr[2] + 0; divisor = 1
				for (i = 0; i < 32 - prefix; i++) divisor *= 2
				return int(ipnumber / divisor) == int(ip_number(cidr[1]) / divisor)
			}
			BEGIN {ipnumber = ip_number(ip)}
			$1 == "R2I" && NF == 8 && $2 == target && ($7 == 0 || $7 > now) && contains_ip($4) {
				printf "%s [%s; %s]\n", $5, $4, $6
			}
		' "$statsdetailreasonindex"
	fi
	[ "$statsdetailreasonindex" = "$RULE_REASON_INDEX" ] \
		|| { [ -z "$statsdetailreasonindex" ] || rm -f "$statsdetailreasonindex"; }
	if [ "$statsdetailstatus" = "0" ] && [ -s "$rulestatusmanifest" ]; then
		while IFS="$(printf '\t')" read -r domainruleversion domainruletarget domainrulevalue domainrulestate _domaincount _domainchecked _domainsuccess _domainchanged _domainfield9 domainrulefield10 domainrulefield11; do
			[ "$domainruletarget" = "$statsdetailmode" ] || continue
			case "$domainrulestate" in current|cached) ;; *) continue ;; esac
			if [ "$domainruleversion" = "D2" ]; then domainrulecache="$domainrulefield11"; else domainrulecache="$domainrulefield10"; fi
			if grep -Fqx "$statsdetailip" "${skynetloc}/lists/rules/$domainrulecache" 2>/dev/null; then
				printf 'Domain: %s [%s]\n' "$domainrulevalue" "$statsdetailip"
			fi
		done < "$rulestatusmanifest"
	fi
	case "$statsdetailstatus" in
		0) unset "statsdetailip" "statsdetailmode" "statsdetailsource" "statsdetailstatus"; return 0 ;;
		*) unset "statsdetailip" "statsdetailmode" "statsdetailsource" "statsdetailstatus"; return 1 ;;
	esac
}

Build_Stats_Ban_Reason_Cache() {
	# Resolve every requested IP while reading the saved IPSet once. The direct
	# CLI lookup above remains available, while WebUI generation avoids one full
	# 5 MB IPSet scan for each recent connection.
	statsreasonrequests="$1"
	statsreasonsource="$2"
	statsreasonoutput="$3"
	: > "$statsreasonoutput" || return 1
	[ -s "$statsreasonrequests" ] || return 0
	statsreasonindex=""
	if Rule_Reason_Index_Is_Current; then statsreasonindex="$RULE_REASON_INDEX"
	elif Build_Rule_Reason_Index "$skynetrules"; then statsreasonindex="$ruleindexstage"; fi
	[ -n "$statsreasonindex" ] || statsreasonindex="/dev/null"

	awk -v requests="$statsreasonrequests" -v domainstatus="$rulestatusmanifest" -v domaincache="${skynetloc}/lists/rules" \
		-v reasonindex="$statsreasonindex" -v now="$(date +%s)" '
		function ip_number(ip, octets) {
			split(ip, octets, ".")
			return octets[1] * 16777216 + octets[2] * 65536 + octets[3] * 256 + octets[4]
		}
		function entry_reason(range, position, reason) {
			position = index($0, "comment \"")
			if (!position) return ""
			reason = substr($0, position + 9)
			sub(/\"$/, "", reason)
			sub(/^ +| +$/, "", reason)
			if (range) reason = reason "*"
			return reason
		}
		function add_reason(address, reason) {
			if (reason == "") reason = "Manual Rule"
			if (user_reason[address] == "") user_reason[address] = reason
			else if (!index(", " user_reason[address] ", ", ", " reason ",")) user_reason[address] = user_reason[address] ", " reason
		}
		function match_range(address, reason, automatic, cidr, prefix, key, ip, matches, total, j) {
			split(address, cidr, "/")
			prefix = cidr[2] + 0
			if (prefix < 0 || prefix > 32) return
			# Index only requested IPs, once per encountered prefix. Streaming ranges
			# keeps memory independent of the number of imported or automatic rules.
			if (!(prefix in indexed)) {
				for (ip in wanted) {
					key = prefix SUBSEP int(wanted[ip] / divisor[prefix])
					network_ips[key] = network_ips[key] " " ip
				}
				indexed[prefix] = 1
			}
			key = prefix SUBSEP int(ip_number(cidr[1]) / divisor[prefix])
			if (!(key in network_ips)) return
			total = split(network_ips[key], matches, " ")
			for (j = 1; j <= total; j++) {
				ip = matches[j]
				if (automatic) {
					if (!resolved[ip]) { result[ip] = reason; resolved[ip] = 1 }
				} else if (!(ip in user_range_reason)) user_range_reason[ip] = reason "*"
			}
		}
		BEGIN {
			divisor[32] = 1
			for (i = 31; i >= 0; i--) divisor[i] = divisor[i + 1] * 2
			while ((getline ip < requests) > 0) {
				if (ip != "" && !(ip in wanted)) {
					wanted[ip] = ip_number(ip)
					order[++count] = ip
				}
			}
			close(requests)
			while ((getline line < domainstatus) > 0) {
				split(line, field, "\t")
				if ((field[1] != "D1" && field[1] != "D2") || field[2] != "ban") continue
				if (field[4] != "current" && field[4] != "cached") continue
				cachefile = domaincache "/" (field[1] == "D2" ? field[11] : field[10])
				while ((getline address < cachefile) > 0) {
					if (!(address in wanted)) continue
					if (domain_reason[address] == "") domain_reason[address] = "Domain: " field[3]
					else domain_reason[address] = domain_reason[address] ", " field[3]
				}
				close(cachefile)
			}
			close(domainstatus)
			while ((getline line < reasonindex) > 0) {
				n = split(line, field, "\t")
				if (n != 8 || field[1] != "R2I" || field[2] != "ban") continue
				if (field[7] > 0 && field[7] <= now) continue
				address = field[4]; reason = field[5]
				if (field[3] == "range") match_range(address, reason, 0)
				else { sub(/\/32$/, "", address); if (address in wanted) add_reason(address, reason) }
			}
			close(reasonindex)
		}
		$1 == "add" && $2 == "Skynet-Blacklist" && ($3 in wanted) && !resolved[$3] {
			result[$3] = entry_reason(0)
			resolved[$3] = 1
			next
		}
		$1 == "add" && $2 == "Skynet-BlockedRanges" {
			split($3, cidr, "/")
			match_range($3, entry_reason(cidr[2] < 32), 1)
		}
		END {
			for (i = 1; i <= count; i++) {
				ip = order[i]
				if (result[ip] == "" && user_reason[ip] != "") result[ip] = user_reason[ip]
				if (result[ip] == "" && (ip in user_range_reason)) result[ip] = user_range_reason[ip]
				if (result[ip] == "" && domain_reason[ip] != "") result[ip] = domain_reason[ip]
				print ip "~" result[ip]
			}
		}
	' "$statsreasonsource" > "$statsreasonoutput"
	statsreasonstatus="$?"
	[ "$statsreasonindex" = "$RULE_REASON_INDEX" ] || [ "$statsreasonindex" = "/dev/null" ] || rm -f "$statsreasonindex"
	return "$statsreasonstatus"
}

Build_Stats_Country_Cache() {
	# Persistent cache contract: IP~country code~last checked~last used. DB-IP's
	# free API accepts 32 addresses per request, avoiding one network round-trip
	# per chart row. Stale values remain usable when the provider is unavailable.
	statscountryrequests="$1"
	statscountryoutput="$2"
	statsgeocache="${skynetloc}/lists/.geoip"
	statsgeotmp="${statsgeocache}.tmp.$$"
	statsgeowork="$TMP_DIR/geo-work.$$"
	statsgeomissing="$TMP_DIR/geo-missing.$$"
	statsgeobatches="$TMP_DIR/geo-batches.$$"
	statsgeonew="$TMP_DIR/geo-new.$$"
	statsgeoresponse="$TMP_DIR/geo-response.$$"
	statsgeonow="$(date +%s)"
	statsgeostatus="0"
	statsgeosource="$statsgeocache"
	[ -f "$statsgeosource" ] || statsgeosource="/dev/null"

	true > "$statscountryoutput" || return 1
	Is_Enabled "$lookupcountry" || return 0
	[ -r "$statscountryrequests" ] && mkdir -p "${skynetloc}/lists" || return 1
	awk -F '~' -v requests="$statscountryrequests" -v now="$statsgeonow" '
		BEGIN {
			while ((getline ip < requests) > 0) if (ip != "") wanted[ip] = 1
			close(requests)
		}
		$1 ~ /^[0-9.]+$/ && $2 ~ /^[A-Z][A-Z]$/ && $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ {
			if ($1 in wanted) $4 = now
			if (($1 in wanted) || now - $4 <= 2592000) print $1 "~" $2 "~" $3 "~" $4
		}' "$statsgeosource" > "$statsgeowork" || statsgeostatus="1"
	awk -F '~' -v cache="$statsgeowork" -v now="$statsgeonow" '
		BEGIN {
			while ((getline line < cache) > 0) {
				split(line, field, "~")
				checked[field[1]] = field[3]
			}
			close(cache)
		}
		NF && (!( $1 in checked) || now - checked[$1] >= 604800) && !seen[$1]++ { print $1 }
	' "$statscountryrequests" > "$statsgeomissing" || statsgeostatus="1"
	awk '
		{
			batch = batch (batch == "" ? "" : ",") $1
			if (++count == 32) { print batch; batch = ""; count = 0 }
		}
		END { if (batch != "") print batch }
	' "$statsgeomissing" > "$statsgeobatches" || statsgeostatus="1"
	true > "$statsgeonew" || statsgeostatus="1"
	true > "$statsgeoresponse" || statsgeostatus="1"
	while IFS= read -r statsgeobatch; do
		[ "$statsgeostatus" = "0" ] || break
		[ -n "$statsgeobatch" ] || continue
		if Curl_Lookup "https://api.db-ip.com/v2/free/${statsgeobatch}/countryCode" > "$statsgeoresponse" 2>/dev/null; then
			case "$statsgeobatch" in
				*,*)
					awk -v now="$statsgeonow" '
						/^[[:space:]]*"[0-9][0-9.]*"[[:space:]]*:[[:space:]]*"[A-Z][A-Z]"/ {
							ip=$0; sub(/^[[:space:]]*"/, "", ip); sub(/".*/, "", ip)
							code=$0; sub(/^[^:]*:[[:space:]]*"/, "", code); sub(/".*/, "", code)
							if (!seen[ip]++) print ip "~" code "~" now "~" now
						}' "$statsgeoresponse" >> "$statsgeonew" || statsgeostatus="1"
				;;
				*)
					statsgeocode="$(tr -d '\r\n' < "$statsgeoresponse")" || statsgeostatus="1"
					case "$statsgeocode" in
						[A-Z][A-Z]) printf '%s~%s~%s~%s\n' "$statsgeobatch" "$statsgeocode" "$statsgeonow" "$statsgeonow" >> "$statsgeonew" || statsgeostatus="1" ;;
					esac
				;;
			esac
		fi
	done < "$statsgeobatches"
	awk -F '~' -v fresh="$statsgeonew" '
		BEGIN {
			while ((getline line < fresh) > 0) {
				split(line, field, "~")
				new[field[1]] = line
				order[++count] = field[1]
			}
			close(fresh)
		}
		!($1 in new) { print }
		END { for (i = 1; i <= count; i++) print new[order[i]] }
	' "$statsgeowork" > "$statsgeotmp" || statsgeostatus="1"
	# Publish an empty snapshot as well so entries unused for 30 days are actually
	# pruned when no current chart IP needs country enrichment.
	awk -F '~' -v requests="$statscountryrequests" '
		BEGIN {
			while ((getline ip < requests) > 0) wanted[ip] = 1
			close(requests)
		}
		($1 in wanted) && !seen[$1]++ { print $1 "~" $2 }
	' "$statsgeotmp" > "$statscountryoutput" || statsgeostatus="1"
	# Provider failures retain stale codes. Local parsing and write failures must
	# preserve both the previous GeoIP cache and the installed chart payload.
	if [ "$statsgeostatus" = "0" ]; then
		mv -f "$statsgeotmp" "$statsgeocache" || statsgeostatus="1"
	fi
	rm -f "$statsgeotmp" "$statsgeowork" "$statsgeomissing" "$statsgeobatches" "$statsgeonew" "$statsgeoresponse"
	return "$statsgeostatus"
}

Lookup_Stats_Country() {
	statslookupip="$1"
	statslookupcountry=""
	Is_Enabled "$lookupcountry" || return 0
	if [ -n "$statscountrycache" ] && [ -f "$statscountrycache" ]; then
		statslookupcountry="$(awk -F '~' -v ip="$statslookupip" '$1 == ip {print $2; exit}' "$statscountrycache")"
	fi
	if [ -z "$statslookupcountry" ] && [ "$statscountrybatch" != "1" ]; then
		statslookupcountry="$(Curl_Lookup "https://api.db-ip.com/v2/free/${statslookupip}/countryCode/" 2>/dev/null | grep -E '^[A-Z]{2}$' || echo '**')"
		[ -n "$statscountrycache" ] && printf '%s~%s\n' "$statslookupip" "$statslookupcountry" >> "$statscountrycache"
	fi
	[ -n "$statslookupcountry" ] || statslookupcountry="**"
	printf '%s\n' "$statslookupcountry"
}

Build_Stats_Domain_Cache() {
	# dnsmasq history can exceed hundreds of megabytes. Load the small chart IP
	# request set first, then retain only matching domain replies in one pass.
	statsdomainrequests="$1"
	statsdomainoutput="$2"
	shift 2
	true > "$statsdomainoutput" || return 1
	[ -s "$statsdomainrequests" ] || return 0
	if ! Is_Enabled "$extendedstats"; then
		return 0
	fi
	if [ "$#" -eq "0" ]; then
		[ -f "/opt/var/log/dnsmasq.log" ] || return 0
		set -- /opt/var/log/dnsmasq*
	fi

	awk -v requests="$statsdomainrequests" '
		BEGIN {
			while ((getline ip < requests) > 0) {
				if (ip != "") wanted[ip] = 1
			}
			close(requests)
		}
		/reply.* is ([0-9]{1,3}\.){3}[0-9]{1,3}$/ {
			ip = $NF
			if (!(ip in wanted)) next
			domain = $(NF-2)
			sub(/^http[s]*:\/\//, "", domain)
			sub(/\/.*/, "", domain)
			sub(/^www\./, "", domain)
			key = ip SUBSEP domain
			if (domain != "" && !seen[key]++) {
				if (domains[ip] == "") domains[ip] = domain
				else domains[ip] = domains[ip] " " domain
			}
		}
		END {
			for (ip in domains) print ip "~" domains[ip]
		}
	' "$@" 2>/dev/null > "$statsdomainoutput"
}

Write_Recent_IP_Stats() {
	statsrecentfile="$1"
	# The enrichment maps are already generated in bulk. Join them in one AWK
	# process instead of rescanning three files for every displayed address.
	awk -v reasons="$statsreasoncache" -v countries="$statscountrycache" -v domains="$statsdomaincache" '
		BEGIN {
			while ((readstatus = (getline line < reasons)) > 0) { split(line, field, "~"); reason[field[1]] = field[2] }
			if (readstatus < 0) exit 1
			close(reasons)
			while ((readstatus = (getline line < countries)) > 0) { split(line, field, "~"); country[field[1]] = field[2] }
			if (readstatus < 0) exit 1
			close(countries)
			while ((readstatus = (getline line < domains)) > 0) { split(line, field, "~"); domain[field[1]] = field[2] }
			if (readstatus < 0) exit 1
			close(domains)
		}
		NF {
			ip = $1
			banreason = (reason[ip] == "" ? "No Longer Blacklisted" : substr(reason[ip], 1, 45))
			countrycode = (country[ip] == "" ? "**" : country[ip])
			domainlist = (domain[ip] == "" ? "*" : domain[ip])
			print ip "~" banreason "~https://otx.alienvault.com/indicator/ip/" ip "~" countrycode "~" domainlist
		}
	' > "$statsrecentfile"
}

Write_Top_IP_Stats() {
	statstopfile="$1"
	statstopdomains="$3"
	awk -v countries="$statscountrycache" -v domains="$statsdomaincache" -v includedomains="$statstopdomains" '
		BEGIN {
			while ((readstatus = (getline line < countries)) > 0) { split(line, field, "~"); country[field[1]] = field[2] }
			if (readstatus < 0) exit 1
			close(countries)
			while ((readstatus = (getline line < domains)) > 0) { split(line, field, "~"); domain[field[1]] = field[2] }
			if (readstatus < 0) exit 1
			close(domains)
		}
		NF >= 2 {
			hits = $1
			ip = $2
			countrycode = (country[ip] == "" ? "**" : country[ip])
			if (includedomains == "domains") {
				domainlist = (domain[ip] == "" ? "*" : domain[ip])
				print hits "~" ip "~" countrycode "~" domainlist
			} else print hits "~" ip "~" countrycode
		}
	' > "$statstopfile"
}

Print_Stats_Rows() {
	statsrowfile="$1"
	statsrowmode="$2"
	awk -v mode="$statsrowmode" -v reasons="$statsreasoncache" -v countries="$statscountrycache" -v domains="$statsdomaincache" '
		BEGIN {
			while ((getline line < reasons) > 0) { position = index(line, "~"); reason[substr(line, 1, position - 1)] = substr(line, position + 1) }
			close(reasons)
			while ((getline line < countries) > 0) { position = index(line, "~"); country[substr(line, 1, position - 1)] = substr(line, position + 1) }
			close(countries)
			while ((getline line < domains) > 0) { position = index(line, "~"); domain[substr(line, 1, position - 1)] = substr(line, position + 1) }
			close(domains)
		}
		NF {
			if (mode == 2) { hits = $1; ip = $NF } else { hits = ""; ip = $1 }
			countrycode = (country[ip] == "" ? "**" : country[ip])
			banreason = (reason[ip] == "" ? "No Longer Blacklisted" : reason[ip])
			if (length(banreason) > 45) banreason = substr(banreason, 1, 45)
			domainlist = domain[ip]
			if (hits != "")
				printf "%-10s | %-15s %-4s | %-55s | %-45s | %-60s\n", hits "x", ip, countrycode, "https://otx.alienvault.com/indicator/ip/" ip, banreason, domainlist
			else
				printf "%-15s %-4s | %-55s | %-45s | %-60s \n", ip, countrycode, "https://otx.alienvault.com/indicator/ip/" ip, banreason, domainlist
		}
	' "$statsrowfile"
}

Show_Stats_Block() {
	# Arguments:
	# $1 = source         ("log" or "events")
	# $2 = pattern        (e.g. "IOT.*$proto")
	# $3 = field          ("SRC", "DST", or "" for full line)
	# $4 = title          (display title)
	# $5 = method         ("head" or "tail")
	# $6 = count          (number of entries)
	# $7 = header_id      (passed to Display_Header)
	# $8 = stats_mode     (1 for recent values, 2 for hit counts)
	case "$1" in
		events) statssource="$skynetevents" ;;
		*)      statssource="$skynetlog" ;;
	esac

	statspattern="$2"
	statsfield="$3"
	statstitle="$4"
	statsmethod="$5"
	statscount="$6"
	statsheader="${7:-1}"
	statsmode="${8:-1}"
	statsindexedsource=""
	if [ "$1" = "log" ] && [ -n "$statsindexpath" ]; then
		case "${statspattern}:${statsfield}" in
			INBOUND*:SRC) statsindexedsource="${statsindexpath}/inbound-src.txt" ;;
			OUTBOUND*DPT=80*:DST) statsindexedsource="${statsindexpath}/outbound-http-dst.txt" ;;
			OUTBOUND*:DST) statsindexedsource="${statsindexpath}/outbound-all-dst.txt" ;;
			INVALID*:SRC) statsindexedsource="${statsindexpath}/invalid-src.txt" ;;
			IOT*:DST) statsindexedsource="${statsindexpath}/iot-dst.txt" ;;
		esac
		if [ -n "$statsindexedsource" ]; then
			statssource="$statsindexedsource"
			statspattern=".*"
			statsfield=""
		fi
	fi

	Display_Header "9"
	Red "$statstitle"
	Display_Header "$statsheader"

	if [ "$statsmode" -eq 2 ]; then
		statsextractmode="top"
	elif [ "$statsmethod" = "tail" ]; then
		statsextractmode="oldest"
	else
		statsextractmode="recent"
	fi
	statsblockrows="$TMP_DIR/stats-block-rows.$$"
	Extract_Stats_Values "$statssource" "$statspattern" "" "$statsfield" "$statsextractmode" "$statscount" > "$statsblockrows" \
		|| { rm -f "$statsblockrows"; return 1; }
	Print_Stats_Rows "$statsblockrows" "$statsmode"
	statsblockstatus="$?"
	rm -f "$statsblockrows"
	return "$statsblockstatus"
}

Show_Action_Rule_History() {
	actionhistorycount="$1"
	actionhistorytmp="$TMP_DIR/action-history.$$"
	awk -F '\t' '$1 == "A1" && NF == 12 && $6 == "rules" && $7 == "add" && $8 == "ban" {
		printf "%s | %-8s | %-9s | %s%s\n", $3, $9, $5, $10, ($11 == "" ? "" : " | " $11)
	}' "$skynetevents" | tail -n "$actionhistorycount" > "$actionhistorytmp"
	echo
	Red "Last $actionhistorycount Manual Ban Actions;"
	printf '%-25s | %-8s | %-9s | %s\n' "Time" "Type" "Result" "Entries / Comment"
	cat "$actionhistorytmp"
	rm -f "$actionhistorytmp"
}

Print_Action_Records() {
	# Present the structured journal consistently without exposing its storage
	# format. An optional address limits results to actions containing that value.
	actionfilteraddress="$1"
	awk -F '\t' -v address="$actionfilteraddress" '
		$1 == "A1" && NF == 12 {
			if (address != "" && !index(" " $10 " ", " " address " ")) next
			detail = $11 == "" ? "" : " (" $11 ")"
			printf "%s [%s] %-8s %-10s %-8s %-18s - %s%s\n", \
				$3, $4, toupper($5), $6, $7, $8 "/" $9, $10, detail
		}
	' "$skynetevents"
}

Show_Associated_Domains() {
	if Is_Enabled "$extendedstats"; then
		# $1 = IP to search
		loghits="$(grep -E "reply.* is $1" /opt/var/log/dnsmasq* 2>/dev/null)"
		if [ -n "$loghits" ]; then
			Red "Associated Domain(s);"
			assdomains="$(printf '%s\n' "$loghits" | awk '{print $(NF-2)}' | Strip_Domain | Filter_OutIP | sort -u)"
			diversion_lists="$(cat /opt/share/diversion/list/blockinglist /opt/share/diversion/list/blacklist 2>/dev/null)"
			printf '%s\n' "$assdomains" | while IFS= read -r domain; do
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

Search_Ban_Reasons() {
	# One case-insensitive fixed-substring scan covers both live blacklist sets.
	# Malware source URLs are resolved from the local filter manifest only; this
	# command intentionally performs no DNS, country or external lookups.
	bansearchterm="$1"
	bansearchlimit="${2:-25}"
	bansearchdata="$TMP_DIR/ban-reasons.$$"
	bansearchcount="$TMP_DIR/ban-reasons-count.$$"
	bansearchsources="$TMP_DIR/ban-sources.$$"

	[ -n "$bansearchterm" ] || { echo "[*] Ban Reason Can't Be Empty"; return 2; }
	case "$bansearchlimit" in
		""|*[!0-9]*) echo "[*] Result Count Must Be Numeric"; return 2 ;;
	esac
	if [ "$bansearchlimit" -lt "1" ] || [ "$bansearchlimit" -gt "100" ]; then
		echo "[*] Result Count Must Be Between 1 And 100"
		return 2
	fi
	{ ipset save Skynet-Blacklist 2>/dev/null \
		&& ipset save Skynet-BlockedRanges 2>/dev/null; } > "$bansearchdata" || return 1
	printf '#\n' > "$bansearchsources" || return 1
	if [ -f /jffs/addons/shared-whitelists/shared-Skynet-whitelist ]; then
		cat /jffs/addons/shared-whitelists/shared-Skynet-whitelist >> "$bansearchsources"
	fi

	printf '%-20s | %-7s | %-48s | %s\n' "IP Address / Range" "Type" "Ban Reason" "Source"
	printf '%-20s-+-%-7s-+-%-48s-+-%s\n' "--------------------" "-------" "------------------------------------------------" "------"
	if ! awk -v term="$bansearchterm" -v limit="$bansearchlimit" -v countfile="$bansearchcount" '
		NR == FNR {
			url = $1
			clean = url
			sub(/[?#].*/, "", clean)
			parts = split(clean, path, "/")
			if (path[parts] != "") sources[tolower(path[parts])] = url
			next
		}
		$1 == "add" && ($2 == "Skynet-Blacklist" || $2 == "Skynet-BlockedRanges") {
			position = index($0, "comment \"")
			if (!position) next
			reason = substr($0, position + 9)
			sub(/\"$/, "", reason)
			if (index(tolower(reason), tolower(term)) == 0) next
			total++
			if (shown >= limit) next
			type = $2 == "Skynet-Blacklist" ? "IP" : "Range"
			source = "-"
			if (reason ~ /^BanMalware: /) {
				name = reason
				sub(/^BanMalware: /, "", name)
				if (tolower(name) in sources) source = sources[tolower(name)]
			}
			printf "%-20s | %-7s | %-48s | %s\n", $3, type, reason, source
			shown++
		}
		END { print total + 0 > countfile }
	' "$bansearchsources" "$bansearchdata"; then
		rm -f "$bansearchdata" "$bansearchcount" "$bansearchsources"
		return 1
	fi
	bansearchtotal="$(cat "$bansearchcount" 2>/dev/null)"
	rm -f "$bansearchdata" "$bansearchcount" "$bansearchsources"
	echo
	echo "[i] ${bansearchtotal:-0} Matching Ban Entries"
	[ "${bansearchtotal:-0}" -le "$bansearchlimit" ] || echo "[i] Showing First $bansearchlimit Results"
}

Prepare_CLI_Stats_Data() {
	# Build one protocol-aware log index, then batch the enrichment needed by all
	# CLI tables. This replaces repeated full log, IPSet and dnsmasq scans.
	statscliproto="$1"
	statsclilimit="$2"
	statsindexpath="$TMP_DIR/stats-index"
	statslookupips="$TMP_DIR/stats-lookup-ips.txt"
	statsreasoncache="$TMP_DIR/stats-reasons.txt"
	statscountrycache="$TMP_DIR/stats-countries.txt"
	statsdomaincache="$TMP_DIR/stats-domains.txt"
	mkdir -p "$statsindexpath" || return 1
	Build_Stats_Log_Index "$skynetlog" "$statsindexpath" "$statscliproto" || return 1
	true > "$statscountrycache" || return 1

	{
		Extract_Stats_Values "${statsindexpath}/inbound-src.txt" ".*" "" "" "recent" "$statsclilimit"
		Extract_Stats_Values "${statsindexpath}/outbound-all-dst.txt" ".*" "" "" "recent" "$statsclilimit"
		Extract_Stats_Values "${statsindexpath}/invalid-src.txt" ".*" "" "" "recent" "$statsclilimit"
		Extract_Stats_Values "${statsindexpath}/outbound-http-dst.txt" ".*" "" "" "recent" "$statsclilimit"
		awk -F '\t' '$1 == "R2" && $3 == "ban" && ($4 == "ip" || $4 == "range") && $7 == "enabled" {print $5}' "$skynetrules" | tail -"$statsclilimit"
		Extract_Stats_Values "${statsindexpath}/inbound-src.txt" ".*" "" "" "top" "$statsclilimit" | awk 'NF >= 2 {print $NF}'
		Extract_Stats_Values "${statsindexpath}/outbound-all-dst.txt" ".*" "" "" "top" "$statsclilimit" | awk 'NF >= 2 {print $NF}'
		Extract_Stats_Values "${statsindexpath}/invalid-src.txt" ".*" "" "" "top" "$statsclilimit" | awk 'NF >= 2 {print $NF}'
		Extract_Stats_Values "${statsindexpath}/outbound-http-dst.txt" ".*" "" "" "top" "$statsclilimit" | awk 'NF >= 2 {print $NF}'
		Extract_Stats_Values "${statsindexpath}/iot-dst.txt" ".*" "" "" "top" "$statsclilimit" | awk 'NF >= 2 {print $NF}'
	} | awk 'NF && !seen[$0]++' > "$statslookupips" || return 1
	Build_Stats_Ban_Reason_Cache "$statslookupips" "$skynetipset" "$statsreasoncache" || return 1
	Build_Stats_Domain_Cache "$statslookupips" "$statsdomaincache"
}

Build_Stats_Search_Log() {
	# Scan the block log once for a search request. The generated files contain
	# only matching rows and small aggregate tables used by the CLI renderer.
	statssearchmode="$1"
	statssearchvalue="$2"
	statssearchproto="$3"
	statssearchprefix="$4"
	statssearchmatches="${statssearchprefix}.matches"
	statssearchsummary="${statssearchprefix}.summary"
	statssearchdpt="${statssearchprefix}.dpt"
	statssearchspt="${statssearchprefix}.spt"
	statssearchhttp="${statssearchprefix}.http"
	statssearchother="${statssearchprefix}.other"
	statssearchlogsummary="${statssearchprefix}.logsummary"
	rm -f "$statssearchmatches" "$statssearchsummary" "$statssearchdpt" "$statssearchspt" "$statssearchhttp" "$statssearchother" "$statssearchlogsummary"
	awk -v mode="$statssearchmode" -v value="$statssearchvalue" -v protocol="$statssearchproto" \
		-v matches="$statssearchmatches" -v summary="$statssearchsummary" \
		-v dptfile="$statssearchdpt" -v sptfile="$statssearchspt" \
		-v httpfile="$statssearchhttp" -v otherfile="$statssearchother" \
		-v logsummary="$statssearchlogsummary" '
		function line_value(name, start, value) {
			start = index($0, " " name "=")
			if (!start) return ""
			value = substr($0, start + length(name) + 2)
			sub(/[ ,].*/, "", value)
			return value
		}
		BEGIN {
			printf "%s", "" > matches; close(matches)
			printf "%s", "" > dptfile; close(dptfile)
			printf "%s", "" > sptfile; close(sptfile)
			printf "%s", "" > httpfile; close(httpfile)
			printf "%s", "" > otherfile; close(otherfile)
		}
		{
			source = destination = destinationport = sourceport = ""
			inbound = index($0, "INBOUND") != 0
			invalid = index($0, "INVALID") != 0
			outbound = index($0, "OUTBOUND") != 0
			if (index($0, "BLOCKED -")) {
				globalevents++
				globalstamp = $1 " " $2 " " $3
				if (globalfirst == "") globalfirst = globalstamp
				globallast = globalstamp
			}
			if (inbound || invalid) {
				source = line_value("SRC")
				globaladdress = source
			} else if (outbound) {
				destination = line_value("DST")
				globaladdress = destination
			}
			else globaladdress = ""
			if (globaladdress ~ /^[0-9.]+$/) globalunique[globaladdress] = 1
			matched = 0
			if (mode == "port") matched = index($0, "PT=" value " ")
			else if (mode == "ip") matched = index($0, "=" value " ")
			else if (mode == "device") matched = outbound && index($0, " SRC=" value " ") && (protocol == "" || index($0, protocol))
			if (!matched) next
			print $0 >> matches
			stamp = $1 " " $2 " " $3
			if (total == 0) first = stamp
			last = stamp
			total++
			if (mode == "port") {
				if (source == "") source = line_value("SRC")
				if (source != "") unique[source] = 1
			}
			if (mode == "ip" && inbound && source == value) {
				destinationport = line_value("DPT")
				sourceport = line_value("SPT")
				if (destinationport != "") dpt[destinationport]++
				if (sourceport != "") spt[sourceport]++
			}
			if (mode == "device") {
				if (destination == "") destination = line_value("DST")
				destinationport = line_value("DPT")
				if (destination != "") {
					if (destinationport == 80 || destinationport == 443) http[destination]++
					else other[destination]++
				}
			}
		}
		END {
			for (item in unique) uniquecount++
			for (item in globalunique) globaluniquecount++
			print globalevents + 0 "~" globaluniquecount + 0 "~" globalfirst "~" globallast > logsummary
			print first "~" last "~" total + 0 "~" uniquecount + 0 > summary
			for (item in dpt) print dpt[item], item > dptfile
			for (item in spt) print spt[item], item > sptfile
			for (item in http) print http[item], item > httpfile
			for (item in other) print other[item], item > otherfile
		}
	' "$skynetlog"
}

Build_Stats_Domain_Search_Log() {
	# Index every resolved address during one block-log pass. Per-address output
	# is rendered from this compact index rather than rescanning the live log.
	statsdomainvalues="$1"
	statsdomainprefix="$2"
	statsdomainmatches="${statsdomainprefix}.matches"
	statsdomainsummary="${statsdomainprefix}.summary"
	statsdomaindpt="${statsdomainprefix}.dpt"
	statsdomainspt="${statsdomainprefix}.spt"
	statsdomainlogsummary="${statsdomainprefix}.logsummary"
	rm -f "$statsdomainmatches" "$statsdomainsummary" "$statsdomaindpt" "$statsdomainspt" "$statsdomainlogsummary"
	awk -v values="$statsdomainvalues" -v matches="$statsdomainmatches" \
		-v summary="$statsdomainsummary" -v dptfile="$statsdomaindpt" -v sptfile="$statsdomainspt" \
		-v logsummary="$statsdomainlogsummary" '
		function line_value(name, start, value) {
			start = index($0, " " name "=")
			if (!start) return ""
			value = substr($0, start + length(name) + 2)
			sub(/[ ,].*/, "", value)
			return value
		}
		function record(address, source, destinationport, sourceport, inbound, stamp) {
			if (!(address in wanted)) return
			print address "~" $0 >> matches
			stamp = $1 " " $2 " " $3
			if (total[address] == 0) first[address] = stamp
			last[address] = stamp
			total[address]++
			if (inbound && source == address) {
				if (destinationport != "") dpt[address SUBSEP destinationport]++
				if (sourceport != "") spt[address SUBSEP sourceport]++
			}
		}
		BEGIN {
			count = split(values, input, " ")
			for (position = 1; position <= count; position++) if (input[position] != "" && !(input[position] in wanted)) {
				wanted[input[position]] = 1
				order[++addresscount] = input[position]
			}
			printf "%s", "" > matches; close(matches)
			printf "%s", "" > dptfile; close(dptfile)
			printf "%s", "" > sptfile; close(sptfile)
		}
		{
			source = line_value("SRC")
			destination = line_value("DST")
			inbound = index($0, "INBOUND") != 0
			if (inbound && source in wanted) {
				destinationport = line_value("DPT")
				sourceport = line_value("SPT")
			} else destinationport = sourceport = ""
			if (index($0, "BLOCKED -")) {
				globalevents++
				globalstamp = $1 " " $2 " " $3
				if (globalfirst == "") globalfirst = globalstamp
				globallast = globalstamp
			}
			if ((index($0, "INBOUND") || index($0, "INVALID")) && source ~ /^[0-9.]+$/) globalunique[source] = 1
			else if (index($0, "OUTBOUND") && destination ~ /^[0-9.]+$/) globalunique[destination] = 1
			record(source, source, destinationport, sourceport, inbound)
			if (destination != source) record(destination, source, destinationport, sourceport, inbound)
		}
		END {
			for (item in globalunique) globaluniquecount++
			print globalevents + 0 "~" globaluniquecount + 0 "~" globalfirst "~" globallast > logsummary
			for (position = 1; position <= addresscount; position++) {
				address = order[position]
				print address "~" first[address] "~" last[address] "~" total[address] + 0 > summary
			}
			for (item in dpt) { split(item, field, SUBSEP); print field[1] "~" dpt[item] " " field[2] > dptfile }
			for (item in spt) { split(item, field, SUBSEP); print field[1] "~" spt[item] " " field[2] > sptfile }
		}
	' "$skynetlog"
}

Remove_Stats_Search_Files() {
	statssearchprefix="$1"
	rm -f "${statssearchprefix}.matches" "${statssearchprefix}.summary" \
		"${statssearchprefix}.dpt" "${statssearchprefix}.spt" \
		"${statssearchprefix}.http" "${statssearchprefix}.other" \
		"${statssearchprefix}.logsummary"
}

Remove_Stats_Domain_Search_Files() {
	statsdomainprefix="$1"
	rm -f "${statsdomainprefix}.matches" "${statsdomainprefix}.summary" \
		"${statsdomainprefix}.dpt" "${statsdomainprefix}.spt" \
		"${statsdomainprefix}.logsummary"
}

Print_Stats_Logging_Header() {
	printf '╔═════════════════════ Logging ═════════════════════════════════════════════════════════════════════════════╗\n'
	printf '║ %-20s │ %-82s ║\n' "Syslog Locations" "$syslogloc $syslog1loc"
	printf '║ %-20s │ %-82s ║\n' "Skynet Log"       "${skynetlog}"
	SZ="$(du -h "${skynetlog}" | awk '{print $1}')"
	printf '║ └── %-16s │ %-82s ║\n' "Used/Total" "$SZ / ${logsize}MB"
	if [ -s "$statslogsummary" ]; then
		IFS='~' read -r statseventcount statsuniquecount monitorfirst monitorlast < "$statslogsummary"
		blockedevents="${statseventcount:-0} (${statsuniquecount:-0} Unique IPs)"
		if [ -n "$monitorfirst" ] && [ -n "$monitorlast" ]; then monitorspan="$monitorfirst → $monitorlast"; else monitorspan="No Data"; fi
		printf '║ %-20s │ %-82s ║\n' "Block Events" "$blockedevents"
	else
		Generate_Blocked_Events
	fi
	printf '║ %-20s │ %-82s ║\n' "Manual Bans" "$(awk -F '\t' '$1 == "R2" && $3 == "ban" && $7 == "enabled" {count++} END {print count + 0}' "$skynetrules")"
	printf '║ %-20s │ %-84s ║\n' "Monitor Span" "$monitorspan"
	printf '╚══════════════════════╧════════════════════════════════════════════════════════════════════════════════════╝\n\n\n'
}

Set_Stats_Search_Count() {
	case "$1" in
		""|*[!0-9]*) return 2 ;;
	esac
	[ "$1" -ge "1" ] 2>/dev/null || return 2
	counter="$1"
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
		if [ ! -s "$skynetlog" ] && [ ! -s "$skynetevents" ] && [ "$2:$3" != "search:reason" ]; then
			echo "[*] No Logging Data Detected - Give This Time To Generate"
			echo; exit 0
		fi
		case "$2:$3" in
			search:ip|search:port|search:device|search:domain) ;;
			reset:*|remove:*|search:*) Print_Stats_Logging_Header ;;
		esac
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
						if ! echo "$4" | Is_Port; then echo "[*] $4 Is Not A Valid Port"; echo; exit 2; fi
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
				case "$3" in
					actions)
						case "$#" in 3) ;; 4) Set_Stats_Search_Count "$4" || { echo "[*] Result Count Must Be A Positive Number"; echo; exit 2; } ;; *) echo "[*] Syntax: firewall stats search actions [count]"; echo; exit 2 ;; esac
						echo "[i] Recorded Actions"
						echo;echo
						Red "$counter Most Recent Actions;"
						Print_Action_Records "" | tail -"$counter"
					;;
					reason)
						case "$#" in 4|5) ;; *) echo "[*] Syntax: firewall stats search reason \"text\" [count]"; echo; exit 2 ;; esac
						Search_Ban_Reasons "$4" "$5" || exit "$?"
					;;
					port)
						case "$#" in 4) ;; 5) Set_Stats_Search_Count "$5" || { echo "[*] Result Count Must Be A Positive Number"; echo; exit 2; } ;; *) echo "[*] Syntax: firewall stats search port <port> [count]"; echo; exit 2 ;; esac
						if ! echo "$4" | Is_Port; then echo "[*] $4 Is Not A Valid Port"; echo; exit 2; fi
						statssearchprefix="$TMP_DIR/stats-search.$$"
						Build_Stats_Search_Log port "$4" "" "$statssearchprefix" || exit 1
						statslogsummary="${statssearchprefix}.logsummary"
						Print_Stats_Logging_Header
						IFS='~' read -r statssearchfirst statssearchlast statssearchtotal statssearchunique < "${statssearchprefix}.summary"
						echo "[i] Port $4 First Tracked On $statssearchfirst"
						echo "[i] Port $4 Last Tracked On $statssearchlast"
						echo "[i] $statssearchtotal Attempts Total"
						echo "[i] $statssearchunique Unique IPs"
						echo;echo
						Red "First Block Tracked On Port $4;"
						sed -n '1p' "${statssearchprefix}.matches"
						echo;echo
						Red "$counter Most Recent Blocks On Port $4;"
						tail -"$counter" "${statssearchprefix}.matches"
						Remove_Stats_Search_Files "$statssearchprefix"
						echo
					;;
					ip)
						case "$#" in 4) ;; 5) Set_Stats_Search_Count "$5" || { echo "[*] Result Count Must Be A Positive Number"; echo; exit 2; } ;; *) echo "[*] Syntax: firewall stats search ip <address> [count]"; echo; exit 2 ;; esac
						if ! echo "$4" | Is_IP; then echo "[*] $4 Is Not A Valid IP"; echo; exit 2; fi
						statssearchprefix="$TMP_DIR/stats-search.$$"
						Build_Stats_Search_Log ip "$4" "" "$statssearchprefix" || exit 1
						statslogsummary="${statssearchprefix}.logsummary"
						Print_Stats_Logging_Header
						unset "found1" "found2" "found3"
						ipset -q test Skynet-Whitelist "$4" && found1=true
						ipset -q test Skynet-WhitelistDomains "$4" && found1=true
						ipset -q test Skynet-Blacklist "$4" && found2=true
						ipset -q test Skynet-BlacklistDomains "$4" && found2=true
						ipset -q test Skynet-BlockedRanges "$4" && found3=true
						echo;echo
						if [ -n "$found1" ]; then
							Red "Whitelist Reasons;"
							Print_Stats_IPSet_Reasons "$4" whitelist
							echo;echo
						fi
						if [ -n "$found2" ] || [ -n "$found3" ]; then
							Red "Ban Reasons;"
							Print_Stats_IPSet_Reasons "$4" ban
						fi
						echo;echo
						ip="$(echo "$4" | sed 's~\.~\\.~g')"
						Show_Associated_Domains "$ip"
						if Is_Enabled "$lookupcountry"; then
							country="$(Curl_Lookup "https://api.db-ip.com/v2/free/${4}/countryCode/" 2>/dev/null | grep -E '^[A-Z]{2}$' || echo '**')"
							echo "[i] IP Location - $country"
							echo
						fi
						IFS='~' read -r statssearchfirst statssearchlast statssearchtotal statssearchunique < "${statssearchprefix}.summary"
						echo "[i] $4 First Tracked On $statssearchfirst"
						echo "[i] $4 Last Tracked On $statssearchlast"
						echo "[i] $statssearchtotal Blocks Total"
						echo;echo
						Red "Action Log Entries For $4;"
						Print_Action_Records "$4"
						echo;echo
						Red "First Block Tracked From $4;"
						sed -n '1p' "${statssearchprefix}.matches"
						echo;echo
						Red "$counter Most Recent Blocks From $4;"
						tail -"$counter" "${statssearchprefix}.matches"
						echo;echo
						Red "Top $counter Targeted Ports From $4 (Inbound);"
						Display_Header "3"
						sort -nr "${statssearchprefix}.dpt" 2>/dev/null | head -"$counter" | awk '{printf "%-10s | %-10s | %-60s\n", $1 "x", $2, "https://www.speedguide.net/port.php?port=" $2 }'
						echo;echo
						Red "Top $counter Sourced Ports From $4 (Inbound);"
						Display_Header "3"
						sort -nr "${statssearchprefix}.spt" 2>/dev/null | head -"$counter" | awk '{printf "%-10s | %-10s | %-60s\n", $1 "x", $2, "https://www.speedguide.net/port.php?port=" $2 }'
						Remove_Stats_Search_Files "$statssearchprefix"
						echo
					;;
					domain)
						case "$#" in 4) ;; 5) Set_Stats_Search_Count "$5" || { echo "[*] Result Count Must Be A Positive Number"; echo; exit 2; } ;; *) echo "[*] Syntax: firewall stats search domain <domain> [count]"; echo; exit 2 ;; esac
						Require_Connection
						if [ -z "$4" ]; then echo "[*] Domain Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
						domain="$(Normalize_Domain "$4")" || { echo "[*] $4 Is Not A Valid Domain"; echo; exit 2; }
						domainips="$(Resolve_Domain_IP_List "$domain" all)" || { echo "[*] Unable To Resolve $domain"; echo; exit 1; }
						statsdomainprefix="$TMP_DIR/stats-domain-search.$$"
						Build_Stats_Domain_Search_Log "$domainips" "$statsdomainprefix" || exit 1
						statslogsummary="${statsdomainprefix}.logsummary"
						Print_Stats_Logging_Header
						printf '%s\n' "$domainips" | tr ' ' '\n' > "$TMP_DIR/stats-domain-ips.$$"
						statscountrycache="$TMP_DIR/stats-domain-countries.$$"
						statscountrybatch="1"
						Build_Stats_Country_Cache "$TMP_DIR/stats-domain-ips.$$" "$statscountrycache" || true
						for ip in $domainips; do
							unset "found1" "found2" "found3"
							ipset -q test Skynet-Whitelist "$ip" && found1=true
							ipset -q test Skynet-WhitelistDomains "$ip" && found1=true
							ipset -q test Skynet-Blacklist "$ip" && found2=true
							ipset -q test Skynet-BlacklistDomains "$ip" && found2=true
							ipset -q test Skynet-BlockedRanges "$ip" && found3=true
							echo
							if [ -n "$found1" ]; then
								Red "Whitelist Reasons;"
								Print_Stats_IPSet_Reasons "$ip" whitelist
								echo
							fi
							if [ -n "$found2" ] || [ -n "$found3" ]; then
								Red "Ban Reasons;"
								Print_Stats_IPSet_Reasons "$ip" ban
							fi
							echo
							ip2="$(echo "$ip" | sed 's~\.~\\.~g')"
							Show_Associated_Domains "$ip2"
							echo;echo
							if [ -n "$found2" ] || [ -n "$found3" ]; then
								if Is_Enabled "$lookupcountry"; then
									country="$(Lookup_Stats_Country "$ip" code)"
									echo "[i] IP Location - $country"
									echo
								fi
								statsdomainrow="$(awk -F '~' -v address="$ip" '$1 == address { print $2 "~" $3 "~" $4; exit }' "${statsdomainprefix}.summary")"
								IFS='~' read -r statssearchfirst statssearchlast statssearchtotal <<EOF
$statsdomainrow
EOF
								echo "[i] $ip First Tracked On $statssearchfirst"
								echo "[i] $ip Last Tracked On $statssearchlast"
								echo "[i] $statssearchtotal Blocks Total"
								echo;echo
								Red "Action Log Entries For $ip;"
								Print_Action_Records "$ip"
								echo;echo
								Red "First Block Tracked From $ip;"
								awk -F '~' -v address="$ip" '$1 == address { sub(/^[^~]*~/, ""); print; exit }' "${statsdomainprefix}.matches"
								echo;echo
								Red "$counter Most Recent Blocks From $ip;"
								awk -F '~' -v address="$ip" '$1 == address { sub(/^[^~]*~/, ""); print }' "${statsdomainprefix}.matches" | tail -"$counter"
								echo;echo
								Red "Top $counter Targeted Ports From $ip (Inbound);"
								Display_Header "3"
								awk -F '~' -v address="$ip" '$1 == address { print $2 }' "${statsdomainprefix}.dpt" | sort -nr | head -"$counter" | awk '{printf "%-10s | %-10s | %-60s\n", $1 "x", $2, "https://www.speedguide.net/port.php?port=" $2 }'
								echo;echo
								Red "Top $counter Sourced Ports From $ip (Inbound);"
								Display_Header "3"
								awk -F '~' -v address="$ip" '$1 == address { print $2 }' "${statsdomainprefix}.spt" | sort -nr | head -"$counter" | awk '{printf "%-10s | %-10s | %-60s\n", $1 "x", $2, "https://www.speedguide.net/port.php?port=" $2 }'
								echo
							fi
							echo
							done
						Remove_Stats_Domain_Search_Files "$statsdomainprefix"
						rm -f "$TMP_DIR/stats-domain-ips.$$" "$statscountrycache"
						unset "statscountrybatch"
					;;
					malware)
						Check_Lock "$@"
						if ! printf '%s\n' "$4" | Is_IPRange; then echo "[*] $4 Is Not A Valid IP/Range"; echo; exit 2; fi
						ip="$(echo "$4" | sed 's~\.~\\.~g')"
						Show_Associated_Domains "$ip"
						printf '   \b\b\b'
						Display_Header "10"
						Red "Exact Matches;"
						Display_Header "5"
						cwd="$(pwd)"
						cd "${skynetloc}/lists" || exit 1
						grep -HE "^$ip$" -- * | while IFS= read -r "list" && [ -n "$list" ]; do
							listfile="${list%%:*}"
							printf '%-20s | %-40s\n' "${list#*:}" "$(grep -F "$listfile" /jffs/addons/shared-whitelists/shared-Skynet-whitelist)"
						done
						printf '   \b\b\b\n\n'
						Red "Possible CIDR Matches;"
						Display_Header "5"
						grep -HE "^$(echo "$ip" | cut -d '.' -f1-3)\..*/" -- * | while IFS= read -r "list" && [ -n "$list" ]; do
							listfile="${list%%:*}"
							printf '%-20s | %-40s\n' "${list#*:}" "$(grep -F "$listfile" /jffs/addons/shared-whitelists/shared-Skynet-whitelist)"
						done
						printf '   \b\b\b'
						cd "$cwd" || exit 1
					;;
					manualbans)
						if [ "$4" -eq "$4" ] 2>/dev/null; then counter="$4"; fi
						manualbanfirst="$(awk -F '\t' '$1 == "A1" && $6 == "rules" && $7 == "add" && $8 == "ban" {print $3; exit}' "$skynetevents")"
						manualbanlast="$(awk -F '\t' '$1 == "A1" && $6 == "rules" && $7 == "add" && $8 == "ban" {value = $3} END {print value}' "$skynetevents")"
						echo "First Manual Ban Issued On ${manualbanfirst:-No Data}"
						echo "Last Manual Ban Issued On ${manualbanlast:-No Data}"
						echo;echo
						Red "First Manual Ban Issued;"
						awk -F '\t' '$1 == "A1" && $6 == "rules" && $7 == "add" && $8 == "ban" {print; exit}' "$skynetevents"
						echo;echo
						Red "$counter Most Recent Manual Bans;"
						awk -F '\t' '$1 == "A1" && $6 == "rules" && $7 == "add" && $8 == "ban" {print}' "$skynetevents" | tail -"$counter"
					;;
					device)
						case "$#" in 4) ;; 5) Set_Stats_Search_Count "$5" || { echo "[*] Result Count Must Be A Positive Number"; echo; exit 2; } ;; *) echo "[*] Syntax: firewall stats search device <address> [count]"; echo; exit 2 ;; esac
						if ! echo "$4" | Is_IP; then echo "[*] $4 Is Not A Valid IP"; echo; exit 2; fi
						statssearchprefix="$TMP_DIR/stats-search.$$"
						Build_Stats_Search_Log device "$4" "$proto" "$statssearchprefix" || exit 1
						statslogsummary="${statssearchprefix}.logsummary"
						Print_Stats_Logging_Header
						IFS='~' read -r statssearchfirst statssearchlast statssearchtotal statssearchunique < "${statssearchprefix}.summary"
						echo "[i] $4 First Tracked On $statssearchfirst"
						echo "[i] $4 Last Tracked On $statssearchlast"
						echo "[i] $statssearchtotal Blocks Total"
						echo;echo
						Red "Device Name;"
						if grep -qF " $4 " "/var/lib/misc/dnsmasq.leases"; then grep -F " $4 " "/var/lib/misc/dnsmasq.leases" | awk '{print $4}'; else echo "Unknown"; fi
						echo;echo
						Red "First Block Tracked From $4;"
						sed -n '1p' "${statssearchprefix}.matches"
						echo;echo
						Red "$counter Most Recent Blocks From $4;"
						tail -"$counter" "${statssearchprefix}.matches"
						{
							awk 'NF >= 2 {print $2}' "${statssearchprefix}.http"
							awk 'NF >= 2 {print $2}' "${statssearchprefix}.other"
						} | awk 'NF && !seen[$0]++' > "$TMP_DIR/stats-lookup-ips.txt"
						statsreasoncache="$TMP_DIR/stats-reasons.txt"
						statscountrycache="$TMP_DIR/stats-countries.txt"
						statsdomaincache="$TMP_DIR/stats-domains.txt"
						statscountrybatch="1"
						Build_Stats_Ban_Reason_Cache "$TMP_DIR/stats-lookup-ips.txt" "$skynetipset" "$statsreasoncache" || exit 1
						Build_Stats_Country_Cache "$TMP_DIR/stats-lookup-ips.txt" "$statscountrycache" || true
						Build_Stats_Domain_Cache "$TMP_DIR/stats-lookup-ips.txt" "$statsdomaincache" || exit 1
						echo;echo
						Red "Top $counter HTTP(s) Blocks (Outbound);"
						Display_Header "2"
						sort -nr "${statssearchprefix}.http" | head -"$counter" > "$TMP_DIR/stats-device-http.$$"
						Print_Stats_Rows "$TMP_DIR/stats-device-http.$$" "2"
						echo;echo
						Red "Top $counter Blocks From (Outbound);"
						Display_Header "2"
						sort -nr "${statssearchprefix}.other" | head -"$counter" > "$TMP_DIR/stats-device-other.$$"
						Print_Stats_Rows "$TMP_DIR/stats-device-other.$$" "2"
						rm -f "$TMP_DIR/stats-device-http.$$" "$TMP_DIR/stats-device-other.$$"
						Remove_Stats_Search_Files "$statssearchprefix"
						unset "statscountrybatch"
					;;
					reports)
						if [ "$4" -eq "$4" ] 2>/dev/null; then counter="$4"; fi
						reportrows="$TMP_DIR/stats-reports.$$"
						grep -F "Skynet: [#] " "$syslog1loc" "$syslogloc" 2>/dev/null > "$reportrows"
						echo "[i] First Report Tracked On $(sed -n '1p' "$reportrows" | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo "[i] Last Report Tracked On $(tail -1 "$reportrows" | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo;echo
						Red "First Report Tracked;"
						sed -n '1p' "$reportrows"
						echo;echo
						Red "$counter Most Recent Reports;"
						tail -"$counter" "$reportrows"
						rm -f "$reportrows"
					;;
					invalid)
						if [ "$4" -eq "$4" ] 2>/dev/null; then counter="$4"; fi
						echo "[i] First Invalid Block Tracked On $(grep -m1 -F "BLOCKED - INVALID" "$skynetlog" | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo "[i] Last Invalid Block Tracked On $(grep -F "BLOCKED - INVALID" "$skynetlog" | tail -1 | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo;echo
						Red "First Invalid Block Tracked;"
						grep -m1 -F "BLOCKED - INVALID" "$skynetlog"
						echo;echo
						Red "$counter Most Recent Invalid Blocks;"
						grep -F "BLOCKED - INVALID" "$skynetlog" | tail -"$counter"
					;;
					connections)
						if [ -f "/proc/bw_cte_dump" ] && [ -f "/tmp/bwdpi/bwdpi.app.db" ]; then
							Display_Header "11"
							connectionfiltertype="$4"
							connectionfiltervalue="$5"
							# Load the DPI application map once, then decode and filter every
							# connection in the same POSIX AWK process.
							awk -v appdb="/tmp/bwdpi/bwdpi.app.db" -v filtertype="$connectionfiltertype" -v filtervalue="$connectionfiltervalue" '
								function hex_number(value, result, position, digit) {
									value = tolower(value)
									result = 0
									for (position = 1; position <= length(value); position++) {
										digit = index("0123456789abcdef", substr(value, position, 1)) - 1
										if (digit < 0) return 0
										result = (result * 16) + digit
									}
									return result
								}
								BEGIN {
									while ((getline line < appdb) > 0) {
										split(line, field, ",")
										if (field[3] == 0) application[field[1] SUBSEP field[2]] = field[4]
									}
									close(appdb)
								}
								{
									split($0, data, /[[:space:]]+/)
									mark = data[8]; sub(/^mark=/, "", mark); mark = hex_number(mark)
									appid = int(((int(mark / 65536) % 64) * 65536) / 65535)
									categoryid = mark % 65536
									proto = data[2]
									sourceip = data[3]; sub(/^src=/, "", sourceip)
									if (index(sourceip, ":")) sourceip = "IPv6 Address"
									destip = data[4]; sub(/^dst=/, "", destip)
									if (index(destip, ":")) destip = "IPv6 Address"
									sport = data[5]; sub(/^sport=/, "", sport)
									dport = data[6]; sub(/^dport=/, "", dport)
									reason = (appid == 0 && categoryid == 0 ? "Unidentified" : application[appid SUBSEP categoryid])
									if (filtertype == "ip" && filtervalue != "" && filtervalue != sourceip && filtervalue != destip) next
									if (filtertype == "port" && filtervalue != "" && filtervalue != sport && filtervalue != dport) next
									if (filtertype == "proto" && filtervalue != "" && filtervalue != proto) next
									if (filtertype == "id" && filtervalue != "" && filtervalue != reason) next
									printf "%-10s | %-18s | %-10s | %-18s | %-10s | %-18s\n", proto, sourceip, sport, destip, dport, reason
								}
							' /proc/bw_cte_dump
							unset "connectionfiltertype" "connectionfiltervalue"
						else
							echo "Please Enable AiProtection To Use This Feature"
						fi
					;;
					iot)
						if [ "$4" -eq "$4" ] 2>/dev/null; then counter="$4"; fi
						echo "[i] First IoT Block Tracked On $(grep -m1 -F "BLOCKED - IOT" "$skynetlog" | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo "[i] Last IoT Block Tracked On $(grep -F "BLOCKED - IOT" "$skynetlog" | tail -1 | awk '{printf "%s %s %s\n", $1, $2, $3}')"
						echo;echo
						Red "First IoT Block Tracked;"
						grep -m1 -F "BLOCKED - IOT" "$skynetlog"
						echo;echo
						Red "$counter Most Recent IoT Blocks;"
						grep -F "BLOCKED - IOT" "$skynetlog" | tail -"$counter"
						echo;echo
						Red "Top $counter IoT Blocks (Outbound);"
						Display_Header "2"
						Extract_Stats_Values "$skynetlog" "IOT.*$proto" "" "DST" "top" "$counter" > "$TMP_DIR/stats-iot.txt" || return 1
						awk 'NF >= 2 {print $NF}' "$TMP_DIR/stats-iot.txt" > "$TMP_DIR/stats-lookup-ips.txt" || return 1
						statsreasoncache="$TMP_DIR/stats-reasons.txt"
						statscountrycache="$TMP_DIR/stats-countries.txt"
						statsdomaincache="$TMP_DIR/stats-domains.txt"
						true > "$statscountrycache" || return 1
						Build_Stats_Ban_Reason_Cache "$TMP_DIR/stats-lookup-ips.txt" "$skynetipset" "$statsreasoncache" || return 1
						Build_Stats_Domain_Cache "$TMP_DIR/stats-lookup-ips.txt" "$statsdomaincache" || return 1
						Print_Stats_Rows "$TMP_DIR/stats-iot.txt" "2"
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
				Prepare_CLI_Stats_Data "$proto" "$counter" || {
					echo "[*] Failed To Prepare Statistics Data"
					return 1
				}
				statslogsummary="${statsindexpath}/summary.txt"
				Print_Stats_Logging_Header
				Display_Header "10"
				Red "Top $counter Targeted Ports (Inbound);"
				Display_Header "3"
				Extract_Stats_Values "${statsindexpath}/inbound-dpt.txt" ".*" "" "" "top" "$counter" | awk '{printf "%-10s | %-10s | %-60s\n", $1 "x", $2, "https://www.speedguide.net/port.php?port=" $2 }'
				Display_Header "9"
				Red "Top $counter Attacker Source Ports (Inbound);"
				Display_Header "3"
				Extract_Stats_Values "${statsindexpath}/inbound-spt.txt" ".*" "" "" "top" "$counter" | awk '{printf "%-10s | %-10s | %-60s\n", $1 "x", $2, "https://www.speedguide.net/port.php?port=" $2 }'
				Show_Stats_Block "log" "INBOUND.*$proto" "SRC" "Last $counter Unique Connections Blocked (Inbound)" "head" "$counter" "1" "1"
				Show_Stats_Block "log" "OUTBOUND.*$proto" "DST" "Last $counter Unique Connections Blocked (Outbound)" "head" "$counter" "1" "1"
				if Is_Enabled "$loginvalid"; then
					Show_Stats_Block "log" "INVALID.*$proto" "SRC" "Last $counter Unique Connections Blocked (Invalid)" "head" "$counter" "1" "1"
				fi
				Show_Action_Rule_History "$counter"
				Show_Stats_Block "log" "OUTBOUND.*$proto.*(DPT=80|DPT=443)" "DST" "Last $counter Unique HTTP(s) Blocks (Outbound)" "head" "$counter" "1" "1"
				Show_Stats_Block "log" "OUTBOUND.*$proto.*(DPT=80|DPT=443)" "DST" "Top $counter HTTP(s) Blocks (Outbound)" "head" "$counter" "2" "2"
				Show_Stats_Block "log" "INBOUND.*$proto" "SRC" "Top $counter Blocks (Inbound)" "head" "$counter" "2" "2"
				Show_Stats_Block "log" "OUTBOUND.*$proto" "DST" "Top $counter Blocks (Outbound)" "head" "$counter" "2" "2"
				if Is_Enabled "$loginvalid"; then
					Show_Stats_Block "log" "INVALID.*$proto" "SRC" "Top $counter Blocks (Invalid)" "head" "$counter" "2" "2"
				fi
				if Is_Enabled "$iotblocked"; then
					Show_Stats_Block "log" "IOT.*$proto" "DST" "Top $counter IoT Blocks (Outbound)" "head" "$counter" "2" "2"
				fi
				Display_Header "9"
				Red "Top $counter Blocked Devices (Outbound);"
				Display_Header "4"
				Extract_Stats_Values "${statsindexpath}/outbound-src.txt" ".*" "" "" "top" "$counter" > "$TMP_DIR/statsclients.txt"
				ip neigh > "$TMP_DIR/statsneighbors.txt" 2>/dev/null
				while read -r hits ipaddr; do
					macaddr="$(awk -v ip="$ipaddr" '$1 == ip { print $5; exit }' "$TMP_DIR/statsneighbors.txt")"
					Resolve_Client_Name
					printf '%-10s | %-16s | %-60s\n' "${hits}x" "${ipaddr}" "$localname"
				done < "$TMP_DIR/statsclients.txt"
			;;
		esac
		rm -f "$TMP_DIR/skynetstats.txt"
}

Generate_WebUI_IOT_Data() {
	# Merge three local sources without network lookups: saved blocks, dnsmasq
	# leases and the neighbour table. Prefix records identify their source before
	# awk folds them into one row per IP/CIDR.
	iotinventory="$TMP_DIR/iot-inventory.$$"
	iotrecords="$TMP_DIR/iot-records.$$"
	iotraw="$TMP_DIR/iot-raw.$$"
	ipset save Skynet-IOT > "$iotraw" 2>/dev/null || return 1
	awk '$1 == "add" { print "B~" $3 }' "$iotraw" > "$iotrecords" || return 1
	if [ -e /var/lib/misc/dnsmasq.leases ] || [ -L /var/lib/misc/dnsmasq.leases ]; then
		awk 'NF >= 4 { print "L~" $3 "~" $2 "~" $4 }' /var/lib/misc/dnsmasq.leases >> "$iotrecords" || return 1
	fi
	# Neighbour discovery is optional enrichment. Discard partial command output
	# on failure; saved devices and lease names remain available without it.
	if ip neigh > "$iotraw" 2>/dev/null; then
		awk '
			/^([0-9]{1,3}\.){3}[0-9]{1,3} / {
				mac = ""
				for (i = 1; i <= NF; i++) if ($i == "lladdr") mac = $(i + 1)
				print "N~" $1 "~" mac "~" $NF
			}' "$iotraw" >> "$iotrecords" || return 1
	fi

	awk -F '~' '
		$1 == "B" { blocked[$2] = 1; entries[$2] = 1 }
		$1 == "L" {
			entries[$2] = 1
			if (mac[$2] == "") mac[$2] = $3
			lease[$2] = $4
		}
		$1 == "N" {
			entries[$2] = 1
			if ($3 != "") mac[$2] = $3
			state[$2] = tolower($4)
		}
		END {
			for (entry in entries)
				printf "%d~%s~%s~%s~%s\n", blocked[entry] + 0, entry, mac[entry], state[entry], lease[entry]
		}' "$iotrecords" > "$iotinventory" || return 1
	sort -t '~' -k1,1nr -k2,2 "$iotinventory" > "$iotrecords" \
		&& mv -f "$iotrecords" "$iotinventory" || return 1

	printf 'var SkynetIOTDevices = [' >> "$settingstmp" || return 1
	iotfirst="1"
	while IFS='~' read -r iotselected ipaddr macaddr iotstate iotlease; do
		[ -n "$ipaddr" ] || continue
		if printf '%s\n' "$ipaddr" | Is_Range; then
			localname="IP Range"
			macaddr="Unknown"
			iotstate="offline"
		else
			Resolve_Client_Name
			if [ "$localname" = "Unknown" ] && [ -n "$iotlease" ] && [ "$iotlease" != "*" ]; then
				localname="$iotlease"
			fi
			if ! printf '%s\n' "$macaddr" | Is_MAC; then
				macaddr="Unknown"
				iotstate="offline"
			else
				case "$iotstate" in failed|incomplete|offline|"") iotstate="offline" ;; *) iotstate="online" ;; esac
			fi
		fi
		iotnamejs="$(printf '%s\n' "$localname" | Escape_JS)" || return 1
		if [ "$iotfirst" != "1" ]; then printf ',' >> "$settingstmp" || return 1; fi
		printf '\n\t{ip:\x27%s\x27,mac:\x27%s\x27,name:\x27%s\x27,state:\x27%s\x27,blocked:%s}' \
			"$ipaddr" "$macaddr" "$iotnamejs" "$iotstate" "$([ "$iotselected" = "1" ] && printf true || printf false)" >> "$settingstmp" || return 1
		iotfirst="0"
	done < "$iotinventory"
	printf '\n];\n' >> "$settingstmp" || return 1
	rm -f "$iotinventory" "$iotrecords" "$iotraw"
}

Generate_WebUI_Feed_Data() {
	feedstatusfile="$skynetloc/lists/.sources"
	feedmembership="$skynetloc/lists/.selection"
	feedlegacymembership="0"
	if [ ! -e "$feedmembership" ] && [ ! -L "$feedmembership" ]; then feedmembership="$feedstatusfile"; feedlegacymembership="1"; fi
	if [ ! -e "$feedmembership" ] && [ ! -L "$feedmembership" ]; then feedmembership="/dev/null"; fi
	if [ ! -e "$feedstatusfile" ] && [ ! -L "$feedstatusfile" ]; then feedstatusfile="/dev/null"; fi
	# Membership drives rows; health joins only on the exact name and URL.
	# Missing health is pending, never a fabricated failed download.
	awk -F '\t' -v status="$feedstatusfile" -v legacy="$feedlegacymembership" -v excluded="$excludelists" '
		BEGIN {
			quote = sprintf("%c", 39)
			split(excluded, values, " "); for (i in values) skip[tolower(values[i])] = 1
			while ((readstatus = getline line < status) > 0) {
				split(line, fields, "\t")
				key = fields[1] SUBSEP fields[2]
				state[key] = fields[4]; entries[key] = fields[5]
				checked[key] = fields[6]; success[key] = fields[7]; changed[key] = fields[9]
			}
			close(status)
			if (readstatus < 0) exit 1
			printf "var SkynetFeeds = ["
		}
		function js(value, i, char, output) {
			output = ""
			for (i = 1; i <= length(value); i++) {
				char = substr(value, i, 1)
				if (char == "\\") output = output "\\\\"
				else if (char == quote) output = output "\\" quote
				else if (char != "\r") output = output char
			}
			return quote output quote
		}
		function number(value) { return value ~ /^[0-9]+$/ ? value + 0 : 0 }
		NF >= 3 {
			key = $1 SUBSEP $2
			enabled = legacy ? !(tolower($1) in skip) : $3 == "enabled"
			current = state[key]
			if (!enabled) current = "excluded"
			else if (current == "excluded") current = number(entries[key]) > 0 ? "cached" : "pending"
			else if (current !~ /^(current|cached|failed)$/) current = "pending"
			if (total++) printf ","
			printf "\n\t{name:%s,url:%s,enabled:%s,state:%s,entries:%.0f,checked:%.0f,success:%.0f,changed:%.0f}", \
				js($1), js($2), enabled ? "true" : "false", js(current), number(entries[key]), number(checked[key]), number(success[key]), number(changed[key])
			count[current]++
		}
		END {
			print "\n];"
			printf "var SkynetFeedSummary = {available:%s,total:%d,current:%d,cached:%d,failed:%d,excluded:%d,pending:%d};\n", \
				total ? "true" : "false", total, count["current"], count["cached"], count["failed"], count["excluded"], count["pending"]
		}
	' "$feedmembership" >> "$settingstmp"
}

Generate_WebUI_Country_Data() {
	countrystatusfile="$skynetloc/lists/countries/.manifest"
	if [ ! -e "$countrystatusfile" ] && [ ! -L "$countrystatusfile" ]; then countrystatusfile="/dev/null"; fi
	# Missing source history is optional; an existing unreadable file is an error.
	# One serializer owns the complete array and summary, including escaping.
	awk -F '\t' -v selected="$countrylist" '
		BEGIN {
			quote = sprintf("%c", 39)
			split(selected, values, " "); for (i in values) wanted[values[i]] = 1
			printf "var SkynetCountries = ["
		}
		function js(value, i, char, output) {
			output = ""
			for (i = 1; i <= length(value); i++) {
				char = substr(value, i, 1)
				if (char == "\\") output = output "\\\\"
				else if (char == quote) output = output "\\" quote
				else if (char != "\r") output = output char
			}
			return quote output quote
		}
		function number(value) { return value ~ /^[0-9]+$/ ? value + 0 : 0 }
		$1 ~ /^[a-z][a-z]$/ && ($1 in wanted) && $3 ~ /^(current|cached|failed)$/ {
			if (total++) printf ","
			printf "\n\t{code:%s,url:%s,state:%s,entries:%.0f,checked:%.0f,success:%.0f,changed:%.0f}", \
				js($1), js($2), js($3), number($4), number($5), number($6), number($8)
			count[$3]++
		}
		END {
			print "\n];"
			printf "var SkynetCountrySummary = {available:%s,total:%d,current:%d,cached:%d,failed:%d};\n", \
				total ? "true" : "false", total, count["current"], count["cached"], count["failed"]
		}
	' "$countrystatusfile" >> "$settingstmp"
}

Generate_WebUI_Rule_Data() {
	rulerecords="$TMP_DIR/webui-rules-records.$$"
	rulerecordssorted="${rulerecords}.sorted"
	if [ ! -e "$skynetrules" ] && [ ! -L "$skynetrules" ]; then
		printf 'var SkynetRules = [];\nvar SkynetRuleSummary = {available:false,timeReady:false,now:0,total:0,manualBans:0,manualWhitelists:0,temporary:0,groups:0,groupEntries:0,domains:0,asns:0,current:0,cached:0,pending:0,empty:0,expired:0,failed:0,lastCheck:0};\n' >> "$settingstmp"
		return
	fi
	if Time_Is_Ready; then rulewebnow="$(date +%s)"; rulewebtimeready="true"; else rulewebnow="0"; rulewebtimeready="false"; fi
	rulewebstatusfile="$rulestatusmanifest"
	if [ ! -e "$rulewebstatusfile" ] && [ ! -L "$rulewebstatusfile" ]; then rulewebstatusfile="/dev/null"; fi
	awk -F '\t' -v OFS='\t' -v status="$rulewebstatusfile" -v datadir="$rulesdatadir" -v now="$rulewebnow" '
		BEGIN {
			while ((readstatus = getline line < status) > 0) {
				split(line, field, "\t")
				if (field[1] == "D1" || field[1] == "D2") {
					key = field[2] SUBSEP field[3]
					domain_state[key] = field[4]; domain_count[key] = field[5]
					domain_checked[key] = field[6]; domain_success[key] = field[7]
				}
			}
			close(status)
			if (readstatus < 0) exit 1
		}
		$1 == "R2" && $7 == "enabled" {
			id = $2; action = $3; type = $4; value = $5; detail = substr($6, 2)
			created = $8 + 0; expires = $9 + 0; data = $10; count = 1
			if (expires > 0 && now > 0 && expires <= now) next
			state = "-"; checked = 0; success = 0
			if (action == "ban" && (type == "ip" || type == "range")) {
				kind = expires > 0 ? "temporary" : "manual"
				setname = expires > 0 ? "Skynet-TemporaryBans" : "Skynet-UserBans"
				display = detail
			}
			else if (action == "whitelist" && (type == "ip" || type == "range")) { kind = "manual"; setname = "Skynet-UserWhitelist"; display = detail }
			else if (type == "domain") {
				kind = "group"; setname = action == "ban" ? "Skynet-BlacklistDomains" : "Skynet-WhitelistDomains"
				display = value; key = action SUBSEP value
				count = domain_count[key] + 0; state = domain_state[key] == "" ? "pending" : domain_state[key]
				checked = domain_checked[key] + 0; success = domain_success[key] + 0
			}
			else if (type == "asn" || type == "import") {
				kind = type == "import" ? "import" : "group"
				setname = action == "ban" ? "Skynet-UserBans" : "Skynet-UserWhitelist"; display = value
				datafile = datadir "/" data
				if (!(data in data_count)) {
					data_count[data] = 0
					while ((datastatus = getline line < datafile) > 0) if (line != "") data_count[data]++
					close(datafile)
					if (datastatus < 0) exit 1
				}
				count = data_count[data]
			}
			else next
			# Prefix empty-capable fields because BusyBox ash collapses adjacent tab
			# delimiters when the generated records are read below.
			print id, kind, action, type, setname, value, "@" detail, "@" display, count, state, checked, success, created, expires
		}
	' "$skynetrules" > "$rulerecords" || { rm -f "$rulerecords"; return 1; }
	if ! sort -t "$(printf '\t')" -k3,3 -k4,4 -k6,6 "$rulerecords" > "$rulerecordssorted" \
		|| ! mv -f "$rulerecordssorted" "$rulerecords"; then
		rm -f "$rulerecords" "$rulerecordssorted"
		return 1
	fi
	# Sorted logical rows are escaped and summarized together; no per-rule shell
	# subprocesses are needed even for large manual rule registries.
	awk -F '\t' -v ready="$rulewebtimeready" -v now="$rulewebnow" '
		BEGIN { quote = sprintf("%c", 39); printf "var SkynetRules = [" }
		function js(value, i, char, output) {
			output = ""
			for (i = 1; i <= length(value); i++) {
				char = substr(value, i, 1)
				if (char == "\\") output = output "\\\\"
				else if (char == quote) output = output "\\" quote
				else if (char != "\r") output = output char
			}
			return quote output quote
		}
		NF == 14 {
			if (total++) printf ","
			printf "\n\t{id:%s,kind:%s,action:%s,type:%s,target:%s,entry:%s,comment:%s,display:%s,count:%s,state:%s,checked:%s,success:%s,created:%s,expires:%s}", \
				js($1), js($2), js($3), js($4), js($5), js($6), js(substr($7, 2)), js(substr($8, 2)), $9 + 0, js($10), $11 + 0, $12 + 0, $13 + 0, $14 + 0
			if ($4 == "domain") {
				domains++
				if ($10 ~ /^(current|cached|empty|expired|failed)$/) health[$10]++
				else health["pending"]++
				if ($11 > lastcheck) lastcheck = $11
			}
			if ($4 == "asn") asns++
			if ($2 == "manual" && $3 == "ban") bans++
			else if ($2 == "manual" && $3 == "whitelist") whitelists++
			else if ($2 == "temporary" && $3 == "ban") temporary++
			else { groups++; entries += $9 }
		}
		END {
			print "\n];"
			printf "var SkynetRuleSummary = {available:true,timeReady:%s,now:%s,total:%d,manualBans:%d,manualWhitelists:%d,temporary:%d,groups:%d,groupEntries:%d,domains:%d,asns:%d,current:%d,cached:%d,pending:%d,empty:%d,expired:%d,failed:%d,lastCheck:%d};\n", \
				ready, now, total, bans, whitelists, temporary, groups, entries, domains, asns, health["current"], health["cached"], health["pending"], health["empty"], health["expired"], health["failed"], lastcheck
		}
	' "$rulerecords" >> "$settingstmp"
	rulewebstatus="$?"
	rm -f "$rulerecords"
	return "$rulewebstatus"
}

Generate_WebUI_Action_Data() {
	# Keep only the last twenty valid records, including this request's pending
	# actions. Serialization is bounded and does not fork once per field.
	set -- /dev/null
	if [ -e "$skynetevents" ] || [ -L "$skynetevents" ]; then set -- "$@" "$skynetevents"; fi
	if [ -e "$actionqueue" ] || [ -L "$actionqueue" ]; then set -- "$@" "$actionqueue"; fi
	awk -F '\t' '
		BEGIN { quote = sprintf("%c", 39) }
		function js(value, i, char, output) {
			output = ""
			for (i = 1; i <= length(value); i++) {
				char = substr(value, i, 1)
				if (char == "\\") output = output "\\\\"
				else if (char == quote) output = output "\\" quote
				else if (char != "\r") output = output char
			}
			return quote output quote
		}
		$1 == "A1" && NF == 12 && $2 ~ /^[0-9]+$/ &&
		$4 ~ /^(cli|menu|webui|cron|startup)$/ && $5 ~ /^(success|degraded|failed)$/ &&
		$6 ~ /^(rules|iot|countries|feeds|settings|system)$/ { rows[count++ % 20] = $0 }
		END {
			printf "var SkynetActions = ["
			for (i = (count > 20 ? count - 20 : 0); i < count; i++) {
				split(rows[i % 20], field, "\t")
				if (first++) printf ","
				printf "\n\t{epoch:%s,time:%s,origin:%s,result:%s,area:%s,operation:%s,target:%s,type:%s,entries:%s,detail:%s,transaction:%s}", \
					field[2], js(field[3]), js(field[4]), js(field[5]), js(field[6]), js(field[7]), \
					js(field[8]), js(field[9]), js(field[10]), js(field[11]), js(field[12])
			}
			print "\n];"
		}
	' "$@" >> "$settingstmp"
}

Generate_WebUI_Settings() {
	# Publish one complete payload. The final generation and request fields let
	# the browser distinguish completed actions from a cached previous response.
	Update_Block_Counts strict || { Log error "Failed To Read IPSet Counters - Existing WebUI Settings Retained"; return 1; }
	settingsfile="${skynetloc}/webui/settings.js"
	settingstmp="${settingsfile}.tmp.$$"
	settingspreparestatus="0"
	customlistjs="$(settings_template="$customlisturl" awk 'BEGIN {
		value = ENVIRON["settings_template"]
		for (i = 1; i <= length(value); i++) {
			char = substr(value, i, 1)
			if (char == "\\" || char == "\"") printf "\\%s", char
			else if (char == "\r" || char == "\n") printf " "
			else printf "%s", char
		}
	}')" || settingspreparestatus="1"
	excludelistsjs="$(printf '%s\n' "$excludelists" | Escape_JS)" || settingspreparestatus="1"
	sysloglocjs="$(printf '%s' "$syslogloc" | Escape_JS)" || settingspreparestatus="1"
	syslog1locjs="$(printf '%s' "$syslog1loc" | Escape_JS)" || settingspreparestatus="1"
	settingsiotraw="$TMP_DIR/settings-iot.$$"
	if ipset save Skynet-IOT > "$settingsiotraw" 2>/dev/null; then
		iotentries="$(awk '$1 == "add" { if (output != "") output = output " "; output = output $3 } END { print output }' "$settingsiotraw")" || settingspreparestatus="1"
		iotcount="$(awk '$1 == "add" {count++} END {print count + 0}' "$settingsiotraw")" || settingspreparestatus="1"
	else settingspreparestatus="1"
	fi
	rm -f "$settingsiotraw"
	if [ "$settingspreparestatus" = "0" ] && printf 'var SkynetSettings = {"autoupdate":"%s","banmalwareupdate":"%s","banmalwarelastupdated":"%s","blacklist1count":"%s","blacklist2count":"%s","countrylist":"%s","customlisturl":"%s","excludelists":"%s","filtertraffic":"%s","unbanprivateip":"%s","banaiprotect":"%s","securemode":"%s","loginvalid":"%s","logsize":"%s","extendedstats":"%s","lookupcountry":"%s","cdnwhitelist":"%s","iotblocked":"%s","iotlogging":"%s","iotports":"%s","iotproto":"%s","iotentries":"%s","iotcount":"%s"};\n' "$autoupdate" "$banmalwareupdate" "$banmalwarelastupdated" "$blacklist1count" "$blacklist2count" "$countrylist" "$customlistjs" "$excludelistsjs" "$filtertraffic" "$unbanprivateip" "$banaiprotect" "$securemode" "$loginvalid" "$logsize" "$extendedstats" "$lookupcountry" "$cdnwhitelist" "$iotblocked" "$iotlogging" "$iotports" "$iotproto" "$iotentries" "$iotcount" > "$settingstmp" \
		&& printf 'SkynetSettings.logmode = "%s";\n' "$logmode" >> "$settingstmp" \
		&& printf 'SkynetSettings.syslogmode = "%s";\n' "$syslogmode" >> "$settingstmp" \
		&& printf "SkynetSettings.syslogloc = '%s';\nSkynetSettings.syslog1loc = '%s';\n" \
			"$sysloglocjs" "$syslog1locjs" >> "$settingstmp" \
		&& Generate_WebUI_IOT_Data \
		&& Generate_WebUI_Feed_Data \
		&& Generate_WebUI_Country_Data \
		&& Generate_WebUI_Rule_Data \
		&& Generate_WebUI_Action_Data \
		&& printf 'var SkynetSettingsGenerated = "%s.%s";\n' "$(date +%s)" "$$" >> "$settingstmp" \
		&& printf 'var SkynetSettingsResult = "%s";\n' "${settingsresult:-ready}" >> "$settingstmp" \
		&& printf 'var SkynetSettingsRequest = "%s";\n' "${webuirequestid:-}" >> "$settingstmp" \
		&& [ -s "$settingstmp" ] && mv -f "$settingstmp" "$settingsfile"; then
		return 0
	fi
	rm -f "$settingstmp"
	Log error "Failed To Generate WebUI Settings - Existing File Retained"
	return 1
}

Generate_Stats() {
	# Generate every chart into an isolated workspace and publish stats.js only
	# after all required arrays are complete. The previous payload survives any
	# parsing, lookup or write failure.
	Addon_API_Supported || return 0
	Is_Enabled "$displaywebui" || return 0
	Is_Enabled "$logmode" || return 0
	Update_Block_Counts strict || { Log error "Failed To Read IPSet Counters - Existing Statistics Retained"; return 1; }

	# Intermediate chart indexes stay in RAM; only the complete payload is
	# published to USB. The process workspace is removed by the cleanup trap.
	statsworkspace="$TMP_DIR/stats"
	if ! mkdir -p "$statsworkspace" || [ ! -w "$statsworkspace" ]; then
		Log error "Failed To Create WebUI Statistics Workspace"
		return 1
	fi

	statsfile="${skynetloc}/webui/stats.js"
	statstmp="${statsfile}.tmp.$$"
	statsbanlist="${statsworkspace}/banlist.txt"
	statscountrycache="${statsworkspace}/countries.txt"
	statsdomaincache="${statsworkspace}/domains.txt"
	statsreasoncache="${statsworkspace}/reasons.txt"
	statslookupips="${statsworkspace}/lookup-ips.txt"
	statsreasonips="${statsworkspace}/reason-ips.txt"
	statsstatus="0"

	true > "$statstmp" || statsstatus="1"
	true > "$statscountrycache" || statsstatus="1"
	awk '$1 == "add" && ($2 == "Skynet-Blacklist" || $2 == "Skynet-BlockedRanges")' "$skynetipset" > "$statsbanlist" || statsstatus="1"

	statsprerouting="${statsworkspace}/prerouting.txt"
	statsoutput="${statsworkspace}/output.txt"
	iptables -xnvL PREROUTING -t raw > "$statsprerouting" 2>/dev/null || statsstatus="1"
	iptables -xnvL OUTPUT -t raw > "$statsoutput" 2>/dev/null || statsstatus="1"
	statshits="$(awk '
		index($0, "LOG") == 0 && index($0, "Skynet-Master src") { inbound += $1 }
		index($0, "LOG") == 0 && index($0, "Skynet-Master dst") { outbound += $1 }
		END { print inbound + 0, outbound + 0 }
	' "$statsprerouting" "$statsoutput")" || statsstatus="1"
	statshits="${statshits:-0 0}"
	hits1="${statshits%% *}"
	hits2="${statshits#* }"

	Write_Stats_ToJS "$blacklist1count" "$statstmp" "SetBLCount1" "blcount1" || statsstatus="1"
	Write_Stats_ToJS "$blacklist2count" "$statstmp" "SetBLCount2" "blcount2" || statsstatus="1"
	Write_Stats_ToJS "$hits1" "$statstmp" "SetHits1" "hits1" || statsstatus="1"
	Write_Stats_ToJS "$hits2" "$statstmp" "SetHits2" "hits2" || statsstatus="1"
	statslogsize="$(du -h "$skynetlog")" || statsstatus="1"
	Write_Stats_ToJS "${statslogsize%%[[:space:]]*}B" "$statstmp" "SetStatsSize" "statssize" || statsstatus="1"
	printf 'var SkynetStatsGenerated = "%s.%s";\n' "$(date +%s)" "$$" >> "$statstmp" || statsstatus="1"
	case "${SKYNET_WEBUI_REQUEST:-}" in *[!0-9]*) statsstatus="1" ;; esac
	printf 'var SkynetStatsRequest = "%s";\n' "${SKYNET_WEBUI_REQUEST:-}" >> "$statstmp" || statsstatus="1"

	Build_Stats_Log_Index "$skynetlog" "$statsworkspace" || statsstatus="1"
	statsspan=""
	IFS= read -r statsspan < "${statsworkspace}/span.txt"
	Write_Stats_ToJS "${statsspan:-N/A}" "$statstmp" "SetStatsDate" "statsdate" || statsstatus="1"
	Write_Data_ToJS "${statsworkspace}/activity.txt" "$statstmp" "LabelActivityToday" "DataActivityInbound" "DataActivityOutbound" "DataActivityInvalid" "DataActivityIOT" || statsstatus="1"

	# Extract chart IPs before enrichment so the large IPSet and dnsmasq histories
	# are each scanned once for only the addresses the WebUI will display.
	Extract_Stats_Values "${statsworkspace}/inbound-src.txt" ".*" "" "" "recent" "10" > "${statsworkspace}/liconn-ips.txt" || statsstatus="1"
	Extract_Stats_Values "${statsworkspace}/outbound-dst.txt" ".*" "" "" "recent" "10" > "${statsworkspace}/loconn-ips.txt" || statsstatus="1"
	Extract_Stats_Values "${statsworkspace}/outbound-http-dst.txt" ".*" "" "" "recent" "10" > "${statsworkspace}/lhconn-ips.txt" || statsstatus="1"
	Extract_Stats_Values "${statsworkspace}/outbound-http-dst.txt" ".*" "" "" "top" "10" > "${statsworkspace}/thconn-ips.txt" || statsstatus="1"
	Extract_Stats_Values "${statsworkspace}/inbound-src.txt" ".*" "" "" "top" "10" > "${statsworkspace}/ticonn-ips.txt" || statsstatus="1"
	Extract_Stats_Values "${statsworkspace}/outbound-dst.txt" ".*" "" "" "top" "10" > "${statsworkspace}/toconn-ips.txt" || statsstatus="1"
	if Is_Enabled "$loginvalid"; then
		Extract_Stats_Values "${statsworkspace}/invalid-src.txt" ".*" "" "" "top" "10" > "${statsworkspace}/tinvconn-ips.txt" || statsstatus="1"
	else
		true > "${statsworkspace}/tinvconn-ips.txt" || statsstatus="1"
	fi
	if Is_Enabled "$iotblocked"; then
		Extract_Stats_Values "${statsworkspace}/iot-dst.txt" ".*" "" "" "top" "10" > "${statsworkspace}/tiotconn-ips.txt" || statsstatus="1"
	else
		true > "${statsworkspace}/tiotconn-ips.txt" || statsstatus="1"
	fi
	awk 'NF && !seen[$NF]++ {print $NF}' \
		"${statsworkspace}/liconn-ips.txt" "${statsworkspace}/loconn-ips.txt" "${statsworkspace}/lhconn-ips.txt" \
		"${statsworkspace}/thconn-ips.txt" "${statsworkspace}/ticonn-ips.txt" \
		"${statsworkspace}/toconn-ips.txt" "${statsworkspace}/tinvconn-ips.txt" "${statsworkspace}/tiotconn-ips.txt" \
		> "$statslookupips" || statsstatus="1"
	awk 'NF && !seen[$0]++' "${statsworkspace}/liconn-ips.txt" "${statsworkspace}/loconn-ips.txt" \
		"${statsworkspace}/lhconn-ips.txt" > "$statsreasonips" || statsstatus="1"
	Build_Stats_Ban_Reason_Cache "$statsreasonips" "$statsbanlist" "$statsreasoncache" || statsstatus="1"
	Build_Stats_Domain_Cache "$statslookupips" "$statsdomaincache" || statsstatus="1"
	statscountrybatch="1"
	Build_Stats_Country_Cache "$statslookupips" "$statscountrycache" || statsstatus="1"

	# Inbound Ports
	Extract_Stats_Values "${statsworkspace}/inbound-dpt.txt" ".*" "" "" "top" "10" > "${statsworkspace}/ports.txt" \
		&& awk '{print $1 "~" $2}' "${statsworkspace}/ports.txt" > "${statsworkspace}/iport.txt" || statsstatus="1"
	Write_Data_ToJS "${statsworkspace}/iport.txt" "$statstmp" "DataInPortHits" "LabelInPortHits" || statsstatus="1"

	# Source Ports
	Extract_Stats_Values "${statsworkspace}/inbound-spt.txt" ".*" "" "" "top" "10" > "${statsworkspace}/ports.txt" \
		&& awk '{print $1 "~" $2}' "${statsworkspace}/ports.txt" > "${statsworkspace}/sport.txt" || statsstatus="1"
	Write_Data_ToJS "${statsworkspace}/sport.txt" "$statstmp" "DataSPortHits" "LabelSPortHits" || statsstatus="1"

	# Recent Connections
	Write_Recent_IP_Stats "${statsworkspace}/liconn.txt" < "${statsworkspace}/liconn-ips.txt" || statsstatus="1"
	Write_Data_ToJS "${statsworkspace}/liconn.txt" "$statstmp" "LabelInConn_IPs" "LabelInConn_BanReason" "LabelInConn_AlienVault" "LabelInConn_Country" "LabelInConn_AssDomains" || statsstatus="1"

	Write_Recent_IP_Stats "${statsworkspace}/loconn.txt" < "${statsworkspace}/loconn-ips.txt" || statsstatus="1"
	Write_Data_ToJS "${statsworkspace}/loconn.txt" "$statstmp" "LabelOutConn_IPs" "LabelOutConn_BanReason" "LabelOutConn_AlienVault" "LabelOutConn_Country" "LabelOutConn_AssDomains" || statsstatus="1"

	Write_Recent_IP_Stats "${statsworkspace}/lhconn.txt" < "${statsworkspace}/lhconn-ips.txt" || statsstatus="1"
	Write_Data_ToJS "${statsworkspace}/lhconn.txt" "$statstmp" "LabelHTTPConn_IPs" "LabelHTTPConn_BanReason" "LabelHTTPConn_AlienVault" "LabelHTTPConn_Country" "LabelHTTPConn_AssDomains" || statsstatus="1"

	# Top Connections
	Write_Top_IP_Stats "${statsworkspace}/thconn.txt" code domains < "${statsworkspace}/thconn-ips.txt" || statsstatus="1"
	Write_Data_ToJS "${statsworkspace}/thconn.txt" "$statstmp" "DataTHConnHits" "LabelTHConnHits_IPs" "LabelTHConnHits_Country" "LabelTHConnHits_AssDomains" || statsstatus="1"

	Write_Top_IP_Stats "${statsworkspace}/ticonn.txt" code nodomains < "${statsworkspace}/ticonn-ips.txt" || statsstatus="1"
	Write_Data_ToJS "${statsworkspace}/ticonn.txt" "$statstmp" "DataTIConnHits" "LabelTIConnHits_IPs" "LabelTIConnHits_Country" || statsstatus="1"

	Write_Top_IP_Stats "${statsworkspace}/toconn.txt" code domains < "${statsworkspace}/toconn-ips.txt" || statsstatus="1"
	Write_Data_ToJS "${statsworkspace}/toconn.txt" "$statstmp" "DataTOConnHits" "LabelTOConnHits_IPs" "LabelTOConnHits_Country" "LabelTOConnHits_AssDomains" || statsstatus="1"

	if Is_Enabled "$loginvalid"; then
		Write_Top_IP_Stats "${statsworkspace}/tinvconn.txt" code nodomains < "${statsworkspace}/tinvconn-ips.txt" || statsstatus="1"
	else
		true > "${statsworkspace}/tinvconn.txt" || statsstatus="1"
	fi
	Write_Data_ToJS "${statsworkspace}/tinvconn.txt" "$statstmp" "DataTInvConnHits" "LabelTInvConnHits_IPs" "LabelTInvConnHits_Country" || statsstatus="1"

	if Is_Enabled "$iotblocked"; then
		Write_Top_IP_Stats "${statsworkspace}/tiotconn.txt" code domains < "${statsworkspace}/tiotconn-ips.txt" || statsstatus="1"
	else
		true > "${statsworkspace}/tiotconn.txt" || statsstatus="1"
	fi
	Write_Data_ToJS "${statsworkspace}/tiotconn.txt" "$statstmp" "DataTIOTConnHits" "LabelTIOTConnHits_IPs" "LabelTIOTConnHits_Country" "LabelTIOTConnHits_AssDomains" || statsstatus="1"

	# Top Clients
	Extract_Stats_Values "${statsworkspace}/outbound-src.txt" ".*" "" "" "top" "10" > "${statsworkspace}/clients.txt" || statsstatus="1"
	statsneighbors="${statsworkspace}/neighbors.txt"
	ip neigh > "$statsneighbors" 2>/dev/null
	Prepare_Client_Name_Data "$statsneighbors" || true
	while read -r statsclienthits statsclientip; do
		[ -n "$statsclientip" ] || continue
		ipaddr="$statsclientip"
		macaddr="$(awk -v ip="$statsclientip" '$1 == ip {print $5; exit}' "$statsneighbors")"
		Resolve_Client_Name
		printf '%s\n' "$macaddr" | Is_MAC || macaddr="Unknown"
		[ "${#localname}" -le 20 ] || localname="$(printf '%s' "$localname" | cut -c1-20)"
		printf '%s~%s (%s)~%s\n' "$statsclienthits" "$statsclientip" "$localname" "$macaddr" || { statsstatus="1"; break; }
	done < "${statsworkspace}/clients.txt" > "${statsworkspace}/tcconn.txt" || statsstatus="1"
	Clear_Client_Name_Data
	Write_Data_ToJS "${statsworkspace}/tcconn.txt" "$statstmp" "DataTCConnHits" "LabelTCConnHits" "LabelTCConnHits_MAC" || statsstatus="1"

	if [ "$statsstatus" = "0" ] && printf 'var SkynetStatsComplete = true;\n' >> "$statstmp" \
		&& [ -s "$statstmp" ] && mv -f "$statstmp" "$statsfile"; then
		rm -rf "$statsworkspace"
		Generate_WebUI_Settings
		return "$?"
	fi

	rm -f "$statstmp"
	rm -rf "$statsworkspace"
	Log error "Failed To Generate WebUI Statistics - Existing File Retained"
	Generate_WebUI_Settings
	return 1
}
Generate_Blocked_Events() {
	# Count events, unique remote IPs and the monitor span in one log pass. A
	# manual counter is used because POSIX awk does not define length(array).
	if blockedeventsummary="$(awk '
		/\[BLOCKED - (INBOUND|OUTBOUND|INVALID|IOT)\]/ {
			eventcount++
			stamp=$1 " " $2 " " $3
			if (monitorfirst == "") monitorfirst=stamp
			monitorlast=stamp
		}
		/\[BLOCKED - (INBOUND|INVALID)\]/ {
			for (i = 1; i <= NF; i++)
				if ($i ~ /^SRC=/) {
					split($i, ip, "=")
					if (ip[2] ~ /^[0-9.]+$/ && !seen[ip[2]]++) uniquecount++
					break
				}
		}
		/\[BLOCKED - OUTBOUND\]/ {
			for (i = 1; i <= NF; i++)
				if ($i ~ /^DST=/) {
					split($i, ip, "=")
					if (ip[2] ~ /^[0-9.]+$/ && !seen[ip[2]]++) uniquecount++
					break
				}
		}
		END { printf "%d (%d Unique IPs)|%s|%s", eventcount, uniquecount, monitorfirst, monitorlast }
	' "$skynetlog")"; then
		blockedevents="${blockedeventsummary%%|*}"
		monitorvalues="${blockedeventsummary#*|}"
		monitorfirst="${monitorvalues%%|*}"
		monitorlast="${monitorvalues#*|}"
		if [ -n "$monitorfirst" ] && [ -n "$monitorlast" ]; then
			monitorspan="$monitorfirst → $monitorlast"
		else
			monitorspan="No Data"
		fi
	else
		blockedevents="Unavailable"
		monitorspan="Unavailable"
	fi
	printf '║ %-20s │ %-82s ║\n' "Block Events" "$blockedevents"
}

########################
#- WebUI Installation -#
########################

Find_WebUI_Page() {
	# Prefer an exact source match, then reclaim an older Skynet page by its
	# unique title. This avoids consuming a second Merlin user-page slot.
	if Addon_API_Supported && Is_Enabled "$displaywebui"; then
		MyPage="none"
		webuipagemd5="$(md5sum < "$1")"
		for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
			page="/www/user/user$i.asp"
			if [ -f "$page" ] && [ "$webuipagemd5" = "$(md5sum < "$page")" ]; then
				MyPage="user$i.asp"
				return
			elif [ -f "$page" ] && grep -qF '<title>Skynet Statistics</title>' "$page"; then
				MyPage="user$i.asp"
				return
			elif [ "$MyPage" = "none" ] && [ ! -f "$page" ]; then
				MyPage="user$i.asp"
			fi
		done
	fi
}

Install_WebUI_Page() {
	Addon_API_Supported || return 1
	Is_Enabled "$displaywebui" || return 0
	[ -f "${skynetloc}/webui/skynet.asp" ] || {
		Log error "Unable To Mount Skynet Web Page - Source File Missing"
		return 1
	}

	Find_WebUI_Page "${skynetloc}/webui/skynet.asp"
	if [ "$MyPage" = "none" ]; then
		Log error "Unable To Mount Skynet Web Page - No Mount Points Available"
		return 1
	fi
	Log info "Mounting Skynet Web Page As $MyPage"
	ln -sf "${skynetloc}/webui/skynet.asp" "/www/user/$MyPage" || return 1
	if [ "$(uname -o)" = "ASUSWRT-Merlin" ]; then
		if [ ! -f "/tmp/menuTree.js" ]; then
			cp -f "/www/require/modules/menuTree.js" "/tmp/" || return 1
		fi
		sed -i "\\~$MyPage~d" /tmp/menuTree.js \
			&& sed -i "/url: \"Advanced_Firewall_Content.asp\", tabName:/a {url: \"$MyPage\", tabName: \"Skynet\"}," /tmp/menuTree.js \
			|| return 1
		umount /www/require/modules/menuTree.js 2>/dev/null
		mount -o bind /tmp/menuTree.js /www/require/modules/menuTree.js || return 1
	else
		MyPageTitle="${MyPage%.asp}.title"
		echo "Skynet" > "/www/user/$MyPageTitle" || return 1
	fi
	mkdir -p "/www/user/skynet" \
		&& ln -sf "${skynetloc}/webui/stats.js" "/www/user/skynet/stats.js" \
		&& ln -sf "${skynetloc}/webui/settings.js" "/www/user/skynet/settings.js" \
		|| return 1
	Unload_Cron "genstats" || return 1
	Load_Cron "genstats"
}

Uninstall_WebUI_Page() {
	Find_WebUI_Page "${skynetloc}/webui/skynet.asp"
	if [ -n "$MyPage" ] && [ "$MyPage" != "none" ]; then
		if [ -f "/tmp/menuTree.js" ]; then
			sed -i "\\~$MyPage~d" /tmp/menuTree.js || return 1
			umount /www/require/modules/menuTree.js
			mount -o bind /tmp/menuTree.js /www/require/modules/menuTree.js || return 1
		else
			MyPageTitle="${MyPage%.asp}.title"
			rm -f "/www/user/$MyPageTitle" || return 1
		fi
		rm -f "/www/user/$MyPage" && rm -rf "/www/user/skynet" || return 1
	fi
	Unload_Cron "genstats"
}

Download_File() {
	# Download beside the destination and replace only a complete file. The MD5
	# comparison avoids unnecessary flash/USB writes when content is unchanged.
	# "stage" retains the validated temporary file for a coordinated update.
	downloadfile="$1"
	downloaddest="$2"
	downloadforce="$3"
	downloadaction="$4"
	downloadchanged="0"

	downloadurl="${remotedir}/${downloadfile}"
	downloadname="$(basename "$downloadfile")"
	downloadtmp="${downloaddest}.tmp.$$"

	if ! Curl_Fetch -o "$downloadtmp" "$downloadurl" || [ ! -s "$downloadtmp" ]; then
		rm -f "$downloadtmp"
		Log error "Failed To Update $downloadname"
		return 1
	fi

	downloadremotemd5="$(md5sum "$downloadtmp" | awk '{print $1}')"
	downloadlocalmd5="$(md5sum "$downloaddest" 2>/dev/null | awk '{print $1}')"
	if [ "$downloadname" = "firewall.sh" ]; then
		if ! chmod 755 "$downloadtmp" || ! sh -n "$downloadtmp"; then
			rm -f "$downloadtmp"
			Log error "Invalid Update File Detected ($downloadname)"
			return 1
		fi
	fi
	if [ "$downloadname" = "skynet.asp" ] \
		&& { ! grep -qF 'SkynetUI.initialize = function()' "$downloadtmp" \
			|| ! grep -qF '</html>' "$downloadtmp"; }; then
		rm -f "$downloadtmp"
		Log error "Invalid Update File Detected ($downloadname)"
		return 1
	fi
	if [ "$downloadremotemd5" != "$downloadlocalmd5" ] || [ "$downloadforce" = "-f" ]; then
		downloadchanged="1"
	fi

	if [ "$downloadaction" = "stage" ]; then
		return 0
	fi
	if [ "$downloadchanged" = "1" ]; then
		if mv -f "$downloadtmp" "$downloaddest"; then
			echo "[i] Updated $downloadname"
		else
			rm -f "$downloadtmp"
			Log error "Failed To Update $downloadname"
			return 1
		fi
	else
		rm -f "$downloadtmp"
		echo "[i] No change to $downloadname (MD5 matched)"
	fi
}

########################
#- Devices And Storage -#
########################

Prepare_Client_Name_Data() {
	# Resolve only the OUI prefixes present in the supplied device data. The
	# 1.3MB Merlin database is then scanned once instead of once per device.
	clientouifile="$TMP_DIR/client-ouis.$$"
	clientouiprepared="0"
	rm -f "$clientouifile"
	[ -s "$1" ] && [ -r /www/ajax/ouiDB.json ] || return 0
	if awk '
		NR == FNR {
			record=$0
			gsub(/~/, " ", record)
			count=split(record, field, /[[:space:]]+/)
			for (i=1; i <= count; i++) {
				mac=field[i]
				gsub(/:/, "", mac)
				if (length(mac) == 12 && mac !~ /[^0-9A-Fa-f]/)
					wanted[toupper(substr(mac, 1, 6))]=1
			}
			next
		}
		{
			prefix=toupper(substr($0, 2, 6))
			if (prefix in wanted) {
				vendor=$0
				sub(/^[^:]*:[[:space:]]*"/, "", vendor)
				sub(/",?[[:space:]]*$/, "", vendor)
				print prefix "\t" vendor
			}
		}
	' "$1" /www/ajax/ouiDB.json > "$clientouifile"; then
		clientouiprepared="1"
		return 0
	fi
	rm -f "$clientouifile"
	return 1
}

Clear_Client_Name_Data() {
	rm -f "$clientouifile"
	unset "clientouifile" "clientouiprepared"
}

Resolve_Client_Name() {
	localname=""
	if [ "$customclientlistloaded" != "1" ]; then
		customclientlist="$(nvram get custom_clientlist)"
		customclientlistloaded="1"
	fi
	if [ "$clientcontextloaded" != "1" ]; then
		clientwanip="$(nvram get wan0_ipaddr)"
		clientwgsip="$(nvram get wgs1_addr | cut -d'/' -f1)"
		clientvpnremote1="$(nvram get vpn_server1_remote)"
		clientvpnremote2="$(nvram get vpn_server2_remote)"
		clientcontextloaded="1"
	fi
	
	# Merlin stores custom clients as <display name>...MAC records. Extract the
	# name associated with this MAC, then remove characters unsafe for chart text.
	if [ -n "$macaddr" ] && [ -n "$customclientlist" ]; then
		localname="$(printf '%s\n' "$customclientlist" | grep -ioE "<.*>$macaddr" | sed -E 's/.*<([^>]+)>[^<]*$/\1/; s/[^a-zA-Z0-9.-]//g')"
	fi
	
	# Fallback to dnsmasq leases
	if [ -z "$localname" ]; then
		localname="$(awk -v ip="$ipaddr" '$3 == ip { print $4; exit }' /var/lib/misc/dnsmasq.leases)"
	fi
	
	# If no name found, check OUI DB for MAC address
	if [ -z "$localname" ] || [ "$localname" = "*" ]; then
		if [ -n "$macaddr" ]; then
			macaddr2="$(printf '%s\n' "$macaddr" | awk '{ gsub(/:/, ""); print toupper(substr($0, 1, 6)) }')"
			if [ "$clientouiprepared" = "1" ]; then
				localname="$(awk -F '\t' -v prefix="$macaddr2" '$1 == prefix { print $2; exit }' "$clientouifile")"
			else
				localname="$(awk -v prefix="\"$macaddr2\"" 'index($0, prefix) == 1 { value=$0; sub(/^[^:]*:[[:space:]]*"/, "", value); sub(/",?[[:space:]]*$/, "", value); print value; exit }' /www/ajax/ouiDB.json)"
			fi
		fi
		# Additional checks for specific cases	
		if [ -z "$localname" ]; then
			case "$ipaddr" in
				"$clientwanip")
					localname="$model"
				;;
				"$clientwgsip")
					localname="Wireguard VPN Server"
				;;
				"$clientvpnremote1" | "$clientvpnremote2")
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
		localname="$(printf '%.40s' "$localname")"
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
	for tempfile in /tmp/skynet/maintenance.status.tmp.*; do
		[ -f "$tempfile" ] || continue
		temppid="${tempfile##*.}"
		[ "$temppid" = "$$" ] && continue
		[ -d "/proc/$temppid" ] || rm -f "$tempfile"
	done
}

Swap_Path_Is_Valid() {
	case "$swaplocation" in *'/../'*|*'/./'*|*'//'*) return 1 ;; /tmp/mnt/*/myswap.swp) ;; *) return 1 ;; esac
	# Restrict paths interpolated into hooks to literal mount-path characters.
	printf '%s\n' "$swaplocation" | grep -qE '^/tmp/mnt/[A-Za-z0-9_./ ()+-]+/myswap\.swp$'
}

Skynet_Owns_Swap() {
	Swap_Path_Is_Valid && [ -f "$swaplocation" ] && [ ! -L "$swaplocation" ] \
		&& [ "$(readlink -f "$swaplocation" 2>/dev/null)" = "$swaplocation" ] \
		&& awk -v path="$swaplocation" '
			/^[[:space:]]*#/ {next}
			/swapon / && (index($0,path) || index($0,"$1/myswap.swp")) {
				if ($0 ~ /# Skynet[[:space:]]*$/) owned=1; else shared=1
			}
			END {exit !owned || shared}
		' /jffs/scripts/post-mount
}

Maintain_Swap_Hook() {
	if Skynet_Owns_Swap; then
		# Only the configured mount can disable this swap; other devices and
		# swap owners are unaffected when another USB partition is unmounted.
		swaphook="[ \"\$1\" != \"${swaplocation%/*}\" ] || [ ! -f \"$swaplocation\" ] || swapoff \"$swaplocation\" 2>/dev/null # Skynet"
		if ! Check_Skynet_Hook /jffs/scripts/unmount "$swaphook"; then
			Publish_Skynet_Hook /jffs/scripts/unmount "$swaphook" || return 1
		fi
	elif grep -q 'swapoff .*# Skynet' /jffs/scripts/unmount; then
		# Remove the obsolete global swapoff hook even on amtm-managed installs.
		Publish_Skynet_Hook /jffs/scripts/unmount "" || return 1
	fi
	unset "swaphook"
}

Remove_Swap() {
	# Refuse another addon's file and keep hooks/file intact if swapoff fails.
	if ! Skynet_Owns_Swap; then
		echo "[*] SWAP File Ownership Could Not Be Confirmed - Existing Swap Retained"
		return 1
	fi
	if awk -v path="$swaplocation" '$1 == path && $2 == "file" {found=1} END {exit !found}' /proc/swaps \
		&& ! swapoff "$swaplocation"; then
		echo "[*] Unable To Disable SWAP File - Existing File And Hooks Retained"
		return 1
	fi
	echo "[i] Removing SWAP File ($swaplocation)"
	rm -f "$swaplocation" || return 1
	sed -i '\~swapon .*# Skynet~d' /jffs/scripts/post-mount \
		&& sed -i '\~swapoff .*# Skynet~d' /jffs/scripts/unmount || return 1
	swaplocation=""
	echo "[i] SWAP File Removed"
}

Create_Swap() {
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
	Swap_Path_Is_Valid || { echo "[*] Unsupported SWAP File Path"; return 1; }

	# Never overwrite an existing swap file or disable another addon's swap.
	if [ -e "$swaplocation" ] || [ -L "$swaplocation" ]; then
		echo "[*] Existing SWAP File Detected ($swaplocation) - Exiting"
		return 1
	fi

	avail_kb=$(df -k "$device" | awk 'NR==2 {print $4}')
	case "$avail_kb" in ""|*[!0-9]*) echo "[*] Unable To Read Free Space"; return 1 ;; esac
	avail_mb=$(( avail_kb / 1024 ))
	if [ -z "$avail_kb" ] || [ "$avail_kb" -lt "$swapsize_kb" ]; then
		echo "[*] Not enough free space on $device (${avail_mb}MB available)"
		echo
		return 1
	fi

	swapsize_mb=$(( swapsize_kb / 1024 ))
	echo "[i] Creating ${swapsize_mb}MB swap file at $swaplocation"
	echo
	if ! (umask 077; dd if=/dev/zero bs=1M count="$swapsize_mb" of="$swaplocation" 2>/dev/null) \
		|| ! mkswap "$swaplocation" || ! swapon "$swaplocation"; then
		rm -f "$swaplocation"
		echo "[*] Failed To Create Or Enable SWAP File"
		return 1
	fi

	# Restrict hook edits to Skynet and activation to the configured mount.
	swaphook="[ \"\$1\" != \"${swaplocation%/*}\" ] || [ ! -f \"$swaplocation\" ] || swapon \"$swaplocation\" # Skynet"
	if ! Publish_Skynet_Hook /jffs/scripts/post-mount "$swaphook"; then
		echo "[*] SWAP Enabled But Post-Mount Hook Could Not Be Updated"
		return 1
	fi

	Maintain_Swap_Hook || return 1

	echo
	echo "[i] Swap file created at $swaplocation"
	echo
}

####################
#- Menu Utilities -#
####################

Return_To_Menu() {
	unset "option1" "option2" "option3" "option4" "option5" "option3list" "option4list"
	Release_Lock
	trap - 0 INT TERM
	Cleanup_Runtime
	clear
	exec "$0"
}

Invalid_Option() {
	Ylow "[*] $1 Isn't An Option!"
	echo
}

Menu_Require_Running() {
	if ! Check_IPSets || ! Check_IPTables; then
		echo "[*] Skynet Not Running - Exiting"
		echo
		Return_To_Menu
		return 1   # indicate failure
	fi
	return 0       # Skynet is running
}

Prompt_Input() {
	case "$1" in
		[0-9]*-[0-9]*)
			if [ -t 1 ] || [ -t 2 ]; then
				printf 'Select \033[1;36m[%s or e]\033[0m: ' "$1"
			else
				printf 'Select [%s or e]: ' "$1"
			fi
		;;
		*)
			if [ -t 1 ] || [ -t 2 ]; then
				printf '\033[1;36m%s\033[0m: ' "$1"
			else
				printf '%s: ' "$1"
			fi
		;;
	esac
	read -r "$2"
	echo
}

Prompt_Typed() {
	promptvar="$1"
	promptlabel="${2:-$promptvar}"
	prompttext="${3:-}"

	[ -n "$prompttext" ] && echo "$prompttext"

	if [ -t 1 ] || [ -t 2 ]; then
		printf '\033[1;36m%s\033[0m: ' "$promptlabel"
	else
		printf '%s: ' "$promptlabel"
	fi
	read -r "${promptvar?}"
	promptstatus="$?"
	case "$promptstatus" in
		0) unset "promptvar" "promptlabel" "prompttext" "promptstatus"; return 0 ;;
		*) unset "promptvar" "promptlabel" "prompttext" "promptstatus"; return 1 ;;
	esac
}

Show_Menu() {
	# usage: Show_Menu "Title" "Opt1" "Opt2" ... ["Exit"]
	showmenutitle="$1"
	shift
	if [ -t 1 ] || [ -t 2 ]; then
		showmenucolor="1"
		printf '\033[1;36m%s\033[0m\n\n' "$showmenutitle"
	else
		showmenucolor="0"
		printf '%s\n\n' "$showmenutitle"
	fi

	showmenuexit=""
	showmenucount="$#"
	showmenuindex="1"

	for showmenuoption in "$@"; do
		if [ "$showmenuindex" -eq "$showmenucount" ] && [ "$showmenuoption" = "Exit" ]; then
			showmenuexit="$showmenuoption"
		else
			if [ "$showmenucolor" = "1" ]; then
				if [ "$showmenuindex" -lt "10" ]; then
					printf '  \033[1;36m[%s]\033[0m  %s\n' "$showmenuindex" "$showmenuoption"
				else
					printf '  \033[1;36m[%s]\033[0m %s\n' "$showmenuindex" "$showmenuoption"
				fi
			elif [ "$showmenuindex" -lt "10" ]; then
				printf '  [%s]  %s\n' "$showmenuindex" "$showmenuoption"
			else
				printf '  [%s] %s\n' "$showmenuindex" "$showmenuoption"
			fi
			showmenuindex=$((showmenuindex + 1))
		fi
	done

	if [ -n "$showmenuexit" ]; then
		echo
		if [ "$showmenucolor" = "1" ]; then
			printf '  \033[1;36m[e]\033[0m  %s\n' "$showmenuexit"
		else
			printf '  [e]  %s\n' "$showmenuexit"
		fi
	fi

	echo
	unset "showmenutitle" "showmenucolor" "showmenuexit" "showmenucount" "showmenuindex" "showmenuoption"
}

###################################
#- Logs, Configuration And WebUI -#
###################################

Sanitize_Action_Field() {
	# Action records are tab-separated. Flatten line breaks and control characters
	# so user comments cannot create extra fields or forged journal records.
	awk '
		BEGIN { ORS = "" }
		{
			if (NR > 1) printf " "
			gsub(/[[:cntrl:]]/, " ")
			printf "%s", $0
		}
	'
}

Queue_Action() {
	# A failed record remains a publication failure even if later records queue
	# successfully or the failed write left no file to publish.
	Append_Action_Record "$@" && return 0
	actionqueuefailed="1"
	return 1
}

Append_Action_Record() {
	# A1: epoch, timestamp, origin, result, area, operation, target, type,
	# subjects, detail and transaction ID. One row describes one committed batch.
	# Persistent history is intentionally silent until the router clock is trusted.
	Time_Is_Ready || return 0
	actionresult="$1"
	actionarea="$2"
	actionoperation="$3"
	actiontarget="$4"
	actiontype="$5"
	actionentries="$6"
	actiondetail="$7"
	case "$actionresult" in success|degraded|failed) ;; *) return 1 ;; esac
	case "$actionarea" in rules|iot|countries|feeds|settings|system) ;; *) return 1 ;; esac
	case "$actionoperation" in add|remove|enable|disable|refresh|update|restore|expire) ;; *) return 1 ;; esac
	case "$actiontarget" in ""|*[!A-Za-z0-9_-]*) return 1 ;; esac
	case "$actiontype" in ""|*[!A-Za-z0-9_-]*) return 1 ;; esac
	actionorigin="${SKYNET_ACTION_ORIGIN:-cli}"
	case "$actionorigin" in cli|menu|webui|cron|startup) ;; *) actionorigin="cli" ;; esac
	actionepoch="$(date +%s)" || return 1
	actiontimestamp="$(date '+%Y-%m-%d %H:%M:%S %z')" || return 1
	actiontransaction="${SKYNET_ACTION_TRANSACTION:-${actionepoch}.$$}"
	actionentries="$(printf '%s\n' "$actionentries" | Sanitize_Action_Field)" || return 1
	actiondetail="$(printf '%s\n' "$actiondetail" | Sanitize_Action_Field)" || return 1
	actiontransaction="$(printf '%s\n' "$actiontransaction" | Sanitize_Action_Field)" || return 1
	[ -n "$actionentries" ] || return 1
	[ "${#actionentries}" -le "8192" ] || actionentries="$(printf '%s' "$actionentries" | cut -c 1-8192)" || return 1
	[ "${#actiondetail}" -le "512" ] || actiondetail="$(printf '%s' "$actiondetail" | cut -c 1-512)" || return 1
	[ "${#actiontransaction}" -le "128" ] || return 1
	actionqueue="${actionqueue:-$TMP_DIR/actions.$$}"
	[ -e "$actionqueue" ] || { printf '' > "$actionqueue" && chmod 600 "$actionqueue"; } || return 1
	printf 'A1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$actionepoch" "$actiontimestamp" "$actionorigin" "$actionresult" "$actionarea" \
		"$actionoperation" "$actiontarget" "$actiontype" "$actionentries" "$actiondetail" \
		"$actiontransaction" >> "$actionqueue"
}

Inspect_Action_File() {
	# Validate the A1 contract while counting records and their expected bytes.
	# Existing text summaries remain readable until normal retention compaction;
	# queues accept only structured rows. The byte count detects a partial line.
	[ -f "$1" ] && [ -s "$1" ] || return 1
	awk -F '\t' -v legacy="${2:-0}" '
		function valid() {
			if ($1 == "A1" && NF == 12 && $2 ~ /^[0-9]+$/ \
				&& $3 != "" && length($3) <= 40 && $3 !~ /[[:cntrl:]]/ \
				&& $4 ~ /^(cli|menu|webui|cron|startup)$/ \
				&& $5 ~ /^(success|degraded|failed)$/ \
				&& $6 ~ /^(rules|iot|countries|feeds|settings|system)$/ \
				&& $7 ~ /^(add|remove|enable|disable|refresh|update|restore|expire)$/ \
				&& $8 ~ /^[A-Za-z0-9_-]+$/ && $9 ~ /^[A-Za-z0-9_-]+$/ \
				&& $10 != "" && length($10) <= 8192 && $10 !~ /[[:cntrl:]]/ \
				&& length($11) <= 512 && $11 !~ /[[:cntrl:]]/ \
				&& $12 != "" && length($12) <= 128 && $12 !~ /[[:cntrl:]]/) return 1
			return legacy == 1 && $0 ~ /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[[:space:]]/ \
				&& index($0, " Skynet: [#] ") && length($0) <= 8192 && $0 !~ /[[:cntrl:]]/
		}
		BEGIN { clean = 1 }
		{ bytes += length($0) + 1; if (!valid()) clean = 0 }
		END {
			printf "%d %d\n", NR, bytes
			if (!clean || NR == 0) exit 1
		}
	' "$1"
}

Validate_Action_File() {
	Inspect_Action_File "$1" > /dev/null
}

Filter_Action_Files() {
	# Compaction accepts only complete records. A partial final write or damaged
	# legacy row is discarded without affecting newer valid history.
	awk -F '\t' '
		function valid() {
			return $1 == "A1" && NF == 12 && $2 ~ /^[0-9]+$/ \
				&& $3 != "" && length($3) <= 40 && $3 !~ /[[:cntrl:]]/ \
				&& $4 ~ /^(cli|menu|webui|cron|startup)$/ \
				&& $5 ~ /^(success|degraded|failed)$/ \
				&& $6 ~ /^(rules|iot|countries|feeds|settings|system)$/ \
				&& $7 ~ /^(add|remove|enable|disable|refresh|update|restore|expire)$/ \
				&& $8 ~ /^[A-Za-z0-9_-]+$/ && $9 ~ /^[A-Za-z0-9_-]+$/ \
				&& $10 != "" && length($10) <= 8192 && $10 !~ /[[:cntrl:]]/ \
				&& length($11) <= 512 && $11 !~ /[[:cntrl:]]/ \
				&& $12 != "" && length($12) <= 128 && $12 !~ /[[:cntrl:]]/
		}
		valid()
	' "$@"
}

Publish_Actions_Locked() {
	[ -n "$actionqueue" ] && [ -s "$actionqueue" ] || return 0
	[ ! -L "$skynetevents" ] || { Log error -s "Refusing To Write Action History Through A Symbolic Link"; return 1; }
	[ ! -e "$skynetevents" ] || [ -f "$skynetevents" ] \
		|| { Log error -s "Action History Is Not A Regular File"; return 1; }
	actionmetrics="$(Inspect_Action_File "$actionqueue")"
	actioninspectstatus="$?"
	if [ "$actioninspectstatus" != "0" ]; then
		Log error -s "Invalid Action History Record Rejected"
		return 1
	fi
	IFS=' ' read -r actionlines actionsize <<EOF
$actionmetrics
EOF

	# The process-wide Skynet lock serializes publishers. Normal writes append;
	# the journal is rewritten only when either retention limit is reached.
	actioncompactneeded="0"
	if [ -f "$skynetevents" ]; then
		actioncurrentsize="$(wc -c < "$skynetevents" 2>/dev/null)"
		if [ -s "$skynetevents" ]; then
			actioncurrentmetrics="$(Inspect_Action_File "$skynetevents" 1)"
			actioninspectstatus="$?"
			IFS=' ' read -r actioncurrentlines actionexpectedsize <<EOF
$actioncurrentmetrics
EOF
			if [ "$actioninspectstatus" != "0" ] || [ "$actionexpectedsize" != "$actioncurrentsize" ]; then
				actioncompactneeded="1"
			fi
		else
			actioncurrentlines="0"
			actionexpectedsize="0"
		fi
	else
		actioncurrentsize="0"
		actioncurrentlines="0"
		actionexpectedsize="0"
	fi
	for actionvalue in "$actionsize" "$actionlines" "$actioncurrentsize" "$actioncurrentlines" "$actionexpectedsize"; do
		case "$actionvalue" in ""|*[!0-9]*) Log error -s "Failed To Read Action History"; return 1 ;; esac
	done
	actionsize=$((actioncurrentsize + actionsize))
	actionlines=$((actioncurrentlines + actionlines))

	if [ "$actioncompactneeded" = "1" ] || [ "$actionsize" -gt "1048576" ] || [ "$actionlines" -gt "2000" ]; then
		actionpublishtmp="${skynetevents}.tmp.$$"
		actioncompacttmp="${skynetevents}.compact.$$"
		actiontrimtmp="${skynetevents}.trim.$$"
		rm -f "$actionpublishtmp" "$actioncompacttmp" "$actiontrimtmp"
		if [ -f "$skynetevents" ]; then
			Filter_Action_Files "$skynetevents" "$actionqueue" > "$actionpublishtmp"
		else
			Filter_Action_Files "$actionqueue" > "$actionpublishtmp"
		fi
		actionfilterstatus="$?"
		if [ "$actionfilterstatus" != "0" ] || [ ! -s "$actionpublishtmp" ] \
			|| ! tail -n 2000 "$actionpublishtmp" > "$actioncompacttmp" || [ ! -s "$actioncompacttmp" ] \
			|| ! chmod 600 "$actioncompacttmp"; then
			rm -f "$actionpublishtmp" "$actioncompacttmp" "$actiontrimtmp"
			Log error -s "Failed To Compact Action History - Existing History Retained"
			return 1
		fi
		actioncompactsize="$(wc -c < "$actioncompacttmp" 2>/dev/null)"
		case "$actioncompactsize" in
			""|*[!0-9]*)
				rm -f "$actionpublishtmp" "$actioncompacttmp" "$actiontrimtmp"
				Log error -s "Failed To Compact Action History - Existing History Retained"
				return 1
			;;
		esac
		if [ "$actioncompactsize" -gt "1048576" ]; then
			if ! tail -c 1048576 "$actioncompacttmp" > "$actionpublishtmp" \
				|| ! sed '1d' "$actionpublishtmp" > "$actiontrimtmp" \
				|| [ ! -s "$actiontrimtmp" ] || ! chmod 600 "$actiontrimtmp" \
				|| ! mv -f "$actiontrimtmp" "$skynetevents"; then
				rm -f "$actionpublishtmp" "$actioncompacttmp" "$actiontrimtmp"
				Log error -s "Failed To Compact Action History - Existing History Retained"
				return 1
			fi
			rm -f "$actioncompacttmp"
		else
			if ! mv -f "$actioncompacttmp" "$skynetevents"; then
				rm -f "$actionpublishtmp" "$actioncompacttmp" "$actiontrimtmp"
				Log error -s "Failed To Compact Action History - Existing History Retained"
				return 1
			fi
		fi
		rm -f "$actionpublishtmp"
		actioncompacttmp=""
		actiontrimtmp=""
	else
		if [ ! -f "$skynetevents" ]; then
			if ! printf '' > "$skynetevents" || ! chmod 600 "$skynetevents"; then
				rm -f "$skynetevents"
				Log error -s "Failed To Create Action History"
				return 1
			fi
		fi
		if ! cat "$actionqueue" >> "$skynetevents" || ! chmod 600 "$skynetevents"; then
			Log error -s "Failed To Record Action History"
			return 1
		fi
	fi
	rm -f "$actionqueue"
	actionqueue=""
	actionpublishtmp=""
	unset "actioncompactsize" "actioncompactneeded" "actionfilterstatus" "actioninspectstatus" \
		"actionmetrics" "actioncurrentmetrics" "actionexpectedsize" "actionsize" \
		"actionlines" "actioncurrentsize" "actioncurrentlines" "actionvalue"
	return 0
}

Publish_Actions() {
	if [ -n "$actionqueue" ] && [ -s "$actionqueue" ]; then
		Acquire_Log_Lock || { actionqueuefailed="1"; return 1; }
		Publish_Actions_Locked || actionqueuefailed="1"
		Release_Log_Lock
	fi
	if [ "${actionqueuefailed:-0}" = "1" ]; then
		Log error -s "Failed To Save Complete Action History"
		return 1
	fi
	return 0
}

Discard_Actions() {
	[ -n "$actionqueue" ] && rm -f "$actionqueue"
	actionqueue=""
}

Publish_Failed_Actions() {
	[ -n "$actionqueue" ] && [ -s "$actionqueue" ] || return 0
	if ! Validate_Action_File "$actionqueue"; then
		Log error -s "Invalid Action History Record Rejected"
		return 1
	fi
	actionfailedtmp="$TMP_DIR/actions-failed.$$"
	awk -F '\t' '$1 == "A1" && $5 == "failed"' "$actionqueue" > "$actionfailedtmp" || return 1
	if [ -s "$actionfailedtmp" ]; then
		mv -f "$actionfailedtmp" "$actionqueue" && Publish_Actions
	else
		rm -f "$actionfailedtmp"
		Discard_Actions
	fi
}

Archive_Block_Logs() {
	# Pre-NTP records are deliberately left in the source log and are never copied
	# into persistent Skynet history with an untrusted timestamp.
	Time_Is_Ready || return 0
	Acquire_Log_Lock || return 1
	archivefailed="0"
	archiverewritten="0"
	archiverecords="$TMP_DIR/archive-records.$$"
	archiverollback="$TMP_DIR/archive-rollback.$$"
	for syslogfile in "$syslog1loc" "$syslogloc"; do
		[ -f "$syslogfile" ] || continue
		# Detect cleanup and extract Skynet records in one pass. Native DROP
		# messages are discarded; unrelated system messages stay in syslog.
		awk '
			/BLOCKED -/ { print; found = 1; next }
			/kernel: DROP IN=/ { found = 1 }
			END { exit found ? 0 : 3 }
		' "$syslogfile" > "$archiverecords" 2>/dev/null
		case "$?" in 0) ;; 3) continue ;; *) archivefailed="1"; continue ;; esac
		archiveoldsize="$(wc -c < "$skynetlog" 2>/dev/null)"
		case "$archiveoldsize" in ""|*[!0-9]*) archivefailed="1"; continue ;; esac
		if cat "$archiverecords" >> "$skynetlog" 2>/dev/null \
			&& sed -i '\~BLOCKED -~d; /kernel: DROP IN=/d' "$syslogfile" 2>/dev/null; then
			archiverewritten="1"
			if [ -s "$archiverecords" ]; then Whitelist_Blocked_Private_IPs "$archiverecords" || archivefailed="1"; fi
		else
			archivefailed="1"
			if head -c "$archiveoldsize" "$skynetlog" > "$archiverollback" 2>/dev/null \
				&& chmod 600 "$archiverollback" && mv -f "$archiverollback" "$skynetlog"; then :; else
				Log error "Failed To Restore Firewall Log After Archive Failure"
			fi
		fi
	done
	rm -f "$archiverecords" "$archiverollback"
	Release_Log_Lock
	if [ "$archiverewritten" = "1" ] && [ -f "/opt/etc/syslog-ng.d/skynet" ]; then
		killall -HUP syslog-ng 2>/dev/null
	fi
	[ "$archivefailed" = "0" ] || { Log error "Failed To Archive Firewall Logs - Source Logs Retained"; return 1; }
}

Enforce_Log_Limit_Locked() {
	log_kb="$(du -k "$skynetlog" 2>/dev/null | cut -f1)" || log_kb="0"
	log_kb="${log_kb:-0}"
	log_kb_limit="$((logsize * 1024))"
	if [ "$log_kb" -ge "$log_kb_limit" ] || [ "$1" = "force" ]; then
		if Generate_Stats; then
			sed -i '/BLOCKED -/d' "$skynetlog" 2>/dev/null || return 1
			iptables -Z PREROUTING -t raw || return 1
			log_kb="$(du -k "$skynetlog" 2>/dev/null | cut -f1)" || log_kb="0"
			if [ "${log_kb:-0}" -ge 3000 ]; then : > "$skynetlog" || return 1; fi
		else
			Log error "Failed To Generate Statistics - Firewall Logs Retained"
			return 1
		fi
	fi
	return 0
}

Enforce_Log_Limit() {
	Acquire_Log_Lock || return 1
	Enforce_Log_Limit_Locked "$@"
	loglimitstatus="$?"
	Release_Log_Lock
	return "$loglimitstatus"
}

Housekeep_Syslog() {
	logcounts="$(awk '
		/Skynet: \[i\] Startup Initiated/ { starts++ }
		/Skynet: \[i\] Restarting Firewall Service/ { restarts++ }
		END { print starts + 0, restarts + 0 }
	' "$syslogloc" 2>/dev/null)"
	logcounts="${logcounts:-0 0}"
	start_count="${logcounts%% *}"
	restart_count="${logcounts#* }"
	sysloghousekeeping="0"
	if [ "$1" = "all" ]; then
		sed -i '/Skynet: \[i\] /{
			/Startup Initiated/!{
				/Restarting Firewall Service/!d
			}
		}; /Skynet: \[#\] /d; /Skynet: \[\*\] Lock /d' "$syslog1loc" "$syslogloc" 2>/dev/null
		sysloghousekeeping="1"
	fi
	if [ "$start_count" -gt 3 ]; then
		sed -i '/Skynet: \[i\] Startup Initiated/d' "$syslog1loc" "$syslogloc" 2>/dev/null
		sysloghousekeeping="1"
	fi
	if [ "$restart_count" -gt 3 ]; then
		sed -i '/Skynet: \[i\] Restarting Firewall Service/d' "$syslog1loc" "$syslogloc" 2>/dev/null
		sysloghousekeeping="1"
	fi
	if [ "$sysloghousekeeping" = "1" ] && [ -f "/opt/etc/syslog-ng.d/skynet" ]; then
		killall -HUP syslog-ng 2>/dev/null
	fi
}

Prune_IOT_Device_Logs() {
	# Match source addresses against the removed IPv4/CIDR batch in one log scan.
	# Prefix-indexed networks avoid scanning every removed device for each packet.
	[ -n "$1" ] && [ -e "$skynetlog" ] || return 0
	[ -f "$skynetlog" ] || return 1
	Acquire_Log_Lock || return 1
	iotlogwork="$TMP_DIR/iot-prune.$$"
	iotlogtmp="${skynetlog}.tmp.$$"
	iotlogstatus="0"
	if ! awk -v entries="$1" '
		function address(value, octets, count, i, number) {
			if (value !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return -1
			count=split(value,octets,"."); number=0
			for(i=1;i<=count;i++) {
				if(octets[i]>255) return -1
				number=number*256+octets[i]
			}
			return number
		}
		BEGIN {
			count=split(entries,items,/[[:space:]]+/)
			for(i=1;i<=count;i++) {
				if(items[i]=="") continue
				parts=split(items[i],cidr,"/"); prefix=parts==1 ? 32 : cidr[2]
				number=address(cidr[1])
				if(parts>2 || number<0 || prefix !~ /^[0-9]+$/ || prefix>32) exit 1
				width=2^(32-prefix); widths[prefix]=width
				networks[prefix,int(number/width)]=1
			}
		}
		{
			if(index($0,"[BLOCKED - IOT]") && match($0,/[[:space:]]SRC=[^[:space:]]+/)) {
				number=address(substr($0,RSTART+5,RLENGTH-5))
				if(number>=0) for(prefix in widths)
					if((prefix SUBSEP int(number/widths[prefix])) in networks) next
			}
			print
		}
	' "$skynetlog" > "$iotlogwork"; then
		iotlogstatus="1"
	elif ! cmp -s "$iotlogwork" "$skynetlog"; then
		cp -f "$iotlogwork" "$iotlogtmp" && chmod 600 "$iotlogtmp" \
			&& mv -f "$iotlogtmp" "$skynetlog" || iotlogstatus="1"
	fi
	rm -f "$iotlogwork" "$iotlogtmp"
	Release_Log_Lock
	return "$iotlogstatus"
}

Purge_Logs() {
	Archive_Block_Logs || return 1
	Enforce_Log_Limit "$1" || return 1
	Housekeep_Syslog "$1"
}

Print_Command_Summary() {
	oldips="${blacklist1count:-0}"
	oldranges="${blacklist2count:-0}"
	Update_Block_Counts
	blacklist1count="${blacklist1count:-0}"
	blacklist2count="${blacklist2count:-0}"
	hits1="0"
	hits2="0"
	unset fail
	if Check_IPTables; then
		hitcounts="$({ iptables -xnvL PREROUTING -t raw; iptables -xnvL OUTPUT -t raw; } 2>/dev/null | awk '
			index($0, "LOG") == 0 && index($0, "Skynet-Master src") { inbound += $1 }
			index($0, "LOG") == 0 && index($0, "Skynet-Master dst") { outbound += $1 }
			END { print inbound + 0, outbound + 0 }
		')"
		hitcounts="${hitcounts:-0 0}"
		hits1="${hitcounts%% *}"
		hits2="${hitcounts#* }"
		[ "$filtertraffic" = "outbound" ] && hits1="0"
		[ "$filtertraffic" = "inbound" ] && hits2="0"
	fi
	ftime="$(($(Uptime_Seconds) - stime))"
	ipdelta="$((blacklist1count - oldips))"
	rangedelta="$((blacklist2count - oldranges))"
	case "$ipdelta" in -*) newips="$ipdelta" ;; *) newips="+$ipdelta" ;; esac
	case "$rangedelta" in -*) newranges="$rangedelta" ;; *) newranges="+$rangedelta" ;; esac
	if [ "$1" = "minimal" ]; then
		# Only print log to terminal
		Grn "$blacklist1count IPs (${newips}) -- $blacklist2count Ranges Banned (${newranges}) || $hits1 Inbound -- $hits2 Outbound Connections Blocked!"
	else
		# Print log to terminal and syslog
		logz="[#] $blacklist1count IPs (${newips}) -- $blacklist2count Ranges Banned (${newranges}) || $hits1 Inbound -- $hits2 Outbound Connections Blocked! [$1] [${ftime}s]"
		Log "$logz"
	fi
}


Load_Config() {
	[ -f "$skynetcfg" ] || return 1
	if [ "$1" = "fresh" ]; then
		# A restored older config may omit settings present in the running process.
		# Clear only persisted values; paths, locks and transaction state stay live.
		unset model localver swaplocation blacklist1count blacklist2count customlisturl customlist2url \
			banmalwarelastupdated countrylist excludelists autoupdate banmalwareupdate forcebanmalwareupdate \
			filtertraffic unbanprivateip banaiprotect securemode cdnwhitelist iotblocked iotlogging iotports iotproto \
			logmode loginvalid logsize extendedstats syslogmode syslogloc syslog1loc lookupcountry displaywebui fastswitch \
			configlegacyexclusions configlegacyports
	fi
	syslogmode=""
	# skynet.cfg is generated exclusively by Write_Config. Keep the saved version
	# as the upgrade marker until startup migration completes successfully.
	# shellcheck disable=SC1090
	. "$skynetcfg"
	configpreviousver="$localver"
	configcurrentver="$(Filter_Version < "$0")"
	configchanged="0"
	upgradefrom=""
	if [ -z "$configpreviousver" ] || [ "$configpreviousver" != "$configcurrentver" ]; then
		upgradefrom="${configpreviousver:-legacy}"
		configchanged="1"
	else
		localver="$configcurrentver"
	fi

	# Invalid or missing values use conservative defaults and never enable a
	# protection feature implicitly.
	case "$blacklist1count" in ""|*[!0-9]*) blacklist1count="0"; configchanged="1" ;; esac
	case "$blacklist2count" in ""|*[!0-9]*) blacklist2count="0"; configchanged="1" ;; esac
	case "$banmalwarelastupdated" in "") ;; *[!0-9]*) banmalwarelastupdated=""; configchanged="1" ;; esac
	case "$autoupdate" in enabled|disabled) ;; *) autoupdate="disabled"; configchanged="1" ;; esac
	case "$banmalwareupdate" in daily|weekly|disabled) ;; *) banmalwareupdate="disabled"; configchanged="1" ;; esac
	case "$forcebanmalwareupdate" in enabled|disabled) ;; *) forcebanmalwareupdate="disabled"; configchanged="1" ;; esac
	case "$logmode" in enabled|disabled) ;; *) logmode="disabled"; configchanged="1" ;; esac
	case "$loginvalid" in enabled|disabled) ;; *) loginvalid="disabled"; configchanged="1" ;; esac
	case "$filtertraffic" in all|inbound|outbound) ;; *) filtertraffic="all"; configchanged="1" ;; esac
	case "$unbanprivateip" in enabled|disabled) ;; *) unbanprivateip="disabled"; configchanged="1" ;; esac
	case "$banaiprotect" in enabled|disabled) ;; *) banaiprotect="disabled"; configchanged="1" ;; esac
	case "$securemode" in enabled|disabled) ;; *) securemode="disabled"; configchanged="1" ;; esac
	case "$extendedstats" in enabled|disabled) ;; *) extendedstats="disabled"; configchanged="1" ;; esac
	case "$iotblocked" in enabled|disabled) ;; *) iotblocked="disabled"; configchanged="1" ;; esac
	case "$iotlogging" in enabled|disabled) ;; *) iotlogging="disabled"; configchanged="1" ;; esac
	case "$iotproto" in udp|tcp|all) ;; *) iotproto="udp"; configchanged="1" ;; esac
	case "$lookupcountry" in enabled|disabled) ;; *) lookupcountry="disabled"; configchanged="1" ;; esac
	case "$cdnwhitelist" in enabled|disabled) ;; *) cdnwhitelist="disabled"; configchanged="1" ;; esac
	case "$displaywebui" in enabled|disabled) ;; *) displaywebui="disabled"; configchanged="1" ;; esac
	case "$logsize" in
		""|*[!0-9]*) logsize="10"; configchanged="1" ;;
		*) [ "$logsize" -ge "10" ] || { logsize="10"; configchanged="1"; } ;;
	esac
	[ -n "$syslogloc" ] || { syslogloc="/tmp/syslog.log"; configchanged="1"; }
	[ -n "$syslog1loc" ] || { syslog1loc="/tmp/syslog.log-1"; configchanged="1"; }
	case "$syslogmode" in
		auto|custom) ;;
		*) syslogmode="auto"; configchanged="1" ;;
	esac
	Resolve_Syslog_Sources

	if [ -n "$countrylist" ]; then
		# Country codes are lowercase, unique and space separated. If an older
		# value is malformed, recover the authoritative selection from IPSet
		# comments such as: comment "Country: au".
		configoldlist="$countrylist"
		configinvalid="0"
		configlower="$(printf '%s\n' "$countrylist" | awk '{ print tolower($0) }')"
		if countrylist="$(Normalize_List "$configlower")"; then
			:
		else
			countrylist=""
			configinvalid="1"
		fi
		for configitem in $countrylist; do
			case "$configitem" in [a-z][a-z]) Is_Country_Code "$configitem" || configinvalid="1" ;; *) configinvalid="1" ;; esac
		done
		if [ "$configinvalid" = "1" ] || [ -z "$countrylist" ]; then
			configcountrycandidates="$(sed -n 's~.*comment "Country: \([A-Za-z][A-Za-z]\)".*~\1~p' "$skynetipset" 2>/dev/null | awk '{ value = tolower($0); if (!seen[value]++) { if (output != "") output = output " "; output = output value } } END { print output }')"
			countrylist=""
			for configitem in $configcountrycandidates; do
				Is_Country_Code "$configitem" || continue
				countrylist="${countrylist}${countrylist:+ }$configitem"
			done
			configchanged="1"
		elif [ "$countrylist" != "$configoldlist" ]; then
			configchanged="1"
		fi
	fi
	if [ -n "$excludelists" ]; then
		# Exclusions are exact filter-list basenames, never regular expressions.
		configoldlist="$excludelists"
		excludelists="$(printf '%s\n' "$excludelists" | tr '|' ' ')"
		configinvalid="0"
		if ! excludelists="$(Normalize_List "$excludelists")"; then
			excludelists=""
			configinvalid="1"
		fi
		for configitem in $excludelists; do
			case "$configitem" in ""|*[!A-Za-z0-9._-]*) configinvalid="1" ;; esac
		done
		if [ "$configinvalid" = "1" ]; then
			excludelists=""
			configlegacyexclusions="1"
			configchanged="1"
		elif [ "$excludelists" != "$configoldlist" ]; then
			configchanged="1"
		fi
	fi
	if [ -z "$iotports" ] && [ "$iotproto" != "udp" ]; then
		# An empty list paired with a non-UDP protocol is stored as an explicit
		# port 123 policy; the canonical empty policy remains UDP NTP.
		iotports="123"
		configchanged="1"
	elif [ "$iotports" != "none" ] && [ -n "$iotports" ]; then
		# Stored ports are normalized to the space-separated configuration format.
		# iptables multiport accepts no more than 15 ports.
		configoldlist="$iotports"
		iotports="$(printf '%s\n' "$iotports" | tr ',' ' ')"
		configinvalid="0"
		if ! iotports="$(Normalize_List "$iotports")"; then
			iotports=""
			configinvalid="1"
		fi
		configcount="0"
		for configitem in $iotports; do
			configcount=$((configcount + 1))
			printf '%s\n' "$configitem" | Is_Port || configinvalid="1"
		done
		[ "$configcount" -le "15" ] || configinvalid="1"
		if [ "$configinvalid" = "1" ]; then
			iotports=""
			configlegacyports="1"
			configchanged="1"
		elif [ "$iotports" != "$configoldlist" ]; then
			configchanged="1"
		fi
	fi
	unset "configoldlist" "configlower" "configinvalid" "configcount" "configitem"
}

Migrate_Installation() {
	# Generated WebUI payloads are deliberately discarded across versions; the
	# current stats engine rebuilds them after persistent data has been restored.
	if [ -n "$upgradefrom" ]; then
		localver="$configcurrentver"
		Log info "Migrating Skynet Data From $upgradefrom To $localver"
		rm -f "${skynetloc}/webui/stats.js" "${skynetloc}/webui/settings.js" || return 1
	elif [ "$configchanged" = "1" ]; then
		Log info "Normalizing Skynet Configuration"
	fi
	if [ "$configlegacyexclusions" = "1" ]; then
		Log error -s "Legacy Malware Exclusions Could Not Be Converted - Exclusions Reset"
	fi
	if [ "$configlegacyports" = "1" ]; then
		Log error -s "Invalid Legacy IoT Ports Detected - Default NTP Access Restored"
	fi
	unset "configchanged" "configlegacyexclusions" "configlegacyports"
}

Write_Config() {
	# Pass values through the environment without AWK -v escape interpretation.
	configtmp="${skynetcfg}.tmp.$$"
	if [ -e "$configtmp" ] || [ -L "$configtmp" ]; then
		unset "configtmp"
		Log error "Failed To Stage Config - Existing File Retained"
		return 1
	fi
	if configstamp=$(date +"%b %e %T") &&
	config_model="$model" config_localver="$localver" config_swaplocation="$swaplocation" \
	config_blacklist1count="$blacklist1count" config_blacklist2count="$blacklist2count" \
	config_customlisturl="$customlisturl" config_banmalwarelastupdated="$banmalwarelastupdated" \
	config_countrylist="$countrylist" config_excludelists="$excludelists" \
	config_autoupdate="$autoupdate" config_banmalwareupdate="$banmalwareupdate" config_forcebanmalwareupdate="$forcebanmalwareupdate" \
	config_filtertraffic="$filtertraffic" config_unbanprivateip="$unbanprivateip" \
	config_banaiprotect="$banaiprotect" config_securemode="$securemode" config_cdnwhitelist="$cdnwhitelist" \
	config_iotblocked="$iotblocked" config_iotlogging="$iotlogging" config_iotports="$iotports" config_iotproto="$iotproto" \
	config_logmode="$logmode" config_loginvalid="$loginvalid" config_logsize="$logsize" \
	config_extendedstats="$extendedstats" config_syslogmode="${syslogmode:-auto}" \
	config_syslogloc="$syslogloc" config_syslog1loc="$syslog1loc" config_lookupcountry="$lookupcountry" \
	config_displaywebui="$displaywebui" \
	awk -v stamp="$configstamp" '
		function section(title, keys, count, fields, i, key, value, j, char, output) {
			printf "%s## %s ##\n", title == "Installer" ? "" : "\n", title
			count = split(keys, fields, " ")
			for (i = 1; i <= count; i++) {
				key = fields[i]; value = ENVIRON["config_" key]; output = ""
				for (j = 1; j <= length(value); j++) {
					char = substr(value, j, 1)
					if (char == "\\" || char == "\"" || char == "$" || char == "`") output = output "\\" char
					else if (char == "\n") output = output " "
					else if (char != "\r") output = output char
				}
				printf "%s=\"%s\"\n", key, output
			}
		}
		BEGIN {
			print "################################################"
			print "## Generated By Skynet - Do Not Manually Edit ##"
			printf "%-45s %s\n\n", "## " stamp, "##"
			section("Installer", "model localver swaplocation")
			section("Counters / Lists", "blacklist1count blacklist2count customlisturl banmalwarelastupdated countrylist excludelists")
			section("Updates & Lists", "autoupdate banmalwareupdate forcebanmalwareupdate")
			section("Protection", "filtertraffic unbanprivateip banaiprotect securemode cdnwhitelist")
			section("IoT Isolation", "iotblocked iotlogging iotports iotproto")
			section("Logging & Statistics", "logmode loginvalid logsize extendedstats syslogmode syslogloc syslog1loc lookupcountry")
			section("Integration & Advanced", "displaywebui")
			print "\n################################################"
		}
	' > "$configtmp" && [ -s "$configtmp" ] && mv -f "$configtmp" "$skynetcfg"; then
		unset "configtmp" "configstamp"
		return 0
	fi
	rm -f "$configtmp"
	unset "configtmp" "configstamp"
	Log error "Failed To Write Config - Existing File Retained"
	return 1
}

Run_WebUI_Command() {
	# The invoked command acquires the kernel-owned state lock. A concurrent
	# operation reports busy immediately; lock-file existence is never ownership.
	SKYNET_ACTION_ORIGIN="webui" SKYNET_ACTION_TRANSACTION="${webuirequestid:-}" SKYNET_WEBUI_REQUEST="${webuirequestid:-}" sh "$0" "$@"
}

Publish_WebUI_Result() {
	# A completed payload and a successful operation are separate requirements.
	Generate_WebUI_Settings || return 1
	case "$settingsresult" in
		success|warning:*|degraded|degraded:*) return 0 ;;
		validation) return 2 ;;
		*) return 1 ;;
	esac
}

Apply_WebUI_Stats() {
	nocfg="1"
	settingsresult="error"
	webuistatsoutput="$TMP_DIR/webui-stats-output.$$"
	# A rejected worker never publishes stats.js. Publish its result separately
	# so polling can finish without replacing the previous charts.
	if Run_WebUI_Command debug genstats > "$webuistatsoutput" 2>&1; then
		settingsresult="success"
	elif grep -qE 'Lock File Detected|Lock file busy' "$webuistatsoutput"; then
		settingsresult="busy"
	fi
	rm -f "$webuistatsoutput"
	Publish_WebUI_Result
}

Apply_WebUI_Toggle() {
	if [ "$1" != "$2" ]; then
		case "$1" in
			enabled) Run_WebUI_Command settings "$3" enable >/dev/null 2>&1 ;;
			disabled) Run_WebUI_Command settings "$3" disable >/dev/null 2>&1 ;;
		esac
	fi
}

Apply_WebUI_Settings() {
	# Validate the entire Merlin settings payload before invoking any command.
	# Commands are then applied in order and stop at the first failure; reloading
	# the generated payload makes the page reflect the values actually committed.
	settingsresult="success"
	if [ ! -f "$_am_settings_path" ]; then
		settingsresult="error"
	else
		webuiautoupdate="$(am_settings_get skynet_autoupdate)"
		webuifilter="$(am_settings_get skynet_filtertraffic)"
		webuimalware="$(am_settings_get skynet_banmalwareupdate)"
		webuicustomlist="$(am_settings_get skynet_customlisturl)"
		webuiunbanprivate="$(am_settings_get skynet_unbanprivateip)"
		webuiaiprotect="$(am_settings_get skynet_banaiprotect)"
		webuisecuremode="$(am_settings_get skynet_securemode)"
		webuilogmode="$(am_settings_get skynet_logmode)"
		webuisyslogmode="$(am_settings_get skynet_syslogmode)"
		webuisyslog="$(am_settings_get skynet_syslogloc)"
		webuisyslog1="$(am_settings_get skynet_syslog1loc)"
		# Older open pages omit these controls; retain their saved values.
		[ -n "$webuilogmode" ] || webuilogmode="$logmode"
		[ -n "$webuisyslogmode" ] || webuisyslogmode="$syslogmode"
		[ -n "$webuisyslog" ] || webuisyslog="$syslogloc"
		[ -n "$webuisyslog1" ] || webuisyslog1="$syslog1loc"
		webuiloginvalid="$(am_settings_get skynet_loginvalid)"
		webuilogsize="$(am_settings_get skynet_logsize)"
		webuiextended="$(am_settings_get skynet_extendedstats)"
		webuicountry="$(am_settings_get skynet_lookupcountry)"
		webuicdn="$(am_settings_get skynet_cdnwhitelist)"

		case "$webuiautoupdate" in enabled|disabled) ;; *) settingsresult="error" ;; esac
		case "$webuifilter" in all|inbound|outbound) ;; *) settingsresult="error" ;; esac
		case "$webuimalware" in daily|weekly|disabled) ;; *) settingsresult="error" ;; esac
		if [ -n "$webuicustomlist" ]; then
			# Require HTTP(S) and URL-safe characters; quotes and shell syntax are
			# intentionally excluded before the value reaches a CLI command.
			[ "${#webuicustomlist}" -le 512 ] 2>/dev/null || settingsresult="error"
			printf '%s\n' "$webuicustomlist" | grep -qE '^https?://[A-Za-z0-9._~:/?&=#%@+,-]+$' || settingsresult="error"
		fi
		case "$webuiunbanprivate" in enabled|disabled) ;; *) settingsresult="error" ;; esac
		case "$webuiaiprotect" in enabled|disabled) ;; *) settingsresult="error" ;; esac
		case "$webuisecuremode" in enabled|disabled) ;; *) settingsresult="error" ;; esac
		case "$webuilogmode" in enabled|disabled) ;; *) settingsresult="error" ;; esac
		case "$webuisyslogmode" in
			auto) ;;
			custom)
				Validate_Syslog_Path "$webuisyslog" && Validate_Syslog_Path "$webuisyslog1" \
					&& [ "$webuisyslog" != "$webuisyslog1" ] || settingsresult="error"
			;;
			*) settingsresult="error" ;;
		esac
		case "$webuiloginvalid" in enabled|disabled) ;; *) settingsresult="error" ;; esac
		case "$webuilogsize" in ""|*[!0-9]*) settingsresult="error" ;; *) [ "$webuilogsize" -ge 10 ] 2>/dev/null || settingsresult="error" ;; esac
		case "$webuiextended" in enabled|disabled) ;; *) settingsresult="error" ;; esac
		case "$webuicountry" in enabled|disabled) ;; *) settingsresult="error" ;; esac
		case "$webuicdn" in enabled|disabled) ;; *) settingsresult="error" ;; esac
	fi

	if [ "$settingsresult" = "success" ]; then
		Apply_WebUI_Toggle "$webuiautoupdate" "$autoupdate" autoupdate || settingsresult="error"
		if [ "$settingsresult" = "success" ] && [ "$webuifilter" != "$filtertraffic" ]; then
			Run_WebUI_Command settings filter "$webuifilter" >/dev/null 2>&1 || settingsresult="error"
		fi
		if [ "$settingsresult" = "success" ] && [ "$webuimalware" != "$banmalwareupdate" ]; then
			if [ "$webuimalware" = "disabled" ]; then webuimalware="disable"; fi
			Run_WebUI_Command settings banmalware "$webuimalware" >/dev/null 2>&1 || settingsresult="error"
		fi
		if [ "$settingsresult" = "success" ]; then
			Apply_WebUI_Toggle "$webuiunbanprivate" "$unbanprivateip" unbanprivate || settingsresult="error"
		fi
		if [ "$settingsresult" = "success" ]; then
			Apply_WebUI_Toggle "$webuiaiprotect" "$banaiprotect" banaiprotect || settingsresult="error"
		fi
		if [ "$settingsresult" = "success" ]; then
			Apply_WebUI_Toggle "$webuisecuremode" "$securemode" securemode || settingsresult="error"
		fi
		if [ "$settingsresult" = "success" ]; then
			Apply_WebUI_Toggle "$webuiloginvalid" "$loginvalid" loginvalid || settingsresult="error"
		fi
		if [ "$settingsresult" = "success" ]; then
			Apply_WebUI_Toggle "$webuilogmode" "$logmode" logmode || settingsresult="error"
		fi
		if [ "$settingsresult" = "success" ] && [ "$webuilogsize" != "$logsize" ]; then
			Run_WebUI_Command settings logsize "$webuilogsize" >/dev/null 2>&1 || settingsresult="error"
		fi
		if [ "$settingsresult" = "success" ]; then
			Apply_WebUI_Toggle "$webuiextended" "$extendedstats" extendedstats || settingsresult="error"
		fi
		if [ "$settingsresult" = "success" ]; then
			Apply_WebUI_Toggle "$webuicountry" "$lookupcountry" lookupcountry || settingsresult="error"
		fi
		if [ "$settingsresult" = "success" ]; then
			Apply_WebUI_Toggle "$webuicdn" "$cdnwhitelist" cdnwhitelist || settingsresult="error"
		fi
		if [ "$settingsresult" = "success" ] && [ "$webuicustomlist" != "$customlisturl" ]; then
			if [ -n "$webuicustomlist" ]; then
				Run_WebUI_Command banmalware "$webuicustomlist" >/dev/null 2>&1 || settingsresult="error"
			else
				Run_WebUI_Command banmalware reset >/dev/null 2>&1 || settingsresult="error"
			fi
		fi
	fi

	# Apply log source paths last so preceding commands archive from the saved sources.
	if [ "$settingsresult" = "success" ]; then
		if [ "$webuisyslogmode" = "auto" ]; then
			[ "$syslogmode" = "auto" ] || Run_WebUI_Command settings syslog auto >/dev/null 2>&1 || settingsresult="error"
		elif [ "$syslogmode" != "custom" ] || [ "$webuisyslog" != "$syslogloc" ] || [ "$webuisyslog1" != "$syslog1loc" ]; then
			Run_WebUI_Command settings syslog "$webuisyslog" "$webuisyslog1" >/dev/null 2>&1 || settingsresult="error"
		fi
	fi
	Load_Config || settingsresult="error"
	Publish_WebUI_Result
}

Apply_WebUI_Threat_Feeds() {
	# Feed selection and blacklist replacement are one CLI transaction. The WebUI
	# stages membership or exclusions and translates the worker result into compact
	# tokens consumed by the existing settings.js poller.
	settingsresult="error"
	webuifeedoutput="$TMP_DIR/webui-feed-output"
	if [ -f "$_am_settings_path" ]; then
		webuifeedaction="$(am_settings_get skynet_feed_action)"
		webuifeedvalues="$(am_settings_get skynet_feed_values)"
		webuiexclusions="$(am_settings_get skynet_excludelists)"
		# Explicit actions avoid replaying retained addon fields on Update Now.
		if [ -z "$webuifeedaction" ]; then
			if [ "$(am_settings_get skynet_feedchange)" = "1" ]; then webuifeedaction="selection"; else webuifeedaction="refresh"; fi
		fi
		case "$webuifeedaction" in
			refresh) set -- banmalware ;;
			selection)
				if [ -n "$webuiexclusions" ]; then set -- banmalware exclude "$webuiexclusions"
				else set -- banmalware exclude reset; fi
			;;
			add|remove)
				if [ -n "$webuifeedvalues" ]; then set -- banmalware "$webuifeedaction" "$webuifeedvalues"
				else settingsresult="filter"; fi
			;;
			template)
				if [ -n "$webuifeedvalues" ]; then
					case "$webuifeedvalues" in http://*|https://*) set -- banmalware "$webuifeedvalues" ;; *) settingsresult="filter" ;; esac
				else set -- banmalware reset; fi
			;;
			*) settingsresult="filter" ;;
		esac
		if [ "$settingsresult" != "filter" ]; then
			Run_WebUI_Command "$@" > "$webuifeedoutput" 2>&1
			webuifeedstatus="$?"

			if [ "$webuifeedstatus" = "0" ]; then
				if awk -F '\t' '$3 == "enabled" && $4 == "cached" { found=1 } END { exit !found }' "${skynetloc}/lists/.sources" 2>/dev/null; then
					settingsresult="degraded"
				else
					settingsresult="success"
				fi
			elif [ "$webuifeedstatus" = "2" ]; then
				if [ "$webuifeedaction" = "template" ]; then settingsresult="filter"
				else settingsresult="validation"; fi
			elif grep -q 'No Valid Cached Copy For Malware Source' "$webuifeedoutput" 2>/dev/null; then
				webuifailedsource="$(sed -n 's~.*No Valid Cached Copy For Malware Source (\([^)]*\)).*~\1~p' "$webuifeedoutput" | tail -1)"
				case "$webuifailedsource" in ""|*[!A-Za-z0-9._-]*) settingsresult="error" ;; *) settingsresult="failed:$webuifailedsource" ;; esac
			elif grep -qE 'Failed To Process Filter List|No Valid Malware Sources|At Least One Malware Source|Stopping Banmalware' "$webuifeedoutput" 2>/dev/null; then
				settingsresult="filter"
			elif grep -qE 'Unable To (Build|Apply|Save|Publish).*Blacklist|Unable To Refresh AiProtect Bans|Unable To Publish Malware Source Status|Unable To Save Malware Cache Manifest' "$webuifeedoutput" 2>/dev/null; then
				settingsresult="apply"
			fi
		fi
	fi

	rm -f "$webuifeedoutput"
	Load_Config || settingsresult="error"
	Publish_WebUI_Result
}

Apply_WebUI_Countries() {
	# Country CLI updates are atomic. Preserve its specific failure reason in a
	# compact result token so JavaScript can present a useful message.
	settingsresult="error"
	if [ -f "$_am_settings_path" ]; then
		webuicountries="$(am_settings_get skynet_countrylist | awk '{$1=$1; print tolower($0)}')"
		webuicountryrefresh="$(am_settings_get skynet_countryrefresh)"
		webuicountrysorted="$(printf '%s\n' "$webuicountries" | tr ' ' '\n' | sort | awk 'NF {output = output (output == "" ? "" : " ") $1} END {print output}')"
		countrylistsorted="$(printf '%s\n' "$countrylist" | tr ' ' '\n' | sort | awk 'NF {output = output (output == "" ? "" : " ") $1} END {print output}')"

		if [ -z "$webuicountries" ] || printf '%s\n' "$webuicountries" | grep -qE '^([a-z][a-z])( [a-z][a-z])*$'; then
			if [ "$webuicountryrefresh" = "1" ] && [ "$webuicountrysorted" != "$countrylistsorted" ]; then
				settingsresult="validation"
			elif [ "$webuicountryrefresh" = "1" ] && [ -n "$countrylist" ]; then
				if webuicountryresult="$(Run_WebUI_Command ban country refresh 2>&1)"; then
					webuicachedcountries="$(printf '%s\n' "$webuicountryresult" | sed -n 's~.*Using Cached Country List (\([^)]*\)).*~\1~p' \
						| awk '{if (output != "") output = output ","; output = output $1} END {print output}')"
					if [ -n "$webuicachedcountries" ]; then settingsresult="degraded:${webuicachedcountries}"; else settingsresult="success"; fi
				else
					case "$webuicountryresult" in
						*"Failed To Download Country List"*) webuicountry="$(printf '%s\n' "$webuicountryresult" | sed -n 's~.*Failed To Download Country List (\([^)]*\)).*~\1~p' | tail -1)"; settingsresult="download:${webuicountry}" ;;
						*"No Valid IPv4 Ranges Found"*) webuicountry="$(printf '%s\n' "$webuicountryresult" | sed -n 's~.*No Valid IPv4 Ranges Found For (\([^)]*\)).*~\1~p' | tail -1)"; settingsresult="invalid:${webuicountry}" ;;
						*"Previous Bans Restored"*) settingsresult="restore" ;;
						*"Connection Error Detected"*) settingsresult="connection" ;;
					esac
				fi
			elif [ "$webuicountries" = "$countrylist" ]; then
				settingsresult="success"
			elif [ -n "$webuicountries" ]; then
				if webuicountryresult="$(Run_WebUI_Command ban country "$webuicountries" 2>&1)"; then
					webuicachedcountries="$(printf '%s\n' "$webuicountryresult" | sed -n 's~.*Using Cached Country List (\([^)]*\)).*~\1~p' \
						| awk '{if (output != "") output = output ","; output = output $1} END {print output}')"
					if [ -n "$webuicachedcountries" ]; then
						settingsresult="degraded:${webuicachedcountries}"
					else
						settingsresult="success"
					fi
				else
					case "$webuicountryresult" in
						*"Failed To Download Country List"*)
							webuicountry="$(printf '%s\n' "$webuicountryresult" | sed -n 's~.*Failed To Download Country List (\([^)]*\)).*~\1~p' | tail -1)"
							settingsresult="download:${webuicountry}"
						;;
						*"No Valid IPv4 Ranges Found"*)
							webuicountry="$(printf '%s\n' "$webuicountryresult" | sed -n 's~.*No Valid IPv4 Ranges Found For (\([^)]*\)).*~\1~p' | tail -1)"
							settingsresult="invalid:${webuicountry}"
						;;
						*"Previous Bans Restored"*) settingsresult="restore" ;;
						*"Connection Error Detected"*) settingsresult="connection" ;;
					esac
				fi
			else
				Run_WebUI_Command unban country >/dev/null 2>&1 && settingsresult="success"
			fi
		fi
	fi

	Load_Config || settingsresult="error"
	Publish_WebUI_Result
}

Set_WebUI_Rule_Result() {
	# Translate the public command result without exposing command output in the
	# generated payload. Specific tokens let the WebUI distinguish input, source,
	# ownership, persistence and live-apply failures.
	webuirulestatus="$1"
	webuiruleoutput="$2"
	case "$webuirulestatus" in
		0) settingsresult="success"; webuirulepersisted="1" ;;
		2)
			if grep -qF "Already Owned By Another Rule" "$webuiruleoutput" 2>/dev/null; then
				settingsresult="conflict"
			else
				settingsresult="validation"
			fi
		;;
		*)
			if grep -qF "Lock File Detected" "$webuiruleoutput" 2>/dev/null; then
				settingsresult="busy"
			elif grep -qF "Unable To Resolve" "$webuiruleoutput" 2>/dev/null; then
				settingsresult="resolve"
			elif grep -qF "Failed To Download Or Apply" "$webuiruleoutput" 2>/dev/null; then
				settingsresult="source"
			elif grep -qE "Failed To (Save|Write)|Unable To Save" "$webuiruleoutput" 2>/dev/null; then
				settingsresult="save"
			else
				settingsresult="apply"
			fi
		;;
	esac
}

Queue_WebUI_Rule_Failure() {
	case "$settingsresult" in apply|save|resolve|source|error) ;; *) return 0 ;; esac
	# A nested public command may already have recorded this transaction.
	if [ -n "$webuirequestid" ] && awk -F '\t' -v transaction="$webuirequestid" \
		'$1 == "A1" && $5 == "failed" && $6 == "rules" && $12 == transaction {found = 1} END {exit !found}' \
		"$skynetevents" 2>/dev/null; then
		return 0
	fi
	webuifailureoperation="$webuiruleoperation"
	webuifailuretarget="$webuiruleaction"
	webuifailuretype="$webuirulemode"
	webuifailureentries="${webuiruleentries:-requested rules}"
	if [ "$webuiruleoperation" = "refresh" ]; then
		webuifailuretarget="all"
		webuifailuretype="logical"
		webuifailureentries="registered rules"
	elif [ "$webuiruleaction" = "unban" ]; then
		webuifailureoperation="remove"
		webuifailuretarget="ban"
	fi
	case "$webuifailureoperation" in add|remove|refresh) ;; *) webuifailureoperation="update" ;; esac
	case "$webuifailuretarget" in ""|*[!A-Za-z0-9_-]*) webuifailuretarget="rules" ;; esac
	case "$webuifailuretype" in ""|*[!A-Za-z0-9_-]*) webuifailuretype="request" ;; esac
	case "$settingsresult" in
		save) webuifailuredetail="Persistence failed" ;;
		resolve) webuifailuredetail="Domain resolution failed" ;;
		source) webuifailuredetail="Source retrieval failed" ;;
		apply) webuifailuredetail="Firewall update failed" ;;
		*) webuifailuredetail="Request failed" ;;
	esac
	Queue_Action failed rules "$webuifailureoperation" "$webuifailuretarget" "$webuifailuretype" \
		"$webuifailureentries" "$webuifailuredetail" || Log error -s "Failed To Queue Rule Failure"
}

Apply_WebUI_Rules() {
	settingsresult="error"
	webuiruleoperation="$(am_settings_get skynet_ruleoperation)"
	webuiruleaction="$(am_settings_get skynet_ruleaction)"
	webuirulemode="$(am_settings_get skynet_rulemode)"
	webuiruleentries="$(am_settings_get skynet_ruleentries)"
	webuirulecomment="$(am_settings_get skynet_rulecomment)"
	webuirulecomments="$(am_settings_get skynet_rulecomments)"
	webuirulecommentfile=""
	webuiruletimeout="$(am_settings_get skynet_ruletimeout)"
	webuiruleid="$(am_settings_get skynet_ruleid)"
	webuirulepersisted="0"
	webuiruleoutput=""
	settingsresult="ready"
	SKYNET_ACTION_ORIGIN="webui"
	SKYNET_ACTION_TRANSACTION="$webuirequestid"
	if ! Time_Is_Ready && { [ "$webuiruleoperation" = "refresh" ] \
		|| { [ "$webuiruleoperation" = "add" ] && [ "$webuiruleaction" != "unban" ]; }; }; then
		settingsresult="time"
		nocfg="1"
		Generate_WebUI_Settings
		return 1
	fi

	case "$webuiruleoperation:$webuiruleaction:$webuirulemode" in
		refresh:*:*)
			webuiruleoutput="$TMP_DIR/webui-rule-output.$$"
			Run_WebUI_Command rules refresh > "$webuiruleoutput" 2>&1
			webuirulestatus="$?"
			Set_WebUI_Rule_Result "$webuirulestatus" "$webuiruleoutput"
			if [ "$settingsresult" = "success" ] && awk -F '\t' -v transaction="$webuirequestid" '
				$1 == "A1" && $5 == "degraded" && $6 == "rules" && $7 == "refresh" && $12 == transaction {found = 1}
				END {exit !found}
			' "$skynetevents" 2>/dev/null; then
				settingsresult="degraded"
			fi
			rm -f "$webuiruleoutput"
		;;
		add:unban:ip)
			Check_Lock webui rules || return 1
			webuiruleentries="$(Normalize_List "$webuiruleentries")" || settingsresult="validation"
			if [ "$settingsresult" = "ready" ]; then
				for webuiruleentry in $webuiruleentries; do
					if ! printf '%s\n' "$webuiruleentry" | Is_IPRange; then
						settingsresult="validation"
						break
					fi
				done
			fi
			if [ "$settingsresult" = "ready" ]; then
				Apply_Registered_Address_Rules remove ban "$webuiruleentries" ""
				webuirulestatus="$?"
				if [ "$webuirulestatus" = "0" ]; then
					settingsresult="success"
					webuirulepersisted="1"
					webuirulecovered="0"
					for webuiruleentry in $webuiruleentries; do
						webuirulepattern="$(printf '%s\n' "$webuiruleentry" | sed 's/\./\\./g')"
						sed -i "\\~BLOCKED.*=$webuirulepattern ~d" "$skynetlog"
						if printf '%s\n' "$webuiruleentry" | Is_IP; then webuiruleentrytype="ip"; else webuiruleentrytype="range"; fi
						Ban_Value_Is_Covered "$webuiruleentrytype" "$webuiruleentry" && webuirulecovered="1"
					done
					if [ "$webuirulecovered" = "1" ]; then settingsresult="warning:covered"; webuiruleresult="degraded"
					else webuiruleresult="success"; fi
					Queue_Action "$webuiruleresult" rules remove ban address "$webuiruleentries" "" \
						|| Log error -s "Failed To Queue Rule Action"
				elif [ "$webuirulestatus" = "2" ]; then settingsresult="stale"
				else settingsresult="apply"
				fi
			fi
		;;
		add:ban:ip|add:whitelist:ip)
			Check_Lock webui rules || return 1
			webuiruleentries="$(Normalize_List "$webuiruleentries")" || settingsresult="validation"
			Validate_IPSet_Comment "$webuirulecomment" 242 || settingsresult="validation"
			if [ -n "$webuirulecomments" ]; then
				# One-line tab-separated address/comment pairs fit Merlin custom settings;
				# comments reject tabs/newlines and are validated again during staging.
				webuirulecommentfile="$TMP_DIR/webui-rule-comments.$$"
				printf '%s\n' "$webuirulecomments" | awk -F '\t' '
					NR != 1 || NF % 2 {invalid=1}
					{for (i=1; i<NF; i+=2) print $i "\t" $(i+1)}
					END {exit invalid ? 2 : 0}
				' > "$webuirulecommentfile" || settingsresult="validation"
			fi
			webuiruleexpires="0"
			if [ "$webuiruleaction" = "whitelist" ] && [ -n "$webuiruletimeout" ]; then settingsresult="validation"; fi
			if [ "$webuiruleaction" = "ban" ] && [ -n "$webuiruletimeout" ]; then
				case "$webuiruletimeout" in
					15m) webuiruleduration="900" ;;
					1h) webuiruleduration="3600" ;;
					6h) webuiruleduration="21600" ;;
					24h) webuiruleduration="86400" ;;
					7d) webuiruleduration="604800" ;;
					*) settingsresult="validation" ;;
				esac
				if [ "$settingsresult" = "ready" ] || [ "$settingsresult" = "error" ]; then
					if Time_Is_Ready; then webuiruleexpires="$(($(date +%s) + webuiruleduration))"; else settingsresult="time"; fi
				fi
			fi
			webuirulewarning="0"
			if [ "$settingsresult" = "ready" ]; then
				if ! Time_Is_Ready; then settingsresult="time"; fi
				for webuiruleentry in $webuiruleentries; do
					printf '%s\n' "$webuiruleentry" | Is_IPRange || { settingsresult="validation"; break; }
					if [ "$webuiruleaction" = "ban" ]; then
						webuirulewhitelisttest="${webuiruleentry%%/*}"
						IP_Is_Whitelisted "$webuirulewhitelisttest" && webuirulewarning="1"
					fi
				done
			fi
			if [ "$settingsresult" = "ready" ]; then
				Apply_Registered_Address_Rules add "$webuiruleaction" "$webuiruleentries" "$webuirulecomment" "$webuiruleexpires" "$webuirulecommentfile"
				webuirulestatus="$?"
			fi
			if [ "$settingsresult" = "ready" ] && [ "$webuirulestatus" = "0" ]; then
				webuirulepersisted="1"
				if [ "$webuiruleexpires" -gt "0" ] && [ "$rulestagepermanent" -gt "0" ]; then
					settingsresult="warning:permanent"
					webuiruleactionresult="degraded"
				elif [ "$webuirulewarning" = "1" ]; then
					settingsresult="warning:whitelist"
					webuiruleactionresult="degraded"
				else
					settingsresult="success"
					webuiruleactionresult="success"
				fi
				if [ -n "$webuirulecommentfile" ]; then webuiruledetail="Comments stored per rule"; else webuiruledetail="$webuirulecomment"; fi
				if [ "$webuiruleexpires" -gt "0" ]; then webuiruledetail="${webuiruledetail}${webuiruledetail:+; }Expires $(Format_Threat_Feed_Time "$webuiruleexpires")"; fi
				if [ "$rulestagechanged" -gt "0" ]; then
					Queue_Action "$webuiruleactionresult" rules add "$webuiruleaction" address "$webuiruleentries" "$webuiruledetail" \
						|| Log error -s "Failed To Queue Rule Action"
				fi
			elif [ "$settingsresult" = "ready" ]; then
				if [ "$webuirulestatus" = "2" ]; then settingsresult="validation"; else settingsresult="apply"; fi
			fi
		;;
		remove:*:id)
			Check_Lock webui rules || return 1
			if ! printf '%s\n' "$webuiruleid" | grep -qE '^r[0-9]+(-[0-9]+)?$'; then settingsresult="validation"; fi
			if [ "$settingsresult" = "ready" ]; then
				Remove_Registered_Rule_ID "$webuiruleid"
				case "$?" in 0) settingsresult="success"; webuirulepersisted="1" ;; 2) settingsresult="stale" ;; *) settingsresult="apply" ;; esac
				if [ "$settingsresult" = "success" ]; then
					webuiruleresult="success"
					if [ "$ruleremovetarget" = "ban" ] && { [ "$ruleremovetype" = "ip" ] || [ "$ruleremovetype" = "range" ]; } \
						&& Ban_Value_Is_Covered "$ruleremovetype" "$ruleremovevalue"; then
						settingsresult="warning:covered"
						webuiruleresult="degraded"
					fi
					Queue_Action "$webuiruleresult" rules remove "$ruleremovetarget" "$ruleremovetype" "$ruleremovevalue" "${ruleremovecomment#C}" \
						|| Log error -s "Failed To Queue Rule Action"
				fi
			fi
		;;
		add:ban:domain|add:whitelist:domain|add:unban:domain|add:ban:asn|add:whitelist:asn|add:unban:asn)
			webuiruleentries="$(Normalize_List "$webuiruleentries")" || settingsresult="validation"
			if [ "$settingsresult" != "validation" ]; then
				# Values are validated by the public dispatcher before any live change.
				# shellcheck disable=SC2086
				set -- $webuiruleentries
				webuiruleoutput="$TMP_DIR/webui-rule-output.$$"
				if [ "$webuiruleaction" = "ban" ]; then Run_WebUI_Command ban "$webuirulemode" "$@" > "$webuiruleoutput" 2>&1
				elif [ "$webuiruleaction" = "whitelist" ]; then Run_WebUI_Command whitelist "$webuirulemode" "$@" > "$webuiruleoutput" 2>&1
				else Run_WebUI_Command unban "$webuirulemode" "$@" > "$webuiruleoutput" 2>&1
				fi
				webuirulestatus="$?"
				Set_WebUI_Rule_Result "$webuirulestatus" "$webuiruleoutput"
				rm -f "$webuiruleoutput"
			fi
		;;
		remove:ban:domain|remove:whitelist:domain|remove:ban:asn|remove:whitelist:asn)
			webuiruleentries="$(Normalize_List "$webuiruleentries")" || settingsresult="validation"
			if [ "$settingsresult" != "validation" ]; then
				# shellcheck disable=SC2086
				set -- $webuiruleentries
				webuiruleoutput="$TMP_DIR/webui-rule-output.$$"
				case "$webuiruleaction:$webuirulemode" in
					ban:domain) Run_WebUI_Command unban domain "$@" > "$webuiruleoutput" 2>&1 ;;
					ban:asn) Run_WebUI_Command unban asn "$@" > "$webuiruleoutput" 2>&1 ;;
					whitelist:domain) Run_WebUI_Command whitelist remove domain "$@" > "$webuiruleoutput" 2>&1 ;;
					whitelist:asn) Run_WebUI_Command whitelist remove asn "$@" > "$webuiruleoutput" 2>&1 ;;
				esac
				webuirulestatus="$?"
				Set_WebUI_Rule_Result "$webuirulestatus" "$webuiruleoutput"
				rm -f "$webuiruleoutput"
			fi
		;;
		*) settingsresult="validation" ;;
	esac

	case "$settingsresult" in success|warning:whitelist|warning:permanent|warning:covered) ;; *) Discard_Actions ;; esac
	if [ "$settingsresult" = "success" ] && [ "$webuirulepersisted" = "1" ]; then
		Load_Config || settingsresult="error"
		nocfg="1"
	fi
	[ -z "$webuiruleoutput" ] || rm -f "$webuiruleoutput"
	nocfg="1"
	Load_Config || settingsresult="error"
	Queue_WebUI_Rule_Failure
	case "$settingsresult" in
		success|warning:whitelist|warning:permanent|warning:covered|degraded) Publish_Actions || { Log error -s "Failed To Record Committed Rule Action"; settingsresult="save"; } ;;
		apply|save|resolve|source|error) Publish_Failed_Actions || Log error -s "Failed To Record Rule Failure" ;;
	esac
	Publish_WebUI_Result
}

Replace_IOT_Entries() {
	# Build the complete IoT set beside the live set, then swap it into service.
	# The live set is never flushed while a replacement is still being prepared.
	iotreplacelist="$1"
	iotreplacetmp="Skynet-IOT-Tmp"
	cleanupipsets="${cleanupipsets}${cleanupipsets:+ }${iotreplacetmp}"
	iotreplacefile="$TMP_DIR/iot-replace.$$"
	true > "$iotreplacefile" || return 1
	for iotreplaceentry in $iotreplacelist; do
		printf 'add %s %s comment "IOTBan: %s"\n' "$iotreplacetmp" "$iotreplaceentry" "$(date +"%b %e %T")" >> "$iotreplacefile" \
			|| { rm -f "$iotreplacefile"; return 1; }
	done
	Destroy_IPSets "$iotreplacetmp"
	if ! ipset -q create "$iotreplacetmp" hash:net hashsize 64 maxelem "$((65536 * 6))" comment \
		|| { [ -s "$iotreplacefile" ] && ! ipset restore < "$iotreplacefile"; }; then
		Destroy_IPSets "$iotreplacetmp"
		rm -f "$iotreplacefile"
		return 1
	fi
	trap '' INT TERM
	if ipset swap "$iotreplacetmp" Skynet-IOT; then
		Destroy_IPSets "$iotreplacetmp"
		Set_Cleanup_Traps
		rm -f "$iotreplacefile"
		return 0
	fi
	Destroy_IPSets "$iotreplacetmp"
	Set_Cleanup_Traps
	rm -f "$iotreplacefile"
	return 1
}

Restore_WebUI_IOT() {
	# Roll back IPSet contents, rule options, switches and persistent files as one
	# unit after a failed WebUI IoT transaction.
	iotwebrestore="$TMP_DIR/iot-webui-restore.$$"
	awk '$1 == "add"' "$iotwebsnapshot" > "$iotwebrestore" \
		|| { rm -f "$iotwebrestore"; return 1; }
	Unload_LogIPTables
	Unload_IOT_Rules 2>/dev/null || { rm -f "$iotwebrestore"; return 1; }
	if ! ipset flush Skynet-IOT 2>/dev/null \
		|| { [ -s "$iotwebrestore" ] && ! ipset restore < "$iotwebrestore" 2>/dev/null; }; then
		rm -f "$iotwebrestore"
		return 1
	fi
	rm -f "$iotwebrestore"
	iotports="$iotweboldports"
	iotproto="$iotweboldproto"
	iotblocked="$iotweboldblocked"
	iotlogging="$iotweboldlogging"
	Load_IOT_Rules || return 1
	Load_LogIPTables || return 1
	return 0
}

Apply_WebUI_IOT() {
	# Validate every field before unloading live rules. Once validation passes,
	# retain both the IPSet and scalar settings needed for full rollback.
	settingsresult="error"
	webuiiotentries="$(am_settings_get skynet_iotentries)"
	webuiiotports="$(am_settings_get skynet_iotports)"
	webuiiotproto="$(am_settings_get skynet_iotproto)"
	webuiiotblocked="$(am_settings_get skynet_iotblocked)"
	webuiiotlogging="$(am_settings_get skynet_iotlogging)"

	if [ -n "$webuiiotentries" ]; then
		webuiiotentries="$(Normalize_List "$webuiiotentries")" || { settingsresult="validation"; Generate_WebUI_Settings; return 2; }
		for webuiiotentry in $webuiiotentries; do
			printf '%s\n' "$webuiiotentry" | Is_IPRange || { settingsresult="validation"; Generate_WebUI_Settings; return 2; }
		done
	fi
	if [ "$webuiiotports" != "none" ] && [ -n "$webuiiotports" ]; then
		webuiiotports="$(Normalize_List "$webuiiotports")" || { settingsresult="validation"; Generate_WebUI_Settings; return 2; }
		webuiiotportcount="0"
		for webuiiotport in $webuiiotports; do
			printf '%s\n' "$webuiiotport" | Is_Port || { settingsresult="validation"; Generate_WebUI_Settings; return 2; }
			webuiiotportcount=$((webuiiotportcount + 1))
		done
		[ "$webuiiotportcount" -le "15" ] || { settingsresult="validation"; Generate_WebUI_Settings; return 2; }
	fi
	case "$webuiiotproto" in udp|tcp|all) ;; *) settingsresult="validation"; Generate_WebUI_Settings; return 2 ;; esac
	# The empty policy is always the canonical UDP NTP default. Normalizing here
	# also protects requests submitted by an older cached WebUI.
	[ -n "$webuiiotports" ] || webuiiotproto="udp"
	case "$webuiiotblocked:$webuiiotlogging" in
		enabled:enabled|enabled:disabled|disabled:enabled|disabled:disabled) ;;
		*) settingsresult="validation"; Generate_WebUI_Settings; return 2 ;;
	esac

	iotwebsnapshot="$TMP_DIR/iot-webui-old.$$"
	ipset save Skynet-IOT > "$iotwebsnapshot" 2>/dev/null || { Generate_WebUI_Settings; return 1; }
	iotweboldports="$iotports"
	iotweboldproto="$iotproto"
	iotweboldblocked="$iotblocked"
	iotweboldlogging="$iotlogging"
	iotwebflowentries=""
	if [ "$webuiiotblocked" = "enabled" ]; then
		if [ "$iotweboldblocked" != "enabled" ] || [ "$iotweboldports:$iotweboldproto" != "$webuiiotports:$webuiiotproto" ]; then
			iotwebflowentries="$webuiiotentries"
		else
			iotwebflowentries="$(awk -v entries="$webuiiotentries" '
				$1 == "add" {old[$3]=1}
				END {n=split(entries, entry, " "); for (i=1; i<=n; i++) if (!(entry[i] in old)) print entry[i]}
			' "$iotwebsnapshot")" || { rm -f "$iotwebsnapshot"; Generate_WebUI_Settings; return 1; }
		fi
	fi
	Acquire_Firewall_Lock || { rm -f "$iotwebsnapshot"; Generate_WebUI_Settings; return 1; }
	Unload_LogIPTables
	if ! Unload_IOT_Rules || ! Replace_IOT_Entries "$webuiiotentries"; then
		Load_IOT_Rules || Log error -s "Failed To Restore IoT Firewall Rules"
		Load_LogIPTables || Log error -s "Failed To Restore IoT Logging Rules"
		Release_Firewall_Lock
		rm -f "$iotwebsnapshot"
		settingsresult="apply"
		Generate_WebUI_Settings
		return 1
	fi
	iotports="$webuiiotports"
	iotproto="$webuiiotproto"
	iotblocked="$webuiiotblocked"
	iotlogging="$webuiiotlogging"
	if ! Load_IOT_Rules; then
		Restore_WebUI_IOT || Log error -s "Failed To Fully Restore IoT Configuration"
		Release_Firewall_Lock
		rm -f "$iotwebsnapshot"
		Generate_WebUI_Settings
		return 1
	fi
	if ! Load_LogIPTables || ! Revalidate_IOT_Connections "$iotwebflowentries"; then
		Restore_WebUI_IOT || Log error -s "Failed To Fully Restore IoT Configuration"
		Release_Firewall_Lock
		rm -f "$iotwebsnapshot"
		settingsresult="apply"
		Generate_WebUI_Settings
		return 1
	fi
	Release_Firewall_Lock
	if ! Save_IPSets || ! Write_Config; then
		if Acquire_Firewall_Lock; then
			Restore_WebUI_IOT || Log error -s "Failed To Fully Restore IoT Configuration"
			Release_Firewall_Lock
		else
			Log error -s "Failed To Lock Firewall For IoT Rollback"
		fi
		if ! Save_IPSets || ! Write_Config; then Log error -s "Failed To Persist Restored IoT Configuration"; fi
		rm -f "$iotwebsnapshot"
		settingsresult="apply"
		Generate_WebUI_Settings
		return 1
	fi
	nocfg="1"
	iotweblogstatus="0"
	iotremovedentries=""
	while read -r iotoldaction _iotoldset iotoldentry _iotoldtail; do
		[ "$iotoldaction" = "add" ] || continue
		case " $webuiiotentries " in
			*" $iotoldentry "*) ;;
			*) iotremovedentries="${iotremovedentries}${iotremovedentries:+ }$iotoldentry" ;;
		esac
	done < "$iotwebsnapshot" || iotweblogstatus="1"
	Prune_IOT_Device_Logs "$iotremovedentries" || iotweblogstatus="1"
	rm -f "$iotwebsnapshot"
	settingsresult="success"
	if [ "$iotweblogstatus" != "0" ]; then
		Log error -s "Failed To Prune Removed IoT Device Logs"
		settingsresult="save"
	fi
	Queue_Action success iot update isolation "configuration" \
		"${webuiiotentries:-no devices}" "Blocking $webuiiotblocked; logging $webuiiotlogging; ports ${webuiiotports:-UDP/123}; protocol $webuiiotproto" \
		|| { Log error -s "Failed To Queue IoT Action"; settingsresult="save"; }
	Publish_Actions || { Log error -s "Failed To Record Committed IoT Action"; settingsresult="save"; }
	Publish_WebUI_Result
}

######################
#- Command Handlers -#
######################

Print_Rule_Status() {
	Validate_Rule_Registry "$skynetrules" || { echo "[*] Rule Registry Is Unavailable Or Invalid"; return 1; }
	rulestatuscounts="$(awk -F '\t' '
		$1 == "R2" && $7 == "enabled" {
			total++
			if ($4 == "domain") domains++
			else if ($4 == "asn") asns++
			else addresses++
		}
		END {print total + 0, addresses + 0, domains + 0, asns + 0}
	' "$skynetrules")"
	# shellcheck disable=SC2086 # Four validated numeric fields are split intentionally.
	set -- $rulestatuscounts
	echo "[i] Registered Rules: ${1:-0} (${2:-0} IP/CIDR, ${3:-0} Domain, ${4:-0} ASN)"
	if [ -s "$rulestatusmanifest" ]; then
		echo
		printf '%-11s | %-42s | %-8s | %-9s | %s\n' "Policy" "Domain" "Answers" "State" "Last Success"
		printf '%-11s-+-%-42s-+-%-8s-+-%-9s-+-%s\n' "-----------" "------------------------------------------" "--------" "---------" "--------------------"
		while IFS="$(printf '\t')" read -r _domainversion domainstatustarget domainstatusvalue domainstatusstate domainstatuscount _domainchecked domainstatussuccess _domainchanged _domainfield9 _domainfield10 _domainfield11; do
			printf '%-11s | %-42s | %-8s | %-9s | %s\n' "$domainstatustarget" "$domainstatusvalue" "$domainstatuscount" "$domainstatusstate" "$(Format_Threat_Feed_Time "$domainstatussuccess")"
		done < "$rulestatusmanifest"
	elif [ "${3:-0}" -gt "0" ]; then
		echo "[i] Domain health will be available after the next rule refresh"
	fi
}

Build_Domain_Rule_Action_Detail() {
	# Summarise the committed observed state without turning action history into a
	# second state store. The manifest remains authoritative for current health.
	awk -F '\t' -v old="${domainmanifestold:-}" '
		function load_old(line, field, key) {
			split(line, field, "\t")
			if (field[1] != "D1" && field[1] != "D2") return
			key = field[2] SUBSEP field[3]
			old_state[key] = field[4]; old_count[key] = field[5]
			old_hash[key] = field[1] == "D2" ? field[10] : field[9]
		}
		BEGIN {
			if (old != "") {
				while ((getline line < old) > 0) load_old(line)
				close(old)
			}
		}
		$1 == "D1" || $1 == "D2" {
			key = $2 SUBSEP $3; seen[key] = 1; entries += $5
			state[$4]++
			hash = $1 == "D2" ? $10 : $9
			if (!(key in old_state) || old_state[key] != $4 || old_count[key] != $5 || old_hash[key] != hash) changed++
		}
		END {
			for (key in old_state) if (!(key in seen)) changed++
			printf "%d domains changed; %d current, %d cached, %d empty, %d expired, %d failed; %d addresses", \
				changed + 0, state["current"] + 0, state["cached"] + 0, state["empty"] + 0, \
				state["expired"] + 0, state["failed"] + 0, entries + 0
		}
	' "$rulestatusmanifest" 2>/dev/null
}

Dispatch_Rules() {
	case "$2" in
		status)
			[ "$#" -eq "2" ] || { echo "[*] Usage: firewall rules status"; echo; return 2; }
			Print_Rule_Status
			echo
			nolog="2"
			nocfg="1"
		;;
		remove)
			if [ "$#" -ne "3" ] || ! printf '%s\n' "$3" | grep -qE '^r[0-9]+(-[0-9]+)?$'; then
				echo "[*] Usage: firewall rules remove <rule-id>"; echo; return 2
			fi
			Check_Lock "$@"
			Require_Running
			Require_Rule_Registry
			Purge_Logs
			Remove_Registered_Rule_ID "$3"
			ruleremovestatus="$?"
			if [ "$ruleremovestatus" = "2" ]; then echo "[*] Rule ID Not Found"; echo; return 2; fi
			[ "$ruleremovestatus" = "0" ] || { echo "[*] Failed To Remove Rule - Existing Rules Retained"; echo; return 1; }
			Queue_Action success rules remove "$ruleremovetarget" "$ruleremovetype" "$ruleremovevalue" "${ruleremovecomment#C}" \
				|| Log error -s "Failed To Queue Rule Action"
			return 0
		;;
		refresh)
			[ "$#" -eq "2" ] || { echo "[*] Usage: firewall rules refresh"; echo; return 2; }
			Check_Lock "$@"
			Require_Running
			Require_Rule_Registry
			Require_Time
			Purge_Logs
			echo "[i] Refreshing Domain Rules"
			if ! Update_Domain_Rules "$skynetrules" refresh; then
				Queue_Action failed rules refresh all domain "registered domains" "Resolution failed" || true
				echo "[*] Failed To Refresh Domain Rules - Existing Rules Retained"
				echo
				return 1
			fi
			rulerefreshasn="1"
			asnrefreshchanged="0"
			if [ "${SKYNET_ACTION_ORIGIN:-}" = "cron" ] && [ "$(date +%H)" != "00" ]; then
				rulerefreshasn="0"
			fi
			if [ "$rulerefreshasn" = "1" ]; then
				echo "[i] Refreshing ASN Rules"
				if ! Refresh_Registered_ASN_Rules; then
					Rollback_Domain_Rule_Update || Log error -s "Failed To Restore Rule Refresh State"
					Queue_Action failed rules refresh all asn "registered ASNs" "Source or apply failure" || true
					echo "[*] Failed To Refresh ASN Rules - Complete Previous Rule State Restored"
					echo
					return 1
				fi
			fi
			if awk -F '\t' '($1 == "D1" || $1 == "D2") && $4 != "current" {found = 1} END {exit !found}' "$rulestatusmanifest" 2>/dev/null; then
				rulerefreshresult="degraded"
				echo "[!] Domain Rules Refreshed With Degraded Sources"
			else
				rulerefreshresult="success"
			fi
			rulerefreshentries="$(awk -F '\t' '$1 == "R2" && ($4 == "domain" || $4 == "asn") && $7 == "enabled" {count++} END {print count + 0}' "$skynetrules") logical rules"
			rulerefreshdetail="$(Build_Domain_Rule_Action_Detail)"
			if [ "$asnrefreshchanged" = "1" ]; then rulerefreshdetail="$rulerefreshdetail; ASN ranges updated"; fi
			[ "$rulerefreshasn" = "1" ] || rulerefreshdetail="$rulerefreshdetail; ASN refresh not due"
			rulerefreshduration="$(($(Uptime_Seconds) - stime))"
			rulerefreshdetail="$rulerefreshdetail; ${rulerefreshduration}s"
			# Check times change on every refresh; journal only changed content or
			# health, while keeping degraded and failed results visible.
			if [ "${rulerefreshdetail%% *}" -gt "0" ] || [ "$asnrefreshchanged" = "1" ] || [ "$rulerefreshresult" != "success" ]; then
				Queue_Action "$rulerefreshresult" rules refresh all logical "$rulerefreshentries" "$rulerefreshdetail" || Log error -s "Failed To Queue Rule Refresh"
			fi
			[ "${SKYNET_ACTION_ORIGIN:-}" = "webui" ] || Generate_WebUI_Settings || Log error -s "Failed To Refresh WebUI Rule Data"
			return 0
		;;
		*) Command_Not_Recognized ;;
	esac
}

Dispatch_Unban() {
	Check_Lock "$@"
	Require_Running
	Require_Rule_Registry
	Purge_Logs
	case "$2" in
		ip)
			unbanlist="$(Normalize_Arguments_From 3 "$@")" || { echo "[*] IP Field Can't Be Empty"; echo; exit 2; }
			for unbanentry in $unbanlist; do
				if ! printf '%s\n' "$unbanentry" | Is_IP; then echo "[*] $unbanentry Is Not A Valid IP"; echo; exit 2; fi
			done
			echo "[i] Unbanning $unbanlist"
			Apply_Registered_Manual_Rules remove ban ip "" "$unbanlist"
			unbanstatus="$?"
			if [ "$unbanstatus" = "2" ]; then echo "[*] Manual IP Rule Not Found"; echo; exit 2; fi
			[ "$unbanstatus" = "0" ] || { echo; exit 1; }
			Queue_Action success rules remove ban ip "$unbanlist" "" || Log error -s "Failed To Queue Rule Action"
			for unbanentry in $unbanlist; do
				sed -i "\\~BLOCKED.*=$unbanentry ~d" "$skynetlog"
			done
			for unbanentry in $unbanlist; do
				if Ban_Value_Is_Covered ip "$unbanentry"; then echo "[!] $unbanentry Remains Covered By Another Rule"; fi
			done
			return 0
		;;
		range)
			unbanlist="$(Normalize_Arguments_From 3 "$@")" || { echo "[*] Range Field Can't Be Empty"; echo; exit 2; }
			for unbanentry in $unbanlist; do
				if ! printf '%s\n' "$unbanentry" | Is_Range; then echo "[*] $unbanentry Is Not A Valid Range"; echo; exit 2; fi
			done
			echo "[i] Unbanning $unbanlist"
			Apply_Registered_Manual_Rules remove ban range "" "$unbanlist"
			unbanstatus="$?"
			if [ "$unbanstatus" = "2" ]; then echo "[*] Manual Range Rule Not Found"; echo; exit 2; fi
			[ "$unbanstatus" = "0" ] || { echo; exit 1; }
			Queue_Action success rules remove ban range "$unbanlist" "" || Log error -s "Failed To Queue Rule Action"
			for unbanentry in $unbanlist; do
				sed -i "\\~BLOCKED.*=$unbanentry ~d" "$skynetlog"
			done
			for unbanentry in $unbanlist; do
				if Ban_Value_Is_Covered range "$unbanentry"; then echo "[!] $unbanentry Remains Covered By Another Rule"; fi
			done
			return 0
		;;
		domain)
			shift 2
			[ "$#" -gt "0" ] || { echo "[*] Domain Field Can't Be Empty"; echo; exit 2; }
			domainlist=""
			for domaininput in "$@"; do
				domain="$(Normalize_Domain "$domaininput")" || { echo "[*] $domaininput Is Not A Valid Domain"; echo; exit 2; }
				case " $domainlist " in *" $domain "*) continue ;; esac
				domainlist="${domainlist}${domainlist:+ }$domain"
			done
			echo "[i] Removing $domainlist From Blacklist"
			Stage_Rule_Registry remove ban domain "$domainlist" ""
			domainstatus="$?"
			if [ "$domainstatus" = "2" ]; then echo "[*] Domain Rule Not Found"; echo; exit 2; fi
			[ "$domainstatus" = "0" ] || { echo "[*] Failed To Stage Domain Rules"; echo; exit 1; }
			Update_Domain_Rules "$rulestagefile" cached || { echo "[*] Failed To Update Domain Rules - Existing Rules Retained"; echo; exit 1; }
			Queue_Action success rules remove ban domain "$domainlist" "" || Log error -s "Failed To Queue Rule Action"
			return 0
		;;
		comment)
			[ "$#" -eq "3" ] && [ -n "$3" ] || { echo "[*] Syntax: firewall unban comment \"text\""; echo; exit 2; }
			echo "[i] Removing Bans With Comment Containing ($3)"
			unbancommentlist="$(awk -F '\t' -v text="$3" '$1 == "R2" && $3 == "ban" && ($4 == "ip" || $4 == "range") && index(substr($6, 2), text) {print $5}' "$skynetrules" | awk 'NF {output = output (output == "" ? "" : " ") $1} END {print output}')"
			[ -n "$unbancommentlist" ] || { echo "[*] No Manual Ban Comments Matched"; echo; exit 2; }
			Apply_Registered_Address_Rules remove ban "$unbancommentlist" "" || { echo; exit 1; }
			Queue_Action success rules remove ban comment "$unbancommentlist" "$3" || Log error -s "Failed To Queue Rule Action"
			return 0
		;;
		country)
			countryclearoldlist="$countrylist"
			countryclearsnapshot="$TMP_DIR/country-clear-old.$$"
			ipset save Skynet-BlockedRanges > "$countryclearsnapshot" 2>/dev/null \
				|| { echo "[*] Failed To Snapshot Existing Country Bans"; echo; exit 1; }
			echo "[i] Removing Previous Country Bans (${countrylist})"
			Remove_IPSet_Entries Skynet-BlockedRanges "Country: " || { rm -f "$countryclearsnapshot"; echo; exit 1; }
			countrylist=""
			Update_Block_Counts
			echo "[i] Saving Changes"
			countrycachedir="${skynetloc}/lists/countries"
			countrycachemanifest="${countrycachedir}/.manifest"
			if Save_IPSets && Write_Config && Publish_Country_Cache ""; then
				nocfg="1"
				Queue_Action success countries remove blocked country "$countryclearoldlist" || Log error -s "Failed To Queue Country Action"
				rm -f "$countryclearsnapshot"
				return 0
			fi
			if ! Restore_IPSet_Snapshot Skynet-BlockedRanges "$countryclearsnapshot"; then
				Log error -s "Failed To Restore Country Bans After Save Failure"
			fi
			countrylist="$countryclearoldlist"
			Update_Block_Counts
			if ! Save_IPSets || ! Write_Config; then
				Log error -s "Failed To Restore Country Configuration"
			fi
			nocfg="1"
			rm -f "$countryclearsnapshot"
			echo "[*] Failed To Save Country Changes - Previous Bans Restored"
			echo
			exit 1
		;;
		asn)
			shift 2
			asnlist="$(Normalize_ASN_Arguments "$@")" || { echo "[*] ASN Values Must Use AS Followed By Up To Six Digits"; echo; exit 2; }
			echo "[i] Removing Previous $asnlist Bans"
			Apply_Registered_ASN_Rules remove ban "$asnlist"
			asnstatus="$?"
			if [ "$asnstatus" = "2" ]; then echo "[*] ASN Rule Not Found"; echo; exit 2; fi
			[ "$asnstatus" = "0" ] || { echo; exit 1; }
			Queue_Action success rules remove ban asn "$asnlist" "" || Log error -s "Failed To Queue Rule Action"
			return 0
		;;
		malware)
			echo "[i] Removing Previous Malware Blacklist Entries"
			Remove_Automatic_Bans comment "BanMalware" \
				|| { echo "[*] Failed To Remove Malware Entries - Existing Bans Retained"; echo; exit 1; }
			Queue_Action success feeds remove malware blacklist "all malware entries" "" || Log error -s "Failed To Queue Malware Action"
			return 0
		;;
		nomanual)
			echo "[i] Removing All Non-Manual Bans"
			Remove_Automatic_Bans all "" \
				|| { echo "[*] Failed To Remove Non-Manual Bans - Existing Bans Retained"; echo; exit 1; }
			sed -i '\~Manual ~!d' "$skynetlog"
			iptables -Z PREROUTING -t raw
			Queue_Action success rules remove ban automatic "non-manual bans" "" || Log error -s "Failed To Queue Rule Action"
			nocfg="1"
			return 0
		;;
		all)
			echo "[i] Removing All $((blacklist1count + blacklist2count)) Entries From Blacklist"
			Clear_All_Bans || { echo "[*] Failed To Clear Blacklist - Existing Rules Retained"; echo; exit 1; }
			iptables -Z PREROUTING -t raw
			true > "$skynetlog"
			Queue_Action success rules remove ban all "all blacklist entries" "" || Log error -s "Failed To Queue Rule Action"
			return 0
		;;
		*)
			Command_Not_Recognized
		;;
		esac
}

Normalize_Country_Zone() {
	# Country files must contain complete public IPv4 CIDRs. Rejecting the whole
	# payload prevents a truncated or changed provider response being applied.
	awk '
		function usable(value, count, prefix, i, first, second, third) {
			count = split(value, part, "/")
			if (count != 2 || part[2] !~ /^[0-9]+$/ || part[2] < 0 || part[2] > 32) return 0
			if (split(part[1], octet, ".") != 4) return 0
			for (i = 1; i <= 4; i++)
				if (octet[i] !~ /^[0-9]+$/ || octet[i] < 0 || octet[i] > 255) return 0
			first = octet[1] + 0
			second = octet[2] + 0
			third = octet[3] + 0
			if (first == 0 || first == 10 || first == 127 || first >= 224) return 0
			if (first == 100 && second >= 64 && second <= 127) return 0
			if (first == 169 && second == 254) return 0
			if (first == 172 && second >= 16 && second <= 31) return 0
			if (first == 192 && second == 168) return 0
			if (first == 192 && second == 0 && (third == 0 || third == 2)) return 0
			if (first == 198 && (second == 18 || second == 19)) return 0
			if (first == 198 && second == 51 && third == 100) return 0
			if (first == 203 && second == 0 && third == 113) return 0
			return 1
		}
		{
			sub(/\r$/, "")
			if ($0 == "" || $0 ~ /^#/) next
			if (NF != 1 || !usable($1)) invalid = 1
			else if (!seen[$1]++) { print $1; entries++ }
		}
		END { if (invalid || entries == 0) exit 1 }
	' "$1" > "$2"
}

Fetch_Country_Zone() {
	countryfetchcode="$1"
	countryfetchurl="https://www.ipdeny.com/ipblocks/data/aggregated/${countryfetchcode}-aggregated.zone"
	countryfetchcache="${countrycachedir}/${countryfetchcode}.zone"
	countryfetchraw="$TMP_DIR/country.${countryfetchcode}.raw"
	countryfetchzone="$TMP_DIR/country.${countryfetchcode}.zone"
	countryfetchresult="$TMP_DIR/country.${countryfetchcode}.result"
	countryfetchvalidation="$TMP_DIR/country.${countryfetchcode}.valid"
	countryfetchnow="$(date +%s)"
	countryfetchvalid="0"
	countryfetcholdsuccess="0"
	countryfetcholdhash=""
	countryfetcholdchanged="0"
	rm -f "$countryfetchraw" "$countryfetchzone" "$countryfetchresult" "$countryfetchvalidation"
	if [ -s "$countryfetchcache" ] && [ -s "$countrycachemanifest" ] \
		&& awk -F '\t' -v code="$countryfetchcode" -v url="$countryfetchurl" \
			'$1 == code && $2 == url {found=1} END {exit !found}' "$countrycachemanifest" \
		&& Normalize_Country_Zone "$countryfetchcache" "$countryfetchvalidation"; then
		countryfetchold="$(awk -F '\t' -v code="$countryfetchcode" -v url="$countryfetchurl" \
			'$1 == code && $2 == url {print $6 "~" $7 "~" $8; exit}' "$countrycachemanifest")"
		IFS='~' read -r countryfetcholdsuccess countryfetcholdhash countryfetcholdchanged <<EOF
$countryfetchold
EOF
		countryfetchentries="$(wc -l < "$countryfetchvalidation")"
		countryfetchhash="$(sha256sum "$countryfetchvalidation" 2>/dev/null | awk '{print $1}')"
		case "$countryfetcholdsuccess" in ""|*[!0-9]*) countryfetcholdsuccess="$(date -r "$countryfetchcache" +%s 2>/dev/null)" ;; esac
		case "$countryfetcholdsuccess" in ""|*[!0-9]*) countryfetcholdsuccess="$countryfetchnow" ;; esac
		case "$countryfetcholdchanged" in ""|*[!0-9]*) countryfetcholdchanged="$countryfetcholdsuccess" ;; esac
		countryfetchvalid="1"
		countryfetchhttp="$(Curl_Fetch -z "$countryfetchcache" -o "$countryfetchraw" -w '%{http_code}' "$countryfetchurl")"
		countryfetchstatus="$?"
	else
		countryfetchhttp="$(Curl_Fetch -o "$countryfetchraw" -w '%{http_code}' "$countryfetchurl")"
		countryfetchstatus="$?"
	fi
	if [ "$countryfetchstatus" = "0" ] && [ "$countryfetchhttp" = "304" ] && [ "$countryfetchvalid" = "1" ]; then
		printf 'current\t%s\t%s\t%s\t%s\t%s\tok\n' "$countryfetchentries" "$countryfetchnow" "$countryfetchnow" "$countryfetchhash" "$countryfetcholdchanged" > "$countryfetchresult"
	elif [ "$countryfetchstatus" = "0" ] && [ -s "$countryfetchraw" ]; then
		if Normalize_Country_Zone "$countryfetchraw" "$countryfetchzone"; then
			countryfetchentries="$(wc -l < "$countryfetchzone")"
			countryfetchhash="$(sha256sum "$countryfetchzone" 2>/dev/null | awk '{print $1}')"
			if [ -n "$countryfetcholdhash" ] && [ "$countryfetcholdhash" = "$countryfetchhash" ]; then
				countryfetchchanged="$countryfetcholdchanged"
			else
				countryfetchchanged="$countryfetchnow"
			fi
			printf 'current\t%s\t%s\t%s\t%s\t%s\tok\n' "$countryfetchentries" "$countryfetchnow" "$countryfetchnow" "$countryfetchhash" "$countryfetchchanged" > "$countryfetchresult"
		elif [ "$countryfetchvalid" = "1" ]; then
			printf 'cached\t%s\t%s\t%s\t%s\t%s\tinvalid\n' "$countryfetchentries" "$countryfetchnow" "$countryfetcholdsuccess" "$countryfetchhash" "$countryfetcholdchanged" > "$countryfetchresult"
		else
			printf 'failed\t0\t%s\t0\t-\t0\tinvalid\n' "$countryfetchnow" > "$countryfetchresult"
		fi
	elif [ "$countryfetchvalid" = "1" ]; then
		printf 'cached\t%s\t%s\t%s\t%s\t%s\tdownload\n' "$countryfetchentries" "$countryfetchnow" "$countryfetcholdsuccess" "$countryfetchhash" "$countryfetcholdchanged" > "$countryfetchresult"
	else
		printf 'failed\t0\t%s\t0\t-\t0\tdownload\n' "$countryfetchnow" > "$countryfetchresult"
	fi
	rm -f "$countryfetchraw" "$countryfetchvalidation"
}

Build_Country_Update() {
	countryrequested="$1"
	countrycachedir="${skynetloc}/lists/countries"
	countrycachemanifest="${countrycachedir}/.manifest"
	countrytmp="$TMP_DIR/country.restore.$$"
	countrydegraded=""
	mkdir -p "$countrycachedir" || return 1
	true > "$countrytmp" || return 1
	Start_Background_Jobs
	for country in $countryrequested; do
		Fetch_Country_Zone "$country" &
		Wait_Background_Job_Slot 4
	done
	Wait_Background_Jobs
	for country in $countryrequested; do
		countryresultfile="$TMP_DIR/country.${country}.result"
		countryresult="failed"
		countryresultreason="download"
		[ -s "$countryresultfile" ] && IFS="$(printf '\t')" read -r countryresult _countryentries _countrychecked _countrysuccess _countryhash _countrychanged countryresultreason < "$countryresultfile"
		case "$countryresult" in
			current)
				if [ -s "$TMP_DIR/country.${country}.zone" ]; then countrysource="$TMP_DIR/country.${country}.zone"; else countrysource="${countrycachedir}/${country}.zone"; fi
			;;
			cached)
				countrysource="${countrycachedir}/${country}.zone"
				countrydegraded="${countrydegraded}${countrydegraded:+ }${country}"
				echo "[!] Using Cached Country List (${country})"
			;;
			*)
				if [ "$countryresultreason" = "invalid" ]; then echo "[*] No Valid IPv4 Ranges Found For (${country})"; else echo "[*] Failed To Download Country List (${country})"; fi
				return 1
			;;
		esac
		awk -v code="$country" '{printf "add Skynet-BlockedRanges %s comment \"Country: %s\"\n", $1, code}' "$countrysource" >> "$countrytmp" || return 1
	done
	[ -s "$countrytmp" ]
}

Publish_Country_Cache() {
	countrypublishlist="$1"
	countrycachedir="${countrycachedir:-${skynetloc}/lists/countries}"
	countrycachemanifest="${countrycachemanifest:-${countrycachedir}/.manifest}"
	countrymanifesttmp="${countrycachemanifest}.tmp.$$"
	mkdir -p "$countrycachedir" || return 1
	true > "$countrymanifesttmp" || return 1
	for country in $countrypublishlist; do
		countryresult="failed"
		countryentries="0"
		countrychecked="0"
		countrysuccess="0"
		countryhash="-"
		countrychanged="0"
		[ -s "$TMP_DIR/country.${country}.result" ] && IFS="$(printf '\t')" read -r countryresult countryentries countrychecked countrysuccess countryhash countrychanged _countryreason < "$TMP_DIR/country.${country}.result"
		if [ -s "$TMP_DIR/country.${country}.zone" ]; then
			mv -f "$TMP_DIR/country.${country}.zone" "${countrycachedir}/${country}.zone" \
				|| { rm -f "$countrymanifesttmp"; return 1; }
		fi
		[ -s "${countrycachedir}/${country}.zone" ] || { rm -f "$countrymanifesttmp"; return 1; }
		printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$country" "https://www.ipdeny.com/ipblocks/data/aggregated/${country}-aggregated.zone" "$countryresult" "$countryentries" "$countrychecked" "$countrysuccess" "$countryhash" "$countrychanged" >> "$countrymanifesttmp" \
			|| { rm -f "$countrymanifesttmp"; return 1; }
	done
	# Publish ownership before deleting obsolete files. If the atomic manifest move
	# fails, the previous mapping remains valid and any new file is merely orphaned.
	if ! mv -f "$countrymanifesttmp" "$countrycachemanifest"; then
		rm -f "$countrymanifesttmp"
		return 1
	fi
	for countrycachefile in "$countrycachedir"/*.zone; do
		[ -f "$countrycachefile" ] || continue
		countrycachecode="$(basename "$countrycachefile" .zone)"
		case " $countrypublishlist " in
			*" $countrycachecode "*) ;;
			*) rm -f "$countrycachefile" ;;
		esac
		done
	rm -f "$TMP_DIR"/country.*.raw "$TMP_DIR"/country.*.zone "$TMP_DIR"/country.*.result
}

Publish_Country_Refresh_Failure() {
	# A failed refresh cannot change live bans, but its health row must record that
	# the selected source no longer has a usable cache.
	countryfailedlist="$1"
	countrycachedir="${skynetloc}/lists/countries"
	countrycachemanifest="${countrycachedir}/.manifest"
	countryfailedtmp="${countrycachemanifest}.tmp.$$"
	mkdir -p "$countrycachedir" || return 1
	true > "$countryfailedtmp" || return 1
	for country in $countryfailedlist; do
		countryfailedurl="https://www.ipdeny.com/ipblocks/data/aggregated/${country}-aggregated.zone"
		countryoldrow="$(awk -F '\t' -v code="$country" '$1 == code {print; exit}' "$countrycachemanifest" 2>/dev/null)"
		countryoldsuccess="0"
		countryoldhash="-"
		countryoldchanged="0"
		if [ -n "$countryoldrow" ]; then
			IFS="$(printf '\t')" read -r _countryoldcode _countryoldurl _countryoldstate _countryoldentries _countryoldchecked countryoldsuccess countryoldhash countryoldchanged <<EOF
$countryoldrow
EOF
		fi
		countryresultfile="$TMP_DIR/country.${country}.result"
		countryresultstate=""
		if [ -s "$countryresultfile" ]; then
			IFS="$(printf '\t')" read -r countryresultstate _countryresultentries countryresultchecked _countryresultsuccess _countryresulthash _countryresultchanged _countryresultreason < "$countryresultfile"
		fi
		if [ "$countryresultstate" = "failed" ]; then
			printf '%s\t%s\tfailed\t0\t%s\t%s\t%s\t%s\n' "$country" "$countryfailedurl" "${countryresultchecked:-0}" "$countryoldsuccess" "$countryoldhash" "$countryoldchanged" >> "$countryfailedtmp" || return 1
		elif [ -n "$countryoldrow" ]; then
			printf '%s\n' "$countryoldrow" >> "$countryfailedtmp" || return 1
		else
			printf '%s\t%s\tfailed\t0\t0\t0\t-\t0\n' "$country" "$countryfailedurl" >> "$countryfailedtmp" || return 1
		fi
	done
	mv -f "$countryfailedtmp" "$countrycachemanifest"
}

Print_Country_Status() {
	countrystatusmanifest="${skynetloc}/lists/countries/.manifest"
	echo "[i] Selected Countries: ${countrylist:-None}"
	if [ ! -s "$countrystatusmanifest" ] || ! awk -F '\t' 'NF >= 8 { found = 1 } END { exit !found }' "$countrystatusmanifest"; then
		echo "[i] Country source details will be available after the next refresh"
		return 0
	fi
	echo
	printf '%-8s | %-10s | %-10s | %-20s | %s\n' "Country" "Ranges" "State" "Last Success" "Source"
	printf '%-8s-+-%-10s-+-%-10s-+-%-20s-+-%s\n' "--------" "----------" "----------" "--------------------" "------"
	while IFS="$(printf '\t')" read -r countrycode countryurl countrystate countryentries _countrychecked countrysuccess _countryhash _countrychanged; do
		case "$countrystate" in current|cached|failed) ;; *) continue ;; esac
		case "$countryentries" in ""|*[!0-9]*) countryentries="0" ;; esac
		countrylast="$(Format_Threat_Feed_Time "$countrysuccess")"
		printf '%-8s | %-10s | %-10s | %-20s | %s\n' "$(printf '%s' "$countrycode" | awk '{print toupper($0)}')" "$countryentries" "$countrystate" "$countrylast" "$countryurl"
	done < "$countrystatusmanifest"
}

Dispatch_Ban() {
	if [ "$2:$3" = "country:status" ]; then
		[ "$#" -eq "3" ] || { echo "[*] Usage: firewall ban country status"; echo; return 2; }
		Print_Country_Status
		echo
		nolog="2"
		nocfg="1"
		return 0
	fi
	Check_Lock "$@"
	Require_Running
	Require_Rule_Registry
	Require_Time
	Purge_Logs
	case "$2" in
		ip)
			shift 2
			Parse_Ban_Arguments ip 242 "$@" || { echo "[*] $parsederror"; echo; exit 2; }
			Require_Time
			banlist="$parsedentries"
			desc="$parsedcomment"
			echo "[i] Banning $banlist"
			Apply_Registered_Manual_Rules add ban ip "$desc" "$banlist" "$parsedexpires" || { echo; exit 1; }
			banresult="success"
			if [ "$parsedexpires" -gt "0" ] && [ "$rulestagepermanent" -gt "0" ]; then
				banresult="degraded"
				echo "[!] Existing Permanent Rule Retained"
			fi
			for banentry in $banlist; do IP_Is_Whitelisted "$banentry" && banresult="degraded"; done
			[ "$banresult" = "success" ] || echo "[!] Whitelist Precedence Prevents One Or More Bans From Being Enforced"
			if [ "$parsedexpires" -gt "0" ]; then bandetail="${desc}${desc:+; }Expires $(Format_Threat_Feed_Time "$parsedexpires")"; else bandetail="$desc"; fi
			if [ "$rulestagechanged" -gt "0" ]; then
				Queue_Action "$banresult" rules add ban ip "$banlist" "$bandetail" || Log error -s "Failed To Queue Rule Action"
			fi
			return 0
		;;
		range)
			shift 2
			Parse_Ban_Arguments range 242 "$@" || { echo "[*] $parsederror"; echo; exit 2; }
			Require_Time
			banlist="$parsedentries"
			desc="$parsedcomment"
			echo "[i] Banning $banlist"
			Apply_Registered_Manual_Rules add ban range "$desc" "$banlist" "$parsedexpires" || { echo; exit 1; }
			banresult="success"
			if [ "$parsedexpires" -gt "0" ] && [ "$rulestagepermanent" -gt "0" ]; then
				banresult="degraded"
				echo "[!] Existing Permanent Rule Retained"
			fi
			for banentry in $banlist; do IP_Is_Whitelisted "${banentry%%/*}" && banresult="degraded"; done
			[ "$banresult" = "success" ] || echo "[!] Whitelist Precedence Prevents One Or More Bans From Being Enforced"
			if [ "$parsedexpires" -gt "0" ]; then bandetail="${desc}${desc:+; }Expires $(Format_Threat_Feed_Time "$parsedexpires")"; else bandetail="$desc"; fi
			if [ "$rulestagechanged" -gt "0" ]; then
				Queue_Action "$banresult" rules add ban range "$banlist" "$bandetail" || Log error -s "Failed To Queue Rule Action"
			fi
			return 0
		;;
		domain)
			Require_Time
			Require_Connection
			shift 2
			[ "$#" -gt "0" ] || { echo "[*] Domain Field Can't Be Empty"; echo; exit 2; }
			domainbatchlist=""
			for domaininput in "$@"; do
				domain="$(Normalize_Domain "$domaininput")" || { echo "[*] $domaininput Is Not A Valid Domain"; echo; exit 2; }
				case " $domainbatchlist " in *" $domain "*) continue ;; esac
				domainbatchlist="${domainbatchlist}${domainbatchlist:+ }$domain"
			done
			echo "[i] Adding $domainbatchlist To Blacklist"
			Stage_Rule_Registry add ban domain "$domainbatchlist" "" || { echo "[*] Failed To Stage Domain Rules"; echo; exit 1; }
			Update_Domain_Rules "$rulestagefile" required || { echo "[*] Unable To Resolve Domain Rules - Existing Rules Retained"; echo; exit 1; }
			Queue_Action success rules add ban domain "$domainbatchlist" "" || Log error -s "Failed To Queue Rule Action"
			return 0
		;;
		country)
			# Validate and de-duplicate the complete request before downloading or
			# changing any existing country bans.
			if [ "$3" = "refresh" ]; then
				[ "$#" -eq "3" ] || { echo "[*] Usage: firewall ban country refresh"; echo; exit 2; }
				[ -n "$countrylist" ] || { echo "[*] No Countries Are Currently Selected"; echo; exit 2; }
				country_raw="$countrylist"
			else
				country_raw="$(Normalize_Arguments_From 3 "$@")" || { echo "[*] Country Field Can't Be Empty"; echo; exit 2; }
			fi
			if ! countrylinklist="$(printf '%s\n' "$country_raw" | awk '
				{
					for (i = 1; i <= NF; i++) {
						code = tolower($i)
						if (code !~ /^[a-z][a-z]$/) exit 2
						if (!seen[code]++) {
							if (output != "") output = output " "
							output = output code
						}
					}
				}
				END { if (output != "") print output }')"; then
				echo "[✘] Country Codes Must Contain Two Letters"
				echo
				exit 2
			fi
			for countrycode in $countrylinklist; do
				if ! Is_Country_Code "$countrycode"; then
					echo "[✘] $countrycode Is Not A Supported Country Code"
					echo
					exit 2
				fi
			done

			countryoldlist="$countrylist"
			countryactionadded=""
			for countrycode in $countrylinklist; do
				case " $countryoldlist " in
					*" $countrycode "*) ;;
					*) countryactionadded="${countryactionadded}${countryactionadded:+ }$countrycode" ;;
				esac
			done
			countryactionremoved=""
			for countrycode in $countryoldlist; do
				case " $countrylinklist " in
					*" $countrycode "*) ;;
					*) countryactionremoved="${countryactionremoved}${countryactionremoved:+ }$countrycode" ;;
				esac
			done
			echo "[i] Banning Known IP Ranges For (${countrylinklist})"
			echo "[i] Downloading Lists, Filtering IPv4 Ranges & Applying Blacklists"
			countryrangesnapshot="$TMP_DIR/country-ranges-old.$$"
			ipset save Skynet-BlockedRanges > "$countryrangesnapshot" 2>/dev/null || { echo "[*] Failed To Snapshot Existing Country Bans"; echo; exit 1; }
			if ! Build_Country_Update "$countrylinklist"; then
				if [ "$3" = "refresh" ]; then
					Publish_Country_Refresh_Failure "$countrylist" || Log error -s "Failed To Publish Country Source Health"
				fi
				rm -f "$countryrangesnapshot" "$countrytmp" "$TMP_DIR"/country.*.raw "$TMP_DIR"/country.*.zone "$TMP_DIR"/country.*.result
				exit 1
			fi
			# A source refresh is an activity only when its validated content hash
			# changes. Newly selected countries are reported by the add event below.
			countryactionrefreshed=""
			for countrycode in $countrylinklist; do
				case " $countryactionadded " in *" $countrycode "*) continue ;; esac
				countryactionhash=""
				if [ -s "$TMP_DIR/country.${countrycode}.result" ]; then
					IFS="$(printf '\t')" read -r _countryactionstate _countryactionentries _countryactionchecked _countryactionsuccess countryactionhash _countryactionchanged _countryactionreason < "$TMP_DIR/country.${countrycode}.result"
				fi
				countryactionoldhash="$(awk -F '\t' -v code="$countrycode" '$1 == code {print $7; exit}' "$countrycachemanifest" 2>/dev/null)"
				if [ -n "$countryactionhash" ] && [ "$countryactionhash" != "-" ] \
					&& [ "$countryactionhash" != "$countryactionoldhash" ]; then
					countryactionrefreshed="${countryactionrefreshed}${countryactionrefreshed:+ }${countrycode}"
				fi
			done

			if ! Replace_Range_IPSet_Entries "Country: " "$countrytmp"; then
				rm -f "$countryrangesnapshot" "$countrytmp"
				echo "[*] Failed To Apply Country Bans - Previous Bans Restored"
				exit 1
			fi

			countrylist="$countrylinklist"
			Update_Block_Counts
			echo "[i] Saving Changes"
			if ! Save_IPSets || ! Write_Config; then
				Restore_IPSet_Snapshot Skynet-BlockedRanges "$countryrangesnapshot" \
					|| Log error -s "Failed To Restore Country Bans After Save Failure"
				countrylist="$countryoldlist"
				Update_Block_Counts
				if ! Save_IPSets || ! Write_Config; then
					Log error -s "Failed To Restore Country Configuration"
				fi
				nocfg="1"
				rm -f "$countryrangesnapshot" "$countrytmp"
				echo "[*] Failed To Save Country Changes - Previous Bans Restored"
				echo
				exit 1
			fi
			if ! Publish_Country_Cache "$countrylinklist"; then
				Restore_IPSet_Snapshot Skynet-BlockedRanges "$countryrangesnapshot" \
					|| Log error -s "Failed To Restore Country Bans After Cache Publish Failure"
				countrylist="$countryoldlist"
				Update_Block_Counts
				if ! Save_IPSets || ! Write_Config; then
					Log error -s "Failed To Restore Country Configuration"
				fi
				nocfg="1"
				rm -f "$countryrangesnapshot" "$countrytmp"
				echo "[*] Failed To Publish Country Source Status - Previous Bans Restored"
				echo
				exit 1
			fi
			if [ -n "$countrydegraded" ]; then
				echo "[!] Country Blocking Updated Using Cached Data (${countrydegraded})"
				countryactionresult="degraded"
			else
				countryactionresult="success"
			fi
			if [ -n "$countryactionadded" ] || [ -n "$countryactionremoved" ]; then
				if [ -n "$countryactionremoved" ]; then
					Queue_Action "$countryactionresult" countries remove blocked country "$countryactionremoved" "${countrydegraded:-}" || Log error -s "Failed To Queue Removed Countries"
				fi
				if [ -n "$countryactionadded" ]; then
					Queue_Action "$countryactionresult" countries add blocked country "$countryactionadded" "${countrydegraded:-}" || Log error -s "Failed To Queue Added Countries"
				fi
			elif [ -n "$countryactionrefreshed" ]; then
				Queue_Action "$countryactionresult" countries refresh blocked country "$countryactionrefreshed" "${countrydegraded:-}" || Log error -s "Failed To Queue Country Action"
			fi
			nocfg="1"
			rm -f "$countryrangesnapshot" "$countrytmp"
			unset "countryactionadded" "countryactionremoved" "countryactionrefreshed" "countryactionhash" "countryactionoldhash"
			return 0
		;;
		asn)
			Require_Time
			Require_Connection
			shift 2
			asnlist="$(Normalize_ASN_Arguments "$@")" || { echo "[*] ASN Values Must Use AS Followed By Up To Six Digits"; echo; exit 2; }
			echo "[i] Adding $asnlist To Blacklist"
			Apply_Registered_ASN_Rules add ban "$asnlist"
			asnstatus="$?"
			if [ "$asnstatus" != "0" ]; then
				if [ "$asnstatus" = "2" ]; then echo "[*] An ASN Range Is Already Owned By Another Rule"; else echo "[*] Failed To Download Or Apply $asnlist"; fi
				echo
				exit "$asnstatus"
			fi
			Queue_Action success rules add ban asn "$asnlist" "" || Log error -s "Failed To Queue Rule Action"
			return 0
		;;
		*)
			Command_Not_Recognized
		;;
	esac
}

Prepare_Malware_Update() {
	feedselectioncandidate="$TMP_DIR/feed-selection"
	feedselectionbase="$TMP_DIR/feed-selection-base"
	feedselectionchanged="0"
	feedselectionpublished="0"
	feedselectionoperation="$2"
	feedselectionvalues=""
	feedtemplaterequest=""
	case "$feedselectionoperation" in
		""|reset) [ "$#" -le 2 ] || return 2 ;;
		add|remove|include)
			feedselectionvalues="$(Normalize_Arguments_From 3 "$@")" || return 2
		;;
		exclude)
			if [ "$3" != "reset" ] && [ -n "$3" ]; then
				feedselectionvalues="$(Normalize_Arguments_From 3 "$@")" || return 2
			elif [ "$#" -gt 3 ]; then return 2
			fi
		;;
		http://*|https://*) [ "$#" -eq 2 ] || return 2; feedtemplaterequest="$2" ;;
		*) echo "[*] Usage: firewall banmalware [add URL...|remove NAME...|include NAME...|exclude NAME...|reset]"; return 2 ;;
	esac
	case "$feedselectionoperation" in remove|include|exclude)
		for feedselectionname in $feedselectionvalues; do
			case "$feedselectionname" in ""|*[!A-Za-z0-9._-]*) echo "[*] Invalid Malware Source Name"; return 2 ;; esac
		done
	;; esac
	mkdir -p "$skynetloc/lists" || return 1
	Read_Managed_Feed_Selection "$feedselectionbase"
	feedreadstatus="$?"
	case "$feedreadstatus" in
		0|3) ;;
		*)
			if [ "$feedselectionoperation" != "reset" ] && [ -z "$feedtemplaterequest" ]; then
				echo "[*] Invalid Saved Malware Source Selection"
				return 1
			fi
			feedreadstatus="3"
		;;
	esac
	if [ "$feedselectionoperation" = "reset" ]; then
		feedtemplaterequest="https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/filter.list"
		customlisturl=""
		excludelists=""
	elif [ -n "$feedtemplaterequest" ]; then
		customlisturl="$feedtemplaterequest"
		excludelists=""
	elif [ "$feedreadstatus" = "3" ]; then
		feedtemplaterequest="$customlisturl"
		[ -n "$feedtemplaterequest" ] || feedtemplaterequest="https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/filter.list"
	fi
	if [ -n "$feedtemplaterequest" ]; then
		echo "[i] Importing Malware Source Template"
		Curl_Fetch -o "$TMP_DIR/feed-template" "$feedtemplaterequest" || { echo "[*] Failed To Download Malware Source Template"; return 1; }
		if [ "$feedreadstatus" != "0" ]; then : > "$feedselectionbase" || return 1; fi
		if ! Build_Threat_Feed_Manifest "$TMP_DIR/feed-template" "$feedselectioncandidate" "$excludelists" "$feedselectionbase" \
			|| ! Validate_Managed_Feed_Selection "$feedselectioncandidate"; then
			echo "[*] Failed To Process Filter List"
			return 2
		fi
	else
		cp -f "$feedselectionbase" "$feedselectioncandidate" || return 1
	fi
	case "$feedselectionoperation" in
		add)
			awk -F '\t' '{print $2}' "$feedselectioncandidate" > "$TMP_DIR/feed-urls" || return 1
			List_To_Lines "$feedselectionvalues" >> "$TMP_DIR/feed-urls" || return 1
			feedselectionexcluded="$(awk -F '\t' '$3 == "excluded" {printf "%s%s", sep, $1; sep=" "}' "$feedselectioncandidate")" || return 1
			if ! Build_Threat_Feed_Manifest "$TMP_DIR/feed-urls" "$TMP_DIR/feed-added" "$feedselectionexcluded" "$feedselectioncandidate" \
				|| ! mv -f "$TMP_DIR/feed-added" "$feedselectioncandidate"; then
				echo "[*] Invalid Malware Source URL"
				return 2
			fi
		;;
		remove|include|exclude)
			feedinvalid="$(Validate_Threat_Feed_Selection "$feedselectioncandidate" "$feedselectionvalues")" \
				|| { echo "[*] Malware Source Not Found: $feedinvalid"; return 2; }
			awk -F '\t' -v OFS='\t' -v mode="$feedselectionoperation" -v names="$feedselectionvalues" '
				BEGIN {split(names, values, " "); for(i in values) selected[tolower(values[i])] = 1}
				{
					matchname = tolower($1) in selected
					if (mode == "remove" && matchname) next
					if (mode == "include" && matchname) $3 = "enabled"
					if (mode == "exclude") $3 = matchname ? "excluded" : "enabled"
					print
				}' "$feedselectioncandidate" > "$TMP_DIR/feed-edited" \
				&& mv -f "$TMP_DIR/feed-edited" "$feedselectioncandidate" || return 1
		;;
	esac
	Validate_Managed_Feed_Selection "$feedselectioncandidate" \
		|| { echo "[*] At Least One Valid Malware Source Must Remain Enabled"; return 2; }
	# Feed caches are ordinary files. A directory or symlink must never become
	# a download destination, including for an excluded source retained on disk.
	while IFS="$(printf '\t')" read -r feedcachename _feedcacheurl _feedcachestate; do
		feedcachetarget="${skynetloc}/lists/$feedcachename"
		if [ -L "$feedcachetarget" ] || { [ -e "$feedcachetarget" ] && [ ! -f "$feedcachetarget" ]; }; then
			echo "[*] Invalid Malware Cache File ($feedcachename)"
			return 1
		fi
	done < "$feedselectioncandidate"
	excludelists="$(awk -F '\t' '$3 == "excluded" {printf "%s%s", sep, $1; sep=" "}' "$feedselectioncandidate")" || return 1
	if ! cmp -s "$feedselectioncandidate" "$skynetloc/lists/.selection"; then
		# Keep cache bindings and diagnostics consistent if a proposed membership
		# change cannot be committed together with the blacklist.
		for feedprevious in selection manifest sources; do
			if [ -f "$skynetloc/lists/.$feedprevious" ]; then
				cp -f "$skynetloc/lists/.$feedprevious" "$TMP_DIR/feed-previous.$feedprevious" || return 1
			fi
		done
		feednewcachelist="$TMP_DIR/feed-new-cache-names"
		: > "$feednewcachelist" || return 1
		while IFS="$(printf '\t')" read -r feednewcachename _feednewcacheurl _feednewcachestate; do
			if [ ! -e "${skynetloc}/lists/$feednewcachename" ] && [ ! -L "${skynetloc}/lists/$feednewcachename" ]; then
				printf '%s\n' "$feednewcachename" >> "$feednewcachelist" || return 1
			fi
		done < "$feedselectioncandidate"
		feedselectionchanged="1"
		feedselectiontransactionactive="1"
	fi
	[ -z "$excludelists" ] || echo "[i] Excluding Lists: $excludelists"
	return 0
}

Fetch_Threat_Feed_Sources() {
	# Revalidate URL-bound caches with If-Modified-Since. Workers publish small
	# result files because background subshell assignments cannot update BusyBox
	# ash's parent process.
	# Old completion records must not conceal a worker that cannot publish.
	while IFS="$feedtab" read -r list _feedurl selection; do
		[ "$selection" != "enabled" ] || rm -f "$TMP_DIR/feed.${list}.result" || return 1
	done < "$feedmanifest"
	Start_Background_Jobs
	while IFS="$feedtab" read -r list url selection; do
		[ "$selection" = "enabled" ] || continue
		(
			listfile="${skynetloc}/lists/$list"
			listtmp="${skynetloc}/lists/${list}.tmp.$$"
			feedresult="$TMP_DIR/feed.${list}.result"
			cachevalid="0"
			oldsuccess="0"
			rm -f "$listtmp" || exit 1
			if [ -s "$listfile" ] && [ -s "$listmanifest" ] \
				&& awk -v url="$url" -v name="$list" '$1 == url && $2 == name { found=1 } END { exit !found }' "$listmanifest"; then
				cachevalid="1"
				oldsuccess="$(awk -F '\t' -v url="$url" -v name="$list" '$1 == name && $2 == url { print $7; exit }' "${skynetloc}/lists/.sources" 2>/dev/null)"
				case "$oldsuccess" in ""|0|*[!0-9]*) oldsuccess="$(date -r "$listfile" +%s 2>/dev/null || printf 0)" ;; esac
				downloadcode="$(Curl_Fetch -z "$listfile" -o "$listtmp" -w '%{http_code}' "$url")"
				downloadstatus="$?"
			else
				downloadcode="$(Curl_Fetch -o "$listtmp" -w '%{http_code}' "$url")"
				downloadstatus="$?"
			fi

			if [ "$downloadstatus" = "0" ] && [ "$downloadcode" = "304" ] && [ "$cachevalid" = "1" ]; then
				rm -f "$listtmp"
				Write_Threat_Feed_Result "$feedresult" current "$feedchecked" "$feedchecked" || exit 1
				echo "[✔] Up To Date $url"
			elif [ "$downloadstatus" = "0" ] && [ -s "$listtmp" ] && dos2unix "$listtmp"; then
				Write_Threat_Feed_Result "$feedresult" downloaded "$feedchecked" "$feedchecked" || exit 1
				echo "[✔] Downloaded $url"
			elif [ "$cachevalid" = "1" ]; then
				rm -f "$listtmp"
				Write_Threat_Feed_Result "$feedresult" cached "$feedchecked" "$oldsuccess" || exit 1
				echo "[!] Download Failed - Checking Cached $url"
			else
				rm -f "$listtmp"
				Write_Threat_Feed_Result "$feedresult" failed "$feedchecked" 0 || exit 1
				echo "[✘] Download Failed $url"
			fi
		) &
		Wait_Background_Job_Slot 4
	done < "$feedmanifest"
	Wait_Background_Jobs
	while IFS="$feedtab" read -r list _feedurl selection; do
		[ "$selection" != "enabled" ] || Read_Threat_Feed_Result "$TMP_DIR/feed.${list}.result" || return 1
	done < "$feedmanifest"
	return 0
}

Build_Malware_Update() {
Display_Message "[i] Preparing Malware Sources"
filterout="$TMP_DIR/shared-Skynet-whitelist"
feedmanifest="$TMP_DIR/skynet.sources"
feedfilterbackup="$TMP_DIR/shared-Skynet-whitelist.old"
feedfilterpublished="0"
feedfilterhadold="0"
cp -f "$feedselectioncandidate" "$feedmanifest" || return 1
if ! feedinvalid="$(Validate_Threat_Feed_Selection "$feedmanifest" "$excludelists")"; then
	rm -f "$filterout" "$feedmanifest"
	echo "[*] Malware Source Not Found: $feedinvalid"
	echo
	return 2
fi
awk -F '\t' '$3 == "enabled" { print $2 }' "$feedmanifest" > "$filterout" \
	|| { echo "[*] Failed To Build Malware Source List"; return 1; }
if [ ! -s "$filterout" ]; then
	rm -f "$filterout" "$feedmanifest"
	echo "[*] At Least One Malware Source Must Remain Enabled"
	echo
	return 2
fi
if [ -s /jffs/addons/shared-whitelists/shared-Skynet-whitelist ]; then
	cp -f /jffs/addons/shared-whitelists/shared-Skynet-whitelist "$feedfilterbackup" || return 1
	feedfilterhadold="1"
fi
filterpublishtmp="/jffs/addons/shared-whitelists/shared-Skynet-whitelist.tmp.$$"
if ! cp -f "$filterout" "$filterpublishtmp" || ! mv -f "$filterpublishtmp" /jffs/addons/shared-whitelists/shared-Skynet-whitelist; then
	rm -f "$filterpublishtmp"
	echo "[*] Failed To Publish Malware Source List"
	echo
	return 1
fi
feedfilterpublished="1"
Display_Result
Display_Message "[i] Refreshing Whitelists"
Whitelist_Extra
	Whitelist_VPN
	Whitelist_CDN || cdnstatus="1"
	Whitelist_Shared
	Display_Result
case "$cdnresult" in
	current) echo "[i] CDN Whitelist Already Up To Date" ;;
	source) echo "[!] CDN Whitelist Source Unavailable ($cdnfailedsource) - Existing Entries Retained" ;;
	apply) echo "[!] Unable To Apply CDN Whitelist - Existing Entries Retained" ;;
esac
Display_Message "[i] Start Blacklist Consolidation"
echo

if ! mkdir -p "${skynetloc}/lists" || [ ! -w "${skynetloc}/lists" ]; then
	Restore_Threat_Feed_Selection
	echo "[*] Unable To Access Malware List Directory - Stopping Banmalware"
	echo
	return 1
fi

# Phase 1: fetch each source while retaining validated URL-bound caches.
listmanifest="${skynetloc}/lists/.manifest"
feedchecked="$(date +%s)"
feedtab="$(printf '\t')"
Fetch_Threat_Feed_Sources || { Restore_Threat_Feed_Selection; echo "[*] Unable To Complete Malware Source Downloads"; return 1; }

# Phase 2: consolidate staged downloads and retained caches in one parser pass. New
# files replace their cache only after the parser confirms usable entries.
feedfiles="$TMP_DIR/feed-files"
feedcounts="$TMP_DIR/feed-counts"
malwaretmp="$TMP_DIR/malware"
mkdir -p "$feedfiles" || { Restore_Threat_Feed_Selection; echo "[*] Unable To Prepare Malware Sources"; echo; return 1; }
while IFS="$feedtab" read -r list url selection; do
	listfile="${skynetloc}/lists/$list"
	listtmp="${skynetloc}/lists/${list}.tmp.$$"
	feedresult="$TMP_DIR/feed.${list}.result"
	if [ "$selection" = "enabled" ]; then
		Read_Threat_Feed_Result "$feedresult" || { Restore_Threat_Feed_Selection; return 1; }
		case "$feedstate" in
			downloaded) [ -s "$listtmp" ] && ln -s "$listtmp" "$feedfiles/$list" ;;
			current|cached) [ -s "$listfile" ] && ln -s "$listfile" "$feedfiles/$list" ;;
		esac
	elif [ "$selection" = "excluded" ] && [ -s "$listfile" ] && [ -s "$listmanifest" ] \
		&& awk -v url="$url" -v name="$list" '$1 == url && $2 == name { found=1 } END { exit !found }' "$listmanifest"; then
		ln -s "$listfile" "$feedfiles/$list"
	fi
done < "$feedmanifest"
Build_Malware_Restore "$feedmanifest" "$malwaretmp" "$feedcounts"
buildstatus="$?"

# A syntactically downloaded file can still contain no usable public IPv4
# data. Fall back to its matching validated cache, then rebuild once.
feedrebuild="0"
while IFS="$feedtab" read -r list url selection; do
	[ "$selection" = "enabled" ] || continue
	feedresult="$TMP_DIR/feed.${list}.result"
	Read_Threat_Feed_Result "$feedresult" || { Restore_Threat_Feed_Selection; return 1; }
	feedentries="$(awk -F '\t' -v name="$list" '$1 == name { print $2; exit }' "$feedcounts" 2>/dev/null)"
	case "$feedentries" in ""|0|*[!0-9]*)
		listfile="${skynetloc}/lists/$list"
		if [ "$feedstate" = "downloaded" ] && [ -s "$listfile" ] && [ -s "$listmanifest" ] \
			&& awk -v url="$url" -v name="$list" '$1 == url && $2 == name { found=1 } END { exit !found }' "$listmanifest"; then
			oldsuccess="$(awk -F '\t' -v url="$url" -v name="$list" '$1 == name && $2 == url { print $7; exit }' "${skynetloc}/lists/.sources" 2>/dev/null)"
			case "$oldsuccess" in ""|0|*[!0-9]*) oldsuccess="$(date -r "$listfile" +%s 2>/dev/null || printf 0)" ;; esac
			rm -f "$feedfiles/$list" "${skynetloc}/lists/${list}.tmp.$$"
			ln -s "$listfile" "$feedfiles/$list"
			Write_Threat_Feed_Result "$feedresult" cached "$feedchecked" "$oldsuccess" \
				|| { Restore_Threat_Feed_Selection; return 1; }
			feedrebuild="1"
		else
			rm -f "$feedfiles/$list" "${skynetloc}/lists/${list}.tmp.$$"
			Write_Threat_Feed_Result "$feedresult" failed "$feedresultchecked" "$feedresultsuccess" \
				|| { Restore_Threat_Feed_Selection; return 1; }
		fi
	;;
	*)
		if [ "$feedstate" = "downloaded" ]; then
			if mv -f "${skynetloc}/lists/${list}.tmp.$$" "${skynetloc}/lists/$list" \
				&& rm -f "$feedfiles/$list" && ln -s "${skynetloc}/lists/$list" "$feedfiles/$list"; then
				Write_Threat_Feed_Result "$feedresult" current "$feedresultchecked" "$feedresultsuccess" \
					|| { Restore_Threat_Feed_Selection; return 1; }
			else
				Write_Threat_Feed_Result "$feedresult" failed "$feedresultchecked" 0 \
					|| { Restore_Threat_Feed_Selection; return 1; }
			fi
		fi
	;;
	esac
done < "$feedmanifest"
if [ "$feedrebuild" = "1" ]; then
	rm -f "$feedcounts" "$malwaretmp"
	Build_Malware_Restore "$feedmanifest" "$malwaretmp" "$feedcounts"
	buildstatus="$?"
fi

feedfailed="0"
feeddegraded="0"
feedfailedsource=""
feedcachedsources=""
while IFS="$feedtab" read -r list url selection; do
	[ "$selection" = "enabled" ] || continue
	feedresult="$TMP_DIR/feed.${list}.result"
	Read_Threat_Feed_Result "$feedresult" || { Restore_Threat_Feed_Selection; return 1; }
	feedentries="$(awk -F '\t' -v name="$list" '$1 == name { print $2; exit }' "$feedcounts" 2>/dev/null)"
	case "$feedentries" in ""|0|*[!0-9]*)
		feedstate="failed"
		Write_Threat_Feed_Result "$feedresult" failed "$feedchecked" 0 || { Restore_Threat_Feed_Selection; return 1; }
	;; esac
	case "$feedstate" in
		cached)
			feeddegraded="1"
			feedcachedsources="${feedcachedsources:+$feedcachedsources }$list"
		;;
		current) ;;
		*)
			feedfailed="1"
			[ -n "$feedfailedsource" ] || feedfailedsource="$list"
		;;
	esac
done < "$feedmanifest"

# Phase 3: publish cache ownership and source health only after every worker
# and the consolidation parser have completed.
listmanifesttmp="${listmanifest}.tmp.$$"
true > "$listmanifesttmp" || { Restore_Threat_Feed_Selection; echo "[*] Unable To Save Malware Cache Manifest"; echo; return 1; }
while IFS="$feedtab" read -r list url selection; do
	feedstate="excluded"
	feedentries="$(awk -F '\t' -v name="$list" '$1 == name { print $2; exit }' "$feedcounts")" \
		|| { rm -f "$listmanifesttmp"; Restore_Threat_Feed_Selection; return 1; }
	if [ "$selection" = "enabled" ]; then
		Read_Threat_Feed_Result "$TMP_DIR/feed.${list}.result" \
			|| { rm -f "$listmanifesttmp"; Restore_Threat_Feed_Selection; return 1; }
	fi
	feedbind="0"
	case "$selection:$feedstate:$feedentries" in
		enabled:current:[1-9]*|enabled:cached:[1-9]*) feedbind="1" ;;
		excluded:excluded:[1-9]*)
			if [ -s "${skynetloc}/lists/$list" ] && [ -s "$listmanifest" ] \
				&& awk -v url="$url" -v name="$list" '$1 == url && $2 == name { found=1 } END { exit !found }' "$listmanifest"; then
				feedbind="1"
			fi
		;;
	esac
	if [ "$feedbind" = "1" ]; then
		printf '%s %s\n' "$url" "$list" >> "$listmanifesttmp" \
			|| { rm -f "$listmanifesttmp"; Restore_Threat_Feed_Selection; return 1; }
	fi
done < "$feedmanifest"
mv -f "$listmanifesttmp" "$listmanifest" || { Restore_Threat_Feed_Selection; echo "[*] Unable To Publish Malware Cache Manifest"; echo; return 1; }
Publish_Threat_Feed_Status "$feedmanifest" "$feedcounts" || { Restore_Threat_Feed_Selection; echo "[*] Unable To Publish Malware Source Status"; echo; return 1; }


if [ "$feedfailed" = "1" ] || [ "$buildstatus" != "0" ]; then
	Restore_Threat_Feed_Selection
	echo "[✘] No Valid Cached Copy For Malware Source ($feedfailedsource)"
	echo "[*] Existing Blacklist Retained"
	echo
	return 1
fi
if [ "$feeddegraded" = "1" ]; then
	echo "[!] Validated Cached Malware Sources Retained ($feedcachedsources)"
fi
}

Restore_Malware_Blacklist() {
	# Never persist the current sets after a failed live rollback. Restore the
	# original offline snapshot directly and retain it for recovery on any error.
	malwarerestorestatus="0"
	Apply_Blacklist_File "$malwareipsetbackup" >/dev/null 2>&1 || malwarerestorestatus="1"
	if ! cmp -s "$malwareipsetbackup" "$skynetipset"; then
		saveipsettmp="${skynetipset}.tmp.$$"
		if ! cp -f "$malwareipsetbackup" "$saveipsettmp" || ! chmod 600 "$saveipsettmp" \
			|| ! mv -f "$saveipsettmp" "$skynetipset"; then malwarerestorestatus="1"; fi
	fi
	if [ "$malwarerestorestatus" != "0" ]; then
		malwarerollbackpreserve="1"
		Log error -s "Failed To Restore Malware Blacklist - Recovery Snapshot Retained ($malwareipsetbackup)"
	fi
	return "$malwarerestorestatus"
}

Apply_Malware_Update() {
# Build beside the persisted IPSet file and apply it to temporary sets first.
# The live and saved blacklist remain untouched unless the complete restore
# succeeds.
malwareipsettmp="$TMP_DIR/skynet-malware-candidate"
malwareipsetbackup="$TMP_DIR/skynet-blacklist-previous"
if ! sed '\~comment \"BanMalware: ~d' "$skynetipset" > "$malwareipsettmp" \
	|| ! cat "$malwaretmp" >> "$malwareipsettmp" || [ ! -s "$malwareipsettmp" ] \
	|| ! cp -f "$skynetipset" "$malwareipsetbackup"; then
	Restore_Threat_Feed_Selection
	echo "[✘] Unable To Build New Blacklist - Existing Entries Retained"
	echo
	return 1
fi
printf "%-35s | " "[i] Finish Blacklist Consolidation"
Display_Result
Display_Message "[i] Applying New Blacklist"
if Apply_Blacklist_File "$malwareipsettmp"; then
	Display_Result
else
	result="$(Red "[$(($(date +%s) - btime))s]")"
	printf '%-8s\n' "$result"
	printf '%-35s\n' "[✘] Unable To Apply New Blacklist - Existing Entries Retained"
	Restore_Threat_Feed_Selection
	echo
	return 1
fi
Display_Message "[i] Refreshing AiProtect Bans"
if Refresh_AiProtect; then
	Display_Result
else
	result="$(Red "[$(($(date +%s) - btime))s]")"
	printf '%-8s\n' "$result"
	Restore_Malware_Blacklist
	malwarerollbackstatus="$?"
	Restore_Threat_Feed_Selection
	if [ "$malwarerollbackstatus" = "0" ]; then
		echo "[✘] Unable To Refresh AiProtect Bans - Existing Blacklist Restored"
	else
		echo "[✘] Unable To Refresh AiProtect Bans - Blacklist Recovery Required"
	fi
	echo
	return 1
fi
Display_Message "[i] Saving Changes"
forcebanmalwareupdate="disabled"
banmalwarelastupdated="$(date +%s)"
Update_Block_Counts
if Save_IPSets && Publish_Managed_Feed_Selection && Write_Config; then
	feedselectiontransactionactive="0"
	nocfg="1"
	Display_Result
else
	result="$(Red "[$(($(date +%s) - btime))s]")"
	printf '%-8s\n' "$result"
	Restore_Malware_Blacklist
	malwarerollbackstatus="$?"
	Restore_Threat_Feed_Selection
	Restore_Managed_Feed_Selection || Log error -s "Failed To Restore Malware Source Selection"
	if [ "$malwarerollbackstatus" = "0" ]; then
		echo "[✘] Unable To Save Malware Update - Existing Blacklist Restored"
	else
		echo "[✘] Unable To Save Malware Update - Blacklist Recovery Required"
	fi
	echo
	return 1
fi
Prune_Threat_Feed_Caches || Log error -s "Unable To Remove Obsolete Malware Cache"
echo
echo "[i] For Whitelisting Assistance -"
echo "[i] https://www.snbforums.com/threads/release-skynet-router-firewall-security-enhancements.16798/#post-115872"
}

Dispatch_BanMalware() {
	case "$2" in
		status)
			[ "$#" -eq "2" ] || { echo "[*] Usage: firewall banmalware status"; echo; return 2; }
			Print_Threat_Feed_Status
			echo
			nolog="2"
			nocfg="1"
			return 0
		;;
		sources)
			[ "$#" -eq "2" ] || { echo "[*] Usage: firewall banmalware sources"; echo; return 2; }
			Print_Threat_Feed_Sources
			echo
			nolog="2"
			nocfg="1"
			return 0
		;;
	esac
	Check_Lock "$@"
	Require_Running
	Require_Rule_Registry
	Require_Time
	Prepare_Malware_Update "$@"
	malwarestatus="$?"
	[ "$malwarestatus" = "0" ] || exit "$malwarestatus"
	Require_Connection
	Purge_Logs
	if ! Build_Malware_Update; then
		Restore_Managed_Feed_Selection || Log error -s "Failed To Restore Malware Source Selection"
		Queue_Action failed feeds update malware sources "Malware blacklist" "Source preparation failed" || true
		exit 1
	fi
	if ! Apply_Malware_Update; then
		Restore_Managed_Feed_Selection || Log error -s "Failed To Restore Malware Source Selection"
		Queue_Action failed feeds update malware sources "Malware blacklist" "Blacklist apply failed" || true
		exit 1
	fi
	if [ "$feeddegraded" = "1" ]; then malwareactionresult="degraded"; else malwareactionresult="success"; fi
	malwareactionsummary="$(Build_Threat_Feed_Action_Summary)" || malwareactionsummary="Malware blacklist"
	Queue_Action "$malwareactionresult" feeds update malware sources "$malwareactionsummary" "${feedcachedsources:+Cached: $feedcachedsources}" \
		|| Log error -s "Failed To Queue Malware Update"
}

Dispatch_Whitelist() {
	Check_Lock "$@"
	Require_Running
	Require_Rule_Registry
	case "$2" in ip|range|domain|asn|refresh) Require_Time ;; esac
	Purge_Logs
	case "$2" in
		ip|range)
			whitelistentrytype="$2"
			shift 2
			Parse_IPSet_Entry_Arguments "$whitelistentrytype" 242 "$@" || { echo "[*] $parsederror"; echo; exit 2; }
			Require_Time
			whitelistlist="$parsedentries"
			desc="$parsedcomment"
			echo "[i] Whitelisting $whitelistlist"
			Apply_Registered_Manual_Rules add whitelist "$whitelistentrytype" "$desc" "$whitelistlist" || { echo; exit 1; }
			if [ "$rulestagechanged" -gt "0" ]; then
				Queue_Action success rules add whitelist "$whitelistentrytype" "$whitelistlist" "$desc" || Log error -s "Failed To Queue Rule Action"
			fi
			for whitelistentry in $whitelistlist; do
				sed -i "\\~=$whitelistentry ~d" "$skynetlog" \
					|| Log error -s "Failed To Remove Old Logs For $whitelistentry"
			done
			return 0
		;;
		domain)
			Require_Time
			Require_Connection
			shift 2
			[ "$#" -gt "0" ] || { echo "[*] Domain Field Can't Be Empty"; echo; exit 2; }
			domainbatchlist=""
			for domaininput in "$@"; do
				domainvalue="$(Normalize_Domain "$domaininput")" || { echo "[*] $domaininput Is Not A Valid Domain"; echo; exit 2; }
				case " $domainbatchlist " in *" $domainvalue "*) ;; *) domainbatchlist="${domainbatchlist}${domainbatchlist:+ }$domainvalue" ;; esac
			done
			Stage_Rule_Registry add whitelist domain "$domainbatchlist" "" || { echo "[*] Failed To Stage Domain Rules"; echo; exit 1; }
			echo "[i] Adding $domainbatchlist To Whitelist"
			Update_Domain_Rules "$rulestagefile" required || { echo "[*] Unable To Resolve Domain Rules - Existing Rules Retained"; echo; exit 1; }
			Queue_Action success rules add whitelist domain "$domainbatchlist" "" || Log error -s "Failed To Queue Rule Action"
			return 0
		;;
		vpn)
			echo "[i] Updating VPN Whitelist"
			Whitelist_VPN || { echo "[*] Failed To Update VPN Whitelist"; echo; exit 1; }
		;;
		asn)
			Require_Time
			Require_Connection
			shift 2
			asnlist="$(Normalize_ASN_Arguments "$@")" || { echo "[*] ASN Values Must Use AS Followed By Up To Six Digits"; echo; exit 2; }
			echo "[i] Adding $asnlist To Whitelist"
			Apply_Registered_ASN_Rules add whitelist "$asnlist"
			asnstatus="$?"
			if [ "$asnstatus" != "0" ]; then
				if [ "$asnstatus" = "2" ]; then echo "[*] An ASN Range Is Already Owned By Another Rule"; else echo "[*] Failed To Download Or Apply $asnlist"; fi
				echo
				exit "$asnstatus"
			fi
			Queue_Action success rules add whitelist asn "$asnlist" "" || Log error -s "Failed To Queue Rule Action"
			return 0
		;;
		remove)
			case "$3" in
				domain)
					shift 3
					[ "$#" -gt "0" ] || { echo "[*] Domain Field Can't Be Empty"; echo; exit 2; }
					domainlist=""
					for domaininput in "$@"; do
						domain="$(Normalize_Domain "$domaininput")" || { echo "[*] $domaininput Is Not A Valid Domain"; echo; exit 2; }
						case " $domainlist " in *" $domain "*) continue ;; esac
						domainlist="${domainlist}${domainlist:+ }$domain"
					done
					Stage_Rule_Registry remove whitelist domain "$domainlist" ""
					domainstatus="$?"
					if [ "$domainstatus" = "2" ]; then echo "[*] Domain Rule Not Found"; echo; exit 2; fi
					[ "$domainstatus" = "0" ] || { echo "[*] Failed To Stage Domain Rules"; echo; exit 1; }
					echo "[i] Removing $domainlist From Whitelist"
					Update_Domain_Rules "$rulestagefile" cached || { echo "[*] Failed To Update Domain Rules - Existing Rules Retained"; echo; exit 1; }
					Queue_Action success rules remove whitelist domain "$domainlist" "" || Log error -s "Failed To Queue Rule Action"
					return 0
				;;
				asn)
					shift 3
					asnlist="$(Normalize_ASN_Arguments "$@")" || { echo "[*] ASN Values Must Use AS Followed By Up To Six Digits"; echo; exit 2; }
					echo "[i] Removing $asnlist From Whitelist"
					Apply_Registered_ASN_Rules remove whitelist "$asnlist"
					asnstatus="$?"
					if [ "$asnstatus" = "2" ]; then echo "[*] ASN Rule Not Found"; echo; exit 2; fi
					[ "$asnstatus" = "0" ] || { echo; exit 1; }
					Queue_Action success rules remove whitelist asn "$asnlist" "" || Log error -s "Failed To Queue Rule Action"
					return 0
				;;
				entry)
					if ! echo "$4" | Is_IPRange; then echo "[*] $4 Is Not A Valid IP/Range"; echo; exit 2; fi
					echo "[i] Removing $4 From Whitelist"
					Apply_Registered_Address_Rules remove whitelist "$4" ""
					whiteliststatus="$?"
					if [ "$whiteliststatus" = "2" ]; then echo "[*] Manual Whitelist Rule Not Found"; echo; exit 2; fi
					[ "$whiteliststatus" = "0" ] || { echo; exit 1; }
					sed -i "\\~=$4 ~d" "$skynetlog"
					if printf '%s\n' "$4" | Is_Range; then whitelisttype="range"; else whitelisttype="ip"; fi
					Queue_Action success rules remove whitelist "$whitelisttype" "$4" "" || Log error -s "Failed To Queue Rule Action"
					return 0
				;;
				comment)
					[ "$#" -eq "4" ] && [ -n "$4" ] || { echo "[*] Syntax: firewall whitelist remove comment \"text\""; echo; exit 2; }
					echo "[i] Removing All Entries With Comment Matching \"$4\" From Whitelist"
					whitelistcommentlist="$(awk -F '\t' -v text="$4" '$1 == "R2" && $3 == "whitelist" && ($4 == "ip" || $4 == "range") && index(substr($6, 2), text) {print $5}' "$skynetrules" | awk 'NF {output = output (output == "" ? "" : " ") $1} END {print output}')"
					[ -n "$whitelistcommentlist" ] || { echo "[*] No Manual Whitelist Comments Matched"; echo; exit 2; }
					Apply_Registered_Address_Rules remove whitelist "$whitelistcommentlist" "" || { echo; exit 1; }
					Queue_Action success rules remove whitelist comment "$whitelistcommentlist" "$4" || Log error -s "Failed To Queue Rule Action"
					return 0
				;;
				all)
					Require_Connection
					echo "[i] Removing User Whitelist Rules"
					Clear_Registered_Rules whitelist || { echo "[*] Failed To Clear Whitelist - Existing Rules Retained"; echo; exit 1; }
					Queue_Action success rules remove whitelist all "all user whitelist rules" "" || Log error -s "Failed To Queue Rule Action"
					return 0
				;;
				*)
					Command_Not_Recognized
				;;
			esac
		;;
		refresh)
			Require_Connection
			echo "[i] Refreshing Shared Whitelist Files"
			Whitelist_Extra || { echo "[*] Failed To Refresh Extra Whitelist"; echo; exit 1; }
			Whitelist_CDN || { echo "[*] Failed To Refresh CDN Whitelist"; echo; exit 1; }
			Whitelist_VPN || { echo "[*] Failed To Refresh VPN Whitelist"; echo; exit 1; }
			Whitelist_Shared || { echo "[*] Failed To Refresh Shared Whitelist"; echo; exit 1; }
			Update_Domain_Rules "$skynetrules" refresh || { echo "[*] Failed To Refresh Domain Rules - Existing Rules Retained"; echo; exit 1; }
			Require_Save_IPSets
			Queue_Action success rules refresh all whitelist "whitelist sources" "" || Log error -s "Failed To Queue Rule Action"
			return 0
		;;
		view)
			case "$3" in
				ips)
					awk -F '\t' '$1 == "R2" && $3 == "whitelist" && ($4 == "ip" || $4 == "range") {print $5 " " substr($6, 2)}' "$skynetrules"
				;;
				domains)
					awk -F '\t' '$1 == "R2" && $3 == "whitelist" && $4 == "domain" {print $5}' "$skynetrules"
				;;
				asns)
					awk -F '\t' '$1 == "R2" && $3 == "whitelist" && $4 == "asn" {print $2 " " $5 " " substr($6, 2)}' "$skynetrules"
				;;
				imported)
					awk -F '\t' '$1 == "R2" && $3 == "whitelist" && $4 == "import" {print $2 " " $5 " " substr($6, 2)}' "$skynetrules"
				;;
				*)
					sed '\~add Skynet-Whitelist ~!d;s~add Skynet-Whitelist ~~' "$skynetipset"
				;;
			esac
			echo
			nocfg="1"
			nolog="2"
			return 0
		;;
		*)
			Command_Not_Recognized
		;;
	esac
	echo "[i] Saving Changes"
	Require_Save_IPSets
}

Dispatch_Import() {
	case "$2" in
		blacklist)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			echo "[i] This Function Extracts All IPs And Adds Them ALL To Blacklist"
			if [ -f "$3" ]; then
				echo "[i] Local Custom List Detected: $3"
				Extract_IPList "$3" "$TMP_DIR/iplist-unfiltered.txt"
			elif [ -n "$3" ]; then
				echo "[i] Remote Custom List Detected: $3"
				Require_Connection
				Download_IPList "$3" || { echo "[*] Download Error Detected - Stopping Import"; echo; exit 1; }
			else
				echo "[*] URL/File Field Can't Be Empty - Please Try Again"
				echo; exit 2
			fi
			if ! Is_IPRange < "$TMP_DIR/iplist-unfiltered.txt"; then echo "[*] No Content Detected - Stopping Import"; echo; exit 1; fi
			echo "[i] Processing List"
			if [ -n "$4" ]; then
				if ! Validate_IPSet_Comment "$4" 242; then echo "[*] Comment Contains Invalid Characters Or Is Too Long"; echo; exit 2; fi
				importdesc="$4"
			else
				importdesc="Imported List"
			fi
			Build_IPList_Restore add blacklist "" "$TMP_DIR/iplist-unfiltered.txt" "$TMP_DIR/iplist-filtered.txt"
			if [ ! -s "$TMP_DIR/iplist-filtered.txt" ]; then echo "[*] No Public IPs Detected - Stopping Import"; echo; exit 1; fi
			echo "[i] Adding IPs To Blacklist"
			Apply_Registered_Import ban "$3" "$importdesc" "$TMP_DIR/iplist-filtered.txt" \
				|| { echo "[*] Failed To Apply Import - Previous Entries Retained"; echo; exit 1; }
			importcount="$(wc -l < "$TMP_DIR/iplist-filtered.txt" | tr -d ' ')"
			rm -f "$TMP_DIR/iplist-unfiltered.txt" "$TMP_DIR/iplist-filtered.txt"
			nocfg="1"
			Queue_Action success rules add ban import "$3" "$importdesc ($importcount entries)" || Log error -s "Failed To Queue Import Action"
		;;
		whitelist)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			echo "[i] This Function Extracts All IPs And Adds Them ALL To Whitelist"
			if [ -f "$3" ]; then
				echo "[i] Local Custom List Detected: $3"
				Extract_IPList "$3" "$TMP_DIR/iplist-unfiltered.txt"
			elif [ -n "$3" ]; then
				echo "[i] Remote Custom List Detected: $3"
				Require_Connection
				Download_IPList "$3" || { echo "[*] Download Error Detected - Stopping Import"; echo; exit 1; }
			else
				echo "[*] URL/File Field Can't Be Empty - Please Try Again"
				echo; exit 2
			fi
			if ! Is_IPRange < "$TMP_DIR/iplist-unfiltered.txt"; then echo "[*] No Content Detected - Stopping Import"; echo; exit 1; fi
			echo "[i] Processing List"
			if [ -n "$4" ]; then
				if ! Validate_IPSet_Comment "$4" 242; then echo "[*] Comment Contains Invalid Characters Or Is Too Long"; echo; exit 2; fi
				importdesc="$4"
			else
				importdesc="Imported List"
			fi
			Build_IPList_Restore add whitelist "" "$TMP_DIR/iplist-unfiltered.txt" "$TMP_DIR/iplist-filtered.txt"
			if [ ! -s "$TMP_DIR/iplist-filtered.txt" ]; then echo "[*] No Public IPs Detected - Stopping Import"; echo; exit 1; fi
			echo "[i] Adding IPs To Whitelist"
			Apply_Registered_Import whitelist "$3" "$importdesc" "$TMP_DIR/iplist-filtered.txt" \
				|| { echo "[*] Failed To Apply Import - Previous Entries Retained"; echo; exit 1; }
			importcount="$(wc -l < "$TMP_DIR/iplist-filtered.txt" | tr -d ' ')"
			rm -f "$TMP_DIR/iplist-unfiltered.txt" "$TMP_DIR/iplist-filtered.txt"
			nocfg="1"
			Queue_Action success rules add whitelist import "$3" "$importdesc ($importcount entries)" || Log error -s "Failed To Queue Import Action"
		;;
		*)
			Command_Not_Recognized
		;;
	esac
}

Dispatch_Save() {
	Check_Lock "$@"
	if ! Check_IPSets || ! Check_IPTables; then
		Log error -s "Rule Integrity Violation - Restarting Firewall [ ${fail}]"
		unset fail
		restartfirewall="1"
		nolog="2"
	else
		Whitelist_Blocked_Private_IPs
		Purge_Logs
		echo "[i] Saving Changes"
		Require_Save_IPSets
		Check_Security
	fi
}

Prune_Expired_Rules() {
	Time_Is_Ready || return 0
	ruleprunenow="$(date +%s)"
	# Read-only probe avoids creating a USB staging file when no deadline is due.
	[ -r "$skynetrules" ] || return 1
	awk -F '\t' -v now="$ruleprunenow" '
		$1 == "R2" && $9 > 0 && $9 <= now { expired = 1; exit }
		END { exit expired ? 0 : 3 }' "$skynetrules"
	ruleprunestatus="$?"
	[ "$ruleprunestatus" != "3" ] || return 0
	[ "$ruleprunestatus" = "0" ] || return 1
	ruleprunefile="${skynetrules}.tmp.$$"
	rulestagefile="$ruleprunefile"
	rulepruneexpired="$TMP_DIR/expired-rules.$$"
	: > "$rulepruneexpired" || return 1
	# Kernel timeouts enforce deadlines independently. Record detected expiry
	# only after pruning commits, with the original deadline in the details.
	awk -F '\t' -v now="$ruleprunenow" -v expired="$rulepruneexpired" '
		$1 == "R2" && $9 > 0 && $9 <= now {
			if ($3 == "ban" && $7 == "enabled") print $4 "\t" $5 "\t" $9 > expired
			changed = 1; next
		}
		{print}
		END {exit changed ? 0 : 3}' "$skynetrules" > "$ruleprunefile"
	ruleprunestatus="$?"
	if [ "$ruleprunestatus" = "3" ]; then rm -f "$ruleprunefile" "$rulepruneexpired"; return 0; fi
	if [ "$ruleprunestatus" != "0" ] || ! Validate_Rule_Registry "$ruleprunefile" \
		|| ! Apply_Rule_Registry_Candidate "$ruleprunefile"; then
		rm -f "$ruleprunefile" "$rulepruneexpired"
		return 1
	fi
	maintenancechanged="1"
	while IFS="$(printf '\t')" read -r ruleprunetype ruleprunevalue ruleprunedeadline; do
		Queue_Action success rules expire ban "$ruleprunetype" "$ruleprunevalue" \
			"Expired $(Format_Threat_Feed_Time "$ruleprunedeadline"); detected during maintenance" \
			|| Log error -s "Failed To Queue Temporary Ban Expiry ($ruleprunevalue)"
	done < "$rulepruneexpired"
	rm -f "$rulepruneexpired"
	# Keep committed expiry records even if a later maintenance check fails.
	Publish_Actions
}

Dispatch_Persist() {
	nolog="2"
	nocfg="1"
	Wait_For_Lock "$@" || return 1
	if Time_Is_Ready; then Archive_Block_Logs || return 1; fi
	Save_IPSets || return 1
}

Dispatch_Maintenance() {
	nolog="2"
	nocfg="1"
	Wait_For_Lock "$@" || return 1
	# A command that held the lock may have changed settings while we waited.
	Load_Config || { Record_Maintenance_Status failed configuration; return 1; }
	maintenancechanged="0"
	if Time_Is_Ready; then
		if Time_Dependent_State_Pending; then
			Activate_Time_Dependent_State || { Record_Maintenance_Status failed activation; return 1; }
			maintenancechanged="1"
		fi
		Archive_Block_Logs || { Record_Maintenance_Status failed archival; return 1; }
		Enforce_Log_Limit || { Record_Maintenance_Status failed log-limit; return 1; }
		Prune_Expired_Rules || { Record_Maintenance_Status failed rule-prune; return 1; }
	fi
	Check_Security || { Record_Maintenance_Status failed security; return 1; }
	if ! Check_IPSets; then
		echo "[*] IPSet Integrity Check Failed ($fail)"
		Record_Maintenance_Status failed ipset
		return 1
	fi
	Reconcile_Firewall_Rules || { Record_Maintenance_Status failed firewall; return 1; }
	if [ -f "$DURABLE_PENDING" ]; then Save_IPSets || { Record_Maintenance_Status failed persistence; return 1; }; fi
	if [ "$maintenancechanged" = "1" ]; then Generate_WebUI_Settings || { Record_Maintenance_Status failed webui; return 1; }; fi
	if Time_Is_Ready; then Record_Maintenance_Status success complete; else Record_Maintenance_Status degraded time-pending; fi
}

Ensure_Startup_Runtime() {
	# Volatile completion state is published only after all per-boot integration
	# succeeds. Retrying this phase must not reload an already active policy.
	[ -f "$STARTUP_READY" ] && return 0
	Wait_For_Lock start || return 1
	[ -f "$STARTUP_READY" ] && return 0
	Maintain_Script_Hooks firewall-start services-stop service-event post-mount unmount \
		|| { Log error -s "Failed To Maintain Script Hooks"; return 1; }
	Clean_Legacy_WebUI_Files || return 1
	Unload_Cron save banmalware autoupdate checkupdate || return 1
	case "$banmalwareupdate" in
		daily) Load_Cron banmalwaredaily || return 1 ;;
		weekly) Load_Cron banmalwareweekly || return 1 ;;
	esac
	if Is_Enabled "$autoupdate"; then Load_Cron autoupdate || return 1
	else Load_Cron checkupdate || return 1; fi
	Load_Cron maintenance rules || return 1
	if Is_Enabled "$displaywebui"; then
		Install_WebUI_Page || { Log error -s "Failed To Install WebUI"; return 1; }
	else
		Uninstall_WebUI_Page || { Log error -s "Failed To Remove WebUI"; return 1; }
	fi
	Generate_WebUI_Settings || return 1
	Publish_Rule_Migration_Complete || return 1
	: > "$STARTUP_READY" && chmod 600 "$STARTUP_READY"
}

Restore_Startup_Policy() {
	# Caller holds the state lock. Rebuild from durable local data without waiting
	# for time, downloading sources or releasing ownership before verification.
	: > "$STARTUP_PENDING" && chmod 600 "$STARTUP_PENDING" || return 1
	rm -f "$STARTUP_READY" || return 1
	Migrate_Installation || { echo "[*] Failed To Migrate Existing Skynet Data"; return 1; }
	# Some Merlin kernels provide the set match without a loadable xt_set module.
	grep -qxF set /proc/net/ip_tables_matches || modprobe xt_set || return 1
	Ensure_IPSet_Topology || { echo "[*] Failed To Create IPSet Topology"; return 1; }
	if [ -f "$skynetipset" ]; then
		ipset restore -! -f "$skynetipset" || { echo "[*] Failed To Restore Saved IPSet Data"; return 1; }
	else
		: > "$skynetipset" && chmod 600 "$skynetipset" || return 1
	fi
	Initialize_Rule_Registry || { echo "[*] Failed To Migrate Rule Registry"; return 1; }
	if ! Time_Is_Ready; then Mark_Time_Dependent_State_Pending || return 1; fi
	Apply_Rule_Registry_Candidate "$skynetrules" startup || { echo "[*] Failed To Compile User Rules"; return 1; }
	Update_Domain_Rules "$skynetrules" startup || { echo "[*] Failed To Restore Cached Domain Rules"; return 1; }
	Migrate_Legacy_IPSet_Ownership || { echo "[*] Failed To Complete Rule Migration"; return 1; }
	Whitelist_Blocked_Private_IPs || { echo "[*] Failed To Whitelist Private Networks"; return 1; }
	Whitelist_VPN || { echo "[*] Failed To Restore VPN Whitelist"; return 1; }
	Whitelist_Shared || { echo "[*] Failed To Restore Shared Whitelist"; return 1; }
	Save_IPSets || { echo "[*] Failed To Persist Restored Base State"; return 1; }
	Reconcile_Firewall_Rules || { echo "[*] Failed To Load Permanent Firewall Rules"; return 1; }
	Check_IPSets || { echo "[*] Restored IPSet Integrity Check Failed ($fail)"; return 1; }
	Revalidate_IOT_Connections || return 1
	rm -f "$STARTUP_PENDING"
}

Dispatch_Start() {
	# Most firewall-start events need only restore Skynet rules after Merlin has
	# rebuilt its base firewall. The complete initialization path is entered only
	# when persistent sets or the R2 registry are unavailable.
	if [ ! -f "$STARTUP_PENDING" ] && Check_IPSets && Validate_Rule_Registry "$skynetrules" && Rule_Migration_Complete; then
		if Time_Is_Ready && Time_Dependent_State_Pending; then
			Wait_For_Lock "$@" || return 1
			if Time_Dependent_State_Pending; then
				Activate_Time_Dependent_State || { echo "[*] Failed To Activate Time-Dependent Rules"; echo; return 1; }
			else
				Reconcile_Firewall_Rules || { echo "[*] Failed To Reconcile Firewall Rules"; echo; return 1; }
			fi
		else
			Reconcile_Firewall_Rules || { echo "[*] Failed To Reconcile Firewall Rules"; echo; return 1; }
		fi
		if ! Time_Is_Ready; then
			Mark_Time_Dependent_State_Pending || return 1
			if Wait_For_Time; then
				Wait_For_Lock "$@" || return 1
				if Time_Dependent_State_Pending; then
					Activate_Time_Dependent_State || { echo "[*] Failed To Activate Time-Dependent Rules"; echo; return 1; }
					Generate_WebUI_Settings || true
				else
					Reconcile_Firewall_Rules || { echo "[*] Failed To Reconcile Firewall Rules"; echo; return 1; }
				fi
			else
				echo "[!] Router Time Is Not Synchronized - Logging And Temporary Rules Remain Pending"
			fi
		fi
		Ensure_Startup_Runtime || return 1
		nocfg="1"
		nolog="2"
		return 0
	fi

	Wait_For_Lock "$@" || return 1
	# Another queued firewall event may have completed cold initialization while
	# this process waited. Re-check before touching persistent state.
	if [ ! -f "$STARTUP_PENDING" ] && Check_IPSets && Validate_Rule_Registry "$skynetrules" && Rule_Migration_Complete; then
		if Time_Is_Ready && Time_Dependent_State_Pending; then
			Activate_Time_Dependent_State || return 1
		else
			Reconcile_Firewall_Rules || return 1
			Time_Is_Ready || Mark_Time_Dependent_State_Pending || return 1
		fi
		Ensure_Startup_Runtime || return 1
		nocfg="1"
		nolog="2"
		return 0
	fi
	echo "[i] Initializing Skynet"
	# A complete set topology alone does not prove restore/compilation succeeded.
	# Keep failed cold initialization eligible for retry until policy is verified.
	: > "$STARTUP_PENDING" && chmod 600 "$STARTUP_PENDING" || return 1
	rm -f "$STARTUP_READY" || return 1
	Check_Settings || { echo; return 1; }
	Restore_Startup_Policy || { echo; return 1; }
	Ensure_Startup_Runtime || return 1
	Release_Lock

	if ! Wait_For_Time; then
		echo "[!] Permanent Protection Active - Logging And Temporary Rules Await Time Synchronization"
		nocfg="1"
		nolog="2"
		return 0
	fi
	Wait_For_Lock "$@" || return 1
	Activate_Time_Dependent_State || { echo "[*] Failed To Activate Time-Dependent Rules"; echo; return 1; }
	Purge_Logs "all"
	[ -f "${skynetloc}/webui/stats.js" ] || Generate_Stats
	Generate_WebUI_Settings || { echo "[*] Failed To Generate WebUI Settings"; echo; return 1; }
	Queue_Action success system restore startup lifecycle "Skynet" "Protection and time-dependent services active" \
		|| Log error -s "Failed To Queue Startup Action"
	if Is_Enabled "$forcebanmalwareupdate"; then
		Write_Config || { echo "[*] Failed To Save Configuration"; echo; return 1; }
		Release_Lock
		"$0" banmalware
		return "$?"
	fi
}

Dispatch_Restart() {
	Check_Lock "$@"
	if Time_Is_Ready; then Purge_Logs || return 1; fi
	echo "[i] Restarting Firewall Service"
	Release_Lock
	restartfirewall="1"
	nolog="2"
	nocfg="1"
}

Dispatch_Disable() {
	Check_Lock "$@"
	echo "[i] Saving Changes"
	Require_Save_IPSets
	echo "[i] Unloading Skynet Components"
	Unload_Cron "all"
	Unload_Skynet_Firewall_Rules || { echo "[*] Failed To Unload Skynet Firewall Rules"; echo; exit 1; }
	Unload_IPSets
	Uninstall_WebUI_Page
	Log info "Skynet Disabled"
	Purge_Logs "all"
	nolog="2"
}

Restore_Update_Files() {
	cp -f "$updatefirewallbackup" "$updatescripttarget" || return 1
	if [ "$updatewebuichanged" = "1" ]; then
		if [ "$updatewebuihadold" = "1" ]; then
			cp -f "$updatewebuibackup" "${skynetloc}/webui/skynet.asp" || return 1
		else
			rm -f "${skynetloc}/webui/skynet.asp" || return 1
		fi
	fi
}

Dispatch_Update() {
	Check_Lock "$@"
	Require_Connection
	# /opt/bin/firewall is normally a symlink. Always update the installed script
	# itself so invocation through either the alias, symlink or full path is safe.
	updatescripttarget="/jffs/scripts/firewall"
	if [ ! -f "$updatescripttarget" ]; then
		Log error "Skynet Update Failed - Installed Script Not Found"
		echo
		exit 1
	fi
	if [ "$1" = "amtmupdate" ] && [ "$2" = "check" ]; then
		exit 0
	fi
	remotedir="https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master"
	if ! Download_File "firewall.sh" "$updatescripttarget" "$2" stage; then
		Log error "Failed To Check For Updates"
		echo
		exit 1
	fi
	updatetmp="$downloadtmp"
	remotever="$(Filter_Version < "$updatetmp")"
	localmd5="$(md5sum "$updatescripttarget" | awk '{print $1}')"
	remotemd5="$(md5sum "$updatetmp" | awk '{print $1}')"
	if [ -z "$remotever" ]; then
		rm -f "$updatetmp"
		Log error "Invalid Update File Detected"
		echo
		exit 1
	fi
	if [ "$localmd5" = "$remotemd5" ] && [ "$2" != "-f" ]; then
		rm -f "$updatetmp"
		Log info "Skynet Up To Date - $localver (${localmd5})"
		nolog="2"
	elif [ "$localmd5" != "$remotemd5" ] && [ "$2" = "check" ]; then
		rm -f "$updatetmp"
		Log info "Skynet Update Detected - $remotever (${remotemd5})"
		nolog="2"
	elif [ "$2" = "-f" ]; then
		echo "[i] Forcing Update"
	fi
	if [ "$localmd5" != "$remotemd5" ] || [ "$2" = "-f" ] && [ "$nolog" != "2" ]; then
		Log info "New Version Detected - Updating To $remotever (${remotemd5})"
		mkdir -p "${skynetloc}/webui" || { rm -f "$updatetmp"; Log error "Failed To Prepare WebUI Directory"; echo; exit 1; }
		if ! Download_File "webui/skynet.asp" "${skynetloc}/webui/skynet.asp" "$2" stage; then
			rm -f "$updatetmp"
			Log error "Skynet Update Failed - Existing Files Retained"
			echo
			exit 1
		fi
		updatewebuitmp="$downloadtmp"
		updatewebuichanged="$downloadchanged"
		updatefirewallbackup="${updatescripttarget}.old.$$"
		updatewebuibackup="${skynetloc}/webui/skynet.asp.old.$$"
		updatewebuihadold="0"
		if [ -f "${skynetloc}/webui/skynet.asp" ]; then
			updatewebuihadold="1"
		fi
		if ! cp -f "$updatescripttarget" "$updatefirewallbackup" \
			|| { [ "$updatewebuichanged" = "1" ] && [ "$updatewebuihadold" = "1" ] \
				&& ! cp -f "${skynetloc}/webui/skynet.asp" "$updatewebuibackup"; }; then
			rm -f "$updatetmp" "$updatewebuitmp" "$updatefirewallbackup" "$updatewebuibackup"
			Log error "Skynet Update Failed - Unable To Back Up Existing Files"
			echo
			exit 1
		fi
		echo "[i] Saving Changes"
		Require_Save_IPSets
		echo "[i] Unloading Skynet Components"
		Unload_Cron "all"
		Unload_Skynet_Firewall_Rules || { echo "[*] Failed To Unload Skynet Firewall Rules"; echo; exit 1; }
		Unload_IPSets
		Uninstall_WebUI_Page
		updatefailed="0"
		if [ "$updatewebuichanged" = "1" ] \
			&& ! mv -f "$updatewebuitmp" "${skynetloc}/webui/skynet.asp"; then
			updatefailed="1"
		fi
		if [ "$updatefailed" = "0" ] && ! mv -f "$updatetmp" "$updatescripttarget"; then
			updatefailed="1"
		fi
		if [ "$updatefailed" = "1" ]; then
			Restore_Update_Files >/dev/null 2>&1 \
				|| Log error "Skynet Update Rollback Failed - Manual Recovery Required"
			rm -f "$updatetmp" "$updatewebuitmp" "$updatefirewallbackup" "$updatewebuibackup"
			Log info "Restarting Firewall Service"
			service restart_firewall >/dev/null 2>&1 \
				|| Log error "Firewall Restart Failed - Run ( service restart_firewall )"
			Log error "Skynet Update Failed - Existing Files Retained"
			echo
			exit 1
		fi
		Log info "Restarting Firewall Service"
		if service restart_firewall >/dev/null 2>&1; then
			rm -f "$updatewebuitmp" "$updatefirewallbackup" "$updatewebuibackup"
			echo
			exit 0
		fi
		Log error "Firewall Restart Failed - Restoring Previous Skynet Files"
		if Restore_Update_Files >/dev/null 2>&1; then
			service restart_firewall >/dev/null 2>&1 \
				|| Log error "Firewall Restart Failed - Run ( service restart_firewall )"
		else
			Log error "Skynet Update Rollback Failed - Manual Recovery Required"
		fi
		rm -f "$updatewebuitmp" "$updatefirewallbackup" "$updatewebuibackup"
		Log error "Skynet Update Failed - Existing Files Retained"
		echo
		exit 1
	fi
}

Settings_AutoUpdate() {
	case "$3" in
		enable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			autoupdateold="$autoupdate"
			if ! Unload_Cron "checkupdate" || ! Load_Cron "autoupdate"; then
				Unload_Cron "autoupdate" >/dev/null 2>&1
				autoupdate="$autoupdateold"
				if Is_Enabled "$autoupdate"; then Load_Cron "autoupdate"; else Load_Cron "checkupdate"; fi
				echo "[*] Failed To Update Auto-Update Schedule"
				echo
				exit 1
			fi
			autoupdate="enabled"
			echo "[i] Skynet Auto-Updates Enabled"
		;;
		disable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			autoupdateold="$autoupdate"
			if ! Unload_Cron "autoupdate" || ! Load_Cron "checkupdate"; then
				Unload_Cron "checkupdate" >/dev/null 2>&1
				autoupdate="$autoupdateold"
				if Is_Enabled "$autoupdate"; then Load_Cron "autoupdate"; else Load_Cron "checkupdate"; fi
				echo "[*] Failed To Update Auto-Update Schedule"
				echo
				exit 1
			fi
			autoupdate="disabled"
			echo "[i] Skynet Auto-Updates Disabled"
		;;
		*)
			Command_Not_Recognized
		;;
	esac
}

Settings_MalwareSchedule() {
	case "$3" in
		daily)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			malwarescheduleold="$banmalwareupdate"
			if ! Unload_Cron "banmalware" || ! Load_Cron "banmalwaredaily"; then
				Unload_Cron "banmalware" >/dev/null 2>&1
				case "$malwarescheduleold" in daily) Load_Cron banmalwaredaily ;; weekly) Load_Cron banmalwareweekly ;; esac
				echo "[*] Failed To Update Malware Schedule"; echo; exit 1
			fi
			banmalwareupdate="daily"
			forcebanmalwareupdate="enabled"
			echo "[i] Daily Malware Blacklist Updates Enabled"
		;;
		weekly)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			malwarescheduleold="$banmalwareupdate"
			if ! Unload_Cron "banmalware" || ! Load_Cron "banmalwareweekly"; then
				Unload_Cron "banmalware" >/dev/null 2>&1
				case "$malwarescheduleold" in daily) Load_Cron banmalwaredaily ;; weekly) Load_Cron banmalwareweekly ;; esac
				echo "[*] Failed To Update Malware Schedule"; echo; exit 1
			fi
			banmalwareupdate="weekly"
			forcebanmalwareupdate="enabled"
			echo "[i] Weekly Malware Blacklist Updates Enabled"
		;;
		disable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			malwarescheduleold="$banmalwareupdate"
			if ! Unload_Cron "banmalware"; then
				case "$malwarescheduleold" in daily) Load_Cron banmalwaredaily ;; weekly) Load_Cron banmalwareweekly ;; esac
				echo "[*] Failed To Disable Malware Schedule"; echo; exit 1
			fi
			banmalwareupdate="disabled"
			echo "[i] Malware Blacklist Updates Disabled"
		;;
		*)
			Command_Not_Recognized
		;;
	esac
}

Settings_LogMode() {
	case "$3" in
		enable) logmodenew="enabled"; logmodemessage="Logging Enabled" ;;
		disable) logmodenew="disabled"; logmodemessage="Logging Disabled" ;;
		*) Command_Not_Recognized ;;
	esac
	Check_Lock "$@" || return 1
	Require_Running
	Purge_Logs || return 1
	logmodeold="$logmode"
	Acquire_Firewall_Lock || return 1
	Unload_LogIPTables
	logmode="$logmodenew"
	if ! Load_LogIPTables || ! Write_Config; then
		Unload_LogIPTables
		logmode="$logmodeold"
		Load_LogIPTables || Log error -s "Failed To Restore Logging Rules"
		Release_Firewall_Lock
		echo "[*] Failed To Update Logging"; echo
		return 1
	fi
	Release_Firewall_Lock
	# Persist enforcement before presentation work. A later failure is reported
	# without discarding the mode already installed in the firewall.
	nocfg="1"
	if Is_Enabled "$logmode" && Is_Enabled "$displaywebui"; then
		Load_Cron genstats || { Log error -s "Failed To Update Statistics Schedule"; return 1; }
	else
		Unload_Cron genstats || { Log error -s "Failed To Update Statistics Schedule"; return 1; }
	fi
	Generate_WebUI_Settings || return 1
	echo "[i] $logmodemessage"
}

Settings_InvalidLogging() {
	case "$3" in
		enable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			loginvalidold="$loginvalid"
			Acquire_Firewall_Lock || exit 1
			Unload_LogIPTables
			loginvalid="enabled"
			if ! Load_LogIPTables; then
				Unload_LogIPTables
				loginvalid="$loginvalidold"
				Load_LogIPTables || Log error -s "Failed To Restore Logging Rules"
				echo "[*] Failed To Enable Invalid Packet Logging"; echo; exit 1
			fi
			Release_Firewall_Lock
			echo "[i] Invalid IP Logging Enabled"
		;;
		disable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			loginvalidold="$loginvalid"
			Acquire_Firewall_Lock || exit 1
			Unload_LogIPTables
			loginvalid="disabled"
			if ! Load_LogIPTables; then
				Unload_LogIPTables
				loginvalid="$loginvalidold"
				Load_LogIPTables || Log error -s "Failed To Restore Logging Rules"
				echo "[*] Failed To Disable Invalid Packet Logging"; echo; exit 1
			fi
			Release_Firewall_Lock
			echo "[i] Invalid IP Logging Disabled"
		;;
		*)
			Command_Not_Recognized
		;;
	esac
}

Settings_LogSize() {
	case "$3" in
		10)
			Check_Lock "$@"
			Require_Running
			logsize="10"
			Purge_Logs
			echo "[i] Log Size Set To 10MB"
		;;
		*)
			Check_Lock "$@"
			Require_Running
			if Is_Numeric "$3"; then
				if [ "$3" -lt 10 ]; then
					echo "[*] $3 Is Not A Valid Size - Must Be At Least 10MB"
					exit 2
				else
					logsize="$3"
					Purge_Logs
					echo "[i] Log Size Set To ${logsize}MB"
				fi
			else
				echo "[*] $3 Is Not A Valid Size - Must Be Numeric"
				exit 2
			fi
		;;
	esac
}

Settings_TrafficFilter() {
	case "$3" in
		all) trafficfiltermessage="Inbound & Outbound Filtering Enabled" ;;
		inbound) trafficfiltermessage="Inbound Filtering Enabled" ;;
		outbound) trafficfiltermessage="Outbound Filtering Enabled" ;;
		*) Command_Not_Recognized ;;
	esac
	Check_Lock "$@"
	Require_Running
	Purge_Logs
	trafficfilterold="$filtertraffic"
	Acquire_Firewall_Lock || exit 1
	Unload_LogIPTables
	if ! Unload_IOT_Rules; then
		Load_LogIPTables || Log error -s "Failed To Restore Logging Rules"
		echo "[*] Failed To Unload IoT Firewall Rules"; echo; exit 1
	fi
	Unload_IPTables
	filtertraffic="$3"
	if Load_IPTables && Load_IOT_Rules && Load_LogIPTables; then
		Release_Firewall_Lock
		echo "[i] $trafficfiltermessage"
		return 0
	fi
	Unload_LogIPTables
	Unload_IOT_Rules 2>/dev/null
	Unload_IPTables
	filtertraffic="$trafficfilterold"
	if ! Load_IPTables || ! Load_IOT_Rules || ! Load_LogIPTables; then
		Log error -s "Failed To Restore Previous Firewall Rules"
	fi
	echo "[*] Failed To Update Traffic Filtering - Previous Setting Restored"
	echo
	exit 1
}

Settings_UnbanPrivate() {
	case "$3" in
		enable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			unbanprivateip="enabled"
			echo "[i] Unban Private IP Enabled"

		;;
		disable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			unbanprivateip="disabled"
			echo "[i] Unban Private IP Disabled"
		;;
		*)
			Command_Not_Recognized
		;;
	esac
}

Settings_AiProtect() {
	case "$3" in
		enable)
			Check_Lock "$@"
			Require_Running
			Require_Connection
			Purge_Logs
			banaiprotectold="$banaiprotect"
			banaiprotect="enabled"
			if ! Refresh_AiProtect; then
				banaiprotect="$banaiprotectold"
				echo "[*] Failed To Import AiProtection Data"; echo; exit 1
			fi
			echo "[i] Import AiProtect Data Enabled"
		;;
		disable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			banaiprotect="disabled"
			Remove_IPSet_Entries Skynet-Blacklist "BanAiProtect" || { echo; exit 1; }
			echo "[i] Import AiProtect Data Disabled"
		;;
		*)
			Command_Not_Recognized
		;;
	esac
	echo "[i] Saving Changes"
	Require_Save_IPSets
}

Settings_SecureMode() {
	case "$3" in
		enable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			securemode="enabled"
			Check_Security
			echo "[i] Secure Mode Enabled"
		;;
		disable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			securemode="disabled"
			echo "[i] Secure Mode Disabled"
		;;
		*)
			Command_Not_Recognized
		;;
	esac
}

Settings_ExtendedStats() {
	case "$3" in
		enable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			extendedstats="enabled"
			Check_Security
			echo "[i] Extended Statistics Enabled"
		;;
		disable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			extendedstats="disabled"
			echo "[i] Extended Statistics Disabled"
		;;
		*)
			Command_Not_Recognized
		;;
	esac
}

Settings_Syslog() {
	Check_Lock "$@"
	Require_Running
	if [ "$#" -lt 3 ] || [ "$#" -gt 4 ] || { [ "$2" = "syslog1" ] && [ "$#" -ne 3 ]; }; then
		echo "[*] Use settings syslog auto Or settings syslog <file> [rotated-file]"; echo; exit 2
	fi
	case "$3" in
		auto|default)
			[ "$#" -eq 3 ] || { echo "[*] Automatic Syslog Does Not Accept File Paths"; echo; exit 2; }
			syslogmode="auto"
			Resolve_Syslog_Sources
		;;
		*)
			syslognew="$syslogloc"; syslognewarchive="$syslog1loc"
			if [ "$2" = "syslog1" ]; then syslognewarchive="$3"
			else syslognew="$3"; [ "$#" -ne 4 ] || syslognewarchive="$4"; fi
			if ! Validate_Syslog_Path "$syslognew" || ! Validate_Syslog_Path "$syslognewarchive" || [ "$syslognew" = "$syslognewarchive" ]; then
				echo "[*] Invalid Syslog Paths - Use Different Absolute Files In Existing Directories"; echo; exit 2
			fi
			syslogmode="custom"
			syslogloc="$syslognew"; syslog1loc="$syslognewarchive"
			unset "syslognew" "syslognewarchive"
		;;
	esac
	echo "[i] Syslog Source ($syslogmode): $syslogloc"
	echo "[i] Rotated Syslog: $syslog1loc"
}

Settings_IOT() {
	Check_Lock "$@"
	Require_Running
	if [ -z "$3" ]; then echo "[*] Option Not Specified - Exiting"; echo; exit 2; fi
	case "$3" in
		enable)
			Set_IOT_Blocking "enabled" || { echo; exit 1; }
			echo "[i] IoT WAN Blocking Enabled"
		;;
		disable)
			Set_IOT_Blocking "disabled" || { echo; exit 1; }
			echo "[i] IoT WAN Blocking Disabled - Device List Preserved"
		;;
		unban)
			iotlist="$(Normalize_Arguments_From 4 "$@")" || { echo "[*] Device List Can't Be Empty"; echo; exit 2; }
			for iotentry in $iotlist; do
				if ! printf '%s\n' "$iotentry" | Is_IPRange; then echo "[*] $iotentry Is Not A Valid IP/Range"; echo; exit 2; fi
			done
			Update_IPSet_Batch del Skynet-IOT "" "$iotlist" || { echo; exit 1; }
			if ! Prune_IOT_Device_Logs "$iotlist"; then
				Save_IPSets || Log error -s "Failed To Save Removed IoT Devices"
				Log error -s "IoT Devices Removed - Failed To Prune Device Logs"
				return 1
			fi
			echo "[i] IoT Device List Updated"
		;;
		ban)
			iotlist="$(Normalize_Arguments_From 4 "$@")" || { echo "[*] Device List Can't Be Empty"; echo; exit 2; }
			for iotentry in $iotlist; do
				if ! printf '%s\n' "$iotentry" | Is_IPRange; then echo "[*] $iotentry Is Not A Valid IP/Range"; echo; exit 2; fi
			done
			desc="$(date +"%b %e %T")"
			Update_IPSet_Batch add Skynet-IOT "IOTBan: $desc" "$iotlist" || { echo; exit 1; }
			echo "[i] IoT Device List Updated"
		;;
		view)
			Display_Header "6"
			iotviewneighbors="$TMP_DIR/iot-view-neighbors.$$"
			ip neigh 2>/dev/null \
				| grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3} ' \
				| sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 \
				> "$iotviewneighbors"
			Prepare_Client_Name_Data "$iotviewneighbors" || :
			while IFS=' ' read -r ipaddr _neighcommand _neighdevice _neighlabel macaddr _neighstate _neighrest; do
				Resolve_Client_Name
				if ipset test Skynet-IOT "$ipaddr" >/dev/null 2>&1; then
					if Is_Enabled "$iotblocked"; then
						state="$(Ylow Blocked)"
					else
						state="$(Ylow Paused)"
					fi
				elif ! printf '%s\n' "$macaddr" | Is_MAC; then
					macaddr="Unknown"
					state="$(Red Offline)"
				else
					state="$(Grn Unblocked)"
				fi
				printf '║ %-40s ║ %-16s ║ %-20s ║ %-20s ║\n' "$localname" "$ipaddr" "$macaddr" "$state"
			done < "$iotviewneighbors"
			Clear_Client_Name_Data
			rm -f "$iotviewneighbors"
			unset "iotviewneighbors" "_neighcommand" "_neighdevice" "_neighlabel" "_neighstate" "_neighrest" "ipaddr" "macaddr" "state" "localname"
			printf '╚══════════════════════════════════════════╩══════════════════╩══════════════════════╩══════════════════════╝\n'
			echo;echo
			case "$iotports" in
				"")
					echo "Allowed Ports: $(Grn "UDP/123 (NTP Time Sync - Default)")"
				;;
				none)
					echo "Allowed Ports: $(Grn "None")"
				;;
				*)
					echo "Allowed Traffic Protocols: $(Grn "$iotproto")"
					echo "Allowed Ports: $(Grn "$iotports")"
				;;
			esac
		;;
		ports)
			case "$4:$#" in
				default:4|reset:4) iotnewports=""; iotnewproto="udp" ;;
				none:4) iotnewports="none"; iotnewproto="$iotproto" ;;
				*)
					iotnewproto="$iotproto"
					iotnewports="$(Normalize_Arguments_From 4 "$@")" || { echo "[*] Port List Can't Be Empty"; echo; exit 2; }
				iotportcount="0"
				for port in $iotnewports; do
					if ! printf '%s\n' "$port" | Is_Port; then echo "[*] $port Is Not A Valid Port"; echo; exit 2; fi
					iotportcount=$((iotportcount + 1))
				done
				if [ "$iotportcount" -gt "15" ]; then echo "[*] A Maximum Of 15 Ports Can Be Configured"; echo; exit 2; fi
				;;
			esac
			Set_IOT_Rule_Options "$iotnewports" "$iotnewproto" || { echo; exit 1; }
			case "$iotnewports" in
				"") echo "[i] IoT Allowed Ports Set To UDP/123 For NTP Time Sync" ;;
				none) echo "[i] All IoT WAN Ports Blocked" ;;
				*) echo "[i] IoT Allowed Ports Updated" ;;
			esac
		;;
		proto)
			case "$4:$#" in
				udp:4|tcp:4|all:4) iotnewproto="$4" ;;
				*) echo "[*] Protocol Must Be udp, tcp Or all"; echo; exit 2 ;;
			esac
			case "$iotports" in
				"")
					# Selecting a protocol converts the default NTP rule into an explicit
					# custom port 123 policy.
					iotnewports="123"
				;;
				none)
					echo "[*] Configure Custom Ports Before Selecting A Protocol"
					echo
					exit 2
				;;
				*) iotnewports="$iotports" ;;
			esac
			Set_IOT_Rule_Options "$iotnewports" "$iotnewproto" || { echo; exit 1; }
			echo "[i] IoT Allowed Protocol Set To $iotnewproto"
		;;
		*)
			Command_Not_Recognized
		;;
	esac
	if [ "$3" != "view" ]; then
		echo "[i] Saving Changes"
		Save_IPSets || { echo "[*] Failed To Save IoT Device List"; echo; exit 1; }
	fi
}

Settings_IOTLogging() {
	case "$3" in
		enable)
			Check_Lock "$@"
	Require_Running
	Purge_Logs
	iotloggingold="$iotlogging"
	Acquire_Firewall_Lock || exit 1
	Unload_LogIPTables
			iotlogging="enabled"
			if ! Load_LogIPTables; then
				Unload_LogIPTables
				iotlogging="$iotloggingold"
				Load_LogIPTables || Log error -s "Failed To Restore IoT Logging Rules"
				echo "[*] Failed To Enable IoT Block Logging"; echo; exit 1
			fi
			Release_Firewall_Lock
			echo "[i] IoT Block Logging Enabled"
		;;
		disable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			iotloggingold="$iotlogging"
			Acquire_Firewall_Lock || exit 1
			Unload_LogIPTables
			iotlogging="disabled"
			if ! Load_LogIPTables; then
				Unload_LogIPTables
				iotlogging="$iotloggingold"
				Load_LogIPTables || Log error -s "Failed To Restore IoT Logging Rules"
				echo "[*] Failed To Disable IoT Block Logging"; echo; exit 1
			fi
			Release_Firewall_Lock
			echo "[i] IoT Block Logging Disabled"
		;;
		*)
			Command_Not_Recognized
		;;
	esac
}

Settings_CountryLookup() {
	case "$3" in
		enable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			lookupcountry="enabled"
			echo "[i] Country Lookups For Stat Data Enabled"
		;;
		disable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			lookupcountry="disabled"
			echo "[i] Country Lookups For Stat Data Disabled"
		;;
		*)
			Command_Not_Recognized
		;;
	esac
}

Settings_CDNWhitelist() {
	case "$3" in
		enable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			cdnwhitelistold="$cdnwhitelist"
			cdnwhitelist="enabled"
			if ! Whitelist_CDN; then
				cdnwhitelist="$cdnwhitelistold"
				echo "[*] Failed To Enable CDN Whitelisting - Existing Entries Retained"; echo; exit 1
			fi
			Require_Save_IPSets
			echo "[i] CDN Whitelisting Enabled"
		;;
		disable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			cdnwhitelistold="$cdnwhitelist"
			cdnwhitelist="disabled"
			if ! Whitelist_CDN; then
				cdnwhitelist="$cdnwhitelistold"
				echo "[*] Failed To Disable CDN Whitelisting"; echo; exit 1
			fi
			Require_Save_IPSets
			echo "[i] CDN Whitelisting Disabled"
		;;
		*)
			Command_Not_Recognized
		;;
	esac
}

Settings_WebUI() {
	case "$3" in
		enable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			if Addon_API_Supported; then
				displaywebui="enabled"
				Install_WebUI_Page || { displaywebui="disabled"; echo; exit 1; }
				echo "[i] WebUI Enabled"
				echo "[i] Generating Stats"
				Generate_Stats
			else
				echo "[*] Firmware Version Not Supported - Please Update To Use This Feature"
				exit 2
			fi
		;;
		disable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			Uninstall_WebUI_Page
			displaywebui="disabled"
			echo "[i] WebUI Disabled"
		;;
		*)
			Command_Not_Recognized
		;;
	esac
}

Settings_Unknown() {
	Command_Not_Recognized
}

Dispatch_Settings() {
	case "$2" in
		autoupdate) Settings_AutoUpdate "$@" ;;
		banmalware) Settings_MalwareSchedule "$@" ;;
		logmode) Settings_LogMode "$@" ;;
		loginvalid) Settings_InvalidLogging "$@" ;;
		logsize) Settings_LogSize "$@" ;;
		filter) Settings_TrafficFilter "$@" ;;
		unbanprivate) Settings_UnbanPrivate "$@" ;;
		banaiprotect) Settings_AiProtect "$@" ;;
		securemode) Settings_SecureMode "$@" ;;
		extendedstats) Settings_ExtendedStats "$@" ;;
		syslog|syslog1) Settings_Syslog "$@" ;;
		iot) Settings_IOT "$@" ;;
		iotlogging) Settings_IOTLogging "$@" ;;
		lookupcountry) Settings_CountryLookup "$@" ;;
		cdnwhitelist) Settings_CDNWhitelist "$@" ;;
		webui) Settings_WebUI "$@" ;;
		*) Settings_Unknown "$@" ;;
	esac
	settingscommandstatus="$?"
	[ "$settingscommandstatus" = "0" ] || return "$settingscommandstatus"
	settingsactionarea="settings"
	settingsactiontarget="$2"
	settingsactiontype="value"
	settingsactionoperation="update"
	settingsactionentries="$3"
	settingsactiondetail=""
	case "$2:$3" in
		iot:view) return 0 ;;
		iot:enable|iotlogging:enable) settingsactionarea="iot"; settingsactionoperation="enable" ;;
		iot:disable|iotlogging:disable) settingsactionarea="iot"; settingsactionoperation="disable" ;;
		iot:ban) settingsactionarea="iot"; settingsactionoperation="add"; shift 3; settingsactionentries="$*" ;;
		iot:unban) settingsactionarea="iot"; settingsactionoperation="remove"; shift 3; settingsactionentries="$*" ;;
		iot:ports|iot:proto) settingsactionarea="iot"; shift 3; settingsactionentries="$*" ;;
		*:enable) settingsactionoperation="enable" ;;
		*:disable) settingsactionoperation="disable" ;;
		banmalware:*) settingsactiontype="schedule" ;;
		logsize:*) settingsactiontype="megabytes" ;;
		filter:*) settingsactiontype="direction" ;;
		syslog:*|syslog1:*)
			settingsactiontype="path"
			settingsactionentries="$syslogloc"
			if [ "$syslogmode" = "auto" ]; then settingsactiondetail="Automatic"; else settingsactiondetail="Custom"; fi
			settingsactiondetail="$settingsactiondetail; Rotated syslog: $syslog1loc"
		;;
	esac
	[ -n "$settingsactionentries" ] || settingsactionentries="$settingsactiontarget"
	Queue_Action success "$settingsactionarea" "$settingsactionoperation" "$settingsactiontarget" "$settingsactiontype" "$settingsactionentries" "$settingsactiondetail" \
		|| {
			# Enforcement already succeeded; retain its configuration even when
			# the action journal cannot accept the corresponding record.
			[ "$nocfg" = "1" ] || Write_Config || Log error -s "Failed To Save Committed Setting"
			nocfg="1"
			Log error -s "Failed To Queue Committed Setting Action"
			return 1
		}
}

Dispatch_WebUI() {
	SKYNET_ACTION_ORIGIN="webui"
	# Only this dispatcher publishes completion for the submitted request.
	# Worker and scheduled payloads cannot acknowledge an unrelated browser action.
	nocfg="1"
	nolog="2"
	webuiaction="${2%_*}"
	webuirequestid="${2##*_}"
	case "$webuirequestid" in ""|*[!0-9]*) webuirequestid=""; return 2 ;; esac
	[ "${#webuirequestid}" -le 32 ] || { webuirequestid=""; return 2; }
	[ -f /usr/sbin/helper.sh ] || return 1
	# shellcheck disable=SC1091
	. /usr/sbin/helper.sh
	# Snapshot Merlin's input once. A queued older service event must not apply
	# fields submitted by another tab; the event and payload carry the same ID.
	if ! cp -f "$_am_settings_path" "$TMP_DIR/webui-settings" \
		|| ! cmp -s "$_am_settings_path" "$TMP_DIR/webui-settings"; then
		settingsresult="busy"
		Publish_WebUI_Result
		return 1
	fi
	_am_settings_path="$TMP_DIR/webui-settings"
	if [ "$(am_settings_get skynet_request)" != "$webuirequestid" ]; then
		settingsresult="busy"
		Publish_WebUI_Result
		return 1
	fi
	# WebUI actions publish their own result payloads and remain silent in the
	# background service-event process.
	nolog="2"
	case "$webuiaction" in
		SkynetStats)
			Apply_WebUI_Stats
		;;
		SkynetSettings|apply)
			Apply_WebUI_Settings
		;;
		SkynetSettingsLoad|load)
			nocfg="1"
			settingsresult="success"
			Generate_WebUI_Settings
		;;
		SkynetBanMalware|banmalware)
			Apply_WebUI_Threat_Feeds
		;;
		SkynetCountries|countries)
			Apply_WebUI_Countries
		;;
		SkynetRules|rules)
			Apply_WebUI_Rules || commandfailed="$?"
		;;
		SkynetIOT|iot)
			Check_Lock "$@" || return 1
			Apply_WebUI_IOT || commandfailed="$?"
		;;
		*)
			Command_Not_Recognized
		;;
	esac
}

Select_Debug_Watch_Line() {
	debugwatchline="$1"
	case "$debugwatchline" in
		*INVALID*) debugwatchfield="DST"; debugwatchcolour="Blue" ;;
		*INBOUND*) debugwatchfield="SRC"; debugwatchcolour="Ylow" ;;
		*OUTBOUND*|*IOT*) debugwatchfield="DST"; debugwatchcolour="Red" ;;
		*) return 1 ;;
	esac
	case "$debugwatchmode" in
		ip) case "$debugwatchline" in *"=$debugwatchvalue "*) ;; *) return 1 ;; esac ;;
		port) case "$debugwatchline" in *"PT=$debugwatchvalue "*) ;; *) return 1 ;; esac ;;
	esac
}

Print_Debug_Watch_Line() {
	case "$debugwatchcolour" in
		Blue) Blue "$debugwatchline" ;;
		Ylow) Ylow "$debugwatchline" ;;
		*) Red "$debugwatchline" ;;
	esac
	Is_Enabled "$extendedstats" || return 0
	case "$debugwatchfield" in
		SRC) debugwatchtoken=${debugwatchline#* SRC=} ;;
		DST) debugwatchtoken=${debugwatchline#* DST=} ;;
		*) return 0 ;;
	esac
	[ "$debugwatchtoken" = "$debugwatchline" ] && return 0
	debugwatchtoken=${debugwatchtoken%% *}
	debugwatchip=${debugwatchtoken%%,*}
	[ -n "$debugwatchip" ] || return 0
	# Limit the live enrichment scan to the newest 100 dnsmasq records.
	debugwatchdomains="$(tail -n 100 /opt/var/log/dnsmasq.log 2>/dev/null \
		| awk -v ip="$debugwatchip" '/reply / && index($0, " is " ip) { print $(NF-2) }' \
		| Strip_Domain | Filter_OutIP | xargs)"
	[ -z "$debugwatchdomains" ] || Red "Associated Domain(s) - [$debugwatchdomains]"
}

Debug_Watch() {
	Require_Running
	if [ "$logmode" = "disabled" ]; then echo "[*] Logging Is Disabled - Exiting!"; echo; exit 2; fi
	debugwatchmode="$3"
	debugwatchvalue="$4"
	case "$debugwatchmode" in
		ip)
			printf '%s\n' "$debugwatchvalue" | Is_IP || { echo "[*] $debugwatchvalue Is Not A Valid IP"; echo; exit 2; }
			echo "[i] Filtering Entries Involving IP $debugwatchvalue"
		;;
		port)
			printf '%s\n' "$debugwatchvalue" | Is_Port || { echo "[*] $debugwatchvalue Is Not A Valid Port"; echo; exit 2; }
			echo "[i] Filtering Entries Involving Port $debugwatchvalue"
		;;
		*) debugwatchmode="all" ;;
	esac
	trap 'echo;echo;echo "[*] Interrupted"; break; Purge_Logs' INT
	echo "[i] Watching Syslog For Log Entries (ctrl +c) To Stop"
	echo
	Purge_Logs
	tail -F "$syslogloc" | while IFS= read -r debugwatchline; do
		Select_Debug_Watch_Line "$debugwatchline" || continue
		Print_Debug_Watch_Line
	done
	Set_Cleanup_Traps
	nocfg="1"
}

Debug_Info() {
	debugpublicip="$(nvram get wan0_ipaddr)"
	if Read_Active_Lock; then
		echo
		Red "[*] Lock File Detected ($lockstatuscommand) (pid=$lockstatuspid, runtime=${lockstatusruntime}s)"
		Ylow '[*] Locked Processes Generally Take 1-2 Minutes To Complete And May Result In Temporarily "Failed" Tests'
	fi
	unset "lockstatuscommand" "lockstatuspid" "lockstatusepoch" "lockstatusruntime"
	printf '╔═════════════════════ System ══════════════════════════════════════════════════════════════════════════════╗\n'
	printf '║ %-20s │ %-82s ║\n' "Router Model"   "$(nvram get productid)"
	printf '║ %-20s │ %-82s ║\n' "Skynet Version" "$localver ($(Filter_Date < "$0"))"
	printf '║ └── %-16s │ %-82s ║\n' "Hash" "$(md5sum "$0" | awk "{print \$1}")"
	printf '║ %-20s │ %-82s ║\n' "FW Version"     "$(uname -o) v$(nvram get buildno)_$(nvram get extendno) (Kernel $(uname -r)) ($(uname -v | awk "{printf \"%s %s %s\n\", \$5,\$6,\$9}"))"
	printf '║ %-20s │ %-82s ║\n' "iptables"       "$(iptables --version)"
	printf '║ %-20s │ %-82s ║\n' "ipset"          "$(ipset -v 2>/dev/null | head -n1)"
	if printf '%s\n' "$debugpublicip" | Is_PrivateIP; then debugpublicipdisplay="$(Red "$debugpublicip")"; else debugpublicipdisplay="$debugpublicip"; fi
	printf '║ %-20s │ %-82s ║\n' "Public IP"      "$debugpublicipdisplay"
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
	debugmemory="$(awk '
		/MemTotal:/ { total=$2 }
		/MemAvailable:/ { available=$2; found=1 }
		/MemFree:/ { free=$2 }
		END { if (!found) available=free; printf "%d %d", available / 1024, total / 1024 }
	' /proc/meminfo)"
	memavailable="${debugmemory%% *}"
	totalmem="${debugmemory#* }"
	printf '║ %-20s │ %-82s ║\n' "RAM Available/Total" "(${memavailable}M / ${totalmem}M)"
	printf '╚══════════════════════╧════════════════════════════════════════════════════════════════════════════════════╝\n\n\n'
	printf '╔═════════════════════ Lifecycle ═══════════════════════════════════════════════════════════════════════════╗\n'
	if Time_Is_Ready; then debugtimestatus="Ready"; else debugtimestatus="Pending"; fi
	printf '║ %-20s │ %-82s ║\n' "Router Time" "$debugtimestatus"
	if ! Is_Enabled "$logmode"; then
		debugloggingstatus="Disabled"
	elif iptables-save 2>/dev/null | grep -qF '[BLOCKED -'; then
		debugloggingstatus="Active"
	else
		debugloggingstatus="Pending"
	fi
	printf '║ %-20s │ %-82s ║\n' "Packet Logging" "$debugloggingstatus"
	debugtemporarycount="$(ipset list Skynet-TemporaryBans 2>/dev/null | awk -F ': ' '/^Number of entries:/ {print $2; exit}')"
	case "$debugtemporarycount" in ""|*[!0-9]*) debugtemporarycount="0" ;; esac
	if Time_Dependent_State_Pending; then debugtemporarystatus="$debugtemporarycount active; restoration pending"
	else debugtemporarystatus="$debugtemporarycount active"; fi
	printf '║ %-20s │ %-82s ║\n' "Temporary Rules" "$debugtemporarystatus"
	debugnextexpiry="$(awk -F '\t' -v now="$(date +%s)" '$1 == "R2" && $9 > now && (!expiry || $9 < expiry) {expiry=$9} END {print expiry + 0}' "$skynetrules" 2>/dev/null)"
	if [ "$debugnextexpiry" -gt "0" ] 2>/dev/null; then debugnextexpirydisplay="$(Format_Threat_Feed_Time "$debugnextexpiry")"
	else debugnextexpirydisplay="None"; fi
	printf '║ %-20s │ %-82s ║\n' "Next Expiry" "$debugnextexpirydisplay"
	if Validate_Rule_Registry "$skynetrules"; then debugregistrystatus="R2 valid"
	else debugregistrystatus="Invalid"; fi
	Rule_Migration_Complete || debugregistrystatus="$debugregistrystatus; migration pending"
	printf '║ %-20s │ %-82s ║\n' "Rule Registry" "$debugregistrystatus"
	debugmaintenancestatus="Not run since startup"
	if IFS="$(printf '\t')" read -r debugmaintenanceversion debugmaintenanceepoch debugmaintenanceresult debugmaintenancedetail 2>/dev/null < "$MAINTENANCE_STATUS" \
		&& [ "$debugmaintenanceversion" = "M1" ]; then
		if [ "$debugmaintenanceepoch" -gt "0" ] 2>/dev/null; then debugmaintenancetime="$(Format_Threat_Feed_Time "$debugmaintenanceepoch")"
		else debugmaintenancetime="time pending"; fi
		debugmaintenancestatus="$debugmaintenanceresult ($debugmaintenancedetail; $debugmaintenancetime)"
	fi
	printf '║ %-20s │ %-82s ║\n' "Maintenance" "$debugmaintenancestatus"
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
	printf '║ %-20s │ %-84s ║\n' "Monitor Span"      "$monitorspan"
	printf '╚══════════════════════╧════════════════════════════════════════════════════════════════════════════════════╝\n\n\n'
	passedtests="0"
	totaltests="18"
	Display_Header "6"
	debugneighbors="$TMP_DIR/debug-neighbors.$$"
	ip neigh 2>/dev/null \
	| grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3} ' \
	| sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 \
	> "$debugneighbors"
	Prepare_Client_Name_Data "$debugneighbors" || :
	while IFS=' ' read -r ipaddr _neighcommand _neighdevice _neighlabel macaddr state _neighrest; do
		Resolve_Client_Name

		if ! printf '%s\n' "$macaddr" | Is_MAC; then
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
	done < "$debugneighbors"
	Clear_Client_Name_Data
	rm -f "$debugneighbors"
	unset "debugneighbors"
	printf '╚══════════════════════════════════════════╩══════════════════╩══════════════════════╩══════════════════════╝\n\n\n'
	Display_Header "7"
	printf "║ %-33s ║ " "Internet Connectivity"
	if Check_Connection >/dev/null 2>&1; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
	printf '%-80s ║\n' "$result"
	printf "║ %-33s ║ " "Public IP Address"
	publicip="$debugpublicip"
	if printf '%s\n' "$publicip" | Is_IP && ! printf '%s\n' "$publicip" | Is_PrivateIP; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
	printf '%-80s ║\n' "$result"
	printf "║ %-33s ║ " "Write Permission"
	if [ -w "${skynetloc}" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
	printf '%-80s ║\n' "$result"
	printf "║ %-33s ║ " "Config File"
	if [ -f "${skynetcfg}" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
	printf '%-80s ║\n' "$result"
	debugfirewallstarthook="sh /jffs/scripts/firewall start skynetloc=${skynetloc} # Skynet"
	debugservicesstophook='sh /jffs/scripts/firewall persist # Skynet'
	debugserviceeventhook="case \"\$1:\$2\" in start:Skynet*) sh /jffs/scripts/firewall webui \"\$2\" ;; esac # Skynet"
	printf "║ %-33s ║ " "Firewall-Start Entry"
	if Check_Skynet_Hook /jffs/scripts/firewall-start "$debugfirewallstarthook"; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
	printf '%-80s ║\n' "$result"
	printf "║ %-33s ║ " "Services-Stop Entry"
	if Check_Skynet_Hook /jffs/scripts/services-stop "$debugservicesstophook"; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
	printf '%-80s ║\n' "$result"
	printf "║ %-33s ║ " "Service-Event Entry"
	if Check_Skynet_Hook /jffs/scripts/service-event "$debugserviceeventhook"; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
	printf '%-80s ║\n' "$result"
	unset "debugfirewallstarthook" "debugservicesstophook" "debugserviceeventhook"
	printf "║ %-33s ║ " "Profile.add Entry"
	if grep -qE '^[[:space:]]*[^#].*# Skynet' /jffs/configs/profile.add; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
	printf '%-80s ║\n' "$result"
	printf "║ %-33s ║ " "SWAP File"
	if Check_Swap; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"
	elif ! Swap_Required; then result="$(Grn "[Optional]")"; passedtests="$((passedtests + 1))"
	else result="$(Red "[Failed]")"; fi
	printf '%-80s ║\n' "$result"
	printf "║ %-33s ║ " "Cron Jobs"
	if [ "$(cru l | grep -c "Skynet")" -ge "2" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
	printf '%-80s ║\n' "$result"
	printf "║ %-33s ║ " "NTP Sync"
	if [ "$(nvram get ntp_ready)" = "1" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
	printf '%-80s ║\n' "$result"
	debugmessageloglevel="$(nvram get message_loglevel)"
	debugloglevel="$(nvram get log_level)"
	printf "║ %-33s ║ " "Log Level $debugmessageloglevel Settings"
	if [ "$debugmessageloglevel" -le "$debugloglevel" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
	printf '%-80s ║\n' "$result"
	debugiptablesfail=""
	if Check_IPTables duplicates; then debugiptablespassed="1"; else debugiptablespassed="0"; debugiptablesfail="$fail"; fi
	printf "║ %-33s ║ " "Duplicate Rules In RAW"
	if [ "$checkrawduplicates" = "0" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
	printf '%-80s ║\n' "$result"
	printf "║ %-33s ║ " "IPSets"
	debugipsetfail=""
	if Check_IPSets; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; debugipsetfail="$fail"; fi
	printf '%-80s ║\n' "$result"
	printf "║ %-33s ║ " "Firewall Rules"
	if [ "$debugiptablespassed" = "1" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
	printf '%-80s ║\n' "$result"
	fail="${debugipsetfail}${debugiptablesfail}"
	if Is_Enabled "$displaywebui"; then
		printf "║ %-33s ║ " "Local WebUI Files"
		[ -f "${skynetloc}/webui/skynet.asp" ] || localfail="${localfail}skynet.asp "
		[ -f "${skynetloc}/webui/stats.js" ] || localfail="${localfail}stats.js "
		[ -f "${skynetloc}/webui/settings.js" ] || localfail="${localfail}settings.js "
		if [ -z "$localfail" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
		printf '%-80s ║\n' "$result"
		printf "║ %-33s ║ " "Mounted WebUI Files"
		Find_WebUI_Page "${skynetloc}/webui/skynet.asp" 2>/dev/null
		[ -f "/www/user/${MyPage}" ] || mountedfail="${mountedfail}skynet.asp "
		[ -f "/www/user/skynet/stats.js" ] || mountedfail="${mountedfail}stats.js "
		[ -f "/www/user/skynet/settings.js" ] || mountedfail="${mountedfail}settings.js "
		if [ -z "$mountedfail" ]; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
		printf '%-80s ║\n' "$result"
		printf "║ %-33s ║ " "MenuTree.js Entry"
		if grep -qF "Skynet" "/www/require/modules/menuTree.js"; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
		printf '%-80s ║\n' "$result"
	else
		totaltests="$((totaltests - 3))"
	fi
	printf '╠═══════════════════════════════════╩═══════════════════════════════════════════════════════════════════════╣\n'
	printf '║ %-105s ║\n' "${passedtests}/${totaltests} Tests Successful"
	printf '╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n\n\n'
	Display_Header "8"
	Display_Settings_Category "Updates & Lists" first
	printf '║ %-33s ║ %-80s ║\n' "Skynet Auto-Updates" "$(if Is_Enabled "$autoupdate"; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
	case "$banmalwareupdate" in
		daily) malwareupdatestatus="$(Grn "[Daily]")" ;;
		weekly) malwareupdatestatus="$(Grn "[Weekly]")" ;;
		*) malwareupdatestatus="$(Red "[Disabled]")" ;;
	esac
	printf '║ %-33s ║ %-80s ║\n' "Malware List Auto-Updates" "$malwareupdatestatus"
	Display_Settings_Category "Protection"
	case "$filtertraffic" in
		all) filtertrafficstatus="$(Grn "[Inbound & Outbound]")" ;;
		inbound) filtertrafficstatus="$(Ylow "[Inbound Only]")" ;;
		outbound) filtertrafficstatus="$(Ylow "[Outbound Only]")" ;;
		*) filtertrafficstatus="$(Red "[Unknown]")" ;;
	esac
	printf '║ %-33s ║ %-80s ║\n' "Traffic Filtering" "$filtertrafficstatus"
	printf '║ %-33s ║ %-80s ║\n' "Unban Private IPs" "$(if Is_Enabled "$unbanprivateip"; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
	printf '║ %-33s ║ %-80s ║\n' "Import AiProtection Bans" "$(if Is_Enabled "$banaiprotect"; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
	printf '║ %-33s ║ %-80s ║\n' "Secure Mode" "$(if Is_Enabled "$securemode"; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
	printf '║ %-33s ║ %-80s ║\n' "CDN Whitelisting" "$(if Is_Enabled "$cdnwhitelist"; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
	Display_Settings_Category "IoT Isolation"
	printf '║ %-33s ║ %-80s ║\n' "IoT WAN Blocking" "$(if Is_Enabled "$iotblocked"; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
	printf '║ %-33s ║ %-80s ║\n' "IoT Block Logging" "$(if Is_Enabled "$iotlogging"; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
	case "$iotports" in
		"") iotallowedstatus="$(Grn "[UDP 123 - NTP Default]")" ;;
		none) iotallowedstatus="$(Ylow "[None]")" ;;
		*)
			case "$iotproto" in udp) iotprotolabel="UDP" ;; tcp) iotprotolabel="TCP" ;; all) iotprotolabel="TCP & UDP" ;; *) iotprotolabel="Unknown" ;; esac
			iotportdisplay="$iotports"
			[ "${#iotportdisplay}" -le "55" ] || iotportdisplay="$(printf '%.54s+' "$iotportdisplay")"
			iotallowedstatus="$(Grn "[$iotprotolabel - $iotportdisplay]")"
		;;
	esac
	printf '║ %-33s ║ %-80s ║\n' "Allowed Internet Traffic" "$iotallowedstatus"
	Display_Settings_Category "Logging & Statistics"
	printf '║ %-33s ║ %-80s ║\n' "Logging" "$(if Is_Enabled "$logmode"; then Grn "[Enabled]"; else Red "[Disabled]"; fi)"
	printf '║ %-33s ║ %-80s ║\n' "Invalid Packet Logging" "$(if Is_Enabled "$loginvalid"; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
	printf '║ %-33s ║ %-80s ║\n' "Log Size" "$(Grn "[${logsize}MB]")"
	printf '║ %-33s ║ %-80s ║\n' "Extended Statistics" "$(if Is_Enabled "$extendedstats"; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
	printf '║ %-33s ║ %-80s ║\n' "Log Source" "$(if [ "$syslogmode" = "auto" ]; then Grn "[Automatic]"; else Ylow "[Custom]"; fi)"
	printf '║ %-33s ║ %-80s ║\n' "Country Lookup" "$(if Is_Enabled "$lookupcountry"; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
	Display_Settings_Category "Integration & Advanced"
	printf '║ %-33s ║ %-80s ║\n' "WebUI" "$(if Is_Enabled "$displaywebui"; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
	printf '╚═══════════════════════════════════╩═══════════════════════════════════════════════════════════════════════╝\n'
	if [ -n "$fail" ]; then echo;echo "[*] Rule Integrity Violation - [ ${fail}]"; unset fail; fi
	if [ -n "$localfail" ]; then echo;echo "[*] Local File Missing - [ ${localfail}]"; fi
	if [ -n "$mountedfail" ]; then echo;echo "[*] Mounted File Missing - [ ${mountedfail}]"; fi
	if [ "$3" = "extended" ]; then echo;echo; cat "$skynetcfg"; fi
	unset "malwareupdatestatus" "filtertrafficstatus" "iotallowedstatus" "iotprotolabel" "iotportdisplay" "localfail" "mountedfail"
	nocfg="1"
}

Debug_Generate_Stats() {
	if ! Is_Enabled "$logmode"; then
		echo "[*] Statistics Require Logging - To Enable Use ( sh $0 settings logmode enable )"
		return 2
	fi
	Check_Lock "$@" || return 1
	Purge_Logs "all" || return 1
	if Addon_API_Supported; then
		if Is_Enabled "$displaywebui"; then
			echo "[i] Generating Stats For WebUI"
			Generate_Stats
		else
			echo "[*] WebUI Is Currently Disabled - To Enable Use ( sh $0 settings webui enable )"
			return 1
		fi
	else
		return 1
	fi
}

Debug_Clean() {
	echo "[i] Cleaning Syslog Entries"
	Purge_Logs "all"
	sed -i '\~Skynet: \[%\] ~d' "$syslog1loc" "$syslogloc" 2>/dev/null
	echo "[i] Complete!"
	echo
	nolog="2"
	nocfg="1"
}

Debug_Swap() {
	case "$3" in
		install)
			Check_Lock "$@"
			Maintain_Script_Hooks firewall-start services-stop service-event post-mount unmount || { echo "[*] Failed To Maintain Script Hooks"; echo; exit 1; }
			Clean_Legacy_WebUI_Files || { echo "[*] Failed To Remove Legacy WebUI Files"; echo; exit 1; }
			swaplocation="$(awk 'NR==2 { print $1 }' /proc/swaps)"
			if [ -z "$swaplocation" ] && ! Check_Swap; then
				Manage_Device
				Create_Swap || return 1
				nolog="2"
			else
				echo "[*] Pre-existing SWAP File Detected - Exiting!"
			fi
		;;
		uninstall)
			Check_Lock "$@"
			Remove_Swap || return 1
			nolog="2"
		;;
		*)
			Command_Not_Recognized
		;;
	esac
}

Debug_Backup() {
	Check_Lock "$@"
	Require_Running
	Purge_Logs || return 1
	echo "[i] Saving Changes"
	Require_Save_IPSets
	echo "[i] Backing Up Skynet Related Files"
	echo
	set -- skynet.ipset skynet.log skynet.cfg
	[ ! -f "$skynetevents" ] || set -- "$@" events.log
	[ ! -f "$skynetrules" ] || set -- "$@" skynet.rules
	[ ! -d "${skynetloc}/lists" ] || set -- "$@" lists
	backuptmp="${skynetloc}/Skynet-Backup.tar.gz.tmp.$$"
	# Publish only a complete archive; failed writes never replace a good backup.
	if ! tar -czf "$backuptmp" -C "${skynetloc}" "$@" \
		|| ! tar -tzf "$backuptmp" >/dev/null || ! chmod 600 "$backuptmp" \
		|| ! mv -f "$backuptmp" "${skynetloc}/Skynet-Backup.tar.gz"; then
		rm -f "$backuptmp"
		echo "[*] Failed To Create Backup"; echo; return 1
	fi
	echo
	echo "[i] Backup Saved To ${skynetloc}/Skynet-Backup.tar.gz"
	echo "[i] Copy This File To A Safe Location"
}

Validate_Backup_Archive() {
	# Accept only regular data files and directories in the backup contract.
	# Reject links before extraction, including hard links and traversal paths.
	tar -tzf "$1" > "$TMP_DIR/backup-names.$$" 2>/dev/null \
		&& tar -tvzf "$1" > "$TMP_DIR/backup-types.$$" 2>/dev/null || return 1
	awk '
		/^skynet\.(cfg|ipset|log|rules)$/ || /^events\.log$/ {next}
		/^lists\/$/ || /^lists\/[A-Za-z0-9_.\/-]+$/ {
			if ($0 ~ /(^|\/)\.\.?(\/|$)/ || $0 ~ /\/\//) exit 1
			next
		}
		{exit 1}
	' "$TMP_DIR/backup-names.$$" \
		&& awk 'substr($0,1,1) != "-" && substr($0,1,1) != "d" {exit 1}' "$TMP_DIR/backup-types.$$" \
		&& grep -qxF skynet.cfg "$TMP_DIR/backup-names.$$" \
		&& grep -qxF skynet.ipset "$TMP_DIR/backup-names.$$"
}

Validate_Backup_Data() {
	backupvalidate="$1"
	# Config is sourced on startup. Accept only generated quoted assignments;
	# dollars, backticks, quotes and backslashes must be escaped within values.
	awk '
		BEGIN {
			n=split("model localver swaplocation blacklist1count blacklist2count customlisturl customlist2url banmalwarelastupdated countrylist excludelists autoupdate banmalwareupdate forcebanmalwareupdate filtertraffic unbanprivateip banaiprotect securemode cdnwhitelist iotblocked iotlogging iotports iotproto logmode loginvalid logsize extendedstats syslogmode syslogloc syslog1loc lookupcountry displaywebui fastswitch", keys, " ")
			for(i=1;i<=n;i++) allowed[keys[i]]=1
		}
		/^[[:space:]]*(#|$)/ {next}
		! /^[A-Za-z_][A-Za-z0-9_]*=".*"$/ {exit 1}
		{
			key=$0; sub(/=.*/, "", key); if(!allowed[key] || seen[key]++) exit 1
			sub(/^[^=]+="/, ""); sub(/"$/, "")
			for (i=1;i<=length($0);i++) {
				c=substr($0,i,1)
				if(c=="\\") {i++; if(i>length($0) || index("\\\"$`",substr($0,i,1))==0) exit 1}
				else if(index("\"$`",c)) exit 1
			}
		}
	' "$backupvalidate/skynet.cfg" || return 1
	awk '
		function reject() {bad=1; exit 1}
		# IPSet save quotes comments and escapes embedded quotes/backslashes.
		# Parse those separately from legacy per-entry numeric metadata.
		function valid_tail(text, key, value, i, char, count, closed) {
			while (text != "") {
				sub(/^[[:space:]]+/, "", text)
				if (text == "") return 1
				if (text !~ /^[a-z]+[[:space:]]+/) return 0
				key=text; sub(/[[:space:]].*/, "", key)
				sub(/^[a-z]+[[:space:]]+/, "", text)
				if (key == "comment") {
					if (substr(text,1,1) != "\"") return 0
					count=0; closed=0
					for (i=2;i<=length(text);i++) {
						char=substr(text,i,1)
						if (char == "\"") {closed=1; break}
						if (char == "\\") {i++; if (i>length(text) || index("\\\"",substr(text,i,1))==0) return 0}
						if (++count>255) return 0
					}
					if (!closed) return 0
					text=substr(text,i+1)
					if (text != "" && text !~ /^[[:space:]]/) return 0
				} else {
					value=text; sub(/[[:space:]].*/, "", value)
					if (key ~ /^(packets|bytes|timeout|skbqueue)$/) {if (value !~ /^[0-9]+$/) return 0}
					else if (key == "skbmark") {if (value !~ /^0x[0-9a-fA-F]+(\/0x[0-9a-fA-F]+)?$/) return 0}
					else if (key == "skbprio") {if (value !~ /^[0-9a-fA-F]+:[0-9a-fA-F]+$/) return 0}
					else return 0
					text=substr(text,length(value)+1)
				}
			}
			return 1
		}
		$1 != "create" && $1 != "add" {reject()}
		$2 !~ /^Skynet-(Blacklist|BlockedRanges|Whitelist|IOT|Master|MasterWL)$/ {reject()}
		NF < 3 {reject()}
		$1 == "create" {
			if (($2 ~ /^Skynet-Master/ && $3 != "list:set") \
				|| ($2 == "Skynet-Blacklist" && $3 != "hash:ip") \
				|| ($2 !~ /^Skynet-Master/ && $2 != "Skynet-Blacklist" && $3 != "hash:net")) reject()
			if (created[$2]++) reject()
			capacity[$2]=$3 == "list:set" ? 8 : 65536
			for(i=4;i<=NF;i++) {
				if ($i == "family") {i++; if ($i != "inet") reject()}
				else if ($i ~ /^(hashsize|maxelem|timeout|size|bucketsize|netmask)$/) {
					option=$i; i++
					if ($i !~ /^[0-9]+$/ || ($i == 0 && option != "timeout")) reject()
					if (option == "netmask" && $i > 32) reject()
					if (option == "maxelem" || option == "size") capacity[$2]=$i
				}
				else if ($i ~ /^(comment|counters|skbinfo|forceadd)$/) continue
				else reject()
			}
		}
		$1 == "add" {
			if (!created[$2] || ++entries[$2] > capacity[$2]) reject()
			if ($2 ~ /^Skynet-Master/ && $3 !~ /^Skynet-(Blacklist|BlockedRanges|Whitelist|IOT)$/) reject()
			if ($2 == "Skynet-Blacklist" && index($3,"/")) reject()
			tail=$0; sub(/^[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+/, "", tail)
			if (!valid_tail(tail)) reject()
		}
		END {
			if (bad || !created["Skynet-Blacklist"] || !created["Skynet-BlockedRanges"] \
				|| !created["Skynet-Whitelist"] || !created["Skynet-IOT"]) exit 1
		}
	' "$backupvalidate/skynet.ipset" || return 1
	awk '$1 == "add" && $2 !~ /^Skynet-Master/ {print $3}' "$backupvalidate/skynet.ipset" > "$TMP_DIR/backup-addresses.$$" || return 1
	Normalize_IPSet_Entries any < "$TMP_DIR/backup-addresses.$$" > "$TMP_DIR/backup-normalized.$$" || return 1
	if [ -f "$backupvalidate/skynet.rules" ]; then
		if Validate_Rule_Registry "$backupvalidate/skynet.rules"; then
			awk -F "\t" '$4 == "asn" || $4 == "import" {print $4 " " $10}' "$backupvalidate/skynet.rules" > "$TMP_DIR/backup-sidecars.$$" || return 1
			while read -r backupdatatype backupdataname; do
				Validate_Rule_Data_File "$backupvalidate/lists/rules/data/$backupdataname" \
					&& Validate_Rule_Data_Reference "$backupdatatype" "$backupdataname" "$backupvalidate/lists/rules/data/$backupdataname" || return 1
			done < "$TMP_DIR/backup-sidecars.$$"
		else
			Validate_Legacy_Rule_Registry "$backupvalidate/skynet.rules" || return 1
		fi
	fi
}

Restore_Backup_Policy() {
	# Separate work directories keep failed candidate sidecars out of recovery.
	# Nested domain transactions must finish before their parent restores files.
	mkdir -m 700 "$backuprestoredir/$1" || return 1
	TMP_DIR="$backuprestoredir/$1"
	unset customclientlistloaded clientcontextloaded rulevalidationactive rulevalidatedfiles
	backuprestoreresult="0"
	if ! Load_Config fresh || ! Restore_Startup_Policy; then
		backuprestoreresult="1"
	elif ! Ensure_Startup_Runtime || ! Write_Config; then
		backuprestoreresult="1"
	fi
	if [ "${domaintransactionactive:-0}" = "1" ]; then
		Rollback_Domain_Rule_Update || backuprestoreresult="1"
	fi
	TMP_DIR="$backuprestoretmp"
	return "$backuprestoreresult"
}

Rollback_Backup_Restore() {
	trap '' INT TERM
	backuprestoreactive="0"
	backuprestorestatus="0"
	# Copy rather than move the originals: a later kernel or filesystem failure
	# must leave a complete recovery copy, not only the components still pending.
	for backupitem in $backupreplaced; do
		if ! rm -rf "${skynetloc:?}/$backupitem"; then backuprestorestatus="1"; continue; fi
		if [ -e "$backuprestoredir/old/$backupitem" ] || [ -L "$backuprestoredir/old/$backupitem" ]; then
			cp -a "$backuprestoredir/old/$backupitem" "${skynetloc}/$backupitem" || backuprestorestatus="1"
		fi
	done
	if [ "$backuprestorestatus" = "0" ] && [ "$backuprestoretouched" = "1" ]; then
		if ! Unload_Skynet_Firewall_Rules || ! Unload_IPSets; then backuprestorestatus="1"
		elif [ "$backuprestorewasactive" = "1" ]; then
			Restore_Backup_Policy recovery || backuprestorestatus="1"
		else
			Load_Config fresh || backuprestorestatus="1"
		fi
	fi
	if [ "$backuprestorestatus" != "0" ]; then
		backuprestorepreserve="1"
		Log error -s "Backup Recovery Failed - Previous Files Retained ($backuprestoredir/old)"
	else
		rm -rf "$backuprestoredir" || backuprestorestatus="1"
	fi
	return "$backuprestorestatus"
}

Debug_Restore() {
	Check_Lock "$@"
	nocfg="1"
	nolog="2"
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
	Validate_Backup_Archive "$backuplocation" || { echo "[*] Backup Archive Is Invalid Or Contains Unsupported Files"; return 2; }
	backuprestoredir="${skynetloc}/.restore.$$"
	mkdir -m 700 "$backuprestoredir" "$backuprestoredir/new" "$backuprestoredir/old" || return 1
	# Extract away from live data. Existing action history is never rolled back.
	if ! tar -xzf "$backuplocation" -C "$backuprestoredir/new" \
		|| ! Validate_Backup_Data "$backuprestoredir/new"; then
		rm -rf "$backuprestoredir"
		echo "[*] Backup Data Is Invalid - Existing Installation Retained"
		return 2
	fi
	Purge_Logs || { rm -rf "$backuprestoredir"; return 1; }
	backuprestorewasactive="0"
	if Check_IPSets; then
		backuprestorewasactive="1"
		Save_IPSets || { rm -rf "$backuprestoredir"; return 1; }
	else
		backuprestoresets="$(ipset -n list 2>/dev/null)" || { rm -rf "$backuprestoredir"; return 1; }
		if printf '%s\n' "$backuprestoresets" | grep -q '^Skynet-'; then
			echo "[*] Existing IPSet Topology Is Incomplete - Repair Skynet Before Restoring A Backup"
			rm -rf "$backuprestoredir"
			return 1
		fi
	fi
	# Keep every previous component until synchronous policy and integration
	# checks complete. An interrupted restore follows the same recovery path.
	backuprestoretmp="$TMP_DIR"
	backuprestoretouched="0"
	backuprestoreactive="1"
	backupreplaced=""
	backupstatus="0"
	trap '' INT TERM
	for backupitem in skynet.cfg skynet.ipset skynet.log skynet.rules lists; do
		if { [ -e "${skynetloc}/$backupitem" ] || [ -L "${skynetloc}/$backupitem" ]; } && ! mv "${skynetloc}/$backupitem" "$backuprestoredir/old/$backupitem"; then backupstatus="1"; break; fi
		backupreplaced="$backupitem $backupreplaced"
		if [ -e "$backuprestoredir/new/$backupitem" ] && ! mv "$backuprestoredir/new/$backupitem" "${skynetloc}/$backupitem"; then backupstatus="1"; break; fi
	done
	if [ "$backupstatus" = "0" ]; then
		# Pending state forces concurrent firewall-start events through the state
		# lock rather than accepting the topology during replacement.
		if ! rm -f "$STARTUP_READY" || ! : > "$STARTUP_PENDING" || ! chmod 600 "$STARTUP_PENDING"; then backupstatus="1"
		else
			backuprestoretouched="1"
			if ! Unload_Skynet_Firewall_Rules || ! Unload_IPSets || ! Restore_Backup_Policy candidate; then backupstatus="1"; fi
		fi
	fi
	if [ "$backupstatus" != "0" ]; then
		if Rollback_Backup_Restore; then echo "[*] Backup Restore Failed - Previous Data And Policy Restored"; fi
		Set_Cleanup_Traps
		return 1
	fi
	backuprestoreactive="0"
	Set_Cleanup_Traps
	rm -rf "$backuprestoredir" || return 1
	echo
	echo "[i] Backup Restored"
	Queue_Action success system restore backup archive "Skynet-Backup.tar.gz" "Configuration and firewall data restored" \
		|| { Log error -s "Failed To Queue Restore Action"; return 1; }
}

Debug_Run() {
	Check_Lock "$@"
	func="$3"
	# Remove debug, run and the function name while retaining function arguments.
	shift 3

	# Only named functions defined by this script may be invoked.
	if grep -qE "^[[:space:]]*${func}[[:space:]]*\(\)" "$0"; then
		# Display the exact function invocation.
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
			commandfailed="$code"
		fi
	else
		echo "[!] Function ${func}() does not exist"
		commandfailed="2"
	fi
}

Debug_Unknown() {
	Command_Not_Recognized
}

Dispatch_Debug() {
	case "$2" in
		watch) Debug_Watch "$@" ;;
		info) Debug_Info "$@" ;;
		genstats) Debug_Generate_Stats "$@" ;;
		clean) Debug_Clean "$@" ;;
		swap) Debug_Swap "$@" ;;
		backup) Debug_Backup "$@" ;;
		restore) Debug_Restore "$@" ;;
		run) Debug_Run "$@" ;;
		*) Debug_Unknown "$@" ;;
	esac
}

Dispatch_Stats() {
	Run_Stats "$@"
}

Dispatch_Install() {
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
	Maintain_Script_Hooks firewall-start services-stop service-event post-mount unmount || { echo "[*] Failed To Maintain Script Hooks"; echo; exit 1; }
	Clean_Legacy_WebUI_Files || { echo "[*] Failed To Remove Legacy WebUI Files"; echo; exit 1; }
	if Swap_Required && ! Check_Swap; then Create_Swap || return 1; fi
	if [ -f "$skynetlog" ]; then mv "$skynetlog" "${device}/skynet/skynet.log"; fi
	if [ -f "$skynetevents" ]; then mv "$skynetevents" "${device}/skynet/events.log"; fi
	if [ -f "$skynetipset" ]; then mv "$skynetipset" "${device}/skynet/skynet.ipset"; fi
	if [ -f "$skynetrules" ]; then mv "$skynetrules" "${device}/skynet/skynet.rules"; fi
	if [ "${skynetloc}" != "${device}/skynet" ] && [ -d "${skynetloc}/lists/rules" ]; then
		mkdir -p "${device}/skynet/lists"
		rm -rf "${device}/skynet/lists/rules"
		mv "${skynetloc}/lists/rules" "${device}/skynet/lists/rules"
	fi
	if [ -f "${skynetloc}/Skynet-Backup.tar.gz" ]; then mv "${skynetloc}/Skynet-Backup.tar.gz" "${device}/skynet/Skynet-Backup.tar.gz"; fi
	if [ "${skynetloc}" != "${device}/skynet" ]; then rm -rf "${skynetloc}"; fi
	skynetloc="${device}/skynet"
	skynetcfg="${device}/skynet/skynet.cfg"
	touch "${device}/skynet/events.log"
	chmod 600 "${device}/skynet/events.log"
	touch "${device}/skynet/skynet.log"
	remotedir="https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master"
	mkdir -p "${skynetloc}/webui"
	Download_File "webui/skynet.asp" "${skynetloc}/webui/skynet.asp" \
		|| { echo "[*] Failed To Install WebUI"; echo; exit 1; }
	[ -z "$(nvram get odmpid)" ] && model="$(nvram get productid)" || model="$(nvram get odmpid)"
	if [ -z "$loginvalid" ]; then loginvalid="disabled"; fi
	if [ -z "$logsize" ]; then logsize="10"; fi
	if [ -z "$unbanprivateip" ]; then unbanprivateip="enabled"; fi
	if [ -z "$banaiprotect" ]; then banaiprotect="enabled"; fi
	if [ -z "$securemode" ]; then securemode="enabled"; fi
	if [ -z "$extendedstats" ]; then extendedstats="enabled"; fi
	if [ -z "$syslogloc" ]; then syslogloc="/tmp/syslog.log"; fi
	if [ -z "$syslog1loc" ]; then syslog1loc="/tmp/syslog.log-1"; fi
	if [ -z "$iotblocked" ]; then iotblocked="disabled"; fi
	if [ -z "$iotlogging" ]; then iotlogging="enabled"; fi
	if [ -z "$iotproto" ]; then iotproto="udp"; fi
	if [ -z "$lookupcountry" ]; then lookupcountry="enabled"; fi
	if [ -z "$cdnwhitelist" ]; then cdnwhitelist="enabled"; fi
	if [ -z "$displaywebui" ]; then displaywebui="enabled"; fi
	Write_Config || { echo "[*] Failed To Save Configuration"; echo; exit 1; }
	cmdline="sh /jffs/scripts/firewall start skynetloc=${device}/skynet # Skynet"
	Publish_Skynet_Hook /jffs/scripts/firewall-start "$cmdline" || { echo "[*] Failed To Update Firewall-Start Hook"; echo; exit 1; }
	unset "cmdline"
	echo
	nvram commit
	if [ "$forcereboot" = "1" ]; then
		Prompt_Typed "installconfirm" "i" "[i] Reboot Required To Complete Installation"
		unset "installconfirm"
		service reboot
		exit 0
	fi
	Unload_Cron "all"
	Unload_Skynet_Firewall_Rules || { echo "[*] Failed To Unload Skynet Firewall Rules"; echo; exit 1; }
	Unload_IPSets
	echo "[i] Restarting Firewall Service To Complete Installation"
	restartfirewall="1"
	nolog="2"
}

Dispatch_Uninstall() {
	echo "If You Were Experiencing Issues, Try Update Or Visit SNBForums/GitHub For Support"
	echo "https://github.com/Adamm00/IPSet_ASUS"
	echo
	while true; do
		Show_Menu "Warning - This Will Delete All Files In The Skynet Directory. Are You Sure You Want To Uninstall?" \
			"Yes" \
			"No" \
			"Exit"
		uninstallconfirm=""
		Prompt_Input "1-2" uninstallconfirm
		case "$uninstallconfirm" in
			1)
				if Skynet_Owns_Swap; then
					while true; do
						Show_Menu "Would You Like To Remove Skynet Generated Swap File?" \
							"Yes" \
							"No" \
							"Exit"
						Prompt_Input "1-2" removeswap
						case "${removeswap:?}" in
							1)
								Remove_Swap || return 1
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
				Unload_Skynet_Firewall_Rules || { echo "[*] Failed To Unload Skynet Firewall Rules"; echo; exit 1; }
				Unload_IPSets
				Uninstall_WebUI_Page
				nvram set fw_log_x=none
				nvram commit
				echo "[i] Deleting Skynet Files"
				sed -i '\~# Skynet~d' /jffs/scripts/firewall-start /jffs/scripts/services-stop /jffs/scripts/service-event /jffs/configs/profile.add /jffs/configs/dnsmasq.conf.add
				service restart_dnsmasq >/dev/null 2>&1
				rm -rf "/jffs/addons/shared-whitelists/shared-Skynet-whitelist" "/jffs/addons/shared-whitelists/shared-Skynet2-whitelist" "${skynetloc}" "/jffs/scripts/firewall" "/opt/bin/firewall" "/tmp/skynet.lock" "/tmp/skynet"
				[ ! -f "/opt/etc/syslog-ng.d/skynet" ] || echo "[i] Reconfigure Scribe To Restore Its Standard Firewall Log Handler"
				echo "[i] Restarting Firewall Service"
				service restart_firewall
				exit 0
			;;
			2|e|exit)
				echo "[*] Exiting!"
				echo; exit 0
			;;
			*)
				Invalid_Option "$uninstallconfirm"
			;;
		esac
	done
}

Dispatch_Unknown() {
	Command_Not_Recognized
}

Dispatch_Command() {
	case "$1" in
		unban) Dispatch_Unban "$@" ;;
		ban) Dispatch_Ban "$@" ;;
		banmalware) Dispatch_BanMalware "$@" ;;
		rules) Dispatch_Rules "$@" ;;
		whitelist) Dispatch_Whitelist "$@" ;;
		import) Dispatch_Import "$@" ;;
		save) Dispatch_Save "$@" ;;
		persist) Dispatch_Persist "$@" ;;
		maintenance) Dispatch_Maintenance "$@" ;;
		start) Dispatch_Start "$@" ;;
		restart) Dispatch_Restart "$@" ;;
		disable) Dispatch_Disable "$@" ;;
		update|amtmupdate) Dispatch_Update "$@" ;;
		settings) Dispatch_Settings "$@" ;;
		webui) Dispatch_WebUI "$@" ;;
		debug) Dispatch_Debug "$@" ;;
		stats) Dispatch_Stats "$@" ;;
		install) Dispatch_Install "$@" ;;
		uninstall) Dispatch_Uninstall "$@" ;;
		*) Dispatch_Unknown "$@" ;;
	esac
}
#######################
#- Interactive Menus -#
#######################

Menu_Validate_Entry_List() {
	menuentrytype="$1"
	menuentrylist="$(Normalize_List "$2")" || return 1
	for menuentry in $menuentrylist; do
		Validate_IPSet_Entry_Type "$menuentrytype" "$menuentry" || return 1
	done
}

Menu_Validate_Homogeneous_IPSet_List() {
	menuentrylist="$(Normalize_List "$1")" || return 1
	menuentrytype=""
	for menuentry in $menuentrylist; do
		if printf '%s\n' "$menuentry" | Is_IP; then menucurrenttype="ip"
		elif printf '%s\n' "$menuentry" | Is_Range; then menucurrenttype="range"
		else return 1
		fi
		[ -z "$menuentrytype" ] && menuentrytype="$menucurrenttype"
		[ "$menuentrytype" = "$menucurrenttype" ] || return 1
	done
}

Menu_Validate_Domain_List() {
	menudomainraw="$(Normalize_List "$1")" || return 1
	menudomainlist=""
	for menudomain in $menudomainraw; do
		menudomain="$(Normalize_Domain "$menudomain")" || return 1
		menudomainlist="${menudomainlist}${menudomainlist:+ }$menudomain"
	done
}

Menu_Validate_ASN_List() {
	menuasnraw="$(Normalize_List "$1")" || return 1
	menuasnlist=""
	for menuasn in $menuasnraw; do
		menuasn="$(Normalize_ASN_Arguments "$menuasn")" || return 1
		menuasnlist="${menuasnlist}${menuasnlist:+ }$menuasn"
	done
}

Menu_Unban() {
	while :; do
		if ! Menu_Require_Running; then break; fi
		option1="unban"
		while true; do
			Show_Menu "Select Unban Type:" \
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
					Prompt_Typed "option3" "IPs" "Input IPs To Unban Separated By Spaces:"
					if ! Menu_Validate_Entry_List ip "$option3"; then echo "[*] One Or More Entries Are Not Valid IPs"; echo; unset "option2" "option3"; continue; fi
					option3="$menuentrylist"; option3list="1"
					break
				;;
				2)
					option2="range"
					Prompt_Typed "option3" "Ranges" "Input Ranges To Unban Separated By Spaces:"
					if ! Menu_Validate_Entry_List range "$option3"; then echo "[*] One Or More Entries Are Not Valid Ranges"; echo; unset "option2" "option3"; continue; fi
					option3="$menuentrylist"; option3list="1"
					break
				;;
				3)
					option2="domain"
					Prompt_Typed "option3" "Domains" "Input Domains To Unban Separated By Spaces:"
					if ! Menu_Validate_Domain_List "$option3"; then echo "[*] One Or More Domains Are Not Valid"; echo; unset "option2" "option3"; continue; fi
					option3="$menudomainlist"; option3list="1"
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
					Prompt_Typed "option3" "ASNs" "Input ASNs To Unban Separated By Spaces:"
					if ! Menu_Validate_ASN_List "$option3"; then echo "[*] One Or More ASNs Are Not Valid"; echo; unset "option2" "option3"; continue; fi
					option3="$menuasnlist"; option3list="1"
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
	done
}

Menu_Ban() {
	while :; do
		if ! Menu_Require_Running; then break; fi
		option1="ban"
		while true; do
			Show_Menu "Select Ban Type:" \
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
					Prompt_Typed "option3" "IPs" "Input IPs To Ban Separated By Spaces:"
					if ! Menu_Validate_Entry_List ip "$option3"; then echo "[*] One Or More Entries Are Not Valid IPs"; echo; unset "option2" "option3"; continue; fi
					option3="$menuentrylist"; option3list="1"
					Prompt_Typed "option5" "Comment" "Input Comment For Ban:"
					if [ "${#option5}" -gt "242" ]; then echo "[*] $option5 Is Not A Valid Comment. 242 Chars Max"; echo; unset "option2" "option3" "option5"; continue; fi
					[ -z "$option5" ] || option4="comment"
					break
				;;
				2)
					option2="range"
					Prompt_Typed "option3" "Ranges" "Input Ranges To Ban Separated By Spaces:"
					if ! Menu_Validate_Entry_List range "$option3"; then echo "[*] One Or More Entries Are Not Valid Ranges"; echo; unset "option2" "option3"; continue; fi
					option3="$menuentrylist"; option3list="1"
					Prompt_Typed "option5" "Comment" "Input Comment For Ban:"
					if [ "${#option5}" -gt "242" ]; then echo "[*] $option5 Is Not A Valid Comment. 242 Chars Max"; echo; unset "option2" "option3" "option5"; continue; fi
					[ -z "$option5" ] || option4="comment"
					break
				;;
				3)
					option2="domain"
					Prompt_Typed "option3" "Domains" "Input Domains To Ban Separated By Spaces:"
					if ! Menu_Validate_Domain_List "$option3"; then echo "[*] One Or More Domains Are Not Valid"; echo; unset "option2" "option3"; continue; fi
					option3="$menudomainlist"; option3list="1"
					break
				;;
				4)
					option2="country"
					if [ -n "$countrylist" ]; then echo "Countries Currently Banned: (${countrylist})"; fi
					Prompt_Typed "option3" "Countries" "Input Country Abbreviations To Ban:"
					if [ -z "$option3" ]; then echo "[*] Country Field Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
					if printf '%s\n' "$option3" | grep -qF "\""; then echo "[*] Country Field Can't Include Quotes - Please Try Again"; echo; unset "option2" "option3"; continue; fi
					option3list="1"
					break
				;;
				5)
					option2="asn"
					Prompt_Typed "option3" "ASNs" "Input ASNs To Ban Separated By Spaces:"
					if ! Menu_Validate_ASN_List "$option3"; then echo "[*] One Or More ASNs Are Not Valid"; echo; unset "option2" "option3"; continue; fi
					option3="$menuasnlist"; option3list="1"
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
	done
}

Menu_BanMalware() {
	while :; do
		if ! Menu_Require_Running; then break; fi
		option1="banmalware"
		while true; do
			Show_Menu "Malware Blacklist & Threat Feeds:" \
				"Update Malware Blacklist" \
				"View Threat Feed Status" \
				"View Threat Feed Sources" \
				"Change Filter List URL" \
				"Reset Filter List URL" \
				"Exclude Threat Feeds" \
				"Include Threat Feeds" \
				"Enable All Threat Feeds" \
				"Exit"
			Prompt_Input "1-8" menu2
			case "$menu2" in
				1)
					break
				;;
				2)
					option2="status"
					break
				;;
				3)
					option2="sources"
					break
				;;
				4)
					Prompt_Typed "option2" "URL" "Input Custom Filter List URL:"
					if [ -z "$option2" ]; then echo "[*] URL Field Can't Be Empty - Please Try Again"; echo; unset "option2"; continue; fi
					break
				;;
				5)
					option2="reset"
					break
				;;
				6)
					option2="exclude"
					Prompt_Typed "option3" "Feeds" "Input Threat Feed Names Separated By Spaces:"
					if [ -z "$option3" ]; then echo "[*] Exclusion List Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
					break
				;;
				7)
					option2="include"
					Prompt_Typed "option3" "Feeds" "Input Excluded Threat Feed Names Separated By Spaces:"
					if [ -z "$option3" ]; then echo "[*] Include List Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
					break
				;;
				8)
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
	done
}

Menu_Rules() {
	while :; do
		if ! Menu_Require_Running; then break; fi
		option1="rules"
		Show_Menu "Dynamic Rule Management:" \
			"View Rule Status" \
			"Refresh Domain And ASN Rules" \
			"Exit"
		Prompt_Input "1-2" menu2
		case "$menu2" in
			1) option2="status"; break ;;
			2) option2="refresh"; break ;;
			e|exit|back|menu) Return_To_Menu; break ;;
			*) Invalid_Option "$menu2" ;;
		esac
	done
}

Menu_Whitelist() {
	while :; do
		if ! Menu_Require_Running; then break; fi
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
					Prompt_Typed "option3" "IPs/Ranges" "Input IPs Or Ranges To Whitelist Separated By Spaces:"
					if ! Menu_Validate_Homogeneous_IPSet_List "$option3"; then echo "[*] Entries Must Be Valid And All Use The Same IP Or Range Type"; echo; unset "option2" "option3"; continue; fi
					option2="$menuentrytype"; option3="$menuentrylist"; option3list="1"
					Prompt_Typed "option5" "Comment" "Input Comment For Whitelist:"
					if [ "${#option5}" -gt "242" ]; then echo "[*] $option5 Is Not A Valid Comment. 242 Chars Max"; echo; unset "option2" "option3" "option5"; continue; fi
					[ -z "$option5" ] || option4="comment"
					break
				;;
				2)
					option2="domain"
					Prompt_Typed "option3" "Domains" "Input Domains To Whitelist Separated By Spaces:"
					if ! Menu_Validate_Domain_List "$option3"; then echo "[*] One Or More Domains Are Not Valid"; echo; unset "option2" "option3"; continue; fi
					option3="$menudomainlist"; option3list="1"
					break
				;;
				3)
					option2="asn"
					Prompt_Typed "option3" "ASNs" "Input ASNs To Whitelist Separated By Spaces:"
					if ! Menu_Validate_ASN_List "$option3"; then echo "[*] One Or More ASNs Are Not Valid"; echo; unset "option2" "option3"; continue; fi
					option3="$menuasnlist"; option3list="1"
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
							"Domain" \
							"ASN" \
							"Entries Matching Comment" \
							"Exit"
						Prompt_Input "1-5" menu3
						case "${menu3:?}" in
							1)
								option3="all"
								break
							;;
							2)
								option3="entry"
								Prompt_Typed "option4" "IP/Range" "Input IP Or Range To Remove:"
								if ! printf '%s\n' "$option4" | Is_IPRange; then echo "[*] $option4 Is Not A Valid IP/Range"; echo; unset "option3" "option4"; continue; fi
								break
							;;
							3)
								option3="domain"
								Prompt_Typed "option4" "Domains" "Input Domains To Remove Separated By Spaces:"
								if ! Menu_Validate_Domain_List "$option4"; then echo "[*] One Or More Domains Are Not Valid"; echo; unset "option3" "option4"; continue; fi
								option4="$menudomainlist"; option4list="1"
								break
							;;
							4)
								option3="asn"
								Prompt_Typed "option4" "ASNs" "Input ASNs To Remove Separated By Spaces:"
								if ! Menu_Validate_ASN_List "$option4"; then echo "[*] One Or More ASNs Are Not Valid"; echo; unset "option3" "option4"; continue; fi
								option4="$menuasnlist"; option4list="1"
								break
							;;
							5)
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
	done
}

Menu_Import() {
	while :; do
		if ! Menu_Require_Running; then break; fi
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
	done
}

Menu_Update() {
	while :; do
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
	done
}

Menu_Settings_Toggle() {
	Require_Running
	option2="$1"
	while true; do
		Show_Menu "$2" \
			"Enable" \
			"Disable" \
			"Exit"
		Prompt_Input "1-2" menu3
		case "$menu3" in
			1) option3="enable"; break ;;
			2) option3="disable"; break ;;
			e|exit|back|menu) Return_To_Menu; break ;;
			*) Invalid_Option "$menu3" ;;
		esac
	done
}

Menu_Settings_Malware_Schedule() {
	Require_Running
	option2="banmalware"
	while true; do
		Show_Menu "Select Malware Blacklist Updating Frequency:" \
			"Daily" \
			"Weekly" \
			"Disable" \
			"Exit"
		Prompt_Input "1-3" menu3
		case "$menu3" in
			1) option3="daily"; break ;;
			2) option3="weekly"; break ;;
			3) option3="disable"; break ;;
			e|exit|back|menu) Return_To_Menu; break ;;
			*) Invalid_Option "$menu3" ;;
		esac
	done
}

Menu_Settings_Log_Size() {
	Require_Running
	option2="logsize"
	while true; do
		Show_Menu "Select Log Size:" \
			"10MB (Default)" \
			"Custom" \
			"Exit"
		Prompt_Input "1-2" menu3
		case "$menu3" in
			1) option3="10"; break ;;
			2)
				Prompt_Typed "option3" "Size" "Input Custom Log Size (in MB):"
				if ! Is_Numeric "$option3"; then echo; echo "[*] $option3 Is Not A Valid Size"; echo; unset "option3"; continue; fi
				if [ "$option3" -lt 10 ]; then echo; echo "[*] $option3 Is Not A Valid Size - Must Be At Least 10MB"; echo; unset "option3"; continue; fi
				break
			;;
			e|exit|back|menu) Return_To_Menu; break ;;
			*) Invalid_Option "$menu3" ;;
		esac
	done
}

Menu_Settings_Traffic_Filter() {
	Require_Running
	option2="filter"
	while true; do
		Show_Menu "Select Traffic Filtering Mode:" \
			"Inbound & Outbound (Recommended)" \
			"Inbound" \
			"Outbound" \
			"Exit"
		Prompt_Input "1-3" menu3
		case "$menu3" in
			1) option3="all"; break ;;
			2) option3="inbound"; break ;;
			3) option3="outbound"; break ;;
			e|exit|back|menu) Return_To_Menu; break ;;
			*) Invalid_Option "$menu3" ;;
		esac
	done
}

Menu_Settings_Syslog() {
	Require_Running
	while true; do
		Show_Menu "Select Syslog To Configure:" \
			"syslog.log" \
			"syslog.log-1" \
			"Exit"
		Prompt_Input "1-2" menu3
		case "$menu3" in
			1) option2="syslog"; sysloglabel="Syslog" ;;
			2) option2="syslog1"; sysloglabel="Syslog-1" ;;
			e|exit|back|menu) Return_To_Menu; break ;;
			*) Invalid_Option "$menu3"; continue ;;
		esac
		while true; do
			Show_Menu "Select Syslog Location:" \
				"Automatic (Both Log Paths)" \
				"Custom" \
				"Exit"
			Prompt_Input "1-2" menu3
			case "$menu3" in
				1) option3="auto"; break ;;
				2)
					Prompt_Typed "option3" "File" "Input Custom $sysloglabel Location:"
					if [ -z "$option3" ]; then echo "[*] File Field Can't Be Empty - Please Try Again"; echo; unset "option3"; continue; fi
					break
				;;
				e|exit|back|menu) Return_To_Menu; break ;;
				*) Invalid_Option "$menu3" ;;
			esac
		done
		break
	done
	unset "sysloglabel"
}

Menu_Settings_IOT() {
	Require_Running
	option2="iot"
	while true; do
		Show_Menu "Select IoT Option:" \
			"Enable IoT WAN Blocking" \
			"Disable IoT WAN Blocking" \
			"Unban Devices" \
			"Ban Devices" \
			"View IoT Device List" \
			"Add Custom Allowed Ports" \
			"Allow NTP Time Sync Only (Default)" \
			"Block All WAN Ports" \
			"Select Allowed Protocols" \
			"Exit"
		Prompt_Input "1-9" menu3
		case "$menu3" in
			1) option3="enable"; break ;;
			2) option3="disable"; break ;;
			3) option3="unban"; Prompt_Typed "option4" "IP" "Input Local IPs/Ranges Separated By Spaces:"; break ;;
			4) option3="ban"; Prompt_Typed "option4" "IP" "Input Local IPs/Ranges Separated By Spaces:"; break ;;
			5) option3="view"; break ;;
			6)
				option3="ports"
				case "$iotports" in
					""|none) ;;
					*) echo "Current Custom Ports Allowed: $(Grn "$iotports")"; echo ;;
				esac
				Prompt_Typed "option4" "Ports" "Input Custom Ports Separated By Spaces:"
				break
			;;
			7) option3="ports"; option4="default"; break ;;
			8) option3="ports"; option4="none"; break ;;
			9)
				option3="proto"
				while true; do
					Show_Menu "Select Port Protocol To Allow:" \
						"UDP" \
						"TCP" \
						"Both" \
						"Exit"
					menu4=""
					Prompt_Input "1-3" menu4
					case "$menu4" in
						1) option4="udp"; break ;;
						2) option4="tcp"; break ;;
						3) option4="all"; break ;;
						e|exit|back|menu) Return_To_Menu; break ;;
						*) Invalid_Option "$menu4" ;;
					esac
				done
				break
			;;
			e|exit|back|menu) Return_To_Menu; break ;;
			*) Invalid_Option "$menu3" ;;
		esac
	done
}

Menu_Settings() {
	while :; do
		option1="settings"
		while true; do
			Show_Menu "Select Settings Category:" \
				"Updates & Lists" \
				"Protection" \
				"IoT Isolation" \
				"Logging & Statistics" \
				"Integration & Advanced" \
				"Exit"
			settingscategory=""
			Prompt_Input "1-5" settingscategory
			settingsitem=""
			case "$settingscategory" in
				1)
					Show_Menu "Updates & Lists:" "Skynet Auto-Updates" "Malware List Auto-Updates" "Exit"
					Prompt_Input "1-2" settingsitem
					case "$settingsitem" in 1) menu2="1" ;; 2) menu2="2" ;; e|exit|back|menu) continue ;; *) Invalid_Option "$settingsitem"; continue ;; esac
				;;
				2)
					Show_Menu "Protection:" "Traffic Filtering" "Unban Private IPs" "Import AiProtection Bans" "Secure Mode" "CDN Whitelisting" "Exit"
					Prompt_Input "1-5" settingsitem
					case "$settingsitem" in 1) menu2="6" ;; 2) menu2="7" ;; 3) menu2="8" ;; 4) menu2="9" ;; 5) menu2="16" ;; e|exit|back|menu) continue ;; *) Invalid_Option "$settingsitem"; continue ;; esac
				;;
				3)
					Show_Menu "IoT Isolation:" "IoT Devices & Blocking" "IoT Logging" "Exit"
					Prompt_Input "1-2" settingsitem
					case "$settingsitem" in 1) menu2="13" ;; 2) menu2="14" ;; e|exit|back|menu) continue ;; *) Invalid_Option "$settingsitem"; continue ;; esac
				;;
				4)
					Show_Menu "Logging & Statistics:" "Logging" "Invalid Packet Logging" "Log Size" "Extended Statistics" "Syslog Locations" "Country Lookup" "Exit"
					Prompt_Input "1-6" settingsitem
					case "$settingsitem" in 1) menu2="3" ;; 2) menu2="4" ;; 3) menu2="5" ;; 4) menu2="10" ;; 5) menu2="12" ;; 6) menu2="15" ;; e|exit|back|menu) continue ;; *) Invalid_Option "$settingsitem"; continue ;; esac
				;;
				5) menu2="17" ;;
				e|exit|back|menu) Return_To_Menu; break ;;
				*) Invalid_Option "$settingscategory"; continue ;;
			esac
			case "$menu2" in
				1) Menu_Settings_Toggle "autoupdate" "Select Skynet Auto-Update Option:" ;;
				2) Menu_Settings_Malware_Schedule ;;
				3) Menu_Settings_Toggle "logmode" "Select Logging Option" ;;
				4) Menu_Settings_Toggle "loginvalid" "Select Invalid Packet Logging Option" ;;
				5) Menu_Settings_Log_Size ;;
				6) Menu_Settings_Traffic_Filter ;;
				7) Menu_Settings_Toggle "unbanprivate" "Select Unban Private IPs Option:" ;;
				8) Menu_Settings_Toggle "banaiprotect" "Select AiProtection Ban Import Option:" ;;
				9) Menu_Settings_Toggle "securemode" "Select Secure Mode Option" ;;
				10) Menu_Settings_Toggle "extendedstats" "Select Extended Statistics Option" ;;
				12) Menu_Settings_Syslog ;;
				13) Menu_Settings_IOT ;;
				14) Menu_Settings_Toggle "iotlogging" "Select IoT Logging Option" ;;
				15) Menu_Settings_Toggle "lookupcountry" "Select Country Lookup Option:" ;;
				16) Menu_Settings_Toggle "cdnwhitelist" "Select CDN Whitelisting Option:" ;;
				17) Menu_Settings_Toggle "webui" "Select WebUI Option:" ;;
				e|exit|back|menu) Return_To_Menu ;;
				*) Invalid_Option "$menu2"; continue ;;
			esac
			break
		done
		break
	done
}

Menu_Debug() {
	while :; do
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
					Require_Running
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
								if ! printf '%s\n' "$option4" | Is_IP; then echo "[*] $option4 Is Not A Valid IP"; echo; unset "option3" "option4"; continue; fi
								break
							;;
							3)
								option3="port"
								Prompt_Typed "option4" "Port"
								if ! printf '%s\n' "$option4" | Is_Port; then echo "[*] $option4 Is Not A Valid Port"; echo; unset "option3" "option4"; continue; fi
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
					Require_Running
					option2="backup"
					break
				;;
				6)
					Require_Running
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
	done
}

Menu_Stats_Result_Count() {
	menucount=""
	while true; do
		Show_Menu "Select Result Count:" \
			"10" \
			"20" \
			"50" \
			"Custom" \
			"Exit"
		Prompt_Input "1-4" menu3
		case "$menu3" in
			1) menucount="10"; break ;;
			2) menucount="20"; break ;;
			3) menucount="50"; break ;;
			4)
				Prompt_Typed "menucount" "Number" "Enter Custom Amount:"
				if ! Is_Numeric "$menucount"; then echo "[*] $menucount Isn't A Valid Number!"; echo; unset "menucount"; continue; fi
				break
			;;
			e|exit|back|menu) Return_To_Menu; break ;;
			*) Invalid_Option "$menu3" ;;
		esac
	done
}

Menu_Stats_Display() {
	Menu_Stats_Result_Count
	option3="$menucount"
	unset "menucount"
	while true; do
		Show_Menu "Select Protocol:" \
			"All" \
			"TCP" \
			"UDP" \
			"ICMP" \
			"Exit"
		Prompt_Input "1-4" menu4
		case "$menu4" in
			1) break ;;
			2) option2="tcp"; break ;;
			3) option2="udp"; break ;;
			4) option2="icmp"; break ;;
			e|exit|back|menu) Return_To_Menu; break ;;
			*) Invalid_Option "$menu4" ;;
		esac
	done
}

Menu_Stats_Connections() {
	option3="connections"
	while true; do
		Show_Menu "Select Connection Filter:" \
			"All Results" \
			"Search By IP" \
			"Search By Port" \
			"Search By Protocol" \
			"Search By Identification" \
			"Exit"
		menu5=""
		Prompt_Input "1-5" menu5
		case "$menu5" in
			1) break ;;
			2)
				option4="ip"
				Prompt_Typed "option5" "IP"
				if ! printf '%s\n' "$option5" | Is_IP; then echo "[*] $option5 Is Not A Valid IP"; echo; unset "option4" "option5"; continue; fi
				break
			;;
			3)
				option4="port"
				Prompt_Typed "option5" "Port"
				if ! printf '%s\n' "$option5" | Is_Port; then echo "[*] $option5 Is Not A Valid Port"; echo; unset "option4" "option5"; continue; fi
				break
			;;
			4)
				option4="proto"
				Prompt_Typed "option5" "Protocol"
				case "$option5" in tcp|udp|icmp) break ;; *) echo "[*] $option5 Is Not A Valid Protocol"; echo; unset "option4" "option5" ;; esac
			;;
			5) option4="id"; Prompt_Typed "option5" "Identification"; break ;;
			e|exit|back|menu) Return_To_Menu; break ;;
			*) Invalid_Option "$menu5" ;;
		esac
	done
}

Menu_Stats_Search() {
	option2="search"
	while true; do
		Show_Menu "Select Statistics Search:" \
			"Entries For A Specific Port" \
			"Entries For A Specific IP" \
			"Entries For A Specific Domain" \
			"Search Malware Lists For IP" \
			"Search Ban Reasons" \
			"Search Manual Bans" \
			"Recent WebUI Rule Actions" \
			"Outbound Entries From A Local Device" \
			"Hourly Reports" \
			"Invalid Packets" \
			"Active Connections" \
			"IoT Packets" \
			"Exit"
		Prompt_Input "1-12" menu4
		case "$menu4" in
			1)
				option3="port"; Prompt_Input "Port" option4
				if ! printf '%s\n' "$option4" | Is_Port; then echo "[*] $option4 Is Not A Valid Port"; echo; unset "option3" "option4"; continue; fi
				break
			;;
			2)
				option3="ip"; Prompt_Input "IP" option4
				if ! printf '%s\n' "$option4" | Is_IP; then echo "[*] $option4 Is Not A Valid IP"; echo; unset "option3" "option4"; continue; fi
				break
			;;
			3)
				option3="domain"; Prompt_Input "Domain" option4
				if [ -z "$option4" ]; then echo "[*] Domain Field Can't Be Empty - Please Try Again"; echo; unset "option3" "option4"; continue; fi
				break
			;;
			4)
				option3="malware"; Prompt_Input "IP" option4
				if ! printf '%s\n' "$option4" | Is_IPRange; then echo "[*] $option4 Is Not A Valid IP/Range"; echo; unset "option3" "option4"; continue; fi
				break
			;;
			5)
				option3="reason"; Prompt_Typed "option4" "Text" "Input Ban Reason Search Text:"
				if [ -z "$option4" ]; then echo "[*] Search Text Can't Be Empty"; echo; unset "option3" "option4"; continue; fi
				break
			;;
			6) option3="manualbans"; break ;;
			7) option3="actions"; break ;;
			8)
				option3="device"; Prompt_Input "Local IP" option4
				if ! printf '%s\n' "$option4" | Is_IP; then echo "[*] $option4 Is Not A Valid IP"; echo; unset "option3" "option4"; continue; fi
				break
			;;
			9) option3="reports"; break ;;
			10) option3="invalid"; break ;;
			11) Menu_Stats_Connections; break ;;
			12) option3="iot"; break ;;
			e|exit|back|menu) Return_To_Menu; break ;;
			*) Invalid_Option "$menu4" ;;
		esac
	done
	if [ "$option3" != "connections" ]; then
		Menu_Stats_Result_Count
		if [ -n "$option4" ]; then option5="$menucount"; else option4="$menucount"; fi
		unset "menucount"
	fi
}

Menu_Stats_Remove() {
	option2="remove"
	while true; do
		Show_Menu "Select Logs To Remove:" \
			"Logs Containing Specific IP" \
			"Logs Containing Specific Port" \
			"Exit"
		Prompt_Input "1-2" menu3
		case "$menu3" in
			1)
				option3="ip"; Prompt_Typed "option4" "IP"
				if ! printf '%s\n' "$option4" | Is_IP; then echo "[*] $option4 Is Not A Valid IP"; echo; unset "option3" "option4"; continue; fi
				break
			;;
			2)
				option3="port"; Prompt_Typed "option4" "Port"
				if ! printf '%s\n' "$option4" | Is_Port; then echo "[*] $option4 Is Not A Valid Port"; echo; unset "option3" "option4"; continue; fi
				break
			;;
			e|exit|back|menu) Return_To_Menu; break ;;
			*) Invalid_Option "$menu3" ;;
		esac
	done
}

Menu_Stats() {
	option1="stats"
	while true; do
		Show_Menu "Select Statistics Option:" \
			"Display" \
			"Search" \
			"Remove" \
			"Reset" \
			"Exit"
		Prompt_Input "1-4" menu2
		case "$menu2" in
			1) Menu_Stats_Display; break ;;
			2) Menu_Stats_Search; break ;;
			3) Menu_Stats_Remove; break ;;
			4) option2="reset"; break ;;
			e|exit|back|menu) Return_To_Menu; break ;;
			*) Invalid_Option "$menu2" ;;
		esac
	done
}

Load_Menu() {
	Load_Config || return 1
	Display_Header "9"
	menupublicip="$(nvram get wan0_ipaddr)"
	if printf '%s\n' "$menupublicip" | Is_PrivateIP; then
		menupublicipdisplay="$(Red "$menupublicip")"
	else
		menupublicipdisplay="$menupublicip"
	fi
	printf '╔═════════════════════ System ══════════════════════════════════════════════════════════════════════════════╗\n'
	printf '║ %-20s │ %-82s ║\n' "Router Model"   "$(nvram get productid)"
	printf '║ %-20s │ %-82s ║\n' "Skynet Version" "$localver ($(Filter_Date < "$0"))"
	printf '║ └── %-16s │ %-82s ║\n' "Hash" "$(md5sum "$0" | awk "{print \$1}")"
	printf '║ %-20s │ %-82s ║\n' "Install Dir"    "${skynetloc}"
	printf '║ %-20s │ %-82s ║\n' "FW Version"     "$(uname -o) v$(nvram get buildno)_$(nvram get extendno) (Kernel $(uname -r)) ($(uname -v | awk "{printf \"%s %s %s\n\", \$5,\$6,\$9}"))"
	printf '║ %-20s │ %-82s ║\n' "iptables"       "$(iptables --version)"
	printf '║ %-20s │ %-82s ║\n' "ipset"          "$(ipset -v 2>/dev/null | head -n1)"
	printf '║ %-20s │ %-82s ║\n' "Public IP"      "$menupublicipdisplay"
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
	unset "menupublicip" "menupublicipdisplay"
	if Read_Active_Lock; then
		Red "[*] Lock File Detected ($lockstatuscommand) (pid=$lockstatuspid, runtime=${lockstatusruntime}s)"
		Ylow '[*] Locked Processes Generally Take 1-2 Minutes To Complete And May Result In Temporarily "Failed" Tests'
		echo;echo
	fi
	unset "lockstatuscommand" "lockstatuspid" "lockstatusepoch" "lockstatusruntime"
	if ! Check_Connection >/dev/null 2>&1; then
		printf '%-35s | %-8s\n' "Internet Connectivity" "$(Red "[Failed]")"
	fi
	menufirewallstarthook="sh /jffs/scripts/firewall start skynetloc=${skynetloc} # Skynet"
	if ! Check_Skynet_Hook /jffs/scripts/firewall-start "$menufirewallstarthook"; then
		printf '%-35s | %-8s\n' "Firewall-Start Entry" "$(Red "[Failed]")"
	fi
	unset "menufirewallstarthook"
	if ! [ -w "${skynetloc}" ]; then
		printf '%-35s | %-8s\n' "Write Permission" "$(Red "[Failed]")"
	fi
	if Swap_Required && ! Check_Swap; then
		printf '%-35s | %-8s\n' "SWAP" "$(Red "[Failed]")"
	fi
	if [ "$(cru l | grep -c "Skynet")" -lt "2" ]; then
		printf '%-35s | %-8s\n' "Cron Jobs" "$(Red "[Failed]")"
	fi
	if ! Check_IPSets; then
		printf '%-35s | %-8s\n' "IPSets" "$(Red "[Failed]")"; nolog="1"; unset fail
	fi
	if ! Check_IPTables; then
		printf '%-35s | %-8s\n' "Firewall Rules" "$(Red "[Failed]")"; nolog="1"; unset fail
	fi
	if [ "$nolog" != "1" ]; then Print_Command_Summary "minimal"; fi
	unset "nolog"
	unset "option1" "option2" "option3" "option4" "option5" "option3list" "option4list"
	reloadmenu="1"
	Purge_Logs
	echo;echo
	while true; do
		Show_Menu "Select Menu Option" \
			"Unban" \
			"Ban" \
			"Malware Blacklist" \
			"Whitelist" \
			"Dynamic Rules" \
			"Import IP List" \
			"Save" \
			"Restart Skynet" \
			"Temporarily Disable Skynet" \
			"Update Skynet" \
			"Settings" \
			"Debug Options" \
			"Statistics" \
			"Install Skynet" \
			"Uninstall" \
			"Exit"
		Prompt_Input "1-15" menu
		case "$menu" in
			1)
				Menu_Unban
				break
			;;
			2)
				Menu_Ban
				break
			;;
			3)
				Menu_BanMalware
				break
			;;
			4)
				Menu_Whitelist
				break
			;;
			5)
				Menu_Rules
				break
			;;
			6)
				Menu_Import
				break
			;;
			7)
				Menu_Require_Running
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
				Menu_Update
				break
			;;
			11)
				Menu_Settings
				break
			;;
			12)
				Menu_Debug
				break
			;;
			13)
				Menu_Stats
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
				Return_To_Menu
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

#############
#- Startup -#
#############

printf '\033[?7l'
if [ "$1" != "amtmupdate" ]; then
	clear
	sed -n '2,14p' "$0"
fi

if [ -L /tmp/skynet ] || ! mkdir -p /tmp/skynet || ! chmod 700 /tmp/skynet; then
	printf '%s\n' "[*] Unable To Secure Temporary Workspace - Exiting" >&2
	exit 1
fi
TMP_DIR="/tmp/skynet/tmp.$$"
rm -rf "$TMP_DIR"
mkdir -m 700 "$TMP_DIR" || { rm -rf "$TMP_DIR"; exit 1; }
mkdir -p /jffs/addons/shared-whitelists

skynetloc="$(awk '$1 == "sh" && $2 == "/jffs/scripts/firewall" && $3 == "start" {
	for (i = 4; i <= NF; i++) {
		if ($i ~ /^skynetloc=/) {
			sub(/^skynetloc=/, "", $i)
			print $i
			exit
		}
	}
}' /jffs/scripts/firewall-start 2>/dev/null)"
skynetcfg="${skynetloc}/skynet.cfg"
skynetlog="${skynetloc}/skynet.log"
skynetevents="${skynetloc}/events.log"
skynetrules="${skynetloc}/skynet.rules"
rulestatusmanifest="${skynetloc}/lists/rules/.manifest"
rulesdatadir="${skynetloc}/lists/rules/data"
RULE_REASON_INDEX="${skynetloc}/lists/rules/.reasons"
RULE_MIGRATION_STATE="${skynetloc}/lists/rules/.migration"
skynetipset="${skynetloc}/skynet.ipset"
LOCK_FILE="/tmp/skynet/state.lock"
FIREWALL_LOCK="/tmp/skynet/firewall.lock"
LOG_LOCK="/tmp/skynet/log.lock"
TIME_PENDING="/tmp/skynet/time.pending"
STARTUP_PENDING="/tmp/skynet/startup.pending"
STARTUP_READY="/tmp/skynet/startup.ready"
DURABLE_PENDING="/tmp/skynet/snapshot.pending"
MAINTENANCE_STATUS="/tmp/skynet/maintenance.status"
state_lock_held="0"
firewall_lock_held="0"
log_lock_held="0"
domaincachegrace="86400"
domainemptythreshold="2"

# Default to the NVRAM’s WAN interface name, but if the protocol is PPPoE, override to ppp0
iface="$(nvram get wan0_ifname)"
[ "$(nvram get wan0_proto)" = "pppoe" ] && iface="ppp0"

Set_Cleanup_Traps

# An interactive first run without an install directory enters the installer.
if [ -z "$skynetloc" ] && tty >/dev/null 2>&1; then
	set -- "install"
fi

stime="$(Uptime_Seconds)"
Find_Install_Dir "$@" || exit 1

# Load saved defaults from the config file if it exists
if [ -f "$skynetcfg" ]; then
	Load_Config
fi
# Display the interactive menu when no command argument is provided
if [ -z "$1" ]; then
	Load_Menu
fi

# Rebuild positional parameters from validated interactive menu choices.
if [ -n "$option1" ]; then
	SKYNET_ACTION_ORIGIN="menu"
	# Clear the original command before appending menu values.
	set --
	[ -z "$option1" ] || set -- "$@" "$option1"
	[ -z "$option2" ] || set -- "$@" "$option2"
	if [ "$option3list" = "1" ]; then
		# Menu list values were fully validated before splitting into the same
		# positional form accepted by non-interactive commands.
		for opt in $option3; do set -- "$@" "$opt"; done
	elif [ -n "$option3" ]; then
		set -- "$@" "$option3"
	fi
	if [ "$option4list" = "1" ]; then
		for opt in $option4; do set -- "$@" "$opt"; done
	elif [ -n "$option4" ]; then
		set -- "$@" "$option4"
	fi
	[ -z "$option5" ] || set -- "$@" "$option5"
	stime="$(Uptime_Seconds)"
	echo "[$] $0 $*"
fi

if [ "$1" != "amtmupdate" ]; then
	Display_Header "9"
fi

##############
#- Commands -#
##############

Clean_Stale_Temp
Dispatch_Command "$@"
dispatchstatus="$?"
Display_Header "9"
if [ "$nolog" != "2" ]; then Print_Command_Summary "$@"; echo; fi
commandstatus="${commandfailed:-$dispatchstatus}"
if [ "$commandstatus" = "0" ] && [ "$nocfg" != "1" ]; then Write_Config || commandstatus="1"; fi
if [ "$restartfirewall" = "1" ]; then
	if ! service restart_firewall; then
		Log error -s "Firewall Restart Failed - Run ( service restart_firewall )"
		commandstatus="1"
	fi
	echo
fi
if [ "$commandstatus" = "0" ]; then
	Publish_Actions || commandstatus="1"
else
	Publish_Failed_Actions || Log error -s "Failed To Record Action Failure"
fi
if [ -n "$reloadmenu" ]; then echo;echo; printf "[i] Press Enter To Continue..."; read -r "_menucontinue"; Return_To_Menu; fi
exit "$commandstatus"
