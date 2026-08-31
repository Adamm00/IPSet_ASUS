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
	# Every exit path restores terminal line wrapping, including validation errors,
	# signals and read-only commands that return before the main footer.
	if [ -t 1 ] || [ -t 2 ]; then printf '\033[?7h'; fi
	case "$TMP_DIR" in
		/tmp/skynet/tmp.[0-9]*) rm -rf "$TMP_DIR" ;;
	esac
	for tempfile in "$settingstmp" "$statstmp" "$downloadtmp" "$configtmp" "$saveipsettmp" "$malwareipsettmp" "$hooktmp" "$listmanifesttmp" "$feedstatustmp" "$countrymanifesttmp" "$filterpublishtmp" "$dnsmasqtmp" "$sharedwhitelisttmp" "$clientouifile" "$debugneighbors" "$iotviewneighbors" "$updatetmp" "$updatewebuitmp" "$updatefirewallbackup" "$updatewebuibackup"; do
		[ -n "$tempfile" ] && rm -f "$tempfile"
	done
	if [ -n "$skynetloc" ]; then
		[ "$webuistatsactive" = "1" ] && rm -rf "${skynetloc}/webui/stats"
		rm -f "${skynetloc}/lists/"*.tmp."$$" "${skynetloc}/lists/".*.tmp."$$"
	fi
	# BusyBox ash on Merlin does not provide `command -v`; cleanup traps are
	# installed only after every function is defined, so the worker is safe to call.
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

	if [ "$logstderr" = "1" ]; then
		# logger -s echoes to stderr
		logger -s -t "$logtag" "$logmessage"
	else
		logger -t "$logtag" "$logmessage"
		echo "$logmessage"
	fi
	unset "logstderr" "logtag" "logprefix" "logmessage"
}

Check_NTP() {
	case "$1" in
		uninstall|disable) return 0 ;;
	esac

	ntptimer="0"
	while [ "$(nvram get ntp_ready)" != "1" ] && [ "$ntptimer" -lt "300" ]; do
		ntptimer=$((ntptimer + 1))
		if [ "$ntptimer" -eq 60 ]; then
			echo
			Log info -s "Waiting For NTP To Synchronize..."
		fi
		sleep 1
	done
	if [ "$ntptimer" -ge 300 ]; then
		Log error -s "NTP Synchronization Failed After 5 Minutes - Please Check Your Configuration"
		echo
		exit 1
	fi
	unset "ntptimer"
}

Check_Lock() {
	# FD 9 owns the flock for this process. The file content is diagnostic
	# metadata only: command|pid|start_epoch.
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

		# If we have a non-empty PID and that process exists
		if [ -n "$locked_pid" ] && [ -d "/proc/$locked_pid" ]; then
			lockage=$((lockcurrenttime - lock_timestamp))

			if [ "$lockage" -gt 1800 ] 2>/dev/null; then
				# Stale lock: kill and re-acquire
				if kill "$locked_pid" 2>/dev/null; then
					Log info -s "Killed stale Skynet process (pid=$locked_pid) after $lockage seconds"
				fi
				: > "$LOCK_FILE"
				if ! flock -n 9; then
					Log error -s "Lock acquisition failed after killing stale process - Exiting (pid=$locked_pid)"
					echo; exit 1
				fi
			else
				# Active lock held by running process
				Log error -s "Lock File Detected ($locked_cmd) (pid=$locked_pid, runtime=${lockage}s) - Exiting"
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
	echo "$0 $*|$$|$(date +%s)" > "$LOCK_FILE"
	unset "locked_cmd" "locked_pid" "lock_timestamp" "lockcurrenttime" "lockage"
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
	[ ! -f "$LOCK_FILE" ] && exec 9>&- && return

	IFS='|' read -r _lockcommand lockownerpid _locktimestamp < "$LOCK_FILE"

	if [ "$lockownerpid" != "$$" ]; then
		unset "_lockcommand" "lockownerpid" "_locktimestamp"
		return
	fi

	# We own the lock
	exec 9>&-
	rm -f "$LOCK_FILE"
	unset "_lockcommand" "lockownerpid" "_locktimestamp"
}

Find_Install_Dir() {
	# Skip for installer/info commands
	case "$1" in
		install|uninstall|disable|update|restart|info) return 0 ;;
	esac

	if [ ! -d "${skynetloc}" ] || [ ! -w "${skynetloc}" ]; then
		Check_Lock "$@"

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

	if [ -z "$swaplocation" ] && ! Check_Swap; then
		Log error -s "Skynet Requires A SWAP File - Install One ( $0 debug swap install )"
		return 1
	fi

	if Check_Swap && [ -z "$(grep -E 'swapon [^#]+' /jffs/scripts/post-mount | cut -d ' ' -f2)" ]; then
		Log error -s "SWAPON Entry Missing - Fix This By Running ( $0 debug swap uninstall ) Then ( $0 debug swap install )"
		return 1
	fi

	if grep -q '^partition' /proc/swaps; then
		Log error -s "SWAP Partitions Not Supported - Please Use SWAP File"
		return 1
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
		# 1) Grab the numeric gateway IP from the routing table
		connectiongateway="$(route -n | awk '$1=="0.0.0.0"{print $2; exit}')"

		# 2) Quick ping gateway (1 s timeout) if we have a gateway
		if [ -n "$connectiongateway" ] && ping -c1 -W1 "$connectiongateway" >/dev/null 2>&1; then
			return 0
		fi

		# 3) Quick ping a reliable public IP (1 s timeout)
		if ping -c1 -W1 1.1.1.1 >/dev/null 2>&1; then
			return 0
		fi

		# 4) ARP fallback on the known $iface (1 s timeout) if we have a gateway
		if [ -n "$connectiongateway" ] && arping -c1 -w1 -I "$iface" "$connectiongateway" >/dev/null 2>&1; then
			return 0
		fi

		# If this wasn't the last attempt, wait and retry
		if [ "$connectionattempt" -lt "$connectionretries" ]; then
			sleep "$connectiondelay"
		fi

		connectionattempt=$((connectionattempt + 1))
	done

	# Final failure: print a single message like the original function
	if [ -z "$connectiongateway" ]; then
		Log error -s "Connection Error Detected - Unable To Determine Gateway Or Reach Public IP"
	else
		Log error -s "Connection Error Detected - Unable To Reach Gateway ($connectiongateway) Or Public IP"
	fi

	return 1
}

Require_Connection() {
	Check_Connection "$@" || { echo; exit 1; }
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
	awk -v excluded="$3" '
		BEGIN {
			OFS = "\t"
			split(excluded, values, " ")
			for (i in values) skip[tolower(values[i])] = 1
		}
		NF == 1 {
			sub(/\r$/, "")
			url = $1
			if (url !~ /^https?:\/\// || seen_url[url]++) next

			count = split(url, parts, "/")
			name = parts[count]
			sub(/[?#].*$/, "", name)
			gsub(/[^A-Za-z0-9._-]/, "_", name)
			# Hidden names are omitted by the consolidation glob and overlap internal
			# cache files; countries is the country-cache directory. Keep ample room
			# for collision suffixes and per-process temporary extensions.
			if (name == "" || name ~ /^\./ || tolower(name) == "countries") next
			if (length(name) > 120) name = substr(name, 1, 120)

			raw_name = name
			name = raw_name
			suffix = 0
			# A natural basename such as foo.1 can collide with the suffix generated
			# for a preceding duplicate foo. Test every final case-folded name so all
			# cache, result and status paths remain unique.
			while (tolower(name) in used_name) name = raw_name "." ++suffix
			used_name[tolower(name)] = 1

			state = (tolower(name) in skip) ? "excluded" : "enabled"
			print name, url, state
		}' "$1" > "$2"
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
	true > "$feedstatustmp" || return 1
	while IFS="$feedtab" read -r feedname feedurl feedenabled; do
		feedstate="excluded"
		feedentries="$(awk -F '\t' -v name="$feedname" '$1 == name { print $2; exit }' "$feedcounts" 2>/dev/null)"
		feedchecked="0"
		feedsuccess="0"
		feedoldhash=""
		feedoldchanged="0"
		if [ -s "$feedstatusfile" ]; then
			feedold="$(awk -F '\t' -v name="$feedname" -v url="$feedurl" '$1 == name && $2 == url { print $6 "\t" $7 "\t" $8 "\t" $9; exit }' "$feedstatusfile")"
			if [ -n "$feedold" ]; then
				IFS="$feedtab" read -r feedoldchecked feedoldsuccess feedoldhash feedoldchanged <<EOF
$feedold
EOF
				feedchecked="${feedoldchecked:-0}"
				feedsuccess="${feedoldsuccess:-0}"
			fi
		fi
		if [ "$feedenabled" = "enabled" ]; then
			feedresult="$TMP_DIR/feed.${feedname}.result"
			if [ -s "$feedresult" ]; then
				IFS="$feedtab" read -r feedstate feedchecked feedsuccess < "$feedresult"
			else
				feedstate="failed"
			fi
		fi
		case "$feedentries" in ""|*[!0-9]*) feedentries="0" ;; esac
		case "$feedchecked" in ""|*[!0-9]*) feedchecked="0" ;; esac
		case "$feedsuccess" in ""|*[!0-9]*) feedsuccess="0" ;; esac
		feedhash="$(sha256sum "${skynetloc}/lists/$feedname" 2>/dev/null | awk '{print $1}')"
		feedchanged="$feedoldchanged"
		if [ -n "$feedhash" ] && [ "$feedhash" != "$feedoldhash" ]; then
			feedchanged="$(date -r "${skynetloc}/lists/$feedname" +%s 2>/dev/null || printf '%s' "$feedchecked")"
		elif [ -z "$feedhash" ]; then
			feedchanged="0"
		fi
		case "$feedchanged" in ""|*[!0-9]*) feedchanged="0" ;; esac
		printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
			"$feedname" "$feedurl" "$feedenabled" "$feedstate" "$feedentries" "$feedchecked" "$feedsuccess" "$feedhash" "$feedchanged" >> "$feedstatustmp" || return 1
	done < "$feedmanifest"
	[ -s "$feedstatustmp" ] && mv -f "$feedstatustmp" "$feedstatusfile"
}

Build_Malware_Restore() {
	# Parse every retained source once. Counts remain per source while duplicate
	# addresses are emitted only once across the enabled source set.
	awk -v manifest="$1" -v countfile="$3" '
		BEGIN {
			while ((getline line < manifest) > 0) {
				split(line, fields, "\t")
				enabled[fields[1]] = fields[3]
			}
			close(manifest)
		}
		function usable(value, part_count, prefix, octet_count, first, second, third, fourth) {
			part_count = split(value, address_parts, "/")
			if (part_count > 2) return 0
			if (part_count == 2) {
				prefix = address_parts[2]
				if (prefix !~ /^[0-9]+$/ || prefix < 0 || prefix > 32) return 0
			}
			octet_count = split(address_parts[1], octets, ".")
			if (octet_count != 4) return 0
			for (i = 1; i <= 4; i++) {
				if (octets[i] !~ /^[0-9]+$/ || octets[i] < 0 || octets[i] > 255) return 0
			}
			first = octets[1] + 0
			second = octets[2] + 0
			third = octets[3] + 0
			fourth = octets[4] + 0
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
			value = $1
			source = FILENAME
			gsub(".*/", "", source)
			if (!usable(value)) next
			source_key = source SUBSEP value
			if (!source_seen[source_key]++) source_count[source]++
			if (enabled[source] != "enabled" || global_seen[value]++) next
			valid_entries++
			if (value !~ /\// || value ~ /\/32$/)
				print "add Skynet-Blacklist " value " comment \"BanMalware: " source "\""
			else
				print "add Skynet-BlockedRanges " value " comment \"BanMalware: " source "\""
		}
		END {
			for (source in source_count) print source "\t" source_count[source] > countfile
			close(countfile)
			if (valid_entries == 0) exit 1
		}' "$TMP_DIR/feed-files/"* > "$2"
}

Extract_IPList() {
	# Keep only complete IPv4 or CIDR lines. The octet branches enforce 0-255
	# and the optional prefix branch enforces /0-/32.
	dos2unix < "$1" | grep -E '^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)$' > "$2"
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
	# as a range. This keeps import and deport set selection identical.
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

Apply_ASN_List() {
	asntmp="$TMP_DIR/asn"
	if ! Curl_Fetch -o "$asntmp" "https://asn.ipinfo.app/api/text/list/$2"; then
		rm -f "$asntmp" "${asntmp}.restore"
		return 1
	fi
	awk -v setname="$1" -v asn="$2" '/^(((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\/(1?[0-9]|2?[0-9]|3?[0-2]))?)([[:space:]]|$)/{printf "add %s %s comment \"ASN: %s \"\n", setname, $1, asn }' "$asntmp" | awk '!x[$0]++' > "${asntmp}.restore"
	if [ ! -s "${asntmp}.restore" ] || ! Apply_IPSet_File "${asntmp}.restore"; then
		rm -f "$asntmp" "${asntmp}.restore"
		return 1
	fi
	rm -f "$asntmp" "${asntmp}.restore"
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

	# Ensure swap is disabled during unmount.
	if ! grep -qE '^swapoff ' /jffs/scripts/unmount; then
		sed -i '\~swapoff ~d' /jffs/scripts/unmount || return 1
		echo 'swapoff -a 2>/dev/null # Skynet' >> /jffs/scripts/unmount || return 1
	fi

	# Save firewall state during service shutdown.
	servicesstophook='sh /jffs/scripts/firewall save # Skynet'
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
		grep -hoE '([0-9]{1,3}\.){3}[0-9]{1,3}' "/jffs/chkupdate.sh" "/tmp/update" "/tmp/.update.log" "/jffs/runtime.log" "/jffs/scripts/openvpn-event" 2>/dev/null | awk '!x[$0]++' | while IFS= read -r ip; do
			echo "add Skynet-Blacklist $ip comment \"Malware: chkupdate.sh\""
		done | ipset restore -!
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
		for tempfile in "${skynetloc}/lists/"*.tmp.* "${skynetloc}/lists/".*.tmp.* "${skynetloc}/lists/countries/.manifest.tmp."* "${skynetloc}/skynet.cfg.tmp."* "${skynetloc}/skynet.ipset.tmp."* "${skynetloc}/webui/settings.js.tmp."* "${skynetloc}/webui/skynet.asp.tmp."* "${skynetloc}/webui/skynet.asp.old."* "${skynetloc}/webui/stats.js.tmp."* "$0.tmp."* "$0.old."*; do
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
	for destroyipset in "$@"; do
		ipset -q destroy "$destroyipset" 2>/dev/null
	done
	unset destroyipset
}

Update_IPSet() {
	# Preserve legacy nofilter behaviour; IPSet validates the supplied entry.
	ipsetaction="$1"
	ipsetname="$2"
	ipsetentry="$3"
	ipsetcomment="$4"

	case "$ipsetaction" in
		add|del) ;;
		*) Log error -s "Invalid IPSet Action ($ipsetaction)"; return 1 ;;
	esac
	case "$ipsetname" in
		Skynet-Whitelist|Skynet-Blacklist|Skynet-BlockedRanges|Skynet-IOT|Skynet-Master|Skynet-MasterWL) ;;
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
	Get_IPSet_Entries "$1" "$2" | awk '{ printf "del %s %s\n", $2, $3 }' | ipset restore -! && return
	Log error -s "Failed To Remove $2 Entries From $1"
	return 1
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
	# leaving VPN, allowed-port and ICMP rules above the final DROP rule.
	iotrulesaction="$1"
	iotrulesstatus="0"
	case "$iotports" in
		"") iotportmode="default"; iotportcsv="123" ;;
		none) iotportmode="none"; iotportcsv="" ;;
		*) iotportmode="custom"; iotportcsv="$(List_To_CSV "$iotports")" ;;
	esac

	Apply_IOT_Rule "$iotrulesaction" FORWARD -i br+ -m set --match-set Skynet-IOT src -j DROP || return 1
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
	Apply_IOT_Rule "$iotrulesaction" FORWARD -i br+ -m set --match-set Skynet-IOT src -o "$iface" -p icmp -j ACCEPT || return 1
	return "$iotrulesstatus"
}

Unload_IOT_Rules() {
	Apply_IOT_Rules del
}

Load_IOT_Rules() {
	Is_Enabled "$iotblocked" || return 0
	if Apply_IOT_Rules add; then
		return 0
	fi
	Apply_IOT_Rules del 2>/dev/null
	return 1
}

Set_IOT_Blocking() {
	# Rule replacement is transactional. Restore the saved switch and rule set
	# if the new layout cannot be installed.
	[ "$1" = "$iotblocked" ] && return 0
	iotoldblocked="$iotblocked"
	Purge_Logs
	Unload_LogIPTables
	if ! Unload_IOT_Rules; then
		Load_IOT_Rules
		Load_LogIPTables
		return 1
	fi
	iotblocked="$1"
	if ! Load_IOT_Rules; then
		Unload_IOT_Rules
		iotblocked="$iotoldblocked"
		Load_IOT_Rules
		Load_LogIPTables
		Log error -s "Failed To Update IoT Firewall Rules - Previous Rules Restored"
		return 1
	fi
	Load_LogIPTables
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
	Unload_LogIPTables
	if ! Unload_IOT_Rules; then
		Load_IOT_Rules
		Load_LogIPTables
		return 1
	fi
	iotports="$iotnewports"
	iotproto="$iotnewproto"
	if ! Load_IOT_Rules; then
		Unload_IOT_Rules
		iotports="$iotoldports"
		iotproto="$iotoldproto"
		Load_IOT_Rules
		Load_LogIPTables
		Log error -s "Failed To Update IoT Rule Options - Previous Rules Restored"
		return 1
	fi
	Load_LogIPTables
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
		END {
			if (!found1) printf "#1 "
			if (!found2) printf "#2 "
			if (!found3) printf "#3 "
			if (!found4) printf "#4 "
			if (!found5) printf "#5 "
		}
	')"
	[ -z "$fail" ]
}

Check_IPTables() {
	# Compare the exact iptables-save representation so similarly named rules
	# from another addon cannot satisfy Skynet integrity checks.
	fail=""
	checkrawrules="$TMP_DIR/iptables.raw"
	checkfilterrules="$TMP_DIR/iptables.filter"
	checkwgs="$(nvram get wgs_enable)"
	checkvpn1="$(nvram get vpn_server1_state)"
	checkvpn2="$(nvram get vpn_server2_state)"
	checkfwlog="$(nvram get fw_log_x)"
	iptables-save -t raw > "$checkrawrules" 2>/dev/null
	iptables-save -t filter > "$checkfilterrules" 2>/dev/null
	checkrawduplicates=""
	if [ "$1" = "duplicates" ]; then
		# Reuse the integrity snapshot rather than exporting the RAW table again.
		if awk 'index($0, " ") && seen[$0]++ { found=1; exit } END { exit !found }' "$checkrawrules"; then
			checkrawduplicates="1"
		else
			checkrawduplicates="0"
		fi
	fi

	#6: WireGuard DROP
	if [ "$checkwgs" = "1" ]; then
		grep -Fq -- '-A PREROUTING -i wgs+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP' "$checkrawrules" || fail="${fail}#6 "
	fi

	#7: OpenVPN DROP
	if [ "$checkvpn1" != "0" ] || [ "$checkvpn2" != "0" ]; then
		grep -Fq -- '-A PREROUTING -i tun2+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP' "$checkrawrules" || fail="${fail}#7 "
	fi

	#8: Inbound on $iface
	if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then
		grep -Fq -- "-A PREROUTING -i $iface -m set ! --match-set Skynet-MasterWL src -m set --match-set Skynet-Master src -j DROP" "$checkrawrules" || fail="${fail}#8 "
	fi

	#9 & #10: Outbound on br+ and OUTPUT
	if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
		grep -Fq -- '-A PREROUTING -i br+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP' "$checkrawrules" || fail="${fail}#9 "
		grep -Fq -- '-A OUTPUT -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j DROP' "$checkrawrules" || fail="${fail}#10 "
	fi

	#11-17: IoT blocking
	if Is_Enabled "$iotblocked"; then
		case "$iotports" in
			"") checkiotportmode="default"; checkiotports="123" ;;
			none) checkiotportmode="none"; checkiotports="" ;;
			*) checkiotportmode="custom"; checkiotports="$(List_To_CSV "$iotports")" ;;
		esac
		if [ "$checkwgs" = "1" ]; then
			grep -Fq -- '-A FORWARD -i br+ -o wgs+ -m set --match-set Skynet-IOT src -j ACCEPT' "$checkfilterrules" || fail="${fail}#11 "
		fi
		if [ "$checkvpn1" != "0" ] || [ "$checkvpn2" != "0" ]; then
			grep -Fq -- '-A FORWARD -i br+ -o tun2+ -m set --match-set Skynet-IOT src -j ACCEPT' "$checkfilterrules" || fail="${fail}#12 "
		fi
		grep -Fq -- '-A FORWARD -i br+ -m set --match-set Skynet-IOT src -j DROP' "$checkfilterrules" || fail="${fail}#13 "
		if [ "$checkiotportmode" = "custom" ]; then
			if [ "$iotproto" = "all" ] || [ "$iotproto" = "udp" ]; then
				grep -Fq -- "-A FORWARD -i br+ -o $iface -p udp -m set --match-set Skynet-IOT src -m udp -m multiport --dports $checkiotports -j ACCEPT" "$checkfilterrules" || fail="${fail}#14 "
			fi
			if [ "$iotproto" = "all" ] || [ "$iotproto" = "tcp" ]; then
				grep -Fq -- "-A FORWARD -i br+ -o $iface -p tcp -m set --match-set Skynet-IOT src -m tcp -m multiport --dports $checkiotports -j ACCEPT" "$checkfilterrules" || fail="${fail}#15 "
			fi
		elif [ "$checkiotportmode" = "default" ]; then
			grep -Fq -- "-A FORWARD -i br+ -o $iface -p udp -m set --match-set Skynet-IOT src -m udp --dport 123 -j ACCEPT" "$checkfilterrules" || fail="${fail}#16 "
		fi
	fi

	#18-24: LOG rules
	if Is_Enabled "$logmode"; then
		#18: OpenVPN LOG
		if [ "$checkvpn1" != "0" ] || [ "$checkvpn2" != "0" ]; then
			grep -Fq -- '-A PREROUTING -i tun2+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] "' "$checkrawrules" || fail="${fail}#18 "
		fi

		#19: WireGuard LOG
		if [ "$checkwgs" = "1" ]; then
			grep -Fq -- '-A PREROUTING -i wgs+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] "' "$checkrawrules" || fail="${fail}#19 "
		fi

		#20: IoT LOG
		if Is_Enabled "$iotblocked" && Is_Enabled "$iotlogging"; then
			grep -Fq -- '-A FORWARD -i br+ -m set --match-set Skynet-IOT src -j LOG --log-prefix "[BLOCKED - IOT] "' "$checkfilterrules" || fail="${fail}#20 "
		fi

		#21: Inbound LOG
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then
			grep -Fq -- "-A PREROUTING -i $iface -m set ! --match-set Skynet-MasterWL src -m set --match-set Skynet-Master src -j LOG --log-prefix \"[BLOCKED - INBOUND] \"" "$checkrawrules" || fail="${fail}#21 "
		fi

		#22: Outbound PREROUTING LOG
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
			grep -Fq -- '-A PREROUTING -i br+ -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] "' "$checkrawrules" || fail="${fail}#22 "
		fi

		#23: Outbound OUTPUT LOG
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
			grep -Fq -- '-A OUTPUT -m set ! --match-set Skynet-MasterWL dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] "' "$checkrawrules" || fail="${fail}#23 "
		fi

		#24: Invalid LOG
		if [ "$checkfwlog" = "drop" ] || [ "$checkfwlog" = "both" ] && Is_Enabled "$loginvalid"; then
			grep -Fq -- '-A logdrop -m state --state NEW -j LOG --log-prefix "[BLOCKED - INVALID] "' "$checkfilterrules" || fail="${fail}#24 "
		fi
	fi

	rm -f "$checkrawrules" "$checkfilterrules"
	[ -z "$fail" ]
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
		Skynet-Whitelist Skynet-WhitelistDomains Skynet-IOT
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
				cru a Skynet_genstats "$min 11,23 * * * sh /jffs/scripts/firewall debug genstats"
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
	# The legacy single-entry form without the separator remains supported.
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

	# Preserve `entry "comment"`, but never reinterpret a malformed numeric IP
	# or range as a comment. Numeric comments can use the explicit separator.
	if [ "$#" -eq "2" ] \
		&& Validate_IPSet_Entry_Type "$parseentrytype" "$1" \
		&& ! Validate_IPSet_Entry_Type "$parseentrytype" "$2"; then
		case "$2" in
			*[!0-9./]*)
				parsedentries="$1"
				parsedcomment="$2"
				parsecommentmode="2"
			;;
		esac
	fi

	if [ -z "$parsedentries" ]; then
		for parseentryvalue in "$@"; do
			if [ "$parseentryvalue" = "comment" ] && [ "$parsecommentmode" = "0" ]; then
				[ -n "$parsedentries" ] || { parsederror="Entry Field Can't Be Empty"; return 1; }
				parsecommentmode="1"
				continue
			fi
			case "$parsecommentmode" in
				0)
					if ! Validate_IPSet_Entry_Type "$parseentrytype" "$parseentryvalue"; then
						parsederror="$parseentryvalue Is Not A Valid IP/Range"
						return 1
					fi
					parsedentries="${parsedentries}${parsedentries:+ }$parseentryvalue"
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
	fi

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

IPSet_Entry_Count() {
	# Terse mode avoids serialising every member merely to read the header count.
	ipset list -t "$1" 2>/dev/null | awk -F ': ' '/^Number of entries:/ { print $2; found = 1; exit }
		END { if (!found) print 0 }'
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
		add:Skynet-Whitelist|add:Skynet-Blacklist|add:Skynet-IOT|\
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

	if [ ! -s "$batchfile" ] || ipset restore < "$batchfile"; then
		rm -f "$batchfile" "$batchsnapshot"
		return 0
	fi

	ipset flush "$batchset" 2>/dev/null
	ipset restore -! < "$batchsnapshot" 2>/dev/null
	rm -f "$batchfile" "$batchsnapshot"
	Log error -s "Failed To Update IPSet ($batchset) - Previous Entries Restored"
	return 1
}

# Apply a prepared add/del file containing only Skynet data sets. Every affected
# set is restored together if any operation fails. An internal caller may supply
# a current snapshot it already needed, avoiding a second full IPSet export.
Apply_IPSet_File() {
	ipsetfile="$1"
	ipsetsnapshot="$2"
	ipsetsnapshotowned="0"
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
	if ipset restore -! < "$ipsetfile"; then
		[ "$ipsetsnapshotowned" = "0" ] || rm -f "$ipsetsnapshot"
		return 0
	fi
	for ipsetname in $ipsetnames; do
		ipset flush "$ipsetname" 2>/dev/null
	done
	if ! ipset restore -! < "$ipsetsnapshot" 2>/dev/null; then
		Log error -s "Failed To Fully Restore IPSet Data"
	fi
	[ "$ipsetsnapshotowned" = "0" ] || rm -f "$ipsetsnapshot"
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
	# their final DNS form before any network work begins.
	awk -v mode="$1" '
		{
			value = tolower($0)
			sub(/\.$/, "", value)
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
			if (mode == "single") output = value
			else if (!seen[value]++) print value
		}
		END {
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

Generate_Ban_Stats() {
	case "$1" in
		1)
			statsbanip="$statdata"
			statsbanhits=""
		;;
		2)
			statsbanline="$(printf '%s\n' "$statdata" | sed 's/^[[:space:]]*//')"
			statsbanhits="${statsbanline%% *}"
			statsbanip="${statsbanline##* }"
		;;
		*)
			echo "[*] Error - No Stats Specified To Load"
			return 1
		;;
	esac

	statsbancountry="$(Lookup_Stats_Country "$statsbanip" code)"
	statsbanreason="$(Lookup_Stats_Ban_Reason "$statsbanip")"
	if [ -z "$statsbanreason" ] && ! ipset -q test Skynet-Blacklist "$statsbanip" && ! ipset -q test Skynet-BlockedRanges "$statsbanip"; then
		statsbanreason="No Longer Blacklisted"
	fi
	[ "${#statsbanreason}" -le 45 ] || statsbanreason="$(printf '%s' "$statsbanreason" | cut -c1-45)"
	if [ -n "$statsdomaincache" ] && [ -f "$statsdomaincache" ]; then
		statsbandomains="$(Lookup_Stats_Domains "$statsbanip")"
		[ "$statsbandomains" = "*" ] && statsbandomains=""
	else
		statsbandomains="$(awk -v ip="$statsbanip" '$2 == ip {print $1}' "$TMP_DIR/skynetstats.txt" 2>/dev/null | xargs)"
	fi

	if [ -n "$statsbanhits" ]; then
		printf '%-10s | %-15s %-4s | %-55s | %-45s | %-60s\n' "${statsbanhits}x" "$statsbanip" "$statsbancountry" "https://otx.alienvault.com/indicator/ip/${statsbanip}" "$statsbanreason" "$statsbandomains"
	else
		printf '%-15s %-4s | %-55s | %-45s | %-60s \n' "$statsbanip" "$statsbancountry" "https://otx.alienvault.com/indicator/ip/${statsbanip}" "$statsbanreason" "$statsbandomains"
	fi
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
	lookupdomain="$1"
	lookuptimeout="$2"
	lookupresultfile="$TMP_DIR/ns.$(printf '%s' "$lookupdomain" | tr -c 'A-Za-z0-9' '_')"
	lookupanswerfile="${lookupresultfile}.answers"

	(
		if [ -n "$3" ]; then
			nslookup "$lookupdomain" "$3" > "$lookupresultfile" 2>/dev/null
		else
			nslookup "$lookupdomain" > "$lookupresultfile" 2>/dev/null
		fi
	) &
	lookuppid=$!
	( sleep "$lookuptimeout"; kill "$lookuppid" 2>/dev/null ) &
	lookupwatchdogpid=$!

	wait "$lookuppid" 2>/dev/null
	lookupstatus="$?"
	kill "$lookupwatchdogpid" 2>/dev/null
	wait "$lookupwatchdogpid" 2>/dev/null

	if [ "$lookupstatus" = "0" ] && [ -s "$lookupresultfile" ]; then
		awk -v q="$lookupdomain" '
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
		' "$lookupresultfile" | Filter_IP | awk '!seen[$0]++' > "$lookupanswerfile"
	fi

	if [ -s "$lookupanswerfile" ]; then
		cat "$lookupanswerfile"
		lookupstatus="$?"
	else
		lookupstatus="1"
	fi
	rm -f "$lookupresultfile" "$lookupanswerfile"
	return "$lookupstatus"
}

Resolve_Normalized_Domain_IP_List() {
	# The caller has already passed the hostname through Normalize_Domain or its
	# batch equivalent. Resolve once and emit validated addresses in supplied mode.
	domainresolveinput="$1"
	case "$2" in all|public) ;; *) return 1 ;; esac
	if [ -n "$3" ]; then
		domainresolveips="$(Domain_Lookup "$domainresolveinput" 3 "$3")" || return 1
	else
		domainresolveips="$(Domain_Lookup "$domainresolveinput" 3)" || return 1
	fi
	if [ "$2" = "public" ]; then
		domainresolveips="$(printf '%s\n' "$domainresolveips" | Filter_PrivateIP)" || return 1
	fi
	Normalize_List "$domainresolveips"
}

Resolve_Domain_IP_List() {
	# Public command paths validate one value here; bulk workers normalise their
	# complete input once and call Resolve_Normalized_Domain_IP_List directly.
	domainresolveinput="$(Normalize_Domain "$1")" || return 1
	Resolve_Normalized_Domain_IP_List "$domainresolveinput" "$2" "$3"
}

Save_IPSets() {
	# Persist every Skynet set as one snapshot and atomically replace the previous
	# file only after all ipset save calls complete.
	Check_IPSets || return 1
	saveipsettmp="${skynetipset}.tmp.$$"
	if { ipset save Skynet-Whitelist && ipset save Skynet-WhitelistDomains && ipset save Skynet-Blacklist && ipset save Skynet-BlockedRanges && ipset save Skynet-Master && ipset save Skynet-MasterWL && ipset save Skynet-IOT; } > "$saveipsettmp" 2>/dev/null \
		&& [ -s "$saveipsettmp" ] && mv -f "$saveipsettmp" "$skynetipset"; then
		return 0
	fi
	rm -f "$saveipsettmp"
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
		ipset swap "$blacklisttempset" Skynet-Blacklist 2>/dev/null
		Destroy_IPSets "$blacklisttempset" "$rangestempset"
		Set_Cleanup_Traps
		return 1
	fi
	Destroy_IPSets "$blacklisttempset" "$rangestempset"
	Set_Cleanup_Traps
}

Whitelist_Blocked_Private_IPs() {
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
		' "$syslogloc" > "$privateipfile" || { rm -f "$privateipfile"; return 1; }
		if [ -s "$privateipfile" ]; then
			Apply_IPSet_File "$privateipfile" || { rm -f "$privateipfile"; return 1; }
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


Refresh_Manual_Ban_Domains() {
	if grep -qF "[Manual Ban] TYPE=Domain" "$skynetevents"; then
		awk '/\[Manual Ban\] TYPE=Domain/{if(!x[$9]++)print $9}' "$skynetevents" | sed 's~Host=~~g' > "$TMP_DIR/mbans.list"
		sed -i '\~\[Manual Ban\] TYPE=Domain~d;' "$skynetevents"
		Remove_IPSet_Entries Skynet-Blacklist "ManualBanD" || return 1
		{
			Start_Background_Jobs
			while IFS= read -r "domain"; do
				{
					domainips="$(Resolve_Domain_IP_List "$domain" public)" || exit 0
					for ip in $domainips; do
						echo "add Skynet-Blacklist $ip comment \"ManualBanD: $domain\""
						echo "$(date +"%b %e %T") Skynet: [Manual Ban] TYPE=Domain SRC=$ip Host=$domain " >> "$skynetevents"
					done
				} &
				Wait_Background_Job_Slot 4
			done < "$TMP_DIR/mbans.list"
			Wait_Background_Jobs
		} | ipset restore -! || return 1
		rm -f "$TMP_DIR/mbans.list"
	fi
}

Refresh_Manual_Whitelist_Domains() {
	if grep -qE "Manual Whitelist.* TYPE=Domain" "$skynetevents"; then
		awk '/Manual Whitelist.* TYPE=Domain/{if(!x[$9]++)print $9}' "$skynetevents" | sed 's~Host=~~g' > "$TMP_DIR/mwhitelist.list"
		sed -i '\~\[Manual Whitelist\] TYPE=Domain~d;' "$skynetevents"
		Remove_IPSet_Entries Skynet-Whitelist "ManualWlistD" || return 1
		{
			Start_Background_Jobs
			while IFS= read -r domain; do
				{
					domainips="$(Resolve_Domain_IP_List "$domain" public)" || exit 0
					for ip in $domainips; do
						echo "add Skynet-Whitelist $ip comment \"ManualWlistD: $domain\""
						echo "$(date +"%b %e %T") Skynet: [Manual Whitelist] TYPE=Domain SRC=$ip Host=$domain " >> "$skynetevents"
					done
				} &
				Wait_Background_Job_Slot 4
			done < "$TMP_DIR/mwhitelist.list"
			Wait_Background_Jobs
		} | ipset restore -! || return 1
		cat "$TMP_DIR/mwhitelist.list" >> /jffs/addons/shared-whitelists/shared-Skynet2-whitelist
		rm -f "$TMP_DIR/mwhitelist.list"
	fi
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
				elif sed '\~^add Skynet-Whitelist ~!d;\~CDN-Whitelist~!d;s~ comment.*~~;s~add~del~' "$cdnsnapshot" | ipset restore -! \
					&& ipset restore -! < "$cdnrestore"; then
					cdnresult="updated"
				else
					sed 's~^add~del~;s~ comment.*~~' "$cdnrestore" | ipset restore -!
					ipset restore -! < "$cdnsnapshot"
					cdnstatus="1"
					cdnresult="apply"
				fi
			else
				cdnstatus="1"
				cdnresult="apply"
			fi
		fi
		if [ "$cdnstatus" != "0" ]; then
			grep -E 'GoogleDNS|CloudFlareDNS' "$cdnlist" | ipset restore -!
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
			vpnsubnet="$(nvram get "${vpnserver}_sn")"
			vpnnetmask="$(nvram get "${vpnserver}_nm")"
		fi
		vpnprefix="$(Netmask_To_Prefix "$vpnnetmask" 2>/dev/null)" || vpnprefix=""
		[ -n "$vpnsubnet" ] && [ -n "$vpnprefix" ] \
			&& printf '%s/%s~nvram: %s\n' "$vpnsubnet" "$vpnprefix" "$vpnserver" >> "$vpnentries"
	done

	# Prefer Merlin's resolved endpoint, then resolve the configured address.
	# Configured profiles are included before the tunnel connects.
	for vpnclient in vpn_client1 vpn_client2 vpn_client3 vpn_client4 vpn_client5; do
		vpnendpoint="$(nvram get "${vpnclient}_rip")"
		if ! printf '%s\n' "$vpnendpoint" | Filter_IP >/dev/null; then
			vpnaddress="$(nvram get "${vpnclient}_addr")"
			[ -n "$vpnaddress" ] || continue
			if printf '%s\n' "$vpnaddress" | Filter_IP >/dev/null; then
				vpnendpoint="$vpnaddress"
			else
				vpnendpoint="$(Resolve_Domain_IP_List "$vpnaddress" public 2>/dev/null)" || continue
			fi
		fi
		printf '%s\n' "$vpnendpoint" | while IFS= read -r vpnaddress; do
			[ -n "$vpnaddress" ] || continue
			printf '%s/24~nvram: %s_addr\n' "$vpnaddress" "$vpnclient" >> "$vpnentries"
		done
	done
	if [ "$(nvram get wgc_enable)" = "1" ]; then
		vpnendpoint="$(nvram get wgc_ep_addr)"
		if ! printf '%s\n' "$vpnendpoint" | Filter_IP >/dev/null; then
			vpnendpoint="$(Resolve_Domain_IP_List "$vpnendpoint" public 2>/dev/null)" || vpnendpoint=""
		fi
		printf '%s\n' "$vpnendpoint" | while IFS= read -r vpnaddress; do
			[ -n "$vpnaddress" ] || continue
			printf '%s/24~nvram: wgc_ep_addr\n' "$vpnaddress" >> "$vpnentries"
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
	if [ -f "/dev/astrill/openvpn.conf" ]; then
		Update_IPSet add Skynet-Whitelist "$(sed '\~remote ~!d;s~remote ~~' "/dev/astrill/openvpn.conf")/24" "nvram: Astrill_VPN"
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

	# Publish a new dnsmasq file only when the generated Skynet lines differ.
	# Avoiding an unchanged restart preserves dnsmasq's cache before the bounded
	# lookups below repopulate Skynet-WhitelistDomains.
	dnsmasqfile="/jffs/configs/dnsmasq.conf.add"
	dnsmasqtmp="${dnsmasqfile}.tmp.$$"
	dnsmasqdomains="$TMP_DIR/dnsmasq-domains.$$"
	dnsmasqchanged="0"
	if [ -f "$dnsmasqfile" ]; then
		sed '\~# Skynet~d' "$dnsmasqfile" > "$dnsmasqtmp" || { rm -f "$dnsmasqtmp"; return 1; }
	else
		true > "$dnsmasqtmp" || return 1
	fi
	Strip_Domain /jffs/addons/shared-whitelists/shared-*-whitelist > "$dnsmasqdomains" \
		|| { rm -f "$dnsmasqtmp" "$dnsmasqdomains"; return 1; }
	awk '
		NF {
			line = line (count == 0 ? "ipset=/" : "/") $0
			count++
			if (count == 20) {
				print line "/Skynet-WhitelistDomains # Skynet"
				line = ""
				count = 0
			}
		}
		END { if (count) print line "/Skynet-WhitelistDomains # Skynet" }
	' "$dnsmasqdomains" >> "$dnsmasqtmp" || { rm -f "$dnsmasqtmp" "$dnsmasqdomains"; return 1; }
	rm -f "$dnsmasqdomains"
	if [ -f "$dnsmasqfile" ] && cmp -s "$dnsmasqtmp" "$dnsmasqfile"; then
		rm -f "$dnsmasqtmp"
	else
		if ! chmod 644 "$dnsmasqtmp" || ! mv -f "$dnsmasqtmp" "$dnsmasqfile"; then
			rm -f "$dnsmasqtmp"
			return 1
		fi
		dnsmasqchanged="1"
	fi
	ipset flush Skynet-WhitelistDomains
	[ "$dnsmasqchanged" = "0" ] || service restart_dnsmasq >/dev/null 2>&1
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
	Strip_Domain < /jffs/addons/shared-whitelists/shared-Skynet2-whitelist | {
		Start_Background_Jobs
		while IFS= read -r domain; do
			Domain_Lookup "$domain" 3 127.0.0.1 >/dev/null 2>&1 &
			Wait_Background_Job_Slot 4
		done
		Wait_Background_Jobs
	}
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
		jsvalue="$(Escape_JS < "$1")"
	else
		jsvalue="$(printf '%s' "$1" | Escape_JS)"
	fi
	{
		echo "function ${3}() {"
		printf "\tdocument.getElementById(\"%s\").innerHTML = '%s'\n" "$4" "$jsvalue"
		echo "}"
		echo
	} >> "$2"
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
	for statsindexfile in inbound-src inbound-dpt inbound-spt outbound-src outbound-dst outbound-all-dst outbound-http-dst invalid-src iot-dst activity span; do
		true > "${statsindexpath}/${statsindexfile}.txt" || return 1
	done

	awk -v path="$statsindexpath" -v proto="$statsindexproto" -v today="$(date '+%b %e')" -v hour="$(date '+%H')" '
		# Values in kernel logs end at the next space or comma.
		function field_value(field, position, value) {
			position = index($0, field "=")
			if (!position) return ""
			value = substr($0, position + length(field) + 1)
			sub(/[ ,].*/, "", value)
			return value
		}
		BEGIN { hour += 0 }
		{
			if (index($0, "BLOCKED -")) {
				stamp = $1 " " $2 " " $3
				if (first == "") first = stamp
				last = stamp
			}
			if (proto != "" && index($0, "PROTO=" proto " ") == 0) next
			if ($0 ~ /INBOUND/) {
				if ((value = field_value("SRC")) != "") print value >> path "/inbound-src.txt"
				if ((value = field_value("DPT")) != "") print value >> path "/inbound-dpt.txt"
				if ((value = field_value("SPT")) != "") print value >> path "/inbound-spt.txt"
			} else if ($0 ~ /OUTBOUND/) {
				if ((value = field_value("SRC")) != "") print value >> path "/outbound-src.txt"
				if ((value = field_value("DST")) != "") {
					print value >> path "/outbound-all-dst.txt"
					if ($0 ~ /DPT=(80|443) /) print value >> path "/outbound-http-dst.txt"
					else print value >> path "/outbound-dst.txt"
				}
			} else if ($0 ~ /INVALID/) {
				if ((value = field_value("SRC")) != "") print value >> path "/invalid-src.txt"
			} else if ($0 ~ /IOT/) {
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
			for (i = 0; i <= hour; i++)
				printf "%02d:00~%d~%d~%d~%d\n", i, inbound[i] + 0, outbound[i] + 0, invalid[i] + 0, iot[i] + 0 > path "/activity.txt"
			if (first != "") print first " To " last > path "/span.txt"
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
	if [ -n "$statsextractfield" ]; then
		statsextractfield="${statsextractfield}="
	fi

	awk -v matchpattern="$statsextractinclude" -v skippattern="$statsextractexclude" -v field="$statsextractfield" -v mode="$statsextractmode" -v limit="$statsextractlimit" '
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

			if (mode == "top") hits[value]++
			else values[++entries] = value
		}
		END {
			if (mode == "top") {
				for (value in hits) printf "%7d %s\n", hits[value], value
			} else if (mode == "oldest") {
				for (i = 1; i <= entries && output < limit; i++) {
					value = values[i]
					if (!(value in seen)) {
						print value
						seen[value] = 1
						output++
					}
				}
			} else {
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
	' "$statsextractsource" | {
		if [ "$statsextractmode" = "top" ]; then
			sort -nr | head -n "$statsextractlimit"
		else
			cat
		fi
	}
}

Lookup_Stats_Ban_Reason() {
	# Convert IPv4 addresses to unsigned 32-bit numbers so CIDR membership can be
	# tested using division, which BusyBox awk supports without bitwise helpers.
	statslookupip="$1"
	statslookupsource="${2:-$skynetipset}"
	if [ -n "$statsreasoncache" ] && [ -f "$statsreasoncache" ]; then
		awk -v ip="$statslookupip" 'index($0, ip "~") == 1 {print substr($0, length(ip) + 2); exit}' "$statsreasoncache"
		return
	fi

	awk -v ip="$statslookupip" '
		function trim(value) { sub(/^ +| +$/, "", value); return value }
		function print_reason(range, position, reason) {
			position = index($0, "comment \"")
			if (position) {
				reason = substr($0, position + 9)
				sub(/"$/, "", reason)
				printf "%s", trim(reason)
				if (range) printf "*"
				printf "\n"
			}
		}
		BEGIN {
			split(ip, address, ".")
			ipnumber = address[1] * 16777216 + address[2] * 65536 + address[3] * 256 + address[4]
		}
		$1 == "add" && $2 == "Skynet-Blacklist" && $3 == ip {
			print_reason(0)
			exit
		}
		$1 == "add" && $2 == "Skynet-BlockedRanges" {
			split($3, cidr, "/")
			split(cidr[1], network, ".")
			prefix = cidr[2]
			networknumber = network[1] * 16777216 + network[2] * 65536 + network[3] * 256 + network[4]
			divisor = 1
			for (i = 0; i < 32 - prefix; i++) divisor *= 2
			if (int(ipnumber / divisor) == int(networknumber / divisor)) {
				print_reason(prefix < 32)
				exit
			}
		}
	' "$statslookupsource"
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

	awk -v requests="$statsreasonrequests" '
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
		BEGIN {
			while ((getline ip < requests) > 0) {
				if (ip != "" && !(ip in wanted)) {
					wanted[ip] = ip_number(ip)
					order[++count] = ip
				}
			}
			close(requests)
		}
		$1 == "add" && $2 == "Skynet-Blacklist" && ($3 in wanted) && !resolved[$3] {
			result[$3] = entry_reason(0)
			resolved[$3] = 1
			next
		}
		$1 == "add" && $2 == "Skynet-BlockedRanges" {
			split($3, cidr, "/")
			prefix = cidr[2]
			network = ip_number(cidr[1])
			divisor = 1
			for (i = 0; i < 32 - prefix; i++) divisor *= 2
			for (ip in wanted) {
				if (!resolved[ip] && int(wanted[ip] / divisor) == int(network / divisor)) {
					result[ip] = entry_reason(prefix < 32)
					resolved[ip] = 1
				}
			}
		}
		END {
			for (i = 1; i <= count; i++) print order[i] "~" result[order[i]]
		}
	' "$statsreasonsource" > "$statsreasonoutput"
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

	true > "$statscountryoutput" || return 1
	Is_Enabled "$lookupcountry" || return 0
	mkdir -p "${skynetloc}/lists" || return 0
	awk -F '~' -v requests="$statscountryrequests" -v now="$statsgeonow" '
		BEGIN {
			while ((getline ip < requests) > 0) if (ip != "") wanted[ip] = 1
			close(requests)
		}
		$1 ~ /^[0-9.]+$/ && $2 ~ /^[A-Z][A-Z]$/ && $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ {
			if ($1 in wanted) $4 = now
			if (($1 in wanted) || now - $4 <= 2592000) print $1 "~" $2 "~" $3 "~" $4
		}' "$statsgeocache" 2>/dev/null > "$statsgeowork"
	awk -F '~' -v cache="$statsgeowork" -v now="$statsgeonow" '
		BEGIN {
			while ((getline line < cache) > 0) {
				split(line, field, "~")
				checked[field[1]] = field[3]
			}
			close(cache)
		}
		NF && (!( $1 in checked) || now - checked[$1] >= 604800) && !seen[$1]++ { print $1 }
	' "$statscountryrequests" > "$statsgeomissing"
	awk '
		{
			batch = batch (batch == "" ? "" : ",") $1
			if (++count == 32) { print batch; batch = ""; count = 0 }
		}
		END { if (batch != "") print batch }
	' "$statsgeomissing" > "$statsgeobatches"
	true > "$statsgeonew"
	while IFS= read -r statsgeobatch; do
		[ -n "$statsgeobatch" ] || continue
		if Curl_Lookup "https://api.db-ip.com/v2/free/${statsgeobatch}/countryCode" > "$statsgeoresponse" 2>/dev/null; then
			case "$statsgeobatch" in
				*,*)
					sed -n 's/^[[:space:]]*"\([0-9][0-9.]*\)"[[:space:]]*:[[:space:]]*"\([A-Z][A-Z]\)".*/\1~\2/p' "$statsgeoresponse" \
						| awk -F '~' -v now="$statsgeonow" '$1 != "" && !seen[$1]++ { print $1 "~" $2 "~" now "~" now }' >> "$statsgeonew"
				;;
				*)
					statsgeocode="$(tr -d '\r\n' < "$statsgeoresponse")"
					case "$statsgeocode" in
						[A-Z][A-Z]) printf '%s~%s~%s~%s\n' "$statsgeobatch" "$statsgeocode" "$statsgeonow" "$statsgeonow" >> "$statsgeonew" ;;
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
	' "$statsgeowork" > "$statsgeotmp"
	# Publish an empty snapshot as well so entries unused for 30 days are actually
	# pruned when no current chart IP needs country enrichment.
	mv -f "$statsgeotmp" "$statsgeocache" 2>/dev/null || true
	awk -F '~' -v requests="$statscountryrequests" '
		BEGIN {
			while ((getline ip < requests) > 0) wanted[ip] = 1
			close(requests)
		}
		($1 in wanted) && !seen[$1]++ { print $1 "~" $2 }
	' "$statsgeocache" 2>/dev/null > "$statscountryoutput"
	rm -f "$statsgeotmp" "$statsgeowork" "$statsgeomissing" "$statsgeobatches" "$statsgeonew" "$statsgeoresponse"
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

Lookup_Stats_Domains() {
	statslookupdomains="$(awk -F "~" -v ip="$1" '$1 == ip {print $2; exit}' "$statsdomaincache")"
	[ -n "$statslookupdomains" ] || statslookupdomains="*"
	printf '%s\n' "$statslookupdomains"
}

Build_Stats_Domain_Cache() {
	# dnsmasq history can exceed hundreds of megabytes. Load the small chart IP
	# request set first, then retain only matching domain replies in one pass.
	statsdomainrequests="$1"
	statsdomainoutput="$2"
	shift 2
	true > "$statsdomainoutput" || return 1
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
			gsub(/www\./, "", domain)
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
	true > "$statsrecentfile" || return 1
	while IFS= read -r statsrecentip; do
		[ -n "$statsrecentip" ] || continue
		statsrecentreason="$(Lookup_Stats_Ban_Reason "$statsrecentip" "$statsbanlist")"
		[ -n "$statsrecentreason" ] || statsrecentreason="*"
		[ "${#statsrecentreason}" -le 45 ] || statsrecentreason="$(printf '%s' "$statsrecentreason" | cut -c1-45)"
		statsrecentcountry="$(Lookup_Stats_Country "$statsrecentip" code)"
		statsrecentdomains="$(Lookup_Stats_Domains "$statsrecentip")"
		printf '%s~%s~https://otx.alienvault.com/indicator/ip/%s~%s~%s\n' "$statsrecentip" "$statsrecentreason" "$statsrecentip" "$statsrecentcountry" "$statsrecentdomains" >> "$statsrecentfile" || return 1
	done
}

Write_Top_IP_Stats() {
	statstopfile="$1"
	statstopcountrytype="$2"
	statstopdomains="$3"
	true > "$statstopfile" || return 1
	while read -r statstophits statstopip; do
		[ -n "$statstopip" ] || continue
		statstopcountry="$(Lookup_Stats_Country "$statstopip" "$statstopcountrytype")"
		if [ "$statstopdomains" = "domains" ]; then
			statstopdomainlist="$(Lookup_Stats_Domains "$statstopip")"
			printf '%s~%s~%s~%s\n' "$statstophits" "$statstopip" "$statstopcountry" "$statstopdomainlist" >> "$statstopfile" || return 1
		else
			printf '%s~%s~%s\n' "$statstophits" "$statstopip" "$statstopcountry" >> "$statstopfile" || return 1
		fi
	done
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
	# $8 = stats_mode     (passed to Generate_Ban_Stats)
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
	Extract_Stats_Values "$statssource" "$statspattern" "" "$statsfield" "$statsextractmode" "$statscount" | while IFS= read -r statdata; do
		Generate_Ban_Stats "$statsmode"
	done
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
	{ ipset save Skynet-Blacklist 2>/dev/null; ipset save Skynet-BlockedRanges 2>/dev/null; } > "$bansearchdata" || return 1
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
		Extract_Stats_Values "$skynetevents" "Manual Ban" "" "SRC" "oldest" "$statsclilimit"
		Extract_Stats_Values "${statsindexpath}/inbound-src.txt" ".*" "" "" "top" "$statsclilimit" | awk 'NF >= 2 {print $NF}'
		Extract_Stats_Values "${statsindexpath}/outbound-all-dst.txt" ".*" "" "" "top" "$statsclilimit" | awk 'NF >= 2 {print $NF}'
		Extract_Stats_Values "${statsindexpath}/invalid-src.txt" ".*" "" "" "top" "$statsclilimit" | awk 'NF >= 2 {print $NF}'
		Extract_Stats_Values "${statsindexpath}/outbound-http-dst.txt" ".*" "" "" "top" "$statsclilimit" | awk 'NF >= 2 {print $NF}'
		Extract_Stats_Values "${statsindexpath}/iot-dst.txt" ".*" "" "" "top" "$statsclilimit" | awk 'NF >= 2 {print $NF}'
	} | awk 'NF && !seen[$0]++' > "$statslookupips" || return 1
	Build_Stats_Ban_Reason_Cache "$statslookupips" "$skynetipset" "$statsreasoncache" || return 1
	Build_Stats_Domain_Cache "$statslookupips" "$statsdomaincache"
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
		printf '╔═════════════════════ Logging ═════════════════════════════════════════════════════════════════════════════╗\n'
		printf '║ %-20s │ %-82s ║\n' "Syslog Locations" "$syslogloc $syslog1loc"
		printf '║ %-20s │ %-82s ║\n' "Skynet Log"       "${skynetlog}"
		SZ="$(du -h "${skynetlog}" | awk '{print $1}')"
		printf '║ └── %-16s │ %-82s ║\n' "Used/Total" "$SZ / ${logsize}MB"
		Generate_Blocked_Events
		printf '║ %-20s │ %-82s ║\n' "Manual Bans"       "$(grep -Fc "Manual Ban" "$skynetevents")"
		printf '║ %-20s │ %-84s ║\n' "Monitor Span"      "$monitorspan"
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
					reason)
						Search_Ban_Reasons "$4" "$5" || exit "$?"
					;;
					port)
						if ! echo "$4" | Is_Port; then echo "[*] $4 Is Not A Valid Port"; echo; exit 2; fi
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
						if ! echo "$4" | Is_IP; then echo "[*] $4 Is Not A Valid IP"; echo; exit 2; fi
						if [ "$5" -eq "$5" ] 2>/dev/null; then counter="$5"; fi
						unset "found1" "found2" "found3"
						ipset -q test Skynet-Whitelist "$4" && found1=true
						ipset -q test Skynet-Blacklist "$4" && found2=true
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
						Require_Connection
						if [ -z "$4" ]; then echo "[*] Domain Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
						domain="$(Normalize_Domain "$4")" || { echo "[*] $4 Is Not A Valid Domain"; echo; exit 2; }
						domainips="$(Resolve_Domain_IP_List "$domain" all)" || { echo "[*] Unable To Resolve $domain"; echo; exit 1; }
						if [ "$5" -eq "$5" ] 2>/dev/null; then counter="$5"; fi
						for ip in $domainips; do
							unset "found1" "found2" "found3"
							ipset -q test Skynet-Whitelist "$ip" && found1=true
							ipset -q test Skynet-Blacklist "$ip" && found2=true
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
									country="$(Curl_Lookup "https://api.db-ip.com/v2/free/${ip}/countryCode/" 2>/dev/null | grep -E '^[A-Z]{2}$' || echo '**')"
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
						echo "[i] $(grep -Ec "OUTBOUND.* SRC=$4 " "$skynetlog") Blocks Total"
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
							while IFS= read -r "logs"; do
								# bw_cte_dump fields are whitespace-delimited kernel data. Decode the
								# DPI mark in-shell instead of spawning utilities for every row.
								# shellcheck disable=SC2086
								set -- $logs
								mark="${8#mark=}"
								mark="$(printf '%d\n' "0x${mark}")"
								appid="$(((mark & 0x3F0000) / 65535))"
								categoryid="$((mark & 0xFFFF))"
								proto="$2"
								sourceip="${3#*=}"
								case "$sourceip" in *:*) sourceip="IPv6 Address" ;; esac
								destip="${4#*=}"
								case "$destip" in *:*) destip="IPv6 Address" ;; esac
								sport="${5#*=}"
								dport="${6#*=}"
								if [ "$categoryid" = "0" ] && [ "$appid" = "0" ]; then
									reason="Unidentified"
								else
									reason="$(awk -F ',' -v app="$appid" -v category="$categoryid" '$1 == app && $2 == category && $3 == 0 { print $4; exit }' /tmp/bwdpi/bwdpi.app.db)"
								fi
								[ "$connectionfiltertype" = "ip" ] && [ -n "$connectionfiltervalue" ] && [ "$connectionfiltervalue" != "$sourceip" ] && [ "$connectionfiltervalue" != "$destip" ] && continue
								[ "$connectionfiltertype" = "port" ] && [ -n "$connectionfiltervalue" ] && [ "$connectionfiltervalue" != "$sport" ] && [ "$connectionfiltervalue" != "$dport" ] && continue
								[ "$connectionfiltertype" = "proto" ] && [ -n "$connectionfiltervalue" ] && [ "$connectionfiltervalue" != "$proto" ] && continue
								[ "$connectionfiltertype" = "id" ] && [ -n "$connectionfiltervalue" ] && [ "$connectionfiltervalue" != "$reason" ] && continue
								printf '%-10s | %-18s | %-10s | %-18s | %-10s | %-18s\n' "$proto" "$sourceip" "$sport" "$destip" "$dport" "$reason"
							done < /proc/bw_cte_dump
							unset "connectionfiltertype" "connectionfiltervalue" "logs" "mark" "appid" "categoryid" "proto" "sourceip" "destip" "sport" "dport" "reason"
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
						while IFS= read -r "statdata"; do
							Generate_Ban_Stats "2"
						done < "$TMP_DIR/stats-iot.txt"
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
				Show_Stats_Block "events" "Manual Ban" "SRC" "Last $counter Manual Bans" "tail" "$counter" "1" "1"
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
	{
		ipset save Skynet-IOT 2>/dev/null | awk '$1 == "add" { print "B~" $3 }'
		if [ -f /var/lib/misc/dnsmasq.leases ]; then
			awk 'NF >= 4 { print "L~" $3 "~" $2 "~" $4 }' /var/lib/misc/dnsmasq.leases
		fi
		ip neigh 2>/dev/null | awk '
			/^([0-9]{1,3}\.){3}[0-9]{1,3} / {
				mac = ""
				for (i = 1; i <= NF; i++) if ($i == "lladdr") mac = $(i + 1)
				print "N~" $1 "~" mac "~" $NF
			}'
	} > "$iotrecords" || return 1

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
		}' "$iotrecords" | sort -t '~' -k1,1nr -k2,2 > "$iotinventory" || return 1

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
		iotnamejs="$(printf '%s\n' "$localname" | Escape_JS)"
		[ "$iotfirst" = "1" ] || printf ',' >> "$settingstmp"
		printf '\n\t{ip:\x27%s\x27,mac:\x27%s\x27,name:\x27%s\x27,state:\x27%s\x27,blocked:%s}' \
			"$ipaddr" "$macaddr" "$iotnamejs" "$iotstate" "$([ "$iotselected" = "1" ] && printf true || printf false)" >> "$settingstmp" || return 1
		iotfirst="0"
	done < "$iotinventory"
	printf '\n];\n' >> "$settingstmp" || return 1
	rm -f "$iotinventory" "$iotrecords"
}

Generate_WebUI_Feed_Data() {
	feedstatusfile="${skynetloc}/lists/.sources"
	printf 'var SkynetFeeds = [' >> "$settingstmp" || return 1
	feedfirst="1"
	feedtotal="0"
	feedcurrent="0"
	feedcached="0"
	feedfailed="0"
	feedexcluded="0"
	if [ -s "$feedstatusfile" ]; then
		feedtab="$(printf '\t')"
		while IFS="$feedtab" read -r feedname feedurl _feedstatusenabled feedstate feedentries feedchecked feedsuccess _feedhash feedchanged; do
			feedenabled="true"
			feednamelower="$(printf '%s\n' "$feedname" | awk '{ print tolower($0) }')"
			for feedexcludedname in $excludelists; do
				feedexcludedlower="$(printf '%s\n' "$feedexcludedname" | awk '{ print tolower($0) }')"
				if [ "$feedexcludedlower" = "$feednamelower" ]; then
					feedenabled="false"
					break
				fi
			done
			if [ "$feedenabled" = "false" ]; then
				feedstate="excluded"
			elif [ "$feedstate" = "excluded" ]; then
				if [ "$feedentries" -gt 0 ] 2>/dev/null; then feedstate="cached"; else feedstate="failed"; fi
			fi
			case "$feedstate" in current|cached|failed|excluded) ;; *) feedstate="failed" ;; esac
			case "$feedentries" in ""|*[!0-9]*) feedentries="0" ;; esac
			case "$feedchecked" in ""|*[!0-9]*) feedchecked="0" ;; esac
			case "$feedsuccess" in ""|*[!0-9]*) feedsuccess="0" ;; esac
			case "$feedchanged" in ""|*[!0-9]*) feedchanged="0" ;; esac
			feednamejs="$(printf '%s\n' "$feedname" | Escape_JS)"
			feedurljs="$(printf '%s\n' "$feedurl" | Escape_JS)"
			[ "$feedfirst" = "1" ] || printf ',' >> "$settingstmp"
			printf '\n\t{name:\x27%s\x27,url:\x27%s\x27,enabled:%s,state:\x27%s\x27,entries:%s,checked:%s,success:%s,changed:%s}' \
				"$feednamejs" "$feedurljs" "$feedenabled" "$feedstate" "$feedentries" "$feedchecked" "$feedsuccess" "$feedchanged" >> "$settingstmp" || return 1
			feedfirst="0"
			feedtotal=$((feedtotal + 1))
			case "$feedstate" in
				current) feedcurrent=$((feedcurrent + 1)) ;;
				cached) feedcached=$((feedcached + 1)) ;;
				failed) feedfailed=$((feedfailed + 1)) ;;
				excluded) feedexcluded=$((feedexcluded + 1)) ;;
			esac
		done < "$feedstatusfile"
	fi
	printf '\n];\n' >> "$settingstmp" || return 1
	if [ -s "$feedstatusfile" ]; then feedavailable="true"; else feedavailable="false"; fi
	printf 'var SkynetFeedSummary = {available:%s,total:%s,current:%s,cached:%s,failed:%s,excluded:%s};\n' \
		"$feedavailable" "$feedtotal" "$feedcurrent" "$feedcached" "$feedfailed" "$feedexcluded" >> "$settingstmp" || return 1
}

Generate_WebUI_Settings() {
	# settings.js is a complete point-in-time payload. The epoch.pid generation
	# stamp is written last and lets the browser distinguish a completed action
	# from a cached copy of the previous payload.
	settingsfile="${skynetloc}/webui/settings.js"
	settingstmp="${settingsfile}.tmp.$$"
	customlistjs="$(printf '%s' "$customlisturl" | tr '\r\n' '  ' | sed 's/\\/\\\\/g;s/"/\\"/g')"
	excludelistsjs="$(printf '%s\n' "$excludelists" | Escape_JS)"
	iotentries="$(ipset save Skynet-IOT 2>/dev/null | awk '$1 == "add" { if (output != "") output = output " "; output = output $3 } END { print output }')"
	iotcount="$(IPSet_Entry_Count Skynet-IOT)"
	if printf 'var SkynetSettings = {"autoupdate":"%s","banmalwareupdate":"%s","banmalwarelastupdated":"%s","blacklist1count":"%s","blacklist2count":"%s","countrylist":"%s","customlisturl":"%s","excludelists":"%s","filtertraffic":"%s","unbanprivateip":"%s","banaiprotect":"%s","securemode":"%s","loginvalid":"%s","logsize":"%s","extendedstats":"%s","lookupcountry":"%s","cdnwhitelist":"%s","iotblocked":"%s","iotlogging":"%s","iotports":"%s","iotproto":"%s","iotentries":"%s","iotcount":"%s"};\n' "$autoupdate" "$banmalwareupdate" "$banmalwarelastupdated" "$blacklist1count" "$blacklist2count" "$countrylist" "$customlistjs" "$excludelistsjs" "$filtertraffic" "$unbanprivateip" "$banaiprotect" "$securemode" "$loginvalid" "$logsize" "$extendedstats" "$lookupcountry" "$cdnwhitelist" "$iotblocked" "$iotlogging" "$iotports" "$iotproto" "$iotentries" "$iotcount" > "$settingstmp" \
		&& Generate_WebUI_IOT_Data \
		&& Generate_WebUI_Feed_Data \
		&& printf 'var SkynetSettingsGenerated = "%s.%s";\n' "$(date +%s)" "$$" >> "$settingstmp" \
		&& printf 'var SkynetSettingsResult = "%s";\n' "${settingsresult:-ready}" >> "$settingstmp" \
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

	webuistatsactive="1"
	statsworkspace="${skynetloc}/webui/stats"
	if ! mkdir -p "$statsworkspace" || [ ! -w "$statsworkspace" ]; then
		unset "webuistatsactive"
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
	grep -E '^add Skynet-(Blacklist|BlockedRanges) ' "$skynetipset" > "$statsbanlist" || true

	statsprerouting="${statsworkspace}/prerouting.txt"
	statsoutput="${statsworkspace}/output.txt"
	iptables -xnvL PREROUTING -t raw > "$statsprerouting" 2>/dev/null || true > "$statsprerouting"
	iptables -xnvL OUTPUT -t raw > "$statsoutput" 2>/dev/null || true > "$statsoutput"
	statshits="$(awk '
		index($0, "LOG") == 0 && index($0, "Skynet-Master src") { inbound += $1 }
		index($0, "LOG") == 0 && index($0, "Skynet-Master dst") { outbound += $1 }
		END { print inbound + 0, outbound + 0 }
	' "$statsprerouting" "$statsoutput")"
	statshits="${statshits:-0 0}"
	hits1="${statshits%% *}"
	hits2="${statshits#* }"

	Write_Stats_ToJS "$blacklist1count" "$statstmp" "SetBLCount1" "blcount1" || statsstatus="1"
	Write_Stats_ToJS "$blacklist2count" "$statstmp" "SetBLCount2" "blcount2" || statsstatus="1"
	Write_Stats_ToJS "$hits1" "$statstmp" "SetHits1" "hits1" || statsstatus="1"
	Write_Stats_ToJS "$hits2" "$statstmp" "SetHits2" "hits2" || statsstatus="1"
	Write_Stats_ToJS "$(du -h "$skynetlog" | awk '{print $1}')B" "$statstmp" "SetStatsSize" "statssize" || statsstatus="1"
	printf 'var SkynetStatsGenerated = "%s.%s";\n' "$(date +%s)" "$$" >> "$statstmp" || statsstatus="1"

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
		true > "${statsworkspace}/tinvconn-ips.txt"
	fi
	if Is_Enabled "$iotblocked"; then
		Extract_Stats_Values "${statsworkspace}/iot-dst.txt" ".*" "" "" "top" "10" > "${statsworkspace}/tiotconn-ips.txt" || statsstatus="1"
	else
		true > "${statsworkspace}/tiotconn-ips.txt"
	fi
	{
		cat "${statsworkspace}/liconn-ips.txt" "${statsworkspace}/loconn-ips.txt" "${statsworkspace}/lhconn-ips.txt"
		awk 'NF >= 2 {print $NF}' "${statsworkspace}/thconn-ips.txt" "${statsworkspace}/ticonn-ips.txt" \
			"${statsworkspace}/toconn-ips.txt" "${statsworkspace}/tinvconn-ips.txt" "${statsworkspace}/tiotconn-ips.txt"
	} | awk 'NF && !seen[$0]++' > "$statslookupips" || statsstatus="1"
	cat "${statsworkspace}/liconn-ips.txt" "${statsworkspace}/loconn-ips.txt" "${statsworkspace}/lhconn-ips.txt" |
		awk 'NF && !seen[$0]++' > "$statsreasonips" || statsstatus="1"
	Build_Stats_Ban_Reason_Cache "$statsreasonips" "$statsbanlist" "$statsreasoncache" || statsstatus="1"
	Build_Stats_Domain_Cache "$statslookupips" "$statsdomaincache" || statsstatus="1"
	statscountrybatch="1"
	Build_Stats_Country_Cache "$statslookupips" "$statscountrycache" || statsstatus="1"

	# Inbound Ports
	Extract_Stats_Values "${statsworkspace}/inbound-dpt.txt" ".*" "" "" "top" "10" |
		sed "s~^[ \t]*~~;s~ ~\~~g" > "${statsworkspace}/iport.txt"
	Write_Data_ToJS "${statsworkspace}/iport.txt" "$statstmp" "DataInPortHits" "LabelInPortHits" || statsstatus="1"

	# Source Ports
	Extract_Stats_Values "${statsworkspace}/inbound-spt.txt" ".*" "" "" "top" "10" |
		sed "s~^[ \t]*~~;s~ ~\~~g" > "${statsworkspace}/sport.txt"
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
		true > "${statsworkspace}/tinvconn.txt"
	fi
	Write_Data_ToJS "${statsworkspace}/tinvconn.txt" "$statstmp" "DataTInvConnHits" "LabelTInvConnHits_IPs" "LabelTInvConnHits_Country" || statsstatus="1"

	if Is_Enabled "$iotblocked"; then
		Write_Top_IP_Stats "${statsworkspace}/tiotconn.txt" code domains < "${statsworkspace}/tiotconn-ips.txt" || statsstatus="1"
	else
		true > "${statsworkspace}/tiotconn.txt"
	fi
	Write_Data_ToJS "${statsworkspace}/tiotconn.txt" "$statstmp" "DataTIOTConnHits" "LabelTIOTConnHits_IPs" "LabelTIOTConnHits_Country" "LabelTIOTConnHits_AssDomains" || statsstatus="1"

	# Top Clients
	Extract_Stats_Values "${statsworkspace}/outbound-src.txt" ".*" "" "" "top" "10" > "${statsworkspace}/clients.txt"
	statsneighbors="${statsworkspace}/neighbors.txt"
	ip neigh > "$statsneighbors" 2>/dev/null
	while read -r statsclienthits statsclientip; do
		[ -n "$statsclientip" ] || continue
		ipaddr="$statsclientip"
		macaddr="$(awk -v ip="$statsclientip" '$1 == ip {print $5; exit}' "$statsneighbors")"
		Resolve_Client_Name
		printf '%s\n' "$macaddr" | Is_MAC || macaddr="Unknown"
		[ "${#localname}" -le 20 ] || localname="$(printf '%s' "$localname" | cut -c1-20)"
		printf '%s~%s (%s)~%s\n' "$statsclienthits" "$statsclientip" "$localname" "$macaddr"
	done < "${statsworkspace}/clients.txt" > "${statsworkspace}/tcconn.txt"
	Write_Data_ToJS "${statsworkspace}/tcconn.txt" "$statstmp" "DataTCConnHits" "LabelTCConnHits" "LabelTCConnHits_MAC" || statsstatus="1"

	if [ "$statsstatus" = "0" ] && printf 'var SkynetStatsComplete = true;\n' >> "$statstmp" \
		&& [ -s "$statstmp" ] && mv -f "$statstmp" "$statsfile"; then
		rm -rf "$statsworkspace"
		unset "webuistatsactive"
		Generate_WebUI_Settings
		return "$?"
	fi

	rm -f "$statstmp"
	rm -rf "$statsworkspace"
	unset "webuistatsactive"
	Log error "Failed To Generate WebUI Statistics - Existing File Retained"
	Generate_WebUI_Settings
	return 1
}
Generate_Blocked_Events() {
	# Count events, unique remote IPs and the monitor span in one log pass. A
	# manual counter is used because POSIX awk does not define length(array).
	if blockedeventsummary="$(awk '
		/BLOCKED -/ {
			stamp=$1 " " $2 " " $3
			if (monitorfirst == "") monitorfirst=stamp
			monitorlast=stamp
		}
		/INBOUND|INVALID/ {
			for (i = 1; i <= NF; i++)
				if ($i ~ /^SRC=/) {
					split($i, ip, "=")
					if (ip[2] ~ /^[0-9.]+$/ && !seen[ip[2]]++) uniquecount++
					break
				}
		}
		/OUTBOUND/ {
			for (i = 1; i <= NF; i++)
				if ($i ~ /^DST=/) {
					split($i, ip, "=")
					if (ip[2] ~ /^[0-9.]+$/ && !seen[ip[2]]++) uniquecount++
					break
				}
		}
		END { printf "%d (%d Unique IPs)|%s|%s", NR, uniquecount, monitorfirst, monitorlast }
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
	if ! Is_Enabled "$logmode"; then
		Log error "WebUI Integration Requires Logging To Be Enabled"
		return 1
	fi
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
			sed -i "\\~$MyPage~d" /tmp/menuTree.js
			umount /www/require/modules/menuTree.js
			mount -o bind /tmp/menuTree.js /www/require/modules/menuTree.js
		else
			MyPageTitle="${MyPage%.asp}.title"
			rm -f "/www/user/$MyPageTitle"
		fi
		rm -f "/www/user/$MyPage"
		rm -rf "/www/user/skynet"
		Unload_Cron "genstats"
	fi
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

####################
#- Menu Utilities -#
####################

Return_To_Menu() {
	unset "option1" "option2" "option3" "option4" "option5"
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

Purge_Logs() {
	# Extract all BLOCKED lines into skynetlog, then delete them from source
	archivefailed="0"
	for syslogfile in "$syslog1loc" "$syslogloc"; do
		[ -f "$syslogfile" ] || continue
		if sed -n '\~BLOCKED -~p' "$syslogfile" >> "$skynetlog" 2>/dev/null; then
			sed -i '\~BLOCKED -~d' "$syslogfile" 2>/dev/null || archivefailed="1"
		else
			archivefailed="1"
		fi
	done
	[ "$archivefailed" = "0" ] || Log error "Failed To Archive Firewall Logs - Source Logs Retained"
	logcounts="$(awk '
		/Skynet: \[#\]/ { events++ }
		/Skynet: \[i\] Startup Initiated/ { starts++ }
		/Skynet: \[i\] Restarting Firewall Service/ { restarts++ }
		END { print events + 0, starts + 0, restarts + 0 }
	' "$syslogloc" 2>/dev/null)"
	logcounts="${logcounts:-0 0 0}"
	count_events="${logcounts%% *}"
	logcounts="${logcounts#* }"
	start_count="${logcounts%% *}"
	restart_count="${logcounts#* }"

	# Ensure skynetlog isn’t too large (or force), run stats, and truncate if still big
	log_kb=$(du -k "$skynetlog" 2>/dev/null | cut -f1) || log_kb=0
	log_kb=${log_kb:-0}
	log_kb_limit="$((logsize * 1024))"
	if [ "$log_kb" -ge "$log_kb_limit" ] || [ "$1" = "force" ]; then
		if Generate_Stats; then
			sed -i '/BLOCKED -/d' "$skynetlog" 2>/dev/null
			sed -i '/Skynet: \[#\] /d' "$skynetevents" 2>/dev/null
			iptables -Z PREROUTING -t raw
			log_kb=$(du -k "$skynetlog" 2>/dev/null | cut -f1) || log_kb=0
			log_kb=${log_kb:-0}
			[ "$log_kb" -ge 3000 ] && : > "$skynetlog"
		else
			Log error "Failed To Generate Statistics - Firewall Logs Retained"
		fi
	fi

	# Move numbered Skynet event lines into events.log, then purge info and lock entries
	if [ "$1" = "all" ] || [ "$count_events" -gt 24 ]; then
		archivefailed="0"
		for syslogfile in "$syslog1loc" "$syslogloc"; do
			[ -f "$syslogfile" ] || continue
			if sed -n '/Skynet: \[#\] /p' "$syslogfile" >> "$skynetevents" 2>/dev/null; then
				sed -i '
					/Skynet: \[i\] /{
						/Startup Initiated/!{
							/Restarting Firewall Service/!d
						}
					}
					/Skynet: \[#\] /d
					/Skynet: \[\*\] Lock /d
				' "$syslogfile" 2>/dev/null || archivefailed="1"
			else
				archivefailed="1"
			fi
		done
		[ "$archivefailed" = "0" ] || Log error "Failed To Archive Skynet Events - Source Logs Retained"
	fi

	# If more than three startup banners exist, remove them all so only the next one appears
	if [ "$start_count" -gt 3 ]; then
		sed -i '/Skynet: \[i\] Startup Initiated/d' "$syslog1loc" "$syslogloc" 2>/dev/null
	fi

	# If more than three restart banners exist, remove them all so only the next one appears
	if [ "$restart_count" -gt 3 ]; then
		sed -i '/Skynet: \[i\] Restarting Firewall Service/d' "$syslog1loc" "$syslogloc" 2>/dev/null
	fi

	# Reload syslog-ng only if configured
	[ -f "/opt/etc/syslog-ng.d/skynet" ] && killall -HUP syslog-ng 2>/dev/null
	return 0
}

Print_Command_Summary() {
	oldips="${blacklist1count:-0}"
	oldranges="${blacklist2count:-0}"
	blacklist1count="$(IPSet_Entry_Count Skynet-Blacklist)"
	blacklist2count="$(IPSet_Entry_Count Skynet-BlockedRanges)"
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
	ftime="$(($(date +%s) - stime))"
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

Write_Config_Value() {
	# Escape shell-sensitive characters before writing a value that Load_Config
	# will later source. Embedded newlines are flattened to one configuration line.
	awk -v key="$1" '
		function escape(value, i, char, output) {
			for (i = 1; i <= length(value); i++) {
				char = substr(value, i, 1)
				if (char == "\\") output = output "\\\\"
				else if (char == "\"") output = output "\\\""
				else if (char == "$") output = output "\\$"
				else if (char == "`") output = output "\\`"
				else if (char != "\r") output = output char
			}
			return output
		}
		{
			if (NR > 1) value = value " "
			value = value $0
		}
		END { printf "%s=\"%s\"\n", key, escape(value) }
	' <<EOF
$2
EOF
}

Load_Config() {
	[ -f "$skynetcfg" ] || return 1
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

	# Invalid or missing values use conservative defaults. This preserves the old
	# effective behaviour without accidentally enabling a protection feature.
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
			case "$configitem" in [a-z][a-z]) ;; *) configinvalid="1" ;; esac
		done
		if [ "$configinvalid" = "1" ] || [ -z "$countrylist" ]; then
			countrylist="$(sed -n 's~.*comment "Country: \([A-Za-z][A-Za-z]\)".*~\1~p' "$skynetipset" 2>/dev/null | awk '{ value = tolower($0); if (!seen[value]++) { if (output != "") output = output " "; output = output value } } END { print output }')"
			configchanged="1"
		elif [ "$countrylist" != "$configoldlist" ]; then
			configchanged="1"
		fi
	fi
	if [ -n "$excludelists" ]; then
		# Exclusions are exact filter-list basenames, never regular expressions.
		configoldlist="$excludelists"
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
		# Before explicit port policies, an empty list used the selected protocol
		# for port 123. Preserve that uncommon legacy rule as a custom port before
		# making the empty/default policy the technically correct UDP NTP rule.
		iotports="123"
		configchanged="1"
	elif [ "$iotports" != "none" ] && [ -n "$iotports" ]; then
		# iptables multiport accepts no more than 15 ports. Clearing an invalid
		# legacy list safely restores Skynet's documented NTP default.
		configoldlist="$iotports"
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
	# Write beside the live file and rename only after a complete non-empty file
	# exists. A failed write therefore retains the previous configuration.
	configtmp="${skynetcfg}.tmp.$$"
	{
		printf '%s\n' "################################################"
		printf '%s\n' "## Generated By Skynet - Do Not Manually Edit ##"
		printf '%-45s %s\n\n' "## $(date +"%b %e %T")" "##"
		printf '%s\n' "## Installer ##"
		Write_Config_Value "model" "$model"
		Write_Config_Value "localver" "$localver"
		Write_Config_Value "swaplocation" "$swaplocation"
		printf '\n%s\n' "## Counters / Lists ##"
		Write_Config_Value "blacklist1count" "$blacklist1count"
		Write_Config_Value "blacklist2count" "$blacklist2count"
		Write_Config_Value "customlisturl" "$customlisturl"
		Write_Config_Value "banmalwarelastupdated" "$banmalwarelastupdated"
		Write_Config_Value "countrylist" "$countrylist"
		Write_Config_Value "excludelists" "$excludelists"
		printf '\n%s\n' "## Updates & Lists ##"
		Write_Config_Value "autoupdate" "$autoupdate"
		Write_Config_Value "banmalwareupdate" "$banmalwareupdate"
		Write_Config_Value "forcebanmalwareupdate" "$forcebanmalwareupdate"
		printf '\n%s\n' "## Protection ##"
		Write_Config_Value "filtertraffic" "$filtertraffic"
		Write_Config_Value "unbanprivateip" "$unbanprivateip"
		Write_Config_Value "banaiprotect" "$banaiprotect"
		Write_Config_Value "securemode" "$securemode"
		Write_Config_Value "cdnwhitelist" "$cdnwhitelist"
		printf '\n%s\n' "## IoT Isolation ##"
		Write_Config_Value "iotblocked" "$iotblocked"
		Write_Config_Value "iotlogging" "$iotlogging"
		Write_Config_Value "iotports" "$iotports"
		Write_Config_Value "iotproto" "$iotproto"
		printf '\n%s\n' "## Logging & Statistics ##"
		Write_Config_Value "logmode" "$logmode"
		Write_Config_Value "loginvalid" "$loginvalid"
		Write_Config_Value "logsize" "$logsize"
		Write_Config_Value "extendedstats" "$extendedstats"
		Write_Config_Value "syslogloc" "$syslogloc"
		Write_Config_Value "syslog1loc" "$syslog1loc"
		Write_Config_Value "lookupcountry" "$lookupcountry"
		printf '\n%s\n' "## Integration & Advanced ##"
		Write_Config_Value "displaywebui" "$displaywebui"
		printf '\n%s\n' "################################################"
	} > "$configtmp" && [ -s "$configtmp" ] && mv -f "$configtmp" "$skynetcfg" && return 0
	rm -f "$configtmp"
	Log error "Failed To Write Config - Existing File Retained"
	return 1
}

Run_WebUI_Command() {
	# Merlin service-event actions run independently of the page request. Wait
	# for the active Skynet owner to finish, then invoke the normal CLI handler.
	webuiwait="0"
	while [ -f "$LOCK_FILE" ]; do
		webuipid="$(cut -d'|' -f2 "$LOCK_FILE" 2>/dev/null)"
		if [ -z "$webuipid" ] || [ ! -d "/proc/$webuipid" ]; then
			break
		fi
		[ "$webuiwait" -ge "300" ] && return 1
		sleep 1
		webuiwait=$((webuiwait + 1))
	done
	sh "$0" "$@"
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
	if [ ! -f "/usr/sbin/helper.sh" ]; then
		settingsresult="error"
	else
		# shellcheck disable=SC1091
		. /usr/sbin/helper.sh
		webuiautoupdate="$(am_settings_get skynet_autoupdate)"
		webuifilter="$(am_settings_get skynet_filtertraffic)"
		webuimalware="$(am_settings_get skynet_banmalwareupdate)"
		webuicustomlist="$(am_settings_get skynet_customlisturl)"
		webuiunbanprivate="$(am_settings_get skynet_unbanprivateip)"
		webuiaiprotect="$(am_settings_get skynet_banaiprotect)"
		webuisecuremode="$(am_settings_get skynet_securemode)"
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

	Load_Config || settingsresult="error"
	Generate_WebUI_Settings
}

Apply_WebUI_Threat_Feeds() {
	# Feed selection and blacklist replacement are one CLI transaction. The WebUI
	# only stages the complete exclusion list and translates the worker result into
	# compact tokens consumed by the existing settings.js poller.
	settingsresult="error"
	webuifeedoutput="$TMP_DIR/webui-feed-output"
	webuifeedchange="0"
	if [ -f "/usr/sbin/helper.sh" ]; then
		# shellcheck disable=SC1091
		. /usr/sbin/helper.sh
		webuifeedchange="$(am_settings_get skynet_feedchange)"
		if [ "$webuifeedchange" = "1" ]; then
			webuiexclusions="$(am_settings_get skynet_excludelists)"
			if [ -n "$webuiexclusions" ]; then
				webuiexclusions="$(Normalize_List "$webuiexclusions")" || settingsresult="filter"
				for webuiexclusion in $webuiexclusions; do
					printf '%s\n' "$webuiexclusion" | grep -qE '^[A-Za-z0-9._-]+$' || settingsresult="filter"
				done
			fi
		fi

		if [ "$settingsresult" != "filter" ]; then
			if [ "$webuifeedchange" = "1" ] && [ -n "$webuiexclusions" ]; then
				Run_WebUI_Command banmalware exclude "$webuiexclusions" > "$webuifeedoutput" 2>&1
				webuifeedstatus="$?"
			elif [ "$webuifeedchange" = "1" ]; then
				Run_WebUI_Command banmalware exclude reset > "$webuifeedoutput" 2>&1
				webuifeedstatus="$?"
			else
				Run_WebUI_Command banmalware > "$webuifeedoutput" 2>&1
				webuifeedstatus="$?"
			fi

			if [ "$webuifeedstatus" = "0" ]; then
				if awk -F '\t' '$3 == "enabled" && $4 == "cached" { found=1 } END { exit !found }' "${skynetloc}/lists/.sources" 2>/dev/null; then
					settingsresult="degraded"
				else
					settingsresult="success"
				fi
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
	Generate_WebUI_Settings
}

Apply_WebUI_Countries() {
	# Country CLI updates are atomic. Preserve its specific failure reason in a
	# compact result token so JavaScript can present a useful message.
	settingsresult="error"
	if [ -f "/usr/sbin/helper.sh" ]; then
		# shellcheck disable=SC1091
		. /usr/sbin/helper.sh
		webuicountries="$(am_settings_get skynet_countrylist | awk '{$1=$1; print tolower($0)}')"

		if [ -z "$webuicountries" ] || printf '%s\n' "$webuicountries" | grep -qE '^([a-z][a-z])( [a-z][a-z])*$'; then
			if [ "$webuicountries" = "$countrylist" ]; then
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
	Generate_WebUI_Settings
}

Replace_IOT_Entries() {
	# Replace the complete IoT IPSet from validated entries. The saved snapshot
	# is restored if either the flush or replacement restore fails.
	iotreplacelist="$1"
	iotreplacesnapshot="$TMP_DIR/iot-snapshot.$$"
	iotreplacefile="$TMP_DIR/iot-replace.$$"

	if ! ipset save Skynet-IOT > "$iotreplacesnapshot" 2>/dev/null; then
		return 1
	fi
	true > "$iotreplacefile" || return 1
	for iotreplaceentry in $iotreplacelist; do
		printf 'add Skynet-IOT %s comment "IOTBan: %s"\n' "$iotreplaceentry" "$(date +"%b %e %T")" >> "$iotreplacefile"
	done
	if ipset flush Skynet-IOT && { [ ! -s "$iotreplacefile" ] || ipset restore -! < "$iotreplacefile"; }; then
		rm -f "$iotreplacesnapshot" "$iotreplacefile"
		return 0
	fi
	ipset flush Skynet-IOT 2>/dev/null
	ipset restore -! < "$iotreplacesnapshot" 2>/dev/null
	rm -f "$iotreplacesnapshot" "$iotreplacefile"
	return 1
}

Restore_WebUI_IOT() {
	# Roll back IPSet contents, rule options, switches and persistent files as one
	# unit after a failed WebUI IoT transaction.
	Unload_LogIPTables
	Unload_IOT_Rules 2>/dev/null
	ipset flush Skynet-IOT 2>/dev/null
	ipset restore -! < "$iotwebsnapshot" 2>/dev/null
	iotports="$iotweboldports"
	iotproto="$iotweboldproto"
	iotblocked="$iotweboldblocked"
	iotlogging="$iotweboldlogging"
	Load_IOT_Rules
	Load_LogIPTables
	Save_IPSets && Write_Config
}

Apply_WebUI_IOT() {
	# Validate every field before unloading live rules. Once validation passes,
	# retain both the IPSet and scalar settings needed for full rollback.
	settingsresult="error"
	[ -f "/usr/sbin/helper.sh" ] || { Generate_WebUI_Settings; return 1; }
	# shellcheck disable=SC1091
	. /usr/sbin/helper.sh
	webuiiotentries="$(am_settings_get skynet_iotentries)"
	webuiiotports="$(am_settings_get skynet_iotports)"
	webuiiotproto="$(am_settings_get skynet_iotproto)"
	webuiiotblocked="$(am_settings_get skynet_iotblocked)"
	webuiiotlogging="$(am_settings_get skynet_iotlogging)"

	if [ -n "$webuiiotentries" ]; then
		webuiiotentries="$(Normalize_List "$webuiiotentries")" || { Generate_WebUI_Settings; return 2; }
		for webuiiotentry in $webuiiotentries; do
			printf '%s\n' "$webuiiotentry" | Is_IPRange || { Generate_WebUI_Settings; return 2; }
		done
	fi
	if [ "$webuiiotports" != "none" ] && [ -n "$webuiiotports" ]; then
		webuiiotports="$(Normalize_List "$webuiiotports")" || { Generate_WebUI_Settings; return 2; }
		webuiiotportcount="0"
		for webuiiotport in $webuiiotports; do
			printf '%s\n' "$webuiiotport" | Is_Port || { Generate_WebUI_Settings; return 2; }
			webuiiotportcount=$((webuiiotportcount + 1))
		done
		[ "$webuiiotportcount" -le "15" ] || { Generate_WebUI_Settings; return 2; }
	fi
	case "$webuiiotproto" in udp|tcp|all) ;; *) Generate_WebUI_Settings; return 2 ;; esac
	# The empty policy is always the canonical UDP NTP default. Normalizing here
	# also protects requests submitted by an older cached WebUI.
	[ -n "$webuiiotports" ] || webuiiotproto="udp"
	case "$webuiiotblocked:$webuiiotlogging" in
		enabled:enabled|enabled:disabled|disabled:enabled|disabled:disabled) ;;
		*) Generate_WebUI_Settings; return 2 ;;
	esac

	iotwebsnapshot="$TMP_DIR/iot-webui-old.$$"
	ipset save Skynet-IOT > "$iotwebsnapshot" 2>/dev/null || { Generate_WebUI_Settings; return 1; }
	iotweboldports="$iotports"
	iotweboldproto="$iotproto"
	iotweboldblocked="$iotblocked"
	iotweboldlogging="$iotlogging"
	Unload_LogIPTables
	if ! Unload_IOT_Rules || ! Replace_IOT_Entries "$webuiiotentries"; then
		Load_IOT_Rules
		Load_LogIPTables
		rm -f "$iotwebsnapshot"
		Generate_WebUI_Settings
		return 1
	fi
	iotports="$webuiiotports"
	iotproto="$webuiiotproto"
	iotblocked="$webuiiotblocked"
	iotlogging="$webuiiotlogging"
	if ! Load_IOT_Rules; then
		Restore_WebUI_IOT || Log error -s "Failed To Fully Restore IoT Configuration"
		rm -f "$iotwebsnapshot"
		Generate_WebUI_Settings
		return 1
	fi
	Load_LogIPTables
	if ! Save_IPSets || ! Write_Config; then
		Restore_WebUI_IOT || Log error -s "Failed To Fully Restore IoT Configuration"
		rm -f "$iotwebsnapshot"
		Generate_WebUI_Settings
		return 1
	fi
	nocfg="1"
	awk '$1 == "add" { print $3 }' "$iotwebsnapshot" | while IFS= read -r iotoldentry; do
		case " $webuiiotentries " in
			*" $iotoldentry "*) ;;
			*) sed -i "\\~BLOCKED - IOT.*=$iotoldentry ~d" "$skynetlog" ;;
		esac
	done
	rm -f "$iotwebsnapshot"
	settingsresult="success"
	Generate_WebUI_Settings
}

######################
#- Command Handlers -#
######################

Dispatch_Unban() {
	Check_Lock "$@"
	Require_Running
	Purge_Logs
	case "$2" in
		ip)
			unbanlist="$(Normalize_Arguments_From 3 "$@")" || { echo "[*] IP Field Can't Be Empty"; echo; exit 2; }
			for unbanentry in $unbanlist; do
				if ! printf '%s\n' "$unbanentry" | Is_IP; then echo "[*] $unbanentry Is Not A Valid IP"; echo; exit 2; fi
			done
			echo "[i] Unbanning $unbanlist"
			Update_IPSet_Batch del Skynet-Blacklist "" "$unbanlist" || { echo; exit 1; }
			for unbanentry in $unbanlist; do
				sed -i "\\~\\(BLOCKED.*=$unbanentry \\|Manual Ban.*=$unbanentry \\)~d" "$skynetlog" "$skynetevents"
			done
		;;
		range)
			unbanlist="$(Normalize_Arguments_From 3 "$@")" || { echo "[*] Range Field Can't Be Empty"; echo; exit 2; }
			for unbanentry in $unbanlist; do
				if ! printf '%s\n' "$unbanentry" | Is_Range; then echo "[*] $unbanentry Is Not A Valid Range"; echo; exit 2; fi
			done
			echo "[i] Unbanning $unbanlist"
			Update_IPSet_Batch del Skynet-BlockedRanges "" "$unbanlist" || { echo; exit 1; }
			for unbanentry in $unbanlist; do
				sed -i "\\~\\(BLOCKED.*=$unbanentry \\|Manual Ban.*=$unbanentry \\)~d" "$skynetlog" "$skynetevents"
			done
		;;
		domain)
			Require_Connection
			if [ -z "$3" ]; then echo "[*] Domain Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
			domain="$(Normalize_Domain "$3")" || { echo "[*] $3 Is Not A Valid Domain"; echo; exit 2; }
			domainips="$(Resolve_Domain_IP_List "$domain" all)" || { echo "[*] Unable To Resolve $domain"; echo; exit 1; }
			echo "[i] Removing $domain From Blacklist"
			Update_IPSet_Batch del Skynet-Blacklist "" "$domainips" || { echo; exit 1; }
			for ip in $domainips; do
				echo "[i] Unbanning $ip"
				sed -i "\\~\\(BLOCKED.*=$ip \\|Manual Ban.*=$ip \\)~d" "$skynetlog" "$skynetevents"
			done
		;;
		comment)
			if [ -z "$3" ]; then echo "[*] Comment Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
			echo "[i] Removing Bans With Comment Containing ($3)"
			Remove_IPSet_Entries Skynet-Blacklist "$3" || { echo; exit 1; }
			Remove_IPSet_Entries Skynet-BlockedRanges "$3" || { echo; exit 1; }
			echo "[i] Removing Old Logs - This May Take Awhile (To Skip Type ctrl+c)"
			trap 'echo;echo;echo "[*] Interrupted"; break' INT
			{ Get_IPSet_Entries Skynet-Blacklist "$3"; Get_IPSet_Entries Skynet-BlockedRanges "$3"; } | awk '{ print $3 }' | while IFS= read -r "ip"; do
				sed -i "\\~\\(BLOCKED.*=$ip \\|Manual Ban.*=$ip \\)~d" "$skynetlog" "$skynetevents"
			done
			Set_Cleanup_Traps
		;;
		country)
			echo "[i] Removing Previous Country Bans (${countrylist})"
			Remove_IPSet_Entries Skynet-BlockedRanges "Country: " || { echo; exit 1; }
			unset "countrylist"
		;;
		asn)
			if [ -z "$3" ]; then echo "[*] ASN Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
			if ! echo "$3" | Is_ASN; then echo "[*] $3 Is Not A Valid ASN"; echo; exit 2; fi
			asnlist="$(echo "$3" | awk '{print toupper($0)}')"
			echo "[i] Removing Previous $asnlist Bans"
			Remove_IPSet_Entries Skynet-BlockedRanges "$asnlist " || { echo; exit 1; }
		;;
		malware)
			echo "[i] Removing Previous Malware Blacklist Entries"
			Remove_IPSet_Entries Skynet-Blacklist "BanMalware" || { echo; exit 1; }
			Remove_IPSet_Entries Skynet-BlockedRanges "BanMalware" || { echo; exit 1; }
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
	Require_Save_IPSets
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
	countryfetchvalid="0"
	rm -f "$countryfetchraw" "$countryfetchzone" "$countryfetchresult"
	if [ -s "$countryfetchcache" ] && [ -s "$countrycachemanifest" ] \
		&& awk -F '\t' -v code="$countryfetchcode" -v url="$countryfetchurl" \
			'$1 == code && $2 == url {found=1} END {exit !found}' "$countrycachemanifest"; then
		countryfetchvalid="1"
		countryfetchhttp="$(Curl_Fetch -z "$countryfetchcache" -o "$countryfetchraw" -w '%{http_code}' "$countryfetchurl")"
		countryfetchstatus="$?"
	else
		countryfetchhttp="$(Curl_Fetch -o "$countryfetchraw" -w '%{http_code}' "$countryfetchurl")"
		countryfetchstatus="$?"
	fi
	if [ "$countryfetchstatus" = "0" ] && [ "$countryfetchhttp" = "304" ] && [ "$countryfetchvalid" = "1" ]; then
		rm -f "$countryfetchraw"
		printf 'current\n' > "$countryfetchresult"
	elif [ "$countryfetchstatus" = "0" ] && [ -s "$countryfetchraw" ]; then
		if Normalize_Country_Zone "$countryfetchraw" "$countryfetchzone"; then
			rm -f "$countryfetchraw"
			printf 'downloaded\n' > "$countryfetchresult"
		elif [ "$countryfetchvalid" = "1" ]; then
			rm -f "$countryfetchraw" "$countryfetchzone"
			printf 'cached\n' > "$countryfetchresult"
		else
			rm -f "$countryfetchraw" "$countryfetchzone"
			printf 'invalid\n' > "$countryfetchresult"
		fi
	elif [ "$countryfetchvalid" = "1" ]; then
		rm -f "$countryfetchraw" "$countryfetchzone"
		printf 'cached\n' > "$countryfetchresult"
	else
		rm -f "$countryfetchraw" "$countryfetchzone"
		printf 'failed\n' > "$countryfetchresult"
	fi
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
		[ -s "$countryresultfile" ] && IFS= read -r countryresult < "$countryresultfile"
		case "$countryresult" in
			downloaded) countrysource="$TMP_DIR/country.${country}.zone" ;;
			current) countrysource="${countrycachedir}/${country}.zone" ;;
			cached)
				countrysource="${countrycachedir}/${country}.zone"
				countrydegraded="${countrydegraded}${countrydegraded:+ }${country}"
				echo "[!] Using Cached Country List (${country})"
			;;
			invalid)
				echo "[*] No Valid IPv4 Ranges Found For (${country})"
				return 1
			;;
			*)
				echo "[*] Failed To Download Country List (${country})"
				return 1
			;;
		esac
		awk -v code="$country" '{printf "add Skynet-BlockedRanges %s comment \"Country: %s\"\n", $1, code}' "$countrysource" >> "$countrytmp" || return 1
	done
	[ -s "$countrytmp" ]
}

Publish_Country_Cache() {
	countrypublishlist="$1"
	countrymanifesttmp="${countrycachemanifest}.tmp.$$"
	true > "$countrymanifesttmp" || return 1
	for country in $countrypublishlist; do
		countryresult=""
		[ -s "$TMP_DIR/country.${country}.result" ] && IFS= read -r countryresult < "$TMP_DIR/country.${country}.result"
		if [ "$countryresult" = "downloaded" ]; then
			mv -f "$TMP_DIR/country.${country}.zone" "${countrycachedir}/${country}.zone" \
				|| { rm -f "$countrymanifesttmp"; return 1; }
		fi
		[ -s "${countrycachedir}/${country}.zone" ] || { rm -f "$countrymanifesttmp"; return 1; }
		printf '%s\t%s\n' "$country" "https://www.ipdeny.com/ipblocks/data/aggregated/${country}-aggregated.zone" >> "$countrymanifesttmp" \
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

Dispatch_Ban() {
	Check_Lock "$@"
	Require_Running
	Purge_Logs
	case "$2" in
		ip)
			shift 2
			Parse_IPSet_Entry_Arguments ip 244 "$@" || { echo "[*] $parsederror"; echo; exit 2; }
			banlist="$parsedentries"
			desc="$parsedcomment"
			[ -n "$desc" ] || desc="$(date +"%b %e %T")"
			echo "[i] Banning $banlist"
			Update_IPSet_Batch add Skynet-Blacklist "ManualBan: $desc" "$banlist" || { echo; exit 1; }
			for banentry in $banlist; do
				echo "$(date +"%b %e %T") Skynet: [Manual Ban] TYPE=Single SRC=$banentry COMMENT=$desc " >> "$skynetevents"
			done
		;;
		range)
			shift 2
			Parse_IPSet_Entry_Arguments range 243 "$@" || { echo "[*] $parsederror"; echo; exit 2; }
			banlist="$parsedentries"
			desc="$parsedcomment"
			[ -n "$desc" ] || desc="$(date +"%b %e %T")"
			echo "[i] Banning $banlist"
			Update_IPSet_Batch add Skynet-BlockedRanges "ManualRBan: $desc" "$banlist" || { echo; exit 1; }
			for banentry in $banlist; do
				echo "$(date +"%b %e %T") Skynet: [Manual Ban] TYPE=Range SRC=$banentry COMMENT=$desc " >> "$skynetevents"
			done
		;;
		domain)
			Require_Connection
			if [ -z "$3" ]; then echo "[*] Domain Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
			domain="$(Normalize_Domain "$3")" || { echo "[*] $3 Is Not A Valid Domain"; echo; exit 2; }
			domainips="$(Resolve_Domain_IP_List "$domain" public)" || { echo "[*] Unable To Resolve A Public IP For $domain"; echo; exit 1; }
			echo "[i] Adding $domain To Blacklist"
			Update_IPSet_Batch add Skynet-Blacklist "ManualBanD: $domain" "$domainips" || { echo; exit 1; }
			for ip in $domainips; do
				echo "[i] Banning $ip"
				echo "$(date +"%b %e %T") Skynet: [Manual Ban] TYPE=Domain SRC=$ip Host=$domain " >> "$skynetevents"
			done
		;;
		country)
			# Validate and de-duplicate the complete request before downloading or
			# changing any existing country bans.
			country_raw="$(Normalize_Arguments_From 3 "$@")" || { echo "[*] Country Field Can't Be Empty"; echo; exit 2; }
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

			echo "[i] Banning Known IP Ranges For (${countrylinklist})"
			echo "[i] Downloading Lists, Filtering IPv4 Ranges & Applying Blacklists"
			if ! Build_Country_Update "$countrylinklist"; then
				rm -f "$countrytmp" "$TMP_DIR"/country.*.raw "$TMP_DIR"/country.*.zone "$TMP_DIR"/country.*.result
				exit 1
			fi

			if ! Replace_Range_IPSet_Entries "Country: " "$countrytmp"; then
				rm -f "$countrytmp"
				echo "[*] Failed To Apply Country Bans - Previous Bans Restored"
				exit 1
			fi

			countrylist="$countrylinklist"
			Publish_Country_Cache "$countrylinklist" || Log error -s "Failed To Publish Country List Cache"
			if [ -n "$countrydegraded" ]; then
				echo "[!] Country Blocking Updated Using Cached Data (${countrydegraded})"
			fi
			rm -f "$countrytmp"
		;;
		asn)
			Require_Connection
			if [ -z "$3" ]; then echo "[*] ASN Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
			if ! echo "$3" | Is_ASN; then echo "[*] $3 Is Not A Valid ASN"; echo; exit 2; fi
			asnlist="$(echo "$3" | awk '{print toupper($0)}')"
			echo "[i] Adding $asnlist To Blacklist"
			if ! Apply_ASN_List "Skynet-BlockedRanges" "$asnlist"; then
				echo "[*] Failed To Download Or Apply $asnlist"
				echo
				exit 1
			fi
		;;
		*)
			Command_Not_Recognized
		;;
	esac
	echo "[i] Saving Changes"
	Require_Save_IPSets
}

Prepare_Malware_Update() {
if [ "$2" = "include" ]; then
	includelists="$(Normalize_Arguments_From 3 "$@")" || { echo "[*] Include List Can't Be Empty"; echo; return 2; }
	for includelist in $includelists; do
		if ! printf '%s\n' "$includelist" | grep -qE '^[A-Za-z0-9._-]+$'; then
			echo "[*] $includelist Is Not A Valid List Name"
			echo
			return 2
		fi
		if ! printf '%s\n' "$excludelists" | awk -v name="$includelist" '
			{ for (i = 1; i <= NF; i++) if (tolower($i) == tolower(name)) found=1 }
			END { exit !found }'; then
			echo "[*] $includelist Is Not Currently Excluded"
			echo
			return 2
		fi
	done
	excludelists="$(printf '%s\n' "$excludelists" | awk -v included="$includelists" '
		BEGIN {
			split(included, values, " ")
			for (i in values) remove[tolower(values[i])] = 1
		}
		{
			for (i = 1; i <= NF; i++) {
				if (tolower($i) in remove) continue
				if (output != "") output = output " "
				output = output $i
			}
		}
		END { print output }')"
	echo "[i] Including Lists: $includelists"
	set -- "banmalware"
fi
if [ "$2" = "exclude" ]; then
	if [ "$3" = "reset" ] || [ -z "$3" ]; then
		echo "[i] Exclusion List Reset"
		unset "excludelists"
	else
		excludelists="$(Normalize_Arguments_From 3 "$@")" || { echo "[*] Invalid Exclusion List"; echo; return 2; }
		for excludelist in $excludelists; do
			if ! printf '%s\n' "$excludelist" | grep -qE '^[A-Za-z0-9._-]+$'; then
				echo "[*] $excludelist Is Not A Valid List Name"
				echo
				return 2
			fi
		done
	fi
	set -- "banmalware"
fi
if [ -n "$excludelists" ]; then echo "[i] Excluding Lists: $excludelists"; fi
if [ "$2" = "reset" ]; then
	echo "[i] Filter URL Reset"
	unset "customlisturl"
fi
if [ -n "$2" ] && [ "$2" != "reset" ]; then
	customlisturl="$2"
	listurl="$customlisturl"
	echo "[i] Custom Filter Detected: $customlisturl"
else
	if [ -n "$customlisturl" ]; then
		listurl="$customlisturl"
		echo "[i] Custom Filter Detected: $customlisturl"
	else
		listurl="https://raw.githubusercontent.com/Adamm00/IPSet_ASUS/master/filter.list"
	fi
fi
}

Fetch_Threat_Feed_Sources() {
	# Revalidate URL-bound caches with If-Modified-Since. Workers publish small
	# result files because background subshell assignments cannot update BusyBox
	# ash's parent process.
	Start_Background_Jobs
	while IFS="$feedtab" read -r list url selection; do
		[ "$selection" = "enabled" ] || continue
		(
			listfile="${skynetloc}/lists/$list"
			listtmp="${skynetloc}/lists/${list}.tmp.$$"
			feedresult="$TMP_DIR/feed.${list}.result"
			cachevalid="0"
			oldsuccess="0"
			rm -f "$listtmp" "$feedresult"
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
				printf 'current\t%s\t%s\n' "$feedchecked" "$feedchecked" > "$feedresult"
				echo "[✔] Up To Date $url"
			elif [ "$downloadstatus" = "0" ] && [ -s "$listtmp" ] && dos2unix "$listtmp"; then
				printf 'downloaded\t%s\t%s\n' "$feedchecked" "$feedchecked" > "$feedresult"
				echo "[✔] Downloaded $url"
			elif [ "$cachevalid" = "1" ]; then
				rm -f "$listtmp"
				printf 'cached\t%s\t%s\n' "$feedchecked" "$oldsuccess" > "$feedresult"
				echo "[!] Download Failed - Checking Cached $url"
			else
				rm -f "$listtmp"
				printf 'failed\t%s\t0\n' "$feedchecked" > "$feedresult"
				echo "[✘] Download Failed $url"
			fi
		) &
		Wait_Background_Job_Slot 4
	done < "$feedmanifest"
	Wait_Background_Jobs
}

Build_Malware_Update() {
Display_Message "[i] Downloading filter.list"
filtertmp="$TMP_DIR/filter.list"
filterout="$TMP_DIR/shared-Skynet-whitelist"
feedmanifest="$TMP_DIR/skynet.sources"
feedfilterbackup="$TMP_DIR/shared-Skynet-whitelist.old"
feedfilterpublished="0"
feedfilterhadold="0"
Curl_Fetch -o "$filtertmp" "$listurl" || { rm -f "$filtertmp" "$filterout"; echo "[*] Stopping Banmalware"; echo; return 1; }
Build_Threat_Feed_Manifest "$filtertmp" "$feedmanifest" "$excludelists" || {
	rm -f "$filtertmp" "$filterout" "$feedmanifest"
	echo "[*] Failed To Process Filter List"
	echo
	return 1
}
if [ ! -s "$feedmanifest" ]; then
	rm -f "$filtertmp" "$filterout" "$feedmanifest"
	echo "[*] No Valid Malware Sources Found - Stopping Banmalware"
	echo
	return 1
fi
if ! feedinvalid="$(Validate_Threat_Feed_Selection "$feedmanifest" "$excludelists")"; then
	rm -f "$filtertmp" "$filterout" "$feedmanifest"
	echo "[*] Malware Source Not Found: $feedinvalid"
	echo
	return 2
fi
awk -F '\t' '$3 == "enabled" { print $2 }' "$feedmanifest" > "$filterout"
if [ ! -s "$filterout" ]; then
	rm -f "$filtertmp" "$filterout" "$feedmanifest"
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
rm -f "$filtertmp"
Display_Result
Display_Message "[i] Refreshing Whitelists"
Whitelist_Extra
Whitelist_VPN
Whitelist_CDN || cdnstatus="1"
Whitelist_Shared
Refresh_Manual_Whitelist_Domains
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
Fetch_Threat_Feed_Sources

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
	if [ "$selection" = "enabled" ] && [ -s "$feedresult" ]; then
		read -r feedstate _feedresultchecked < "$feedresult"
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
	feedstate="failed"
	feedresultchecked="$feedchecked"
	feedresultsuccess="0"
	if [ -s "$feedresult" ]; then
		IFS="$feedtab" read -r feedstate feedresultchecked feedresultsuccess < "$feedresult"
	fi
	feedentries="$(awk -F '\t' -v name="$list" '$1 == name { print $2; exit }' "$feedcounts" 2>/dev/null)"
	case "$feedentries" in ""|0|*[!0-9]*)
		listfile="${skynetloc}/lists/$list"
		if [ "$feedstate" = "downloaded" ] && [ -s "$listfile" ] && [ -s "$listmanifest" ] \
			&& awk -v url="$url" -v name="$list" '$1 == url && $2 == name { found=1 } END { exit !found }' "$listmanifest"; then
			oldsuccess="$(awk -F '\t' -v url="$url" -v name="$list" '$1 == name && $2 == url { print $7; exit }' "${skynetloc}/lists/.sources" 2>/dev/null)"
			case "$oldsuccess" in ""|0|*[!0-9]*) oldsuccess="$(date -r "$listfile" +%s 2>/dev/null || printf 0)" ;; esac
			rm -f "$feedfiles/$list" "${skynetloc}/lists/${list}.tmp.$$"
			ln -s "$listfile" "$feedfiles/$list"
			printf 'cached\t%s\t%s\n' "$feedchecked" "$oldsuccess" > "$feedresult"
			feedrebuild="1"
		else
			rm -f "$feedfiles/$list" "${skynetloc}/lists/${list}.tmp.$$"
			printf 'failed\t%s\t%s\n' "$feedresultchecked" "$feedresultsuccess" > "$feedresult"
		fi
	;;
	*)
		if [ "$feedstate" = "downloaded" ]; then
			if mv -f "${skynetloc}/lists/${list}.tmp.$$" "${skynetloc}/lists/$list" \
				&& rm -f "$feedfiles/$list" && ln -s "${skynetloc}/lists/$list" "$feedfiles/$list"; then
				printf 'current\t%s\t%s\n' "$feedresultchecked" "$feedresultsuccess" > "$feedresult"
			else
				printf 'failed\t%s\t0\n' "$feedresultchecked" > "$feedresult"
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
	feedstate="failed"
	feedresult="$TMP_DIR/feed.${list}.result"
	[ -s "$feedresult" ] && IFS="$feedtab" read -r feedstate _feedresultchecked _feedresultentries < "$feedresult"
	feedentries="$(awk -F '\t' -v name="$list" '$1 == name { print $2; exit }' "$feedcounts" 2>/dev/null)"
	case "$feedentries" in ""|0|*[!0-9]*) feedstate="failed"; printf 'failed\t%s\t0\n' "$feedchecked" > "$feedresult" ;; esac
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
	feedentries="$(awk -F '\t' -v name="$list" '$1 == name { print $2; exit }' "$feedcounts" 2>/dev/null)"
	[ -s "$TMP_DIR/feed.${list}.result" ] && IFS="$feedtab" read -r feedstate _feedresultchecked _feedresultentries < "$TMP_DIR/feed.${list}.result"
	case "$selection:$feedstate:$feedentries" in
		enabled:current:[1-9]*|enabled:cached:[1-9]*) printf '%s %s\n' "$url" "$list" >> "$listmanifesttmp" ;;
		excluded:excluded:[1-9]*)
			if [ -s "${skynetloc}/lists/$list" ] && [ -s "$listmanifest" ] \
				&& awk -v url="$url" -v name="$list" '$1 == url && $2 == name { found=1 } END { exit !found }' "$listmanifest"; then
				printf '%s %s\n' "$url" "$list" >> "$listmanifesttmp"
			fi
		;;
	esac
done < "$feedmanifest"
mv -f "$listmanifesttmp" "$listmanifest" || { Restore_Threat_Feed_Selection; echo "[*] Unable To Publish Malware Cache Manifest"; echo; return 1; }
Publish_Threat_Feed_Status "$feedmanifest" "$feedcounts" || { Restore_Threat_Feed_Selection; echo "[*] Unable To Publish Malware Source Status"; echo; return 1; }

# The published URL/name mapping contains every current or retained cache.
# This removes disappeared URLs while keeping excluded sources ready for use;
# a changed URL with the same basename cannot retain the old file binding.
for file in "${skynetloc}/lists/"*; do
	[ -f "$file" ] || continue
	basefile="$(basename "$file")"
	if ! awk -v name="$basefile" '$2 == name { found=1 } END { exit !found }' "$listmanifest"; then
		rm -f "$file"
	fi
done

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
	Apply_Blacklist_File "$malwareipsetbackup" >/dev/null 2>&1
	Restore_Threat_Feed_Selection
	echo "[✘] Unable To Refresh AiProtect Bans - Existing Blacklist Restored"
	echo
	return 1
fi
Display_Message "[i] Saving Changes"
forcebanmalwareupdate="disabled"
banmalwarelastupdated="$(date +%s)"
blacklist1count="$(IPSet_Entry_Count Skynet-Blacklist)"
blacklist2count="$(IPSet_Entry_Count Skynet-BlockedRanges)"
if Save_IPSets && Write_Config; then
	nocfg="1"
	Display_Result
else
	result="$(Red "[$(($(date +%s) - btime))s]")"
	printf '%-8s\n' "$result"
	Apply_Blacklist_File "$malwareipsetbackup" >/dev/null 2>&1
	if ! Save_IPSets; then
		saveipsettmp="${skynetipset}.tmp.$$"
		cp -f "$malwareipsetbackup" "$saveipsettmp" && mv -f "$saveipsettmp" "$skynetipset"
	fi
	Restore_Threat_Feed_Selection
	echo "[✘] Unable To Save Malware Update - Existing Blacklist Restored"
	echo
	return 1
fi
echo
echo "[i] For Whitelisting Assistance -"
echo "[i] https://www.snbforums.com/threads/release-skynet-router-firewall-security-enhancements.16798/#post-115872"
}

Dispatch_BanMalware() {
	case "$2" in
		status)
			Print_Threat_Feed_Status
			echo
			nolog="2"
			nocfg="1"
			return 0
		;;
		sources)
			Print_Threat_Feed_Sources
			echo
			nolog="2"
			nocfg="1"
			return 0
		;;
	esac
	Check_Lock "$@"
	Require_Running
	Prepare_Malware_Update "$@" || exit "$?"
	Require_Connection
	Purge_Logs
	Build_Malware_Update || exit "$?"
	Apply_Malware_Update || exit "$?"
}

Dispatch_Whitelist() {
	Check_Lock "$@"
	Require_Running
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
			Update_IPSet add Skynet-Whitelist "$3" "ManualWlist: $desc" || { echo; exit 1; }
			sed -i "\\~=$3 ~d" "$skynetlog" "$skynetevents" && echo "$(date +"%b %e %T") Skynet: [Manual Whitelist] TYPE=Single SRC=$3 COMMENT=$desc " >> "$skynetevents"
			Update_IPSet del Skynet-Blacklist "$3" || { echo; exit 1; }
			Update_IPSet del Skynet-BlockedRanges "$3" || { echo; exit 1; }
		;;
		domain)
			Require_Connection
			if [ -z "$3" ]; then echo "[*] Domain Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
			domain="$(Normalize_Domain "$3")" || { echo "[*] $3 Is Not A Valid Domain"; echo; exit 2; }
			domainips="$(Resolve_Domain_IP_List "$domain" all)" || { echo "[*] Unable To Resolve $domain"; echo; exit 1; }
			domainipsetfile="$TMP_DIR/domain-whitelist.$$"
			true > "$domainipsetfile" || { echo; exit 1; }
			for ip in $domainips; do
				printf 'add Skynet-Whitelist %s comment "ManualWlistD: %s"\n' "$ip" "$domain" >> "$domainipsetfile"
				printf 'del Skynet-Blacklist %s\n' "$ip" >> "$domainipsetfile"
			done
			echo "[i] Adding $domain To Whitelist"
			Apply_IPSet_File "$domainipsetfile" || { rm -f "$domainipsetfile"; echo; exit 1; }
			rm -f "$domainipsetfile"
			for ip in $domainips; do
				echo "[i] Whitelisting $ip"
				sed -i "\\~=$ip ~d" "$skynetlog" "$skynetevents" && echo "$(date +"%b %e %T") Skynet: [Manual Whitelist] TYPE=Domain SRC=$ip Host=$domain " >> "$skynetevents"
			done
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
			if ! Apply_ASN_List "Skynet-Whitelist" "$asnlist"; then
				echo "[*] Failed To Download Or Apply $asnlist"
				echo
				exit 1
			fi
		;;
		remove)
			case "$3" in
				entry)
					if ! echo "$4" | Is_IPRange; then echo "[*] $4 Is Not A Valid IP/Range"; echo; exit 2; fi
					echo "[i] Removing $4 From Whitelist"
					Update_IPSet del Skynet-Whitelist "$4" || { echo; exit 1; }
					sed -i "\\~=$4 ~d" "$skynetlog" "$skynetevents"
				;;
				comment)
					if [ -z "$4" ]; then echo "[*] Comment Field Can't Be Empty - Please Try Again"; echo; exit 2; fi
					echo "[i] Removing All Entries With Comment Matching \"$4\" From Whitelist"
					Remove_IPSet_Entries Skynet-Whitelist "$4" || { echo; exit 1; }
					echo "[i] Removing Old Logs - This May Take Awhile (To Skip Type ctrl+c)"
					trap 'echo;echo;echo "[*] Interrupted"; break' INT
					Get_IPSet_Entries Skynet-Whitelist "$4" | awk '{ print $3 }' | while IFS= read -r "ip"; do
						sed -i "\\~=$ip ~d" "$skynetlog" "$skynetevents"
					done
					Set_Cleanup_Traps
				;;
				all)
					Require_Connection
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
			Require_Connection
			echo "[i] Refreshing Shared Whitelist Files"
			Whitelist_Extra
			Whitelist_CDN
			Whitelist_VPN
			Whitelist_Shared
			Refresh_Manual_Whitelist_Domains
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
				if ! Validate_IPSet_Comment "$4" 245; then echo "[*] Comment Contains Invalid Characters Or Is Too Long"; echo; exit 2; fi
				importdesc="Imported: $4"
			else
				importdesc="Imported: $(date +"%b %e %T")"
			fi
			Build_IPList_Restore add blacklist "$importdesc" "$TMP_DIR/iplist-unfiltered.txt" "$TMP_DIR/iplist-filtered.txt"
			if [ ! -s "$TMP_DIR/iplist-filtered.txt" ]; then echo "[*] No Public IPs Detected - Stopping Import"; echo; exit 1; fi
			echo "[i] Adding IPs To Blacklist"
			Apply_IPSet_File "$TMP_DIR/iplist-filtered.txt" || { echo "[*] Failed To Apply Import - Previous Entries Restored"; echo; exit 1; }
			rm -f "$TMP_DIR/iplist-unfiltered.txt" "$TMP_DIR/iplist-filtered.txt"
			echo "[i] Saving Changes"
			Require_Save_IPSets
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
				if ! Validate_IPSet_Comment "$4" 245; then echo "[*] Comment Contains Invalid Characters Or Is Too Long"; echo; exit 2; fi
				importdesc="Imported: $4"
			else
				importdesc="Imported: $(date +"%b %e %T")"
			fi
			Build_IPList_Restore add whitelist "$importdesc" "$TMP_DIR/iplist-unfiltered.txt" "$TMP_DIR/iplist-filtered.txt"
			if [ ! -s "$TMP_DIR/iplist-filtered.txt" ]; then echo "[*] No Public IPs Detected - Stopping Import"; echo; exit 1; fi
			echo "[i] Adding IPs To Whitelist"
			Apply_IPSet_File "$TMP_DIR/iplist-filtered.txt" || { echo "[*] Failed To Apply Import - Previous Entries Restored"; echo; exit 1; }
			rm -f "$TMP_DIR/iplist-unfiltered.txt" "$TMP_DIR/iplist-filtered.txt"
			echo "[i] Saving Changes"
			Require_Save_IPSets
		;;
		*)
			Command_Not_Recognized
		;;
	esac
}

Dispatch_Deport() {
	case "$2" in
		blacklist)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			echo "[i] This Function Extracts All IPs And Removes Them ALL From Blacklist"
			if [ -f "$3" ]; then
				echo "[i] Local Custom List Detected: $3"
				Extract_IPList "$3" "$TMP_DIR/iplist-unfiltered.txt"
			elif [ -n "$3" ]; then
				echo "[i] Remote Custom List Detected: $3"
				Require_Connection
				Download_IPList "$3" || { echo "[*] Download Error Detected - Stopping Deport"; echo; exit 1; }
			else
				echo "[*] URL/File Field Can't Be Empty - Please Try Again"
				echo; exit 2
			fi
			if ! Is_IPRange < "$TMP_DIR/iplist-unfiltered.txt"; then echo "[*] No Content Detected - Stopping Deport"; echo; exit 1; fi
			echo "[i] Processing List"
			Build_IPList_Restore del blacklist "" "$TMP_DIR/iplist-unfiltered.txt" "$TMP_DIR/iplist-filtered.txt"
			if [ ! -s "$TMP_DIR/iplist-filtered.txt" ]; then echo "[*] No Public IPs Detected - Stopping Deport"; echo; exit 1; fi
			echo "[i] Removing IPs From Blacklist"
			Apply_IPSet_File "$TMP_DIR/iplist-filtered.txt" || { echo "[*] Failed To Apply Deport - Previous Entries Restored"; echo; exit 1; }
			rm -f "$TMP_DIR/iplist-unfiltered.txt" "$TMP_DIR/iplist-filtered.txt"
			echo "[i] Saving Changes"
			Require_Save_IPSets
		;;
		whitelist)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			echo "[i] This Function Extracts All IPs And Removes Them ALL From Whitelist"
			if [ -f "$3" ]; then
				echo "[i] Local Custom List Detected: $3"
				Extract_IPList "$3" "$TMP_DIR/iplist-unfiltered.txt"
			elif [ -n "$3" ]; then
				echo "[i] Remote Custom List Detected: $3"
				Require_Connection
				Download_IPList "$3" || { echo "[*] Download Error Detected - Stopping Deport"; echo; exit 1; }
			else
				echo "[*] URL/File Field Can't Be Empty - Please Try Again"
				echo; exit 2
			fi
			if ! Is_IPRange < "$TMP_DIR/iplist-unfiltered.txt"; then echo "[*] No Content Detected - Stopping Deport"; echo; exit 1; fi
			echo "[i] Processing List"
			Build_IPList_Restore del whitelist "" "$TMP_DIR/iplist-unfiltered.txt" "$TMP_DIR/iplist-filtered.txt"
			if [ ! -s "$TMP_DIR/iplist-filtered.txt" ]; then echo "[*] No Public IPs Detected - Stopping Deport"; echo; exit 1; fi
			echo "[i] Removing IPs From Whitelist"
			Apply_IPSet_File "$TMP_DIR/iplist-filtered.txt" || { echo "[*] Failed To Apply Deport - Previous Entries Restored"; echo; exit 1; }
			rm -f "$TMP_DIR/iplist-unfiltered.txt" "$TMP_DIR/iplist-filtered.txt"
			echo "[i] Saving Changes"
			Require_Save_IPSets
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

Dispatch_Start() {
	Check_Lock "$@"
	startarguments=""
	startskipfirst="1"
	for startargument in "$@"; do
		if [ "$startskipfirst" = "1" ]; then
			startskipfirst="0"
			continue
		fi
		startarguments="${startarguments}${startarguments:+ }$startargument"
	done
	Log info "Startup Initiated... ( $startarguments )"
	unset "startarguments" "startskipfirst" "startargument"
	Unload_Cron "all"
	Check_Settings || { echo; exit 1; }
	Migrate_Installation || { echo "[*] Failed To Migrate Existing Skynet Data"; echo; exit 1; }
	Maintain_Script_Hooks firewall-start services-stop service-event post-mount unmount || { echo "[*] Failed To Maintain Script Hooks"; echo; exit 1; }
	Clean_Legacy_WebUI_Files || { echo "[*] Failed To Remove Legacy WebUI Files"; echo; exit 1; }
	Require_Connection 10 5
	Load_Cron "save"
	modprobe xt_set
	if [ -f "$skynetipset" ]; then
		ipset restore -! -f "$skynetipset" || { Log error -s "Failed To Restore Saved IPSet Data"; echo; exit 1; }
	else
		Log info -s "Setting Up Skynet"
		touch "$skynetipset" || { Log error -s "Failed To Create IPSet Data File"; echo; exit 1; }
	fi
	Ensure_IPSet Skynet-Whitelist hash:net hashsize 64 maxelem "$((65536 * 6))" comment || { echo; exit 1; }
	Ensure_IPSet Skynet-WhitelistDomains hash:ip hashsize 64 maxelem "$((65536 * 8))" comment timeout 86400 || { echo; exit 1; }
	Ensure_IPSet Skynet-Blacklist hash:ip hashsize 64 maxelem "$((65536 * 16))" comment || { echo; exit 1; }
	Ensure_IPSet Skynet-BlockedRanges hash:net hashsize 64 maxelem "$((65536 * 6))" comment || { echo; exit 1; }
	Ensure_IPSet Skynet-Master list:set || { echo; exit 1; }
	Ensure_IPSet Skynet-MasterWL list:set || { echo; exit 1; }
	Ensure_IPSet Skynet-IOT hash:net hashsize 64 maxelem "$((65536 * 6))" comment || { echo; exit 1; }
	Update_IPSet add Skynet-Master Skynet-Blacklist || { echo; exit 1; }
	Update_IPSet add Skynet-Master Skynet-BlockedRanges || { echo; exit 1; }
	Update_IPSet add Skynet-MasterWL Skynet-Whitelist || { echo; exit 1; }
	Update_IPSet add Skynet-MasterWL Skynet-WhitelistDomains || { echo; exit 1; }
	Whitelist_Blocked_Private_IPs
	Purge_Logs "all"
	Whitelist_Extra
	Whitelist_CDN
	Remove_IPSet_Entries Skynet-Whitelist "nvram: " || { echo; exit 1; }
	Whitelist_VPN
	Whitelist_Shared
	Refresh_Manual_Whitelist_Domains
	Refresh_Manual_Ban_Domains
	Refresh_AiProtect
	Check_Security
	echo "[i] Saving Changes"
	Require_Save_IPSets
	Generate_Stats
	Install_WebUI_Page
	while [ "$(($(date +%s) - stime))" -lt "20" ]; do
		sleep 1
	done
	Unload_IPTables
	Unload_IOT_Rules
	Unload_LogIPTables
	Load_IPTables
	Load_IOT_Rules
	Load_LogIPTables
	unset "nolog"
	sed -i '\~DROP IN=~d' "$syslog1loc" "$syslogloc" 2>/dev/null
	if Is_Enabled "$forcebanmalwareupdate"; then
		Write_Config || { echo "[*] Failed To Save Configuration"; echo; exit 1; }
		Release_Lock
		# force a summary now, before we trigger banmalware
		Print_Command_Summary "$@"
		# then run banmalware as a child (not via exec)
		"$0" banmalware
		exit "$?"
	fi
}

Dispatch_Restart() {
	Check_Lock "$@"
	Purge_Logs
	echo "[i] Saving Changes"
	Require_Save_IPSets
	echo "[i] Unloading Skynet Components"
	Unload_Cron "all"
	Unload_IPTables
	Unload_IOT_Rules
	Unload_LogIPTables
	Unload_IPSets
	Uninstall_WebUI_Page
	iptables -t raw -F
	Log info "Restarting Firewall Service"
	restartfirewall="1"
	nolog="2"
}

Dispatch_Disable() {
	Check_Lock "$@"
	echo "[i] Saving Changes"
	Require_Save_IPSets
	echo "[i] Unloading Skynet Components"
	Unload_Cron "all"
	Unload_IPTables
	Unload_IOT_Rules
	Unload_LogIPTables
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
		Unload_IPTables
		Unload_IOT_Rules
		Unload_LogIPTables
		Unload_IPSets
		iptables -t raw -F
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
			autoupdate="enabled"
			Unload_Cron "checkupdate"
			Load_Cron "autoupdate"
			echo "[i] Skynet Auto-Updates Enabled"
		;;
		disable)
			Check_Lock "$@"
			Require_Running
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
}

Settings_MalwareSchedule() {
	case "$3" in
		daily)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			banmalwareupdate="daily"
			forcebanmalwareupdate="enabled"
			Unload_Cron "banmalware"
			Load_Cron "banmalwaredaily"
			echo "[i] Daily Malware Blacklist Updates Enabled"
		;;
		weekly)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			banmalwareupdate="weekly"
			forcebanmalwareupdate="enabled"
			Unload_Cron "banmalware"
			Load_Cron "banmalwareweekly"
			echo "[i] Weekly Malware Blacklist Updates Enabled"
		;;
		disable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			banmalwareupdate="disabled"
			Unload_Cron "banmalware"
			echo "[i] Malware Blacklist Updates Disabled"
		;;
		*)
			Command_Not_Recognized
		;;
	esac
}

Settings_LogMode() {
	case "$3" in
		enable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			logmode="enabled"
			Unload_LogIPTables
			Load_LogIPTables
			echo "[i] Logging Enabled"
		;;
		disable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			logmode="disabled"
			Unload_LogIPTables
			echo "[i] Logging Disabled"
		;;
		*)
			Command_Not_Recognized
		;;
	esac
}

Settings_InvalidLogging() {
	case "$3" in
		enable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			loginvalid="enabled"
			Unload_LogIPTables
			Load_LogIPTables
			echo "[i] Invalid IP Logging Enabled"
		;;
		disable)
			Check_Lock "$@"
			Require_Running
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
		all)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			filtertraffic="all"
			Unload_IPTables
			Unload_IOT_Rules
			Unload_LogIPTables
			Load_IPTables
			Load_IOT_Rules
			Load_LogIPTables
			echo "[i] Inbound & Outbound Filtering Enabled"

		;;
		inbound)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			filtertraffic="inbound"
			Unload_IPTables
			Unload_IOT_Rules
			Unload_LogIPTables
			Load_IPTables
			Load_IOT_Rules
			Load_LogIPTables
			echo "[i] Inbound Filtering Enabled"
		;;
		outbound)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			filtertraffic="outbound"
			Unload_IPTables
			Unload_IOT_Rules
			Unload_LogIPTables
			Load_IPTables
			Load_IOT_Rules
			Load_LogIPTables
			echo "[i] Outbound Filtering Enabled"
		;;
		*)
			Command_Not_Recognized
		;;
	esac
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
			banaiprotect="enabled"
			Refresh_AiProtect
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
	if [ -z "$3" ]; then echo "[*] Syslog Location Not Specified - Exiting"; echo; exit 2; fi
	case "$3" in
		default)
			syslogloc="/tmp/syslog.log"
		;;
		*)
			syslogloc="$3"
		;;
	esac
	echo "[i] Syslog Location Set To $syslogloc"
}

Settings_SyslogArchive() {
	Check_Lock "$@"
	Require_Running
	if [ -z "$3" ]; then echo "[*] Syslog-1 Location Not Specified - Exiting"; echo; exit 2; fi
	case "$3" in
		default)
			syslog1loc="/tmp/syslog.log-1"
		;;
		*)
			syslog1loc="$3"
		;;
	esac
	echo "[i] Syslog-1 Location Set To $syslog1loc"
}

Settings_IOT() {
	Check_Lock "$@"
	Require_Running
	if [ -z "$3" ]; then echo "[*] Option Not Specified - Exiting"; echo; exit 2; fi
	case "$3" in
		enable)
			Set_IOT_Blocking "enabled" || { echo; exit 1; }
			echo "[i] IoT Blocking Enabled"
		;;
		disable)
			Set_IOT_Blocking "disabled" || { echo; exit 1; }
			echo "[i] IoT Blocking Disabled - Device List Preserved"
		;;
		unban)
			iotlist="$(Normalize_Arguments_From 4 "$@")" || { echo "[*] Device List Can't Be Empty"; echo; exit 2; }
			for iotentry in $iotlist; do
				if ! printf '%s\n' "$iotentry" | Is_IPRange; then echo "[*] $iotentry Is Not A Valid IP/Range"; echo; exit 2; fi
			done
			Update_IPSet_Batch del Skynet-IOT "" "$iotlist" || { echo; exit 1; }
			for iotentry in $iotlist; do
				sed -i "\\~BLOCKED - IOT.*=$iotentry ~d" "$skynetlog"
			done
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
					# Preserve the historical CLI result: selecting a protocol while
					# on the NTP default creates an explicit custom port 123 policy.
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
			iotlogging="enabled"
			Unload_LogIPTables
			Load_LogIPTables
			echo "[i] IoT Block Logging Enabled"
		;;
		disable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			iotlogging="disabled"
			Unload_LogIPTables
			Load_LogIPTables
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
			cdnwhitelist="enabled"
			Whitelist_CDN
			echo "[i] CDN Whitelisting Enabled"
		;;
		disable)
			Check_Lock "$@"
			Require_Running
			Purge_Logs
			cdnwhitelist="disabled"
			Whitelist_CDN
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
		syslog) Settings_Syslog "$@" ;;
		syslog1) Settings_SyslogArchive "$@" ;;
		iot) Settings_IOT "$@" ;;
		iotlogging) Settings_IOTLogging "$@" ;;
		lookupcountry) Settings_CountryLookup "$@" ;;
		cdnwhitelist) Settings_CDNWhitelist "$@" ;;
		webui) Settings_WebUI "$@" ;;
		*) Settings_Unknown "$@" ;;
	esac
}

Dispatch_WebUI() {
	case "$2" in
		SkynetStats)
			Run_WebUI_Command debug genstats
		;;
		SkynetSettings|apply)
			Apply_WebUI_Settings
		;;
		SkynetSettingsLoad|load)
			Generate_WebUI_Settings
		;;
		SkynetBanMalware|banmalware)
			Apply_WebUI_Threat_Feeds
		;;
		SkynetCountries|countries)
			Apply_WebUI_Countries
		;;
		SkynetIOT|iot)
			Check_Lock "$@"
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
	debugservicesstophook='sh /jffs/scripts/firewall save # Skynet'
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
	if Check_Swap; then result="$(Grn "[Passed]")"; passedtests="$((passedtests + 1))"; else result="$(Red "[Failed]")"; fi
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
	printf '║ %-33s ║ %-80s ║\n' "IoT Blocking" "$(if Is_Enabled "$iotblocked"; then Grn "[Enabled]"; else Ylow "[Disabled]"; fi)"
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
	printf '║ %-33s ║ %-80s ║\n' "Syslog Location" "$(if { [ "$syslogloc" = "/tmp/syslog.log" ] && [ "$syslog1loc" = "/tmp/syslog.log-1" ]; } || { [ "$syslogloc" = "/jffs/syslog.log" ] && [ "$syslog1loc" = "/jffs/syslog.log-1" ]; } then Grn "[Default]"; else Ylow "[Custom]"; fi)"
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
	Check_Lock "$@"
	Purge_Logs "all"
	if Addon_API_Supported; then
		if Is_Enabled "$displaywebui"; then
			echo "[i] Generating Stats For WebUI"
			Generate_Stats
		else
			echo "[*] WebUI Is Currently Disabled - To Enable Use ( sh $0 settings webui enable )"
		fi
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
				Create_Swap
				echo "[i] Saving Changes"
				Require_Save_IPSets
				echo "[i] Unloading Skynet Components"
				Unload_Cron "all"
				Unload_IPTables
				Unload_IOT_Rules
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
			Require_Save_IPSets
			echo "[i] Unloading Skynet Components"
			Unload_Cron "all"
			Unload_IPTables
			Unload_IOT_Rules
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
}

Debug_Backup() {
	Check_Lock "$@"
	Require_Running
	Purge_Logs
	echo "[i] Saving Changes"
	Require_Save_IPSets
	echo "[i] Backing Up Skynet Related Files"
	echo
	tar -czvf "${skynetloc}/Skynet-Backup.tar.gz" -C "${skynetloc}" skynet.ipset skynet.log events.log skynet.cfg
	echo
	echo "[i] Backup Saved To ${skynetloc}/Skynet-Backup.tar.gz"
	echo "[i] Copy This File To A Safe Location"
}

Debug_Restore() {
	Check_Lock "$@"
	Require_Running
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
	Unload_IOT_Rules
	Unload_LogIPTables
	Unload_IPSets
	tar -xzvf "$backuplocation" -C "${skynetloc}"
	echo
	echo "[i] Backup Restored"
	Log info "Restarting Firewall Service"
	restartfirewall="1"
	nolog="2"
}

Debug_Run() {
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
	Unload_IPTables
	Unload_IOT_Rules
	Unload_LogIPTables
	Unload_IPSets
	iptables -t raw -F
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
				Unload_IOT_Rules
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
		whitelist) Dispatch_Whitelist "$@" ;;
		import) Dispatch_Import "$@" ;;
		deport) Dispatch_Deport "$@" ;;
		save) Dispatch_Save "$@" ;;
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
					Prompt_Typed "option3" "IP" "Input IP To Unban:"
					if ! printf '%s\n' "$option3" | Is_IP; then echo "[*] $option3 Is Not A Valid IP"; echo; unset "option2" "option3"; continue; fi
					break
				;;
				2)
					option2="range"
					Prompt_Typed "option3" "Range" "Input Range To Unban:"
					if ! printf '%s\n' "$option3" | Is_Range; then echo "[*] $option3 Is Not A Valid Range"; echo; unset "option2" "option3"; continue; fi
					break
				;;
				3)
					option2="domain"
					Prompt_Typed "option3" "Domain" "Input Domain To Unban:"
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
					if ! printf '%s\n' "$option3" | Is_ASN; then echo "[*] $option3 Is Not A Valid ASN"; echo; unset "option2" "option3"; continue; fi
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
					Prompt_Typed "option3" "IP" "Input IP To Ban:"
					if ! printf '%s\n' "$option3" | Is_IP; then echo "[*] $option3 Is Not A Valid IP"; echo; unset "option2" "option3"; continue; fi
					Prompt_Typed "option4" "Comment" "Input Comment For Ban:"
					if [ "${#option4}" -gt "244" ]; then echo "[*] $option4 Is Not A Valid Comment. 244 Chars Max"; echo; unset "option2" "option3" "option4"; continue; fi
					break
				;;
				2)
					option2="range"
					Prompt_Typed "option3" "Range" "Input Range To Ban:"
					if ! printf '%s\n' "$option3" | Is_Range; then echo "[*] $option3 Is Not A Valid Range"; echo; unset "option2" "option3"; continue; fi
					Prompt_Typed "option4" "Comment" "Input Comment For Ban:"
					if [ "${#option4}" -gt "243" ]; then echo "[*] $option4 Is Not A Valid Comment. 243 Chars Max"; echo; unset "option2" "option3" "option4"; continue; fi
					break
				;;
				3)
					option2="domain"
					Prompt_Typed "option3" "Domain" "Input Domain To Ban:"
					if [ -z "$option3" ]; then echo "[*] URL Field Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
					break
				;;
				4)
					option2="country"
					if [ -n "$countrylist" ]; then echo "Countries Currently Banned: (${countrylist})"; fi
					Prompt_Typed "option3" "Countries" "Input Country Abbreviations To Ban:"
					if [ -z "$option3" ]; then echo "[*] Country Field Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
					if printf '%s\n' "$option3" | grep -qF "\""; then echo "[*] Country Field Can't Include Quotes - Please Try Again"; echo; unset "option2" "option3"; continue; fi
					break
				;;
				5)
					option2="asn"
					Prompt_Typed "option3" "ASN" "Input ASN To Ban:"
					if ! printf '%s\n' "$option3" | Is_ASN; then echo "[*] $option3 Is Not A Valid ASN"; echo; unset "option2" "option3"; continue; fi
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
					option2="ip"
					Prompt_Typed "option3" "IP/Range" "Input IP Or Range To Whitelist:"
					if ! printf '%s\n' "$option3" | Is_IPRange; then echo "[*] $option3 Is Not A Valid IP/Range"; echo; unset "option2" "option3"; continue; fi
					Prompt_Typed "option4" "Comment" "Input Comment For Whitelist:"
					if [ "${#option4}" -gt "242" ]; then echo "[*] $option4 Is Not A Valid Comment. 242 Chars Max"; echo; unset "option2" "option3" "option4"; continue; fi
					break
				;;
				2)
					option2="domain"
					Prompt_Typed "option3" "Domain" "Input Domain To Whitelist:"
					if [ -z "$option3" ]; then echo "[*] URL Field Can't Be Empty - Please Try Again"; echo; unset "option2" "option3"; continue; fi
					break
				;;
				3)
					option2="asn"
					Prompt_Typed "option3" "ASN" "Input ASN To Whitelist:"
					if ! printf '%s\n' "$option3" | Is_ASN; then echo "[*] $option3 Is Not A Valid ASN"; echo; unset "option2" "option3"; continue; fi
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
								if ! printf '%s\n' "$option4" | Is_IPRange; then echo "[*] $option4 Is Not A Valid IP/Range"; echo; unset "option3" "option4"; continue; fi
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

Menu_Deport() {
	while :; do
		if ! Menu_Require_Running; then break; fi
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
			1) option2="syslog"; syslogdefault="/tmp/syslog.log"; sysloglabel="Syslog" ;;
			2) option2="syslog1"; syslogdefault="/tmp/syslog.log-1"; sysloglabel="Syslog-1" ;;
			e|exit|back|menu) Return_To_Menu; break ;;
			*) Invalid_Option "$menu3"; continue ;;
		esac
		while true; do
			Show_Menu "Select Syslog Location:" \
				"Default" \
				"Custom" \
				"Exit"
			Prompt_Input "1-2" menu3
			case "$menu3" in
				1) option3="$syslogdefault"; break ;;
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
	unset "syslogdefault" "sysloglabel"
}

Menu_Settings_IOT() {
	Require_Running
	option2="iot"
	while true; do
		Show_Menu "Select IoT Option:" \
			"Enable IoT Blocking" \
			"Disable IoT Blocking" \
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
			"Outbound Entries From A Local Device" \
			"Hourly Reports" \
			"Invalid Packets" \
			"Active Connections" \
			"IoT Packets" \
			"Exit"
		Prompt_Input "1-11" menu4
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
			7)
				option3="device"; Prompt_Input "Local IP" option4
				if ! printf '%s\n' "$option4" | Is_IP; then echo "[*] $option4 Is Not A Valid IP"; echo; unset "option3" "option4"; continue; fi
				break
			;;
			8) option3="reports"; break ;;
			9) option3="invalid"; break ;;
			10) Menu_Stats_Connections; break ;;
			11) option3="iot"; break ;;
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
		printf '%-35s | %-8s\n' "Firewall Rules" "$(Red "[Failed]")"; nolog="1"; unset fail
	fi
	if [ "$nolog" != "1" ]; then Print_Command_Summary "minimal"; fi
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
				Menu_Import
				break
			;;
			6)
				Menu_Deport
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
skynetipset="${skynetloc}/skynet.ipset"
LOCK_FILE="/tmp/skynet.lock"

# Default to the NVRAM’s WAN interface name, but if the protocol is PPPoE, override to ppp0
iface="$(nvram get wan0_ifname)"
[ "$(nvram get wan0_proto)" = "pppoe" ] && iface="ppp0"

Set_Cleanup_Traps

# If we haven’t yet determined an install directory and the script is running in a real terminal,
# force the command to “install” so the installer logic kicks in automatically.
if [ -z "$skynetloc" ] && tty >/dev/null 2>&1; then
	set -- "install"
fi

Check_NTP "$1"
stime="$(date +%s)"
Find_Install_Dir "$@"

# Load saved defaults from the config file if it exists
if [ -f "$skynetcfg" ]; then
	Load_Config
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

if [ "$1" != "amtmupdate" ]; then
	Display_Header "9"
fi

##############
#- Commands -#
##############

Clean_Stale_Temp
Dispatch_Command "$@"
Display_Header "9"
if [ "$nolog" != "2" ]; then Print_Command_Summary "$@"; echo; fi
commandstatus="${commandfailed:-0}"
if [ "$nocfg" != "1" ]; then Write_Config || commandstatus="1"; fi
if [ "$restartfirewall" = "1" ]; then
	if ! service restart_firewall; then
		Log error -s "Firewall Restart Failed - Run ( service restart_firewall )"
		commandstatus="1"
	fi
	echo
fi
if [ -n "$reloadmenu" ]; then echo;echo; printf "[i] Press Enter To Continue..."; read -r "_menucontinue"; Return_To_Menu; fi
exit "$commandstatus"
