#!/opt/bin/python3
"""
Skynet OTX Threat Intel Collector
Reads IPs from Skynet ipset, queries OTX, sends to Splunk ES
"""

import json
import subprocess
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests

# Paths relative to script location
SCRIPT_DIR = Path(__file__).parent.resolve()
CONFIG_FILE = SCRIPT_DIR / "config.json"
STATE_FILE = SCRIPT_DIR / "state.json"
CACHE_FILE = SCRIPT_DIR / "cache.json"
LOG_FILE = SCRIPT_DIR / "skynet_otx.log"

# Default config - overridden by config.json
DEFAULT_CONFIG = {
    "splunk_url": "https://192.168.50.213:8088/services/collector/event",
    "splunk_token": "",
    "splunk_index": "threat_activity",
    "splunk_sourcetype": "otx:threat:intel",
    "otx_key": "",
    "router_hostname": "GT-AX11000",
    "batch_size": 50,
    "max_ips_per_run": 100,
    "otx_cache_hours": 24,
    "otx_rate_limit": 0.5,
    "max_retries": 3,
    "retry_backoff": 2
}


def log(msg: str, level: str = "INFO"):
    """Simple logging to file and stdout"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"{timestamp} - {level} - {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def load_config() -> dict:
    """Load config from JSON file, merge with defaults"""
    config = DEFAULT_CONFIG.copy()

    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                user_config = json.load(f)
                config.update(user_config)
                log(f"Loaded config from {CONFIG_FILE}")
        except json.JSONDecodeError as e:
            log(f"Config JSON parse error: {e}", "ERROR")
        except IOError as e:
            log(f"Config read error: {e}", "ERROR")
    else:
        log(f"No config file at {CONFIG_FILE}, using defaults", "WARN")

    # Validate required fields
    if not config.get("splunk_token"):
        log("Missing splunk_token in config", "ERROR")
        sys.exit(1)
    if not config.get("otx_key"):
        log("Missing otx_key in config", "ERROR")
        sys.exit(1)

    return config


def load_json_file(path: Path, default: dict) -> dict:
    """Load JSON file with error handling"""
    if not path.exists():
        return default
    try:
        with open(path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        log(f"JSON parse error in {path}: {e}", "WARN")
        return default
    except IOError as e:
        log(f"Read error {path}: {e}", "WARN")
        return default


def save_json_file(path: Path, data: dict) -> bool:
    """Atomic save JSON file"""
    tmp_path = path.with_suffix(".tmp")
    try:
        with open(tmp_path, "w") as f:
            json.dump(data, f)
        tmp_path.replace(path)  # Atomic rename
        return True
    except IOError as e:
        log(f"Save error {path}: {e}", "ERROR")
        return False


def get_skynet_ips() -> List[Dict[str, str]]:
    """Get blocked IPs from Skynet ipset with ban reasons"""
    ips = []

    # Flexible regex: IP, optional timeout/other fields, then comment
    # Handles: "1.2.3.4 comment "reason"" and "1.2.3.4 timeout 123 comment "reason""
    pattern = re.compile(r'^(\d+\.\d+\.\d+\.\d+)(?:/\d+)?(?:\s+\S+)*?\s+comment\s+"([^"]+)"')

    for ipset_name in ['Skynet-Blacklist', 'Skynet-BlockedRanges']:
        try:
            result = subprocess.run(
                ['ipset', 'list', ipset_name],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode != 0:
                log(f"ipset list {ipset_name} failed: {result.stderr}", "WARN")
                continue

            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line or line.startswith('Name:') or line.startswith('Type:'):
                    continue

                match = pattern.match(line)
                if match:
                    ips.append({
                        'ip': match.group(1),
                        'reason': match.group(2)
                    })

        except subprocess.TimeoutExpired:
            log(f"Timeout reading {ipset_name}", "ERROR")
        except Exception as e:
            log(f"Error reading {ipset_name}: {e}", "ERROR")

    log(f"Found {len(ips)} IPs in Skynet blocklists")
    return ips


def fetch_otx(ip: str, config: dict, cache: dict) -> Optional[Dict]:
    """Fetch OTX threat intel with caching and retry"""
    cache_ttl = config.get("otx_cache_hours", 24) * 3600

    # Check cache
    if ip in cache:
        cached = cache[ip]
        if time.time() - cached.get("ts", 0) < cache_ttl:
            return cached.get("data")

    # Retry with backoff
    max_retries = config.get("max_retries", 3)
    backoff = config.get("retry_backoff", 2)

    for attempt in range(max_retries):
        try:
            resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": config["otx_key"]},
                timeout=15
            )

            if resp.status_code == 200:
                data = resp.json()
                pulses = data.get("pulse_info", {}).get("pulses", [])

                intel = {
                    "ip": ip,
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "country": data.get("country_code", ""),
                    "country_name": data.get("country_name", ""),
                    "asn": data.get("asn", ""),
                    "city": data.get("city", ""),
                    "pulses": [],
                    "tags": [],
                    "malware_families": [],
                    "attack_ids": []
                }

                for pulse in pulses[:10]:
                    intel["pulses"].append({
                        "id": pulse.get("id", ""),
                        "name": pulse.get("name", ""),
                        "description": pulse.get("description", "")[:300] if pulse.get("description") else ""
                    })
                    intel["tags"].extend(pulse.get("tags", []))
                    intel["malware_families"].extend(pulse.get("malware_families", []))
                    intel["attack_ids"].extend(pulse.get("attack_ids", []))

                # Dedupe lists
                intel["tags"] = list(set(intel["tags"]))[:15]
                intel["malware_families"] = list(set(intel["malware_families"]))[:10]
                intel["attack_ids"] = list(set(intel["attack_ids"]))[:10]

                cache[ip] = {"ts": time.time(), "data": intel}
                return intel

            elif resp.status_code == 404:
                # IP not in OTX - cache empty result
                intel = {
                    "ip": ip,
                    "pulse_count": 0,
                    "country": "",
                    "asn": "",
                    "pulses": [],
                    "tags": [],
                    "malware_families": [],
                    "attack_ids": [],
                    "not_in_otx": True
                }
                cache[ip] = {"ts": time.time(), "data": intel}
                return intel

            elif resp.status_code == 429:
                # Rate limited - wait and retry
                wait_time = backoff ** (attempt + 1)
                log(f"OTX rate limited, waiting {wait_time}s", "WARN")
                time.sleep(wait_time)
                continue

            else:
                log(f"OTX API error for {ip}: {resp.status_code}", "WARN")

        except requests.exceptions.Timeout:
            log(f"OTX timeout for {ip} (attempt {attempt + 1})", "WARN")
            time.sleep(backoff ** attempt)
        except requests.exceptions.RequestException as e:
            log(f"OTX request error for {ip}: {e}", "WARN")
            time.sleep(backoff ** attempt)

    return None


def build_event(ip_info: Dict, otx_intel: Dict, config: dict) -> Dict:
    """Build CIM-compliant Splunk event"""
    pc = otx_intel.get("pulse_count", 0)

    # Severity based on pulse count
    if pc >= 10:
        severity, severity_id = "critical", 5
    elif pc >= 5:
        severity, severity_id = "high", 4
    elif pc >= 2:
        severity, severity_id = "medium", 3
    elif pc >= 1:
        severity, severity_id = "low", 2
    else:
        severity, severity_id = "informational", 1

    # Get first pulse info if available
    pulses = otx_intel.get("pulses", [])
    first_pulse = pulses[0] if pulses else {}

    return {
        "_time": time.time(),

        # CIM Threat Intelligence
        "threat_key": ip_info["ip"],
        "threat_match_field": "src_ip",
        "threat_match_value": ip_info["ip"],
        "threat_collection": "alienvault_otx",
        "threat_collection_key": ip_info["ip"],
        "threat_source_name": "AlienVault OTX",
        "threat_source_id": first_pulse.get("id", ""),
        "threat_description": first_pulse.get("description", ""),

        # CIM Network/IDS
        "src_ip": ip_info["ip"],
        "severity": severity,
        "severity_id": severity_id,
        "signature": ip_info.get("reason", "Skynet Block"),
        "category": "threat_intel",
        "action": "blocked",

        # OTX enrichment
        "otx_pulse_count": pc,
        "otx_country": otx_intel.get("country", ""),
        "otx_country_name": otx_intel.get("country_name", ""),
        "otx_asn": otx_intel.get("asn", ""),
        "otx_city": otx_intel.get("city", ""),
        "otx_tags": otx_intel.get("tags", []),
        "otx_pulses": [p.get("name", "") for p in pulses[:5]],
        "otx_malware_families": otx_intel.get("malware_families", []),
        "mitre_technique_id": otx_intel.get("attack_ids", []),
        "otx_url": f"https://otx.alienvault.com/indicator/ip/{ip_info['ip']}",
        "otx_not_found": otx_intel.get("not_in_otx", False),

        # Skynet context
        "skynet_reason": ip_info.get("reason", "Unknown"),

        # Device
        "dvc": config.get("router_hostname", "unknown"),
        "vendor": "ASUS",
        "vendor_product": "Skynet Firewall"
    }


def send_to_splunk(events: List[Dict], config: dict) -> bool:
    """Send events to Splunk HEC with retry"""
    if not events:
        return True

    # Build payload
    payload_lines = []
    for event in events:
        hec_event = {
            "time": event.get("_time", time.time()),
            "host": config.get("router_hostname", "skynet"),
            "source": "skynet_otx_collector",
            "sourcetype": config.get("splunk_sourcetype", "otx:threat:intel"),
            "index": config.get("splunk_index", "threat_activity"),
            "event": event
        }
        payload_lines.append(json.dumps(hec_event))

    payload = "\n".join(payload_lines)

    max_retries = config.get("max_retries", 3)
    backoff = config.get("retry_backoff", 2)

    for attempt in range(max_retries):
        try:
            resp = requests.post(
                config["splunk_url"],
                headers={
                    "Authorization": f"Splunk {config['splunk_token']}",
                    "Content-Type": "application/json"
                },
                data=payload,
                verify=False,
                timeout=30
            )

            if resp.status_code == 200:
                result = resp.json()
                if result.get("text") == "Success":
                    log(f"Sent {len(events)} events to Splunk")
                    return True
                else:
                    log(f"Splunk error: {result}", "ERROR")
            else:
                log(f"Splunk HTTP {resp.status_code}: {resp.text}", "ERROR")

        except requests.exceptions.RequestException as e:
            log(f"Splunk request error (attempt {attempt + 1}): {e}", "WARN")

        if attempt < max_retries - 1:
            wait_time = backoff ** (attempt + 1)
            log(f"Retrying in {wait_time}s...")
            time.sleep(wait_time)

    return False


def run_collection(config: dict) -> int:
    """Main collection routine"""
    # Load state and cache
    state = load_json_file(STATE_FILE, {"sent": []})
    cache = load_json_file(CACHE_FILE, {})
    sent: Set[str] = set(state.get("sent", []))

    log(f"State: {len(sent)} IPs already processed")

    # Get IPs from Skynet
    skynet_ips = get_skynet_ips()

    # Filter to new IPs only
    new_ips = [ip for ip in skynet_ips if ip["ip"] not in sent]
    max_per_run = config.get("max_ips_per_run", 100)
    new_ips = new_ips[:max_per_run]

    log(f"Processing {len(new_ips)} new IPs (limit {max_per_run})")

    if not new_ips:
        log("No new IPs to process")
        return 0

    rate_limit = config.get("otx_rate_limit", 0.5)
    batch_size = config.get("batch_size", 50)
    events = []
    processed_ips = []
    total_sent = 0

    for i, ip_info in enumerate(new_ips):
        ip = ip_info["ip"]

        # Fetch OTX data
        otx_intel = fetch_otx(ip, config, cache)

        if otx_intel:
            event = build_event(ip_info, otx_intel, config)
            events.append(event)
            processed_ips.append(ip)

        # Rate limit
        time.sleep(rate_limit)

        # Batch send - only clear if successful
        if len(events) >= batch_size:
            if send_to_splunk(events, config):
                total_sent += len(events)
                sent.update(processed_ips)
                # Save state after each successful batch
                save_json_file(STATE_FILE, {"sent": list(sent), "updated": time.time()})
            else:
                log(f"Batch send failed, will retry these {len(events)} IPs next run", "ERROR")
            events = []
            processed_ips = []

    # Send remaining events
    if events:
        if send_to_splunk(events, config):
            total_sent += len(events)
            sent.update(processed_ips)
        else:
            log(f"Final batch send failed, will retry these {len(events)} IPs next run", "ERROR")

    # Save state and cache
    save_json_file(STATE_FILE, {"sent": list(sent), "updated": time.time()})
    save_json_file(CACHE_FILE, cache)

    log(f"Complete: {total_sent} events sent")
    return total_sent


def test_connections(config: dict):
    """Test Splunk and OTX connectivity"""
    print("=" * 50)
    print("Testing Splunk HEC...")
    test_event = {
        "_time": time.time(),
        "message": "Skynet OTX Collector test event",
        "test": True
    }
    if send_to_splunk([test_event], config):
        print("✓ Splunk HEC: OK")
    else:
        print("✗ Splunk HEC: FAILED")

    print("\nTesting OTX API...")
    cache = {}
    result = fetch_otx("8.8.8.8", config, cache)
    if result:
        print(f"✓ OTX API: OK (8.8.8.8 has {result.get('pulse_count', 0)} pulses)")
    else:
        print("✗ OTX API: FAILED")

    print("\nTesting ipset...")
    ips = get_skynet_ips()
    if ips:
        print(f"✓ ipset: OK ({len(ips)} IPs found)")
    else:
        print("✗ ipset: No IPs found or command failed")

    print("=" * 50)


def reset_state():
    """Reset state file to reprocess all IPs"""
    if STATE_FILE.exists():
        STATE_FILE.unlink()
        print(f"Deleted {STATE_FILE}")
    print("State reset - all IPs will be reprocessed on next run")


def show_status(config: dict):
    """Show current status"""
    state = load_json_file(STATE_FILE, {"sent": []})
    cache = load_json_file(CACHE_FILE, {})

    print(f"Config: {CONFIG_FILE}")
    print(f"State:  {STATE_FILE}")
    print(f"Cache:  {CACHE_FILE}")
    print(f"Log:    {LOG_FILE}")
    print()
    print(f"IPs sent to Splunk: {len(state.get('sent', []))}")
    print(f"IPs in OTX cache:   {len(cache)}")

    if state.get("updated"):
        updated = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(state["updated"]))
        print(f"Last run:           {updated}")

    print()
    ips = get_skynet_ips()
    pending = [ip for ip in ips if ip["ip"] not in state.get("sent", [])]
    print(f"Skynet blocklist:   {len(ips)} IPs")
    print(f"Pending to send:    {len(pending)} IPs")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Skynet OTX Threat Intel Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 skynet_otx_splunk.py              # Run collection
  python3 skynet_otx_splunk.py --test       # Test connections
  python3 skynet_otx_splunk.py --status     # Show status
  python3 skynet_otx_splunk.py --reset      # Reset state (reprocess all)
        """
    )
    parser.add_argument("--test", action="store_true", help="Test Splunk and OTX connectivity")
    parser.add_argument("--reset", action="store_true", help="Reset state to reprocess all IPs")
    parser.add_argument("--status", action="store_true", help="Show current status")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")

    args = parser.parse_args()

    if args.reset:
        reset_state()
        return

    config = load_config()

    if args.test:
        test_connections(config)
        return

    if args.status:
        show_status(config)
        return

    # Run collection
    try:
        count = run_collection(config)
        sys.exit(0 if count >= 0 else 1)
    except KeyboardInterrupt:
        log("Interrupted")
        sys.exit(130)
    except Exception as e:
        log(f"Fatal error: {e}", "ERROR")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
