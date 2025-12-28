#!/opt/bin/python3
"""
Skynet OTX Threat Intelligence Collector for Splunk ES
Collects OTX threat intel for IPs in Skynet's blocklist

This script:
1. Reads blocked IPs from Skynet ipset
2. Fetches OTX threat intelligence for each IP
3. Sends threat intel to Splunk ES as a threat feed

Does NOT touch syslog - that's already going to Splunk.
"""

import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("ERROR: Install requests: opkg install python3-requests")
    sys.exit(1)


# ============================================================================
# Configuration
# ============================================================================

CONFIG = {
    # Splunk HEC
    "splunk_hec_url": "https://192.168.50.213:8088/services/collector/event",
    "splunk_hec_token": "935af03b-c11c-403a-98e7-904eaf7d88e5",
    "splunk_index": "threat_activity",
    "splunk_sourcetype": "otx:threat:intel",
    "splunk_source": "alienvault_otx",

    # OTX API
    "otx_api_key": "85d7363b64fff612405535891cffaab7d269f89324da10bc1165f45aea103eaa",
    "otx_base_url": "https://otx.alienvault.com/api/v1",

    # Paths
    "state_file": "/tmp/mnt/OTX/otx_state.json",
    "cache_file": "/tmp/mnt/OTX/otx_cache.json",
    "log_file": "/tmp/mnt/OTX/skynet_otx.log",

    # Settings
    "batch_size": 50,
    "otx_cache_hours": 24,
    "max_ips_per_run": 100,

    # Router
    "router_hostname": "GT-AX11000",
    "router_ip": "192.168.50.1"
}


# ============================================================================
# Logging
# ============================================================================

def setup_logging(debug=False):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(CONFIG["log_file"])
        ]
    )


# ============================================================================
# OTX Cache
# ============================================================================

class OTXCache:
    def __init__(self, cache_file: str, ttl_hours: int = 24):
        self.cache_file = Path(cache_file)
        self.ttl_seconds = ttl_hours * 3600
        self.cache = self._load()

    def _load(self) -> dict:
        if self.cache_file.exists():
            try:
                with open(self.cache_file) as f:
                    data = json.load(f)
                # Clean expired
                cutoff = time.time() - self.ttl_seconds
                return {k: v for k, v in data.items() if v.get('ts', 0) > cutoff}
            except:
                pass
        return {}

    def save(self):
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f)

    def get(self, ip: str) -> Optional[dict]:
        if ip in self.cache:
            entry = self.cache[ip]
            if time.time() - entry.get('ts', 0) < self.ttl_seconds:
                return entry.get('data')
        return None

    def set(self, ip: str, data: dict):
        self.cache[ip] = {'ts': time.time(), 'data': data}


# ============================================================================
# State Tracker (which IPs we've already sent)
# ============================================================================

class StateTracker:
    def __init__(self, state_file: str):
        self.state_file = Path(state_file)
        self.sent_ips = self._load()

    def _load(self) -> set:
        if self.state_file.exists():
            try:
                with open(self.state_file) as f:
                    data = json.load(f)
                return set(data.get('sent_ips', []))
            except:
                pass
        return set()

    def save(self):
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_file, 'w') as f:
            json.dump({'sent_ips': list(self.sent_ips), 'updated': time.time()}, f)

    def is_sent(self, ip: str) -> bool:
        return ip in self.sent_ips

    def mark_sent(self, ip: str):
        self.sent_ips.add(ip)


# ============================================================================
# Get IPs from Skynet IPSet
# ============================================================================

def get_skynet_ips() -> List[Dict[str, str]]:
    """Get blocked IPs from Skynet ipset with their ban reasons"""
    ips = []

    # Try ipset command
    for ipset_name in ['Skynet-Blacklist', 'Skynet-BlockedRanges']:
        try:
            result = subprocess.run(
                ['ipset', 'list', ipset_name],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    # Parse: 1.2.3.4 comment "BanMalware: source.ipset"
                    match = re.match(
                        r'^(\d+\.\d+\.\d+\.\d+)(?:/\d+)?.*?comment\s+"([^"]*)"',
                        line.strip()
                    )
                    if match:
                        ip, reason = match.groups()
                        ips.append({'ip': ip, 'reason': reason})
        except Exception as e:
            logging.warning(f"Error reading {ipset_name}: {e}")

    logging.info(f"Found {len(ips)} IPs in Skynet blocklist")
    return ips


# ============================================================================
# OTX API Client
# ============================================================================

def fetch_otx_intel(ip: str, api_key: str) -> Optional[Dict]:
    """Fetch threat intelligence from OTX for an IP"""
    url = f"{CONFIG['otx_base_url']}/indicators/IPv4/{ip}/general"
    headers = {
        'X-OTX-API-KEY': api_key,
        'Accept': 'application/json'
    }

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()

            # Extract key threat intel
            pulses = data.get('pulse_info', {}).get('pulses', [])

            intel = {
                'ip': ip,
                'pulse_count': data.get('pulse_info', {}).get('count', 0),
                'reputation': data.get('reputation', 0),
                'country_code': data.get('country_code', ''),
                'country_name': data.get('country_name', ''),
                'asn': data.get('asn', ''),
                'city': data.get('city', ''),
                'whois': data.get('whois', '')[:500] if data.get('whois') else '',
                'pulses': [],
                'tags': [],
                'malware_families': [],
                'targeted_countries': [],
                'attack_ids': []
            }

            # Extract from pulses
            for pulse in pulses[:20]:
                intel['pulses'].append({
                    'id': pulse.get('id', ''),
                    'name': pulse.get('name', ''),
                    'description': pulse.get('description', '')[:300],
                    'created': pulse.get('created', ''),
                    'modified': pulse.get('modified', ''),
                    'author': pulse.get('author_name', ''),
                    'adversary': pulse.get('adversary', ''),
                    'tlp': pulse.get('tlp', ''),
                    'industries': pulse.get('industries', []),
                })
                intel['tags'].extend(pulse.get('tags', []))
                intel['malware_families'].extend(pulse.get('malware_families', []))
                intel['targeted_countries'].extend(pulse.get('targeted_countries', []))
                intel['attack_ids'].extend(pulse.get('attack_ids', []))

            # Dedupe
            intel['tags'] = list(set(intel['tags']))[:20]
            intel['malware_families'] = list(set(intel['malware_families']))[:10]
            intel['targeted_countries'] = list(set(intel['targeted_countries']))[:10]
            intel['attack_ids'] = list(set(intel['attack_ids']))[:10]

            return intel

        elif resp.status_code == 404:
            return {'ip': ip, 'pulse_count': 0, 'not_found': True}
        else:
            logging.warning(f"OTX API error for {ip}: {resp.status_code}")
            return None

    except Exception as e:
        logging.error(f"OTX request failed for {ip}: {e}")
        return None


# ============================================================================
# Build Splunk CIM Event
# ============================================================================

def build_cim_event(ip_info: Dict, otx_intel: Dict) -> Dict:
    """Build CIM-compliant threat intel event for Splunk"""

    pulse_count = otx_intel.get('pulse_count', 0)

    # Determine severity based on pulse count
    if pulse_count >= 10:
        severity = 'critical'
        severity_id = 5
    elif pulse_count >= 5:
        severity = 'high'
        severity_id = 4
    elif pulse_count >= 2:
        severity = 'medium'
        severity_id = 3
    elif pulse_count >= 1:
        severity = 'low'
        severity_id = 2
    else:
        severity = 'informational'
        severity_id = 1

    event = {
        '_time': time.time(),

        # CIM Threat Intelligence fields
        'threat_key': ip_info['ip'],
        'threat_match_field': 'src_ip',
        'threat_match_value': ip_info['ip'],
        'threat_collection': 'alienvault_otx',
        'threat_collection_key': ip_info['ip'],
        'threat_source_name': 'AlienVault OTX',
        'threat_source_id': otx_intel.get('pulses', [{}])[0].get('id', ''),

        # Threat details
        'threat_category': otx_intel.get('tags', [])[:5],
        'threat_description': otx_intel.get('pulses', [{}])[0].get('description', ''),
        'malware_family': otx_intel.get('malware_families', []),
        'mitre_technique_id': otx_intel.get('attack_ids', []),

        # Severity
        'severity': severity,
        'severity_id': severity_id,
        'priority': severity,

        # IP details
        'src_ip': ip_info['ip'],
        'ip': ip_info['ip'],
        'dest_ip': CONFIG['router_ip'],

        # GeoIP from OTX
        'src_country': otx_intel.get('country_code', ''),
        'src_country_name': otx_intel.get('country_name', ''),
        'src_city': otx_intel.get('city', ''),
        'src_asn': otx_intel.get('asn', ''),

        # OTX specific
        'otx_pulse_count': pulse_count,
        'otx_reputation': otx_intel.get('reputation', 0),
        'otx_url': f"https://otx.alienvault.com/indicator/ip/{ip_info['ip']}",
        'otx_pulses': [p.get('name', '') for p in otx_intel.get('pulses', [])[:5]],
        'otx_tags': otx_intel.get('tags', [])[:10],
        'otx_malware_families': otx_intel.get('malware_families', []),
        'otx_targeted_countries': otx_intel.get('targeted_countries', []),
        'otx_adversary': otx_intel.get('pulses', [{}])[0].get('adversary', ''),

        # Skynet context
        'skynet_ban_reason': ip_info.get('reason', 'Unknown'),
        'signature': ip_info.get('reason', 'Skynet Block'),

        # Device context
        'dvc': CONFIG['router_hostname'],
        'dvc_ip': CONFIG['router_ip'],
        'vendor': 'ASUS',
        'vendor_product': 'Skynet Firewall',
        'app': 'skynet',

        # Action
        'action': 'blocked',
        'status': 'success'
    }

    return event


# ============================================================================
# Send to Splunk HEC
# ============================================================================

def send_to_splunk(events: List[Dict]) -> bool:
    """Send events to Splunk HEC"""
    if not events:
        return True

    payload = ""
    for event in events:
        hec_event = {
            'time': event.get('_time', time.time()),
            'host': CONFIG['router_hostname'],
            'source': CONFIG['splunk_source'],
            'sourcetype': CONFIG['splunk_sourcetype'],
            'index': CONFIG['splunk_index'],
            'event': event
        }
        payload += json.dumps(hec_event) + "\n"

    try:
        resp = requests.post(
            CONFIG['splunk_hec_url'],
            headers={
                'Authorization': f"Splunk {CONFIG['splunk_hec_token']}",
                'Content-Type': 'application/json'
            },
            data=payload,
            verify=False,
            timeout=30
        )

        if resp.status_code == 200:
            logging.info(f"Sent {len(events)} threat intel events to Splunk")
            return True
        else:
            logging.error(f"Splunk HEC error: {resp.status_code} - {resp.text}")
            return False

    except Exception as e:
        logging.error(f"Splunk HEC failed: {e}")
        return False


# ============================================================================
# Main
# ============================================================================

def run_collection():
    """Main collection routine"""
    cache = OTXCache(CONFIG['cache_file'], CONFIG['otx_cache_hours'])
    state = StateTracker(CONFIG['state_file'])

    # Get IPs from Skynet
    skynet_ips = get_skynet_ips()

    # Filter to IPs we haven't sent yet
    new_ips = [ip for ip in skynet_ips if not state.is_sent(ip['ip'])]
    logging.info(f"Found {len(new_ips)} new IPs to process")

    if not new_ips:
        logging.info("No new IPs to process")
        return 0

    # Limit per run
    new_ips = new_ips[:CONFIG['max_ips_per_run']]

    events = []
    for ip_info in new_ips:
        ip = ip_info['ip']

        # Check cache first
        otx_intel = cache.get(ip)

        if not otx_intel:
            # Fetch from OTX
            otx_intel = fetch_otx_intel(ip, CONFIG['otx_api_key'])
            if otx_intel:
                cache.set(ip, otx_intel)
            time.sleep(0.5)  # Rate limit

        if otx_intel:
            event = build_cim_event(ip_info, otx_intel)
            events.append(event)
            state.mark_sent(ip)

        # Batch send
        if len(events) >= CONFIG['batch_size']:
            send_to_splunk(events)
            events = []

    # Send remaining
    if events:
        send_to_splunk(events)

    # Save state
    cache.save()
    state.save()

    logging.info(f"Processed {len(new_ips)} IPs")
    return len(new_ips)


def test_connections():
    """Test Splunk and OTX connectivity"""
    print("Testing Splunk HEC...")
    test_event = {'_time': time.time(), 'message': 'OTX collector test', 'test': True}
    if send_to_splunk([test_event]):
        print("✓ Splunk HEC OK")
    else:
        print("✗ Splunk HEC FAILED")

    print("\nTesting OTX API...")
    result = fetch_otx_intel('8.8.8.8', CONFIG['otx_api_key'])
    if result:
        print(f"✓ OTX API OK - Google DNS has {result.get('pulse_count', 0)} pulses")
    else:
        print("✗ OTX API FAILED")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Skynet OTX Threat Intel Collector')
    parser.add_argument('--test', action='store_true', help='Test connections')
    parser.add_argument('--debug', action='store_true', help='Debug logging')
    parser.add_argument('--reset', action='store_true', help='Reset state (re-send all)')
    args = parser.parse_args()

    setup_logging(args.debug)

    if args.reset:
        Path(CONFIG['state_file']).unlink(missing_ok=True)
        print("State reset - will re-process all IPs")
        return

    if args.test:
        test_connections()
        return

    run_collection()


if __name__ == '__main__':
    main()
