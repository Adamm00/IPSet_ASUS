#!/opt/bin/python3
"""
Skynet OTX Threat Intelligence Collector for Splunk ES
Designed for ASUS routers running AsusWRT-Merlin with Skynet firewall

This script:
1. Parses Skynet firewall logs for blocked threats
2. Enriches threat data with OTX (AlienVault Open Threat Exchange) intelligence
3. Exports CIM-compliant events to Splunk ES via HEC

Requirements:
- Python 3.x (via Entware: opkg install python3 python3-pip)
- requests library (pip3 install requests)

Author: Claude Code
Version: 1.0.0
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
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

# Handle missing requests library gracefully
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("WARNING: 'requests' library not found. Install with: opkg install python3-requests")
    print("         or: pip3 install requests")


# ============================================================================
# Configuration - Load from config file or use defaults
# ============================================================================

class Config:
    """Configuration management for the script"""

    def __init__(self, config_path: str = None):
        # Default paths for ASUS router
        self.script_dir = Path(__file__).parent.resolve()
        self.config_path = config_path or self.script_dir / "skynet_otx_config.json"

        # Default configuration
        self.defaults = {
            # Splunk HEC Configuration
            "splunk_hec_url": "https://192.168.50.213:8088/services/collector/event",
            "splunk_hec_token": "935af03b-c11c-403a-98e7-904eaf7d88e5",
            "splunk_index": "threat_activity",
            "splunk_sourcetype": "skynet:otx:threat",
            "splunk_source": "skynet_firewall",
            "splunk_verify_ssl": False,

            # OTX Configuration
            "otx_api_key": "85d7363b64fff612405535891cffaab7d269f89324da10bc1165f45aea103eaa",
            "otx_base_url": "https://otx.alienvault.com/api/v1",
            "otx_cache_ttl": 3600,  # Cache OTX results for 1 hour
            "otx_rate_limit": 0.5,  # Seconds between OTX API calls

            # Skynet Log Locations
            "syslog_paths": [
                "/tmp/syslog.log",
                "/jffs/syslog.log",
                "/opt/var/log/messages"
            ],
            "skynet_log_path": "/opt/share/skynet/skynet.log",
            "skynet_ipset_path": "/opt/share/skynet/skynet.ipset",

            # Processing Options
            "batch_size": 50,  # Events per HEC batch
            "state_file": "/tmp/mnt/OTX/skynet_otx_state.json",
            "cache_file": "/tmp/mnt/OTX/otx_cache.json",
            "log_file": "/tmp/mnt/OTX/skynet_otx.log",
            "max_events_per_run": 500,  # Limit events per execution
            "dedupe_window": 300,  # Dedupe same IP within 5 minutes

            # Router Info
            "router_ip": "192.168.50.1",
            "router_hostname": "GT-AX11000"
        }

        self.config = self._load_config()

    def _load_config(self) -> dict:
        """Load configuration from file, merging with defaults"""
        config = self.defaults.copy()

        if Path(self.config_path).exists():
            try:
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
                    config.update(user_config)
            except (json.JSONDecodeError, IOError) as e:
                logging.warning(f"Failed to load config file: {e}")

        return config

    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except IOError as e:
            logging.error(f"Failed to save config: {e}")

    def __getattr__(self, name):
        """Allow attribute-style access to config values"""
        if name in ('config', 'defaults', 'config_path', 'script_dir'):
            return object.__getattribute__(self, name)
        return self.config.get(name)


# ============================================================================
# Logging Setup
# ============================================================================

def setup_logging(log_file: str, debug: bool = False):
    """Configure logging for the script"""
    level = logging.DEBUG if debug else logging.INFO

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)

    # File handler
    try:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(level)
    except IOError:
        file_handler = None

    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(level)
    logger.addHandler(console_handler)
    if file_handler:
        logger.addHandler(file_handler)

    return logger


# ============================================================================
# State Management
# ============================================================================

class StateManager:
    """Manage processing state to avoid duplicate events"""

    def __init__(self, state_file: str):
        self.state_file = Path(state_file)
        self.state = self._load_state()

    def _load_state(self) -> dict:
        """Load state from file"""
        default_state = {
            "last_position": {},  # file -> byte position
            "processed_events": {},  # event_hash -> timestamp
            "last_run": None
        }

        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    # Clean old entries (older than 1 hour)
                    cutoff = time.time() - 3600
                    state["processed_events"] = {
                        k: v for k, v in state.get("processed_events", {}).items()
                        if v > cutoff
                    }
                    return state
            except (json.JSONDecodeError, IOError):
                pass

        return default_state

    def save_state(self):
        """Save state to file"""
        self.state["last_run"] = time.time()
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.state_file, 'w') as f:
                json.dump(self.state, f)
        except IOError as e:
            logging.error(f"Failed to save state: {e}")

    def get_file_position(self, filepath: str) -> int:
        """Get last read position for a file"""
        return self.state.get("last_position", {}).get(filepath, 0)

    def set_file_position(self, filepath: str, position: int):
        """Set last read position for a file"""
        if "last_position" not in self.state:
            self.state["last_position"] = {}
        self.state["last_position"][filepath] = position

    def is_processed(self, event_hash: str, window: int = 300) -> bool:
        """Check if event was recently processed (within window seconds)"""
        if event_hash in self.state.get("processed_events", {}):
            if time.time() - self.state["processed_events"][event_hash] < window:
                return True
        return False

    def mark_processed(self, event_hash: str):
        """Mark event as processed"""
        if "processed_events" not in self.state:
            self.state["processed_events"] = {}
        self.state["processed_events"][event_hash] = time.time()


# ============================================================================
# OTX Client
# ============================================================================

class OTXClient:
    """AlienVault OTX API client with caching"""

    def __init__(self, api_key: str, base_url: str, cache_file: str,
                 cache_ttl: int = 3600, rate_limit: float = 0.5):
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.cache_file = Path(cache_file)
        self.cache_ttl = cache_ttl
        self.rate_limit = rate_limit
        self.last_request = 0
        self.cache = self._load_cache()
        self.session = None

        if REQUESTS_AVAILABLE:
            self.session = requests.Session()
            self.session.headers.update({
                'X-OTX-API-KEY': self.api_key,
                'Accept': 'application/json',
                'User-Agent': 'Skynet-OTX-Collector/1.0'
            })

    def _load_cache(self) -> dict:
        """Load OTX cache from file"""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    cache = json.load(f)
                    # Clean expired entries
                    cutoff = time.time() - self.cache_ttl
                    return {
                        k: v for k, v in cache.items()
                        if v.get('timestamp', 0) > cutoff
                    }
            except (json.JSONDecodeError, IOError):
                pass
        return {}

    def _save_cache(self):
        """Save OTX cache to file"""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
        except IOError as e:
            logging.warning(f"Failed to save OTX cache: {e}")

    def _rate_limit_wait(self):
        """Enforce rate limiting"""
        elapsed = time.time() - self.last_request
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self.last_request = time.time()

    def get_ip_reputation(self, ip: str) -> Optional[Dict]:
        """Get OTX reputation data for an IP address"""
        if not REQUESTS_AVAILABLE or not self.session:
            return self._get_fallback_data(ip)

        cache_key = f"ip:{ip}"

        # Check cache
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if time.time() - cached.get('timestamp', 0) < self.cache_ttl:
                logging.debug(f"OTX cache hit for {ip}")
                return cached.get('data')

        # Rate limit
        self._rate_limit_wait()

        try:
            # Get general indicator info
            url = f"{self.base_url}/indicators/IPv4/{ip}/general"
            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()

                # Extract relevant threat intelligence
                result = {
                    'ip': ip,
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'reputation': data.get('reputation', 0),
                    'country': data.get('country_code', 'Unknown'),
                    'asn': data.get('asn', 'Unknown'),
                    'categories': [],
                    'malware_families': [],
                    'threat_types': [],
                    'pulses': [],
                    'validation': data.get('validation', []),
                    'whois': data.get('whois', ''),
                    'otx_url': f"https://otx.alienvault.com/indicator/ip/{ip}"
                }

                # Extract pulse information
                pulses = data.get('pulse_info', {}).get('pulses', [])[:10]  # Limit to 10
                for pulse in pulses:
                    pulse_info = {
                        'id': pulse.get('id', ''),
                        'name': pulse.get('name', ''),
                        'description': pulse.get('description', '')[:200],
                        'created': pulse.get('created', ''),
                        'tags': pulse.get('tags', [])[:5],
                        'targeted_countries': pulse.get('targeted_countries', []),
                        'malware_families': pulse.get('malware_families', []),
                        'attack_ids': pulse.get('attack_ids', []),
                        'industries': pulse.get('industries', [])
                    }
                    result['pulses'].append(pulse_info)

                    # Aggregate categories and malware families
                    result['malware_families'].extend(pulse.get('malware_families', []))
                    for tag in pulse.get('tags', []):
                        if tag not in result['categories']:
                            result['categories'].append(tag)

                # Dedupe
                result['malware_families'] = list(set(result['malware_families']))[:10]
                result['categories'] = result['categories'][:10]

                # Cache result
                self.cache[cache_key] = {
                    'timestamp': time.time(),
                    'data': result
                }
                self._save_cache()

                logging.debug(f"OTX fetched data for {ip}: {result['pulse_count']} pulses")
                return result

            elif response.status_code == 404:
                # IP not found in OTX - cache negative result
                result = self._get_fallback_data(ip)
                self.cache[cache_key] = {
                    'timestamp': time.time(),
                    'data': result
                }
                return result
            else:
                logging.warning(f"OTX API error for {ip}: {response.status_code}")
                return self._get_fallback_data(ip)

        except requests.exceptions.RequestException as e:
            logging.warning(f"OTX request failed for {ip}: {e}")
            return self._get_fallback_data(ip)

    def _get_fallback_data(self, ip: str) -> Dict:
        """Return minimal data when OTX is unavailable"""
        return {
            'ip': ip,
            'pulse_count': 0,
            'reputation': 0,
            'country': 'Unknown',
            'asn': 'Unknown',
            'categories': [],
            'malware_families': [],
            'threat_types': [],
            'pulses': [],
            'otx_url': f"https://otx.alienvault.com/indicator/ip/{ip}"
        }


# ============================================================================
# Skynet Log Parser
# ============================================================================

class SkynetLogParser:
    """Parse Skynet firewall logs"""

    # Regex patterns for log parsing
    BLOCKED_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*?'
        r'\[BLOCKED\s*-\s*(?P<direction>INBOUND|OUTBOUND|INVALID|IOT)\].*?'
        r'(?:PROTO=(?P<proto>\w+))?.*?'
        r'(?:SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+))?.*?'
        r'(?:DST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+))?.*?'
        r'(?:SPT=(?P<src_port>\d+))?.*?'
        r'(?:DPT=(?P<dst_port>\d+))?'
    )

    # RFC1918 private IP ranges
    PRIVATE_RANGES = [
        re.compile(r'^10\.'),
        re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'),
        re.compile(r'^192\.168\.'),
        re.compile(r'^127\.'),
        re.compile(r'^169\.254\.'),
    ]

    def __init__(self, ipset_path: str):
        self.ipset_path = ipset_path
        self.ban_reasons = self._load_ipset_comments()

    def _load_ipset_comments(self) -> Dict[str, str]:
        """Load ban reasons from ipset file or command"""
        reasons = {}

        # Try to read from file first
        if Path(self.ipset_path).exists():
            try:
                with open(self.ipset_path, 'r') as f:
                    for line in f:
                        match = re.match(
                            r'add\s+\S+\s+(\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+comment\s+"([^"]+)"',
                            line.strip()
                        )
                        if match:
                            ip, comment = match.groups()
                            reasons[ip.split('/')[0]] = comment
            except IOError:
                pass

        # Also try ipset list command
        try:
            result = subprocess.run(
                ['ipset', 'list', '-t'],
                capture_output=True,
                text=True,
                timeout=10
            )
            # Parse ipset output for set names
            sets_to_check = ['Skynet-Blacklist', 'Skynet-BlockedRanges']

            for ipset_name in sets_to_check:
                try:
                    result = subprocess.run(
                        ['ipset', 'list', ipset_name],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            # Parse: 1.2.3.4 comment "BanMalware: source.ipset"
                            match = re.match(
                                r'(\d+\.\d+\.\d+\.\d+)(?:/\d+)?.*comment\s+"([^"]+)"',
                                line.strip()
                            )
                            if match:
                                ip, comment = match.groups()
                                reasons[ip] = comment
                except subprocess.TimeoutExpired:
                    pass
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        logging.info(f"Loaded {len(reasons)} ban reasons from ipset")
        return reasons

    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        return any(pattern.match(ip) for pattern in self.PRIVATE_RANGES)

    def parse_log_line(self, line: str) -> Optional[Dict]:
        """Parse a single log line"""
        match = self.BLOCKED_PATTERN.search(line)
        if not match:
            return None

        data = match.groupdict()

        # Determine threat IP based on direction
        direction = data.get('direction', 'UNKNOWN')
        src_ip = data.get('src_ip', '')
        dst_ip = data.get('dst_ip', '')

        if direction == 'INBOUND':
            threat_ip = src_ip  # External attacker
            victim_ip = dst_ip
        elif direction == 'OUTBOUND':
            threat_ip = dst_ip  # C2 or malware destination
            victim_ip = src_ip
        else:
            # For INVALID/IOT, use non-private IP as threat
            if src_ip and not self.is_private_ip(src_ip):
                threat_ip = src_ip
                victim_ip = dst_ip
            else:
                threat_ip = dst_ip
                victim_ip = src_ip

        if not threat_ip or self.is_private_ip(threat_ip):
            return None

        # Get ban reason
        ban_reason = self.ban_reasons.get(threat_ip, 'Unknown')

        # Parse timestamp
        timestamp_str = data.get('timestamp', '')
        try:
            # Add current year to timestamp
            current_year = datetime.now().year
            parsed_time = datetime.strptime(
                f"{current_year} {timestamp_str}",
                "%Y %b %d %H:%M:%S"
            )
            epoch_time = parsed_time.timestamp()
        except ValueError:
            epoch_time = time.time()

        return {
            'timestamp': epoch_time,
            'timestamp_str': timestamp_str,
            'direction': direction,
            'threat_ip': threat_ip,
            'victim_ip': victim_ip,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': data.get('src_port', ''),
            'dst_port': data.get('dst_port', ''),
            'protocol': data.get('proto', 'UNKNOWN'),
            'ban_reason': ban_reason,
            'raw_log': line.strip()
        }

    def parse_log_file(self, filepath: str, start_position: int = 0,
                       max_lines: int = 1000) -> Tuple[List[Dict], int]:
        """Parse log file from given position"""
        events = []
        current_position = start_position

        try:
            file_size = os.path.getsize(filepath)

            # Handle log rotation - if file is smaller than last position
            if file_size < start_position:
                logging.info(f"Log rotation detected for {filepath}")
                start_position = 0

            with open(filepath, 'r', errors='ignore') as f:
                f.seek(start_position)
                lines_read = 0

                for line in f:
                    lines_read += 1
                    if lines_read > max_lines:
                        break

                    if '[BLOCKED' in line:
                        event = self.parse_log_line(line)
                        if event:
                            events.append(event)

                current_position = f.tell()

        except IOError as e:
            logging.error(f"Error reading {filepath}: {e}")

        logging.info(f"Parsed {len(events)} events from {filepath}")
        return events, current_position


# ============================================================================
# Splunk HEC Client
# ============================================================================

class SplunkHECClient:
    """Splunk HTTP Event Collector client"""

    def __init__(self, hec_url: str, token: str, index: str,
                 sourcetype: str, source: str, verify_ssl: bool = False):
        self.hec_url = hec_url
        self.token = token
        self.index = index
        self.sourcetype = sourcetype
        self.source = source
        self.verify_ssl = verify_ssl
        self.session = None

        if REQUESTS_AVAILABLE:
            self.session = requests.Session()
            self.session.headers.update({
                'Authorization': f'Splunk {self.token}',
                'Content-Type': 'application/json'
            })

    def send_events(self, events: List[Dict]) -> bool:
        """Send batch of events to Splunk HEC"""
        if not REQUESTS_AVAILABLE or not self.session:
            logging.error("Requests library not available")
            return False

        if not events:
            return True

        # Build HEC payload
        payload = ""
        for event in events:
            hec_event = {
                'time': event.get('_time', time.time()),
                'host': event.get('host', 'skynet'),
                'source': self.source,
                'sourcetype': self.sourcetype,
                'index': self.index,
                'event': event
            }
            payload += json.dumps(hec_event) + "\n"

        try:
            response = self.session.post(
                self.hec_url,
                data=payload,
                verify=self.verify_ssl,
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                if result.get('text') == 'Success':
                    logging.info(f"Successfully sent {len(events)} events to Splunk")
                    return True
                else:
                    logging.error(f"Splunk HEC error: {result}")
                    return False
            else:
                logging.error(f"Splunk HEC HTTP error: {response.status_code} - {response.text}")
                return False

        except requests.exceptions.RequestException as e:
            logging.error(f"Splunk HEC request failed: {e}")
            return False


# ============================================================================
# CIM Event Builder
# ============================================================================

class CIMEventBuilder:
    """Build Splunk CIM-compliant events for threat intelligence"""

    def __init__(self, router_ip: str, router_hostname: str):
        self.router_ip = router_ip
        self.router_hostname = router_hostname

    def build_threat_event(self, log_event: Dict, otx_data: Optional[Dict]) -> Dict:
        """Build a CIM-compliant threat intelligence event"""

        # Base event with Splunk CIM Network Traffic fields
        event = {
            # Timestamps
            '_time': log_event['timestamp'],
            'timestamp': datetime.fromtimestamp(log_event['timestamp']).isoformat(),

            # CIM: Network Traffic
            'action': 'blocked',
            'app': 'skynet',
            'bytes': 0,
            'bytes_in': 0,
            'bytes_out': 0,
            'dest': log_event['dst_ip'],
            'dest_ip': log_event['dst_ip'],
            'dest_port': log_event.get('dst_port', ''),
            'direction': log_event['direction'].lower(),
            'dvc': self.router_hostname,
            'dvc_ip': self.router_ip,
            'protocol': log_event.get('protocol', 'unknown').lower(),
            'src': log_event['src_ip'],
            'src_ip': log_event['src_ip'],
            'src_port': log_event.get('src_port', ''),
            'transport': log_event.get('protocol', 'unknown').lower(),
            'vendor': 'ASUS',
            'vendor_product': 'Skynet Firewall',

            # CIM: Intrusion Detection
            'category': 'network',
            'ids_type': 'network',
            'severity': 'medium',
            'signature': log_event['ban_reason'],
            'signature_id': self._generate_signature_id(log_event['ban_reason']),

            # CIM: Threat Intelligence
            'threat_match_field': 'src_ip' if log_event['direction'] == 'INBOUND' else 'dest_ip',
            'threat_match_value': log_event['threat_ip'],
            'threat_key': log_event['threat_ip'],

            # Skynet-specific fields
            'skynet_direction': log_event['direction'],
            'skynet_ban_reason': log_event['ban_reason'],
            'threat_ip': log_event['threat_ip'],
            'victim_ip': log_event.get('victim_ip', ''),

            # Device context
            'host': self.router_hostname,
            'host_ip': self.router_ip
        }

        # Extract threat source from ban reason
        threat_source = self._parse_threat_source(log_event['ban_reason'])
        event['threat_collection'] = threat_source.get('collection', 'unknown')
        event['threat_collection_key'] = threat_source.get('source_file', 'unknown')

        # Enrich with OTX data if available
        if otx_data:
            event.update(self._build_otx_fields(otx_data))

        return event

    def _generate_signature_id(self, ban_reason: str) -> str:
        """Generate a signature ID from ban reason"""
        # Create deterministic ID from ban reason
        import hashlib
        return hashlib.md5(ban_reason.encode()).hexdigest()[:8]

    def _parse_threat_source(self, ban_reason: str) -> Dict:
        """Parse the threat source from ban reason"""
        result = {
            'type': 'unknown',
            'collection': 'skynet',
            'source_file': ''
        }

        if not ban_reason:
            return result

        # Parse different ban reason formats
        # "BanMalware: cybercrime.ipset"
        # "ManualBan: reason"
        # "BanAiProtect: malware.example.com"
        # "Ban Country: CN"

        if ban_reason.startswith('BanMalware:'):
            result['type'] = 'malware_list'
            result['collection'] = 'firehol'
            source = ban_reason.replace('BanMalware:', '').strip()
            result['source_file'] = source

            # Map source file to threat category
            if 'cybercrime' in source.lower():
                result['threat_category'] = 'cybercrime'
            elif 'spamhaus' in source.lower():
                result['threat_category'] = 'spam'
            elif 'firehol' in source.lower():
                result['threat_category'] = 'malicious'
            elif 'compromised' in source.lower():
                result['threat_category'] = 'compromised'
            elif 'dyndns' in source.lower() or 'ponmocup' in source.lower():
                result['threat_category'] = 'botnet'
            else:
                result['threat_category'] = 'malware'

        elif ban_reason.startswith('ManualBan:'):
            result['type'] = 'manual'
            result['collection'] = 'manual'
            result['source_file'] = ban_reason.replace('ManualBan:', '').strip()
            result['threat_category'] = 'suspicious'

        elif ban_reason.startswith('BanAiProtect:'):
            result['type'] = 'aiprotect'
            result['collection'] = 'asus_aiprotect'
            result['source_file'] = ban_reason.replace('BanAiProtect:', '').strip()
            result['threat_category'] = 'malware'

        elif 'Country' in ban_reason:
            result['type'] = 'geo_block'
            result['collection'] = 'country_block'
            match = re.search(r':\s*(\w+)', ban_reason)
            if match:
                result['source_file'] = match.group(1)
            result['threat_category'] = 'geographic'

        return result

    def _build_otx_fields(self, otx_data: Dict) -> Dict:
        """Build OTX-specific fields for CIM"""
        fields = {
            # OTX enrichment
            'otx_pulse_count': otx_data.get('pulse_count', 0),
            'otx_reputation': otx_data.get('reputation', 0),
            'otx_country': otx_data.get('country', 'Unknown'),
            'otx_asn': otx_data.get('asn', 'Unknown'),
            'otx_url': otx_data.get('otx_url', ''),

            # CIM threat intel fields from OTX
            'threat_category': [],
            'threat_description': '',
            'threat_source_id': '',
            'threat_source_name': 'AlienVault OTX'
        }

        # Extract categories and malware families
        categories = otx_data.get('categories', [])
        malware_families = otx_data.get('malware_families', [])

        if categories:
            fields['threat_category'] = categories[:5]
            fields['otx_categories'] = categories

        if malware_families:
            fields['otx_malware_families'] = malware_families
            fields['malware_family'] = malware_families[0] if malware_families else ''

        # Build threat description from pulses
        pulses = otx_data.get('pulses', [])
        if pulses:
            first_pulse = pulses[0]
            fields['threat_source_id'] = first_pulse.get('id', '')
            fields['threat_description'] = first_pulse.get('description', '')[:500]

            # Extract all pulse names
            pulse_names = [p.get('name', '') for p in pulses if p.get('name')]
            fields['otx_pulse_names'] = pulse_names[:5]

            # Extract targeted countries and industries
            targeted_countries = []
            industries = []
            attack_ids = []

            for pulse in pulses:
                targeted_countries.extend(pulse.get('targeted_countries', []))
                industries.extend(pulse.get('industries', []))
                attack_ids.extend(pulse.get('attack_ids', []))

            if targeted_countries:
                fields['otx_targeted_countries'] = list(set(targeted_countries))[:10]
            if industries:
                fields['otx_targeted_industries'] = list(set(industries))[:10]
            if attack_ids:
                # MITRE ATT&CK IDs
                fields['mitre_technique_id'] = list(set(attack_ids))[:10]

        # Set severity based on pulse count and reputation
        pulse_count = otx_data.get('pulse_count', 0)
        if pulse_count >= 10:
            fields['severity'] = 'critical'
            fields['severity_id'] = 5
        elif pulse_count >= 5:
            fields['severity'] = 'high'
            fields['severity_id'] = 4
        elif pulse_count >= 2:
            fields['severity'] = 'medium'
            fields['severity_id'] = 3
        elif pulse_count >= 1:
            fields['severity'] = 'low'
            fields['severity_id'] = 2
        else:
            fields['severity'] = 'informational'
            fields['severity_id'] = 1

        return fields


# ============================================================================
# Main Collector
# ============================================================================

class SkynetOTXCollector:
    """Main collector class orchestrating the data pipeline"""

    def __init__(self, config: Config):
        self.config = config
        self.state = StateManager(config.state_file)
        self.parser = SkynetLogParser(config.skynet_ipset_path)
        self.otx = OTXClient(
            api_key=config.otx_api_key,
            base_url=config.otx_base_url,
            cache_file=config.cache_file,
            cache_ttl=config.otx_cache_ttl,
            rate_limit=config.otx_rate_limit
        )
        self.splunk = SplunkHECClient(
            hec_url=config.splunk_hec_url,
            token=config.splunk_hec_token,
            index=config.splunk_index,
            sourcetype=config.splunk_sourcetype,
            source=config.splunk_source,
            verify_ssl=config.splunk_verify_ssl
        )
        self.cim_builder = CIMEventBuilder(
            router_ip=config.router_ip,
            router_hostname=config.router_hostname
        )

    def collect_and_send(self) -> int:
        """Main collection and sending workflow"""
        all_events = []

        # Find available log files
        log_files = []
        for log_path in self.config.syslog_paths:
            if Path(log_path).exists():
                log_files.append(log_path)

        # Also check skynet-specific log
        if Path(self.config.skynet_log_path).exists():
            log_files.append(self.config.skynet_log_path)

        if not log_files:
            logging.warning("No log files found")
            return 0

        logging.info(f"Processing log files: {log_files}")

        # Parse each log file
        for log_file in log_files:
            start_pos = self.state.get_file_position(log_file)
            events, end_pos = self.parser.parse_log_file(
                log_file,
                start_pos,
                max_lines=self.config.max_events_per_run
            )
            self.state.set_file_position(log_file, end_pos)
            all_events.extend(events)

        if not all_events:
            logging.info("No new events found")
            self.state.save_state()
            return 0

        # Deduplicate events
        unique_events = []
        seen_ips = defaultdict(list)

        for event in all_events:
            event_hash = f"{event['threat_ip']}:{event['direction']}:{event['dst_port']}"

            if not self.state.is_processed(event_hash, self.config.dedupe_window):
                unique_events.append(event)
                self.state.mark_processed(event_hash)
                seen_ips[event['threat_ip']].append(event)

        logging.info(f"Processing {len(unique_events)} unique events ({len(all_events)} total)")

        # Get unique threat IPs for OTX lookup
        unique_ips = list(set(e['threat_ip'] for e in unique_events))
        logging.info(f"Looking up {len(unique_ips)} unique IPs in OTX")

        # Fetch OTX data for each unique IP
        otx_cache = {}
        for ip in unique_ips[:100]:  # Limit OTX lookups
            otx_data = self.otx.get_ip_reputation(ip)
            if otx_data:
                otx_cache[ip] = otx_data

        # Build CIM-compliant events
        cim_events = []
        for event in unique_events:
            otx_data = otx_cache.get(event['threat_ip'])
            cim_event = self.cim_builder.build_threat_event(event, otx_data)
            cim_events.append(cim_event)

        # Send to Splunk in batches
        sent_count = 0
        batch_size = self.config.batch_size

        for i in range(0, len(cim_events), batch_size):
            batch = cim_events[i:i + batch_size]
            if self.splunk.send_events(batch):
                sent_count += len(batch)
            else:
                logging.error(f"Failed to send batch {i // batch_size + 1}")

        # Save state
        self.state.save_state()

        logging.info(f"Collection complete: {sent_count}/{len(cim_events)} events sent to Splunk")
        return sent_count


# ============================================================================
# CLI Interface
# ============================================================================

def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Skynet OTX Threat Intelligence Collector for Splunk ES',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                     # Run collection once
  %(prog)s --debug             # Run with debug logging
  %(prog)s --daemon --interval 300  # Run every 5 minutes
  %(prog)s --test-splunk       # Test Splunk HEC connectivity
  %(prog)s --test-otx          # Test OTX API connectivity
  %(prog)s --config /path/to/config.json  # Use custom config
        """
    )

    parser.add_argument('--config', '-c', help='Path to config file')
    parser.add_argument('--debug', '-d', action='store_true', help='Enable debug logging')
    parser.add_argument('--daemon', action='store_true', help='Run continuously')
    parser.add_argument('--interval', type=int, default=300, help='Interval in seconds for daemon mode')
    parser.add_argument('--test-splunk', action='store_true', help='Test Splunk HEC connectivity')
    parser.add_argument('--test-otx', action='store_true', help='Test OTX API connectivity')
    parser.add_argument('--dry-run', action='store_true', help='Parse logs but do not send to Splunk')
    parser.add_argument('--version', action='version', version='Skynet OTX Collector v1.0.0')

    args = parser.parse_args()

    # Load configuration
    config = Config(args.config)

    # Setup logging
    setup_logging(config.log_file, args.debug)

    # Check for requests library
    if not REQUESTS_AVAILABLE:
        logging.error("Required 'requests' library is not installed")
        logging.error("Install with: opkg install python3-requests")
        logging.error("         or: pip3 install requests")
        sys.exit(1)

    # Test modes
    if args.test_splunk:
        logging.info("Testing Splunk HEC connectivity...")
        splunk = SplunkHECClient(
            hec_url=config.splunk_hec_url,
            token=config.splunk_hec_token,
            index=config.splunk_index,
            sourcetype=config.splunk_sourcetype,
            source=config.splunk_source,
            verify_ssl=config.splunk_verify_ssl
        )
        test_event = {
            '_time': time.time(),
            'message': 'Skynet OTX Collector test event',
            'test': True
        }
        if splunk.send_events([test_event]):
            logging.info("SUCCESS: Splunk HEC connection working")
            sys.exit(0)
        else:
            logging.error("FAILED: Could not connect to Splunk HEC")
            sys.exit(1)

    if args.test_otx:
        logging.info("Testing OTX API connectivity...")
        otx = OTXClient(
            api_key=config.otx_api_key,
            base_url=config.otx_base_url,
            cache_file=config.cache_file
        )
        # Test with a known malicious IP
        result = otx.get_ip_reputation('8.8.8.8')  # Google DNS as test
        if result:
            logging.info(f"SUCCESS: OTX API working - Got data for 8.8.8.8")
            logging.info(f"  Pulse count: {result.get('pulse_count', 0)}")
            logging.info(f"  Country: {result.get('country', 'Unknown')}")
            sys.exit(0)
        else:
            logging.error("FAILED: Could not connect to OTX API")
            sys.exit(1)

    # Main collection
    collector = SkynetOTXCollector(config)

    if args.daemon:
        logging.info(f"Starting daemon mode with {args.interval}s interval")
        while True:
            try:
                if not args.dry_run:
                    collector.collect_and_send()
                else:
                    logging.info("Dry run - would collect and send events")
            except KeyboardInterrupt:
                logging.info("Shutdown requested")
                break
            except Exception as e:
                logging.error(f"Collection error: {e}")

            time.sleep(args.interval)
    else:
        try:
            if not args.dry_run:
                count = collector.collect_and_send()
                logging.info(f"Sent {count} events")
            else:
                logging.info("Dry run mode - parsing logs only")
                # Just parse and display
                for log_path in config.syslog_paths:
                    if Path(log_path).exists():
                        events, _ = collector.parser.parse_log_file(log_path, 0, 100)
                        for event in events[:10]:
                            print(json.dumps(event, indent=2))
        except KeyboardInterrupt:
            logging.info("Interrupted")
        except Exception as e:
            logging.error(f"Error: {e}")
            if args.debug:
                import traceback
                traceback.print_exc()
            sys.exit(1)


if __name__ == '__main__':
    main()
