# Skynet OTX Threat Collector - Installation Guide

Collects threat intelligence from Skynet firewall logs, enriches with AlienVault OTX data, and exports CIM-compliant events to Splunk ES.

## Quick Install

```bash
# SSH to router
ssh cvalentine@192.168.50.1

# Install Python dependencies (via Entware)
opkg update
opkg install python3 python3-pip python3-requests

# Copy files to USB drive
cd /tmp/mnt/OTX
# Copy: skynet_otx_splunk.py, skynet_otx_config.json, skynet_otx_runner.sh

# Make executable
chmod +x skynet_otx_splunk.py skynet_otx_runner.sh

# Test connectivity
./skynet_otx_runner.sh test

# Run once to verify
./skynet_otx_runner.sh run

# Install to cron (runs every 5 minutes)
./skynet_otx_runner.sh install
```

## Configuration

Edit `skynet_otx_config.json`:

| Setting | Value |
|---------|-------|
| `splunk_hec_url` | `https://192.168.50.213:8088/services/collector/event` |
| `splunk_hec_token` | Your Splunk HEC token |
| `splunk_index` | `threat_activity` |
| `otx_api_key` | Your OTX API key |
| `router_ip` | `192.168.50.1` |
| `router_hostname` | `GT-AX11000` |

## Commands

```bash
./skynet_otx_runner.sh start      # Start daemon
./skynet_otx_runner.sh stop       # Stop daemon
./skynet_otx_runner.sh run        # Run once
./skynet_otx_runner.sh status     # Check status
./skynet_otx_runner.sh install    # Add to cron
./skynet_otx_runner.sh uninstall  # Remove from cron
./skynet_otx_runner.sh test       # Test connections
```

## Splunk ES CIM Fields

Events are sent with these CIM-compliant fields:

**Network Traffic:**
- `src_ip`, `dest_ip`, `src_port`, `dest_port`
- `action` (blocked), `transport`, `direction`

**Threat Intelligence:**
- `threat_match_field`, `threat_match_value`
- `threat_category`, `threat_collection`
- `signature`, `severity`

**OTX Enrichment:**
- `otx_pulse_count`, `otx_reputation`
- `otx_country`, `otx_asn`
- `otx_malware_families`, `otx_categories`
- `mitre_technique_id`

## Logs

- Application: `/tmp/mnt/OTX/skynet_otx.log`
- State: `/tmp/mnt/OTX/skynet_otx_state.json`
- OTX Cache: `/tmp/mnt/OTX/otx_cache.json`
