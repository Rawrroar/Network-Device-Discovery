# nautobot-plugin-device-auto-discovery

A [Nautobot](https://nautobot.com/) App for automatic network device discovery via ICMP ping sweep, SNMP, and SSH.

## Overview

This plugin discovers network devices on your IP ranges and automatically creates them in Nautobot. It supports three discovery methods:

- **ICMP Ping Sweep** — find live hosts in a CIDR range
- **SNMP Discovery** — query live hosts for hostname, model, vendor, and platform via SNMP
- **SSH Discovery** — connect via SSH, run show commands, and parse output for device identification

The **Full Discovery** job orchestrates all three methods in sequence: ping first, then SNMP on live hosts, then SSH on any remaining hosts.

## Features

- Auto-creates `Manufacturer`, `DeviceType`, and `Platform` objects when not found
- Tracks discovery history via `DiscoveryScan` and `DiscoveryResult` models
- Configurable defaults for device location, role, status, and tags
- Threaded/concurrent scanning for fast results
- Dry-run mode for SNMP, SSH, and Full jobs
- Compatible with Nautobot v3.x

### SNMP table collection

When a device responds to SNMP, the plugin walks common MIB tables and populates Nautobot:

- **System scalars** — `sysName`, `sysDescr`, `sysObjectID`, `sysContact`, `sysLocation`
- **Interfaces (IF-MIB)** — creates `dcim.Interface` objects with name, type, MAC, MTU, speed, admin/oper status (as `Active`/`Maintenance` status and `enabled`), and `ifAlias` as the description
- **IP addresses (IP-MIB)** — creates `ipam.IPAddress` objects and assigns them to the matching interface
- **Physical inventory (ENTITY-MIB)** — used to populate the Device `serial` number
- **Neighbors (LLDP-MIB / CISCO-CDP-MIB)** — recorded on the `DiscoveryResult` (`neighbors_found`, `discovered_data`), not linked as Cables

Raw walked tables are stored in `DiscoveryResult.discovered_data` so you can review exactly what was found, including in dry-run mode.

## Requirements

- Nautobot >= 3.0, < 4.0
- Python >= 3.9
- `pysnmp>=4.4` for SNMP queries (both the classic sync API, pysnmp < 7, and the asyncio API, pysnmp >= 7, are supported)
- `paramiko` for SSH connections

## Installation

### 1. Install the package

```bash
pip install nautobot-plugin-device-auto-discovery
```

Or install from source:

```bash
pip install git+https://github.com/your-org/nautobot-plugin-device-auto-discovery.git
```

### 2. Enable the App in `nautobot_config.py`

```python
PLUGINS = [
    "nautobot_plugin_device_auto_discovery",
]
```

### 3. Configure defaults (optional)

```python
PLUGINS_CONFIG = {
    "nautobot_plugin_device_auto_discovery": {
        "default_location": "Unknown",
        "default_role": "Network Device",
        "default_status": "Active",
        "default_tags": ["auto-discovered"],
        "create_missing_objects": True,
        "snmp_timeout": 3,
        "snmp_retries": 2,
        "snmp_community": "public",
        "populate_interfaces": True,
        "populate_ip_addresses": True,
        "include_neighbors": True,
        "max_walk_oids": 1000,
        "ssh_timeout": 10,
        "ssh_banner_timeout": 30,
        "ping_timeout": 2,
        "concurrency": 10,
    },
}
```

### 4. Run migrations

```bash
nautobot-server postupgrade
```

## Usage

### Ping Sweep

Finds live hosts in a CIDR range:

1. Navigate to **Plugins > Device Auto-Discovery > Ping Sweep** (or **Jobs > Ping Sweep**)
2. Enter target network (e.g., `10.0.0.0/24`)
3. Configure timeout and concurrency
4. Run the job

### SNMP Discovery

Discovers devices via SNMP:

1. Navigate to **Jobs > SNMP Discovery**
2. Enter target network
3. Provide SNMP community string
4. Optionally toggle **Populate interfaces**, **Populate IP addresses**, and **Include neighbors**
5. Run the job

Devices discovered via SNMP are auto-created in Nautobot. Platform identification is done via SNMP OID matching. Interfaces and IP addresses are created from the walked IF-MIB and IP-MIB tables; the Device serial number comes from ENTITY-MIB when available. In dry-run mode, no objects are created but all walked table data is captured on the `DiscoveryResult` for review.

### SSH Discovery

Discovers devices via SSH:

1. Navigate to **Jobs > SSH Discovery**
2. Enter target network
3. Provide SSH username and password
4. Run the job

> **Recommendation:** Store credentials in Nautobot Secrets (using Environment Variables or Vault provider) and paste the values into the job inputs.

### Full Discovery

Runs all three methods in sequence:

1. Navigate to **Jobs > Full Discovery**
2. Enter target network
3. Configure SNMP community, SSH credentials
4. Toggle which methods to enable
5. Run the job

The job will:
1. Ping the range to find live hosts
2. Run SNMP on live hosts
3. Run SSH on hosts not identified by SNMP
4. Deduplicate results
5. Create devices in Nautobot

### API Usage

Jobs can also be triggered via the REST API:

```bash
curl -X POST \
  -H "Authorization: Token $TOKEN" \
  -H "Content-Type: application/json" \
  http://nautobot/api/extras/jobs/nautobot_plugin_device_auto_discovery.PingSweep/run/ \
  --data '{"data": {"target_network": "10.0.0.0/24"}}'
```

## Supported Platforms

The plugin maps SNMP OIDs to Nautobot platforms for these vendors:

| Vendor | Platforms |
|--------|-----------|
| Cisco | IOS, IOS-XE, IOS-XR, NX-OS |
| Juniper | Junos |
| Arista | EOS |
| HPE | Comware, ProCurve |
| Nokia | SR OS, SR Linux |
| F5 | TMOS |
| Palo Alto | PAN-OS |
| Fortinet | FortiOS |
| Ubiquiti | EdgeOS, EdgeMAX |

For SSH-discovered devices, vendor detection is done via keyword matching on command output.

## Configuration Reference

| Setting | Default | Description |
|---------|---------|-------------|
| `default_location` | `"Unknown"` | Location assigned to discovered devices |
| `default_role` | `"Network Device"` | Device role assigned to discovered devices |
| `default_status` | `"Active"` | Device status for new devices |
| `default_tags` | `["auto-discovered"]` | Tags to apply to new devices |
| `create_missing_objects` | `True` | Auto-create Manufacturer, DeviceType, Platform if missing |
| `snmp_timeout` | `3` | SNMP query timeout in seconds |
| `snmp_retries` | `2` | SNMP retry count |
| `snmp_community` | `"public"` | Default SNMP community string |
| `populate_interfaces` | `True` | Create `dcim.Interface` objects from IF-MIB |
| `populate_ip_addresses` | `True` | Create/assign `ipam.IPAddress` objects from IP-MIB |
| `include_neighbors` | `True` | Walk LLDP/CDP neighbor tables |
| `max_walk_oids` | `1000` | Cap on rows walked per MIB table |
| `ssh_timeout` | `10` | SSH connection timeout in seconds |
| `ssh_banner_timeout` | `30` | SSH banner wait timeout in seconds |
| `ping_timeout` | `2` | ICMP ping timeout in seconds |
| `concurrency` | `10` | Max concurrent probes |

## Development

### Development Environment

```bash
# Clone the repository
git clone https://github.com/your-org/nautobot-plugin-device-auto-discovery.git
cd nautobot-plugin-device-auto-discovery

# Install in development mode
pip install -e ".[dev]"

# Install Nautobot dev environment per official docs
# https://docs.nautobot.com/projects/core/en/stable/development/core/dev-environment/

# Enable the plugin in your nautobot_config.py
# Run migrations
nautobot-server postupgrade
```

### Running Tests

```bash
coverage run -m pytest tests/
coverage report
```

## License

Apache License 2.0

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Submit a pull request
