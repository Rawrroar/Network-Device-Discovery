# nautobot-plugin-device-auto-discovery

A [Nautobot](https://nautobot.com/) App for automatic network device discovery via ICMP ping sweep, SNMP, and SSH.

## Overview

This plugin discovers network devices on your IP ranges and automatically creates them in Nautobot. It supports three discovery methods:

- **ICMP Ping Sweep** — find live hosts in a CIDR range
- **SNMP Discovery** — query live hosts for hostname, model, vendor, platform, and VLANs via SNMP
- **SSH Discovery** — connect via SSH, run show commands, and parse output for device identification

The **Full Discovery** job orchestrates all three methods in sequence: ping first, then SNMP on live hosts, then SSH on any remaining hosts.

## Features

- Auto-creates `Manufacturer`, `DeviceType`, and `Platform` objects when not found
- Tracks discovery history via `DiscoveryScan` and `DiscoveryResult` models
- Configurable defaults for device location, role, status, and tags
- Threaded/concurrent scanning for fast results
- Dry-run mode for SNMP, SSH, and Full jobs
- **Cable linking** — creates `dcim.Cable` objects from LLDP/CDP neighbor data when both ends can be resolved
- **Crawl Discovery** — iteratively discovers devices from a seed device by following LLDP/CDP neighbors hop by hop
- **DiscoveryProfiles** — reusable scan-scope and settings (prefixes, exclusions, IP cap, ports, timeouts, domain stripping) applied to the SNMP, Full, and Crawl jobs
- **Secrets-based credentials** — SSH and SNMP credentials resolved from weighted Secrets Groups assigned to a profile; the last-known-working SSH group is remembered per device, and SNMPv3 security levels are derived from the secrets present (no credentials in `PLUGINS_CONFIG`)
- **Automated classification** — weighted rules map hostname patterns and IP scopes to Location/Role/Tenant for Not Imported devices, recomputed automatically after scans and rule changes
- **Fast Path** — recurring Full Discovery runs skip SSH platform/credential discovery for devices whose SNMP identity matches stored state, with automatic self-correction on failure
- **Inventory correlation** — each discovered IP is matched against Nautobot by primary IP, hostname, and serial, and persisted on a `DiscoveredDevice` record as `imported`, `new`, `partially_imported`, or `conflict`
- Compatible with Nautobot v3.x

### SNMP table collection

When a device responds to SNMP, the plugin walks common MIB tables and populates Nautobot:

- **System scalars** — `sysName`, `sysDescr`, `sysObjectID`, `sysContact`, `sysLocation`
- **Interfaces (IF-MIB)** — creates `dcim.Interface` objects with name, type, MAC, MTU, speed, admin/oper status (as `Active`/`Maintenance` status and `enabled`), and `ifAlias` as the description
- **IP addresses (IP-MIB)** — creates `ipam.IPAddress` objects and assigns them to the matching interface
- **VLANs (Q-BRIDGE-MIB)** — creates `ipam.VLAN` objects (ID + name) under a per-device `VLANGroup`
- **Physical inventory (ENTITY-MIB)** — used to populate the Device `serial` number
- **Neighbors (LLDP-MIB / CISCO-CDP-MIB)** — recorded on the `DiscoveryResult` (`neighbors_found`, `discovered_data`); when the remote management IP is available it is captured as `remote_ip`
- **Cables** — the SNMP, Full, and Crawl jobs can link `dcim.Cable` objects between a local interface and the matching remote interface/device (matched by remote management IP or device name + port) whenever both ends are resolvable

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
        "snmp_version": "2c",
        "snmpv3_auth_protocol": "SHA",
        "snmpv3_priv_protocol": "AES",
        "populate_interfaces": True,
        "populate_ip_addresses": True,
        "populate_vlans": True,
        "include_neighbors": True,
        "include_vlans": True,
        "max_walk_oids": 1000,
        "ssh_timeout": 10,
        "ssh_banner_timeout": 30,
        "ssh_port": 22,
        "ssh_port_check": True,
        "ping_timeout": 2,
        "concurrency": 10,
    },
}
```

> **Note:** Credential values (`snmp_community`, `snmpv3_*_key`, `ssh_username`,
> `ssh_password`) are intentionally **not** plugin settings. Provide credentials
> through a `SecretsGroup` assigned to a `DiscoveryProfile` (recommended), or as
> job inputs at run time.

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

Discovers devices via SNMP (v1, v2c, or v3):

1. Navigate to **Jobs > SNMP Discovery**
2. Enter target network
3. Select the SNMP version:
   - **`2c` (default)** — provide the community string
   - **`1`** — same community string, SNMPv1 message format
   - **`3`** — provide the SNMPv3 USM username and, optionally, auth/priv
     protocol and passphrase (noAuth/noPriv, authNoPriv, or authPriv are
     selected automatically based on which keys are supplied) plus an
     optional context name for v3B / context-engine-ID setups
4. Optionally toggle **Populate interfaces**, **Populate IP addresses**, **Include neighbors**, **Populate VLANs**, and **Create cables**
5. Run the job

SNMPv3 auth/priv passphrases are treated as sensitive inputs, so the job
cannot be scheduled or run through an approval workflow. For automated runs,
set `snmp_version` to `"3"` and the SNMPv3 fields in `PLUGINS_CONFIG` instead.

Devices discovered via SNMP are auto-created in Nautobot. Platform identification is done via SNMP OID matching. Interfaces and IP addresses are created from the walked IF-MIB and IP-MIB tables; the Device serial number comes from ENTITY-MIB when available. VLANs are created from the Q-BRIDGE-MIB `dot1qVlanStaticTable` (ID + name) under a per-device `VLANGroup`. In dry-run mode, no objects are created but all walked table data is captured on the `DiscoveryResult` for review.

### SSH Discovery

Discovers devices via SSH:

1. Navigate to **Jobs > SSH Discovery**
2. Enter target network
3. Provide SSH username and password (or leave empty to use plugin config defaults)
4. Optionally set a non-default **SSH port**
5. Run the job

For each reachable host, the job opens a PTY-backed interactive shell, disables
paging, escalates to privileged exec when the login prompt requires it, and runs
vendor-specific identification commands:

- **Cisco** — `show version` + `show inventory`
- **Juniper** — `show version` + `show chassis hardware`
- **Arista / Ubiquiti / EdgeOS** — `show version`
- **HPE Comware** — `display version` + `display device manuinfo`
- **Nokia SR OS** — `show system version` + `show system information`
- **FortiGate** — `get system status`
- **Palo Alto** — `show system info`

Vendor is detected from the login banner and/or the first command response;
unknown vendors fall back to a generic command list. Raw command output is
stored on the `DiscoveryResult` (`discovered_data.command_outputs`) for review,
including in dry-run mode.

> **Recommendation:** Store credentials in Nautobot Secrets (using Environment Variables or Vault provider) and paste the values into the job inputs.

### Full Discovery

Runs all three methods in sequence:

1. Navigate to **Jobs > Full Discovery**
2. Enter target network
3. Configure SNMP version/community (or SNMPv3 USM credentials) and SSH credentials
4. Toggle which methods to enable (ping / SNMP / SSH) and whether to populate interfaces, IP addresses, VLANs, and cables
5. Run the job

The job will:
1. Ping the range to find live hosts
2. Run SNMP on live hosts
3. Run SSH on hosts not identified by SNMP
4. Deduplicate results
5. Create devices in Nautobot
6. Create `dcim.Cable` links from the LLDP/CDP neighbor data (when `create_cables` is enabled)

### Crawl Discovery

Discovers devices iteratively from a seed device using SNMP only:

1. Navigate to **Jobs > Crawl Discovery**
2. Select the **seed device** (a Nautobot `Device`); its primary IP is used, or provide a `seed_ip` override
3. Configure `max_depth` (hops from the seed) and `max_devices` (visit cap)
4. Configure SNMP version/community (or SNMPv3 USM credentials) and toggle populate/include flags, including `create_cables`
5. Run the job

The job performs a breadth-first crawl:
1. Walk the seed device's LLDP/CDP neighbor tables via SNMP
2. Create/update each discovered device and record a `DiscoveryResult`
3. Resolve each neighbor's management IP (`remote_ip`, then reverse-DNS on the neighbor name, then an existing Device's primary IP)
4. Continue crawling from each neighbor's IP, level by level, until `max_depth`, `max_devices`, or the visited set is exhausted
5. Create `dcim.Cable` links from the collected neighbor data when `create_cables` is enabled

A visited set (keyed on IP) plus the depth and device caps keep the crawl finite. The seed device does not need an SNMP walkable primary IP if `seed_ip` is provided.

### DiscoveryProfiles

`DiscoveryProfile` records provide a reusable bundle of scan scope and settings that the SNMP, Full, and Crawl jobs accept via a **Profile** job input:

- `included_ip_prefixes` — CIDR prefixes to scan (used instead of the `target_network` input when present)
- `excluded_ip_prefixes` — CIDR prefixes to skip
- `maximum_ip_addresses` — hard cap on the number of hosts scanned (0 = unlimited); the job aborts with an error when exceeded
- `protocols` — which methods to use (`ping`, `snmp`, `ssh`)
- `ssh_port` / `snmp_port` / `snmp_timeout` / `snmp_retries` — transport settings (profile values take precedence over job defaults)
- `snmpv3_auth_protocol` / `snmpv3_priv_protocol` — default SNMPv3 algorithms
- `fast_path` — skip SSH platform/credential discovery on recurring scans when SNMP identity matches stored state (see Fast Path)
- `strip_domain_suffixes` — domain suffixes stripped from discovered hostnames (case-insensitive, longest match wins, dot boundary required)

### Secrets & Credential Management

Credentials are sourced from Nautobot's native **Secrets** framework. Assign one
or more Secrets Groups to a Discovery Profile (each with a priority **weight**)
via the **Discovery Profile Secrets Groups** UI list or the
`/api/plugins/device-auto-discovery/discovery-profile-secrets-groups/` endpoint.

**SSH credential selection:**

1. Groups are ordered by ascending weight (ties broken by name).
2. The **last known working** group recorded on a `DiscoveredDevice` (from a
   previous successful collection against that IP) is attempted first.
3. Each group's SSH Username/Password secrets are tried in order until
   authentication succeeds.

**SNMP credential selection:**

- Only the **lowest-weight** group that defines SNMP secrets is used, with no
  fallback attempts.
- A group supplies v2c credentials via an SNMP **Token** (community string) or
  v3 credentials via SNMP **Username** + **Password** (auth key) + **Key**
  (priv key). The security level (noAuthNoPriv / authNoPriv / authPriv) is
  derived from which secrets are present.

All secret values are fetched through the secrets **provider** at query time
(Environment Variable, text file, Vault, ...), so nothing sensitive is stored
in the plugin. When no profile secrets group applies, jobs fall back to
explicit job inputs.

### Automated Device Classification

After a scan, devices with status **Not Imported** (`new`) need a Location,
Role, and optionally a Tenant before onboarding. **Classification Rules**
derive those values automatically from device hostnames and/or IP scopes —
no separate job to run, results are recomputed in the background whenever a
scan completes or a rule changes.

A rule describes how to derive a single classification target — Location,
Role, or Tenant — for a Not Imported device:

| Field | Purpose |
|-------|---------|
| **Classify As** | Which device field this rule populates: Location, Role, or Tenant |
| **Weight** | Lower weight = higher priority; the first matching enabled rule per target wins |
| **Source Pattern** | Regex with a named `(?P<value>...)` capture group applied to the hostname (case-insensitive) |
| **Match Against** | The Nautobot model the value is matched against — must be Location, Role, or Tenant |
| **Match Field / Operator** | How the extracted value is compared (e.g. `name` + `iexact`) |
| **Match Filters** | Extra equality filters, e.g. `{"status__name": "Active"}` (max two FK traversals) |
| **IP Scope** | Optional list of prefixes restricting the rule to a subset of devices |
| **Transform** | Optional `lowercase` / `uppercase` applied to the extracted value |

A lookup only produces a classification when it returns **exactly one**
candidate — zero or multiple matches are treated as no match, since
incorrect auto-assignment is worse than none. Classification never modifies
devices or triggers onboarding; it only records suggestions:

1. Create rules under **Devices > Discovery > Classification Rules**
2. Run any discovery job — Not Imported devices are classified automatically
3. Review the **Automated Classification** panel on a device's detail view
   (or enable the Classification columns on the list view) and use the
   suggestions to fill in Location/Role/Tenant when onboarding

Example — classify Location from a site code in hostnames like `ams-core-01`:

| Field | Value |
|-------|-------|
| Classify As | Location |
| Source Pattern | `^(?P<value>[a-z]{2,4})-` |
| Match Against | `dcim.location` |
| Match Field | `name` |
| Match Operator | `iexact` |

### Fast Path

Fast Path optimizes recurring **Full Discovery** scans in mature environments
where devices rarely change. It applies only to the SSH collection phase —
SNMP always runs the same way.

Enable it via the `fast_path` flag on a DiscoveryProfile. After the SNMP
phase, for each host that SSH still needs to cover, the job compares the
SNMP-identified identity against the stored `DiscoveredDevice` record:

| Attribute | Must match stored value? |
|-----------|--------------------------|
| Platform (`network_driver`) | Yes |
| Hostname | Yes |
| Serial number | Yes |

When all three match exactly (case-insensitive), the last SSH collection
succeeded, and a valid last-known-working SSH Secrets Group is on file, the
job **skips platform auto-detection and credential iteration** and collects
SSH data directly with the stored credentials.

**Self-correction:** if the direct collection fails (hardware replaced,
platform migrated, credentials rotated), the job immediately falls back to
full discovery for that host, clears the stored SSH success state, and marks
the issue — so the next run performs full discovery and the device becomes
Fast Path eligible again automatically. No permanent false assumptions, no
manual intervention.

Avoid Fast Path during initial onboarding or frequent credential rotation;
the first successful full run primes the stored state that makes a device
eligible.

### Inventory Correlation

Every discovered IP is recorded as a persistent `DiscoveredDevice` row and matched against the Nautobot inventory using three identifying attributes:

| Correlation status | Meaning |
|--------------------|---------|
| `imported` | Exactly one device matches and all known attributes (primary IP, hostname, serial) agree — no changes made |
| `new` | No matching device exists — auto-created in Nautobot by default |
| `partially_imported` | Exactly one device matches but some attributes differ (e.g. new serial) — flagged for review, not auto-created |
| `conflict` | More than one device matches — flagged for review, not auto-created |

The **Create devices** job input controls auto-creation: when disabled (e.g. profile review mode), `new` devices are recorded but not created. Correlation statuses are persisted on the `DiscoveredDevice` record and mirrored onto the `DiscoveryResult` (`new` / `existing` / `partial` / `conflict`).

### API Usage

Jobs can also be triggered via the REST API:

```bash
curl -X POST \
  -H "Authorization: Token $TOKEN" \
  -H "Content-Type: application/json" \
  http://nautobot/api/extras/jobs/nautobot_plugin_device_auto_discovery.PingSweep/run/ \
  --data '{"data": {"target_network": "10.0.0.0/24"}}'
```

The plugin also exposes its own REST API under `/api/plugins/device-auto-discovery/`:

| Endpoint | Model |
|----------|-------|
| `/discovery-scans/` | `DiscoveryScan` — one row per scan run |
| `/discovery-results/` | `DiscoveryResult` — one row per host per scan |
| `/discovery-profiles/` | `DiscoveryProfile` — reusable scan-scope bundles |
| `/discovered-devices/` | `DiscoveredDevice` — per-IP correlation ledger |
| `/discovery-profile-secrets-groups/` | `DiscoveryProfileSecretsGroupAssignment` — weighted credentials per profile |
| `/classification-rules/` | `DeviceClassificationRule` — hostname/IP-scope → Location/Role/Tenant rules |
| `/discovered-device-classifications/` | `DiscoveredDeviceClassification` — computed classification results |

Each endpoint supports the standard Nautobot queryset actions (list, retrieve, create,
update, delete) and is searchable via the `q` parameter.

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
| `snmp_version` | `"2c"` | SNMP version: `"1"`, `"2c"`, or `"3"` (USM) |
| `snmpv3_auth_protocol` | `"SHA"` | SNMPv3 auth protocol: `noAuth`, `MD5`, `SHA`, `SHA-256`, `SHA-384`, `SHA-512` |
| `snmpv3_priv_protocol` | `"AES"` | SNMPv3 privacy protocol: `noPriv`, `DES`, `3DES`, `AES`, `AES-192`, `AES-256` |
| `populate_interfaces` | `True` | Create `dcim.Interface` objects from IF-MIB |
| `populate_ip_addresses` | `True` | Create/assign `ipam.IPAddress` objects from IP-MIB |
| `populate_vlans` | `True` | Create `ipam.VLAN` objects from Q-BRIDGE-MIB |
| `include_neighbors` | `True` | Walk LLDP/CDP neighbor tables |
| `include_vlans` | `True` | Walk the Q-BRIDGE-MIB VLAN table |
| `max_walk_oids` | `1000` | Cap on rows walked per MIB table |
| `ssh_timeout` | `10` | SSH connection timeout in seconds |
| `ssh_banner_timeout` | `30` | SSH banner wait timeout in seconds |
| `ssh_port` | `22` | SSH port used for discovery |
| `ssh_port_check` | `True` | TCP-port-check the host before attempting the SSH handshake |
| `ssh_enable_password` | `""` | Enable password used when a device requires privilege escalation |
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
