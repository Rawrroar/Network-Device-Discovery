# nautobot-plugin-device-auto-discovery

A [Nautobot](https://nautobot.com/) App for automatic network device discovery via ICMP ping sweep, SNMP, and SSH.

## Overview

This plugin discovers network devices on your IP ranges and maintains accurate inventory in Nautobot. Discovery is driven by a **Discovery Profile** that defines scan scope, protocols (`ping` / `snmp` / `ssh`), and credentials; the consolidated **Network Device Discovery** job executes the phases and correlates the results against your inventory.

## Features

- Auto-creates `Manufacturer`, `DeviceType`, and `Platform` objects when not found
- Tracks discovery history via `DiscoveryScan` and `DiscoveryResult` models
- Configurable defaults for device location, role, status, and tags
- Threaded/concurrent scanning for fast results
- Dry-run mode
- **Network Device Discovery** — one consolidated, profile-first job: pick a Discovery Profile and the scan scope, protocols, credentials, and Fast Path all come from the profile. Launch it from the profile's **Run Device Discovery** button.
- **Cable linking** — creates `dcim.Cable` objects from LLDP/CDP neighbor data when both ends can be resolved
- **Crawl Discovery** — iteratively discovers devices from a seed device by following LLDP/CDP neighbors hop by hop
- **DiscoveryProfiles** — reusable scan-scope and settings (prefixes, exclusions, IP cap, ports, timeouts, domain stripping) applied to the SNMP, Full, and Crawl jobs
- **Secrets-based credentials** — SSH and SNMP credentials resolved from weighted Secrets Groups assigned to a profile; the last-known-working SSH group is remembered per device, and SNMPv3 security levels are derived from the secrets present (no credentials in `PLUGINS_CONFIG`)
- **Automated classification** — weighted rules map hostname patterns and IP scopes to Location/Role/Tenant for Not Imported devices, recomputed automatically after scans and rule changes
- **Fast Path** — recurring Full Discovery runs skip SSH platform/credential discovery for devices whose SNMP identity matches stored state, with automatic self-correction on failure
- **Bulk onboarding** — select Not Imported devices and onboard them as Nautobot Devices in one action, with Location/Role/Tenant filled from classification results and optional defaults
- **Scales to large prefixes** — SNMP engine batching bounds peak memory on huge scan surfaces; per-phase concurrency knobs (TCP / SNMP / SSH) and configurable Celery time limits
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

## Compatibility Matrix

| Plugin version | Nautobot versions | Python | Status |
|----------------|-------------------|--------|--------|
| 1.1.x | 3.0 – 3.2.x | 3.9 – 3.12 | Supported |
| 1.0.0 | 3.0 – 3.2.x | 3.9 – 3.12 | Supported (superseded by 1.1.0) |
| 0.4 – 0.11 | 3.0 – 3.2.x | 3.9 – 3.12 | EOL |
| 0.3.x and earlier | 3.0 – 3.1 | 3.9+ | EOL |

Databases: PostgreSQL or MySQL (SQLite is not supported by Nautobot).
The app follows Nautobot's deprecation policy: plugin versions are supported
for the lifetime of the Nautobot minor versions listed above.

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

The plugin provides **five jobs**:

| Job | Purpose |
|-----|---------|
| **Network Device Discovery** | The consolidated, profile-first discovery job (ping → SNMP → SSH phases driven by a Discovery Profile). |
| **Sync Discovered Devices From Network** | Refresh already-known discovered devices (no new discovery): re-query over SNMP, then SSH, updating records and correlation status. |
| **Onboard Discovered Devices** | Create Nautobot Devices from selected Not Imported discovered devices. |
| **Crawl Discovery** | Iteratively discover devices from a seed device by following LLDP/CDP neighbors. |
| **VRF & Route Discovery** | Extract VRFs, route prefixes, and IP addresses into IPAM. |

> **Breaking change (1.0.0):** the standalone **Ping Sweep**, **SNMP Discovery**,
> **SSH Discovery**, and **Full Discovery** jobs were removed. Their engines live
> on inside Network Device Discovery — use a Discovery Profile with
> `protocols: ["snmp"]` or `["ssh"]` to reproduce the old single-protocol jobs.
> Delete any scheduled jobs referencing the removed classes before upgrading.

### Network Device Discovery

The consolidated, profile-first discovery job:

1. Create a **Discovery Profile** (prefixes, protocols, credentials, Fast Path)
2. Open the profile and click **Run Device Discovery**, or run **Jobs > Network Device Discovery** and select the profile
3. The profile's `protocols` list drives the phase selection — `ping`, `snmp`, and/or `ssh`
4. Optionally tick **Dry-run** first to preview what would be discovered

Phase behavior:

1. **Ping Sweep** — find live hosts (ICMP, falling back to TCP probes; skipped when `ping` is not in the profile protocols)
2. **SNMP Discovery** — for live hosts, walk the system scalars plus IF-MIB, IP-MIB, Q-BRIDGE-MIB, ENTITY-MIB, and LLDP/CDP tables. SNMPv1/v2c community or v3 USM (noAuthNoPriv / authNoPriv / authPriv derived from the supplied secrets). Interfaces and IP addresses are created from the walked tables; the Device serial comes from ENTITY-MIB; VLANs are created under a per-device `VLANGroup`.
3. **SSH Discovery** — for hosts not identified by SNMP, open a PTY-backed shell, disable paging, escalate to privileged exec when required, and run vendor-specific identification commands:

- **Cisco** — `show version` + `show inventory`
- **Cisco WLC** — `show sysinfo`
- **Juniper** — `show version` + `show chassis hardware`
- **Arista / Ubiquiti / EdgeOS** — `show version`
- **Aruba (AOS-CX/ArubaOS)** — `show version` + `show system`
- **HPE Comware** — `display version` + `display device manuinfo`
- **Brocade/Ruckus FastIron** — `show version` + `show chassis`
- **Nokia SR OS** — `show system version` + `show system information`
- **FortiGate** — `get system status`
- **Palo Alto** — `show system info`

Vendor is detected from the login banner and/or the first command response;
unknown vendors fall back to a generic command list. Raw command output is
stored on the `DiscoveryResult` (`discovered_data.command_outputs`) for review,
including in dry-run mode.

Then all discovered devices are deduplicated, correlated, and created
(Manufacturer/DeviceType/Platform auto-created when missing), and
`dcim.Cable` links are made from LLDP/CDP neighbor data (when `create_cables`
is enabled).

### Sync Discovered Devices From Network

A refresh job for devices Nautobot **already knows about** — the recurring
companion to discovery:

1. Run **Jobs > Sync Discovered Devices From Network**
2. Optionally select a Discovery Profile (bounds the sync to its prefixes and
   supplies Secrets Group credentials) and/or narrow by correlation status
3. Optionally tick **Dry-run**

For each selected device the job attempts SNMP first, then SSH (preferring
the device's stored last-known-working Secrets Group). Records, correlation
status, and per-protocol collection timestamps are updated in place — **no
new DiscoveredDevice rows are ever created**. A device that answers neither
protocol is marked Not Reachable; a stored-credentials SSH failure clears the
stored SSH state so the next run re-discovers (Fast Path self-correction).

Schedule discovery + sync together: discovery finds what changed on the
network; sync keeps known devices fresh between scans.

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

- `included_ip_prefixes` — CIDR prefixes to scan, comma-separated in the UI (e.g. `192.168.1.0/24, 10.0.0.0/8`; JSON lists also accepted)
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

### Onboarding Discovered Devices

Devices marked **Not Imported** can be onboarded directly from the discovery
results:

1. Select the device(s) on the **Discovered Devices** list view
2. Click **Onboard Selected Devices**
3. In the form, only the defaults are optional when **Fill From
   Classification** is enabled: each device's Location, Role, and Tenant come
   from its Automated Classification results, falling back to the Default
   Location / Role / Tenant you provide. Disable it to apply the defaults to
   every device (Default Location and Default Role are then required).
4. Submit — the **Onboard Discovered Devices** job creates the Device records
   and links them back to their `DiscoveredDevice` entries

The onboarding job can also be run (or scheduled) directly from **Jobs**:
it takes the same parameters plus a comma-separated list of DiscoveredDevice
IDs. Only Not Imported devices are onboarded; already-matched devices are
skipped, and a device that already exists in Nautobot (matched by primary IP,
hostname, or serial) is linked rather than duplicated.

### Fast Path

Fast Path optimizes recurring **Network Device Discovery** scans in mature environments
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

### Scanning Large Prefixes

Discovery Profiles can target very large scan surfaces (e.g. multiple /16
prefixes). To keep worker memory bounded, SNMP discovery runs in **batches**:
a configurable number of IPs is probed per pysnmp engine cycle before moving
on to the next batch, so peak memory scales with the batch size rather than
the total scan surface.

Relevant controls:

| Control | Where | Notes |
|---------|-------|-------|
| `snmp_engine_batch_size` | `PLUGINS_CONFIG` (default `1000`) | IPs per engine cycle; `0` disables batching. Effective SNMP concurrency is capped at this value — keep it ≥ SNMP scan concurrency. |
| **SNMP Scan Concurrency** | per-job (SNMP/Full) | Concurrent SNMP probes; falls back to the generic concurrency input. |
| **TCP Scan Concurrency** | per-job (Full) | Concurrent ping probes in Phase 1. |
| **SSH Login Concurrency** | per-job (Full) | Concurrent SSH logins in Phase 3. |
| **Maximum IP Addresses** | per-profile | Safety cap on scan-surface size. |

Tuning guidance for `snmp_engine_batch_size`:

| Scenario | Suggested value |
|----------|-----------------|
| Small scans (≤ /22) | default `1000` (effectively a single batch) |
| Medium scans (/16) | `500`–`2000` |
| Large scans (multiple /16s) | keep at `1000` or lower |
| Memory-constrained workers | `250`–`500` (caps peak memory, more engine-recycle overhead) |

### Celery Time Limits

Long-running discovery jobs honor two plugin settings (seconds):

| Setting | Default | Meaning |
|---------|---------|---------|
| `soft_time_limit` | `3600` | Raises `SoftTimeLimitExceeded` inside the job so it can fail gracefully. |
| `time_limit` | `3900` | Hard backstop; the worker is forcibly terminated. Must be > `soft_time_limit`. |

Changes take effect after `nautobot-server post_upgrade` (jobs are
re-registered). Per-job Time Limit overrides in the Nautobot UI take
precedence over these settings.

### Inventory Correlation

Every discovered IP is recorded as a persistent `DiscoveredDevice` row and matched against the Nautobot inventory using three identifying attributes:

| Correlation status | Meaning |
|--------------------|---------|
| `imported` | Exactly one device matches and all known attributes (primary IP, hostname, serial) agree — no changes made |
| `new` | No matching device exists — auto-created in Nautobot by default |
| `partially_imported` | Exactly one device matches but some attributes differ (e.g. new serial) — flagged for review, not auto-created |
| `conflict` | More than one device matches — flagged for review, not auto-created |

The **Create devices** job input controls auto-creation: when disabled (e.g. profile review mode), `new` devices are recorded but not created. Correlation statuses are persisted on the `DiscoveredDevice` record and mirrored onto the `DiscoveryResult` (`new` / `existing` / `partial` / `conflict`).

The **Discovered Devices** list view groups records into status tabs —
**Imported**, **New**, **Conflicts** (Partially Imported + Conflict),
**Not Reachable**, **Failed**, and **All** — each with a live count, so
devices needing attention are immediately visible. The active tab can be
combined with the standard search and filter controls.

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
| Cisco | IOS, IOS-XE, IOS-XR, NX-OS, SD-WAN vEdge, WLC AireOS, WLC 9800 (IOS-XE) |
| Juniper | Junos |
| Arista | EOS |
| HPE | Comware, ProCurve |
| Aruba (HPE) | AOS-CX, ArubaOS, Instant |
| Brocade / Ruckus | FastIron (ICX) |
| Nokia | SR OS, SR Linux |
| F5 | TMOS |
| Palo Alto | PAN-OS |
| Fortinet | FortiOS |
| Ubiquiti | EdgeOS, airOS, EdgeMAX, UniFi |

For SSH-discovered devices, vendor detection is done via keyword matching on command output. SSH identification commands, parsers, and VRF/IP/route collectors are available for all of the above (Aruba AOS-CX and Brocade FastIron use Cisco-like `show ip interface brief` / `show ip route` collectors).

The SNMP and SSH platform coverage matrix (which attribute is collected per platform, with stability markers) follows the same platforms as the Nautobot Device Discovery app; treat mappings for the 🧪-class platforms (Nokia, ArubaOS, WLC, FastIron) as best-effort community coverage.

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
| `concurrency` | `10` | Max concurrent probes (fallback for protocol-specific knobs) |
| `snmp_engine_batch_size` | `1000` | IPs per SNMP engine cycle (`0` = unbatched); caps effective SNMP concurrency |
| `soft_time_limit` | `3600` | Celery soft time limit (seconds) for discovery jobs |
| `time_limit` | `3900` | Celery hard time limit (seconds); must exceed `soft_time_limit` |

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
