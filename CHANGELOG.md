# Release Notes

## v1.1.5 - 2026-09

### Fixed

- **Onboarding/Run-Discovery submission crashed with
  `NoReverseMatch: 'jobresult_detail'`** after successfully enqueueing the
  job. Nautobot 3.2.2 has no `jobresult_detail` route; the correct detail
  route name is `extras:jobresult`. Both redirect targets updated.

## v1.1.4 - 2026-09

### Fixed

- **Onboard form and Run Discovery form pages returned 500**
  (`AttributeError: 'NoneType' object has no attribute '_meta'`). The two
  action templates extended `generic/object_detail.html`, whose parent
  template dereferences an `object` context variable that these standalone
  action pages do not provide (`object|validated_viewname:"list"` on None).
  Both templates now extend `base_django.html` directly.

## v1.1.3 - 2026-09

### Fixed

- **Row-selection checkboxes were missing on all list views** (e.g. the
  "Onboard Selected Devices" action could never find selected devices).
  Nautobot requires each list table to declare `pk = ToggleColumn()`; the
  plugin's tables did not, so no checkboxes were rendered. Added the toggle
  column to DiscoveryScan, DiscoveryResult, DiscoveryProfile,
  DiscoveredDevice, and DeviceClassificationRule tables.

## v1.1.2 - 2026-09

### Fixed

- Discovery Profile form now accepts **comma-separated** values for
  `included_ip_prefixes` / `excluded_ip_prefixes` / `protocols` /
  `strip_domain_suffixes` (and the classification rule's IP Scope) instead of
  requiring strict JSON — e.g. `192.168.1.0/24, 10.0.0.0/8`. JSON arrays and
  `['...']` shorthand are also accepted, and stored values render back as
  plain comma-separated text when editing. Invalid prefixes are rejected with
  a clear message.

## v1.1.1 - 2026-09

### Fixed

- **`TypeError: 'NoneType' object is not callable` on every plugin list view**
  (Discovery Profiles, Discovered Devices, etc.). Nautobot's
  `saved_view_modal` template tag resolves the model's FilterSet via
  `get_filterset_for_model`, which requires a top-level `filters.py` module
  with `{Model}FilterSet` classes. The plugin only defined filtersets in
  `api/filtersets.py`, so the lookup returned `None` and `None()` raised.
  Added the expected `filters` module re-exporting all filtersets.

## v1.1.0 — 2026-09

### Added

- **Sync Discovered Devices From Network** job — refreshes already-known
  DiscoveredDevices by re-querying them over SNMP (then SSH), without
  scanning for new hosts. Supports correlation-status filters, profile-scoped
  selection (prefixes + Secrets Group credentials), Fast-Path-style SSH
  preference for the stored last-known-working group, and dry-run.
- `sync` scan method on `DiscoveryScan` (migration 0011).
- Release notes and compatibility matrix documentation.

## v1.0.0 — 2026-09

### Breaking changes

- **Job consolidation**: the standalone **Ping Sweep**, **SNMP Discovery**,
  **SSH Discovery**, and **Full Discovery** jobs were removed. Only four jobs
  are registered now: **Network Device Discovery**, **Sync Discovered Devices
  From Network** (added in 1.1.0), **Crawl Discovery**, and **VRF & Route
  Discovery**. Single-protocol discovery is a Discovery Profile with e.g.
  `protocols: ["snmp"]`. Delete any scheduled jobs referencing the removed
  classes before upgrading; `post_upgrade` removes their Job rows.

### Added (since 0.3.4)

- **Secrets integration** (0.4.0): weighted Secrets Groups per Discovery
  Profile; SSH retry in weight order with last-known-working group persisted
  per device; SNMP uses the lowest-weight group only; SNMPv3 security levels
  derived from the secrets present. Credential settings removed from
  `PLUGINS_CONFIG`.
- **Automated device classification** (0.5.0): `DeviceClassificationRule` +
  `DiscoveredDeviceClassification` models, regex/`(?P<value>...)` extraction
  from hostnames with optional IP scope, weight-ordered per target
  (Location/Role/Tenant), exactly-one-match semantics, automatic
  recomputation via signals, UI panel and REST API.
- **Fast Path** (0.6.0): recurring Network Device Discovery runs skip SSH
  platform/credential discovery when SNMP identity matches stored state
  (platform/hostname/serial); automatic self-correction clears SSH state on
  failure.
- **Bulk onboarding** (0.7.0): "Onboard Selected Devices" action on the
  Discovered Devices list; `OnboardDiscoveredDevicesJob` fills
  Location/Role/Tenant from classification results with optional defaults.
- **Scale knobs** (0.8.0): `snmp_engine_batch_size` SNMP engine batching,
  per-phase concurrency inputs (TCP/SNMP/SSH), `soft_time_limit` /
  `time_limit` plugin settings, `netaddr` dependency declared.
- **Consolidated job + Run buttons** (0.9.0): `NetworkDeviceDiscoveryJob`
  (profile-first, protocols-driven phases) and a **Run Device Discovery**
  button on profile detail pages.
- **Platform expansion** (0.10.0): Aruba AOS-CX / ArubaOS / Instant, Cisco
  WLC (AireOS + 9800), Brocade/Ruckus FastIron — SNMP OID mappings, SSH
  command profiles, and VRF/IP/route collectors.
- **Status tabs** (0.11.0): Discovered Devices list tabs (Imported / New /
  Conflicts / Not Reachable / Failed / All) with live counts.
- **Fix** (0.11.1): the `secrets_groups` M2M no longer appears in profile
  filterset/form/table/detail fields — the auto-generated M2M filter broke
  the Nautobot 3.2.2 list view (`TypeError: 'NoneType' object is not
  callable`). Manage assignments via the assignments list view or REST API.

## v0.3.4 and earlier

See the git history; the plugin supported SNMP/SSH discovery, Discovery
Profiles, inventory correlation, crawl discovery, and cable linking.
