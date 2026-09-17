# AGENTS.md — nautobot-plugin-device-auto-discovery

## Job surface (since 1.1.0)

Five jobs are registered: `NetworkDeviceDiscoveryJob`, `SyncDiscoveredDevicesJob`, `OnboardDiscoveredDevicesJob`, `CrawlDiscoveryJob`, `VRFRouteDiscoveryJob`. `PingSweepJob`, `SNMPDiscoveryJob`, `SSHDiscoveryJob` were hard-deleted; `FullDiscoveryJob` remains as the unregistered engine base class (importable, not in `register_jobs`). Do not re-register the removed jobs; single-protocol discovery = profile with `protocols: ["snmp"]` etc. Tests that ran removed jobs now go through `NetworkDeviceDiscoveryJob` with profiles (`_ConsolidatedJobTestMixin` in test_discovery.py). `SyncDiscoveredDevicesJob` refreshes known DiscoveredDevices only — it must never create new DiscoveredDevice rows (uses `finalize_discovery` with `auto_create=False`).

## Nautobot v3.x Gotchas (already fixed, easy to regress)

- **Role import**: `from nautobot.extras.models import Role` — NOT `dcim.models` (moved in v3.x)
- **Role has no `status` field** — never set `status` on Role objects in jobs.py or tests
- **Migration dependencies**: dcim `0097_virtualdevicecontext_controller_managed_device_group`, extras `0145_objectmetadata_assigned_object_type_cascade`
- **PrimaryModel migrations**: every `CreateModel` MUST include `_custom_field_data = models.JSONField(encoder=django.core.serializers.json.DjangoJSONEncoder, blank=True, default=dict)` — inherited but Django does NOT auto-add it to migrations
- **No `bases` in migrations**: Django auto-infers `PrimaryModel` inheritance; never set `bases = [...]` in migration operations
- **PrimaryModel pk is a UUID**: never hand-define `("id", models.BigAutoField(...))` in a migration — every INSERT then fails with `column "id" is of type bigint but expression is of type uuid`. Correct pattern (see 0001): `("id", models.UUIDField(primary_key=True, serialize=False))`. To convert an already-created table, add RemoveField/AddField for `id` (see migration 0007).
- **Job `StringVar` defaults to `required=True`** (`nautobot.extras.jobs`): any field the custom run template may hide (e.g. SNMPv3 fields in v2c mode) MUST be `required=False`, otherwise the browser silently blocks submit with "form control ... is not focusable" and "Run Job Now" appears to do nothing.
- **`ip_address` / inet fields**: do not filter `ipam.IPAddress.host` (or other inet/cidr columns) with `icontains` — it raises a `FieldError`. Use `filter(host=...)` or exact matching (see correlation.py:24).

## Package / Environment

- `pysnmp>=4.4` (README and pyproject.toml agree)
- Python >= 3.9, Nautobot >= 3.0, < 4.0
- No `[project.optional-dependencies]` or dev tool config in pyproject.toml

## Tests

```bash
coverage run -m pytest tests/
coverage report
```

Test fixtures in `tests/test_discovery.py` also set `status` on `Role` objects — fix the same way as jobs.py (remove `status` from Role `defaults`/`create` calls).

## Migrations

If tables are dropped but the migration record persists in `django_migrations`, the migration appears "already applied" but tables don't exist. Fix:

```sql
DELETE FROM django_migrations WHERE app = 'nautobot_plugin_device_auto_discovery';
```

Then re-run `nautobot-server migrate nautobot_plugin_device_auto_discovery`.

## Architecture

- Single package: `nautobot_plugin_device_auto_discovery/`
- Jobs auto-register via `ready()` import → `register_jobs()`
- OID → platform mapping in `mappings.py` (static table, prefix matching)
- Models: `DiscoveryScan`, `DiscoveryResult`, `DiscoveryProfile`, `DiscoveredDevice` (all `PrimaryModel`), plus `DiscoveryProfileSecretsGroupAssignment` and `DiscoveredDeviceClassification` (plain Nautobot `BaseModel` — no created/last_updated/_custom_field_data; matches core `SecretsGroupAssociation`) and `DeviceClassificationRule` (PrimaryModel). `contenttypes` must be a migration dependency for models with GenericForeignKey-style ContentType FKs.
- Credentials come from Secrets Groups assigned to profiles (`secrets.py`: weighted SSH retry with last-known-working group on `DiscoveredDevice.ssh_secrets_group`; SNMP uses lowest-weight group only). Never put credentials in `DEFAULT_PLUGINS_CONFIG`.
- Classification engine in `classification.py` (rules → Location/Role/Tenant for `new` devices); auto-recompute via `signals.py` registered in `ready()`. Model imports for targets must be `nautobot.dcim.models.Location` style, not `dcim.models.Location`.
- Fast Path (`fast_path` on DiscoveryProfile, `FullDiscoveryJob` engine): eligibility = SNMP identity (platform/hostname/serial, case-insensitive) matches pre-scan snapshot of `DiscoveredDevice` + prior `ssh_collection` + stored `ssh_secrets_group`; snapshot state BEFORE phase 2 since `finalize_discovery` overwrites records. On failure: `mark_fast_path_failure` clears SSH state and the job falls back to full candidate list immediately.
- Onboarding: `OnboardDiscoveredDevicesJob` + `@action onboard` on `DiscoveredDeviceUIViewSet` (GET form / POST enqueues job via `JobResult.enqueue_job`). Custom UIViewSet action URL names use underscore format: `discovereddevice_onboard` (not `-onboard`). List-view button comes from the plugin's `discovereddevice_list.html` template override of the `bulk_buttons` block.
- Scale knobs: `snmp_engine_batch_size` (0 = unbatched) drives `_iter_snmp_batches`/`_run_snmp_scan_batches` in jobs.py — SNMP job scans via batch function, Full job phase 2 iterates batches each with its own bounded ThreadPoolExecutor. Effective SNMP concurrency = min(snmp_concurrency, batch_size). `soft_time_limit`/`time_limit` plugin settings are applied to job class attrs by `_apply_configured_time_limits()` at import time (takes effect after post_upgrade).
- Consolidated job: `NetworkDeviceDiscoveryJob` subclasses `FullDiscoveryJob` (inherits all vars), requires a profile, and forces phase toggles from `profile.protocols`. Job subclasses MUST redefine `Meta` fully (Nautobot's `_get_meta_attr` reads `cls.Meta` without merging). Run-Discovery is a detail `@action` (`discoveryprofile_run-discovery`) so a UI-framework `Button(link_name=...)` can reverse it with pk kwargs.
- Platform mappings: `VENDOR_KEYWORDS` dict order matters — Cisco WLC entry precedes generic `cisco` so AireOS banners don't resolve to plain Cisco. SSH parser regexes MUST contain a capture group (no group → `_parse_ssh_output` falls back to `match.group(0)`, the whole line). `ssh_parsing` has aruba/brocade branches keyed on `show ip interface brief` (AOS-CX cidr-style + FastIron plain-style with space-containing interface names like `ve 1`) and `show run vrf` (top-level `vrf <name>` config lines only).
- Status tabs: `DiscoveredDeviceUIViewSet.STATUS_TABS` + `filter_queryset` maps `?tab=` to `status__in` (conflicts tab = partially_imported + conflict). Tab nav is in the plugin's `discovereddevice_list.html` override of the `table` block using `view.status_tab_definitions` (preserves other GET params) and `view.discovered_device_tab_counts|get_item:...` (`helpers` templatetag).
- Top-level `filters.py` is REQUIRED: Nautobot's `saved_view_modal` templatetag (rendered on every list view) calls `get_filterset_for_model(model)` -> `{Model}FilterSet` from the app's `filters` module; missing module -> `None()` -> `TypeError: 'NoneType' object is not callable` on ALL plugin list pages. It re-exports `api/filtersets.py`. Same convention applies to `tables.py` and `forms.py` class names (`{Model}Table`, `{Model}Form`).
- Custom M2M (`DiscoveryProfile.secrets_groups` through `DiscoveryProfileSecretsGroupAssignment`) must NOT appear in: filterset `Meta.fields` (auto M2M filter breaks the list-view dynamic filter form — Nautobot 3.2.2 renders it as `TypeError: 'NoneType' object is not callable`), the filter form, the table `Meta.fields`, or detail `ObjectFieldsPanel.fields`. It IS exposed via the REST API and the assignments list view — manage it there.
- REST API in `api/` (`NautobotModelViewSet` + `OrderedDefaultRouter`) mounted at `/api/plugins/device-auto-discovery/`; filtersets are `NautobotFilterSet` + `SearchFilter`
- UI viewsets/tables implemented in `views.py`/`tables.py`
- No external services required; uses `pysnmp` + `paramiko` at runtime

## Deploy

- Build wheel: `python -m pip wheel . -w dist --no-deps` (`python -m build` is shadowed by the local `build/` dir; delete `build/` first)
- Server: `pip install --upgrade dist/<wheel>`, `nautobot-server migrate nautobot_plugin_device_auto_discovery`, restart worker
