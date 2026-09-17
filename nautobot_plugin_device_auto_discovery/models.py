"""Django models for the Device Auto-Discovery plugin."""

import django.core.serializers.json

from django.db import models
from nautobot.apps.models import BaseModel, PrimaryModel


class DiscoveryScan(PrimaryModel):
    """Represents a single discovery scan run."""

    class ScanMethod(models.TextChoices):
        PING = "ping", "ICMP Ping Sweep"
        SNMP = "snmp", "SNMP Discovery"
        SSH = "ssh", "SSH Discovery"
        FULL = "full", "Full Discovery (Ping + SNMP + SSH)"
        CRAWL = "crawl", "Crawl Discovery (seed device + neighbors)"
        VRF = "vrf", "VRF & Route Discovery"
        SYNC = "sync", "Sync Discovered Devices From Network"

    name = models.CharField(
        max_length=100,
        help_text="Display name for this scan.",
    )
    scan_method = models.CharField(
        max_length=10,
        choices=ScanMethod.choices,
        help_text="The discovery method used.",
    )
    target_network = models.GenericIPAddressField(
        protocol="both",
        unpack_ipv4=False,
        null=True,
        blank=True,
        help_text="The target IP range in CIDR notation (e.g., 10.0.0.0/24).",
    )
    status = models.CharField(
        max_length=30,
        default="pending",
        choices=[
            ("pending", "Pending"),
            ("running", "Running"),
            ("completed", "Completed"),
            ("failed", "Failed"),
        ],
    )
    devices_discovered = models.PositiveIntegerField(
        default=0,
        help_text="Number of devices discovered in this scan.",
    )
    devices_created = models.PositiveIntegerField(
        default=0,
        help_text="Number of new Device objects created in Nautobot.",
    )
    cables_created = models.PositiveIntegerField(
        default=0,
        help_text="Number of dcim.Cable objects created from neighbor data.",
    )
    seed_device = models.ForeignKey(
        "dcim.Device",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="crawl_scans",
        help_text="Seed device for crawl discovery scans.",
    )
    error_message = models.TextField(
        blank=True,
        default="",
        help_text="Error message if the scan failed.",
    )

    class Meta:
        ordering = ["-created"]

    def __str__(self):
        return f"{self.name} ({self.get_scan_method_display()})"


class DiscoveryResult(PrimaryModel):
    """Represents a single device discovered during a scan."""

    class ResultStatus(models.TextChoices):
        NEW = "new", "New (created in Nautobot)"
        EXISTING = "existing", "Already exists in Nautobot"
        PARTIAL = "partial", "Partially matches an existing record"
        CONFLICT = "conflict", "Conflicts with existing record"
        FAILED = "failed", "Failed to process"

    scan = models.ForeignKey(
        DiscoveryScan,
        on_delete=models.CASCADE,
        related_name="results",
        help_text="The discovery scan this result belongs to.",
    )
    ip_address = models.GenericIPAddressField(
        protocol="both",
        unpack_ipv4=False,
        help_text="IP address of the discovered device.",
    )
    hostname = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Device hostname.",
    )
    vendor = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="Device vendor/manufacturer.",
    )
    model = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Device model.",
    )
    serial_number = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="Device serial number.",
    )
    os_version = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Operating system / software version.",
    )
    platform_name = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="Inferred Nautobot Platform name.",
    )
    discovery_method = models.CharField(
        max_length=10,
        choices=[("snmp", "SNMP"), ("ssh", "SSH"), ("ping", "Ping")],
        help_text="Which method discovered this device.",
    )
    result_status = models.CharField(
        max_length=10,
        choices=ResultStatus.choices,
        default=ResultStatus.NEW,
        help_text="Whether the device was new, existing, or conflicting.",
    )
    nautobot_device = models.ForeignKey(
        "dcim.Device",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="discovery_results",
        help_text="The Nautobot Device object, if created or matched.",
    )
    sys_location = models.CharField(
        max_length=200,
        blank=True,
        default="",
        help_text="SNMP sysLocation value.",
    )
    sys_contact = models.CharField(
        max_length=200,
        blank=True,
        default="",
        help_text="SNMP sysContact value.",
    )
    interfaces_found = models.PositiveIntegerField(
        default=0,
        help_text="Number of interfaces discovered via SNMP.",
    )
    ip_addresses_found = models.PositiveIntegerField(
        default=0,
        help_text="Number of IP addresses discovered via SNMP.",
    )
    vrfs_found = models.PositiveIntegerField(
        default=0,
        help_text="Number of VRFs discovered via SNMP (MPLS-VPN-MIB / CISCO-VRF-MIB).",
    )
    neighbors_found = models.PositiveIntegerField(
        default=0,
        help_text="Number of LLDP/CDP neighbors discovered via SNMP.",
    )
    vlans_found = models.PositiveIntegerField(
        default=0,
        help_text="Number of VLANs discovered via SNMP (Q-BRIDGE-MIB).",
    )
    discovered_data = models.JSONField(
        encoder=django.core.serializers.json.DjangoJSONEncoder,
        blank=True,
        default=dict,
        help_text="Raw MIB table data captured during SNMP discovery.",
    )
    error_message = models.TextField(
        blank=True,
        default="",
        help_text="Error details if discovery or creation failed.",
    )

    class Meta:
        ordering = ["-created"]

    def __str__(self):
        return f"{self.hostname or self.ip_address} ({self.result_status})"


class DiscoveryProfile(PrimaryModel):
    """Reusable configuration for device discovery runs."""

    name = models.CharField(
        max_length=200,
        unique=True,
        help_text="Unique name for this discovery profile.",
    )
    description = models.CharField(
        max_length=500,
        blank=True,
        default="",
        help_text="Human-friendly description of this profile.",
    )
    included_ip_prefixes = models.JSONField(
        encoder=django.core.serializers.json.DjangoJSONEncoder,
        blank=True,
        default=list,
        help_text="List of CIDR prefixes to scan (e.g., ['10.0.0.0/24']).",
    )
    excluded_ip_prefixes = models.JSONField(
        encoder=django.core.serializers.json.DjangoJSONEncoder,
        blank=True,
        default=list,
        help_text="List of CIDR prefixes to exclude from scanning.",
    )
    maximum_ip_addresses = models.PositiveIntegerField(
        default=0,
        help_text="Maximum number of IP addresses this profile may scan (0 = unlimited).",
    )
    protocols = models.JSONField(
        encoder=django.core.serializers.json.DjangoJSONEncoder,
        blank=True,
        default=list,
        help_text="Protocols to use: 'ping', 'snmp', 'ssh'.",
    )
    ssh_port = models.PositiveIntegerField(
        default=22,
        help_text="SSH port to use for ssh protocols.",
    )
    snmp_port = models.PositiveIntegerField(
        default=161,
        help_text="SNMP port to use for snmp protocols.",
    )
    snmp_timeout = models.PositiveIntegerField(
        default=5,
        help_text="SNMP timeout in seconds per host.",
    )
    snmp_retries = models.PositiveIntegerField(
        default=0,
        help_text="Number of SNMP retries per host.",
    )
    snmpv3_auth_protocol = models.CharField(
        max_length=50,
        blank=True,
        default="SHA",
        help_text="Default SNMPv3 authentication protocol.",
    )
    snmpv3_priv_protocol = models.CharField(
        max_length=50,
        blank=True,
        default="AES",
        help_text="Default SNMPv3 privacy protocol.",
    )
    fast_path = models.BooleanField(
        default=False,
        help_text="Use the Fast Path method to speed up scans.",
    )
    strip_domain_suffixes = models.JSONField(
        encoder=django.core.serializers.json.DjangoJSONEncoder,
        blank=True,
        default=list,
        help_text="Domain suffixes to strip from discovered hostnames (longest match wins).",
    )
    status = models.CharField(
        max_length=30,
        default="active",
        choices=[
            ("active", "Active"),
            ("inactive", "Inactive"),
        ],
        help_text="Whether this profile is available for use.",
    )
    secrets_groups = models.ManyToManyField(
        to="extras.SecretsGroup",
        through="DiscoveryProfileSecretsGroupAssignment",
        related_name="discovery_profiles",
        blank=True,
        help_text="Secrets Groups supplying SNMP and SSH credentials, ordered by weight.",
    )

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class DiscoveryProfileSecretsGroupAssignment(BaseModel):
    """Assign a Secrets Group to a Discovery Profile with a priority weight.

    Lower weights are tried first for SSH credential iteration; SNMP uses
    only the lowest-weight group that defines SNMP secrets.
    """

    discovery_profile = models.ForeignKey(
        to="nautobot_plugin_device_auto_discovery.DiscoveryProfile",
        on_delete=models.CASCADE,
        related_name="secrets_group_assignments",
        help_text="The Discovery Profile this Secrets Group is assigned to.",
    )
    secrets_group = models.ForeignKey(
        to="extras.SecretsGroup",
        on_delete=models.CASCADE,
        related_name="discovery_profile_assignments",
        help_text="The Secrets Group providing credentials for discovery.",
    )
    weight = models.PositiveSmallIntegerField(
        default=1000,
        help_text="Priority of this group; lower weights are attempted first (SSH) or preferred (SNMP).",
    )

    class Meta:
        unique_together = ("discovery_profile", "secrets_group")
        ordering = ("discovery_profile", "weight", "secrets_group__name")

    def __str__(self):
        return f"{self.discovery_profile}: {self.secrets_group} (weight {self.weight})"


class DiscoveredDevice(PrimaryModel):
    """Persistent per-IP record of a discovered (or attempted) device."""

    class CorrelationStatus(models.TextChoices):
        IMPORTED = "imported", "Imported (matches Nautobot inventory)"
        NEW = "new", "New (not present in Nautobot)"
        PARTIALLY_IMPORTED = "partially_imported", "Partially imported (some attributes differ)"
        CONFLICT = "conflict", "Conflict (multiple devices match)"
        NOT_REACHABLE = "not_reachable", "Not reachable"
        FAILED = "failed", "Failed to process"

    ip_address = models.GenericIPAddressField(
        protocol="both",
        unpack_ipv4=False,
        unique=True,
        help_text="IP address of the discovered device.",
    )
    hostname = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Device hostname.",
    )
    vendor = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="Device vendor/manufacturer.",
    )
    model = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Device model.",
    )
    device_type = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Inferred device type.",
    )
    serial = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="Device serial number.",
    )
    os_version = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Operating system / software version.",
    )
    network_driver = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="Inferred network driver.",
    )
    status = models.CharField(
        max_length=30,
        choices=CorrelationStatus.choices,
        default=CorrelationStatus.NEW,
        help_text="Correlation status against the Nautobot inventory.",
    )
    device = models.ForeignKey(
        "dcim.Device",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="discovered_devices",
        help_text="The matched or created Nautobot Device, if any.",
    )
    ssh_collection = models.BooleanField(
        default=False,
        help_text="Whether SSH data has been collected for this device.",
    )
    snmp_collection = models.BooleanField(
        default=False,
        help_text="Whether SNMP data has been collected for this device.",
    )
    ssh_collection_datetime = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When SSH data was last successfully collected.",
    )
    snmp_collection_datetime = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When SNMP data was last successfully collected.",
    )
    ssh_collection_attempt_datetime = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the last SSH collection attempt was made.",
    )
    snmp_collection_attempt_datetime = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the last SNMP collection attempt was made.",
    )
    ssh_issue = models.CharField(
        max_length=500,
        blank=True,
        default="",
        help_text="Error encountered during the last SSH collection.",
    )
    snmp_issue = models.CharField(
        max_length=500,
        blank=True,
        default="",
        help_text="Error encountered during the last SNMP collection.",
    )
    ssh_port = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="SSH port used for the last collection.",
    )
    snmp_port = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="SNMP port used for the last collection.",
    )
    last_seen = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When this device was last seen during a discovery run.",
    )
    last_scan = models.ForeignKey(
        DiscoveryScan,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
        help_text="The discovery scan that last touched this record.",
    )
    discovered_data = models.JSONField(
        encoder=django.core.serializers.json.DjangoJSONEncoder,
        blank=True,
        default=dict,
        help_text="Raw collection data captured during the last discovery run.",
    )
    ssh_secrets_group = models.ForeignKey(
        to="extras.SecretsGroup",
        on_delete=models.SET_NULL,
        related_name="discovered_devices_ssh",
        blank=True,
        null=True,
        help_text="Secrets Group whose SSH credentials last succeeded on this device.",
    )
    snmp_secrets_group = models.ForeignKey(
        to="extras.SecretsGroup",
        on_delete=models.SET_NULL,
        related_name="discovered_devices_snmp",
        blank=True,
        null=True,
        help_text="Secrets Group whose SNMP credentials last succeeded on this device.",
    )

    class Meta:
        ordering = ["ip_address"]

    def __str__(self):
        return f"{self.hostname or self.ip_address} ({self.get_status_display()})"


class DeviceClassificationRule(PrimaryModel):
    """Derive a Location, Role, or Tenant for Not Imported discovered devices.

    Rules are grouped by ``classify_as`` target and evaluated in weight
    order (ascending, then name). For each target the first enabled rule
    that produces a single unambiguous match wins — zero or multiple
    matches are treated as no match.
    """

    class ClassifyAs(models.TextChoices):
        LOCATION = "location", "Location"
        ROLE = "role", "Role"
        TENANT = "tenant", "Tenant"

    class Transform(models.TextChoices):
        LOWERCASE = "lowercase", "Lowercase"
        UPPERCASE = "uppercase", "Uppercase"

    # classify_as value -> (app_label, model_name) it must be matched against.
    TARGET_MODEL_MAP = {
        ClassifyAs.LOCATION: ("dcim", "location"),
        ClassifyAs.ROLE: ("extras", "role"),
        ClassifyAs.TENANT: ("tenancy", "tenant"),
    }

    name = models.CharField(max_length=200, unique=True)
    description = models.CharField(max_length=500, blank=True, default="")
    classify_as = models.CharField(
        max_length=20,
        choices=ClassifyAs.choices,
        help_text="Which discovered-device field this rule populates.",
    )
    weight = models.PositiveSmallIntegerField(
        default=1000,
        help_text="Lower weight = higher priority within the same classify_as target.",
    )
    source_pattern = models.CharField(
        max_length=500,
        help_text=(
            "Regular expression applied to the source field; must contain a named "
            "'(?P<value>...)' capture group whose value is used in the lookup."
        ),
    )
    match_against = models.CharField(
        max_length=100,
        help_text="Content-type of the model to match against (e.g. 'dcim.location', 'extras.role', 'tenancy.tenant').",
    )
    match_field = models.CharField(
        max_length=100,
        default="name",
        help_text="Field on the matched model to compare the extracted value against.",
    )
    match_operator = models.CharField(
        max_length=20,
        default="iexact",
        choices=[
            ("iexact", "iexact"),
            ("exact", "exact"),
            ("icontains", "icontains"),
            ("istartswith", "istartswith"),
            ("iendswith", "iendswith"),
        ],
        help_text="How the extracted value is compared to the match field.",
    )
    match_filters = models.JSONField(
        encoder=django.core.serializers.json.DjangoJSONEncoder,
        blank=True,
        default=dict,
        help_text=(
            "Optional equality filters narrowing the lookup, e.g. "
            "{\"status__name\": \"Active\"}. Up to two foreign-key traversals."
        ),
    )
    ip_scope = models.JSONField(
        encoder=django.core.serializers.json.DjangoJSONEncoder,
        blank=True,
        default=list,
        help_text="Optional list of CIDR prefixes restricting this rule to devices with an IP in scope.",
    )
    transform = models.CharField(
        max_length=20,
        blank=True,
        choices=Transform.choices,
        help_text="Optional transformation applied to the extracted value before lookup.",
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Only active rules are evaluated.",
    )

    class Meta:
        ordering = ("classify_as", "weight", "name")

    def __str__(self):
        return self.name

    def clean(self):
        """Validate pattern, target/model compatibility, and match filters."""
        from django.core.exceptions import ValidationError

        super().clean()

        if self.source_pattern and "(?P<value>" not in self.source_pattern:
            raise ValidationError({"source_pattern": "Pattern must contain a named capture group '(?P<value>...)'"})
        try:
            import re

            re.compile(self.source_pattern)
        except re.error as exc:
            raise ValidationError({"source_pattern": f"Invalid regular expression: {exc}"}) from exc

        expected = self.TARGET_MODEL_MAP.get(self.classify_as)
        if expected:
            actual = (self.match_against or "").lower().strip()
            if actual not in (f"{expected[0]}.{expected[1]}", f"{expected[0]}.{expected[1]}s"):
                raise ValidationError(
                    {
                        "match_against": (
                            f"'{self.match_against}' is incompatible with classify_as "
                            f"'{self.classify_as}'; expected '{expected[0]}.{expected[1]}'"
                        )
                    }
                )

        for key in (self.match_filters or {}):
            depth = key.count("__") - 1 if key.endswith(("name", "id", "pk")) else key.count("__")
            if key.count("__") > 2 or depth > 2:
                raise ValidationError({"match_filters": f"Filter '{key}' exceeds two foreign-key traversals"})

    def compile(self):
        """Return ``(compiled_regex, lookup_suffix, queryset_filters)`` for the engine."""
        import re

        return re.compile(self.source_pattern), self.match_operator, dict(self.match_filters or {})


class DiscoveredDeviceClassification(BaseModel):
    """Pre-computed Location/Role/Tenant suggestions for a Not Imported device.

    One row per (device, classify_as) target produced by the classification
    engine; records the winning rule and a human-readable reason. Rows are
    deleted when the device leaves the Not Imported state.
    """

    class ClassifyAs(models.TextChoices):
        LOCATION = "location", "Location"
        ROLE = "role", "Role"
        TENANT = "tenant", "Tenant"

    discovered_device = models.ForeignKey(
        to="nautobot_plugin_device_auto_discovery.DiscoveredDevice",
        on_delete=models.CASCADE,
        related_name="classifications",
        help_text="The discovered device this classification applies to.",
    )
    classify_as = models.CharField(max_length=20, choices=ClassifyAs.choices)
    matched_object_type = models.ForeignKey(
        to="contenttypes.ContentType",
        on_delete=models.SET_NULL,
        related_name="+",
        blank=True,
        null=True,
        help_text="Content-type of the matched object (location/role/tenant).",
    )
    matched_object_id = models.UUIDField(blank=True, null=True)
    matched_rule = models.ForeignKey(
        to="nautobot_plugin_device_auto_discovery.DeviceClassificationRule",
        on_delete=models.SET_NULL,
        related_name="classifications",
        blank=True,
        null=True,
        help_text="The rule that produced this classification.",
    )
    reason = models.CharField(
        max_length=500,
        blank=True,
        default="",
        help_text="Human-readable explanation, e.g. \"Rule 'X': extracted 'ams' from 'hostname' — matched location name='ams'\".",
    )

    class Meta:
        unique_together = ("discovered_device", "classify_as")
        ordering = ("discovered_device", "classify_as")

    def __str__(self):
        return f"{self.discovered_device}: {self.classify_as}"
