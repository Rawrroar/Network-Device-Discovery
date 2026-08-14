"""Django models for the Device Auto-Discovery plugin."""

import django.core.serializers.json

from django.db import models
from nautobot.apps.models import PrimaryModel


class DiscoveryScan(PrimaryModel):
    """Represents a single discovery scan run."""

    class ScanMethod(models.TextChoices):
        PING = "ping", "ICMP Ping Sweep"
        SNMP = "snmp", "SNMP Discovery"
        SSH = "ssh", "SSH Discovery"
        FULL = "full", "Full Discovery (Ping + SNMP + SSH)"
        CRAWL = "crawl", "Crawl Discovery (seed device + neighbors)"

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

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


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

    class Meta:
        ordering = ["ip_address"]

    def __str__(self):
        return f"{self.hostname or self.ip_address} ({self.get_status_display()})"
