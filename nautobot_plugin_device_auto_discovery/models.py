"""Django models for the Device Auto-Discovery plugin."""

from django.db import models
from nautobot.apps.models import PrimaryModel


class DiscoveryScan(PrimaryModel):
    """Represents a single discovery scan run."""

    class ScanMethod(models.TextChoices):
        PING = "ping", "ICMP Ping Sweep"
        SNMP = "snmp", "SNMP Discovery"
        SSH = "ssh", "SSH Discovery"
        FULL = "full", "Full Discovery (Ping + SNMP + SSH)"

    name = models.CharField(
        max_length=100,
        help_text="Display name for this scan.",
    )
    scan_method = models.CharField(
        max_length=4,
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
    error_message = models.TextField(
        blank=True,
        default="",
        help_text="Error details if discovery or creation failed.",
    )

    class Meta:
        ordering = ["-created"]

    def __str__(self):
        return f"{self.hostname or self.ip_address} ({self.result_status})"
