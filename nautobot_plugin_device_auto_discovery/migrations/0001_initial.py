"""Initial migration for DiscoveryScan and DiscoveryResult models."""

import django.db.models.deletion
from django.db import migrations, models

import nautobot_plugin_device_auto_discovery.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("dcim", "0097_virtualdevicecontext_controller_managed_device_group"),
        ("extras", "0145_objectmetadata_assigned_object_type_cascade"),
    ]

    operations = [
        migrations.CreateModel(
            name="DiscoveryScan",
            fields=[
                ("id", models.UUIDField(primary_key=True, serialize=False)),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("last_updated", models.DateTimeField(auto_now=True)),
                ("name", models.CharField(help_text="Display name for this scan.", max_length=100)),
                ("scan_method", models.CharField(
                    choices=[
                        ("ping", "ICMP Ping Sweep"),
                        ("snmp", "SNMP Discovery"),
                        ("ssh", "SSH Discovery"),
                        ("full", "Full Discovery (Ping + SNMP + SSH)"),
                    ],
                    help_text="The discovery method used.",
                    max_length=4,
                )),
                ("target_network", models.GenericIPAddressField(
                    blank=True,
                    help_text="The target IP range in CIDR notation (e.g., 10.0.0.0/24).",
                    null=True,
                    unpack_ipv4=False,
                )),
                ("status", models.CharField(
                    choices=[
                        ("pending", "Pending"),
                        ("running", "Running"),
                        ("completed", "Completed"),
                        ("failed", "Failed"),
                    ],
                    default="pending",
                    max_length=30,
                )),
                ("devices_discovered", models.PositiveIntegerField(
                    default=0,
                    help_text="Number of devices discovered in this scan.",
                )),
                ("devices_created", models.PositiveIntegerField(
                    default=0,
                    help_text="Number of new Device objects created in Nautobot.",
                )),
                ("error_message", models.TextField(
                    blank=True,
                    default="",
                    help_text="Error message if the scan failed.",
                )),
            ],
            options={
                "ordering": ["-created"],
            },
            bases=("nautobot.apps.models.PrimaryModel",),
        ),
        migrations.CreateModel(
            name="DiscoveryResult",
            fields=[
                ("id", models.UUIDField(primary_key=True, serialize=False)),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("last_updated", models.DateTimeField(auto_now=True)),
                ("ip_address", models.GenericIPAddressField(
                    help_text="IP address of the discovered device.",
                    unpack_ipv4=False,
                )),
                ("hostname", models.CharField(
                    blank=True,
                    default="",
                    help_text="Device hostname.",
                    max_length=255,
                )),
                ("vendor", models.CharField(
                    blank=True,
                    default="",
                    help_text="Device vendor/manufacturer.",
                    max_length=100,
                )),
                ("model", models.CharField(
                    blank=True,
                    default="",
                    help_text="Device model.",
                    max_length=255,
                )),
                ("serial_number", models.CharField(
                    blank=True,
                    default="",
                    help_text="Device serial number.",
                    max_length=100,
                )),
                ("os_version", models.CharField(
                    blank=True,
                    default="",
                    help_text="Operating system / software version.",
                    max_length=255,
                )),
                ("platform_name", models.CharField(
                    blank=True,
                    default="",
                    help_text="Inferred Nautobot Platform name.",
                    max_length=100,
                )),
                ("discovery_method", models.CharField(
                    choices=[
                        ("snmp", "SNMP"),
                        ("ssh", "SSH"),
                        ("ping", "Ping"),
                    ],
                    help_text="Which method discovered this device.",
                    max_length=10,
                )),
                ("result_status", models.CharField(
                    choices=[
                        ("new", "New (created in Nautobot)"),
                        ("existing", "Already exists in Nautobot"),
                        ("conflict", "Conflicts with existing record"),
                        ("failed", "Failed to process"),
                    ],
                    default="new",
                    help_text="Whether the device was new, existing, or conflicting.",
                    max_length=10,
                )),
                ("error_message", models.TextField(
                    blank=True,
                    default="",
                    help_text="Error details if discovery or creation failed.",
                )),
                ("nautobot_device", models.ForeignKey(
                    blank=True,
                    help_text="The Nautobot Device object, if created or matched.",
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="discovery_results",
                    to="dcim.device",
                )),
                ("scan", models.ForeignKey(
                    help_text="The discovery scan this result belongs to.",
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="results",
                    to="nautobot_plugin_device_auto_discovery.discoveryscan",
                )),
            ],
            options={
                "ordering": ["-created"],
            },
            bases=("nautobot.apps.models.PrimaryModel",),
        ),
    ]
