"""Add DiscoveryProfile and DiscoveredDevice models."""

import django.core.serializers.json
import django.db.models.deletion

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dcim", "0097_virtualdevicecontext_controller_managed_device_group"),
        ("extras", "0145_objectmetadata_assigned_object_type_cascade"),
        ("nautobot_plugin_device_auto_discovery", "0005_crawl_and_cables"),
    ]

    operations = [
        migrations.CreateModel(
            name="DiscoveryProfile",
            fields=[
                (
                    "id",
                    models.UUIDField(primary_key=True, serialize=False),
                ),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("last_updated", models.DateTimeField(auto_now=True)),
                (
                    "_custom_field_data",
                    models.JSONField(
                        encoder=django.core.serializers.json.DjangoJSONEncoder,
                        blank=True,
                        default=dict,
                    ),
                ),
                (
                    "name",
                    models.CharField(
                        max_length=200,
                        unique=True,
                        help_text="Unique name for this discovery profile.",
                    ),
                ),
                (
                    "description",
                    models.CharField(
                        max_length=500,
                        blank=True,
                        default="",
                        help_text="Human-friendly description of this profile.",
                    ),
                ),
                (
                    "included_ip_prefixes",
                    models.JSONField(
                        encoder=django.core.serializers.json.DjangoJSONEncoder,
                        blank=True,
                        default=list,
                        help_text="List of CIDR prefixes to scan (e.g., ['10.0.0.0/24']).",
                    ),
                ),
                (
                    "excluded_ip_prefixes",
                    models.JSONField(
                        encoder=django.core.serializers.json.DjangoJSONEncoder,
                        blank=True,
                        default=list,
                        help_text="List of CIDR prefixes to exclude from scanning.",
                    ),
                ),
                (
                    "maximum_ip_addresses",
                    models.PositiveIntegerField(
                        default=0,
                        help_text="Maximum number of IP addresses this profile may scan (0 = unlimited).",
                    ),
                ),
                (
                    "protocols",
                    models.JSONField(
                        encoder=django.core.serializers.json.DjangoJSONEncoder,
                        blank=True,
                        default=list,
                        help_text="Protocols to use: 'ping', 'snmp', 'ssh'.",
                    ),
                ),
                (
                    "ssh_port",
                    models.PositiveIntegerField(
                        default=22,
                        help_text="SSH port to use for ssh protocols.",
                    ),
                ),
                (
                    "snmp_port",
                    models.PositiveIntegerField(
                        default=161,
                        help_text="SNMP port to use for snmp protocols.",
                    ),
                ),
                (
                    "snmp_timeout",
                    models.PositiveIntegerField(
                        default=5,
                        help_text="SNMP timeout in seconds per host.",
                    ),
                ),
                (
                    "snmp_retries",
                    models.PositiveIntegerField(
                        default=0,
                        help_text="Number of SNMP retries per host.",
                    ),
                ),
                (
                    "snmpv3_auth_protocol",
                    models.CharField(
                        max_length=50,
                        blank=True,
                        default="SHA",
                        help_text="Default SNMPv3 authentication protocol.",
                    ),
                ),
                (
                    "snmpv3_priv_protocol",
                    models.CharField(
                        max_length=50,
                        blank=True,
                        default="AES",
                        help_text="Default SNMPv3 privacy protocol.",
                    ),
                ),
                (
                    "fast_path",
                    models.BooleanField(
                        default=False,
                        help_text="Use the Fast Path method to speed up scans.",
                    ),
                ),
                (
                    "strip_domain_suffixes",
                    models.JSONField(
                        encoder=django.core.serializers.json.DjangoJSONEncoder,
                        blank=True,
                        default=list,
                        help_text="Domain suffixes to strip from discovered hostnames (longest match wins).",
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        max_length=30,
                        default="active",
                        choices=[("active", "Active"), ("inactive", "Inactive")],
                        help_text="Whether this profile is available for use.",
                    ),
                ),
            ],
            options={
                "ordering": ["name"],
            },
        ),
        migrations.CreateModel(
            name="DiscoveredDevice",
            fields=[
                (
                    "id",
                    models.UUIDField(primary_key=True, serialize=False),
                ),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("last_updated", models.DateTimeField(auto_now=True)),
                (
                    "_custom_field_data",
                    models.JSONField(
                        encoder=django.core.serializers.json.DjangoJSONEncoder,
                        blank=True,
                        default=dict,
                    ),
                ),
                (
                    "ip_address",
                    models.GenericIPAddressField(
                        protocol="both",
                        unpack_ipv4=False,
                        unique=True,
                        help_text="IP address of the discovered device.",
                    ),
                ),
                (
                    "hostname",
                    models.CharField(
                        max_length=255,
                        blank=True,
                        default="",
                        help_text="Device hostname.",
                    ),
                ),
                (
                    "vendor",
                    models.CharField(
                        max_length=100,
                        blank=True,
                        default="",
                        help_text="Device vendor/manufacturer.",
                    ),
                ),
                (
                    "model",
                    models.CharField(
                        max_length=255,
                        blank=True,
                        default="",
                        help_text="Device model.",
                    ),
                ),
                (
                    "device_type",
                    models.CharField(
                        max_length=255,
                        blank=True,
                        default="",
                        help_text="Inferred device type.",
                    ),
                ),
                (
                    "serial",
                    models.CharField(
                        max_length=100,
                        blank=True,
                        default="",
                        help_text="Device serial number.",
                    ),
                ),
                (
                    "os_version",
                    models.CharField(
                        max_length=255,
                        blank=True,
                        default="",
                        help_text="Operating system / software version.",
                    ),
                ),
                (
                    "network_driver",
                    models.CharField(
                        max_length=100,
                        blank=True,
                        default="",
                        help_text="Inferred network driver.",
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        max_length=30,
                        choices=[
                            ("imported", "Imported (matches Nautobot inventory)"),
                            ("new", "New (not present in Nautobot)"),
                            ("partially_imported", "Partially imported (some attributes differ)"),
                            ("conflict", "Conflict (multiple devices match)"),
                            ("not_reachable", "Not reachable"),
                            ("failed", "Failed to process"),
                        ],
                        default="new",
                        help_text="Correlation status against the Nautobot inventory.",
                    ),
                ),
                (
                    "device",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="discovered_devices",
                        to="dcim.device",
                        help_text="The matched or created Nautobot Device, if any.",
                    ),
                ),
                (
                    "ssh_collection",
                    models.BooleanField(
                        default=False,
                        help_text="Whether SSH data has been collected for this device.",
                    ),
                ),
                (
                    "snmp_collection",
                    models.BooleanField(
                        default=False,
                        help_text="Whether SNMP data has been collected for this device.",
                    ),
                ),
                (
                    "ssh_collection_datetime",
                    models.DateTimeField(
                        blank=True,
                        null=True,
                        help_text="When SSH data was last successfully collected.",
                    ),
                ),
                (
                    "snmp_collection_datetime",
                    models.DateTimeField(
                        blank=True,
                        null=True,
                        help_text="When SNMP data was last successfully collected.",
                    ),
                ),
                (
                    "ssh_collection_attempt_datetime",
                    models.DateTimeField(
                        blank=True,
                        null=True,
                        help_text="When the last SSH collection attempt was made.",
                    ),
                ),
                (
                    "snmp_collection_attempt_datetime",
                    models.DateTimeField(
                        blank=True,
                        null=True,
                        help_text="When the last SNMP collection attempt was made.",
                    ),
                ),
                (
                    "ssh_issue",
                    models.CharField(
                        max_length=500,
                        blank=True,
                        default="",
                        help_text="Error encountered during the last SSH collection.",
                    ),
                ),
                (
                    "snmp_issue",
                    models.CharField(
                        max_length=500,
                        blank=True,
                        default="",
                        help_text="Error encountered during the last SNMP collection.",
                    ),
                ),
                (
                    "ssh_port",
                    models.PositiveIntegerField(
                        blank=True,
                        null=True,
                        help_text="SSH port used for the last collection.",
                    ),
                ),
                (
                    "snmp_port",
                    models.PositiveIntegerField(
                        blank=True,
                        null=True,
                        help_text="SNMP port used for the last collection.",
                    ),
                ),
                (
                    "last_seen",
                    models.DateTimeField(
                        blank=True,
                        null=True,
                        help_text="When this device was last seen during a discovery run.",
                    ),
                ),
                (
                    "last_scan",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to="nautobot_plugin_device_auto_discovery.discoveryscan",
                        help_text="The discovery scan that last touched this record.",
                    ),
                ),
                (
                    "discovered_data",
                    models.JSONField(
                        encoder=django.core.serializers.json.DjangoJSONEncoder,
                        blank=True,
                        default=dict,
                        help_text="Raw collection data captured during the last discovery run.",
                    ),
                ),
            ],
            options={
                "ordering": ["ip_address"],
            },
        ),
    ]
