"""Add sync scan method to DiscoveryScan."""

import django.core.serializers.json

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dcim", "0097_virtualdevicecontext_controller_managed_device_group"),
        ("extras", "0145_objectmetadata_assigned_object_type_cascade"),
        ("nautobot_plugin_device_auto_discovery", "0010_classification"),
    ]

    operations = [
        migrations.AlterField(
            model_name="discoveryscan",
            name="scan_method",
            field=models.CharField(
                choices=[
                    ("ping", "ICMP Ping Sweep"),
                    ("snmp", "SNMP Discovery"),
                    ("ssh", "SSH Discovery"),
                    ("full", "Full Discovery (Ping + SNMP + SSH)"),
                    ("crawl", "Crawl Discovery (seed device + neighbors)"),
                    ("vrf", "VRF & Route Discovery"),
                    ("sync", "Sync Discovered Devices From Network"),
                ],
                help_text="The discovery method used.",
                max_length=10,
            ),
        ),
    ]
