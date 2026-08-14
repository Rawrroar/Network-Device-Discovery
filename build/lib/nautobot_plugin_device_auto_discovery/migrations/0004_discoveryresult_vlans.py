"""Add vlans_found field to DiscoveryResult."""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("nautobot_plugin_device_auto_discovery", "0003_fix_interface_types"),
    ]

    operations = [
        migrations.AddField(
            model_name="discoveryresult",
            name="vlans_found",
            field=models.PositiveIntegerField(
                default=0,
                help_text="Number of VLANs discovered via SNMP (Q-BRIDGE-MIB).",
            ),
        ),
    ]
