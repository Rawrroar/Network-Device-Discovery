"""Add vrfs_found field to DiscoveryResult."""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("nautobot_plugin_device_auto_discovery", "0007_fix_discoveryprofile_discovereddevice_pk"),
    ]

    operations = [
        migrations.AddField(
            model_name="discoveryresult",
            name="vrfs_found",
            field=models.PositiveIntegerField(
                default=0,
                help_text="Number of VRFs discovered via SNMP (MPLS-VPN-MIB / CISCO-VRF-MIB).",
            ),
        ),
    ]
