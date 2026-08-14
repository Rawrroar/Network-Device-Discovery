"""Add crawl scan method, seed_device, and cables_created fields."""

import django.db.models.deletion

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dcim", "0097_virtualdevicecontext_controller_managed_device_group"),
        ("extras", "0145_objectmetadata_assigned_object_type_cascade"),
        ("nautobot_plugin_device_auto_discovery", "0004_discoveryresult_vlans"),
    ]

    operations = [
        migrations.AlterField(
            model_name="discoveryscan",
            name="scan_method",
            field=models.CharField(
                max_length=10,
                choices=[
                    ("ping", "ICMP Ping Sweep"),
                    ("snmp", "SNMP Discovery"),
                    ("ssh", "SSH Discovery"),
                    ("full", "Full Discovery (Ping + SNMP + SSH)"),
                    ("crawl", "Crawl Discovery (seed device + neighbors)"),
                ],
                help_text="The discovery method used.",
            ),
        ),
        migrations.AddField(
            model_name="discoveryscan",
            name="cables_created",
            field=models.PositiveIntegerField(
                default=0,
                help_text="Number of dcim.Cable objects created from neighbor data.",
            ),
        ),
        migrations.AddField(
            model_name="discoveryscan",
            name="seed_device",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="crawl_scans",
                to="dcim.device",
                help_text="Seed device for crawl discovery scans.",
            ),
        ),
    ]
