"""Add SNMP table-discovered fields to DiscoveryResult."""

import django.core.serializers.json
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("nautobot_plugin_device_auto_discovery", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="discoveryresult",
            name="sys_location",
            field=models.CharField(
                blank=True,
                default="",
                help_text="SNMP sysLocation value.",
                max_length=200,
            ),
        ),
        migrations.AddField(
            model_name="discoveryresult",
            name="sys_contact",
            field=models.CharField(
                blank=True,
                default="",
                help_text="SNMP sysContact value.",
                max_length=200,
            ),
        ),
        migrations.AddField(
            model_name="discoveryresult",
            name="interfaces_found",
            field=models.PositiveIntegerField(
                default=0,
                help_text="Number of interfaces discovered via SNMP.",
            ),
        ),
        migrations.AddField(
            model_name="discoveryresult",
            name="ip_addresses_found",
            field=models.PositiveIntegerField(
                default=0,
                help_text="Number of IP addresses discovered via SNMP.",
            ),
        ),
        migrations.AddField(
            model_name="discoveryresult",
            name="neighbors_found",
            field=models.PositiveIntegerField(
                default=0,
                help_text="Number of LLDP/CDP neighbors discovered via SNMP.",
            ),
        ),
        migrations.AddField(
            model_name="discoveryresult",
            name="discovered_data",
            field=models.JSONField(
                blank=True,
                default=dict,
                encoder=django.core.serializers.json.DjangoJSONEncoder,
                help_text="Raw MIB table data captured during SNMP discovery.",
            ),
        ),
    ]
