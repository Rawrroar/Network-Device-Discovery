"""Add Secrets Group integration for discovery credentials."""

import uuid

import django.db.models.deletion

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("extras", "0145_objectmetadata_assigned_object_type_cascade"),
        ("nautobot_plugin_device_auto_discovery", "0008_discoveryresult_vrfs"),
    ]

    operations = [
        migrations.CreateModel(
            name="DiscoveryProfileSecretsGroupAssignment",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                        unique=True,
                    ),
                ),
                (
                    "weight",
                    models.PositiveSmallIntegerField(
                        default=1000,
                        help_text="Priority of this group; lower weights are attempted first (SSH) or preferred (SNMP).",
                    ),
                ),
                (
                    "discovery_profile",
                    models.ForeignKey(
                        help_text="The Discovery Profile this Secrets Group is assigned to.",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="secrets_group_assignments",
                        to="nautobot_plugin_device_auto_discovery.discoveryprofile",
                    ),
                ),
                (
                    "secrets_group",
                    models.ForeignKey(
                        help_text="The Secrets Group providing credentials for discovery.",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="discovery_profile_assignments",
                        to="extras.secretsgroup",
                    ),
                ),
            ],
            options={
                "ordering": ("discovery_profile", "weight", "secrets_group__name"),
                "unique_together": {("discovery_profile", "secrets_group")},
            },
        ),
        migrations.AddField(
            model_name="discoveryprofile",
            name="secrets_groups",
            field=models.ManyToManyField(
                blank=True,
                help_text="Secrets Groups supplying SNMP and SSH credentials, ordered by weight.",
                related_name="discovery_profiles",
                through="nautobot_plugin_device_auto_discovery.DiscoveryProfileSecretsGroupAssignment",
                to="extras.secretsgroup",
            ),
        ),
        migrations.AddField(
            model_name="discovereddevice",
            name="snmp_secrets_group",
            field=models.ForeignKey(
                blank=True,
                help_text="Secrets Group whose SNMP credentials last succeeded on this device.",
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="discovered_devices_snmp",
                to="extras.secretsgroup",
            ),
        ),
        migrations.AddField(
            model_name="discovereddevice",
            name="ssh_secrets_group",
            field=models.ForeignKey(
                blank=True,
                help_text="Secrets Group whose SSH credentials last succeeded on this device.",
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="discovered_devices_ssh",
                to="extras.secretsgroup",
            ),
        ),
    ]
