"""Add automated device classification models."""

import django.core.serializers.json
import django.db.models.deletion
import nautobot.core.models.fields
import nautobot.extras.models.mixins
import uuid

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("extras", "0145_objectmetadata_assigned_object_type_cascade"),
        ("nautobot_plugin_device_auto_discovery", "0009_secrets_groups"),
    ]

    operations = [
        migrations.CreateModel(
            name="DeviceClassificationRule",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True
                    ),
                ),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                (
                    "_custom_field_data",
                    models.JSONField(
                        blank=True, default=dict, encoder=django.core.serializers.json.DjangoJSONEncoder
                    ),
                ),
                ("name", models.CharField(max_length=200, unique=True)),
                ("description", models.CharField(blank=True, default="", max_length=500)),
                ("classify_as", models.CharField(max_length=20)),
                ("weight", models.PositiveSmallIntegerField(default=1000)),
                ("source_pattern", models.CharField(max_length=500)),
                ("match_against", models.CharField(max_length=100)),
                ("match_field", models.CharField(default="name", max_length=100)),
                ("match_operator", models.CharField(default="iexact", max_length=20)),
                (
                    "match_filters",
                    models.JSONField(
                        blank=True, default=dict, encoder=django.core.serializers.json.DjangoJSONEncoder
                    ),
                ),
                (
                    "ip_scope",
                    models.JSONField(
                        blank=True, default=list, encoder=django.core.serializers.json.DjangoJSONEncoder
                    ),
                ),
                ("transform", models.CharField(blank=True, max_length=20)),
                ("is_active", models.BooleanField(default=True)),
                ("tags", nautobot.core.models.fields.TagsField(through="extras.TaggedItem", to="extras.Tag")),
            ],
            options={
                "ordering": ("classify_as", "weight", "name"),
            },
            bases=(
                nautobot.extras.models.mixins.DataComplianceModelMixin,
                nautobot.extras.models.mixins.DynamicGroupMixin,
                nautobot.extras.models.mixins.NotesMixin,
                models.Model,
            ),
        ),
        migrations.CreateModel(
            name="DiscoveredDeviceClassification",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True
                    ),
                ),
                ("classify_as", models.CharField(max_length=20)),
                ("matched_object_id", models.UUIDField(blank=True, null=True)),
                ("reason", models.CharField(blank=True, default="", max_length=500)),
                (
                    "discovered_device",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="classifications",
                        to="nautobot_plugin_device_auto_discovery.discovereddevice",
                    ),
                ),
                (
                    "matched_object_type",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to="contenttypes.contenttype",
                    ),
                ),
                (
                    "matched_rule",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="classifications",
                        to="nautobot_plugin_device_auto_discovery.deviceclassificationrule",
                    ),
                ),
            ],
            options={
                "ordering": ("discovered_device", "classify_as"),
                "unique_together": {("discovered_device", "classify_as")},
            },
        ),
    ]
