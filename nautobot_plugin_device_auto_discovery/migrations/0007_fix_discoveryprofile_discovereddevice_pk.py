"""Fix DiscoveryProfile and DiscoveredDevice primary keys (bigint -> uuid).

Migration 0006 created these two PrimaryModel tables with a bigint ``id``
column. PrimaryModel uses a UUID primary key, so every INSERT failed with
``column "id" is of type bigint but expression is of type uuid``. This
migration converts the existing columns.

The tables are guaranteed to be empty (no insert ever succeeded), and no
other table has a foreign key to either of them, so the drop/re-add is safe.
"""

import django.db.models.deletion

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("nautobot_plugin_device_auto_discovery", "0006_discovery_profiles_and_devices"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="discoveryprofile",
            name="id",
        ),
        migrations.AddField(
            model_name="discoveryprofile",
            name="id",
            field=models.UUIDField(primary_key=True, serialize=False),
        ),
        migrations.RemoveField(
            model_name="discovereddevice",
            name="id",
        ),
        migrations.AddField(
            model_name="discovereddevice",
            name="id",
            field=models.UUIDField(primary_key=True, serialize=False),
        ),
    ]
