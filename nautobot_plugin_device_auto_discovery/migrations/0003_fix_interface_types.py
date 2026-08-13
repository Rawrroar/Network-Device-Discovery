"""Repair dcim.Interface type values that predate Nautobot 2.0 slug choices.

Older plugin versions mapped IANA ifType codes to the removed IETF type
names ("ethernet-csmacd", "softwareLoopback", ...), which corrupts the
interfaces API (KeyError when serializing the type choice). This data
migration normalizes any stored value that is not a valid
InterfaceTypeChoices value.
"""

from django.db import migrations

# Values written by older plugin versions, mapped to their valid replacement.
LEGACY_TO_VALID = {
    "ethernet-csmacd": "other",
    "softwareLoopback": "virtual",
    "propVirtual": "virtual",
    "l2vlan": "virtual",
    "l3ipvlan": "virtual",
    "ieee8023adLag": "lag",
    "tunnel": "tunnel",
}


def _valid_interface_types():
    from nautobot.dcim.choices import InterfaceTypeChoices

    return {value for _, value in InterfaceTypeChoices.choices()}


def fix_interface_types(apps, schema_editor):
    """Rewrite any Interface whose type is not a valid choice."""
    Interface = apps.get_model("dcim", "Interface")
    valid_types = _valid_interface_types()
    fixed = 0
    for interface in Interface.objects.only("id", "type"):
        new_type = LEGACY_TO_VALID.get(interface.type)
        if new_type is None and interface.type not in valid_types:
            new_type = "other"
        if new_type and new_type != interface.type:
            interface.type = new_type
            interface.save(update_fields=["type"])
            fixed += 1
    if fixed:
        print(f"  Fixed {fixed} dcim.Interface type values")


def reverse_fix(apps, schema_editor):
    """Data migration is not reversible; nothing to undo."""


class Migration(migrations.Migration):
    dependencies = [
        ("nautobot_plugin_device_auto_discovery", "0002_discoveryresult_tables"),
    ]

    operations = [
        migrations.RunPython(fix_interface_types, reverse_fix),
    ]
