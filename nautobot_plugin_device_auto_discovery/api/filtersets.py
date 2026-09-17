"""REST API filtersets."""

from nautobot.apps.filters import NautobotFilterSet
from nautobot.core.filters import SearchFilter

from nautobot_plugin_device_auto_discovery import models


class DiscoveryScanFilterSet(NautobotFilterSet):
    """FilterSet for DiscoveryScan objects."""

    q = SearchFilter(filter_predicates={"name": "icontains", "target_network": "icontains"})

    class Meta:
        model = models.DiscoveryScan
        fields = ("name", "scan_method", "status", "target_network", "seed_device")


class DiscoveryResultFilterSet(NautobotFilterSet):
    """FilterSet for DiscoveryResult objects."""

    q = SearchFilter(
        filter_predicates={
            "hostname": "icontains",
            "vendor": "icontains",
            "model": "icontains",
            "serial_number": "icontains",
        }
    )

    class Meta:
        model = models.DiscoveryResult
        fields = (
            "scan",
            "ip_address",
            "hostname",
            "result_status",
            "discovery_method",
            "nautobot_device",
        )


class DiscoveryProfileFilterSet(NautobotFilterSet):
    """FilterSet for DiscoveryProfile objects."""

    q = SearchFilter(filter_predicates={"name": "icontains", "description": "icontains"})

    class Meta:
        model = models.DiscoveryProfile
        # NOTE: the secrets_groups M2M is intentionally NOT filterable —
        # Nautobot's auto-generated M2M filter for a custom through model
        # breaks the list-view dynamic filter form (TypeError at render).
        # Manage credentials via the assignments list view / API instead.
        fields = ("name", "status")


class DiscoveredDeviceFilterSet(NautobotFilterSet):
    """FilterSet for DiscoveredDevice objects."""

    q = SearchFilter(
        filter_predicates={
            "hostname": "icontains",
            "vendor": "icontains",
            "model": "icontains",
            "serial": "icontains",
        }
    )

    class Meta:
        model = models.DiscoveredDevice
        fields = (
            "ip_address",
            "hostname",
            "status",
            "device",
            "snmp_collection",
            "ssh_collection",
            "ssh_secrets_group",
            "snmp_secrets_group",
        )


class DiscoveryProfileSecretsGroupAssignmentFilterSet(NautobotFilterSet):
    """FilterSet for DiscoveryProfileSecretsGroupAssignment objects."""

    q = SearchFilter(filter_predicates={"discovery_profile__name": "icontains", "secrets_group__name": "icontains"})

    class Meta:
        model = models.DiscoveryProfileSecretsGroupAssignment
        fields = ("discovery_profile", "secrets_group", "weight")


class DeviceClassificationRuleFilterSet(NautobotFilterSet):
    """FilterSet for DeviceClassificationRule objects."""

    q = SearchFilter(filter_predicates={"name": "icontains", "description": "icontains"})

    class Meta:
        model = models.DeviceClassificationRule
        fields = ("name", "classify_as", "match_against", "weight", "is_active")


class DiscoveredDeviceClassificationFilterSet(NautobotFilterSet):
    """FilterSet for DiscoveredDeviceClassification objects."""

    q = SearchFilter(filter_predicates={"discovered_device__hostname": "icontains", "reason": "icontains"})

    class Meta:
        model = models.DiscoveredDeviceClassification
        fields = ("discovered_device", "classify_as", "matched_rule")
