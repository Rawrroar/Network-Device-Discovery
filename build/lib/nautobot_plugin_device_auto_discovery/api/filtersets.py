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
        fields = ("ip_address", "hostname", "status", "device", "snmp_collection", "ssh_collection")
