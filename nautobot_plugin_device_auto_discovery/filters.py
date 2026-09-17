"""Top-level filtersets for Nautobot's model-filter lookup conventions.

Nautobot core resolves a model's FilterSet via ``get_filterset_for_model``,
which expects a ``filters`` module in the app exposing
``{ModelName}FilterSet`` classes (e.g. for saved-view query-param handling
and dynamic filter forms). The canonical filtersets live in
``nautobot_plugin_device_auto_discovery.api.filtersets``; this module
re-exports them under the expected names.
"""

from nautobot_plugin_device_auto_discovery.api.filtersets import (
    DeviceClassificationRuleFilterSet,
    DiscoveryProfileFilterSet,
    DiscoveryProfileSecretsGroupAssignmentFilterSet,
    DiscoveryResultFilterSet,
    DiscoveryScanFilterSet,
    DiscoveredDeviceClassificationFilterSet,
    DiscoveredDeviceFilterSet,
)

__all__ = [
    "DeviceClassificationRuleFilterSet",
    "DiscoveryProfileFilterSet",
    "DiscoveryProfileSecretsGroupAssignmentFilterSet",
    "DiscoveryResultFilterSet",
    "DiscoveryScanFilterSet",
    "DiscoveredDeviceClassificationFilterSet",
    "DiscoveredDeviceFilterSet",
]
