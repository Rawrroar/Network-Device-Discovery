"""REST API viewsets."""

from nautobot.apps.api import NautobotModelViewSet

from nautobot_plugin_device_auto_discovery import models
from nautobot_plugin_device_auto_discovery.api import filtersets, serializers


class DiscoveryScanViewSet(NautobotModelViewSet):
    """ViewSet for DiscoveryScan objects."""

    queryset = models.DiscoveryScan.objects.all()
    serializer_class = serializers.DiscoveryScanSerializer
    filterset_class = filtersets.DiscoveryScanFilterSet


class DiscoveryResultViewSet(NautobotModelViewSet):
    """ViewSet for DiscoveryResult objects."""

    queryset = models.DiscoveryResult.objects.all()
    serializer_class = serializers.DiscoveryResultSerializer
    filterset_class = filtersets.DiscoveryResultFilterSet


class DiscoveryProfileViewSet(NautobotModelViewSet):
    """ViewSet for DiscoveryProfile objects."""

    queryset = models.DiscoveryProfile.objects.all()
    serializer_class = serializers.DiscoveryProfileSerializer
    filterset_class = filtersets.DiscoveryProfileFilterSet


class DiscoveredDeviceViewSet(NautobotModelViewSet):
    """ViewSet for DiscoveredDevice objects."""

    queryset = models.DiscoveredDevice.objects.all()
    serializer_class = serializers.DiscoveredDeviceSerializer
    filterset_class = filtersets.DiscoveredDeviceFilterSet


class DiscoveryProfileSecretsGroupAssignmentViewSet(NautobotModelViewSet):
    """ViewSet for DiscoveryProfileSecretsGroupAssignment objects."""

    queryset = models.DiscoveryProfileSecretsGroupAssignment.objects.all()
    serializer_class = serializers.DiscoveryProfileSecretsGroupAssignmentSerializer
    filterset_class = filtersets.DiscoveryProfileSecretsGroupAssignmentFilterSet


class DeviceClassificationRuleViewSet(NautobotModelViewSet):
    """ViewSet for DeviceClassificationRule objects."""

    queryset = models.DeviceClassificationRule.objects.all()
    serializer_class = serializers.DeviceClassificationRuleSerializer
    filterset_class = filtersets.DeviceClassificationRuleFilterSet


class DiscoveredDeviceClassificationViewSet(NautobotModelViewSet):
    """ViewSet for DiscoveredDeviceClassification objects."""

    queryset = models.DiscoveredDeviceClassification.objects.all()
    serializer_class = serializers.DiscoveredDeviceClassificationSerializer
    filterset_class = filtersets.DiscoveredDeviceClassificationFilterSet
