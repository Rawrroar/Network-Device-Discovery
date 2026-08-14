"""REST API serializers."""

from nautobot.apps.api import NautobotModelSerializer

from nautobot_plugin_device_auto_discovery import models


class DiscoveryScanSerializer(NautobotModelSerializer):
    """Serializer for DiscoveryScan objects."""

    class Meta:
        model = models.DiscoveryScan
        fields = "__all__"


class DiscoveryResultSerializer(NautobotModelSerializer):
    """Serializer for DiscoveryResult objects."""

    class Meta:
        model = models.DiscoveryResult
        fields = "__all__"


class DiscoveryProfileSerializer(NautobotModelSerializer):
    """Serializer for DiscoveryProfile objects."""

    class Meta:
        model = models.DiscoveryProfile
        fields = "__all__"


class DiscoveredDeviceSerializer(NautobotModelSerializer):
    """Serializer for DiscoveredDevice objects."""

    class Meta:
        model = models.DiscoveredDevice
        fields = "__all__"
