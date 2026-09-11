"""UI viewsets for the Device Auto-Discovery plugin."""

from nautobot.apps.views import NautobotUIViewSet

from nautobot_plugin_device_auto_discovery import filtersets, forms, models, tables
from nautobot_plugin_device_auto_discovery.api import serializers


class DiscoveryProfileUIViewSet(NautobotUIViewSet):
    bulk_update_form_class = forms.DiscoveryProfileBulkEditForm
    filterset_class = filtersets.DiscoveryProfileFilterSet
    filterset_form_class = forms.DiscoveryProfileFilterForm
    form_class = forms.DiscoveryProfileForm
    queryset = models.DiscoveryProfile.objects.all()
    serializer_class = serializers.DiscoveryProfileSerializer
    table_class = tables.DiscoveryProfileTable


class DiscoveryScanUIViewSet(NautobotUIViewSet):
    bulk_update_form_class = forms.DiscoveryScanBulkEditForm
    filterset_class = filtersets.DiscoveryScanFilterSet
    filterset_form_class = forms.DiscoveryScanFilterForm
    form_class = forms.DiscoveryScanForm
    queryset = models.DiscoveryScan.objects.all()
    serializer_class = serializers.DiscoveryScanSerializer
    table_class = tables.DiscoveryScanTable


class DiscoveryResultUIViewSet(NautobotUIViewSet):
    bulk_update_form_class = forms.DiscoveryResultBulkEditForm
    filterset_class = filtersets.DiscoveryResultFilterSet
    filterset_form_class = forms.DiscoveryResultFilterForm
    form_class = forms.DiscoveryResultForm
    queryset = models.DiscoveryResult.objects.all()
    serializer_class = serializers.DiscoveryResultSerializer
    table_class = tables.DiscoveryResultTable


class DiscoveredDeviceUIViewSet(NautobotUIViewSet):
    bulk_update_form_class = forms.DiscoveredDeviceBulkEditForm
    filterset_class = filtersets.DiscoveredDeviceFilterSet
    filterset_form_class = forms.DiscoveredDeviceFilterForm
    form_class = forms.DiscoveredDeviceForm
    queryset = models.DiscoveredDevice.objects.all()
    serializer_class = serializers.DiscoveredDeviceSerializer
    table_class = tables.DiscoveredDeviceTable
