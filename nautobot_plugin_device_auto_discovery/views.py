"""UI viewsets for the Device Auto-Discovery plugin."""

from nautobot.apps.ui import ObjectDetailContent, ObjectFieldsPanel, ObjectsTablePanel, SectionChoices
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
    queryset = (
        models.DiscoveredDevice.objects.all()
        .prefetch_related("classifications__matched_rule", "classifications__discovered_device")
    )
    serializer_class = serializers.DiscoveredDeviceSerializer
    table_class = tables.DiscoveredDeviceTable
    object_detail_content = ObjectDetailContent(
        panels=(
            ObjectFieldsPanel(
                label="Discovery",
                section=SectionChoices.LEFT_HALF,
                weight=100,
                fields=(
                    "ip_address",
                    "hostname",
                    "vendor",
                    "model",
                    "serial",
                    "os_version",
                    "status",
                    "device",
                    "last_seen",
                ),
            ),
            ObjectFieldsPanel(
                label="Collection",
                section=SectionChoices.RIGHT_HALF,
                weight=100,
                fields=(
                    "snmp_collection",
                    "snmp_collection_datetime",
                    "snmp_issue",
                    "ssh_collection",
                    "ssh_collection_datetime",
                    "ssh_issue",
                    "ssh_secrets_group",
                    "snmp_secrets_group",
                ),
            ),
            ObjectsTablePanel(
                label="Automated Classification",
                section=SectionChoices.FULL_WIDTH,
                weight=100,
                table_class=tables.DiscoveredDeviceClassificationTable,
                table_attribute="classifications",
                related_field_name="discovered_device",
                table_title="Automated Classification",
                exclude_columns=("discovered_device",),
                include_paginator=False,
            ),
        )
    )


class DiscoveryProfileSecretsGroupAssignmentUIViewSet(NautobotUIViewSet):
    bulk_update_form_class = forms.DiscoveryProfileSecretsGroupAssignmentBulkEditForm
    filterset_class = filtersets.DiscoveryProfileSecretsGroupAssignmentFilterSet
    filterset_form_class = forms.DiscoveryProfileFilterForm
    form_class = forms.DiscoveryProfileSecretsGroupAssignmentForm
    queryset = models.DiscoveryProfileSecretsGroupAssignment.objects.all()
    serializer_class = serializers.DiscoveryProfileSecretsGroupAssignmentSerializer
    table_class = tables.DiscoveryProfileSecretsGroupAssignmentTable


class DeviceClassificationRuleUIViewSet(NautobotUIViewSet):
    bulk_update_form_class = forms.DeviceClassificationRuleBulkEditForm
    filterset_class = filtersets.DeviceClassificationRuleFilterSet
    filterset_form_class = forms.DeviceClassificationRuleFilterForm
    form_class = forms.DeviceClassificationRuleForm
    queryset = models.DeviceClassificationRule.objects.all()
    serializer_class = serializers.DeviceClassificationRuleSerializer
    table_class = tables.DeviceClassificationRuleTable


class DiscoveredDeviceClassificationUIViewSet(NautobotUIViewSet):
    bulk_update_form_class = forms.DiscoveredDeviceClassificationBulkEditForm
    filterset_class = filtersets.DiscoveredDeviceClassificationFilterSet
    filterset_form_class = forms.DiscoveredDeviceClassificationFilterForm
    form_class = forms.DiscoveredDeviceClassificationForm
    queryset = models.DiscoveredDeviceClassification.objects.all()
    serializer_class = serializers.DiscoveredDeviceClassificationSerializer
    table_class = tables.DiscoveredDeviceClassificationTable
