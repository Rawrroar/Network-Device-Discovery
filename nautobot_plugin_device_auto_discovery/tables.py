"""UI tables for the Device Auto-Discovery plugin."""

import django_tables2 as tables
from nautobot.apps.tables import BaseTable, ToggleColumn

from nautobot_plugin_device_auto_discovery import models


class DiscoveryScanTable(BaseTable):
    pk = ToggleColumn()
    name = tables.LinkColumn()
    scan_method = tables.Column(verbose_name="Method")
    status = tables.Column()
    devices_discovered = tables.Column(verbose_name="Devices Found")
    devices_created = tables.Column(verbose_name="Devices Created")
    cables_created = tables.Column(verbose_name="Cables Created")

    class Meta:
        model = models.DiscoveryScan
        fields = (
            "name",
            "scan_method",
            "target_network",
            "status",
            "devices_discovered",
            "devices_created",
            "cables_created",
            "created",
        )
        default_columns = (
            "name",
            "scan_method",
            "target_network",
            "status",
            "devices_discovered",
            "devices_created",
            "cables_created",
        )


class DiscoveryResultTable(BaseTable):
    pk = ToggleColumn()
    hostname = tables.LinkColumn()
    ip_address = tables.Column(verbose_name="IP Address")
    result_status = tables.Column(verbose_name="Status")
    discovery_method = tables.Column(verbose_name="Method")
    vendor = tables.Column()
    nautobot_device = tables.LinkColumn(verbose_name="Nautobot Device")

    class Meta:
        model = models.DiscoveryResult
        fields = (
            "scan",
            "ip_address",
            "hostname",
            "vendor",
            "result_status",
            "discovery_method",
            "nautobot_device",
            "created",
        )
        default_columns = (
            "ip_address",
            "hostname",
            "vendor",
            "result_status",
            "discovery_method",
            "nautobot_device",
            "created",
        )


class DiscoveryProfileTable(BaseTable):
    pk = ToggleColumn()
    name = tables.LinkColumn()
    status = tables.Column()

    class Meta:
        model = models.DiscoveryProfile
        fields = ("name", "status", "protocols", "included_ip_prefixes", "maximum_ip_addresses", "created")
        default_columns = ("name", "status", "protocols", "included_ip_prefixes", "created")


class DiscoveredDeviceTable(BaseTable):
    pk = ToggleColumn()
    hostname = tables.LinkColumn()
    ip_address = tables.Column(verbose_name="IP Address")
    status = tables.Column(verbose_name="Correlation")
    vendor = tables.Column()
    device = tables.LinkColumn(verbose_name="Nautobot Device")
    last_seen = tables.DateTimeColumn(verbose_name="Last Seen")
    classification_location = tables.Column(
        verbose_name="Classification Location", accessor="pk", orderable=False, default=""
    )
    classification_role = tables.Column(
        verbose_name="Classification Role", accessor="pk", orderable=False, default=""
    )
    classification_tenant = tables.Column(
        verbose_name="Classification Tenant", accessor="pk", orderable=False, default=""
    )

    class Meta:
        model = models.DiscoveredDevice
        fields = (
            "hostname",
            "ip_address",
            "status",
            "vendor",
            "model",
            "device",
            "snmp_collection",
            "ssh_collection",
            "ssh_secrets_group",
            "snmp_secrets_group",
            "classification_location",
            "classification_role",
            "classification_tenant",
            "last_seen",
        )
        default_columns = ("hostname", "ip_address", "status", "vendor", "device", "last_seen")

    def _classification_value(self, record, classify_as):
        for classification in getattr(record, "_classification_cache", []) or []:
            if classification.classify_as == classify_as:
                return str(classification.matched_rule)
        return ""

    def render_classification_location(self, record):
        return self._classification_value(record, "location")

    def render_classification_role(self, record):
        return self._classification_value(record, "role")

    def render_classification_tenant(self, record):
        return self._classification_value(record, "tenant")


class DiscoveryProfileSecretsGroupAssignmentTable(BaseTable):
    discovery_profile = tables.LinkColumn()
    secrets_group = tables.LinkColumn()

    class Meta:
        model = models.DiscoveryProfileSecretsGroupAssignment
        fields = ("discovery_profile", "secrets_group", "weight", "created")
        default_columns = ("discovery_profile", "secrets_group", "weight")


class DeviceClassificationRuleTable(BaseTable):
    pk = ToggleColumn()
    name = tables.LinkColumn()
    classify_as = tables.Column(verbose_name="Classify As")

    class Meta:
        model = models.DeviceClassificationRule
        fields = (
            "name",
            "classify_as",
            "weight",
            "source_pattern",
            "match_against",
            "match_field",
            "match_operator",
            "is_active",
        )
        default_columns = ("name", "classify_as", "weight", "source_pattern", "match_against", "is_active")


class DiscoveredDeviceClassificationTable(BaseTable):
    discovered_device = tables.LinkColumn(verbose_name="Discovered Device")
    matched_rule = tables.LinkColumn(verbose_name="Rule")

    class Meta:
        model = models.DiscoveredDeviceClassification
        fields = ("discovered_device", "classify_as", "matched_rule", "reason")
        default_columns = ("discovered_device", "classify_as", "matched_rule", "reason")
