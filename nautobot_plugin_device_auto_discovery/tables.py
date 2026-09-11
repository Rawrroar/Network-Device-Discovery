"""UI tables for the Device Auto-Discovery plugin."""

import django_tables2 as tables
from nautobot.apps.tables import BaseTable

from nautobot_plugin_device_auto_discovery import models


class DiscoveryScanTable(BaseTable):
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
    name = tables.LinkColumn()
    status = tables.Column()

    class Meta:
        model = models.DiscoveryProfile
        fields = ("name", "status", "protocols", "included_ip_prefixes", "maximum_ip_addresses", "created")
        default_columns = ("name", "status", "protocols", "included_ip_prefixes", "created")


class DiscoveredDeviceTable(BaseTable):
    hostname = tables.LinkColumn()
    ip_address = tables.Column(verbose_name="IP Address")
    status = tables.Column(verbose_name="Correlation")
    vendor = tables.Column()
    device = tables.LinkColumn(verbose_name="Nautobot Device")
    last_seen = tables.DateTimeColumn(verbose_name="Last Seen")

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
            "last_seen",
        )
        default_columns = ("hostname", "ip_address", "status", "vendor", "device", "last_seen")
