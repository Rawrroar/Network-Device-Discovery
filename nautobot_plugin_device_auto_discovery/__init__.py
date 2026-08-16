"""Nautobot App Configuration for Device Auto-Discovery."""

from nautobot.apps import NautobotAppConfig


DEFAULT_PLUGINS_CONFIG = {
    "default_location": "Unknown",
    "default_role": "Network Device",
    "default_role_color": "006cd1",
    "default_status": "Active",
    "default_tags": ["auto-discovered"],
    "create_missing_objects": True,
    "snmp_timeout": 3,
    "snmp_retries": 2,
    "snmp_version": "2c",
    "snmp_community": "public",
    "snmpv3_username": "",
    "snmpv3_auth_protocol": "SHA",
    "snmpv3_auth_key": "",
    "snmpv3_priv_protocol": "AES",
    "snmpv3_priv_key": "",
    "snmpv3_context_name": "",
    "ssh_timeout": 10,
    "ssh_banner_timeout": 30,
    "ssh_port": 22,
    "ssh_username": "admin",
    "ssh_password": "",
    "ssh_port_check": True,
    "ssh_enable_password": "",
    "ping_timeout": 2,
    "concurrency": 10,
    "populate_interfaces": True,
    "populate_ip_addresses": True,
    "populate_vrfs": True,
    "populate_vlans": True,
    "include_neighbors": True,
    "include_vlans": True,
    "max_walk_oids": 1000,
}


class DeviceAutoDiscoveryConfig(NautobotAppConfig):
    name = "nautobot_plugin_device_auto_discovery"
    verbose_name = "Device Auto-Discovery"
    version = "0.3.4"
    author = "Developer"
    author_email = "dev@example.com"
    description = "Automatic network device discovery via ICMP ping, SNMP, and SSH."
    required_settings = []
    default_settings = DEFAULT_PLUGINS_CONFIG
    min_version = "3.0"
    max_version = "4.0"
    base_url = "device-auto-discovery"
    docs_view_name = "plugins:nautobot_plugin_device_auto_discovery:documentation"
    required_apps = []
    caching_config = {}

    def ready(self):
        super().ready()
        # Import jobs so they are registered at startup
        import nautobot_plugin_device_auto_discovery.jobs  # noqa: F401


config = DeviceAutoDiscoveryConfig
