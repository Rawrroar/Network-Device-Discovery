"""Nautobot App Configuration for Device Auto-Discovery."""

from nautobot.apps import NautobotAppConfig


DEFAULT_PLUGINS_CONFIG = {
    "default_location": "Unknown",
    "default_role": "Network Device",
    "default_status": "Active",
    "default_tags": ["auto-discovered"],
    "create_missing_objects": True,
    "snmp_timeout": 3,
    "snmp_retries": 2,
    "snmp_community": "public",
    "ssh_timeout": 10,
    "ssh_banner_timeout": 30,
    "ping_timeout": 2,
    "concurrency": 10,
}


class DeviceAutoDiscoveryConfig(NautobotAppConfig):
    name = "nautobot_plugin_device_auto_discovery"
    verbose_name = "Device Auto-Discovery"
    version = "0.1.0"
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
