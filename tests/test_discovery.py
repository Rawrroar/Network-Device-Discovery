"""Tests for the Device Auto-Discovery plugin.

Job-level tests run through ``NetworkDeviceDiscoveryJob`` (the registered
consolidated job) using DiscoveryProfiles to select phases. Helper and
engine functions are tested directly.
"""

import socket
from unittest.mock import patch, MagicMock

from django.test import TestCase, TransactionTestCase
from nautobot.extras.test_tools import run_job_for_testing
from nautobot.dcim.models import Device, DeviceType, Interface, Location, LocationType, Manufacturer, Platform
from nautobot.extras.models import Role
from nautobot.extras.models import Status, Tag
from nautobot.ipam.models import IPAddress, Prefix, VLAN, VLANGroup

from nautobot_plugin_device_auto_discovery.mappings import lookup_platform_from_oid
from nautobot_plugin_device_auto_discovery.models import DiscoveryProfile, DiscoveryResult
from nautobot_plugin_device_auto_discovery.jobs import (
    NetworkDeviceDiscoveryJob,
    FullDiscoveryJob,
    safe_icmp_ping,
    create_device_in_nautobot,
    ensure_parent_prefix,
    network_prefix_for,
    get_or_create_manufacturer,
    get_or_create_platform,
    get_or_create_device_type,
    ssh_connect_and_discover,
    tcp_port_open,
    detect_vendor_from_descr,
    parse_model_from_descr,
    snmp_discover_device,
    _parse_ssh_output,
)


class OIDMappingTests(TestCase):
    """Test SNMP OID to platform mapping."""

    def test_cisco_ios_xe(self):
        result = lookup_platform_from_oid("1.3.6.1.4.1.9.1.675.1.2.3")
        self.assertEqual(result["platform_name"], "Cisco IOS-XE")
        self.assertEqual(result["manufacturer_name"], "Cisco")
        self.assertEqual(result["network_driver"], "ios")

    def test_juniper_junos(self):
        result = lookup_platform_from_oid("1.3.6.1.4.1.2636.1.1.1.1")
        self.assertEqual(result["platform_name"], "Juniper Junos")
        self.assertEqual(result["manufacturer_name"], "Juniper Networks")
        self.assertEqual(result["network_driver"], "junos")

    def test_arista_eos(self):
        result = lookup_platform_from_oid("1.3.6.1.4.1.30065.3.1.2")
        self.assertEqual(result["platform_name"], "Arista EOS")
        self.assertEqual(result["manufacturer_name"], "Arista Networks")
        self.assertEqual(result["network_driver"], "eos")

    def test_unknown_oid(self):
        result = lookup_platform_from_oid("1.3.6.1.4.1.99999.1.1")
        self.assertIsNone(result)

    def test_empty_oid(self):
        result = lookup_platform_from_oid("")
        self.assertIsNone(result)

    def test_none_oid(self):
        result = lookup_platform_from_oid(None)
        self.assertIsNone(result)

    def test_palo_alto(self):
        result = lookup_platform_from_oid("1.3.6.1.4.1.25461.2.1")
        self.assertEqual(result["platform_name"], "Palo Alto PAN-OS")

    def test_fortinet(self):
        result = lookup_platform_from_oid("1.3.6.1.4.1.12356.101.1.1")
        self.assertEqual(result["platform_name"], "Fortinet FortiOS")

    def test_ubiquiti_edgeos(self):
        result = lookup_platform_from_oid("1.3.6.1.4.1.41112.1.3.1")
        self.assertEqual(result["platform_name"], "Ubiquiti EdgeOS")

    def test_ubiquiti_unifi_generic_oid(self):
        result = lookup_platform_from_oid("1.3.6.1.4.1.41112.1.11.1")
        self.assertEqual(result["platform_name"], "Ubiquiti UniFi")
        self.assertEqual(result["manufacturer_name"], "Ubiquiti")

    def test_epson(self):
        result = lookup_platform_from_oid("1.3.6.1.4.1.1248.1.1.1")
        self.assertEqual(result["manufacturer_name"], "Seiko Epson")

    def test_epson_generic_oid(self):
        result = lookup_platform_from_oid("1.3.6.1.4.1.1248.3.2")
        self.assertEqual(result["manufacturer_name"], "Seiko Epson")

    def test_vendor_detection_epson(self):
        self.assertEqual(detect_vendor_from_descr("EPSON XP-8700"), "Seiko Epson")

    def test_vendor_detection_ucos(self):
        self.assertEqual(detect_vendor_from_descr("UCOS 4.1.16850"), "Ubiquiti")


class SNMPDetectionTests(TestCase):
    """Unit tests for vendor/model detection in snmp_discover_device."""

    def _run(self, system, physical):
        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.discover_snmp_tables",
            return_value={
                "system": system,
                "physical": physical,
                "interfaces": [],
                "ip_addresses": [],
                "arp_table": [],
                "neighbors": [],
                "vlans": [],
            },
        ):
            return snmp_discover_device("10.0.0.1", {"snmp_community": "public"})

    def test_vendor_and_model_from_physical_inventory(self):
        info = self._run(
            {"sys_name": "", "sys_descr": "", "sys_object_id": ""},
            [
                {"class": 3, "descr": "Cisco WS-C2960-24TT-L", "serial": "FOC1234A5B6", "model": ""},
            ],
        )
        self.assertEqual(info["vendor"], "Cisco")
        self.assertEqual(info["serial"], "FOC1234A5B6")

    def test_os_version_from_sysdescr(self):
        info = self._run(
            {"sys_name": "sw1", "sys_descr": "Cisco IOS Software, Version 15.2(2)E7", "sys_object_id": ""},
            [],
        )
        self.assertEqual(info["os_version"], "15.2")

    def test_no_response_returns_none(self):
        info = self._run({"sys_name": "", "sys_descr": "", "sys_object_id": ""}, [])
        self.assertIsNone(info)


class HelperFunctionTests(TransactionTestCase):
    """Test device creation and helper functions."""

    @classmethod
    def setUpTestData(cls):
        cls.location_type = LocationType.objects.create(name="Helper Type", nestable=True)
        cls.location_status = Status.objects.get_for_model(Location).first()
        cls.location = Location.objects.create(
            name="Helper Location",
            location_type=cls.location_type,
            status=cls.location_status,
        )
        cls.device_role_status = Status.objects.get_for_model(Role).first()
        cls.device_role = Role.objects.create(
            name="Helper Role",
            color="red",
            status=cls.device_role_status,
        )

    def test_network_prefix_for(self):
        self.assertEqual(network_prefix_for("192.168.1.77", 24), "192.168.1.0/24")
        self.assertEqual(network_prefix_for("192.168.1.77", 32), "192.168.1.77/32")

    def test_get_or_create_manufacturer(self):
        mfr = get_or_create_manufacturer("Acme")
        self.assertEqual(mfr.name, "Acme")
        again = get_or_create_manufacturer("Acme")
        self.assertEqual(mfr.pk, again.pk)

    def test_get_or_create_device_type(self):
        mfr = get_or_create_manufacturer("Acme Type Test")
        dt = get_or_create_device_type(mfr, "Model-X1")
        self.assertEqual(dt.model, "Model-X1")

    def test_get_or_create_platform(self):
        platform = get_or_create_platform("cisco_ios", "Cisco IOS", "Cisco")
        self.assertEqual(platform.network_driver, "cisco_ios")

    def test_create_device_in_nautobot_creates_and_populates(self):
        config = {}
        platform_info = {
            "platform_name": "cisco_ios",
            "manufacturer_name": "Cisco",
            "network_driver": "cisco_ios",
        }
        device, status, error = create_device_in_nautobot(
            "helper-switch-01",
            "10.50.0.1",
            "Cisco",
            "C9300",
            "SN-HElper-01",
            "17.3",
            platform_info,
            config,
            None,
        )
        self.assertEqual(status, "new")
        self.assertEqual(device.name, "helper-switch-01")
        self.assertIsNotNone(device.primary_ip4)

    def test_create_device_updates_existing_serial(self):
        config = {}
        platform_info = {
            "platform_name": "cisco_ios",
            "manufacturer_name": "Cisco",
            "network_driver": "cisco_ios",
        }
        first, status, _ = create_device_in_nautobot(
            "helper-switch-02",
            "10.50.0.2",
            "Cisco",
            "C9300",
            "",
            "17.3",
            platform_info,
            config,
            None,
        )
        self.assertEqual(status, "new")
        updated, status, error = create_device_in_nautobot(
            "helper-switch-02",
            "10.50.0.2",
            "Cisco",
            "No Serial Model",
            "FTJ987654AB",
            "15.2",
            platform_info,
            config,
            None,
        )
        self.assertEqual(status, "existing")
        self.assertEqual(str(updated.serial), "FTJ987654AB")
        Device.objects.filter(name="no-serial-device").delete()


class _ConsolidatedJobTestMixin:
    """Shared helpers for NetworkDeviceDiscoveryJob phase tests."""

    @staticmethod
    def _make_profile(name, protocols, prefix="10.0.0.0/30"):
        return DiscoveryProfile.objects.create(
            name=name,
            included_ip_prefixes=[prefix],
            protocols=list(protocols),
        )

    def _run_job(self, profile, **overrides):
        data = {
            "target_network": profile.included_ip_prefixes[0] if profile.included_ip_prefixes else "10.0.0.0/30",
            "profile": profile,
            "snmp_version": "2c",
            "snmp_community": "public",
            "snmpv3_username": "",
            "snmpv3_auth_key": "",
            "snmpv3_priv_key": "",
            "snmpv3_context_name": "",
            "ssh_username": "admin",
            "ssh_password": "password123",
            "enable_ping": True,
            "enable_snmp": True,
            "enable_ssh": True,
            "populate_interfaces": True,
            "populate_ip_addresses": True,
            "populate_vrfs": True,
            "include_neighbors": True,
            "include_vlans": True,
            "populate_vlans": True,
            "create_cables": True,
            "create_devices": True,
            "dryrun": False,
            "timeout": 1,
            "concurrency": 5,
        }
        data.update(overrides)
        return run_job_for_testing(NetworkDeviceDiscoveryJob, data=data)


class SNMPPhaseTests(_ConsolidatedJobTestMixin, TestCase):
    """SNMP-phase behavior of NetworkDeviceDiscoveryJob (profile protocols=['snmp'])."""

    @classmethod
    def setUpTestData(cls):
        cls.location_type = LocationType.objects.create(name="SNMP Test Type", nestable=True)
        cls.location_status = Status.objects.get_for_model(Location).first()
        cls.location = Location.objects.create(
            name="SNMP Test Location",
            location_type=cls.location_type,
            status=cls.location_status,
        )
        cls.device_role_status = Status.objects.get_for_model(Role).first()
        cls.device_role = Role.objects.create(
            name="SNMP Test Role",
            color="green",
            status=cls.device_role_status,
        )
        cls.profile = cls._make_profile.__func__(cls, "SNMP Phase Profile", ["snmp"])

    def test_snmp_discovery_with_mock(self):
        def mock_snmp_discover(ip_str, config):
            if ip_str == "10.0.0.1":
                return {
                    "hostname": "switch-001",
                    "sys_descr": "Cisco Catalyst 9300, IOS-XE 17.3",
                    "sys_object_id": "1.3.6.1.4.1.9.1.675.1.2.3",
                    "platform_info": {
                        "platform_name": "Cisco IOS-XE",
                        "manufacturer_name": "Cisco",
                        "network_driver": "ios",
                    },
                    "vendor": "Cisco",
                    "model": "Catalyst 9300",
                    "serial": "FCW2134ABCD",
                    "os_version": "IOS-XE 17.3",
                }
            return None

        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device",
            side_effect=mock_snmp_discover,
        ):
            result = self._run_job(self.profile, enable_ssh=False)
            self.assertIn("discovered", result)
            self.assertIn("created", result)
            self.assertGreaterEqual(result["discovered"], 0)

    def test_snmp_discovery_v3_passes_usm_config(self):
        captured = {}

        def mock_snmp_discover(ip_str, config):
            captured["config"] = config
            return None

        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device",
            side_effect=mock_snmp_discover,
        ):
            self._run_job(
                self.profile,
                snmp_version="3",
                snmpv3_username="discover",
                snmpv3_auth_protocol="SHA-256",
                snmpv3_auth_key="auth-pass",
                snmpv3_priv_protocol="AES-192",
                snmpv3_priv_key="priv-pass",
                snmpv3_context_name="ctx",
            )

        self.assertEqual(captured["config"]["snmp_version"], "3")
        self.assertEqual(captured["config"]["snmpv3_username"], "discover")
        self.assertEqual(captured["config"]["snmpv3_auth_protocol"], "SHA-256")
        self.assertEqual(captured["config"]["snmpv3_auth_key"], "auth-pass")
        self.assertEqual(captured["config"]["snmpv3_priv_protocol"], "AES-192")
        self.assertEqual(captured["config"]["snmpv3_priv_key"], "priv-pass")
        self.assertEqual(captured["config"]["snmpv3_context_name"], "ctx")

    def test_snmp_discovery_v3_without_username_fails(self):
        result = self._run_job(self.profile, snmp_version="3", snmpv3_username="")
        self.assertIn("error", result)

    def test_snmp_discovery_no_devices(self):
        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device",
            return_value=None,
        ):
            result = self._run_job(self.profile)
            self.assertEqual(result["discovered"], 0)
            self.assertEqual(result["created"], 0)

    @staticmethod
    def _table_aware_snmp_discover(ip_str, config):
        if ip_str == "10.0.0.1":
            return {
                "hostname": "switch-001",
                "sys_descr": "Cisco Catalyst 9300, IOS-XE 17.3",
                "sys_object_id": "1.3.6.1.4.1.9.1.675.1.2.3",
                "platform_info": {
                    "platform_name": "Cisco IOS-XE",
                    "manufacturer_name": "Cisco",
                    "network_driver": "ios",
                },
                "vendor": "Cisco",
                "model": "Catalyst 9300",
                "serial": "FCW2134ABCD",
                "os_version": "IOS-XE 17.3",
                "sys_contact": "noc@example.com",
                "sys_location": "DC1 Row 3",
                "interfaces": [
                    {
                        "index": "1",
                        "name": "GigabitEthernet0/0/1",
                        "descr": "GigabitEthernet0/0/1",
                        "type": "1000base-t",
                        "mtu": 1500,
                        "speed": 1000000,
                        "mac": "00:11:22:33:44:55",
                        "admin_status": 1,
                        "oper_status": 1,
                        "alias": "Uplink",
                    },
                    {
                        "index": "2",
                        "name": "Loopback0",
                        "descr": "Loopback0",
                        "type": "virtual",
                        "mtu": 1514,
                        "speed": None,
                        "mac": "",
                        "admin_status": 1,
                        "oper_status": 1,
                        "alias": "",
                    },
                ],
                "ip_addresses": [
                    {"address": "10.0.0.1", "prefix_length": 24, "if_index": "1"},
                ],
                "arp_table": [{"if_index": "1", "ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:01"}],
                "physical": [{"class": 3, "descr": "Chassis", "serial": "FCW2134ABCD"}],
                "neighbors": [
                    {
                        "protocol": "lldp",
                        "local_if_index": "1",
                        "local_port_num": "1",
                        "remote_name": "spine-001",
                        "remote_port": "GigabitEthernet0/1",
                        "remote_description": "Cisco IOS-XE",
                        "remote_ip": "",
                        "remote_chassis_id": "00:11:22:33:44:55",
                    },
                ],
                "vlans": [
                    {"vid": 1, "name": "default", "row_status": 1},
                    {"vid": 10, "name": "Management", "row_status": 1},
                ],
                "interfaces_found": 2,
                "ip_addresses_found": 1,
                "neighbors_found": 1,
                "vlans_found": 2,
            }
        return None

    def test_snmp_discovery_populates_interfaces_and_ips(self):
        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device",
            side_effect=self._table_aware_snmp_discover,
        ):
            result = self._run_job(self.profile)
            self.assertEqual(result["discovered"], 1)
            self.assertEqual(result["created"], 1)

        device = Device.objects.get(name="switch-001")
        self.assertEqual(str(device.serial), "FCW2134ABCD")

        iface = Interface.objects.get(device=device, name="GigabitEthernet0/0/1")
        self.assertEqual(iface.type, "1000base-t")
        self.assertEqual(iface.mac_address, "00:11:22:33:44:55")
        self.assertEqual(iface.speed, 1000000)
        self.assertEqual(iface.description, "Uplink")
        self.assertTrue(iface.enabled)

        self.assertTrue(Interface.objects.filter(device=device, name="Loopback0", type="virtual").exists())

        ip_obj = IPAddress.objects.get(address="10.0.0.1/24")
        self.assertEqual(ip_obj.assigned_object, iface)
        self.assertEqual(device.primary_ip4, ip_obj)

        discovery_result = DiscoveryResult.objects.get(ip_address="10.0.0.1")
        self.assertEqual(discovery_result.interfaces_found, 2)
        self.assertEqual(discovery_result.ip_addresses_found, 1)
        self.assertEqual(discovery_result.neighbors_found, 1)
        self.assertEqual(discovery_result.vlans_found, 2)
        self.assertEqual(discovery_result.sys_location, "DC1 Row 3")
        self.assertEqual(discovery_result.sys_contact, "noc@example.com")
        self.assertIn("interfaces", discovery_result.discovered_data)
        self.assertEqual(len(discovery_result.discovered_data["neighbors"]), 1)
        self.assertEqual(len(discovery_result.discovered_data["vlans"]), 2)

        vlan_group = VLANGroup.objects.get(name="switch-001 VLANs")
        self.assertEqual(VLAN.objects.filter(vlan_group=vlan_group).count(), 2)
        vlan10 = VLAN.objects.get(vlan_group=vlan_group, vid=10)
        self.assertEqual(vlan10.name, "Management")

    def test_snmp_discovery_idempotent_on_existing_device(self):
        for _ in range(2):
            with patch(
                "nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device",
                side_effect=self._table_aware_snmp_discover,
            ):
                result = self._run_job(self.profile)
                self.assertEqual(result["discovered"], 1)

        device = Device.objects.get(name="switch-001")
        self.assertEqual(device.interfaces.count(), 2)
        self.assertEqual(IPAddress.objects.filter(host="10.0.0.1", mask_length=24).count(), 1)
        vlan_group = VLANGroup.objects.get(name="switch-001 VLANs")
        self.assertEqual(VLAN.objects.filter(vlan_group=vlan_group).count(), 2)

    def test_snmp_discovery_dry_run_creates_nothing(self):
        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device",
            side_effect=self._table_aware_snmp_discover,
        ):
            result = self._run_job(self.profile, dryrun=True)
            self.assertEqual(result["discovered"], 1)
            self.assertEqual(result["created"], 0)

        self.assertFalse(Device.objects.filter(name="switch-001").exists())
        self.assertFalse(IPAddress.objects.filter(host="10.0.0.1", mask_length=24).exists())
        self.assertFalse(VLANGroup.objects.filter(name="switch-001 VLANs").exists())

        discovery_result = DiscoveryResult.objects.get(ip_address="10.0.0.1")
        self.assertIn("interfaces", discovery_result.discovered_data)
        self.assertIsNone(discovery_result.nautobot_device)
        self.assertIn("Dry-run", discovery_result.error_message)

    def test_snmp_discovery_populate_toggle_off(self):
        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device",
            side_effect=self._table_aware_snmp_discover,
        ):
            result = self._run_job(
                self.profile,
                populate_interfaces=False,
                populate_ip_addresses=False,
                populate_vlans=False,
            )
            self.assertEqual(result["created"], 1)

        device = Device.objects.get(name="switch-001")
        self.assertEqual(device.interfaces.count(), 0)
        self.assertFalse(IPAddress.objects.filter(host="10.0.0.1", mask_length=24).exists())
        self.assertFalse(VLANGroup.objects.filter(name="switch-001 VLANs").exists())


class SSHPhaseTests(_ConsolidatedJobTestMixin, TestCase):
    """SSH-phase behavior of NetworkDeviceDiscoveryJob (profile protocols=['ssh'])."""

    @classmethod
    def setUpTestData(cls):
        cls.location_type = LocationType.objects.create(name="SSH Test Type", nestable=True)
        cls.location_status = Status.objects.get_for_model(Location).first()
        cls.location = Location.objects.create(
            name="SSH Test Location",
            location_type=cls.location_type,
            status=cls.location_status,
        )
        cls.device_role_status = Status.objects.get_for_model(Role).first()
        cls.device_role = Role.objects.create(
            name="SSH Test Role",
            color="purple",
            status=cls.device_role_status,
        )
        cls.profile = cls._make_profile.__func__(cls, "SSH Phase Profile", ["ssh"])

    def test_ssh_phase_requires_credentials(self):
        result = self._run_job(self.profile, ssh_username="", ssh_password="")
        self.assertIn("error", result)
        self.assertIn("SSH credentials", result["error"])

    def test_ssh_discovery_with_mock(self):
        captured = {}

        def mock_ssh_discover(ip_str, username, password, timeout, banner_timeout, port=22, enable_password=None, port_check=True):
            captured["port"] = port
            captured["username"] = username
            if ip_str == "10.0.0.1":
                return {
                    "hostname": "router-001",
                    "vendor": "Juniper Networks",
                    "model": "MX204",
                    "serial": "JS212345678",
                    "os_version": "21.2R3",
                    "raw_output": "",
                    "command_outputs": {"show version": "Model: MX204"},
                }
            return None

        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.ssh_connect_and_discover",
            side_effect=mock_ssh_discover,
        ):
            result = self._run_job(self.profile, ssh_port=22)
            self.assertIn("discovered", result)
            self.assertIn("created", result)
            self.assertEqual(captured["port"], 22)
            self.assertEqual(captured["username"], "admin")

        discovery_result = DiscoveryResult.objects.get(ip_address="10.0.0.1")
        self.assertEqual(discovery_result.discovery_method, "ssh")
        self.assertIn("command_outputs", discovery_result.discovered_data)
        self.assertEqual(discovery_result.discovered_data["command_outputs"]["show version"], "Model: MX204")

    def test_ssh_discovery_dry_run_creates_nothing(self):
        def mock_ssh_discover(ip_str, username, password, timeout, banner_timeout, port=22, enable_password=None, port_check=True):
            if ip_str == "10.0.0.1":
                return {
                    "hostname": "router-002",
                    "vendor": "Cisco",
                    "model": "C9300",
                    "serial": "FOC11111111",
                    "os_version": "17.3",
                    "raw_output": "",
                    "command_outputs": {},
                }
            return None

        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.ssh_connect_and_discover",
            side_effect=mock_ssh_discover,
        ):
            result = self._run_job(self.profile, dryrun=True)
            self.assertEqual(result["discovered"], 1)
            self.assertEqual(result["created"], 0)

        self.assertFalse(Device.objects.filter(name="router-002").exists())

        discovery_result = DiscoveryResult.objects.get(ip_address="10.0.0.1")
        self.assertIsNone(discovery_result.nautobot_device)
        self.assertIn("Dry-run", discovery_result.error_message)

    def test_ssh_discovery_uses_config_defaults(self):
        captured = {}

        def mock_ssh_discover(ip_str, username, password, timeout, banner_timeout, port=22, enable_password=None, port_check=True):
            captured.update(username=username, password=password, port=port)
            if ip_str == "10.0.0.1":
                return {
                    "hostname": "router-003",
                    "vendor": "Cisco",
                    "model": "C9300",
                    "serial": "",
                    "os_version": "",
                    "command_outputs": {},
                }
            return None

        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.get_plugin_config",
            return_value={
                "ssh_username": "ops",
                "ssh_password": "secret",
                "ssh_port": 2222,
                "ssh_banner_timeout": 5,
            },
        ):
            with patch(
                "nautobot_plugin_device_auto_discovery.jobs.ssh_connect_and_discover",
                side_effect=mock_ssh_discover,
            ):
                result = self._run_job(self.profile, ssh_username="", ssh_password="")
                self.assertEqual(result["created"], 1)

        self.assertEqual(captured["username"], "ops")
        self.assertEqual(captured["password"], "secret")
        self.assertEqual(captured["port"], 22)


class SSHFakeChannel:
    """Minimal fake of a paramiko channel backed by scripted byte responses."""

    def __init__(self, initial=b"", responses=()):
        self.buffer = initial
        self.responses = list(responses)
        self.sent = []
        self.timeout = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def send(self, data):
        self.sent.append(data.decode("utf-8").strip())
        if self.responses:
            self.buffer += self.responses.pop(0)
        return len(data)

    def recv(self, n):
        if self.buffer:
            data, self.buffer = self.buffer[:n], self.buffer[n:]
            return data
        raise socket.timeout()


class SSHFakeClient:
    """Minimal fake of a paramiko SSHClient."""

    def __init__(self, channel):
        self.channel = channel
        self.connect_kwargs = {}
        self.closed = False

    def set_missing_host_key_policy(self, policy):
        pass

    def connect(self, **kwargs):
        self.connect_kwargs = kwargs

    def invoke_shell(self):
        return self.channel

    def close(self):
        self.closed = True


class SSHConnectionTests(TestCase):
    """Unit tests for the SSH connection/discovery helper."""

    CISCO_BANNER = "Cisco IOS switch\nswitch-001>\n"
    CISCO_SHOW_VERSION = (
        "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.2(2)E7, RELEASE SOFTWARE (fc1)\n"
        "cisco WS-C2960-24TT-L (PowerPC405) processor (revision C0) with 65536K/4088K bytes of memory.\n"
        "Processor board ID FOC1234A5B6\n"
        "switch-001#\n"
    )
    CISCO_SHOW_INVENTORY = (
        'NAME: "Chassis", DESCR: "Cisco WS-C2960-24TT-L"\n'
        "PID: WS-C2960-24TT-L , VID: V02, SN: FOC1234A5B6\n"
        "switch-001#\n"
    )
    JUNIPER_BANNER = "Juniper Networks\n--- JUNOS 21.2R3.15 Kernel 64-bit ---\n{master:0}\nroot@mx204>\n"
    JUNIPER_SHOW_VERSION = (
        "Hostname: mx204-01\n"
        "Model: mx204\n"
        "Junos: 21.2R3.15\n"
        "JUNOS Base OS boot [21.2R3.15]\n"
        "{master:0}\n"
    )
    JUNIPER_SHOW_CHASSIS = (
        "Hardware inventory:\n"
        "Item             Version  Part number  Serial number     Description\n"
        "Chassis                                JN1234567890      MX204\n"
    )

    def _run_fake(self, banner, responses):
        """Run ssh_connect_and_discover against a fake client and return the result."""
        channel = SSHFakeChannel(initial=banner, responses=responses)
        client = SSHFakeClient(channel)
        fake_paramiko = MagicMock()
        fake_paramiko.SSHClient.return_value = client
        fake_paramiko.AutoAddPolicy = MagicMock()
        with patch.dict("sys.modules", {"paramiko": fake_paramiko}):
            return ssh_connect_and_discover(
                "10.0.0.1",
                "admin",
                "password",
                timeout=5,
                port=22,
                enable_password="enablepw",
                port_check=False,
            )

    def test_parser_cisco(self):
        combined = "\n".join([self.CISCO_BANNER, self.CISCO_SHOW_VERSION, self.CISCO_SHOW_INVENTORY])
        hostname, model, serial, os_version = _parse_ssh_output(combined, "Cisco")
        self.assertEqual(hostname, "switch-001")
        self.assertEqual(model, "WS-C2960-24TT-L")
        self.assertEqual(serial, "FOC1234A5B6")
        self.assertEqual(os_version, "15.2(2)E7")

    def test_parser_juniper(self):
        combined = "\n".join([self.JUNIPER_BANNER, self.JUNIPER_SHOW_VERSION, self.JUNIPER_SHOW_CHASSIS])
        hostname, model, serial, os_version = _parse_ssh_output(combined, "Juniper Networks")
        self.assertEqual(hostname, "mx204-01")
        self.assertEqual(model, "mx204")
        self.assertEqual(serial, "JN1234567890")
        self.assertEqual(os_version, "21.2R3.15")

    def test_parser_generic_fallback(self):
        combined = "Some unknown device output\nModel: UltraSwitch 9000\n"
        hostname, model, serial, os_version = _parse_ssh_output(combined, "")
        self.assertIn(model, ("UltraSwitch", ""))


class ConsolidatedDiscoveryJobTests(_ConsolidatedJobTestMixin, TestCase):
    """Full three-phase orchestration through NetworkDeviceDiscoveryJob."""

    @classmethod
    def setUpTestData(cls):
        cls.location_type = LocationType.objects.create(name="Full Test Type", nestable=True)
        cls.location_status = Status.objects.get_for_model(Location).first()
        cls.location = Location.objects.create(
            name="Full Test Location",
            location_type=cls.location_type,
            status=cls.location_status,
        )
        cls.device_role_status = Status.objects.get_for_model(Role).first()
        cls.device_role = Role.objects.create(
            name="Full Test Role",
            color="orange",
            status=cls.device_role_status,
        )
        cls.profile_full = cls._make_profile.__func__(cls, "NDD All Phases", ["ping", "snmp", "ssh"])
        cls.profile_ping_only = cls._make_profile.__func__(cls, "NDD Ping Only", ["ping"])

    def test_full_discovery_runs_all_phases(self):
        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.safe_icmp_ping",
            side_effect=lambda ip, timeout: ip.endswith(".1") or ip.endswith(".2"),
        ):
            with patch(
                "nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device",
                side_effect=lambda ip_str, config: {
                    "hostname": "switch-full-001",
                    "sys_descr": "Cisco Catalyst 9300, IOS-XE",
                    "sys_object_id": "1.3.6.1.4.1.9.1.675.1.2.3",
                    "platform_info": {
                        "platform_name": "Cisco IOS-XE",
                        "manufacturer_name": "Cisco",
                        "network_driver": "ios",
                    },
                    "vendor": "Cisco",
                    "model": "Catalyst 9300",
                    "serial": "SN123456",
                    "os_version": "IOS-XE 17.3",
                } if ip_str == "10.0.0.1" else None,
            ):
                with patch(
                    "nautobot_plugin_device_auto_discovery.jobs.ssh_connect_and_discover",
                    return_value=None,
                ):
                    result = self._run_job(self.profile_full)
                    self.assertIn("discovered", result)
                    self.assertIn("created", result)
                    self.assertIn("live_hosts", result)
                    self.assertGreaterEqual(result["live_hosts"], 0)

    def test_ping_only_profile(self):
        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.safe_icmp_ping",
            return_value=True,
        ):
            result = self._run_job(self.profile_ping_only, ssh_password="")
            self.assertIn("live_hosts", result)
            self.assertEqual(result["discovered"], 0)

    def test_requires_profile(self):
        result = NetworkDeviceDiscoveryJob().run(
            target_network="10.0.0.0/30",
            snmp_version="2c",
            snmp_community="public",
            ssh_username="",
            ssh_password="",
            enable_ping=True,
            enable_snmp=True,
            enable_ssh=True,
            populate_interfaces=True,
            populate_ip_addresses=True,
            populate_vrfs=True,
            include_neighbors=True,
            include_vlans=True,
            populate_vlans=True,
            create_cables=True,
            profile=None,
            create_devices=True,
            dryrun=True,
            timeout=1,
            concurrency=5,
        )
        self.assertIn("error", result)
        self.assertIn("Discovery Profile is required", result["error"])

    def test_job_registered(self):
        from nautobot.core.celery import registry

        self.assertEqual(NetworkDeviceDiscoveryJob.name, "Network Device Discovery")
        self.assertIn(
            "nautobot_plugin_device_auto_discovery.jobs.NetworkDeviceDiscoveryJob",
            registry["jobs"],
        )
        # Removed jobs are no longer registered
        for removed in (
            "nautobot_plugin_device_auto_discovery.jobs.PingSweepJob",
            "nautobot_plugin_device_auto_discovery.jobs.SNMPDiscoveryJob",
            "nautobot_plugin_device_auto_discovery.jobs.SSHDiscoveryJob",
            "nautobot_plugin_device_auto_discovery.jobs.FullDiscoveryJob",
        ):
            self.assertNotIn(removed, registry["jobs"])


class ICMPPingTests(TestCase):
    """Test the ICMP ping helper."""

    def test_safe_ping_localhost(self):
        result = safe_icmp_ping("127.0.0.1", timeout=2)
        self.assertTrue(result)

    def test_safe_ping_unreachable(self):
        result = safe_icmp_ping("192.0.2.1", timeout=1)
        self.assertFalse(result)
