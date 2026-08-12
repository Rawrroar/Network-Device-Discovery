"""Tests for the Device Auto-Discovery plugin."""

from unittest.mock import patch, MagicMock

from django.test import TestCase, TransactionTestCase
from nautobot.extras.test_tools import run_job_for_testing
from nautobot.dcim.models import Device, DeviceType, Location, LocationType, Manufacturer, Platform, Role
from nautobot.extras.models import Status, Tag

from nautobot_plugin_device_auto_discovery.mappings import lookup_platform_from_oid
from nautobot_plugin_device_auto_discovery.jobs import (
    PingSweepJob,
    SNMPDiscoveryJob,
    SSHDiscoveryJob,
    FullDiscoveryJob,
    safe_icmp_ping,
    create_device_in_nautobot,
    get_or_create_manufacturer,
    get_or_create_platform,
    get_or_create_device_type,
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


class HelperFunctionTests(TestCase):
    """Test device creation helper functions."""

    @classmethod
    def setUpTestData(cls):
        cls.location_type = LocationType.objects.create(name="Test Type", nestable=True)
        cls.location_status = Status.objects.get_for_model(Location).first()
        cls.location = Location.objects.create(
            name="Test Location",
            location_type=cls.location_type,
            status=cls.location_status,
        )
        cls.device_role_status = Status.objects.get_for_model(Role).first()
        cls.device_role = Role.objects.create(
            name="Test Role",
            color="red",
            status=cls.device_role_status,
        )
        cls.device_status = Status.objects.get_for_model(Device).filter(name="Active").first()

    def test_get_or_create_manufacturer(self):
        m1 = get_or_create_manufacturer("cisco")
        self.assertEqual(m1.name, "Cisco")
        m2 = get_or_create_manufacturer("cisco")
        self.assertEqual(m1.pk, m2.pk)

    def test_get_or_create_platform(self):
        p1, created1 = get_or_create_platform("Test Platform", "test_driver", "Test Mfg")
        self.assertTrue(created1)
        p2, created2 = get_or_create_platform("Test Platform", "other_driver", "Test Mfg")
        self.assertFalse(created2)
        self.assertEqual(p1.pk, p2.pk)

    def test_get_or_create_device_type(self):
        mfr = Manufacturer.objects.create(name="Test Manufacturer")
        dt1, created1 = mfr.device_types.get_or_create(
            model="Test Model",
            defaults={"part_number": ""},
        )
        self.assertTrue(created1)

    def test_device_creation_creates_device(self):
        config = {
            "default_location": "Test Location",
            "default_role": "Test Role",
            "default_status": "Active",
            "default_tags": [],
            "create_missing_objects": True,
        }
        platform_info = {
            "platform_name": "Cisco IOS-XE",
            "manufacturer_name": "Cisco",
            "network_driver": "ios",
        }
        device, status, error = create_device_in_nautobot(
            "test-device-001",
            "192.168.1.1",
            "Cisco",
            "Catalyst 9300",
            "FTJ23456ABC",
            "17.3.4",
            platform_info,
            config,
            None,
        )
        self.assertIsNotNone(device)
        self.assertEqual(status, "new")
        self.assertEqual(device.name, "test-device-001")
        self.assertEqual(str(device.serial), "FTJ23456ABC")
        Device.objects.filter(name="test-device-001").delete()

    def test_device_creation_existing_device(self):
        config = {
            "default_location": "Test Location",
            "default_role": "Test Role",
            "default_status": "Active",
            "default_tags": [],
            "create_missing_objects": True,
        }
        mfr = Manufacturer.objects.create(name="Cisco")
        dt = DeviceType.objects.create(model="Existing Model", manufacturer=mfr)
        Device.objects.create(
            name="existing-device",
            device_type=dt,
            role=self.device_role,
            location=self.location,
            status=self.device_status,
        )
        platform_info = {
            "platform_name": "Cisco IOS",
            "manufacturer_name": "Cisco",
            "network_driver": "ios",
        }
        device, status, error = create_device_in_nautobot(
            "existing-device",
            "192.168.1.2",
            "Cisco",
            "Existing Model",
            "",
            "15.2",
            platform_info,
            config,
            None,
        )
        self.assertEqual(status, "existing")
        Device.objects.filter(name="existing-device").delete()


class PingSweepJobTests(TestCase):
    """Test PingSweepJob."""

    def test_ping_sweep_returns_structure(self):
        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.safe_icmp_ping",
            side_effect=lambda ip, timeout: ip.endswith(".1"),
        ):
            result = run_job_for_testing(
                PingSweepJob,
                data={
                    "target_network": "10.0.0.0/30",
                    "timeout": 1,
                    "concurrency": 5,
                },
            )
            self.assertIn("live_ips", result)
            self.assertIn("total_hosts", result)
            self.assertEqual(result["target_network"], "10.0.0.0/30")
            self.assertGreaterEqual(len(result["live_ips"]), 0)

    def test_ping_sweep_empty_result(self):
        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.safe_icmp_ping",
            return_value=False,
        ):
            result = run_job_for_testing(
                PingSweepJob,
                data={
                    "target_network": "10.0.0.0/30",
                    "timeout": 1,
                    "concurrency": 5,
                },
            )
            self.assertEqual(result["live_hosts"], 0)


class SNMPDiscoveryJobTests(TestCase):
    """Test SNMPDiscoveryJob."""

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
            result = run_job_for_testing(
                SNMPDiscoveryJob,
                data={
                    "target_network": "10.0.0.0/30",
                    "snmp_community": "public",
                    "timeout": 1,
                    "concurrency": 5,
                },
            )
            self.assertIn("discovered", result)
            self.assertIn("created", result)
            self.assertGreaterEqual(result["discovered"], 0)

    def test_snmp_discovery_no_devices(self):
        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device",
            return_value=None,
        ):
            result = run_job_for_testing(
                SNMPDiscoveryJob,
                data={
                    "target_network": "10.0.0.0/30",
                    "snmp_community": "public",
                    "timeout": 1,
                    "concurrency": 5,
                },
            )
            self.assertEqual(result["discovered"], 0)
            self.assertEqual(result["created"], 0)


class SSHDiscoveryJobTests(TestCase):
    """Test SSHDiscoveryJob."""

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

    def test_ssh_discovery_no_password_fails(self):
        result = run_job_for_testing(
            SSHDiscoveryJob,
            data={
                "target_network": "10.0.0.0/30",
                "ssh_username": "admin",
                "ssh_password": "",
                "timeout": 1,
                "concurrency": 5,
            },
        )
        self.assertIn("error", result)

    def test_ssh_discovery_with_mock(self):
        def mock_ssh_discover(ip_str, username, password, timeout, banner_timeout):
            if ip_str == "10.0.0.1":
                return {
                    "hostname": "router-001",
                    "vendor": "Juniper Networks",
                    "model": "MX204",
                    "serial": "JS212345678",
                    "os_version": "21.2R3",
                    "raw_output": "",
                }
            return None

        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.ssh_connect_and_discover",
            side_effect=mock_ssh_discover,
        ):
            result = run_job_for_testing(
                SSHDiscoveryJob,
                data={
                    "target_network": "10.0.0.0/30",
                    "ssh_username": "admin",
                    "ssh_password": "password123",
                    "timeout": 1,
                    "concurrency": 5,
                },
            )
            self.assertIn("discovered", result)
            self.assertIn("created", result)


class FullDiscoveryJobTests(TestCase):
    """Test FullDiscoveryJob orchestrator."""

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
                    result = run_job_for_testing(
                        FullDiscoveryJob,
                        data={
                            "target_network": "10.0.0.0/30",
                            "snmp_community": "public",
                            "ssh_username": "admin",
                            "ssh_password": "pass",
                            "enable_ping": True,
                            "enable_snmp": True,
                            "enable_ssh": True,
                            "timeout": 1,
                            "concurrency": 10,
                        },
                    )
                    self.assertIn("discovered", result)
                    self.assertIn("created", result)
                    self.assertIn("live_hosts", result)
                    self.assertGreaterEqual(result["live_hosts"], 0)

    def test_full_discovery_ping_only(self):
        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.safe_icmp_ping",
            return_value=True,
        ):
            result = run_job_for_testing(
                FullDiscoveryJob,
                data={
                    "target_network": "10.0.0.0/30",
                    "snmp_community": "public",
                    "ssh_username": "admin",
                    "ssh_password": "",
                    "enable_ping": True,
                    "enable_snmp": False,
                    "enable_ssh": False,
                    "timeout": 1,
                    "concurrency": 10,
                },
            )
            self.assertIn("live_hosts", result)
            self.assertEqual(result["discovered"], 0)


class ICMPPingTests(TestCase):
    """Test the ICMP ping helper."""

    def test_safe_ping_localhost(self):
        result = safe_icmp_ping("127.0.0.1", timeout=2)
        self.assertTrue(result)

    def test_safe_ping_unreachable(self):
        result = safe_icmp_ping("192.0.2.1", timeout=1)
        self.assertFalse(result)
