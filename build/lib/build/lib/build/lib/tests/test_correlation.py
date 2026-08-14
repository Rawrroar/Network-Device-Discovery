"""Tests for inventory correlation, domain stripping, and profile wiring."""

from unittest.mock import patch

from django.test import TestCase
from nautobot.dcim.models import Device, DeviceType, Location, LocationType, Manufacturer
from nautobot.extras.models import Role, Status
from nautobot.extras.test_tools import run_job_for_testing
from nautobot.ipam.models import IPAddress

from nautobot_plugin_device_auto_discovery.correlation import correlate_device
from nautobot_plugin_device_auto_discovery.jobs import SNMPDiscoveryJob, ensure_parent_prefix
from nautobot_plugin_device_auto_discovery.models import DiscoveredDevice, DiscoveryProfile, DiscoveryResult
from nautobot_plugin_device_auto_discovery.utils import strip_domain_suffixes


class StripDomainSuffixTests(TestCase):
    """Unit tests for utils.strip_domain_suffixes."""

    def test_no_suffixes(self):
        self.assertEqual(
            strip_domain_suffixes("switch-001.example.com", []),
            "switch-001.example.com",
        )

    def test_single_match(self):
        self.assertEqual(
            strip_domain_suffixes("switch-001.example.com", ["example.com"]),
            "switch-001",
        )

    def test_longest_match_wins(self):
        self.assertEqual(
            strip_domain_suffixes("switch-001.sub.example.com", ["example.com", "sub.example.com"]),
            "switch-001",
        )

    def test_no_match(self):
        self.assertEqual(
            strip_domain_suffixes("switch-001.example.com", ["other.net"]),
            "switch-001.example.com",
        )

    def test_case_insensitive(self):
        self.assertEqual(
            strip_domain_suffixes("SWITCH-001.EXAMPLE.COM", ["Example.COM"]),
            "SWITCH-001",
        )

    def test_trailing_root_dot_tolerated(self):
        self.assertEqual(
            strip_domain_suffixes("switch-001.example.com.", ["example.com"]),
            "switch-001",
        )

    def test_dot_boundary_required(self):
        self.assertEqual(
            strip_domain_suffixes("notexample.com", ["example.com"]),
            "notexample.com",
        )

    def test_leading_and_trailing_dots_in_config(self):
        self.assertEqual(
            strip_domain_suffixes("switch-001.example.com", [".example.com."]),
            "switch-001",
        )


class CorrelationTests(TestCase):
    """Unit tests for the inventory correlation engine."""

    @classmethod
    def setUpTestData(cls):
        cls.location_type = LocationType.objects.create(name="Corr Type", nestable=True)
        cls.location = Location.objects.create(
            name="Corr Location",
            location_type=cls.location_type,
            status=Status.objects.get_for_model(Location).first(),
        )
        cls.role = Role.objects.create(
            name="Corr Role",
            color="blue",
            status=Status.objects.get_for_model(Role).first(),
        )
        cls.device_status = Status.objects.get_for_model(Device).filter(name="Active").first()
        cls.mfr = Manufacturer.objects.create(name="Corr Mfr")
        cls.dt = DeviceType.objects.create(model="Corr 9300", manufacturer=cls.mfr)

    def _device(self, name, serial="", ip_str=None):
        device = Device.objects.create(
            name=name,
            device_type=self.dt,
            role=self.role,
            location=self.location,
            status=self.device_status,
        )
        if serial:
            device.serial = serial
            device.save()
        if ip_str:
            ensure_parent_prefix(ip_str, 32)
            ip_obj, _ = IPAddress.objects.get_or_create(
                address=ip_str + "/32",
                defaults={
                    "status": Status.objects.get_for_model(IPAddress).filter(name="Active").first(),
                },
            )
            device.primary_ip4 = ip_obj
            device.save(update_fields=["primary_ip4"])
        return device

    def test_new(self):
        result = correlate_device("10.0.0.50", "ghost", "NOPE")
        self.assertEqual(result["status"], "new")
        self.assertIsNone(result["device"])
        self.assertEqual(result["matches"], [])

    def test_imported_by_all_attributes(self):
        self._device("switch-a", serial="SN123", ip_str="10.0.0.1")
        result = correlate_device("10.0.0.1", "switch-a", "SN123")
        self.assertEqual(result["status"], "imported")
        self.assertIsNotNone(result["device"])
        self.assertTrue(all(result["attributes"].values()))

    def test_imported_by_hostname_only(self):
        self._device("switch-b")
        result = correlate_device("10.0.0.2", "switch-b", "")
        self.assertEqual(result["status"], "imported")
        self.assertTrue(result["attributes"]["hostname"])
        self.assertFalse(result["attributes"]["ip"])

    def test_partially_imported_serial_mismatch(self):
        self._device("switch-c", serial="OLD", ip_str="10.0.0.3")
        result = correlate_device("10.0.0.3", "switch-c", "NEW")
        self.assertEqual(result["status"], "partially_imported")
        self.assertFalse(result["attributes"]["serial"])
        self.assertIsNotNone(result["device"])

    def test_conflict(self):
        self._device("switch-d", ip_str="10.0.0.4")
        self._device("switch-d2", serial="SN-D2")
        result = correlate_device("10.0.0.4", "switch-d2", "SN-D2")
        self.assertEqual(result["status"], "conflict")
        self.assertIsNone(result["device"])
        self.assertEqual(len(result["matches"]), 2)


class ProfileDiscoveryTests(TestCase):
    """Integration tests for DiscoveryProfile wiring in the SNMP job."""

    @classmethod
    def setUpTestData(cls):
        cls.location_type = LocationType.objects.create(name="Profile Type", nestable=True)
        cls.location = Location.objects.create(
            name="Profile Location",
            location_type=cls.location_type,
            status=Status.objects.get_for_model(Location).first(),
        )
        cls.role = Role.objects.create(
            name="Profile Role",
            color="orange",
            status=Status.objects.get_for_model(Role).first(),
        )

    @staticmethod
    def _table_aware_snmp_discover(ip_str, config):
        if ip_str in ("10.0.0.1", "10.0.0.3"):
            return {
                "hostname": "switch-001.corp.example.com" if ip_str == "10.0.0.1" else "switch-003.corp.example.com",
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
                "interfaces": [],
                "ip_addresses": [],
                "arp_table": [],
                "physical": [],
                "neighbors": [],
                "vlans": [],
                "interfaces_found": 0,
                "ip_addresses_found": 0,
                "neighbors_found": 0,
                "vlans_found": 0,
            }
        return None

    def test_profile_scope_exclusions_and_domain_strip(self):
        captured = {}

        def mock_discover(ip_str, config):
            captured["config"] = config
            return self._table_aware_snmp_discover(ip_str, config)

        profile = DiscoveryProfile.objects.create(
            name="Prod Profile",
            included_ip_prefixes=["10.0.0.0/30"],
            excluded_ip_prefixes=["10.0.0.3"],
            strip_domain_suffixes=["corp.example.com"],
            snmp_timeout=7,
        )

        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device",
            side_effect=mock_discover,
        ):
            result = run_job_for_testing(
                SNMPDiscoveryJob,
                data={
                    "target_network": "10.255.255.0/30",
                    "profile": profile,
                    "timeout": 1,
                    "concurrency": 5,
                },
            )

        self.assertEqual(result["discovered"], 1)
        self.assertEqual(result["created"], 1)
        self.assertEqual(captured["config"]["snmp_timeout"], 7)

        device = Device.objects.get(name="switch-001")
        self.assertEqual(str(device.serial), "FCW2134ABCD")

        discovered_device = DiscoveredDevice.objects.get(ip_address="10.0.0.1")
        self.assertEqual(discovered_device.hostname, "switch-001")
        self.assertEqual(discovered_device.status, DiscoveredDevice.CorrelationStatus.NEW)
        self.assertEqual(discovered_device.device, device)
        self.assertFalse(DiscoveredDevice.objects.filter(ip_address="10.0.0.3").exists())

        discovery_result = DiscoveryResult.objects.get(ip_address="10.0.0.1")
        self.assertEqual(discovery_result.hostname, "switch-001")
        self.assertEqual(discovery_result.result_status, "new")

    def test_second_run_marks_existing_imported(self):
        profile = DiscoveryProfile.objects.create(
            name="Idempotent Profile",
            included_ip_prefixes=["10.0.0.0/30"],
            strip_domain_suffixes=["corp.example.com"],
        )
        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device",
            side_effect=self._table_aware_snmp_discover,
        ):
            first = run_job_for_testing(
                SNMPDiscoveryJob,
                data={
                    "target_network": "10.0.0.0/30",
                    "profile": profile,
                    "timeout": 1,
                    "concurrency": 5,
                },
            )
            second = run_job_for_testing(
                SNMPDiscoveryJob,
                data={
                    "target_network": "10.0.0.0/30",
                    "profile": profile,
                    "timeout": 1,
                    "concurrency": 5,
                },
            )

        self.assertEqual(first["created"], 1)
        self.assertEqual(second["created"], 0)
        self.assertEqual(second["existing"], 1)

        discovered_device = DiscoveredDevice.objects.get(ip_address="10.0.0.1")
        self.assertEqual(discovered_device.status, DiscoveredDevice.CorrelationStatus.IMPORTED)
        self.assertIsNotNone(discovered_device.device)

    def test_create_devices_disabled(self):
        profile = DiscoveryProfile.objects.create(
            name="Review Profile",
            included_ip_prefixes=["10.0.0.0/30"],
        )
        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device",
            side_effect=self._table_aware_snmp_discover,
        ):
            result = run_job_for_testing(
                SNMPDiscoveryJob,
                data={
                    "target_network": "10.0.0.0/30",
                    "profile": profile,
                    "create_devices": False,
                    "timeout": 1,
                    "concurrency": 5,
                },
            )

        self.assertEqual(result["created"], 0)
        self.assertFalse(Device.objects.filter(name="switch-001").exists())

        discovered_device = DiscoveredDevice.objects.get(ip_address="10.0.0.1")
        self.assertEqual(discovered_device.status, DiscoveredDevice.CorrelationStatus.NEW)
        self.assertIsNone(discovered_device.device)

        discovery_result = DiscoveryResult.objects.get(ip_address="10.0.0.1")
        self.assertEqual(discovery_result.result_status, "new")
        self.assertIn("Auto-create disabled", discovery_result.error_message)

    def test_maximum_ip_addresses_enforced(self):
        profile = DiscoveryProfile.objects.create(
            name="Capped Profile",
            included_ip_prefixes=["10.0.0.0/30"],
            maximum_ip_addresses=1,
        )
        result = run_job_for_testing(
            SNMPDiscoveryJob,
            data={
                "target_network": "10.0.0.0/30",
                "profile": profile,
                "timeout": 1,
                "concurrency": 5,
            },
        )
        self.assertIn("error", result)
        self.assertIn("maximum_ip_addresses", result["error"])
