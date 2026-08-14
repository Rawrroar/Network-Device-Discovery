"""Tests for CrawlDiscoveryJob (seed-device neighbor crawl)."""

from unittest.mock import patch

from django.test import TestCase
from nautobot.dcim.models import Device, DeviceType, Location, LocationType, Manufacturer
from nautobot.extras.models import Role, Status
from nautobot.extras.test_tools import run_job_for_testing

from nautobot_plugin_device_auto_discovery.jobs import CrawlDiscoveryJob
from nautobot_plugin_device_auto_discovery.models import DiscoveryScan


def _info(hostname, neighbors=None):
    return {
        "hostname": hostname,
        "sys_descr": "Cisco Catalyst 9300, IOS-XE 17.3",
        "sys_object_id": "1.3.6.1.4.1.9.1.675.1.2.3",
        "platform_info": {
            "platform_name": "Cisco IOS-XE",
            "manufacturer_name": "Cisco",
            "network_driver": "ios",
        },
        "vendor": "Cisco",
        "model": "Catalyst 9300",
        "serial": f"SER-{hostname}",
        "os_version": "IOS-XE 17.3",
        "sys_contact": "noc@example.com",
        "sys_location": "DC1",
        "interfaces": [],
        "ip_addresses": [],
        "arp_table": [],
        "physical": [],
        "neighbors": neighbors or [],
        "vlans": [],
        "interfaces_found": 0,
        "ip_addresses_found": 0,
        "neighbors_found": len(neighbors or []),
        "vlans_found": 0,
    }


def _topology():
    """leaf-a (10.0.0.1) -> leaf-b (10.0.0.2) + spine-001 (10.0.0.3)."""

    def discover(ip_str, config):
        if ip_str == "10.0.0.1":
            return _info(
                "leaf-a",
                [
                    {"protocol": "lldp", "local_if_index": "1", "remote_name": "leaf-b", "remote_ip": "10.0.0.2"},
                    {"protocol": "lldp", "local_if_index": "2", "remote_name": "spine-001", "remote_ip": "10.0.0.3"},
                ],
            )
        if ip_str == "10.0.0.2":
            return _info(
                "leaf-b",
                [{"protocol": "lldp", "local_if_index": "1", "remote_name": "spine-001", "remote_ip": "10.0.0.3"}],
            )
        if ip_str == "10.0.0.3":
            return _info("spine-001")
        return None

    return discover


class CrawlDiscoveryJobTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.location_type = LocationType.objects.create(name="Crawl Test Type", nestable=True)
        cls.location = Location.objects.create(
            name="Crawl Test Location",
            location_type=cls.location_type,
            status=Status.objects.get_for_model(Location).first(),
        )
        cls.role = Role.objects.create(name="Crawl Test Role", color="purple")
        cls.device_status = Status.objects.get_for_model(Device).first()
        mfr = Manufacturer.objects.create(name="Cisco")
        cls.device_type = DeviceType.objects.create(model="Crawl 9300", manufacturer=mfr)
        cls.seed = Device.objects.create(
            name="crawl-seed",
            device_type=cls.device_type,
            role=cls.role,
            location=cls.location,
            status=cls.device_status,
        )

    def _run(self, **data):
        defaults = {
            "seed_device": self.seed,
            "seed_ip": "10.0.0.1",
            "max_depth": 2,
            "max_devices": 100,
            "snmp_version": "2c",
            "snmp_community": "public",
            "timeout": 1,
            "concurrency": 5,
            "dryrun": False,
        }
        defaults.update(data)
        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device",
            side_effect=_topology(),
        ):
            return run_job_for_testing(CrawlDiscoveryJob, data=defaults)

    def test_crawl_discovers_neighbors_from_seed(self):
        result = self._run()
        self.assertIn("scan", result)
        self.assertEqual(result["discovered"], 3)
        self.assertEqual(result["created"], 3)
        self.assertEqual(result["failed"], 0)
        self.assertIn("cables_created", result)

        scan = DiscoveryScan.objects.get(pk=result["scan"])
        self.assertEqual(scan.scan_method, DiscoveryScan.ScanMethod.CRAWL)
        self.assertEqual(scan.seed_device, self.seed)
        self.assertEqual(scan.devices_discovered, 3)
        self.assertEqual(scan.devices_created, 3)

        self.assertTrue(Device.objects.filter(name="leaf-a").exists())
        self.assertTrue(Device.objects.filter(name="leaf-b").exists())
        self.assertTrue(Device.objects.filter(name="spine-001").exists())

    def test_crawl_respects_depth_limit(self):
        result = self._run(max_depth=1)
        self.assertEqual(result["discovered"], 1)
        self.assertEqual(result["created"], 1)
        self.assertFalse(Device.objects.filter(name="spine-001").exists())

    def test_crawl_dry_run_creates_nothing(self):
        result = self._run(dryrun=True)
        self.assertEqual(result["discovered"], 3)
        self.assertEqual(result["created"], 0)
        self.assertFalse(Device.objects.filter(name="leaf-a").exists())

    def test_crawl_requires_seed_ip(self):
        seed = Device.objects.create(
            name="crawl-seed-noip",
            device_type=self.device_type,
            role=self.role,
            location=self.location,
            status=self.device_status,
        )
        result = self._run(seed_device=seed, seed_ip="")
        self.assertIn("error", result)
        self.assertIn("no primary IP", result["error"])

    def test_crawl_invalid_snmp_version(self):
        result = self._run(snmp_version="9")
        self.assertIn("error", result)

    def test_crawl_v3_requires_username(self):
        result = self._run(snmp_version="3", snmpv3_username="")
        self.assertIn("error", result)
