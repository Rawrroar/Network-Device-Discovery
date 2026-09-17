"""Tests for SyncDiscoveredDevicesJob."""

from unittest.mock import patch

from django.test import TestCase

from nautobot_plugin_device_auto_discovery.jobs import SyncDiscoveredDevicesJob
from nautobot_plugin_device_auto_discovery.models import DiscoveredDevice, DiscoveryProfile, DiscoveryScan


class SyncJobTestBase(TestCase):
    """Shared fixtures."""

    @classmethod
    def setUpTestData(cls):
        cls.profile = DiscoveryProfile.objects.create(
            name="Sync Profile",
            included_ip_prefixes=["10.16.0.0/24"],
            protocols=["snmp", "ssh"],
        )
        cls.device_imported = DiscoveredDevice.objects.create(
            ip_address="10.16.0.1",
            hostname="sync-sw-01",
            vendor="Cisco",
            model="C9300",
            serial="SYNC001",
            os_version="17.3",
            status=DiscoveredDevice.CorrelationStatus.IMPORTED,
        )
        cls.device_new = DiscoveredDevice.objects.create(
            ip_address="10.16.0.2",
            hostname="sync-sw-02",
            vendor="Cisco",
            model="C9300",
            serial="SYNC002",
            os_version="17.3",
            status=DiscoveredDevice.CorrelationStatus.NEW,
        )
        cls.device_out_of_scope = DiscoveredDevice.objects.create(
            ip_address="172.31.0.9",
            hostname="sync-sw-far",
            status=DiscoveredDevice.CorrelationStatus.NEW,
        )

    @staticmethod
    def _snmp_info(ip_str, serial="SYNC001", hostname="sync-sw-01"):
        return {
            "hostname": hostname,
            "sys_descr": "Cisco IOS-XE 17.3",
            "sys_object_id": "1.3.6.1.4.1.9.1.675.1.2.3",
            "platform_info": {"platform_name": "cisco_iosxe", "manufacturer_name": "Cisco", "network_driver": "cisco_iosxe"},
            "vendor": "Cisco",
            "model": "C9300",
            "serial": serial,
            "os_version": "17.3",
            "sys_contact": "",
            "sys_location": "",
            "interfaces": [],
            "ip_addresses": [],
            "vrfs": [],
            "arp_table": [],
            "physical": [],
            "neighbors": [],
            "vlans": [],
            "interfaces_found": 0,
            "ip_addresses_found": 0,
            "vrfs_found": 0,
            "neighbors_found": 0,
            "vlans_found": 0,
        }


class SyncJobTests(SyncJobTestBase):
    """Core sync behavior."""

    def test_snmp_sync_updates_record(self):
        def fake_snmp(ip_str, config):
            # Reported hostname/serial changed on the network since discovery
            return self._snmp_info(ip_str, serial="SYNC001-NEW", hostname="sync-sw-01-v2")

        with patch("nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device", side_effect=fake_snmp):
            result = SyncDiscoveredDevicesJob().run(
                profile=self.profile, sync_status=None, sync_ssh=False, timeout=1, concurrency=5, dryrun=False
            )

        self.assertEqual(result["snmp"], 2)
        self.assertEqual(result["ssh"], 0)
        self.device_imported.refresh_from_db()
        self.assertEqual(self.device_imported.hostname, "sync-sw-01-v2")
        self.assertEqual(self.device_imported.serial, "SYNC001-NEW")
        self.assertTrue(self.device_imported.snmp_collection)
        # A sync scan record exists
        self.assertTrue(DiscoveryScan.objects.filter(scan_method="sync").exists())

    def test_profile_prefix_bounds_selection(self):
        def fake_snmp(ip_str, config):  # pragma: no cover - should not be called for 172.31
            raise AssertionError(f"unexpected SNMP attempt for {ip_str}")

        with patch("nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device", side_effect=fake_snmp):
            result = SyncDiscoveredDevicesJob().run(
                profile=self.profile, sync_status=None, sync_ssh=False, timeout=1, concurrency=5, dryrun=True
            )
        # Only the two 10.16.0.x devices are in scope; 172.31.0.9 excluded
        self.assertEqual(result["selected"], 2)

    def test_status_filter(self):
        def fake_snmp(ip_str, config):
            return self._snmp_info(ip_str)

        with patch("nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device", side_effect=fake_snmp):
            result = SyncDiscoveredDevicesJob().run(
                profile=None,
                sync_status=[DiscoveredDevice.CorrelationStatus.NEW],
                sync_ssh=False,
                timeout=1,
                concurrency=5,
                dryrun=True,
            )
        self.assertEqual(result["selected"], 2)  # device_new + device_out_of_scope
        self.assertEqual(result["snmp"], 2)

    def test_no_devices_selected(self):
        result = SyncDiscoveredDevicesJob().run(
            profile=None,
            sync_status=[DiscoveredDevice.CorrelationStatus.CONFLICT],
            sync_ssh=False,
            timeout=1,
            concurrency=5,
            dryrun=False,
        )
        self.assertEqual(result["selected"], 0)
        self.assertEqual(result["snmp"], 0)

    def test_snmp_failure_falls_back_to_ssh(self):
        def fake_snmp(ip_str, config):
            return None

        def fake_ssh(ip_str, username, password, **kwargs):
            return {
                "hostname": "sync-sw-01-ssh",
                "vendor": "Cisco",
                "model": "C9300",
                "serial": "SYNC001",
                "os_version": "17.3",
                "command_outputs": {},
            }

        with patch("nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device", side_effect=fake_snmp):
            with patch(
                "nautobot_plugin_device_auto_discovery.jobs.ssh_connect_and_discover", side_effect=fake_ssh
            ):
                result = SyncDiscoveredDevicesJob().run(
                    profile=self.profile,
                    sync_status=None,
                    sync_ssh=True,
                    timeout=1,
                    concurrency=5,
                    dryrun=False,
                )

        self.assertEqual(result["ssh"], 2)
        self.device_imported.refresh_from_db()
        self.assertEqual(self.device_imported.hostname, "sync-sw-01-ssh")

    def test_dryrun_touches_nothing(self):
        def fake_snmp(ip_str, config):
            return self._snmp_info(ip_str, hostname="would-change")

        with patch("nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device", side_effect=fake_snmp):
            result = SyncDiscoveredDevicesJob().run(
                profile=self.profile, sync_status=None, sync_ssh=False, timeout=1, concurrency=5, dryrun=True
            )

        self.assertEqual(result["snmp"], 2)
        self.device_imported.refresh_from_db()
        self.assertEqual(self.device_imported.hostname, "sync-sw-01")

    def test_never_creates_new_devices(self):
        # A device record exists but SNMP now reports a brand-new identity;
        # sync updates the existing row and must not create additional ones.
        count_before = DiscoveredDevice.objects.count()
        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device",
            side_effect=lambda ip, cfg: self._snmp_info(ip, hostname="brand-new-host"),
        ):
            SyncDiscoveredDevicesJob().run(
                profile=self.profile, sync_status=None, sync_ssh=False, timeout=1, concurrency=5, dryrun=False
            )
        self.assertEqual(DiscoveredDevice.objects.count(), count_before)

    def test_job_registered(self):
        from nautobot.core.celery import registry

        self.assertEqual(SyncDiscoveredDevicesJob.name, "Sync Discovered Devices From Network")
        self.assertIn(
            "nautobot_plugin_device_auto_discovery.jobs.SyncDiscoveredDevicesJob",
            registry["jobs"],
        )
