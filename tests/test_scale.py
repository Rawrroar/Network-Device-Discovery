"""Tests for SNMP engine batching, concurrency knobs, and time limits."""

from unittest.mock import patch

from django.test import TestCase

from nautobot_plugin_device_auto_discovery.jobs import (
    FullDiscoveryJob,
    SNMPDiscoveryJob,
    _apply_configured_time_limits,
    _iter_snmp_batches,
    _run_snmp_scan_batches,
    _snmp_batch_size,
)
from nautobot_plugin_device_auto_discovery.models import DiscoveryProfile


class BatchSplittingTests(TestCase):
    """_iter_snmp_batches / _snmp_batch_size behavior."""

    def test_default_batch_size(self):
        self.assertEqual(_snmp_batch_size({}), 1000)

    def test_configured_batch_size(self):
        self.assertEqual(_snmp_batch_size({"snmp_engine_batch_size": 250}), 250)

    def test_zero_disables_batching(self):
        self.assertEqual(_snmp_batch_size({"snmp_engine_batch_size": 0}), 0)

    def test_invalid_batch_size_falls_back(self):
        self.assertEqual(_snmp_batch_size({"snmp_engine_batch_size": "not-a-number"}), 1000)

    def test_single_batch_when_small(self):
        hosts = [f"10.0.0.{i}" for i in range(1, 11)]
        batches = list(_iter_snmp_batches(hosts, {"snmp_engine_batch_size": 1000}))
        self.assertEqual(len(batches), 1)
        self.assertEqual(batches[0], hosts)

    def test_split_into_batches(self):
        hosts = [f"10.0.0.{i}" for i in range(1, 26)]
        batches = list(_iter_snmp_batches(hosts, {"snmp_engine_batch_size": 10}))
        self.assertEqual([len(b) for b in batches], [10, 10, 5])
        # Hosts preserved in order
        self.assertEqual(batches[0][0], "10.0.0.1")
        self.assertEqual(batches[-1][-1], "10.0.0.25")

    def test_unbatched_when_zero(self):
        hosts = [f"10.0.0.{i}" for i in range(1, 26)]
        batches = list(_iter_snmp_batches(hosts, {"snmp_engine_batch_size": 0}))
        self.assertEqual(len(batches), 1)
        self.assertEqual(len(batches[0]), 25)


class RunSnmpScanBatchesTests(TestCase):
    """_run_snmp_scan_batches totals and batching counts."""

    def test_sums_numeric_results(self):
        def scan(batch):
            return {"discovered": len(batch), "created": 1, "label": "ignored"}

        totals = _run_snmp_scan_batches(
            [f"10.0.0.{i}" for i in range(1, 6)],
            {"snmp_engine_batch_size": 2},
            scan,
        )
        self.assertEqual(totals["discovered"], 5)
        self.assertEqual(totals["created"], 3)
        self.assertNotIn("label", totals)
        self.assertEqual(totals["batches"], 3)
        self.assertEqual(totals["batch_size"], 2)

    def test_zero_batch_size_single_pass(self):
        calls = []

        def scan(batch):
            calls.append(len(batch))
            return {"discovered": len(batch)}

        totals = _run_snmp_scan_batches(
            [f"10.0.0.{i}" for i in range(1, 6)],
            {"snmp_engine_batch_size": 0},
            scan,
        )
        self.assertEqual(calls, [5])
        self.assertEqual(totals["batches"], 1)

    def test_empty_hosts(self):
        totals = _run_snmp_scan_batches([], {}, lambda batch: {})
        self.assertEqual(totals["batches"], 1)


class ConcurrencyKnobTests(TestCase):
    """Effective SNMP concurrency capping and per-phase fallbacks."""

    def test_snmp_concurrency_capped_at_batch_size(self):
        # effective = min(concurrency, batch) logic mirrors the job body;
        # here we verify the helper that feeds it.
        config = {"snmp_engine_batch_size": 250}
        batch_size = _snmp_batch_size(config)
        concurrency = 100
        effective = max(1, min(concurrency, batch_size))
        self.assertEqual(effective, 100)

        config = {"snmp_engine_batch_size": 50}
        batch_size = _snmp_batch_size(config)
        effective = max(1, min(100, batch_size))
        self.assertEqual(effective, 50)


class TimeLimitConfigurationTests(TestCase):
    """Plugin-configured Celery soft/hard time limits."""

    def test_defaults_applied(self):
        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.get_plugin_config",
            return_value={"soft_time_limit": 7200, "time_limit": 7500},
        ):
            original_full = FullDiscoveryJob.soft_time_limit
            try:
                _apply_configured_time_limits()
                self.assertEqual(FullDiscoveryJob.soft_time_limit, 7200)
                self.assertEqual(FullDiscoveryJob.time_limit, 7500)
                self.assertEqual(SNMPDiscoveryJob.soft_time_limit, 7200)
            finally:
                FullDiscoveryJob.soft_time_limit = original_full
                FullDiscoveryJob.time_limit = 3600
                SNMPDiscoveryJob.soft_time_limit = 600

    def test_invalid_ratio_ignored(self):
        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.get_plugin_config",
            return_value={"soft_time_limit": 7200, "time_limit": 3600},
        ):
            original_full = FullDiscoveryJob.soft_time_limit
            try:
                _apply_configured_time_limits()
                # unchanged because hard <= soft
                self.assertEqual(FullDiscoveryJob.soft_time_limit, original_full)
            finally:
                FullDiscoveryJob.soft_time_limit = original_full


class FullJobBatchIntegrationTests(TestCase):
    """FullDiscoveryJob end-to-end with a tiny batch size."""

    @classmethod
    def setUpTestData(cls):
        cls.profile = DiscoveryProfile.objects.create(
            name="Batch Profile",
            included_ip_prefixes=["10.11.0.0/29"],
        )

    @staticmethod
    def _snmp_info(ip_str):
        return {
            "hostname": f"batch-{ip_str.split('.')[-1]}",
            "sys_descr": "Cisco IOS-XE 17.3",
            "sys_object_id": "1.3.6.1.4.1.9.1.675.1.2.3",
            "platform_info": {"platform_name": "cisco_iosxe", "manufacturer_name": "Cisco", "network_driver": "cisco_iosxe"},
            "vendor": "Cisco",
            "model": "C9300",
            "serial": f"B{ip_str.split('.')[-1]}",
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

    def test_full_job_runs_with_batching(self):
        from nautobot.extras.test_tools import run_job_for_testing

        def fake_snmp(ip_str, config):
            return self._snmp_info(ip_str)

        with patch("nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device", side_effect=fake_snmp):
            result = run_job_for_testing(
                FullDiscoveryJob,
                data={
                    "target_network": "10.11.0.0/29",
                    "profile": self.profile,
                    "ssh_username": "",
                    "ssh_password": "",
                    "snmp_version": "2c",
                    "snmp_community": "public",
                    "timeout": 1,
                    "concurrency": 5,
                    "enable_ping": False,
                    "enable_ssh": False,
                    "dryrun": True,
                },
            )

        self.assertIn("discovered", result)
        self.assertGreaterEqual(result["discovered"], 1)
