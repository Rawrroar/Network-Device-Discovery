"""Tests for the Fast Path SSH-collection short-circuit."""

from unittest.mock import patch

from django.test import TestCase
from nautobot.extras.choices import SecretsGroupAccessTypeChoices, SecretsGroupSecretTypeChoices
from nautobot.extras.models import Secret, SecretsGroup, SecretsGroupAssociation

from nautobot_plugin_device_auto_discovery.jobs import fast_path_eligible, mark_fast_path_failure
from nautobot_plugin_device_auto_discovery.models import DiscoveryProfile, DiscoveredDevice


def _make_group_with_ssh(name, username, password):
    group = SecretsGroup.objects.create(name=name)
    for index, (secret_type, value) in enumerate(
        [(SecretsGroupSecretTypeChoices.TYPE_USERNAME, username), (SecretsGroupSecretTypeChoices.TYPE_PASSWORD, password)]
    ):
        var_name = f"NB_FP_TEST_{name}_{index}"
        import os

        os.environ[var_name] = value
        secret = Secret.objects.create(
            name=f"fp-secret-{name}-{index}",
            provider="environment-variable",
            parameters={"variable": var_name},
        )
        SecretsGroupAssociation.objects.create(
            secrets_group=group, secret=secret, access_type=SecretsGroupAccessTypeChoices.TYPE_SSH, secret_type=secret_type
        )
    return group


class FastPathEligibleTests(TestCase):
    """Unit tests for the eligibility decision."""

    def setUp(self):
        self.group = _make_group_with_ssh("fp-group", "fastuser", "fastpass")
        self.device = DiscoveredDevice.objects.create(
            ip_address="10.7.0.1",
            hostname="switch-001",
            serial="SN001",
            network_driver="cisco_iosxe",
            ssh_collection=True,
            ssh_secrets_group=self.group,
        )
        self.info = {
            "hostname": "switch-001",
            "serial": "SN001",
            "platform_info": {"platform_name": "cisco_iosxe"},
        }

    def _snapshot(self):
        """Re-read the stored record the way the job snapshots it."""
        return DiscoveredDevice.objects.get(pk=self.device.pk)

    def test_eligible(self):
        eligible, value = fast_path_eligible(self._snapshot(), self.info)
        self.assertTrue(eligible)
        self.assertEqual(value["username"], "fastuser")
        self.assertEqual(value["password"], "fastpass")
        self.assertEqual(value["secrets_group"], self.group)

    def test_no_stored_record(self):
        eligible, reason = fast_path_eligible(None, self.info)
        self.assertFalse(eligible)
        self.assertIn("no stored device record", reason)

    def test_identity_mismatch_hostname(self):
        self.info["hostname"] = "switch-002"
        eligible, reason = fast_path_eligible(self._snapshot(), self.info)
        self.assertFalse(eligible)
        self.assertIn("hostname mismatch", reason)

    def test_identity_mismatch_serial(self):
        self.info["serial"] = "SN999"
        eligible, reason = fast_path_eligible(self._snapshot(), self.info)
        self.assertFalse(eligible)
        self.assertIn("serial mismatch", reason)

    def test_identity_mismatch_platform(self):
        self.info["platform_info"] = {"platform_name": "arista_eos"}
        eligible, reason = fast_path_eligible(self._snapshot(), self.info)
        self.assertFalse(eligible)
        self.assertIn("platform mismatch", reason)

    def test_incomplete_snmp_identity(self):
        self.info["serial"] = ""
        eligible, reason = fast_path_eligible(self._snapshot(), self.info)
        self.assertFalse(eligible)
        self.assertIn("identity incomplete", reason)

    def test_matching_is_case_insensitive(self):
        self.device.hostname = "SWITCH-001"
        self.device.serial = "sn001"
        self.device.network_driver = "CISCO_IOSXE"
        self.device.save()
        eligible, _ = fast_path_eligible(self._snapshot(), self.info)
        self.assertTrue(eligible)

    def test_no_previous_ssh_collection(self):
        self.device.ssh_collection = False
        self.device.save()
        eligible, reason = fast_path_eligible(self._snapshot(), self.info)
        self.assertFalse(eligible)
        self.assertIn("no previous successful SSH collection", reason)

    def test_no_stored_secrets_group(self):
        self.device.ssh_secrets_group = None
        self.device.save()
        eligible, reason = fast_path_eligible(self._snapshot(), self.info)
        self.assertFalse(eligible)
        self.assertIn("no stored SSH secrets group", reason)

    def test_stored_group_without_ssh_secrets(self):
        empty_group = SecretsGroup.objects.create(name="fp-empty")
        self.device.ssh_secrets_group = empty_group
        self.device.save()
        eligible, reason = fast_path_eligible(self._snapshot(), self.info)
        self.assertFalse(eligible)
        self.assertIn("no longer usable", reason)


class FastPathFailureTests(TestCase):
    """Self-correction: a failed direct collection disables Fast Path."""

    def test_mark_failure_clears_ssh_state(self):
        group = _make_group_with_ssh("fp-fail-group", "u", "p")
        DiscoveredDevice.objects.create(
            ip_address="10.7.1.1",
            hostname="sw",
            serial="SN",
            network_driver="x",
            ssh_collection=True,
            ssh_secrets_group=group,
        )
        mark_fast_path_failure("10.7.1.1", "direct SSH collection failed")
        device = DiscoveredDevice.objects.get(ip_address="10.7.1.1")
        self.assertFalse(device.ssh_collection)
        self.assertIsNone(device.ssh_collection_datetime)
        self.assertIsNone(device.ssh_secrets_group)
        self.assertIn("Fast Path failure", device.ssh_issue)
        self.assertIsNotNone(device.ssh_collection_attempt_datetime)

    def test_mark_failure_is_noop_for_unknown_ip(self):
        mark_fast_path_failure("10.7.1.99", "reason")


class FastPathJobIntegrationTests(TestCase):
    """Integration: NetworkDeviceDiscoveryJob honors the profile fast_path flag."""

    @classmethod
    def setUpTestData(cls):
        cls.group = _make_group_with_ssh("fp-job-group", "jobuser", "jobpass")
        cls.profile = DiscoveryProfile.objects.create(
            name="Fast Path Profile",
            included_ip_prefixes=["10.7.2.0/30"],
            fast_path=True,
        )
        from nautobot_plugin_device_auto_discovery.models import DiscoveryProfileSecretsGroupAssignment

        DiscoveryProfileSecretsGroupAssignment.objects.create(
            discovery_profile=cls.profile, secrets_group=cls.group, weight=10
        )

    @staticmethod
    def _snmp_info(ip_str):
        return {
            "hostname": f"sw-{ip_str.split('.')[-1]}",
            "sys_descr": "Cisco IOS-XE 17.3",
            "sys_object_id": "1.3.6.1.4.1.9.1.675.1.2.3",
            "platform_info": {"platform_name": "cisco_iosxe", "manufacturer_name": "Cisco", "network_driver": "cisco_iosxe"},
            "vendor": "Cisco",
            "model": "C9300",
            "serial": f"SN{ip_str.split('.')[-1]}",
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

    def _prep_device(self, ip_str, ssh_collection=True, secrets_group=None):
        info = self._snmp_info(ip_str)
        DiscoveredDevice.objects.create(
            ip_address=ip_str,
            hostname=info["hostname"],
            serial=info["serial"],
            network_driver=info["platform_info"]["network_driver"],
            ssh_collection=ssh_collection,
            ssh_secrets_group=secrets_group or (self.group if ssh_collection else None),
        )
        return info

    def test_fast_path_success_uses_stored_group(self):
        from nautobot.extras.test_tools import run_job_for_testing

        from nautobot_plugin_device_auto_discovery.jobs import NetworkDeviceDiscoveryJob

        ip_str = "10.7.2.1"
        self._prep_device(ip_str)
        calls = []

        def mock_ssh(ip, username, password, **kwargs):
            calls.append((ip, username))
            return {
                "hostname": f"sw-{ip.split('.')[-1]}",
                "vendor": "Cisco",
                "model": "C9300",
                "serial": f"SN{ip.split('.')[-1]}",
                "os_version": "17.3",
                "command_outputs": {},
            }

        with patch("nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device", side_effect=self._snmp_info):
            with patch(
                "nautobot_plugin_device_auto_discovery.jobs.ssh_connect_and_discover", side_effect=mock_ssh
            ):
                result = run_job_for_testing(
                    NetworkDeviceDiscoveryJob,
                    data={
                        "target_network": "10.7.2.0/30",
                        "profile": self.profile,
                        "ssh_username": "",
                        "ssh_password": "",
                        "snmp_version": "2c",
                        "snmp_community": "public",
                        "timeout": 1,
                        "concurrency": 5,
                        "dryrun": False,
                    },
                )

        self.assertEqual(result.get("fast_path_used"), 1)
        self.assertEqual(result.get("fast_path_failures"), 0)
        # Only one SSH call, using the stored group's credentials
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], "jobuser")

    def test_fast_path_failure_falls_back_and_self_corrects(self):
        from nautobot.extras.test_tools import run_job_for_testing

        from nautobot_plugin_device_auto_discovery.jobs import NetworkDeviceDiscoveryJob

        ip_str = "10.7.2.1"
        self._prep_device(ip_str)
        calls = []

        def mock_ssh(ip, username, password, **kwargs):
            calls.append((ip, username))
            if username == "jobuser":
                # Stored credentials no longer work (e.g. rotation or RMA)
                return None
            return {
                "hostname": f"sw-{ip.split('.')[-1]}",
                "vendor": "Cisco",
                "model": "C9300",
                "serial": f"SN{ip.split('.')[-1]}",
                "os_version": "17.3",
                "command_outputs": {},
            }

        with patch("nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device", side_effect=self._snmp_info):
            with patch(
                "nautobot_plugin_device_auto_discovery.jobs.ssh_connect_and_discover", side_effect=mock_ssh
            ):
                result = run_job_for_testing(
                    NetworkDeviceDiscoveryJob,
                    data={
                        "target_network": "10.7.2.0/30",
                        "profile": self.profile,
                        "ssh_username": "",
                        "ssh_password": "",
                        "snmp_version": "2c",
                        "snmp_community": "public",
                        "timeout": 1,
                        "concurrency": 5,
                        "dryrun": False,
                    },
                )

        self.assertEqual(result.get("fast_path_failures"), 1)
        self.assertEqual(result.get("fast_path_used"), 0)
        # Two attempts: fast-path candidate, then full candidate list
        self.assertEqual(len(calls), 2)
        # The stored group was cleared so the next run does full discovery
        device = DiscoveredDevice.objects.get(ip_address=ip_str)
        self.assertFalse(device.ssh_collection)
        self.assertIsNone(device.ssh_secrets_group)

    def test_fast_path_disabled_full_discovery(self):
        from nautobot.extras.test_tools import run_job_for_testing

        from nautobot_plugin_device_auto_discovery.jobs import NetworkDeviceDiscoveryJob

        profile = DiscoveryProfile.objects.create(
            name="No Fast Path Profile",
            included_ip_prefixes=["10.7.3.0/30"],
            fast_path=False,
        )
        from nautobot_plugin_device_auto_discovery.models import DiscoveryProfileSecretsGroupAssignment

        DiscoveryProfileSecretsGroupAssignment.objects.create(
            discovery_profile=profile, secrets_group=self.group, weight=10
        )
        ip_str = "10.7.3.1"
        self._prep_device(ip_str)
        calls = []

        def mock_ssh(ip, username, password, **kwargs):
            calls.append((ip, username))
            return {
                "hostname": f"sw-{ip.split('.')[-1]}",
                "vendor": "Cisco",
                "model": "C9300",
                "serial": f"SN{ip.split('.')[-1]}",
                "os_version": "17.3",
                "command_outputs": {},
            }

        with patch("nautobot_plugin_device_auto_discovery.jobs.snmp_discover_device", side_effect=self._snmp_info):
            with patch(
                "nautobot_plugin_device_auto_discovery.jobs.ssh_connect_and_discover", side_effect=mock_ssh
            ):
                result = run_job_for_testing(
                    NetworkDeviceDiscoveryJob,
                    data={
                        "target_network": "10.7.3.0/30",
                        "profile": profile,
                        "ssh_username": "",
                        "ssh_password": "",
                        "snmp_version": "2c",
                        "snmp_community": "public",
                        "timeout": 1,
                        "concurrency": 5,
                        "dryrun": False,
                    },
                )

        self.assertEqual(result.get("fast_path_used"), 0)
        self.assertEqual(result.get("fast_path_failures"), 0)
        self.assertEqual(len(calls), 1)
