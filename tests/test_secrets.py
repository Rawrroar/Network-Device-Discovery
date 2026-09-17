"""Tests for secrets-group credential resolution and weighted SSH retry."""

import os
from unittest.mock import patch

from django.test import TestCase
from nautobot.extras.choices import (
    SecretsGroupAccessTypeChoices,
    SecretsGroupSecretTypeChoices,
)
from nautobot.extras.models import Secret, SecretsGroup, SecretsGroupAssociation

from nautobot_plugin_device_auto_discovery.models import (
    DiscoveryProfile,
    DiscoveryProfileSecretsGroupAssignment,
    DiscoveredDevice,
)
from nautobot_plugin_device_auto_discovery.secrets import (
    ordered_secrets_groups,
    record_ssh_success,
    snmp_secrets_config,
    ssh_credential_candidates,
    ssh_credential_from_config,
    ssh_connect_with_credentials,
)

_secret_env_counter = [0]


def _add_secret(group, access_type, secret_type, value):
    """Create a real Secret backed by an environment variable and assign it."""
    _secret_env_counter[0] += 1
    var_name = f"NB_TEST_SECRET_{_secret_env_counter[0]}"
    os.environ[var_name] = value
    secret = Secret.objects.create(
        name=f"test-secret-{_secret_env_counter[0]}",
        provider="environment-variable",
        parameters={"variable": var_name},
    )
    SecretsGroupAssociation.objects.create(
        secrets_group=group,
        secret=secret,
        access_type=access_type,
        secret_type=secret_type,
    )
    return secret


class OrderedSecretsGroupsTests(TestCase):
    """Weight ordering of a profile's secrets groups."""

    def setUp(self):
        self.profile = DiscoveryProfile.objects.create(name="Secrets Order Profile")
        self.group_a = SecretsGroup.objects.create(name="Order A")
        self.group_b = SecretsGroup.objects.create(name="Order B")
        self.group_c = SecretsGroup.objects.create(name="Order C")

    def _assign(self, group, weight):
        DiscoveryProfileSecretsGroupAssignment.objects.create(
            discovery_profile=self.profile, secrets_group=group, weight=weight
        )

    def test_empty_profile(self):
        self.assertEqual(ordered_secrets_groups(None), [])
        self.assertEqual(ordered_secrets_groups(self.profile), [])

    def test_ascending_weight(self):
        self._assign(self.group_c, 50)
        self._assign(self.group_a, 10)
        self._assign(self.group_b, 30)
        self.assertEqual(
            ordered_secrets_groups(self.profile),
            [self.group_a, self.group_b, self.group_c],
        )

    def test_ties_broken_by_name(self):
        self._assign(self.group_c, 10)
        self._assign(self.group_a, 10)
        self.assertEqual(ordered_secrets_groups(self.profile), [self.group_a, self.group_c])


class SnmpSecretsConfigTests(TestCase):
    """SNMP credential resolution: lowest-weight group only."""

    def setUp(self):
        self.profile = DiscoveryProfile.objects.create(name="SNMP Secrets Profile")
        self.group_low = SecretsGroup.objects.create(name="SNMP Low")
        self.group_high = SecretsGroup.objects.create(name="SNMP High")

    def test_no_groups_returns_none(self):
        self.assertIsNone(snmp_secrets_config(self.profile))

    def test_no_snmp_secrets_returns_none(self):
        DiscoveryProfileSecretsGroupAssignment.objects.create(
            discovery_profile=self.profile, secrets_group=self.group_low, weight=10
        )
        _add_secret(
            self.group_low,
            SecretsGroupAccessTypeChoices.TYPE_SSH,
            SecretsGroupSecretTypeChoices.TYPE_USERNAME,
            "admin",
        )
        self.assertIsNone(snmp_secrets_config(self.profile))

    def test_v2c_community_from_lowest_weight(self):
        _add_secret(
            self.group_high,
            SecretsGroupAccessTypeChoices.TYPE_SNMP,
            SecretsGroupSecretTypeChoices.TYPE_TOKEN,
            "high-community",
        )
        _add_secret(
            self.group_low,
            SecretsGroupAccessTypeChoices.TYPE_SNMP,
            SecretsGroupSecretTypeChoices.TYPE_TOKEN,
            "low-community",
        )
        DiscoveryProfileSecretsGroupAssignment.objects.create(
            discovery_profile=self.profile, secrets_group=self.group_high, weight=10
        )
        DiscoveryProfileSecretsGroupAssignment.objects.create(
            discovery_profile=self.profile, secrets_group=self.group_low, weight=20
        )
        resolved = snmp_secrets_config(self.profile)
        self.assertEqual(resolved["snmp_version"], "2c")
        self.assertEqual(resolved["snmp_community"], "high-community")

    def test_v3_authpriv(self):
        _add_secret(
            self.group_low,
            SecretsGroupAccessTypeChoices.TYPE_SNMP,
            SecretsGroupSecretTypeChoices.TYPE_USERNAME,
            "v3user",
        )
        _add_secret(
            self.group_low,
            SecretsGroupAccessTypeChoices.TYPE_SNMP,
            SecretsGroupSecretTypeChoices.TYPE_PASSWORD,
            "authpass",
        )
        _add_secret(
            self.group_low,
            SecretsGroupAccessTypeChoices.TYPE_SNMP,
            SecretsGroupSecretTypeChoices.TYPE_KEY,
            "privkey",
        )
        DiscoveryProfileSecretsGroupAssignment.objects.create(
            discovery_profile=self.profile, secrets_group=self.group_low, weight=10
        )
        resolved = snmp_secrets_config(self.profile)
        self.assertEqual(resolved["snmp_version"], "3")
        self.assertEqual(resolved["snmpv3_username"], "v3user")
        self.assertEqual(resolved["snmpv3_auth_key"], "authpass")
        self.assertEqual(resolved["snmpv3_priv_key"], "privkey")
        self.assertEqual(resolved["snmpv3_auth_protocol"], "SHA")
        self.assertEqual(resolved["snmpv3_priv_protocol"], "AES")


class SSHCredentialCandidateTests(TestCase):
    """SSH candidate ordering and preferred-group promotion."""

    def setUp(self):
        self.profile = DiscoveryProfile.objects.create(name="SSH Secrets Profile")
        self.group_low = SecretsGroup.objects.create(name="SSH Low")
        self.group_high = SecretsGroup.objects.create(name="SSH High")
        _add_secret(
            self.group_low,
            SecretsGroupAccessTypeChoices.TYPE_SSH,
            SecretsGroupSecretTypeChoices.TYPE_USERNAME,
            "lowuser",
        )
        _add_secret(
            self.group_low,
            SecretsGroupAccessTypeChoices.TYPE_SSH,
            SecretsGroupSecretTypeChoices.TYPE_PASSWORD,
            "lowpass",
        )
        _add_secret(
            self.group_high,
            SecretsGroupAccessTypeChoices.TYPE_SSH,
            SecretsGroupSecretTypeChoices.TYPE_USERNAME,
            "highuser",
        )
        _add_secret(
            self.group_high,
            SecretsGroupAccessTypeChoices.TYPE_SSH,
            SecretsGroupSecretTypeChoices.TYPE_PASSWORD,
            "highpass",
        )
        DiscoveryProfileSecretsGroupAssignment.objects.create(
            discovery_profile=self.profile, secrets_group=self.group_high, weight=10
        )
        DiscoveryProfileSecretsGroupAssignment.objects.create(
            discovery_profile=self.profile, secrets_group=self.group_low, weight=20
        )

    def test_candidates_ordered_by_weight(self):
        candidates = ssh_credential_candidates(self.profile)
        self.assertEqual([c["username"] for c in candidates], ["highuser", "lowuser"])
        self.assertEqual([c["password"] for c in candidates], ["highpass", "lowpass"])

    def test_preferred_group_tried_first(self):
        candidates = ssh_credential_candidates(self.profile, preferred_group=self.group_low)
        self.assertEqual(candidates[0]["username"], "lowuser")
        self.assertEqual(candidates[-1]["username"], "highuser")

    def test_none_profile_falls_back_to_config(self):
        candidate = ssh_credential_from_config({"ssh_username": "cfguser", "ssh_password": "cfgpass"})
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate["username"], "cfguser")
        self.assertIsNone(candidate["secrets_group"])

    def test_config_without_username_returns_none(self):
        self.assertIsNone(ssh_credential_from_config({"ssh_password": "x"}))


class SSHConnectWithCredentialsTests(TestCase):
    """Retry semantics of the credential iterator."""

    def test_first_candidate_succeeds(self):
        calls = []

        def connect(ip, username, password, **kwargs):
            calls.append(username)
            return {"hostname": "h"}

        info, candidate = ssh_connect_with_credentials(
            "10.0.0.1", [{"username": "a", "password": "p1"}, {"username": "b", "password": "p2"}], connect
        )
        self.assertEqual(calls, ["a"])
        self.assertEqual(candidate["username"], "a")

    def test_falls_through_to_second(self):
        calls = []

        def connect(ip, username, password, **kwargs):
            calls.append(username)
            if username == "b":
                return {"hostname": "h"}
            return None

        info, candidate = ssh_connect_with_credentials(
            "10.0.0.1", [{"username": "a", "password": "p1"}, {"username": "b", "password": "p2"}], connect
        )
        self.assertEqual(calls, ["a", "b"])
        self.assertEqual(candidate["username"], "b")

    def test_all_fail(self):
        info, candidate = ssh_connect_with_credentials(
            "10.0.0.1", [{"username": "a", "password": "p1"}], lambda *a, **k: None
        )
        self.assertIsNone(info)
        self.assertIsNone(candidate)

    def test_empty_candidates(self):
        info, candidate = ssh_connect_with_credentials("10.0.0.1", [], lambda *a, **k: {"hostname": "h"})
        self.assertIsNone(info)


class RecordSSHSuccessTests(TestCase):
    """Last-known-working secrets group persistence."""

    def setUp(self):
        self.group = SecretsGroup.objects.create(name="Working Group")
        self.other = SecretsGroup.objects.create(name="Other Group")

    def test_records_group(self):
        device = DiscoveredDevice.objects.create(ip_address="10.9.0.1")
        record_ssh_success(device, {"username": "u", "password": "p", "secrets_group": self.group})
        device.refresh_from_db()
        self.assertEqual(device.ssh_secrets_group, self.group)

    def test_noop_without_group_or_device(self):
        device = DiscoveredDevice.objects.create(ip_address="10.9.0.2")
        record_ssh_success(device, {"username": "u", "password": "p", "secrets_group": None})
        record_ssh_success(None, {"username": "u", "password": "p", "secrets_group": self.group})
        device.refresh_from_db()
        self.assertIsNone(device.ssh_secrets_group)


class SSHJobSecretsIntegrationTests(TestCase):
    """Integration: NetworkDeviceDiscoveryJob (ssh phase) uses profile secrets groups with retry."""

    @classmethod
    def setUpTestData(cls):
        cls.profile = DiscoveryProfile.objects.create(
            name="SSH Job Profile",
            included_ip_prefixes=["10.0.0.0/30"],
        )
        cls.group = SecretsGroup.objects.create(name="SSH Job Group")
        _add_secret(
            cls.group,
            SecretsGroupAccessTypeChoices.TYPE_SSH,
            SecretsGroupSecretTypeChoices.TYPE_USERNAME,
            "secretuser",
        )
        _add_secret(
            cls.group,
            SecretsGroupAccessTypeChoices.TYPE_SSH,
            SecretsGroupSecretTypeChoices.TYPE_PASSWORD,
            "secretpass",
        )
        DiscoveryProfileSecretsGroupAssignment.objects.create(
            discovery_profile=cls.profile, secrets_group=cls.group, weight=10
        )

    def test_job_uses_secrets_group_credentials(self):
        from nautobot.extras.test_tools import run_job_for_testing

        from nautobot_plugin_device_auto_discovery.jobs import NetworkDeviceDiscoveryJob

        captured = {}

        def mock_ssh_discover(ip_str, username, password, timeout, banner_timeout, port=22, enable_password=None, port_check=True):
            captured.update(username=username, password=password)
            if ip_str == "10.0.0.1":
                return {
                    "hostname": "secrets-router",
                    "vendor": "Cisco",
                    "model": "C9300",
                    "serial": "SEC123",
                    "os_version": "17.3",
                    "command_outputs": {},
                }
            return None

        with patch(
            "nautobot_plugin_device_auto_discovery.jobs.ssh_connect_and_discover",
            side_effect=mock_ssh_discover,
        ):
            result = run_job_for_testing(
                NetworkDeviceDiscoveryJob,
                data={
                    "target_network": "10.0.0.0/30",
                    "ssh_username": "",
                    "ssh_password": "",
                    "profile": self.profile,
                    "snmp_version": "2c",
                    "snmp_community": "public",
                    "enable_ping": False,
                    "enable_snmp": False,
                    "enable_ssh": True,
                    "timeout": 1,
                    "concurrency": 5,
                    "dryrun": False,
                },
            )

        self.assertEqual(result["created"], 1)
        self.assertEqual(captured["username"], "secretuser")
        self.assertEqual(captured["password"], "secretpass")

        device = DiscoveredDevice.objects.get(ip_address="10.0.0.1")
        self.assertEqual(device.ssh_secrets_group, self.group)
