"""Tests for the consolidated Network Device Discovery job and Run-Discovery action."""

from unittest.mock import patch

from django.test import TestCase

from nautobot_plugin_device_auto_discovery.jobs import NetworkDeviceDiscoveryJob
from nautobot_plugin_device_auto_discovery.models import DiscoveryProfile


class NetworkDeviceDiscoveryJobTests(TestCase):
    """Profile-first phase selection and profile requirement."""

    @classmethod
    def setUpTestData(cls):
        cls.profile_full = DiscoveryProfile.objects.create(
            name="NDD Full",
            included_ip_prefixes=["10.12.0.0/30"],
            protocols=["ping", "snmp", "ssh"],
        )
        cls.profile_snmp_only = DiscoveryProfile.objects.create(
            name="NDD SNMP Only",
            included_ip_prefixes=["10.12.1.0/30"],
            protocols=["snmp"],
        )
        cls.profile_no_protocols = DiscoveryProfile.objects.create(
            name="NDD No Protocols",
            included_ip_prefixes=["10.12.2.0/30"],
            protocols=[],
        )

    @staticmethod
    def _snmp_info(ip_str):
        return {
            "hostname": f"ndd-{ip_str.split('.')[-1]}",
            "sys_descr": "Cisco IOS-XE 17.3",
            "sys_object_id": "1.3.6.1.4.1.9.1.675.1.2.3",
            "platform_info": {"platform_name": "cisco_iosxe", "manufacturer_name": "Cisco", "network_driver": "cisco_iosxe"},
            "vendor": "Cisco",
            "model": "C9300",
            "serial": f"N{ip_str.split('.')[-1]}",
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

    def test_requires_profile(self):
        result = NetworkDeviceDiscoveryJob().run(
            target_network="10.12.0.0/30",
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

    def test_profile_protocols_drive_phases(self):
        """SNMP-only profile: ping and SSH phases must be skipped even if toggled on."""
        captured = {}

        def fake_full_run(job_self, **kwargs):
            captured["enable_ping"] = kwargs.get("enable_ping")
            captured["enable_snmp"] = kwargs.get("enable_snmp")
            captured["enable_ssh"] = kwargs.get("enable_ssh")
            return {"ok": True}

        with patch.object(NetworkDeviceDiscoveryJob.__bases__[0], "run", fake_full_run):
            NetworkDeviceDiscoveryJob().run(
                target_network="10.12.1.0/30",
                snmp_version="2c",
                snmp_community="public",
                ssh_username="",
                ssh_password="",
                enable_ping=True,
                enable_snmp=True,
                enable_ssh=True,
                profile=self.profile_snmp_only,
                timeout=1,
                concurrency=5,
            )

        self.assertFalse(captured["enable_ping"])
        self.assertTrue(captured["enable_snmp"])
        self.assertFalse(captured["enable_ssh"])

    def test_profile_without_protocols_keeps_toggles(self):
        captured = {}

        def fake_full_run(job_self, **kwargs):
            captured["enable_ping"] = kwargs.get("enable_ping")
            captured["enable_snmp"] = kwargs.get("enable_snmp")
            return {"ok": True}

        with patch.object(NetworkDeviceDiscoveryJob.__bases__[0], "run", fake_full_run):
            NetworkDeviceDiscoveryJob().run(
                target_network="10.12.2.0/30",
                snmp_version="2c",
                snmp_community="public",
                ssh_username="",
                ssh_password="",
                enable_ping=True,
                enable_snmp=True,
                enable_ssh=False,
                profile=self.profile_no_protocols,
                timeout=1,
                concurrency=5,
            )

        self.assertTrue(captured["enable_ping"])
        self.assertTrue(captured["enable_snmp"])

    def test_job_meta_and_registration(self):
        from nautobot.core.celery import registry

        self.assertEqual(NetworkDeviceDiscoveryJob.name, "Network Device Discovery")
        # registered via register_jobs (import-time side effect)
        self.assertIn(
            "nautobot_plugin_device_auto_discovery.jobs.NetworkDeviceDiscoveryJob",
            registry["jobs"],
        )


class RunDiscoveryActionTests(TestCase):
    """Run Device Discovery detail action: GET form + POST enqueue."""

    @classmethod
    def setUpTestData(cls):
        cls.profile = DiscoveryProfile.objects.create(
            name="Run Action Profile",
            included_ip_prefixes=["10.13.0.0/30"],
            protocols=["snmp", "ssh"],
        )

    def _client(self):
        from django.contrib.auth import get_user_model
        from django.test import Client
        from django.contrib.contenttypes.models import ContentType
        from nautobot.extras.models import ObjectPermission

        user = get_user_model().objects.create_user(username="run-discovery-tester", password="pass12345")
        permission = ObjectPermission.objects.create(
            name="run discovery perm",
            actions=["view", "add", "change"],
            constraints={},
        )
        permission.object_types.add(ContentType.objects.get_for_model(DiscoveryProfile))
        permission.users.add(user)
        permission.save()
        client = Client()
        client.force_login(user)
        return client

    def test_get_run_form(self):
        from django.urls import reverse

        client = self._client()
        url = reverse("plugins:nautobot_plugin_device_auto_discovery:discoveryprofile_run-discovery", kwargs={"pk": self.profile.pk})
        response = client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Run Device Discovery")

    def test_post_enqueues_job(self):
        from django.urls import reverse

        from nautobot.extras.models import Job, JobResult

        Job.objects.update_or_create(
            module_name="nautobot_plugin_device_auto_discovery.jobs",
            job_class_name="NetworkDeviceDiscoveryJob",
            defaults={"enabled": True, "grouping": "Discovery"},
        )
        client = self._client()
        url = reverse("plugins:nautobot_plugin_device_auto_discovery:discoveryprofile_run-discovery", kwargs={"pk": self.profile.pk})
        response = client.post(url, {})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(JobResult.objects.exists())
