"""Tests for the Onboard Discovered Devices job and bulk action."""

from django.test import TestCase
from nautobot.dcim.models import Device, Location, LocationType
from nautobot.extras.models import Role, Status
from nautobot.ipam.models import Namespace
from nautobot.extras.test_tools import run_job_for_testing
from nautobot.tenancy.models import Tenant

from nautobot_plugin_device_auto_discovery.jobs import OnboardDiscoveredDevicesJob
from nautobot_plugin_device_auto_discovery.models import (
    DeviceClassificationRule,
    DiscoveredDevice,
    DiscoveredDeviceClassification,
)


class OnboardingJobTestBase(TestCase):
    """Shared fixtures for onboarding tests."""

    @classmethod
    def setUpTestData(cls):
        cls.location_type = LocationType.objects.create(name="Onboard Type", nestable=True)
        cls.location_status = Status.objects.get_for_model(Location).first()
        cls.location = Location.objects.create(
            name="onboard-site",
            location_type=cls.location_type,
            status=cls.location_status,
        )
        cls.role = Role.objects.create(
            name="onboard-role",
            color="teal",
            status=Status.objects.get_for_model(Role).first(),
        )
        cls.tenant = Tenant.objects.create(name="Onboard Tenant")
        cls.device_status = Status.objects.get_for_model(Device).filter(name="Active").first()
        cls.namespace = Namespace.objects.create(name="Onboard Namespace")

    def _discovered(self, ip, hostname, status=DiscoveredDevice.CorrelationStatus.NEW, **kwargs):
        return DiscoveredDevice.objects.create(
            ip_address=ip,
            hostname=hostname,
            status=status,
            vendor="Cisco",
            model="C9300",
            serial=f"SN-{ip.split('.')[-1]}",
            os_version="17.3",
            **kwargs,
        )


class OnboardDiscoveredDevicesJobTests(OnboardingJobTestBase):
    """Job behavior: creation, classification fill, defaults fallback, guards."""

    def test_onboard_creates_devices(self):
        device = self._discovered("10.8.0.1", "ob-switch-01")
        result = run_job_for_testing(
            OnboardDiscoveredDevicesJob,
            data={
                "pk_list": str(device.pk),
                "default_location": self.location,
                "default_role": self.role,
                "fill_from_classification": False,
                "dryrun": False,
            },
        )
        self.assertEqual(result["onboarded"], 1)
        created = Device.objects.filter(name="ob-switch-01").first()
        self.assertIsNotNone(created)
        self.assertEqual(created.location, self.location)
        self.assertEqual(created.role, self.role)
        self.assertEqual(created.serial, "SN-1")

        device.refresh_from_db()
        self.assertEqual(device.device, created)

    def test_onboard_fills_from_classification(self):
        device = self._discovered("10.8.0.2", "ob-switch-02")
        DeviceClassificationRule.objects.create(
            name="loc rule",
            classify_as=DeviceClassificationRule.ClassifyAs.LOCATION,
            source_pattern="^(?P<value>ob)-",
            match_against="dcim.location",
            match_field="name",
            match_operator="iexact",
        )
        classification = DiscoveredDeviceClassification.objects.get(
            discovered_device=device, classify_as="location"
        )
        self.assertEqual(classification.matched_object_id, self.location.pk)

        # No default_location given — classification must supply it
        result = run_job_for_testing(
            OnboardDiscoveredDevicesJob,
            data={
                "pk_list": str(device.pk),
                "default_role": self.role,
                "fill_from_classification": True,
                "dryrun": False,
            },
        )
        self.assertEqual(result["onboarded"], 1)
        created = Device.objects.get(name="ob-switch-02")
        self.assertEqual(created.location, self.location)
        self.assertEqual(created.role, self.role)

    def test_onboard_falls_back_to_defaults(self):
        device = self._discovered("10.8.0.3", "xyz-switch-03")
        # A classification that won't match (hostname doesn't start with 'ob')
        DeviceClassificationRule.objects.create(
            name="loc rule",
            classify_as=DeviceClassificationRule.ClassifyAs.LOCATION,
            source_pattern="^(?P<value>ob)-",
            match_against="dcim.location",
            match_field="name",
            match_operator="iexact",
        )
        result = run_job_for_testing(
            OnboardDiscoveredDevicesJob,
            data={
                "pk_list": str(device.pk),
                "default_location": self.location,
                "default_role": self.role,
                "fill_from_classification": True,
                "dryrun": False,
            },
        )
        self.assertEqual(result["onboarded"], 1)
        created = Device.objects.get(name="xyz-switch-03")
        self.assertEqual(created.location, self.location)

    def test_onboard_tenant_from_classification(self):
        device = self._discovered("10.8.0.4", "tenantA-switch-04")
        DeviceClassificationRule.objects.create(
            name="tenant rule",
            classify_as=DeviceClassificationRule.ClassifyAs.TENANT,
            source_pattern="^(?P<value>tenantA)-",
            match_against="tenancy.tenant",
            match_field="name",
            match_operator="iexact",
        )
        result = run_job_for_testing(
            OnboardDiscoveredDevicesJob,
            data={
                "pk_list": str(device.pk),
                "default_location": self.location,
                "default_role": self.role,
                "fill_from_classification": True,
                "dryrun": False,
            },
        )
        self.assertEqual(result["onboarded"], 1)
        created = Device.objects.get(name="tenantA-switch-04")
        self.assertEqual(created.tenant, self.tenant)

    def test_defaults_required_when_fill_disabled(self):
        device = self._discovered("10.8.0.5", "ob-switch-05")
        result = run_job_for_testing(
            OnboardDiscoveredDevicesJob,
            data={
                "pk_list": str(device.pk),
                "fill_from_classification": False,
                "dryrun": False,
            },
        )
        self.assertIn("error", result)
        self.assertIn("Default Location and Default Role are required", result["error"])
        self.assertFalse(Device.objects.filter(name="ob-switch-05").exists())

    def test_dryrun_creates_nothing(self):
        device = self._discovered("10.8.0.6", "ob-switch-06")
        result = run_job_for_testing(
            OnboardDiscoveredDevicesJob,
            data={
                "pk_list": str(device.pk),
                "default_location": self.location,
                "default_role": self.role,
                "fill_from_classification": False,
                "dryrun": True,
            },
        )
        self.assertEqual(result["onboarded"], 1)
        self.assertFalse(Device.objects.filter(name="ob-switch-06").exists())

    def test_skips_non_new_devices(self):
        device = self._discovered("10.8.0.7", "ob-switch-07", status=DiscoveredDevice.CorrelationStatus.IMPORTED)
        result = run_job_for_testing(
            OnboardDiscoveredDevicesJob,
            data={
                "pk_list": str(device.pk),
                "default_location": self.location,
                "default_role": self.role,
                "fill_from_classification": False,
                "dryrun": False,
            },
        )
        self.assertEqual(result["onboarded"], 0)
        self.assertEqual(result["failed"], 1)
        self.assertFalse(Device.objects.filter(name="ob-switch-07").exists())

    def test_no_matching_pks(self):
        result = run_job_for_testing(
            OnboardDiscoveredDevicesJob,
            data={
                "pk_list": "00000000-0000-0000-0000-000000000000",
                "dryrun": False,
            },
        )
        self.assertIn("error", result)

    def test_bulk_selection(self):
        devices = [
            self._discovered("10.8.1.1", "bulk-switch-01"),
            self._discovered("10.8.1.2", "bulk-switch-02"),
        ]
        pk_list = ",".join(str(d.pk) for d in devices)
        result = run_job_for_testing(
            OnboardDiscoveredDevicesJob,
            data={
                "pk_list": pk_list,
                "default_location": self.location,
                "default_role": self.role,
                "fill_from_classification": False,
                "dryrun": False,
            },
        )
        self.assertEqual(result["onboarded"], 2)
        self.assertTrue(Device.objects.filter(name="bulk-switch-01").exists())
        self.assertTrue(Device.objects.filter(name="bulk-switch-02").exists())

    def test_existing_device_correlation(self):
        # A device that already exists in Nautobot: onboarding links, not duplicates
        from nautobot.dcim.models import Manufacturer, DeviceType

        manufacturer = Manufacturer.objects.create(name="Onboard Mfr")
        device_type = DeviceType.objects.create(model="OB-9300", manufacturer=manufacturer)
        existing = Device.objects.create(
            name="ob-switch-08",
            device_type=device_type,
            role=self.role,
            location=self.location,
            status=self.device_status,
            serial="SN-8",
        )
        device = self._discovered("10.8.0.8", "ob-switch-08", serial="SN-8")
        result = run_job_for_testing(
            OnboardDiscoveredDevicesJob,
            data={
                "pk_list": str(device.pk),
                "default_location": self.location,
                "default_role": self.role,
                "fill_from_classification": False,
                "dryrun": False,
            },
        )
        self.assertEqual(result["existing"], 1)
        device.refresh_from_db()
        self.assertEqual(device.device, existing)


class OnboardActionPermissionTests(OnboardingJobTestBase):
    """The GET form renders for a logged-in superuser via test client."""

    def test_get_onboard_form(self):
        from django.contrib.auth import get_user_model
        from django.test import Client
        from nautobot.extras.models import ObjectPermission
        from django.contrib.contenttypes.models import ContentType
        from django.urls import reverse

        user = get_user_model().objects.create_user(username="onboard-tester", password="pass12345")
        permission = ObjectPermission.objects.create(
            name="onboard perm",
            actions=["view", "change", "add"],
            constraints={},
        )
        permission.object_types.add(
            ContentType.objects.get_for_model(DiscoveredDevice),
            ContentType.objects.get_for_model(Device),
        )
        permission.users.add(user)
        permission.save()

        device = self._discovered("10.8.2.1", "perm-switch-01")
        client = Client()
        client.force_login(user)
        url = reverse("plugins:nautobot_plugin_device_auto_discovery:discovereddevice_onboard")
        response = client.get(url, {"pk": str(device.pk)})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Onboard 1 discovered device")
