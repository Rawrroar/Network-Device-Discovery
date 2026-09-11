"""Tests for automated device classification: validation, engine, signals."""

from django.core.exceptions import ValidationError
from django.test import TestCase

from nautobot.dcim.models import Location, LocationType
from nautobot.extras.models import Role, Status
from nautobot.tenancy.models import Tenant

from nautobot_plugin_device_auto_discovery.classification import classify_device
from nautobot_plugin_device_auto_discovery.models import (
    DeviceClassificationRule,
    DiscoveredDevice,
    DiscoveredDeviceClassification,
)


class RuleValidationTests(TestCase):
    """Model-level validation of DeviceClassificationRule."""

    def test_pattern_requires_named_group(self):
        rule = DeviceClassificationRule(
            name="bad",
            classify_as=DeviceClassificationRule.ClassifyAs.LOCATION,
            source_pattern="^(ams)-",
            match_against="dcim.location",
        )
        with self.assertRaises(ValidationError) as ctx:
            rule.full_clean()
        self.assertIn("source_pattern", ctx.exception.message_dict)

    def test_pattern_must_compile(self):
        rule = DeviceClassificationRule(
            name="bad",
            classify_as=DeviceClassificationRule.ClassifyAs.LOCATION,
            source_pattern="^(?P<value>[a-z",
            match_against="dcim.location",
        )
        with self.assertRaises(ValidationError) as ctx:
            rule.full_clean()
        self.assertIn("source_pattern", ctx.exception.message_dict)

    def test_match_against_must_match_classify_as(self):
        rule = DeviceClassificationRule(
            name="bad",
            classify_as=DeviceClassificationRule.ClassifyAs.LOCATION,
            source_pattern="^(?P<value>[a-z]+)-",
            match_against="extras.role",
        )
        with self.assertRaises(ValidationError) as ctx:
            rule.full_clean()
        self.assertIn("match_against", ctx.exception.message_dict)

    def test_match_filters_depth_limit(self):
        rule = DeviceClassificationRule(
            name="bad",
            classify_as=DeviceClassificationRule.ClassifyAs.LOCATION,
            source_pattern="^(?P<value>[a-z]+)-",
            match_against="dcim.location",
            match_filters={"a__b__c__d": "x"},
        )
        with self.assertRaises(ValidationError) as ctx:
            rule.full_clean()
        self.assertIn("match_filters", ctx.exception.message_dict)

    def test_valid_rule_passes(self):
        rule = DeviceClassificationRule(
            name="good",
            classify_as=DeviceClassificationRule.ClassifyAs.ROLE,
            source_pattern="-(?P<value>core|edge)-",
            match_against="extras.role",
            match_operator="iexact",
        )
        rule.full_clean()


class ClassificationEngineTests(TestCase):
    """Engine behavior: weight order, exactly-one, ip_scope, transforms."""

    @classmethod
    def setUpTestData(cls):
        cls.location_type = LocationType.objects.create(name="Classify Type", nestable=True)
        cls.location_status = Status.objects.get_for_model(Location).first()
        cls.location = Location.objects.create(
            name="ams",
            location_type=cls.location_type,
            status=cls.location_status,
        )
        cls.role = Role.objects.create(
            name="core",
            color="blue",
            status=Status.objects.get_for_model(Role).first(),
        )
        cls.tenant = Tenant.objects.create(name="Tenant A")

    def _rule(self, **kwargs):
        defaults = {
            "name": "rule",
            "classify_as": DeviceClassificationRule.ClassifyAs.LOCATION,
            "source_pattern": "^(?P<value>[a-z]{2,4})-",
            "match_against": "dcim.location",
            "match_field": "name",
            "match_operator": "exact",
        }
        defaults.update(kwargs)
        return DeviceClassificationRule.objects.create(**defaults)

    def _device(self, hostname, ip="10.99.0.1", status=DiscoveredDevice.CorrelationStatus.NEW):
        return DiscoveredDevice.objects.create(ip_address=ip, hostname=hostname, status=status)

    def test_location_from_hostname(self):
        self._rule(name="site code")
        device = self._device("ams-core-01")
        results = classify_device(device)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].classify_as, "location")
        self.assertEqual(results[0].matched_object_id, self.location.pk)
        self.assertIn("ams", results[0].reason)

    def test_multiple_targets_independent(self):
        self._rule(name="site", classify_as=DeviceClassificationRule.ClassifyAs.LOCATION)
        self._rule(
            name="role kw",
            classify_as=DeviceClassificationRule.ClassifyAs.ROLE,
            source_pattern="-(?P<value>core|edge)-",
            match_against="extras.role",
        )
        device = self._device("ams-core-01")
        results = classify_device(device)
        self.assertEqual(
            sorted(r.classify_as for r in results),
            ["location", "role"],
        )

    def test_zero_matches_is_no_match(self):
        self._rule()
        device = self._device("xyz-core-01")
        results = classify_device(device)
        self.assertEqual(results, [])
        self.assertFalse(DiscoveredDeviceClassification.objects.exists())

    def test_multiple_matches_is_no_match(self):
        Location.objects.create(name="ams2", location_type=self.location_type, status=self.location_status)
        self._rule(match_operator="istartswith")
        device = self._device("ams-core-01")
        results = classify_device(device)
        self.assertEqual(results, [])

    def test_weight_order_wins(self):
        fallback = Location.objects.create(name="fallback", location_type=self.location_type, status=self.location_status)
        self._rule(name="precise", weight=10)
        self._rule(
            name="loose",
            weight=20,
            source_pattern="^(?P<value>[a-z]+)-",
        )
        device = self._device("ams-core-01")
        results = classify_device(device)
        self.assertEqual(results[0].matched_rule.name, "precise")
        self.assertNotEqual(results[0].matched_object_id, fallback.pk)

    def test_inactive_rules_skipped(self):
        self._rule(name="off", is_active=False)
        device = self._device("ams-core-01")
        self.assertEqual(classify_device(device), [])

    def test_ip_scope_excludes(self):
        self._rule(ip_scope=["10.50.0.0/16"])
        device = self._device("ams-core-01")
        self.assertEqual(classify_device(device), [])

    def test_ip_scope_includes(self):
        self._rule(ip_scope=["10.99.0.0/24"])
        device = self._device("ams-core-01")
        results = classify_device(device)
        self.assertEqual(len(results), 1)

    def test_transform_lowercase(self):
        Location.objects.create(name="nyc", location_type=self.location_type, status=self.location_status)
        self._rule(name="upper site", source_pattern="^(?P<value>[A-Z]{3})-", transform=DeviceClassificationRule.Transform.LOWERCASE)
        device = self._device("NYC-core-01")
        results = classify_device(device)
        self.assertEqual(results[0].matched_object_id, Location.objects.get(name="nyc").pk)

    def test_match_filters_narrow_lookup(self):
        self._rule(match_filters={"status__name": self.location_status.name})
        device = self._device("ams-core-01")
        results = classify_device(device)
        self.assertEqual(len(results), 1)

    def test_non_new_device_not_classified_and_rows_purged(self):
        self._rule()
        device = self._device("ams-core-01", status=DiscoveredDevice.CorrelationStatus.IMPORTED)
        results = classify_device(device)
        self.assertEqual(results, [])
        self.assertFalse(DiscoveredDeviceClassification.objects.exists())

    def test_tenant_classification(self):
        self._rule(
            name="tenant rule",
            classify_as=DeviceClassificationRule.ClassifyAs.TENANT,
            source_pattern="^(?P<value>tenant)-",
            match_against="tenancy.tenant",
            match_operator="icontains",
        )
        device = self._device("tenantA-core-01")
        results = classify_device(device)
        # 'tenantA' icontains 'tenant' matches the single Tenant
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].matched_object_id, self.tenant.pk)


class ClassificationSignalTests(TestCase):
    """Signal-driven recomputation and stale-row purging."""

    @classmethod
    def setUpTestData(cls):
        cls.location_type = LocationType.objects.create(name="Signal Type", nestable=True)
        cls.location = Location.objects.create(
            name="sig",
            location_type=cls.location_type,
            status=Status.objects.get_for_model(Location).first(),
        )

    def _rule(self):
        return DeviceClassificationRule.objects.create(
            name="signal rule",
            classify_as=DeviceClassificationRule.ClassifyAs.LOCATION,
            source_pattern="^(?P<value>[a-z]+)-",
            match_against="dcim.location",
            match_field="name",
            match_operator="exact",
        )

    def test_rule_save_triggers_classification(self):
        device = DiscoveredDevice.objects.create(ip_address="10.88.0.1", hostname="sig-core-01")
        self._rule()
        self.assertTrue(
            DiscoveredDeviceClassification.objects.filter(discovered_device=device, classify_as="location").exists()
        )

    def test_rule_delete_purges_classifications(self):
        device = DiscoveredDevice.objects.create(ip_address="10.88.0.2", hostname="sig-core-02")
        rule = self._rule()
        self.assertTrue(DiscoveredDeviceClassification.objects.filter(discovered_device=device).exists())
        rule.delete()
        self.assertFalse(DiscoveredDeviceClassification.objects.filter(discovered_device=device).exists())

    def test_device_status_change_purges_classifications(self):
        self._rule()
        device = DiscoveredDevice.objects.create(ip_address="10.88.0.3", hostname="sig-core-03")
        self.assertTrue(DiscoveredDeviceClassification.objects.filter(discovered_device=device).exists())
        device.status = DiscoveredDevice.CorrelationStatus.IMPORTED
        device.save()
        self.assertFalse(DiscoveredDeviceClassification.objects.filter(discovered_device=device).exists())
