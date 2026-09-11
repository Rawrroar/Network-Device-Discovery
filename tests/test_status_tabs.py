"""Tests for DiscoveredDevice list status tabs."""

from django.test import TestCase

from nautobot_plugin_device_auto_discovery.models import DiscoveredDevice


class StatusTabFilteringTests(TestCase):
    """?tab= maps to the right status groupings."""

    @classmethod
    def setUpTestData(cls):
        DiscoveredDevice.objects.create(ip_address="10.14.0.1", hostname="imp-1", status=DiscoveredDevice.CorrelationStatus.IMPORTED)
        DiscoveredDevice.objects.create(ip_address="10.14.0.2", hostname="imp-2", status=DiscoveredDevice.CorrelationStatus.IMPORTED)
        DiscoveredDevice.objects.create(ip_address="10.14.0.3", hostname="new-1", status=DiscoveredDevice.CorrelationStatus.NEW)
        DiscoveredDevice.objects.create(ip_address="10.14.0.4", hostname="new-2", status=DiscoveredDevice.CorrelationStatus.NEW)
        DiscoveredDevice.objects.create(ip_address="10.14.0.5", hostname="part-1", status=DiscoveredDevice.CorrelationStatus.PARTIALLY_IMPORTED)
        DiscoveredDevice.objects.create(ip_address="10.14.0.6", hostname="conf-1", status=DiscoveredDevice.CorrelationStatus.CONFLICT)
        DiscoveredDevice.objects.create(ip_address="10.14.0.7", hostname="nr-1", status=DiscoveredDevice.CorrelationStatus.NOT_REACHABLE)
        DiscoveredDevice.objects.create(ip_address="10.14.0.8", hostname="fail-1", status=DiscoveredDevice.CorrelationStatus.FAILED)

    def _filter_via_tab_mapping(self, tab):
        """Exercise the viewset's tab→status mapping directly (no HTTP)."""
        from nautobot_plugin_device_auto_discovery.views import DiscoveredDeviceUIViewSet

        statuses = next(s for key, _label, s in DiscoveredDeviceUIViewSet.STATUS_TABS if key == tab)
        qs = DiscoveredDevice.objects.all()
        if statuses is not None:
            qs = qs.filter(status__in=statuses)
        return qs

    def test_imported_tab(self):
        ips = set(self._filter_via_tab_mapping("imported").values_list("ip_address", flat=True))
        self.assertEqual(ips, {"10.14.0.1", "10.14.0.2"})

    def test_new_tab(self):
        ips = set(self._filter_via_tab_mapping("new").values_list("ip_address", flat=True))
        self.assertEqual(ips, {"10.14.0.3", "10.14.0.4"})

    def test_conflicts_tab_groups_partial_and_conflict(self):
        ips = set(self._filter_via_tab_mapping("conflicts").values_list("ip_address", flat=True))
        self.assertEqual(ips, {"10.14.0.5", "10.14.0.6"})

    def test_not_reachable_tab(self):
        ips = set(self._filter_via_tab_mapping("not_reachable").values_list("ip_address", flat=True))
        self.assertEqual(ips, {"10.14.0.7"})

    def test_failed_tab(self):
        ips = set(self._filter_via_tab_mapping("failed").values_list("ip_address", flat=True))
        self.assertEqual(ips, {"10.14.0.8"})

    def test_all_tab_is_everything(self):
        statuses = next(s for key, _l, s in DiscoveredDeviceUIViewSet_STATUS_TABS() if key == "all")
        self.assertIsNone(statuses)

    def test_tab_counts(self):
        from nautobot_plugin_device_auto_discovery.views import DiscoveredDeviceUIViewSet

        class FakeView:
            STATUS_TABS = DiscoveredDeviceUIViewSet.STATUS_TABS
            queryset = DiscoveredDevice.objects.all()

            discovered_device_tab_counts = DiscoveredDeviceUIViewSet.discovered_device_tab_counts

        counts = FakeView().discovered_device_tab_counts
        self.assertEqual(counts["imported"], 2)
        self.assertEqual(counts["new"], 2)
        self.assertEqual(counts["conflicts"], 2)
        self.assertEqual(counts["not_reachable"], 1)
        self.assertEqual(counts["failed"], 1)
        self.assertEqual(counts["all"], 8)


def DiscoveredDeviceUIViewSet_STATUS_TABS():
    from nautobot_plugin_device_auto_discovery.views import DiscoveredDeviceUIViewSet

    return DiscoveredDeviceUIViewSet.STATUS_TABS


class StatusTabViewIntegrationTests(TestCase):
    """GET requests to the list view with ?tab= return filtered rows."""

    @classmethod
    def setUpTestData(cls):
        DiscoveredDevice.objects.create(ip_address="10.15.0.1", hostname="int-imp", status=DiscoveredDevice.CorrelationStatus.IMPORTED)
        DiscoveredDevice.objects.create(ip_address="10.15.0.2", hostname="int-new", status=DiscoveredDevice.CorrelationStatus.NEW)

    def _client(self):
        from django.contrib.auth import get_user_model
        from django.contrib.contenttypes.models import ContentType
        from django.test import Client
        from nautobot.extras.models import ObjectPermission

        user = get_user_model().objects.create_user(username="tab-tester", password="pass12345")
        permission = ObjectPermission.objects.create(
            name="tab perm",
            actions=["view"],
            constraints={},
        )
        permission.object_types.add(ContentType.objects.get_for_model(DiscoveredDevice))
        permission.users.add(user)
        permission.save()
        client = Client()
        client.force_login(user)
        return client

    def test_list_without_tab_shows_all(self):
        from django.urls import reverse

        client = self._client()
        response = client.get(reverse("plugins:nautobot_plugin_device_auto_discovery:discovereddevice_list"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "int-imp")
        self.assertContains(response, "int-new")

    def test_list_with_new_tab_shows_only_new(self):
        from django.urls import reverse

        client = self._client()
        response = client.get(
            reverse("plugins:nautobot_plugin_device_auto_discovery:discovereddevice_list"),
            {"tab": "new"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "int-new")
        self.assertNotContains(response, "int-imp")

    def test_list_with_invalid_tab_falls_back_to_all(self):
        from django.urls import reverse

        client = self._client()
        response = client.get(
            reverse("plugins:nautobot_plugin_device_auto_discovery:discovereddevice_list"),
            {"tab": "bogus"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "int-imp")
        self.assertContains(response, "int-new")
