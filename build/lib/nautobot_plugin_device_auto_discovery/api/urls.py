"""REST API URL configuration."""

from nautobot.apps.api import OrderedDefaultRouter

from nautobot_plugin_device_auto_discovery.api import views

router = OrderedDefaultRouter()

router.register("discovery-scans", views.DiscoveryScanViewSet)
router.register("discovery-results", views.DiscoveryResultViewSet)
router.register("discovery-profiles", views.DiscoveryProfileViewSet)
router.register("discovered-devices", views.DiscoveredDeviceViewSet)

urlpatterns = router.urls
