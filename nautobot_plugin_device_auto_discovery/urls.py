"""URL configuration for the Device Auto-Discovery plugin UI."""

from nautobot.apps.urls import NautobotUIViewSetRouter

from . import views

router = NautobotUIViewSetRouter()
router.register("discovery-scans", views.DiscoveryScanUIViewSet)
router.register("discovery-results", views.DiscoveryResultUIViewSet)
router.register("discovery-profiles", views.DiscoveryProfileUIViewSet)
router.register("discovered-devices", views.DiscoveredDeviceUIViewSet)
router.register("discovery-profile-secrets-groups", views.DiscoveryProfileSecretsGroupAssignmentUIViewSet)

urlpatterns = router.urls
