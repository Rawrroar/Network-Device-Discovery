"""Signal handlers keeping classification results in sync.

- When a ``DeviceClassificationRule`` is created, updated, or deleted, all
  Not Imported devices are re-evaluated so results stay consistent with the
  latest rule set.
- When a ``DiscoveredDevice`` is saved with a status other than Not
  Imported, its classification rows are removed; devices that transition
  back to Not Imported are re-classified.
"""

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .models import DeviceClassificationRule, DiscoveredDevice

_SENTINEL = {"recomputing": False}


def _recompute_all_not_imported():
    """Re-classify every Not Imported device once, guarding against recursion."""
    if _SENTINEL["recomputing"]:
        return
    from .classification import classify_all

    _SENTINEL["recomputing"] = True
    try:
        classify_all(recompute=False)
    finally:
        _SENTINEL["recomputing"] = False


@receiver(post_save, sender=DeviceClassificationRule)
def rule_saved(sender, instance, **kwargs):
    _recompute_all_not_imported()


@receiver(post_delete, sender=DeviceClassificationRule)
def rule_deleted(sender, instance, **kwargs):
    _recompute_all_not_imported()


@receiver(post_save, sender=DiscoveredDevice)
def device_saved(sender, instance, **kwargs):
    """Sync classifications with the device's current correlation status."""
    from .classification import classify_device
    from .models import DiscoveredDeviceClassification

    if instance.status == DiscoveredDevice.CorrelationStatus.NEW:
        # Re-classify on create, on full saves, or when identity fields
        # used by rules were touched; skip partial saves of other fields.
        update_fields = kwargs.get("update_fields")
        tracked = {"hostname", "ip_address"}
        if kwargs.get("created") or not update_fields or tracked.intersection(update_fields):
            classify_device(instance)
    else:
        DiscoveredDeviceClassification.objects.filter(discovered_device=instance).delete()
