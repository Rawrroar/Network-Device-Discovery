"""Automated classification engine for Not Imported discovered devices.

Given a :class:`~nautobot_plugin_device_auto_discovery.models.DiscoveredDevice`
with status ``new`` (Not Imported), evaluates the enabled
:class:`~nautobot_plugin_device_auto_discovery.models.DeviceClassificationRule`
records to derive Location, Role, and Tenant suggestions, persisting the
results as
:class:`~nautobot_plugin_device_auto_discovery.models.DiscoveredDeviceClassification`
rows.

Evaluation per target (Location / Role / Tenant), in rule weight order:

1. If the rule has an ``ip_scope``, the device IP must fall within one of
   the listed prefixes; otherwise the rule is skipped.
2. The ``source_pattern`` regex is applied to the device hostname; it must
   contain a named ``(?P<value>...)`` group — the captured substring is the
   extracted value.
3. The optional ``transform`` is applied (``lowercase`` / ``uppercase``).
4. The target model is queried with
   ``{match_field}__{match_operator}=extracted_value`` narrowed by
   ``match_filters``.
5. If **exactly one** object matches, it is recorded together with the rule
   that produced it. Zero or multiple matches are treated as no match and
   the next rule is tried.

The three targets are evaluated independently. Classification only ever
adds suggestions — it never modifies devices, changes correlation status,
or triggers onboarding.
"""

import ipaddress
import logging
import re

from django.contrib.contenttypes.models import ContentType
from django.utils.module_loading import import_string

from .models import DeviceClassificationRule, DiscoveredDeviceClassification

logger = logging.getLogger(__name__)

# classify_as value -> importable model path
_TARGET_MODEL_PATHS = {
    DeviceClassificationRule.ClassifyAs.LOCATION: "nautobot.dcim.models.Location",
    DeviceClassificationRule.ClassifyAs.ROLE: "nautobot.extras.models.Role",
    DeviceClassificationRule.ClassifyAs.TENANT: "nautobot.tenancy.models.Tenant",
}

_TRANSFORMS = {
    DeviceClassificationRule.Transform.LOWERCASE: str.lower,
    DeviceClassificationRule.Transform.UPPERCASE: str.upper,
}


def _model_for_rule(rule):
    """Resolve the Django model a rule matches against, validating the target."""
    if rule.classify_as not in _TARGET_MODEL_PATHS:
        return None
    expected_app, expected_model = DeviceClassificationRule.TARGET_MODEL_MAP[rule.classify_as]
    actual = (rule.match_against or "").lower().strip().rstrip("s")
    if actual != f"{expected_app}.{expected_model}":
        return None
    try:
        return import_string(_TARGET_MODEL_PATHS[rule.classify_as])
    except (ImportError, AttributeError):
        return None


def _ip_in_scope(ip_str, ip_scope):
    """Return True when the device IP falls within one of the scope prefixes."""
    if not ip_scope:
        return True
    if not ip_str:
        return False
    try:
        address = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for prefix in ip_scope:
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except (ValueError, TypeError):
            continue
        if address.version == network.version and address in network:
            return True
    return False


def _extract_value(rule, device):
    """Apply the rule regex (+ optional transform) to the device hostname.

    Patterns are matched case-insensitively (hostnames are frequently
    upper-cased on devices); the optional ``transform`` is applied to the
    extracted value afterwards. Returns the extracted string or None when
    there is no match.
    """
    try:
        pattern = re.compile(rule.source_pattern, re.IGNORECASE)
    except re.error:
        return None
    source = device.hostname or ""
    if not source:
        return None
    match = pattern.search(source)
    if not match:
        return None
    try:
        value = match.group("value")
    except (IndexError, KeyError):
        return None
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    transform = _TRANSFORMS.get(rule.transform)
    if transform:
        value = transform(value)
    return value


def _match_object(rule, model, value):
    """Run the target lookup, returning ``(match_or_none, filter_description)``."""
    if not rule.match_field:
        return None, ""
    filter_expr = f"{rule.match_field}__{rule.match_operator}"
    try:
        queryset = model.objects.filter(**{filter_expr: value})
        if rule.match_filters:
            queryset = queryset.filter(**rule.match_filters)
        matches = list(queryset[:2])
    except Exception as exc:  # invalid field/operator — treated as no match
        logger.debug("Classification lookup failed for rule %s: %s", rule, exc)
        return None, ""
    if len(matches) != 1:
        return None, f"{filter_expr}={value!r}"
    return matches[0], f"{filter_expr}={value!r}"


def classify_device(device):
    """Compute and persist classifications for a single discovered device.

    Only devices in the Not Imported (``new``) state are classified; for any
    other state any existing classification rows are removed. Existing rows
    are replaced so the results always reflect the current rule set.

    Returns the list of created/updated DiscoveredDeviceClassification rows.
    """
    from .models import DiscoveredDevice

    if device.status != DiscoveredDevice.CorrelationStatus.NEW:
        deleted, _ = DiscoveredDeviceClassification.objects.filter(discovered_device=device).delete()
        if deleted:
            logger.debug("Removed %d stale classification(s) for %s", deleted, device)
        return []

    results = []
    for classify_as, model_path in _TARGET_MODEL_PATHS.items():
        winner = None
        rules = DeviceClassificationRule.objects.filter(classify_as=classify_as, is_active=True).order_by(
            "weight", "name"
        )
        for rule in rules:
            model = _model_for_rule(rule)
            if model is None:
                continue
            if not _ip_in_scope(device.ip_address, rule.ip_scope):
                continue
            value = _extract_value(rule, device)
            if value is None:
                continue
            match, filter_desc = _match_object(rule, model, value)
            if match is None:
                continue
            winner = (rule, model, match, value, filter_desc)
            break

        if winner is None:
            DiscoveredDeviceClassification.objects.filter(
                discovered_device=device, classify_as=classify_as
            ).delete()
            continue

        rule, model, match, value, filter_desc = winner
        obj, _ = DiscoveredDeviceClassification.objects.update_or_create(
            discovered_device=device,
            classify_as=classify_as,
            defaults={
                "matched_object_type": ContentType.objects.get_for_model(model, for_concrete_model=False),
                "matched_object_id": match.pk,
                "matched_rule": rule,
                "reason": f"Rule \"{rule.name}\": extracted \"{value}\" from 'hostname' — "
                f"matched {rule.match_against} {rule.match_field}={getattr(match, rule.match_field, '')}",
            },
        )
        results.append(obj)

    return results


def classify_all(recompute=False):
    """Classify every Not Imported device (optionally all devices).

    Args:
        recompute: when True, also re-evaluates devices whose status is not
            ``new`` in order to purge stale classification rows.

    Returns the number of devices processed.
    """
    from .models import DiscoveredDevice

    queryset = DiscoveredDevice.objects.all()
    if not recompute:
        queryset = queryset.filter(status=DiscoveredDevice.CorrelationStatus.NEW)
    count = 0
    for device in queryset.iterator():
        classify_device(device)
        count += 1
    return count
