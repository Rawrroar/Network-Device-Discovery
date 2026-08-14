"""Inventory correlation engine.

Matches a discovered device against the Nautobot inventory using up to
three identifying attributes - primary IPv4/IPv6, hostname, and serial
number - and assigns one of four correlation statuses, mirroring the
Nautobot Device Discovery app:

- ``imported``            exactly one device matches and all known
                          attributes agree
- ``new``                 no matching device exists
- ``partially_imported``  exactly one device matches but at least one
                          known attribute differs
- ``conflict``            more than one device matches
"""

from django.db.models import Q

from nautobot.dcim.models import Device
from nautobot.ipam.models import IPAddress


def _devices_with_ip(ip_str):
    """Return devices whose primary IP address matches ``ip_str``."""
    ip_obj = IPAddress.objects.filter(host=ip_str).first()
    if not ip_obj:
        return []
    return list(Device.objects.filter(Q(primary_ip4=ip_obj) | Q(primary_ip6=ip_obj)))


def _normalize(value):
    return (value or "").strip().lower()


def _correlate(ip_str, hostname, serial):
    """Build the set of candidate devices and per-attribute agreement."""
    candidates = {}
    for device in _devices_with_ip(ip_str):
        candidates[device.pk] = device
    if hostname:
        for device in Device.objects.filter(name__iexact=hostname):
            candidates[device.pk] = device
    if serial:
        for device in Device.objects.filter(serial__iexact=_normalize(serial)):
            candidates[device.pk] = device
    return list(candidates.values())


def correlate_device(ip_str, hostname="", serial=""):
    """Correlate discovered identity data against the Nautobot inventory.

    Args:
        ip_str (str): discovered management IP address.
        hostname (str): discovered hostname.
        serial (str): discovered serial number.

    Returns:
        dict with keys ``status``, ``device`` (the matched Device or None),
        ``matches`` (list of candidate Devices) and ``attributes`` (per
        attribute agreement for the single-match case).
    """
    matches = _correlate(ip_str, hostname, serial)

    if not matches:
        return {
            "status": "new",
            "device": None,
            "matches": [],
            "attributes": {"ip": False, "hostname": False, "serial": False},
        }

    if len(matches) > 1:
        return {
            "status": "conflict",
            "device": None,
            "matches": matches,
            "attributes": {"ip": False, "hostname": False, "serial": False},
        }

    device = matches[0]
    attributes = {
        "ip": bool(_devices_with_ip(ip_str)),
        "hostname": bool(hostname) and _normalize(device.name) == _normalize(hostname),
        "serial": bool(serial) and _normalize(device.serial) == _normalize(serial),
    }
    known = {
        attr: value
        for attr, value in attributes.items()
        if {"ip": ip_str, "hostname": hostname, "serial": serial}.get(attr)
    }

    if known and all(known.values()):
        status = "imported"
    else:
        status = "partially_imported"

    return {"status": status, "device": device, "matches": matches, "attributes": attributes}
