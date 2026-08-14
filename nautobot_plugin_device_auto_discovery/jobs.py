"""Job classes for network device discovery.

Provides Jobs for ICMP ping sweeps, SNMP discovery, SSH discovery,
and a full discovery orchestrator that combines all methods.
"""

import logging
import re
import socket
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

import netaddr

from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from netaddr import IPNetwork, IPAddress

from nautobot.apps.jobs import (
    BooleanVar,
    ChoiceVar,
    DryRunVar,
    IntegerVar,
    IPNetworkVar,
    Job,
    ObjectVar,
    register_jobs,
    StringVar,
    TextVar,
)
from nautobot.dcim.choices import CableTypeChoices
from nautobot.dcim.models import (
    Cable,
    Device,
    DeviceType,
    Interface,
    Location,
    LocationType,
    Manufacturer,
    Platform,
)
from nautobot.extras.models import Role
from nautobot.extras.models import Status, Tag
from nautobot.ipam.models import IPAddress, Namespace, Prefix, VLAN, VLANGroup

from .models import DiscoveryProfile, DiscoveryResult, DiscoveryScan, DiscoveredDevice
from .correlation import correlate_device
from .mappings import lookup_platform_from_oid
from .snmp_tables import discover_snmp_tables, find_chassis_model, find_chassis_serial, snmp_get
from .ssh_profiles import SSH_PROFILES, GENERIC_INFO_COMMANDS
from .utils import strip_domain_suffixes

# Common SNMP constants kept for backward compatibility
from .snmp_tables import (
    OID_SYSCONTACT as SNMP_OID_SYSCONTACT,
    OID_SYSDESCR as SNMP_OID_SYSDescR,
    OID_SYSLOCATION as SNMP_OID_SYSLOCATION,
    OID_SYSNAME as SNMP_OID_SYSNAME,
    OID_SYSOBJECTID as SNMP_OID_SYSOBJECTID,
)

OPER_STATUS_UP = 1


VENDOR_KEYWORDS = {
    "cisco": "Cisco",
    "juniper": "Juniper Networks",
    "arista": "Arista Networks",
    "hp|hpe|procurve": "HPE",
    "nokia|alcatel": "Nokia",
    "ubiquiti|edge|unifi|ucos|dream machine": "Ubiquiti",
    "f5|bigip": "F5 Networks",
    "palo alto|panos|paloalto": "Palo Alto Networks",
    "fortinet|forti": "Fortinet",
    "epson": "Seiko Epson",
}

# Vendor-specific regexes used to extract a model from sysDescr.
VENDOR_MODEL_PATTERNS = {
    "Ubiquiti": [r"\bUniFi\s+([A-Za-z0-9][A-Za-z0-9\-]*)", r"\b(?:USW|UCG|UDM|UAP|USG)[A-Za-z0-9\-]*"],
    "Cisco": [r"\b(C[A-Z0-9]{2,6}(?:-[A-Z0-9]+)+)\b"],
    "Arista Networks": [r"\b(DCS(?:-[A-Za-z0-9]+)+)\b"],
    "Juniper Networks": [r"\b(ex\d+|mx\d+|qfx\d+|srx\d+)\b"],
    "HPE": [r"\b(?:HP\s+)?(?:Aruba|ProCurve|Comware|FlexFabric)\s+([A-Za-z0-9\-]+)"],
}

# sysLocation/sysContact values that mean "not configured" and should be ignored.
PLACEHOLDER_SYSTEM_VALUES = {"", "location", "contact", "unknown", "none", "n/a", "na", "0", "not set", "not available"}


def detect_vendor_from_descr(sys_descr):
    """Detect the vendor name from a sysDescr string using keyword patterns."""
    if not sys_descr:
        return ""
    for pattern, vendor_name in VENDOR_KEYWORDS.items():
        if re.search(pattern, sys_descr, re.IGNORECASE):
            return vendor_name
    return ""


def parse_model_from_descr(sys_descr, vendor=""):
    """Extract a device model from sysDescr.

    Uses vendor-specific patterns first, then falls back to the first
    alphanumeric token that looks like a product name.
    """
    if not sys_descr:
        return ""
    for regex in VENDOR_MODEL_PATTERNS.get(vendor, []):
        match = re.search(regex, sys_descr, re.IGNORECASE)
        if match:
            return match.group(1) if match.groups() else match.group(0).strip()
    for token in sys_descr.split():
        if not re.match(r"^[A-Za-z][A-Za-z0-9\-_.]*$", token):
            continue
        if not (re.search(r"[A-Za-z]", token) and re.search(r"\d", token)):
            continue
        if re.match(r"^\d+(\.\d+)+$", token):
            continue
        return token
    return ""


def parse_os_version_from_descr(sys_descr):
    """Extract an OS/software version from sysDescr."""
    if not sys_descr:
        return ""
    for pattern in (r"Version\s+([0-9.]+)", r"version\s+([0-9.]+)", r"\bv(\d+(?:\.\d+)+)"):
        match = re.search(pattern, sys_descr)
        if match:
            return match.group(1)
    match = re.search(r"(?<![\w])(\d+\.\d+(?:\.\d+)?)(?![\w.])", sys_descr)
    return match.group(1) if match else ""


def clean_system_scalar(value):
    """Strip placeholder/default sysLocation/sysContact values to empty string."""
    cleaned = (value or "").strip()
    if cleaned.lower() in PLACEHOLDER_SYSTEM_VALUES:
        return ""
    return cleaned


logger = logging.getLogger(__name__.split(".")[0])


def get_plugin_config():
    """Retrieve plugin configuration from PLUGINS_CONFIG."""
    return settings.PLUGINS_CONFIG.get("nautobot_plugin_device_auto_discovery", {})


def get_or_create_default_location(config):
    """Get or create the default Location for discovered devices."""
    location_name = config.get("default_location", "Unknown")
    location_type, _ = LocationType.objects.get_or_create(
        name=location_name + " Type",
        defaults={"nestable": True},
    )
    # Nautobot 3.x: a LocationType must list dcim.device in its
    # content_types for Devices to be valid in its Locations.
    device_content_type = ContentType.objects.get_for_model(Device)
    if device_content_type not in location_type.content_types.all():
        location_type.content_types.add(device_content_type)
    status = Status.objects.get_for_model(Location).first()
    location, _ = Location.objects.get_or_create(
        name=location_name,
        defaults={
            "location_type": location_type,
            "status": status,
        },
    )
    return location


def get_or_create_default_role(config):
    """Get or create the default DeviceRole for discovered devices."""
    role_name = config.get("default_role", "Network Device")
    role, _ = Role.objects.get_or_create(
        name=role_name,
        defaults={
            # Nautobot 3.x expects a hex RGB code, not a named color.
            "color": config.get("default_role_color", "006cd1"),
        },
    )
    # Nautobot 3.x: a Role must list dcim.device in its content_types
    # to be a valid role choice for Devices.
    device_content_type = ContentType.objects.get_for_model(Device)
    if device_content_type not in role.content_types.all():
        role.content_types.add(device_content_type)
    return role


def get_or_create_default_status(config):
    """Get or create the default Status for discovered devices."""
    status_name = config.get("default_status", "Active")
    try:
        return Status.objects.get_for_model(Device).get(name=status_name)
    except Status.DoesNotExist:
        return Status.objects.get_for_model(Device).first()


def get_or_create_manufacturer(vendor_name):
    """Get or create a Manufacturer from a vendor name."""
    vendor_clean = vendor_name.strip().title()
    manufacturer, _ = Manufacturer.objects.get_or_create(
        name=vendor_clean,
    )
    return manufacturer


def get_or_create_platform(platform_name, network_driver, manufacturer_name):
    """Get or create a Platform object."""
    platform, created = Platform.objects.get_or_create(
        name=platform_name,
        defaults={
            "network_driver": network_driver or "",
            "manufacturer": Manufacturer.objects.filter(name__iexact=manufacturer_name).first(),
        },
    )
    return platform, created


def get_or_create_device_type(model_name, manufacturer):
    """Get or create a DeviceType from a model name and manufacturer."""
    model_clean = model_name.strip()
    if not model_clean:
        model_clean = "Unknown"
    device_type, _ = DeviceType.objects.get_or_create(
        model=model_clean,
        defaults={
            "manufacturer": manufacturer,
            "part_number": "",
        },
    )
    return device_type


def resolve_nautobot_objects(hostname, ip_str, vendor, model, serial, os_version, platform_info, config):
    """Resolve or create all Nautobot objects needed for a device.

    Returns:
        dict with keys: device, platform, device_type, manufacturer, location, role, status, created
    """
    create_missing = config.get("create_missing_objects", True)
    if not create_missing:
        return None

    manufacturer_name = (platform_info.get("manufacturer_name") if platform_info else "") or vendor or "Unknown"
    manufacturer = get_or_create_manufacturer(manufacturer_name)

    if platform_info:
        platform, _ = get_or_create_platform(
            platform_info["platform_name"],
            platform_info.get("network_driver", ""),
            platform_info["manufacturer_name"],
        )
    else:
        platform_name = os_version or f"{manufacturer_name} {model or 'Unknown'}"
        platform, _ = get_or_create_platform(
            platform_name,
            "",
            manufacturer_name,
        )

    device_type = get_or_create_device_type(model or "Unknown", manufacturer)
    location = get_or_create_default_location(config)
    role = get_or_create_default_role(config)
    status = get_or_create_default_status(config)

    # Check if device already exists
    existing_device = Device.objects.filter(name=hostname).first()
    if existing_device:
        # Upgrade devices that were previously auto-created with no usable
        # model/vendor info (e.g. a "Unknown" device type). Only touch fields
        # that are placeholder/empty so manual data is never overwritten.
        needs_device_save = False
        current_type = existing_device.device_type.model if existing_device.device_type else ""
        current_mfr = (
            existing_device.device_type.manufacturer.name
            if existing_device.device_type and existing_device.device_type.manufacturer
            else ""
        )
        is_placeholder_type = (not current_type) or current_type.lower() in ("unknown", "default")

        if model and is_placeholder_type:
            existing_device.device_type = device_type
            needs_device_save = True
        elif is_placeholder_type and current_mfr == "Unknown" and manufacturer.name != "Unknown":
            existing_device.device_type.manufacturer = manufacturer
            existing_device.device_type.save()

        if not existing_device.platform and platform:
            existing_device.platform = platform
            needs_device_save = True
        elif existing_device.platform and manufacturer.name != "Unknown":
            # Keep the platform in sync when the device type was upgraded from
            # a placeholder: a platform whose manufacturer is a stale "Unknown"
            # makes the Device fail validation ("platform is limited to ...").
            current_platform_mfr = (
                existing_device.platform.manufacturer.name
                if existing_device.platform.manufacturer
                else ""
            )
            if current_platform_mfr == "Unknown":
                existing_device.platform.manufacturer = manufacturer
                existing_device.platform.save()

        if serial and not existing_device.serial:
            existing_device.serial = serial
            needs_device_save = True

        if needs_device_save:
            existing_device.save()

        return {
            "device": existing_device,
            "platform": platform,
            "device_type": device_type,
            "manufacturer": manufacturer,
            "location": location,
            "role": role,
            "status": status,
            "created": False,
        }

    return {
        "device": None,
        "platform": platform,
        "device_type": device_type,
        "manufacturer": manufacturer,
        "location": location,
        "role": role,
        "status": status,
        "created": True,
    }


def create_device_in_nautobot(
    hostname, ip_str, vendor, model, serial, os_version, platform_info, config, discovery_scan, discovered_info=None
):
    """Create a Device object in Nautobot from discovered data.

    When ``discovered_info`` (the dict from ``snmp_discover_device``) is
    provided, interfaces and IP addresses discovered via SNMP are also
    populated onto the Device.

    Returns:
        tuple: (device, result_status, error_message)
    """
    try:
        resolved = resolve_nautobot_objects(
            hostname, ip_str, vendor, model, serial, os_version, platform_info, config
        )
        if not resolved:
            return None, "failed", "create_missing_objects is disabled in config"

        discovered_info = discovered_info or {}
        serial = serial or (discovered_info.get("serial") or "")
        sys_contact = discovered_info.get("sys_contact") or ""
        sys_location = discovered_info.get("sys_location") or ""

        if resolved["device"]:
            device = resolved["device"]
            status = "existing"
            logger.info("Device %s already exists in Nautobot", hostname)
        else:
            comments = (
                f"Auto-discovered via device-auto-discovery plugin.\n"
                f"OS: {os_version}\nVendor: {vendor}\nModel: {model}"
            )
            if sys_location:
                comments += f"\nLocation: {sys_location}"
            if sys_contact:
                comments += f"\nContact: {sys_contact}"
            device = Device.objects.create(
                name=hostname,
                platform=resolved["platform"],
                device_type=resolved["device_type"],
                role=resolved["role"],
                location=resolved["location"],
                status=resolved["status"],
                serial=serial or "",
                comments=comments,
            )
            # Assign tags
            for tag_name in config.get("default_tags", ["auto-discovered"]):
                tag, _ = Tag.objects.get_or_create(name=tag_name)
                device.tags.add(tag)
            status = "new"
            logger.info("Created device %s in Nautobot", hostname)

        # Populate interfaces / IP addresses from SNMP tables
        if discovered_info:
            populate_device_from_snmp(device, discovered_info, config, ip_str)

        # Assign primary IP (fallback) if not already set by SNMP table population
        if ip_str and not device.primary_ip4:
            try:
                # Nautobot 3.x: IPAddress must have a containing Prefix in its
                # Namespace, otherwise creation fails silently (0 IPs registered).
                # Host routes (/32) are used for the fallback scan address.
                ensure_parent_prefix(ip_str, 32)
                ip_obj, _ = IPAddress.objects.get_or_create(
                    address=ip_str + "/32",
                    defaults={
                        "status": Status.objects.get_for_model(IPAddress).filter(name="Active").first(),
                    },
                )
                device.primary_ip4 = ip_obj
                device.save(update_fields=["primary_ip4"])
            except Exception as ip_err:
                logger.warning("Could not assign primary IP %s: %s", ip_str, ip_err)

        return device, status, ""

    except Exception as exc:
        logger.error("Failed to create device %s: %s", hostname, exc)
        return None, "failed", str(exc)


# ------------------------------------------------------------------ #
#  Neighbor linking & cable creation                                  #
# ------------------------------------------------------------------ #


def get_cable_status():
    """Return the 'Connected' Status usable for dcim.Cable, else the first."""
    return Status.objects.get_for_model(Cable).filter(name="Connected").first() or Status.objects.get_for_model(
        Cable
    ).first()


def _find_device_by_neighbor_name(remote_name):
    """Find a Device matching an LLDP/CDP neighbor sysName.

    Tries an exact case-insensitive match first, then the short
    (domain-stripped) name. Returns None when nothing matches.
    """
    if not remote_name:
        return None
    device = Device.objects.filter(name__iexact=remote_name).first()
    if device:
        return device
    short_name = remote_name.split(".")[0]
    if short_name and short_name != remote_name:
        return Device.objects.filter(name__iexact=short_name).first()
    return None


def _find_interface_by_ip(ip_str):
    """Find an Interface owning the given IP address, when assigned."""
    if not ip_str:
        return None
    try:
        netaddr.IPAddress(ip_str)
    except Exception:
        return None
    ip_obj = IPAddress.objects.filter(host=ip_str).first()
    if ip_obj and isinstance(ip_obj.assigned_object, Interface):
        return ip_obj.assigned_object
    return None


def _resolve_remote_interface(neighbor):
    """Resolve the far-end Interface of an LLDP/CDP neighbor row.

    Priority: by the neighbor's management IP (when it is assigned to an
    interface), then by remote device name + remote port name.

    Returns:
        Interface or None when the far end cannot be resolved.
    """
    remote_ip = neighbor.get("remote_ip") or ""
    if remote_ip:
        iface = _find_interface_by_ip(remote_ip)
        if iface:
            return iface

    device = _find_device_by_neighbor_name(neighbor.get("remote_name") or "")
    if not device:
        return None
    remote_port = neighbor.get("remote_port") or ""
    if not remote_port:
        return None
    for candidate in (remote_port, remote_port.replace(" ", "")):
        iface = device.interfaces.filter(name__iexact=candidate).first()
        if iface:
            return iface
    return None


def _build_interface_index_map(device, interfaces_data):
    """Map SNMP ifIndex -> Interface for a device, from stored walk data."""
    index_map = {}
    for row in interfaces_data:
        index = str(row.get("index") or "")
        name = (row.get("name") or "").strip()
        if not index or not name:
            continue
        iface = device.interfaces.filter(name__iexact=name).first()
        if iface:
            index_map[index] = iface
    return index_map


def link_neighbors_to_cables(scan, config):
    """Create dcim.Cable objects from the LLDP/CDP neighbors in a scan.

    Idempotent: existing terminations are matched first, and any endpoint
    that is already cabled (or cannot be resolved) is skipped.

    Returns:
        int number of cables created.
    """
    if not config.get("create_cables", True):
        return 0

    status = get_cable_status()
    if not status:
        logger.warning("No Status available for dcim.Cable; skipping cable linking.")
        return 0

    cable_type = None
    type_name = str(config.get("cable_type", "copper")).upper()
    if type_name in CableTypeChoices:
        cable_type = CableTypeChoices[type_name].value

    interface_content_type = ContentType.objects.get_for_model(Interface)
    created = 0
    skipped = 0

    results = scan.results.filter(nautobot_device__isnull=False)
    for result in results.select_related("nautobot_device"):
        device = result.nautobot_device
        data = result.discovered_data or {}
        neighbors = data.get("neighbors") or []
        if not neighbors:
            continue
        iface_map = _build_interface_index_map(device, data.get("interfaces") or [])

        for neighbor in neighbors:
            local_iface = iface_map.get(str(neighbor.get("local_if_index") or ""))
            if not local_iface:
                skipped += 1
                continue
            if getattr(local_iface, "cable", None) is not None:
                skipped += 1
                continue
            remote_iface = _resolve_remote_interface(neighbor)
            if not remote_iface or remote_iface.pk == local_iface.pk:
                skipped += 1
                continue
            if getattr(remote_iface, "cable", None) is not None:
                skipped += 1
                continue

            a_pk, b_pk = sorted((local_iface.pk, remote_iface.pk))
            defaults = {
                "status": status,
                "label": f"auto-discovery {scan.name}",
            }
            if cable_type:
                defaults["type"] = cable_type
            try:
                _cable, was_created = Cable.objects.get_or_create(
                    termination_a_type=interface_content_type,
                    termination_a_id=a_pk,
                    termination_b_type=interface_content_type,
                    termination_b_id=b_pk,
                    defaults=defaults,
                )
            except Exception as exc:
                logger.debug("Cable linking failed %s <-> %s: %s", local_iface, remote_iface, exc)
                skipped += 1
                continue
            if was_created:
                created += 1
            else:
                skipped += 1

    logger.info("Cable linking complete for scan %s: %d created, %d skipped", scan, created, skipped)
    return created


def neighbor_management_ip(neighbor):
    """Resolve the management IP of a neighbor for continuing a crawl.

    Priority: remote management IP from the SNMP walk, then reverse-DNS on
    the neighbor name, then the primary IP of an existing Nautobot Device
    with the same name.

    Returns:
        str IP address, or None when no address can be resolved.
    """
    remote_ip = neighbor.get("remote_ip") or ""
    if remote_ip:
        try:
            netaddr.IPAddress(remote_ip)
            return remote_ip
        except Exception:
            pass

    remote_name = neighbor.get("remote_name") or ""
    if not remote_name:
        return None
    try:
        resolved = socket.gethostbyname(remote_name)
        if resolved:
            return resolved
    except (socket.error, OSError):
        pass

    device = Device.objects.filter(name__iexact=remote_name).first()
    if device and device.primary_ip4:
        return str(device.primary_ip4.address.ip)
    return None


# ------------------------------------------------------------------ #
#  DiscoveryProfile + correlation helpers                              #
# ------------------------------------------------------------------ #


def apply_profile(config, profile):
    """Merge a DiscoveryProfile into the runtime config.

    Profile values take precedence over job-level defaults; job-level
    vars that carry explicit user input (credentials, version, etc.) are
    left untouched.
    """
    if not profile:
        return
    config["profile"] = profile
    if profile.included_ip_prefixes:
        config["target_networks"] = list(profile.included_ip_prefixes)
    config["profile_protocols"] = list(profile.protocols or [])
    config["ssh_port"] = profile.ssh_port or config.get("ssh_port", 22)
    config["snmp_port"] = profile.snmp_port or config.get("snmp_port", 161)
    config["profile_snmp_timeout"] = profile.snmp_timeout
    config["snmp_timeout"] = profile.snmp_timeout or config.get("snmp_timeout", 5)
    config["snmp_retries"] = profile.snmp_retries
    config["fast_path"] = bool(profile.fast_path)
    if profile.snmpv3_auth_protocol:
        config["snmpv3_auth_protocol"] = profile.snmpv3_auth_protocol
    if profile.snmpv3_priv_protocol:
        config["snmpv3_priv_protocol"] = profile.snmpv3_priv_protocol
    if profile.strip_domain_suffixes:
        config["strip_domain_suffixes"] = list(profile.strip_domain_suffixes)


def _resolve_networks(target_network, profile=None):
    """Return ``(networks, excluded)`` for the scan.

    Profile included prefixes (minus exclusions) win over a single
    ``target_network``. Invalid prefixes are skipped.
    """
    networks = []
    excluded = []

    prefixes = []
    if profile and profile.included_ip_prefixes:
        prefixes = list(profile.included_ip_prefixes)
    elif target_network:
        prefixes = [str(target_network)]

    for prefix in prefixes:
        try:
            networks.append(IPNetwork(prefix))
        except (ValueError, TypeError, netaddr.core.AddrFormatError):
            continue

    if profile and profile.excluded_ip_prefixes:
        for prefix in profile.excluded_ip_prefixes:
            try:
                excluded.append(IPNetwork(prefix))
            except (ValueError, TypeError, netaddr.core.AddrFormatError):
                continue

    return networks, excluded


def _expanded_hosts(networks, excluded):
    """Expand ``networks`` into a list of host strings, minus exclusions."""
    hosts = []
    for network in networks:
        for ip in network:
            if any(ip in exclusion for exclusion in excluded):
                continue
            hosts.append(str(ip))
    return hosts


def _correlation_status_for(result_status):
    """Map a DiscoveryResult status to a DiscoveredDevice correlation status."""
    return {
        "existing": DiscoveredDevice.CorrelationStatus.IMPORTED,
        "new": DiscoveredDevice.CorrelationStatus.NEW,
        "partial": DiscoveredDevice.CorrelationStatus.PARTIALLY_IMPORTED,
        "conflict": DiscoveredDevice.CorrelationStatus.CONFLICT,
        "failed": DiscoveredDevice.CorrelationStatus.FAILED,
    }.get(result_status, DiscoveredDevice.CorrelationStatus.NEW)


def _result_discovered_data(info, method):
    """Extract the subset of discovered data worth persisting."""
    if method == "ssh":
        return {"command_outputs": info.get("command_outputs", {})}
    return {
        "interfaces": info.get("interfaces", []),
        "ip_addresses": info.get("ip_addresses", []),
        "arp_table": info.get("arp_table", []),
        "physical": info.get("physical", []),
        "neighbors": info.get("neighbors", []),
        "vlans": info.get("vlans", []),
    }


def upsert_discovered_device(ip_str, info, method, config, *, device, result_status, error, scan):
    """Create or update the persistent per-IP DiscoveredDevice record."""
    now = timezone.now()
    platform_info = info.get("platform_info") or {}
    is_snmp = method == "snmp"
    collection_issue = error if result_status == "failed" else ""

    defaults = {
        "hostname": info.get("hostname", ""),
        "vendor": info.get("vendor", ""),
        "model": info.get("model", ""),
        "device_type": info.get("model", ""),
        "serial": info.get("serial", ""),
        "os_version": info.get("os_version", ""),
        "network_driver": platform_info.get("network_driver", ""),
        "status": _correlation_status_for(result_status),
        "device": device,
        "last_seen": now,
        "last_scan": scan,
        "discovered_data": _result_discovered_data(info, method),
    }
    if is_snmp:
        defaults["snmp_collection"] = True
        defaults["snmp_collection_datetime"] = now
        defaults["snmp_collection_attempt_datetime"] = now
        defaults["snmp_issue"] = collection_issue
        defaults["snmp_port"] = config.get("snmp_port")
    else:
        defaults["ssh_collection"] = True
        defaults["ssh_collection_datetime"] = now
        defaults["ssh_collection_attempt_datetime"] = now
        defaults["ssh_issue"] = collection_issue
        defaults["ssh_port"] = config.get("ssh_port")

    return DiscoveredDevice.objects.update_or_create(ip_address=ip_str, defaults=defaults)[0]


def finalize_discovery(scan, ip_str, method, info, config, *, auto_create=True, dryrun=False):
    """Correlate, (optionally) auto-create, and record a discovered device.

    Returns a 4-tuple ``(result_status, device, error, created_now)``.
    """
    info = dict(info or {})
    info["hostname"] = strip_domain_suffixes(
        info.get("hostname", ""), config.get("strip_domain_suffixes") or []
    )
    hostname = info["hostname"]
    serial = info.get("serial", "")

    corr = correlate_device(ip_str, hostname, serial)
    created_now = False

    if dryrun:
        result_status = "existing" if corr["status"] == "imported" else "new"
        device = None
        error = "Dry-run: device discovered but not created"
    elif corr["status"] == "imported":
        result_status = "existing"
        device = corr["device"]
        error = ""
    elif corr["status"] == "new":
        if auto_create:
            device, result_status, error = create_device_in_nautobot(
                hostname,
                ip_str,
                info.get("vendor", ""),
                info.get("model", ""),
                serial,
                info.get("os_version", ""),
                info.get("platform_info"),
                config,
                scan,
                info if method == "snmp" else None,
            )
            created_now = result_status == "new" and device is not None
        else:
            device = None
            result_status = "new"
            error = "Auto-create disabled (profile review mode)"
    else:
        result_status = corr["status"]
        device = corr["device"]
        error = f"Correlation {corr['status']}: device not auto-created; flagged for review"

    upsert_discovered_device(
        ip_str,
        info,
        method,
        config,
        device=device,
        result_status=result_status,
        error=error,
        scan=scan,
    )

    platform_info = info.get("platform_info") or {}
    DiscoveryResult.objects.create(
        scan=scan,
        ip_address=ip_str,
        hostname=hostname,
        vendor=info.get("vendor", ""),
        model=info.get("model", ""),
        serial_number=serial,
        os_version=info.get("os_version", ""),
        platform_name=platform_info.get("platform_name", "") if platform_info else "",
        discovery_method=method,
        result_status=result_status,
        nautobot_device=device,
        sys_location=info.get("sys_location", ""),
        sys_contact=info.get("sys_contact", ""),
        interfaces_found=info.get("interfaces_found", 0),
        ip_addresses_found=info.get("ip_addresses_found", 0),
        neighbors_found=info.get("neighbors_found", 0),
        vlans_found=info.get("vlans_found", 0),
        discovered_data=_result_discovered_data(info, method),
        error_message=error,
    )

    return result_status, device, error, created_now


def safe_icmp_ping(ip_str, timeout=2):
    """Perform an ICMP ping check using socket (fallback when raw sockets unavailable).

    Uses TCP port check on common ports as fallback.
    Returns True if host is reachable.
    """
    # Try raw ICMP first (requires root/admin)
    try:
        import subprocess
        result = subprocess.run(
            ["ping", "-n", "-w", str(timeout * 1000), ip_str],
            capture_output=True,
            timeout=timeout + 1,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: TCP probe on common ports
    for port in (22, 161, 443, 80):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip_str, port))
            sock.close()
            if result == 0:
                return True
        except socket.error:
            continue
    return False


# ------------------------------------------------------------------ #
#  Job: Ping Sweep                                                     #
# ------------------------------------------------------------------ #


class PingSweepJob(Job):
    """Perform an ICMP ping sweep across an IP range.

    Returns a list of live (reachable) IP addresses.
    """

    class Meta:
        name = "Ping Sweep"
        description = """
        Ping sweep across an IP range to find live hosts.

        Scans the specified CIDR range and reports all reachable IP addresses.
        Uses ICMP ping where available, falls back to TCP probes on ports 22/161/443/80.
        """
        read_only = True
        has_sensitive_variables = False

    target_network = IPNetworkVar(
        description="CIDR network to scan (e.g., 10.0.0.0/24)"
    )
    timeout = IntegerVar(
        default=2,
        min_value=1,
        max_value=10,
        description="Timeout in seconds per host.",
    )
    concurrency = IntegerVar(
        default=20,
        min_value=1,
        max_value=100,
        description="Number of concurrent ping probes.",
    )

    def run(self, *, target_network, timeout, concurrency):
        network = IPNetwork(target_network)
        total = len(list(network))
        if network.prefixlen < 16 and network.version == 4:
            self.logger.warning(
                "Large network range detected (/ %d). Scanning %d hosts may take a long time.",
                network.prefixlen,
                total,
            )

        live_ips = []
        scanned = 0
        lock = threading.Lock()

        def scan_host(ip):
            ip_str = str(ip)
            if safe_icmp_ping(ip_str, timeout):
                with lock:
                    live_ips.append(ip_str)
                self.logger.debug("Host %s is alive", ip_str)

        self.logger.info("Starting ping sweep of %s (%d hosts)", network, total)

        hosts = list(network)

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {executor.submit(scan_host, host): host for host in hosts}
            for future in as_completed(futures):
                scanned += 1
                if scanned % 256 == 0:
                    self.logger.info("Scanned %d / %d hosts (%d live so far)", scanned, total, len(live_ips))
                try:
                    future.result()
                except Exception:
                    pass

        live_ips.sort(key=lambda x: IPAddress(x))
        self.logger.info(
            "Ping sweep complete: %d / %d hosts are alive",
            len(live_ips),
            total,
        )

        return {
            "target_network": str(network),
            "total_hosts": total,
            "live_hosts": len(live_ips),
            "live_ips": live_ips,
        }


# ------------------------------------------------------------------ #
#  Job: SNMP Discovery                                                 #
# ------------------------------------------------------------------ #


def snmp_discover_device(ip_str, config):
    """Discover device info and common MIB tables via SNMP.

    Walks the system scalars plus common tables (interfaces, IPs, ARP,
    physical inventory, LLDP/CDP neighbors) for the host.

    Returns:
        dict with hostname, sysdescr, sysobjectid, platform_info, vendor,
        model, serial, os_version, sys_contact, sys_location, interfaces,
        ip_addresses, arp_table, physical, neighbors, vlans and table
        counts, or None if the host is not SNMP-reachable.
    """
    tables = discover_snmp_tables(ip_str, config)
    system = tables["system"]

    sys_name = system.get("sys_name", "")
    sys_descr = system.get("sys_descr", "")
    sys_object_id = system.get("sys_object_id", "")

    if not sys_name and not sys_descr:
        logger.debug(
            "No SNMP system info from %s (version %s, community %r); host may not be SNMP-reachable",
            ip_str,
            config.get("snmp_version", "2c"),
            config.get("snmp_community", "public"),
        )
        return None

    platform_info = lookup_platform_from_oid(sys_object_id)

    vendor = detect_vendor_from_descr(sys_descr)
    if not vendor and platform_info:
        vendor = platform_info.get("manufacturer_name", "")
    model = parse_model_from_descr(sys_descr, vendor)
    if not model and sys_name:
        model = parse_model_from_descr(sys_name, vendor)
    os_version = parse_os_version_from_descr(sys_descr)

    serial = find_chassis_serial(tables["physical"]) or ""

    if not vendor:
        # The sysDescr may be sparse/empty; the ENTITY-MIB physical
        # inventory descriptions often carry the vendor/product name.
        physical_blob = " ".join(
            str(v)
            for e in tables["physical"]
            for v in (e.get("descr"), e.get("model"), e.get("name"))
            if v
        )
        vendor = detect_vendor_from_descr(physical_blob)

    if not model:
        model = find_chassis_model(tables["physical"]) or ""

    return {
        "hostname": sys_name or ip_str,
        "sys_descr": sys_descr or "",
        "sys_object_id": sys_object_id or "",
        "platform_info": platform_info,
        "vendor": vendor,
        "model": model,
        "serial": serial,
        "os_version": os_version,
        "sys_contact": clean_system_scalar(system.get("sys_contact")),
        "sys_location": clean_system_scalar(system.get("sys_location")),
        "interfaces": tables["interfaces"],
        "ip_addresses": tables["ip_addresses"],
        "arp_table": tables["arp_table"],
        "physical": tables["physical"],
        "neighbors": tables["neighbors"],
        "vlans": tables["vlans"],
        "interfaces_found": len(tables["interfaces"]),
        "ip_addresses_found": len(tables["ip_addresses"]),
        "neighbors_found": len(tables["neighbors"]),
        "vlans_found": len(tables["vlans"]),
    }


def get_interface_status(status_name="Active"):
    """Return a Status object usable for dcim.Interface, falling back to the first."""
    return Status.objects.get_for_model(Interface).filter(name=status_name).first() or Status.objects.get_for_model(
        Interface
    ).first()


def get_ip_address_status():
    """Return the default 'Active' Status for ipam.IPAddress."""
    return Status.objects.get_for_model(IPAddress).filter(name="Active").first() or Status.objects.get_for_model(
        IPAddress
    ).first()


def get_vlan_status():
    """Return the default 'Active' Status for ipam.VLAN."""
    return Status.objects.get_for_model(VLAN).filter(name="Active").first() or Status.objects.get_for_model(
        VLAN
    ).first()


def get_default_namespace():
    """Return the default 'Global' IPAM Namespace, creating it if needed.

    Nautobot 2.x/3.x requires IP addresses and prefixes to belong to a
    Namespace; the standard default is named "Global".
    """
    namespace, _ = Namespace.objects.get_or_create(
        name="Global",
        defaults={"description": "Default Global namespace. Created by Nautobot."},
    )
    return namespace


def get_prefix_status():
    """Return the default 'Active' Status for ipam.Prefix."""
    return Status.objects.get_for_model(Prefix).filter(name="Active").first() or Status.objects.get_for_model(
        Prefix
    ).first()


def network_prefix_for(address, prefix_length):
    """Compute the network CIDR containing ``address/prefix_length``.

    Returns a string like ``"10.0.0.0/24"`` (or the host-route network for
    host masks, e.g. ``"192.168.1.47/32"``), or None for an invalid input.
    """
    try:
        network = IPNetwork(f"{address}/{prefix_length}")
        return str(network)
    except Exception:
        return None


def ensure_parent_prefix(address, prefix_length, namespace=None):
    """Find-or-create a Network Prefix able to parent an IP address.

    Nautobot 3.x requires every IPAddress to have a containing Prefix in its
    Namespace (enforced in ``IPAddress.clean()`` and ``get_or_create()``).
    This computes the network for ``address/prefix_length`` and ensures that
    Prefix exists so IPAddress creation cannot fail. Host masks (/32, /128)
    are registered as host-route prefixes.

    Returns:
        Prefix object, or None on failure.
    """
    prefix_cidr = network_prefix_for(address, prefix_length)
    if not prefix_cidr:
        return None
    try:
        prefix, _ = Prefix.objects.get_or_create(
            prefix=prefix_cidr,
            namespace=namespace or get_default_namespace(),
            defaults={"status": get_prefix_status()},
        )
        return prefix
    except Exception as exc:
        logger.debug("Failed to ensure parent prefix %s: %s", prefix_cidr, exc)
        return None


def _interface_enabled(iface_row):
    """Map SNMP admin/oper status to Nautobot Interface.enabled."""
    oper_status = iface_row.get("oper_status")
    if oper_status is not None:
        return oper_status == OPER_STATUS_UP
    admin_status = iface_row.get("admin_status")
    if admin_status is not None:
        return admin_status == OPER_STATUS_UP
    return True


def populate_vlans_from_snmp(device, vlans_data, config):
    """Create ipam.VLAN objects from the Q-BRIDGE-MIB table.

    VLANs discovered on a device are grouped under a per-device
    ``VLANGroup`` so that IDs and names stay unique per group and the
    resulting objects remain idempotent across rescans.

    Returns:
        int number of VLANs created.
    """
    if not device or not vlans_data:
        return 0
    if not config.get("populate_vlans", True):
        return 0

    group, _ = VLANGroup.objects.get_or_create(
        name=f"{device.name} VLANs",
        defaults={"description": f"VLANs auto-discovered on {device.name}."},
    )
    status = get_vlan_status()
    created = 0

    for row in vlans_data:
        vid = row.get("vid")
        if not vid:
            continue
        name = (row.get("name") or f"VLAN {vid}").strip()
        try:
            vlan, was_created = VLAN.objects.get_or_create(
                vlan_group=group,
                vid=vid,
                defaults={"name": name, "status": status},
            )
            if was_created:
                created += 1
            elif name and vlan.name != name:
                vlan.name = name
                vlan.save(update_fields=["name"])
        except Exception as exc:
            logger.debug("Failed to create VLAN %s on %s: %s", vid, device.name, exc)

    return created


def populate_device_from_snmp(device, info, config, ip_str=None):
    """Populate Device, Interface, and IPAddress objects from SNMP tables.

    Creates dcim.Interface objects from the IF-MIB table, assigns
    ipam.IPAddress objects (from IP-MIB) to the matching interfaces, and
    creates ipam.VLAN objects (from Q-BRIDGE-MIB).
    Operates idempotently: existing interfaces/IPs are matched by name/address.

    If ``ip_str`` matches one of the discovered addresses, that IP is set as
    the Device primary IP (using the discovered prefix length).

    Returns:
        dict with counts: interfaces_created, ip_addresses_created, vlans_created
    """
    if not info or not device:
        return {"interfaces_created": 0, "ip_addresses_created": 0, "vlans_created": 0}

    counts = {"interfaces_created": 0, "ip_addresses_created": 0, "vlans_created": 0}
    interfaces_data = info.get("interfaces") or []
    ip_addresses_data = info.get("ip_addresses") or []

    if not config.get("populate_interfaces", True):
        interfaces_data = []
    if not config.get("populate_ip_addresses", True):
        ip_addresses_data = []

    interface_by_index = {}
    for iface_row in interfaces_data:
        name = (iface_row.get("name") or "").strip()
        if not name:
            continue
        try:
            iface, created = Interface.objects.get_or_create(
                device=device,
                name=name,
                defaults={
                    "type": iface_row.get("type", "other"),
                    "status": get_interface_status(
                        "Active" if _interface_enabled(iface_row) else "Maintenance"
                    ),
                    "enabled": _interface_enabled(iface_row),
                    "mac_address": iface_row.get("mac") or None,
                    "mtu": iface_row.get("mtu"),
                    "speed": iface_row.get("speed"),
                    "description": (iface_row.get("alias") or "")[:200],
                },
            )
            if created:
                counts["interfaces_created"] += 1
            else:
                # Update mutable facts on existing interface
                changed = False
                if iface_row.get("mac"):
                    iface.mac_address = iface_row["mac"]
                    changed = True
                if iface_row.get("speed"):
                    iface.speed = iface_row["speed"]
                    changed = True
                if iface_row.get("alias"):
                    iface.description = (iface_row["alias"])[:200]
                    changed = True
                if changed:
                    iface.save(update_fields=["mac_address", "speed", "description"])
            interface_by_index[str(iface_row.get("index"))] = iface
        except Exception as exc:
            logger.debug("Failed to create interface %s on %s: %s", name, device.name, exc)

    active_ip_status = get_ip_address_status()
    primary_ip_obj = None
    for ip_row in ip_addresses_data:
        address = ip_row.get("address")
        if not address:
            continue
        prefix = ip_row.get("prefix_length") or 32
        ip_str_full = f"{address}/{prefix}"
        try:
            # Nautobot 3.x: IPAddress must have a containing Prefix in its
            # Namespace, otherwise creation fails silently (0 IPs registered).
            ensure_parent_prefix(address, prefix)
            ip_obj, created = IPAddress.objects.get_or_create(
                address=ip_str_full,
                defaults={"status": active_ip_status},
            )
            if created:
                counts["ip_addresses_created"] += 1
            iface = interface_by_index.get(str(ip_row.get("if_index")))
            if iface and not ip_obj.assigned_object_id:
                ip_obj.assigned_object = iface
                ip_obj.save()
            if ip_str and str(address) == str(ip_str):
                primary_ip_obj = ip_obj
        except Exception as exc:
            logger.debug("Failed to assign IP %s on %s: %s", ip_str_full, device.name, exc)

    if primary_ip_obj and not device.primary_ip4:
        device.primary_ip4 = primary_ip_obj
        device.save(update_fields=["primary_ip4"])

    counts["vlans_created"] = populate_vlans_from_snmp(device, info.get("vlans") or [], config)

    return counts


class SNMPDiscoveryJob(Job):
    """Discover devices via SNMP across an IP range.

    Queries sysName, sysObjectID, and sysDescr for each host.
    Auto-creates Nautobot Device objects for discovered devices.
    """

    class Meta:
        name = "SNMP Discovery"
        description = """
        Discover network devices using SNMP across an IP range.

        For each reachable host, queries SNMP for:
        - sysName (hostname)
        - sysObjectID (platform identification)
        - sysDescr (vendor, model, OS)
        - sysContact / sysLocation
        - Interface table (IF-MIB), IP address table (IP-MIB)
        - VLAN table (Q-BRIDGE-MIB dot1qVlanStaticTable)
        - Physical inventory (ENTITY-MIB, for serial numbers)
        - LLDP / CDP neighbors

        Discovered devices are automatically created in Nautobot with
        auto-generated Manufacturer, DeviceType, and Platform objects.
        Interfaces, IP addresses, and VLANs are populated from the walked tables.

        Authentication is community-based (v1/v2c) by default. Set
        ``snmp_version`` to ``3`` to use SNMPv3 USM credentials instead.
        """
        dryrun_default = True
        has_sensitive_variables = True
        soft_time_limit = 600
        template_name = "nautobot_plugin_device_auto_discovery/snmp_job_form.html"

    target_network = IPNetworkVar(
        description="CIDR network to scan (e.g., 10.0.0.0/24)"
    )
    snmp_version = ChoiceVar(
        default="2c",
        choices=(("1", "SNMPv1"), ("2c", "SNMPv2c"), ("3", "SNMPv3")),
        description="SNMP version to use: v1/v2c community or v3 USM.",
    )
    snmp_community = StringVar(
        default="public",
        description="SNMP community string (used for v1/v2c; overrides plugin default).",
    )
    snmpv3_username = StringVar(
        default="",
        description="SNMPv3 USM username (used when snmp_version is '3').",
    )
    snmpv3_auth_protocol = StringVar(
        default="SHA",
        description="SNMPv3 authentication protocol: noAuth, MD5, SHA, SHA-256, SHA-384, SHA-512. Ignored without an auth key.",
    )
    snmpv3_auth_key = StringVar(
        default="",
        description="SNMPv3 authentication passphrase. Sensitive; do not schedule or approve runs.",
    )
    snmpv3_priv_protocol = StringVar(
        default="AES",
        description="SNMPv3 privacy protocol: noPriv, DES, 3DES, AES, AES-192, AES-256. Ignored without a privacy key.",
    )
    snmpv3_priv_key = StringVar(
        default="",
        description="SNMPv3 privacy/encryption passphrase. Sensitive; do not schedule or approve runs.",
    )
    snmpv3_context_name = StringVar(
        default="",
        description="Optional SNMPv3 context name (for v3B / context-engine-ID setups).",
    )
    timeout = IntegerVar(
        default=3,
        min_value=1,
        max_value=10,
        description="SNMP timeout in seconds per host.",
    )
    concurrency = IntegerVar(
        default=20,
        min_value=1,
        max_value=100,
        description="Number of concurrent SNMP probes.",
    )
    populate_interfaces = BooleanVar(
        default=True,
        description="Create dcim.Interface objects from the IF-MIB table.",
    )
    populate_ip_addresses = BooleanVar(
        default=True,
        description="Create and assign ipam.IPAddress objects from the IP-MIB table.",
    )
    include_neighbors = BooleanVar(
        default=True,
        description="Walk LLDP and CDP neighbor tables (recorded, not linked).",
    )
    include_vlans = BooleanVar(
        default=True,
        description="Walk the Q-BRIDGE-MIB VLAN table.",
    )
    populate_vlans = BooleanVar(
        default=True,
        description="Create ipam.VLAN objects from the Q-BRIDGE-MIB table.",
    )
    create_cables = BooleanVar(
        default=True,
        description="Create dcim.Cable objects from LLDP/CDP neighbor data when both ends can be resolved.",
    )
    profile = ObjectVar(
        model=DiscoveryProfile,
        required=False,
        description="Optional DiscoveryProfile supplying scan scope and settings.",
    )
    create_devices = BooleanVar(
        default=True,
        description="Create new Nautobot Device objects for discovered devices without an existing match.",
    )
    dryrun = DryRunVar()

    def run(self, *, target_network, snmp_version, snmp_community, snmpv3_username="", snmpv3_auth_protocol="SHA", snmpv3_auth_key="", snmpv3_priv_protocol="AES", snmpv3_priv_key="", snmpv3_context_name="", timeout, concurrency, populate_interfaces=True, populate_ip_addresses=True, include_neighbors=True, include_vlans=True, populate_vlans=True, create_cables=True, profile=None, create_devices=True, dryrun=False):
        config = get_plugin_config()
        snmp_version = str(snmp_version or "2c").strip().lower()
        if snmp_version.startswith("v"):
            snmp_version = snmp_version[1:]
        if snmp_version not in ("1", "2", "2c", "3"):
            self.logger.error("Invalid snmp_version %r; expected '1', '2c', or '3'.", snmp_version)
            return {"error": f"Invalid snmp_version {snmp_version!r}"}
        if snmp_version == "3" and not (snmpv3_username or "").strip():
            self.logger.error("snmp_version '3' requires an SNMPv3 username.")
            return {"error": "snmp_version '3' requires an SNMPv3 username"}
        config["snmp_version"] = snmp_version
        config["snmp_community"] = snmp_community or config.get("snmp_community", "public")
        config["snmpv3_username"] = snmpv3_username or ""
        config["snmpv3_auth_protocol"] = snmpv3_auth_protocol or "SHA"
        config["snmpv3_auth_key"] = snmpv3_auth_key or ""
        config["snmpv3_priv_protocol"] = snmpv3_priv_protocol or "AES"
        config["snmpv3_priv_key"] = snmpv3_priv_key or ""
        config["snmpv3_context_name"] = snmpv3_context_name or ""
        config["snmp_timeout"] = timeout
        config["snmp_retries"] = 2
        config["populate_interfaces"] = populate_interfaces
        config["populate_ip_addresses"] = populate_ip_addresses
        config["include_neighbors"] = include_neighbors
        config["include_vlans"] = include_vlans
        config["populate_vlans"] = populate_vlans
        config["create_cables"] = create_cables

        apply_profile(config, profile)

        networks, excluded = _resolve_networks(target_network, profile)
        if not networks:
            self.logger.error("No valid target networks to scan (profile or target_network required).")
            return {"error": "No valid target networks to scan"}
        network = networks[0]
        scan_name = f"SNMP Scan: {network}"

        hosts = _expanded_hosts(networks, excluded)
        if profile and profile.maximum_ip_addresses and len(hosts) > profile.maximum_ip_addresses:
            self.logger.error(
                "Profile %s exceeds maximum_ip_addresses (%d > %d).",
                profile.name, len(hosts), profile.maximum_ip_addresses,
            )
            return {"error": f"Profile {profile.name} exceeds maximum_ip_addresses ({profile.maximum_ip_addresses})"}

        discovery_scan = DiscoveryScan.objects.create(
            name=scan_name,
            scan_method=DiscoveryScan.ScanMethod.SNMP,
            target_network=str(network),
            status="running",
        )

        total = len(hosts)
        self.logger.info("Starting SNMP discovery of %s (%d hosts)", network, total)

        discovered = 0
        created = 0
        failed = 0
        existing = 0
        conflicts = 0
        errors = []
        lock = threading.Lock()

        def scan_and_create(ip):
            nonlocal discovered, created, failed, existing, conflicts
            ip_str = str(ip)
            try:
                info = snmp_discover_device(ip_str, config)
                if not info:
                    return

                with lock:
                    discovered += 1

                result_status, device, error, created_now = finalize_discovery(
                    discovery_scan,
                    ip_str,
                    "snmp",
                    info,
                    config,
                    auto_create=create_devices,
                    dryrun=dryrun,
                )

                with lock:
                    if created_now:
                        created += 1
                    elif result_status == "existing":
                        existing += 1
                    elif result_status == "failed":
                        failed += 1
                    elif result_status in ("partial", "conflict"):
                        conflicts += 1

                self.logger.info(
                    "SNMP: %s -> %s (%s)%s",
                    ip_str,
                    info["hostname"],
                    result_status,
                    " [dry-run]" if dryrun else "",
                )

            except Exception as exc:
                with lock:
                    failed += 1
                    errors.append(f"{ip_str}: {exc!r}")
                self.logger.error("SNMP scan error for %s: %s", ip_str, exc)

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {executor.submit(scan_and_create, host): host for host in hosts}
            for i, future in enumerate(as_completed(futures), 1):
                if i % 64 == 0:
                    self.logger.info("Processed %d / %d hosts", i, total)
                try:
                    future.result()
                except Exception:
                    pass

        cables_created = 0
        if config.get("create_cables", True):
            cables_created = link_neighbors_to_cables(discovery_scan, config)

        discovery_scan.devices_discovered = discovered
        discovery_scan.devices_created = created
        discovery_scan.cables_created = cables_created
        discovery_scan.status = "completed"
        discovery_scan.save()

        self.logger.info(
            "SNMP discovery complete: %d discovered, %d created, %d existing, %d conflicts, %d failed",
            discovered, created, existing, conflicts, failed,
        )

        return {
            "scan": discovery_scan.pk,
            "target_network": str(network),
            "total_hosts": total,
            "discovered": discovered,
            "created": created,
            "existing": existing,
            "conflicts": conflicts,
            "failed": failed,
            "cables_created": cables_created,
            "errors": errors[:10],
        }


# ------------------------------------------------------------------ #
#  Job: SSH Discovery                                                  #
# ------------------------------------------------------------------ #


def tcp_port_open(ip_str, port, timeout=3):
    """Return True if a TCP connection to (ip, port) succeeds within timeout."""
    try:
        sock = socket.create_connection((ip_str, port), timeout=timeout)
        sock.close()
        return True
    except (socket.error, OSError):
        return False


def _extract_prompt(text):
    """Extract the device CLI prompt from command output, if visible.

    Prompts are the last non-empty line ending in ``>``, ``#``, or ``$``.
    Terminal escape sequences (e.g. colored banners) are stripped first.
    """
    last = ""
    for line in reversed(text.splitlines()):
        if line.strip():
            last = line.strip()
            break
    last = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", last)
    if re.search(r"[>#$]\s*$", last):
        return last
    return ""


def _read_until_prompt(shell, timeout=10, max_output=2_000_000):
    """Read from an interactive paramiko shell until the prompt appears.

    Returns raw bytes. Never blocks longer than ``timeout`` even if the
    device never emits a prompt or keeps the channel open.
    """
    buffer = b""
    shell.settimeout(timeout)
    deadline = time.time() + timeout
    while time.time() < deadline and len(buffer) < max_output:
        try:
            data = shell.recv(65536)
        except socket.timeout:
            break
        except Exception:
            break
        if not data:
            break
        buffer += data
        if _extract_prompt(buffer.decode("utf-8", errors="replace")):
            break
    return buffer


def _send_and_read(shell, command, timeout=10, max_output=2_000_000):
    """Send a command to an interactive shell and read until the prompt returns."""
    shell.send(command.encode("utf-8") + b"\n")
    return _read_until_prompt(shell, timeout=timeout, max_output=max_output)


def _parse_ssh_output(combined, vendor):
    """Apply vendor-specific (or generic) regex parsers to SSH output.

    Returns:
        tuple (hostname, model, serial, os_version)
    """
    hostname = ""
    model = ""
    serial = ""
    os_version = ""

    profile = SSH_PROFILES.get(vendor, {})
    parsers = profile.get("parsers", {})
    if not parsers:
        # Generic fallback
        lines = combined.strip().split("\n")
        first_lines = "\n".join(lines[:10])
        hostname_match = re.search(r"(?:hostname|host)\s*[:\s]+(\S+)", first_lines, re.IGNORECASE)
        if hostname_match:
            hostname = hostname_match.group(1)
        serial_match = re.search(r"(?:serial\s*number|serial\s*id|SN)\s*[:\s]+(\S+)", combined, re.IGNORECASE)
        if serial_match:
            serial = serial_match.group(1)
        ver_match = re.search(r"(?:version|software|os)\s+([\w\d\.]+)", combined, re.IGNORECASE)
        if ver_match:
            os_version = ver_match.group(1)
        model_match = re.search(r"(?:model|platform|hardware)\s*[:\s]+(.+?)(?:,|$|\s)", combined, re.IGNORECASE)
        if model_match:
            model = model_match.group(1).strip()
        return hostname, model, serial, os_version

    for field, patterns in parsers.items():
        for regex in patterns:
            match = re.search(regex, combined, re.IGNORECASE | re.MULTILINE)
            if match:
                value = match.group(1) if match.groups() else match.group(0).strip()
                if field == "hostname":
                    hostname = value
                elif field == "model":
                    model = value
                elif field == "serial":
                    serial = value
                elif field == "os_version":
                    os_version = value
                break

    return hostname, model, serial, os_version


def ssh_connect_and_discover(
    ip_str,
    username,
    password,
    timeout=10,
    banner_timeout=30,
    port=22,
    enable_password=None,
    port_check=True,
):
    """Connect to a device via SSH and extract identification info.

    Performs a quick TCP port check first (unless ``port_check`` is False),
    opens a PTY-backed shell, disables paging, escalates to privileged exec
    when needed, runs vendor-specific show commands, and parses the output.

    Returns:
        dict with hostname, vendor, model, serial, os_version, port,
        command_outputs, raw_output
        or None on failure.
    """
    try:
        import paramiko
    except ImportError:
        logger.warning("paramiko not installed; SSH discovery will not work.")
        return None

    if port_check and not tcp_port_open(ip_str, port, timeout=min(timeout, 5)):
        logger.debug("Port %d not open on %s", port, ip_str)
        return None

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    command_outputs = {}
    hostname = ""
    vendor = ""
    model = ""
    serial = ""
    os_version = ""

    try:
        client.connect(
            hostname=ip_str,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=banner_timeout,
            look_for_keys=False,
            allow_agent=False,
        )

        # Open a persistent interactive shell. Network devices require a
        # pseudo-terminal and typically present their CLI as the user shell,
        # so state (paging, enable mode) is preserved between commands.
        shell = client.invoke_shell()
        shell.settimeout(timeout)

        banner = _read_until_prompt(shell, timeout=timeout).decode("utf-8", errors="replace")
        command_outputs["__banner__"] = banner
        prompt = _extract_prompt(banner)

        # Detect the vendor from the login banner first.
        vendor = detect_vendor_from_descr(banner)
        profile = SSH_PROFILES.get(vendor)

        if not vendor:
            # No vendor hint in the banner; try generic identification
            # commands and detect from the first usable response.
            for cmd in GENERIC_INFO_COMMANDS:
                out = _send_and_read(shell, cmd, timeout=timeout).decode("utf-8", errors="replace")
                command_outputs[cmd] = out
                if out and "invalid" not in out.lower():
                    vendor = detect_vendor_from_descr(out)
                    profile = SSH_PROFILES.get(vendor)
                    if vendor:
                        break
            if not vendor:
                first = banner.strip().split()
                vendor = first[0] if first else "Unknown"

        if profile is None:
            profile = SSH_PROFILES.get(vendor) or {}

        # Best-effort escalation to privileged exec when the login prompt is
        # a user-level ">" prompt and an enable password is available.
        if profile.get("requires_enable") and prompt and prompt.endswith(">"):
            enable_out = _send_and_read(shell, "enable", timeout=timeout).decode("utf-8", errors="replace")
            if "password" in enable_out.lower() and enable_password:
                time.sleep(0.3)
                enable_out += _send_and_read(shell, enable_password, timeout=timeout).decode(
                    "utf-8", errors="replace"
                )
            command_outputs["__enable__"] = enable_out
            prompt = _extract_prompt(enable_out)

        # Disable paging so long outputs are not truncated (errors ignored).
        for cmd in profile.get("pre_commands", []):
            _send_and_read(shell, cmd, timeout=timeout)

        # Run the vendor-specific identification commands.
        info_commands = profile.get("commands") or list(GENERIC_INFO_COMMANDS)
        for cmd in info_commands:
            if cmd in command_outputs:
                continue
            out = _send_and_read(shell, cmd, timeout=timeout).decode("utf-8", errors="replace")
            command_outputs[cmd] = out

        combined = "\n".join(command_outputs.values())
        hostname, model, serial, os_version = _parse_ssh_output(combined, vendor)

        if not hostname:
            hostname = ip_str

        client.close()

        return {
            "hostname": hostname,
            "vendor": vendor,
            "model": model,
            "serial": serial,
            "os_version": os_version,
            "port": port,
            "command_outputs": command_outputs,
            "raw_output": combined[:500],
        }

    except Exception as exc:
        logger.debug("SSH discovery failed for %s: %s", ip_str, exc)
        return None
    finally:
        try:
            client.close()
        except Exception:
            pass


class SSHDiscoveryJob(Job):
    """Discover devices via SSH across an IP range.

    Connects via SSH, runs show commands, parses output to extract
    hostname, vendor, model, serial, and OS version.
    Auto-creates Nautobot Device objects for discovered devices.
    """

    class Meta:
        name = "SSH Discovery"
        description = """
        Discover network devices using SSH across an IP range.

        For each reachable host:
        1. Connects via SSH (default port 22)
        2. Runs vendor-specific show commands to gather identification info
        3. Parses output for hostname, model, serial, and OS version
        4. Auto-creates Nautobot Device objects

        Credentials should be provided via Nautobot Secrets.
        """
        dryrun_default = True
        has_sensitive_variables = True
        soft_time_limit = 600

    target_network = IPNetworkVar(
        description="CIDR network to scan (e.g., 10.0.0.0/24)"
    )
    ssh_username = StringVar(
        default="",
        description="SSH username for device login (falls back to plugin config).",
    )
    ssh_password = StringVar(
        default="",
        description="SSH password for device login. "
                    "Recommended: use Nautobot Secrets and paste the value here.",
    )
    ssh_port = IntegerVar(
        default=22,
        min_value=1,
        max_value=65535,
        description="SSH port to connect to.",
    )
    timeout = IntegerVar(
        default=10,
        min_value=3,
        max_value=60,
        description="SSH connection timeout in seconds.",
    )
    concurrency = IntegerVar(
        default=10,
        min_value=1,
        max_value=50,
        description="Number of concurrent SSH probes.",
    )
    dryrun = DryRunVar()

    def run(self, *, target_network, ssh_username, ssh_password, ssh_port=22, timeout, concurrency, dryrun=False):
        config = get_plugin_config()
        ssh_username = ssh_username or config.get("ssh_username", "admin")
        ssh_password = ssh_password or config.get("ssh_password", "")
        ssh_port = ssh_port or config.get("ssh_port", 22)
        timeout = timeout or config.get("ssh_timeout", 10)

        network = IPNetwork(target_network)
        scan_name = f"SSH Scan: {network}"

        discovery_scan = DiscoveryScan.objects.create(
            name=scan_name,
            scan_method=DiscoveryScan.ScanMethod.SSH,
            target_network=str(network),
            status="running",
        )

        total = len(list(network))
        self.logger.info("Starting SSH discovery of %s (%d hosts)", network, total)

        if not ssh_password:
            self.logger.error("SSH password is required but was not provided.")
            discovery_scan.status = "failed"
            discovery_scan.error_message = "SSH password not provided"
            discovery_scan.save()
            return {"error": "SSH password not provided"}

        discovered = 0
        created = 0
        failed = 0
        existing = 0
        lock = threading.Lock()

        def scan_and_create(ip):
            nonlocal discovered, created, failed, existing
            ip_str = str(ip)
            try:
                info = ssh_connect_and_discover(
                    ip_str,
                    ssh_username,
                    ssh_password,
                    timeout=timeout,
                    banner_timeout=config.get("ssh_banner_timeout", 30),
                    port=ssh_port,
                    enable_password=config.get("ssh_enable_password"),
                    port_check=config.get("ssh_port_check", True),
                )
                if not info:
                    return

                with lock:
                    discovered += 1

                if dryrun:
                    device = None
                    result_status = "new"
                    error = "Dry-run: device discovered but not created"
                else:
                    device, result_status, error = create_device_in_nautobot(
                        info["hostname"],
                        ip_str,
                        info["vendor"],
                        info["model"],
                        info["serial"],
                        info["os_version"],
                        None,
                        config,
                        discovery_scan,
                    )

                DiscoveryResult.objects.create(
                    scan=discovery_scan,
                    ip_address=ip_str,
                    hostname=info["hostname"],
                    vendor=info["vendor"],
                    model=info["model"],
                    serial_number=info["serial"],
                    os_version=info["os_version"],
                    platform_name="",
                    discovery_method="ssh",
                    result_status=result_status,
                    nautobot_device=device,
                    error_message=error,
                    discovered_data={"command_outputs": info.get("command_outputs", {})},
                )

                with lock:
                    if result_status == "new":
                        if not dryrun:
                            created += 1
                    elif result_status == "existing":
                        existing += 1
                    else:
                        failed += 1

                self.logger.info(
                    "SSH: %s -> %s (%s)%s",
                    ip_str,
                    info["hostname"],
                    result_status,
                    " [dry-run]" if dryrun else "",
                )

            except Exception as exc:
                with lock:
                    failed += 1
                self.logger.error("SSH scan error for %s: %s", ip_str, exc)

        hosts = list(network)
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {executor.submit(scan_and_create, host): host for host in hosts}
            for i, future in enumerate(as_completed(futures), 1):
                if i % 64 == 0:
                    self.logger.info("Processed %d / %d hosts", i, total)
                try:
                    future.result()
                except Exception:
                    pass

        discovery_scan.devices_discovered = discovered
        discovery_scan.devices_created = created
        discovery_scan.status = "completed"
        discovery_scan.save()

        self.logger.info(
            "SSH discovery complete: %d discovered, %d created, %d existing, %d failed",
            discovered, created, existing, failed,
        )

        return {
            "scan": discovery_scan.pk,
            "target_network": str(network),
            "total_hosts": total,
            "discovered": discovered,
            "created": created,
            "existing": existing,
            "failed": failed,
        }


# ------------------------------------------------------------------ #
#  Job: Full Discovery                                                 #
# ------------------------------------------------------------------ #


class FullDiscoveryJob(Job):
    """Orchestrator job that runs ping sweep, SNMP, and SSH discovery.

    First pings the range, then runs SNMP on live hosts, then SSH
    on any remaining hosts. Deduplicates results and auto-creates devices.
    """

    class Meta:
        name = "Full Discovery"
        description = """
        Comprehensive network device discovery.

        Runs in three phases:
        1. **Ping Sweep** — find live hosts in the IP range
        2. **SNMP Discovery** — query live hosts for device info via SNMP
        3. **SSH Discovery** — attempt SSH on hosts not identified by SNMP

        All discovered devices are automatically created in Nautobot
        with inferred Manufacturer, DeviceType, and Platform objects.
        SNMP-discovered interfaces, IP addresses, and VLANs are also populated.
        """
        dryrun_default = True
        has_sensitive_variables = True
        soft_time_limit = 1800
        time_limit = 3600
        template_name = "nautobot_plugin_device_auto_discovery/snmp_job_form.html"

    target_network = IPNetworkVar(
        description="CIDR network to scan (e.g., 10.0.0.0/24)"
    )
    snmp_version = ChoiceVar(
        default="2c",
        choices=(("1", "SNMPv1"), ("2c", "SNMPv2c"), ("3", "SNMPv3")),
        description="SNMP version to use: v1/v2c community or v3 USM.",
    )
    snmp_community = StringVar(
        default="public",
        description="SNMP community string (used for v1/v2c).",
    )
    snmpv3_username = StringVar(
        default="",
        description="SNMPv3 USM username (used when snmp_version is '3').",
    )
    snmpv3_auth_protocol = StringVar(
        default="SHA",
        description="SNMPv3 authentication protocol: noAuth, MD5, SHA, SHA-256, SHA-384, SHA-512. Ignored without an auth key.",
    )
    snmpv3_auth_key = StringVar(
        default="",
        description="SNMPv3 authentication passphrase. Sensitive; do not schedule or approve runs.",
    )
    snmpv3_priv_protocol = StringVar(
        default="AES",
        description="SNMPv3 privacy protocol: noPriv, DES, 3DES, AES, AES-192, AES-256. Ignored without a privacy key.",
    )
    snmpv3_priv_key = StringVar(
        default="",
        description="SNMPv3 privacy/encryption passphrase. Sensitive; do not schedule or approve runs.",
    )
    snmpv3_context_name = StringVar(
        default="",
        description="Optional SNMPv3 context name (for v3B / context-engine-ID setups).",
    )
    ssh_username = StringVar(
        default="admin",
        description="SSH username for device login.",
    )
    ssh_password = StringVar(
        default="",
        description="SSH password. Recommended: retrieve from Nautobot Secrets first.",
    )
    enable_ping = BooleanVar(
        default=True,
        description="Run ICMP ping sweep first to narrow down live hosts.",
    )
    enable_snmp = BooleanVar(
        default=True,
        description="Run SNMP discovery on live hosts.",
    )
    enable_ssh = BooleanVar(
        default=True,
        description="Run SSH discovery on hosts not identified by SNMP.",
    )
    populate_interfaces = BooleanVar(
        default=True,
        description="Create dcim.Interface objects from the SNMP IF-MIB table.",
    )
    populate_ip_addresses = BooleanVar(
        default=True,
        description="Create and assign ipam.IPAddress objects from the SNMP IP-MIB table.",
    )
    include_neighbors = BooleanVar(
        default=True,
        description="Walk SNMP LLDP and CDP neighbor tables (recorded, not linked).",
    )
    include_vlans = BooleanVar(
        default=True,
        description="Walk the SNMP Q-BRIDGE-MIB VLAN table.",
    )
    populate_vlans = BooleanVar(
        default=True,
        description="Create ipam.VLAN objects from the SNMP Q-BRIDGE-MIB table.",
    )
    create_cables = BooleanVar(
        default=True,
        description="Create dcim.Cable objects from LLDP/CDP neighbor data when both ends can be resolved.",
    )
    profile = ObjectVar(
        model=DiscoveryProfile,
        required=False,
        description="Optional DiscoveryProfile supplying scan scope and settings.",
    )
    create_devices = BooleanVar(
        default=True,
        description="Create new Nautobot Device objects for discovered devices without an existing match.",
    )
    dryrun = DryRunVar()
    timeout = IntegerVar(
        default=3,
        min_value=1,
        max_value=30,
        description="Per-host timeout in seconds.",
    )
    concurrency = IntegerVar(
        default=20,
        min_value=1,
        max_value=100,
        description="Number of concurrent probes.",
    )

    def run(self, *, target_network, snmp_version, snmp_community, snmpv3_username="", snmpv3_auth_protocol="SHA", snmpv3_auth_key="", snmpv3_priv_protocol="AES", snmpv3_priv_key="", snmpv3_context_name="", ssh_username, ssh_password,
            enable_ping, enable_snmp, enable_ssh, populate_interfaces=True, populate_ip_addresses=True,
            include_neighbors=True, include_vlans=True, populate_vlans=True, create_cables=True, profile=None, create_devices=True, dryrun=False, timeout, concurrency):
        config = get_plugin_config()
        config["populate_interfaces"] = populate_interfaces
        config["populate_ip_addresses"] = populate_ip_addresses
        config["include_neighbors"] = include_neighbors
        config["include_vlans"] = include_vlans
        config["populate_vlans"] = populate_vlans
        config["create_cables"] = create_cables
        snmp_version = str(snmp_version or "2c").strip().lower()
        if snmp_version.startswith("v"):
            snmp_version = snmp_version[1:]
        if snmp_version not in ("1", "2", "2c", "3"):
            self.logger.error("Invalid snmp_version %r; expected '1', '2c', or '3'.", snmp_version)
            return {"error": f"Invalid snmp_version {snmp_version!r}"}
        if snmp_version == "3" and not (snmpv3_username or "").strip():
            self.logger.error("snmp_version '3' requires an SNMPv3 username.")
            return {"error": "snmp_version '3' requires an SNMPv3 username"}
        config["snmp_version"] = snmp_version
        config["snmp_community"] = snmp_community or config.get("snmp_community", "public")
        config["snmpv3_username"] = snmpv3_username or ""
        config["snmpv3_auth_protocol"] = snmpv3_auth_protocol or "SHA"
        config["snmpv3_auth_key"] = snmpv3_auth_key or ""
        config["snmpv3_priv_protocol"] = snmpv3_priv_protocol or "AES"
        config["snmpv3_priv_key"] = snmpv3_priv_key or ""
        config["snmpv3_context_name"] = snmpv3_context_name or ""
        ssh_username = ssh_username or config.get("ssh_username", "admin")
        ssh_password = ssh_password or config.get("ssh_password", "")
        apply_profile(config, profile)
        ssh_port = config.get("ssh_port", 22)

        networks, excluded = _resolve_networks(target_network, profile)
        if not networks:
            self.logger.error("No valid target networks to scan (profile or target_network required).")
            return {"error": "No valid target networks to scan"}
        network = networks[0]
        scan_name = f"Full Scan: {network}"

        all_hosts = _expanded_hosts(networks, excluded)
        if profile and profile.maximum_ip_addresses and len(all_hosts) > profile.maximum_ip_addresses:
            self.logger.error(
                "Profile %s exceeds maximum_ip_addresses (%d > %d).",
                profile.name, len(all_hosts), profile.maximum_ip_addresses,
            )
            return {"error": f"Profile {profile.name} exceeds maximum_ip_addresses ({profile.maximum_ip_addresses})"}

        discovery_scan = DiscoveryScan.objects.create(
            name=scan_name,
            scan_method=DiscoveryScan.ScanMethod.FULL,
            target_network=str(network),
            status="running",
        )

        self.logger.info("Starting full discovery of %s", network)

        live_hosts = set()
        discovered_hosts = set()
        total_discovered = 0
        total_created = 0
        total_existing = 0
        total_conflicts = 0
        total_failed = 0

        # Phase 1: Ping Sweep
        if enable_ping:
            self.logger.info("Phase 1: Ping sweep")
            lock = threading.Lock()

            def check_alive(ip):
                if safe_icmp_ping(str(ip), timeout):
                    with lock:
                        live_hosts.add(str(ip))

            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                futures = {executor.submit(check_alive, host): host for host in all_hosts}
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception:
                        pass

            self.logger.info("Ping sweep found %d / %d live hosts", len(live_hosts), len(all_hosts))
        else:
            live_hosts = {str(ip) for ip in all_hosts}

        # Phase 2: SNMP Discovery
        snmp_results = {}
        if enable_snmp and live_hosts:
            self.logger.info("Phase 2: SNMP discovery on %d live hosts", len(live_hosts))
            config["snmp_timeout"] = config.get("profile_snmp_timeout") or timeout

            lock = threading.Lock()
            for ip_str in live_hosts:
                try:
                    info = snmp_discover_device(ip_str, config)
                    if info:
                        with lock:
                            discovered_hosts.add(ip_str)
                            snmp_results[ip_str] = info
                            total_discovered += 1

                        result_status, device, error, created_now = finalize_discovery(
                            discovery_scan,
                            ip_str,
                            "snmp",
                            info,
                            config,
                            auto_create=create_devices,
                            dryrun=dryrun,
                        )

                        with lock:
                            if created_now:
                                total_created += 1
                            elif result_status == "existing":
                                total_existing += 1
                            elif result_status == "failed":
                                total_failed += 1
                            elif result_status in ("partial", "conflict"):
                                total_conflicts += 1

                        self.logger.info(
                            "SNMP: %s -> %s (%s)%s",
                            ip_str, info["hostname"], result_status,
                            " [dry-run]" if dryrun else "",
                        )

                except Exception as exc:
                    total_failed += 1
                    self.logger.error("SNMP error for %s: %s", ip_str, exc)

            self.logger.info("SNMP discovered %d devices", len(snmp_results))

        # Phase 3: SSH Discovery (on hosts not found by SNMP)
        ssh_targets = live_hosts - discovered_hosts
        if enable_ssh and ssh_targets and ssh_password:
            self.logger.info("Phase 3: SSH discovery on %d remaining hosts", len(ssh_targets))

            lock = threading.Lock()

            def ssh_scan(ip_str):
                nonlocal total_discovered, total_created, total_existing, total_conflicts, total_failed
                try:
                    info = ssh_connect_and_discover(
                        ip_str, ssh_username, ssh_password,
                        timeout=timeout,
                        banner_timeout=config.get("ssh_banner_timeout", 30),
                        port=ssh_port,
                        enable_password=config.get("ssh_enable_password"),
                        port_check=config.get("ssh_port_check", True),
                    )
                    if not info:
                        return

                    with lock:
                        total_discovered += 1

                    result_status, device, error, created_now = finalize_discovery(
                        discovery_scan,
                        ip_str,
                        "ssh",
                        info,
                        config,
                        auto_create=create_devices,
                        dryrun=dryrun,
                    )

                    with lock:
                        if created_now:
                            total_created += 1
                        elif result_status == "existing":
                            total_existing += 1
                        elif result_status == "failed":
                            total_failed += 1
                        elif result_status in ("partial", "conflict"):
                            total_conflicts += 1

                    self.logger.info(
                        "SSH: %s -> %s (%s)%s",
                        ip_str, info["hostname"], result_status,
                        " [dry-run]" if dryrun else "",
                    )

                except Exception as exc:
                    with lock:
                        total_failed += 1
                    self.logger.error("SSH error for %s: %s", ip_str, exc)

            with ThreadPoolExecutor(max_workers=min(concurrency, 10)) as executor:
                futures = {executor.submit(ssh_scan, ip_str): ip_str for ip_str in ssh_targets}
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception:
                        pass

        # Finalize
        cables_created = 0
        if config.get("create_cables", True):
            cables_created = link_neighbors_to_cables(discovery_scan, config)

        discovery_scan.devices_discovered = total_discovered
        discovery_scan.devices_created = total_created
        discovery_scan.cables_created = cables_created
        discovery_scan.status = "completed"
        discovery_scan.save()

        summary = (
            f"Full discovery complete: "
            f"{total_discovered} discovered, "
            f"{total_created} created, "
            f"{total_existing} existing, "
            f"{total_conflicts} conflicts, "
            f"{total_failed} failed"
        )
        self.logger.info(summary)

        return {
            "scan": discovery_scan.pk,
            "target_network": str(network),
            "total_hosts_scanned": len(all_hosts),
            "live_hosts": len(live_hosts),
            "discovered": total_discovered,
            "created": total_created,
            "existing": total_existing,
            "conflicts": total_conflicts,
            "failed": total_failed,
            "cables_created": cables_created,
        }


# ------------------------------------------------------------------ #
#  Job: Crawl Discovery                                               #
# ------------------------------------------------------------------ #


class CrawlDiscoveryJob(Job):
    """Discover devices iteratively from a seed device using SNMP.

    Starts at the seed device's management IP, walks its LLDP/CDP neighbor
    table via SNMP, creates/updates the discovered devices, and repeats for
    each neighbor up to ``max_depth`` hops (breadth-first). A visited set
    plus the depth and device caps keep the crawl finite.
    """

    class Meta:
        name = "Crawl Discovery"
        description = """
        Discover devices iteratively from a seed device using SNMP.

        Starting from the seed device's management IP, each hop walks the
        LLDP/CDP neighbor table, creates/updates the discovered devices, and
        continues crawling from each neighbor's management IP up to
        ``max_depth`` hops.

        Requires SNMP read access (v1/v2c community or SNMPv3 USM) to the
        system and LLDP/CDP tables on every device being crawled.
        """
        dryrun_default = True
        has_sensitive_variables = True
        soft_time_limit = 1800
        time_limit = 3600
        template_name = "nautobot_plugin_device_auto_discovery/snmp_job_form.html"

    seed_device = ObjectVar(
        model=Device,
        description="Nautobot Device to start the crawl from.",
    )
    seed_ip = StringVar(
        default="",
        description="Optional management IP override for the seed device (used when its primary IP is not reachable).",
    )
    max_depth = IntegerVar(
        default=2,
        min_value=1,
        max_value=10,
        description="Maximum number of hops to crawl from the seed device.",
    )
    max_devices = IntegerVar(
        default=50,
        min_value=1,
        max_value=1000,
        description="Maximum number of devices to discover during the crawl.",
    )
    snmp_version = ChoiceVar(
        default="2c",
        choices=(("1", "SNMPv1"), ("2c", "SNMPv2c"), ("3", "SNMPv3")),
        description="SNMP version to use: v1/v2c community or v3 USM.",
    )
    snmp_community = StringVar(
        default="public",
        description="SNMP community string (used for v1/v2c; overrides plugin default).",
    )
    snmpv3_username = StringVar(
        default="",
        description="SNMPv3 USM username (used when snmp_version is '3').",
    )
    snmpv3_auth_protocol = StringVar(
        default="SHA",
        description="SNMPv3 authentication protocol: noAuth, MD5, SHA, SHA-256, SHA-384, SHA-512. Ignored without an auth key.",
    )
    snmpv3_auth_key = StringVar(
        default="",
        description="SNMPv3 authentication passphrase. Sensitive; do not schedule or approve runs.",
    )
    snmpv3_priv_protocol = StringVar(
        default="AES",
        description="SNMPv3 privacy protocol: noPriv, DES, 3DES, AES, AES-192, AES-256. Ignored without a privacy key.",
    )
    snmpv3_priv_key = StringVar(
        default="",
        description="SNMPv3 privacy/encryption passphrase. Sensitive; do not schedule or approve runs.",
    )
    snmpv3_context_name = StringVar(
        default="",
        description="Optional SNMPv3 context name (for v3B / context-engine-ID setups).",
    )
    timeout = IntegerVar(
        default=3,
        min_value=1,
        max_value=10,
        description="SNMP timeout in seconds per host.",
    )
    concurrency = IntegerVar(
        default=10,
        min_value=1,
        max_value=50,
        description="Number of concurrent SNMP probes.",
    )
    populate_interfaces = BooleanVar(
        default=True,
        description="Create dcim.Interface objects from the IF-MIB table.",
    )
    populate_ip_addresses = BooleanVar(
        default=True,
        description="Create and assign ipam.IPAddress objects from the IP-MIB table.",
    )
    include_neighbors = BooleanVar(
        default=True,
        description="Walk LLDP and CDP neighbor tables and continue the crawl from them.",
    )
    include_vlans = BooleanVar(
        default=True,
        description="Walk the Q-BRIDGE-MIB VLAN table.",
    )
    populate_vlans = BooleanVar(
        default=True,
        description="Create ipam.VLAN objects from the Q-BRIDGE-MIB table.",
    )
    create_cables = BooleanVar(
        default=True,
        description="Create dcim.Cable objects from LLDP/CDP neighbor data when both ends can be resolved.",
    )
    profile = ObjectVar(
        model=DiscoveryProfile,
        required=False,
        description="Optional DiscoveryProfile supplying scan settings (scope is driven by the seed device).",
    )
    create_devices = BooleanVar(
        default=True,
        description="Create new Nautobot Device objects for discovered devices without an existing match.",
    )
    dryrun = DryRunVar()

    def run(self, *, seed_device, seed_ip="", max_depth, max_devices, snmp_version, snmp_community, snmpv3_username="", snmpv3_auth_protocol="SHA", snmpv3_auth_key="", snmpv3_priv_protocol="AES", snmpv3_priv_key="", snmpv3_context_name="", timeout, concurrency, populate_interfaces=True, populate_ip_addresses=True, include_neighbors=True, include_vlans=True, populate_vlans=True, create_cables=True, profile=None, create_devices=True, dryrun=False):
        config = get_plugin_config()
        config["populate_interfaces"] = populate_interfaces
        config["populate_ip_addresses"] = populate_ip_addresses
        config["include_neighbors"] = include_neighbors
        config["include_vlans"] = include_vlans
        config["populate_vlans"] = populate_vlans
        config["create_cables"] = create_cables
        config["snmp_timeout"] = timeout
        config["snmp_retries"] = 2

        apply_profile(config, profile)
        config["snmp_timeout"] = config.get("profile_snmp_timeout") or timeout

        if isinstance(seed_device, str):
            seed_device = Device.objects.get(pk=seed_device)
        if not seed_device:
            self.logger.error("A seed device is required.")
            return {"error": "A seed device is required"}

        snmp_version = str(snmp_version or "2c").strip().lower()
        if snmp_version.startswith("v"):
            snmp_version = snmp_version[1:]
        if snmp_version not in ("1", "2", "2c", "3"):
            self.logger.error("Invalid snmp_version %r; expected '1', '2c', or '3'.", snmp_version)
            return {"error": f"Invalid snmp_version {snmp_version!r}"}
        if snmp_version == "3" and not (snmpv3_username or "").strip():
            self.logger.error("snmp_version '3' requires an SNMPv3 username.")
            return {"error": "snmp_version '3' requires an SNMPv3 username"}
        config["snmp_version"] = snmp_version
        config["snmp_community"] = snmp_community or config.get("snmp_community", "public")
        config["snmpv3_username"] = snmpv3_username or ""
        config["snmpv3_auth_protocol"] = snmpv3_auth_protocol or "SHA"
        config["snmpv3_auth_key"] = snmpv3_auth_key or ""
        config["snmpv3_priv_protocol"] = snmpv3_priv_protocol or "AES"
        config["snmpv3_priv_key"] = snmpv3_priv_key or ""
        config["snmpv3_context_name"] = snmpv3_context_name or ""

        start_ip = (seed_ip or "").strip()
        if not start_ip:
            if seed_device.primary_ip4:
                start_ip = str(seed_device.primary_ip4.address.ip)
            elif seed_device.primary_ip6:
                start_ip = str(seed_device.primary_ip6.address.ip)
        if not start_ip:
            self.logger.error(
                "Seed device %s has no primary IP; provide a seed_ip override.", seed_device.name
            )
            return {
                "error": f"Seed device {seed_device.name} has no primary IP; provide a seed_ip override."
            }

        discovery_scan = DiscoveryScan.objects.create(
            name=f"Crawl from {seed_device.name}",
            scan_method=DiscoveryScan.ScanMethod.CRAWL,
            target_network=start_ip,
            seed_device=seed_device,
            status="running",
        )

        self.logger.info(
            "Starting crawl from %s (%s), max_depth=%d, max_devices=%d",
            seed_device.name,
            start_ip,
            max_depth,
            max_devices,
        )

        discovered = 0
        created = 0
        existing = 0
        conflicts = 0
        failed = 0
        visited = {start_ip}
        lock = threading.Lock()

        def process(ip_str, depth):
            nonlocal discovered, created, existing, conflicts, failed
            try:
                info = snmp_discover_device(ip_str, config)
                if not info:
                    return []

                with lock:
                    discovered += 1

                result_status, device, error, created_now = finalize_discovery(
                    discovery_scan,
                    ip_str,
                    "snmp",
                    info,
                    config,
                    auto_create=create_devices,
                    dryrun=dryrun,
                )

                with lock:
                    if created_now:
                        created += 1
                    elif result_status == "existing":
                        existing += 1
                    elif result_status == "failed":
                        failed += 1
                    elif result_status in ("partial", "conflict"):
                        conflicts += 1

                self.logger.info(
                    "Crawl: %s -> %s (%s)%s",
                    ip_str,
                    info["hostname"],
                    result_status,
                    " [dry-run]" if dryrun else "",
                )

                if depth + 1 >= max_depth or not config.get("include_neighbors", True):
                    return []

                next_ips = []
                for neighbor in info.get("neighbors") or []:
                    neighbor_ip = neighbor_management_ip(neighbor)
                    if not neighbor_ip:
                        continue
                    with lock:
                        if neighbor_ip not in visited and len(visited) < max_devices:
                            visited.add(neighbor_ip)
                            next_ips.append(neighbor_ip)
                return next_ips

            except Exception as exc:
                with lock:
                    failed += 1
                self.logger.error("Crawl error for %s: %s", ip_str, exc)
                return []

        queue = deque([start_ip])
        depth = 0
        while queue and depth < max_depth:
            level = list(queue)
            queue.clear()
            next_level = []
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                futures = {executor.submit(process, ip, depth): ip for ip in level}
                for future in as_completed(futures):
                    try:
                        next_level.extend(future.result())
                    except Exception:
                        pass
            queue = deque(next_level)
            depth += 1
            if len(visited) >= max_devices:
                break

        cables_created = 0
        if config.get("create_cables", True):
            cables_created = link_neighbors_to_cables(discovery_scan, config)

        discovery_scan.devices_discovered = discovered
        discovery_scan.devices_created = created
        discovery_scan.cables_created = cables_created
        discovery_scan.status = "completed"
        discovery_scan.save()

        self.logger.info(
            "Crawl discovery complete: %d discovered, %d created, %d existing, %d conflicts, %d failed, %d cables",
            discovered,
            created,
            existing,
            conflicts,
            failed,
            cables_created,
        )

        return {
            "scan": discovery_scan.pk,
            "seed_device": seed_device.name,
            "seed_ip": start_ip,
            "max_depth": max_depth,
            "max_devices": max_devices,
            "discovered": discovered,
            "created": created,
            "existing": existing,
            "conflicts": conflicts,
            "failed": failed,
            "cables_created": cables_created,
        }


# Register all job classes
register_jobs(
    PingSweepJob,
    SNMPDiscoveryJob,
    SSHDiscoveryJob,
    FullDiscoveryJob,
    CrawlDiscoveryJob,
)
