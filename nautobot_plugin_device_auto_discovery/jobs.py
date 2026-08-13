"""Job classes for network device discovery.

Provides Jobs for ICMP ping sweeps, SNMP discovery, SSH discovery,
and a full discovery orchestrator that combines all methods.
"""

import logging
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from django.conf import settings
from netaddr import IPNetwork, IPAddress

from nautobot.apps.jobs import (
    BooleanVar,
    DryRunVar,
    IntegerVar,
    IPNetworkVar,
    Job,
    ObjectVar,
    register_jobs,
    StringVar,
    TextVar,
)
from nautobot.dcim.models import (
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
from nautobot.ipam.models import IPAddress

from .models import DiscoveryScan, DiscoveryResult
from .mappings import lookup_platform_from_oid
from .snmp_tables import discover_snmp_tables, find_chassis_serial, snmp_get

# Common SNMP constants kept for backward compatibility
from .snmp_tables import (
    OID_SYSCONTACT as SNMP_OID_SYSCONTACT,
    OID_SYSDESCR as SNMP_OID_SYSDescR,
    OID_SYSLOCATION as SNMP_OID_SYSLOCATION,
    OID_SYSNAME as SNMP_OID_SYSNAME,
    OID_SYSOBJECTID as SNMP_OID_SYSOBJECTID,
)

OPER_STATUS_UP = 1


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
            "color": "blue",
        },
    )
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
            populate_device_from_snmp(device, discovered_info, config)

        # Assign primary IP
        if ip_str:
            try:
                ip_obj, _ = IPAddress.objects.get_or_create(
                    address=ip_str + "/32",
                    defaults={
                        "status": Status.objects.get_for_model(IPAddress).filter(name="Active").first(),
                    },
                )
                device.primary_ip4 = ip_obj
                device.save()
            except Exception as ip_err:
                logger.warning("Could not assign primary IP %s: %s", ip_str, ip_err)

        return device, status, ""

    except Exception as exc:
        logger.error("Failed to create device %s: %s", hostname, exc)
        return None, "failed", str(exc)


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
        ip_addresses, arp_table, physical, neighbors and table counts,
        or None if the host is not SNMP-reachable.
    """
    tables = discover_snmp_tables(ip_str, config)
    system = tables["system"]

    sys_name = system.get("sys_name", "")
    sys_descr = system.get("sys_descr", "")
    sys_object_id = system.get("sys_object_id", "")

    if not sys_name and not sys_descr:
        logger.debug(
            "No SNMP system info from %s (community %r); host may not be SNMP-reachable",
            ip_str,
            config.get("snmp_community", "public"),
        )
        return None

    platform_info = lookup_platform_from_oid(sys_object_id)

    vendor = ""
    model = ""
    if sys_descr:
        parts = sys_descr.split(",")
        if parts:
            vendor = parts[0].strip()
        if len(parts) > 1:
            model = parts[1].strip()

    serial = find_chassis_serial(tables["physical"]) or ""

    return {
        "hostname": sys_name or ip_str,
        "sys_descr": sys_descr or "",
        "sys_object_id": sys_object_id or "",
        "platform_info": platform_info,
        "vendor": vendor,
        "model": model,
        "serial": serial,
        "os_version": sys_descr or "",
        "sys_contact": system.get("sys_contact", ""),
        "sys_location": system.get("sys_location", ""),
        "interfaces": tables["interfaces"],
        "ip_addresses": tables["ip_addresses"],
        "arp_table": tables["arp_table"],
        "physical": tables["physical"],
        "neighbors": tables["neighbors"],
        "interfaces_found": len(tables["interfaces"]),
        "ip_addresses_found": len(tables["ip_addresses"]),
        "neighbors_found": len(tables["neighbors"]),
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


def _interface_enabled(iface_row):
    """Map SNMP admin/oper status to Nautobot Interface.enabled."""
    oper_status = iface_row.get("oper_status")
    if oper_status is not None:
        return oper_status == OPER_STATUS_UP
    admin_status = iface_row.get("admin_status")
    if admin_status is not None:
        return admin_status == OPER_STATUS_UP
    return True


def populate_device_from_snmp(device, info, config):
    """Populate Device, Interface, and IPAddress objects from SNMP tables.

    Creates dcim.Interface objects from the IF-MIB table and assigns
    ipam.IPAddress objects (from IP-MIB) to the matching interfaces.
    Operates idempotently: existing interfaces/IPs are matched by name/address.

    Returns:
        dict with counts: interfaces_created, ip_addresses_created
    """
    if not info or not device:
        return {"interfaces_created": 0, "ip_addresses_created": 0}

    counts = {"interfaces_created": 0, "ip_addresses_created": 0}
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
    for ip_row in ip_addresses_data:
        address = ip_row.get("address")
        if not address:
            continue
        prefix = ip_row.get("prefix_length") or 32
        ip_str = f"{address}/{prefix}"
        try:
            ip_obj, created = IPAddress.objects.get_or_create(
                address=ip_str,
                defaults={"status": active_ip_status},
            )
            if created:
                counts["ip_addresses_created"] += 1
            iface = interface_by_index.get(str(ip_row.get("if_index")))
            if iface and not ip_obj.assigned_object_id:
                ip_obj.assigned_object = iface
                ip_obj.save()
        except Exception as exc:
            logger.debug("Failed to assign IP %s on %s: %s", ip_str, device.name, exc)

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
        - Physical inventory (ENTITY-MIB, for serial numbers)
        - LLDP / CDP neighbors

        Discovered devices are automatically created in Nautobot with
        auto-generated Manufacturer, DeviceType, and Platform objects.
        Interfaces and IP addresses are populated from the walked tables.
        """
        dryrun_default = True
        has_sensitive_variables = False
        soft_time_limit = 600

    target_network = IPNetworkVar(
        description="CIDR network to scan (e.g., 10.0.0.0/24)"
    )
    snmp_community = StringVar(
        default="public",
        description="SNMP community string (overrides plugin default).",
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
    dryrun = DryRunVar()

    def run(self, *, target_network, snmp_community, timeout, concurrency, populate_interfaces=True, populate_ip_addresses=True, include_neighbors=True, dryrun=False):
        config = get_plugin_config()
        config["snmp_community"] = snmp_community or config.get("snmp_community", "public")
        config["snmp_timeout"] = timeout
        config["snmp_retries"] = 2
        config["populate_interfaces"] = populate_interfaces
        config["populate_ip_addresses"] = populate_ip_addresses
        config["include_neighbors"] = include_neighbors

        network = IPNetwork(target_network)
        scan_name = f"SNMP Scan: {network}"

        discovery_scan = DiscoveryScan.objects.create(
            name=scan_name,
            scan_method=DiscoveryScan.ScanMethod.SNMP,
            target_network=str(network),
            status="running",
        )

        total = len(list(network))
        self.logger.info("Starting SNMP discovery of %s (%d hosts)", network, total)

        discovered = 0
        created = 0
        failed = 0
        existing = 0
        lock = threading.Lock()

        def scan_and_create(ip):
            nonlocal discovered, created, failed, existing
            ip_str = str(ip)
            try:
                info = snmp_discover_device(ip_str, config)
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
                        info["platform_info"],
                        config,
                        discovery_scan,
                        info,
                    )

                # Record result
                DiscoveryResult.objects.create(
                    scan=discovery_scan,
                    ip_address=ip_str,
                    hostname=info["hostname"],
                    vendor=info["vendor"],
                    model=info["model"],
                    serial_number=info["serial"],
                    os_version=info["os_version"],
                    platform_name=info["platform_info"]["platform_name"] if info["platform_info"] else "",
                    discovery_method="snmp",
                    result_status=result_status,
                    nautobot_device=device,
                    sys_location=info.get("sys_location", ""),
                    sys_contact=info.get("sys_contact", ""),
                    interfaces_found=info.get("interfaces_found", 0),
                    ip_addresses_found=info.get("ip_addresses_found", 0),
                    neighbors_found=info.get("neighbors_found", 0),
                    discovered_data={
                        "interfaces": info.get("interfaces", []),
                        "ip_addresses": info.get("ip_addresses", []),
                        "arp_table": info.get("arp_table", []),
                        "physical": info.get("physical", []),
                        "neighbors": info.get("neighbors", []),
                    },
                    error_message=error,
                )

                with lock:
                    if result_status == "new":
                        if not dryrun:
                            created += 1
                    elif result_status == "existing":
                        existing += 1
                    elif result_status == "failed":
                        failed += 1

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
                self.logger.error("SNMP scan error for %s: %s", ip_str, exc)

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
            "SNMP discovery complete: %d discovered, %d created, %d existing, %d failed",
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
#  Job: SSH Discovery                                                  #
# ------------------------------------------------------------------ #


def ssh_connect_and_discover(ip_str, username, password, timeout=10, banner_timeout=30):
    """Connect to a device via SSH and extract identification info.

    Returns:
        dict with hostname, vendor, model, serial, os_version
        or None on failure.
    """
    try:
        import paramiko

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=ip_str,
            port=22,
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=banner_timeout,
            look_for_keys=False,
            allow_agent=False,
        )

        hostname = ""
        vendor = ""
        model = ""
        serial = ""
        os_version = ""

        # Run show version / equivalent commands
        version_commands = [
            "show version",
            "display version",
            "show system information",
            "display current-version",
        ]

        output = ""
        for cmd in version_commands:
            try:
                stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
                output = stdout.read().decode("utf-8", errors="replace")
                err = stderr.read().decode("utf-8", errors="replace")
                if output and "invalid" not in output.lower() and "error" not in err.lower():
                    break
                output = ""
            except (paramiko.SSHException, socket.timeout):
                continue

        if output:
            import re

            lines = output.strip().split("\n")
            first_lines = "\n".join(lines[:10])

            # Try to extract hostname from banner or command output
            hostname_match = re.search(r"(?:hostname|host)\s*[:\s]+(\S+)", first_lines, re.IGNORECASE)
            if hostname_match:
                hostname = hostname_match.group(1)
            else:
                hostname = ip_str

            # Try to extract serial
            serial_match = re.search(r"(?:serial\s*number|serial\s*id|SN)\s*[:\s]+(\S+)", output, re.IGNORECASE)
            if serial_match:
                serial = serial_match.group(1)

            # Try to extract version
            ver_match = re.search(r"(?:version|software|os)\s+([\w\d\.]+)", output, re.IGNORECASE)
            if ver_match:
                os_version = ver_match.group(1)

            # Try to extract model
            model_match = re.search(r"(?:model|platform|hardware)\s*[:\s]+(.+?)(?:,|$|\s)", output, re.IGNORECASE)
            if model_match:
                model = model_match.group(1).strip()

            # Detect vendor from output
            vendor_keywords = {
                "cisco": "Cisco",
                "juniper": "Juniper Networks",
                "arista": "Arista Networks",
                "hp|hpe|procurve": "HPE",
                "nokia|alcatel": "Nokia",
                "ubiquiti|edge": "Ubiquiti",
                "f5": "F5 Networks",
                "palo alto|panos": "Palo Alto Networks",
                "fortinet|forti": "Fortinet",
            }
            for pattern, vendor_name in vendor_keywords.items():
                if re.search(pattern, output, re.IGNORECASE):
                    vendor = vendor_name
                    break

            if not vendor:
                vendor = lines[0].split()[0] if lines else "Unknown"

        client.close()

        return {
            "hostname": hostname,
            "vendor": vendor,
            "model": model,
            "serial": serial,
            "os_version": os_version,
            "raw_output": output[:500],
        }

    except ImportError:
        logger.warning("paramiko not installed; SSH discovery will not work.")
        return None
    except Exception as exc:
        logger.debug("SSH discovery failed for %s: %s", ip_str, exc)
        return None


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
        1. Connects via SSH on port 22
        2. Runs vendor-agnostic show commands
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
        default="admin",
        description="SSH username for device login.",
    )
    ssh_password = StringVar(
        default="",
        description="SSH password for device login. "
                    "Recommended: use Nautobot Secrets and paste the value here.",
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

    def run(self, *, target_network, ssh_username, ssh_password, timeout, concurrency):
        config = get_plugin_config()

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
                )
                if not info:
                    return

                with lock:
                    discovered += 1

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
                )

                with lock:
                    if result_status == "new":
                        created += 1
                    elif result_status == "existing":
                        existing += 1
                    else:
                        failed += 1

                self.logger.info(
                    "SSH: %s -> %s (%s)",
                    ip_str,
                    info["hostname"],
                    result_status,
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
        SNMP-discovered interfaces and IP addresses are also populated.
        """
        dryrun_default = True
        has_sensitive_variables = True
        soft_time_limit = 1800
        time_limit = 3600

    target_network = IPNetworkVar(
        description="CIDR network to scan (e.g., 10.0.0.0/24)"
    )
    snmp_community = StringVar(
        default="public",
        description="SNMP community string.",
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

    def run(self, *, target_network, snmp_community, ssh_username, ssh_password,
            enable_ping, enable_snmp, enable_ssh, populate_interfaces=True, populate_ip_addresses=True,
            include_neighbors=True, dryrun=False, timeout, concurrency):
        config = get_plugin_config()
        config["populate_interfaces"] = populate_interfaces
        config["populate_ip_addresses"] = populate_ip_addresses
        config["include_neighbors"] = include_neighbors
        network = IPNetwork(target_network)
        scan_name = f"Full Scan: {network}"

        discovery_scan = DiscoveryScan.objects.create(
            name=scan_name,
            scan_method=DiscoveryScan.ScanMethod.FULL,
            target_network=str(network),
            status="running",
        )

        self.logger.info("Starting full discovery of %s", network)

        all_hosts = list(network)
        live_hosts = set()
        discovered_hosts = set()
        total_discovered = 0
        total_created = 0
        total_existing = 0
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
            config["snmp_community"] = snmp_community or config.get("snmp_community", "public")
            config["snmp_timeout"] = timeout

            lock = threading.Lock()
            for ip_str in live_hosts:
                try:
                    info = snmp_discover_device(ip_str, config)
                    if info:
                        with lock:
                            discovered_hosts.add(ip_str)
                            snmp_results[ip_str] = info
                            total_discovered += 1

                        if dryrun:
                            device = None
                            result_status = "new"
                            error = "Dry-run: device discovered but not created"
                        else:
                            device, result_status, error = create_device_in_nautobot(
                                info["hostname"], ip_str, info["vendor"], info["model"],
                                info["serial"], info["os_version"], info["platform_info"],
                                config, discovery_scan, info,
                            )

                        DiscoveryResult.objects.create(
                            scan=discovery_scan,
                            ip_address=ip_str,
                            hostname=info["hostname"],
                            vendor=info["vendor"],
                            model=info["model"],
                            serial_number=info["serial"],
                            os_version=info["os_version"],
                            platform_name=info["platform_info"]["platform_name"] if info["platform_info"] else "",
                            discovery_method="snmp",
                            result_status=result_status,
                            nautobot_device=device,
                            sys_location=info.get("sys_location", ""),
                            sys_contact=info.get("sys_contact", ""),
                            interfaces_found=info.get("interfaces_found", 0),
                            ip_addresses_found=info.get("ip_addresses_found", 0),
                            neighbors_found=info.get("neighbors_found", 0),
                            discovered_data={
                                "interfaces": info.get("interfaces", []),
                                "ip_addresses": info.get("ip_addresses", []),
                                "arp_table": info.get("arp_table", []),
                                "physical": info.get("physical", []),
                                "neighbors": info.get("neighbors", []),
                            },
                            error_message=error,
                        )

                        if result_status == "new":
                            if not dryrun:
                                total_created += 1
                        elif result_status == "existing":
                            total_existing += 1

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
                nonlocal total_discovered, total_created, total_existing, total_failed
                try:
                    info = ssh_connect_and_discover(
                        ip_str, ssh_username, ssh_password,
                        timeout=timeout,
                        banner_timeout=config.get("ssh_banner_timeout", 30),
                    )
                    if not info:
                        return

                    with lock:
                        total_discovered += 1

                    if dryrun:
                        device = None
                        result_status = "new"
                        error = "Dry-run: device discovered but not created"
                    else:
                        device, result_status, error = create_device_in_nautobot(
                            info["hostname"], ip_str, info["vendor"], info["model"],
                            info["serial"], info["os_version"], None,
                            config, discovery_scan,
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
                    )

                    with lock:
                        if result_status == "new":
                            if not dryrun:
                                total_created += 1
                        elif result_status == "existing":
                            total_existing += 1
                        else:
                            total_failed += 1

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
        discovery_scan.devices_discovered = total_discovered
        discovery_scan.devices_created = total_created
        discovery_scan.status = "completed"
        discovery_scan.save()

        summary = (
            f"Full discovery complete: "
            f"{total_discovered} discovered, "
            f"{total_created} created, "
            f"{total_existing} existing, "
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
            "failed": total_failed,
        }


# Register all job classes
register_jobs(
    PingSweepJob,
    SNMPDiscoveryJob,
    SSHDiscoveryJob,
    FullDiscoveryJob,
)
