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
    IntegerVar,
    IPNetworkVar,
    Job,
    ObjectVar,
    register_jobs,
    StringVar,
    TextVar,
)
from nautobot.dcim.models import Device, DeviceType, Location, LocationType, Manufacturer, Platform
from nautobot.extras.models import Role
from nautobot.extras.models import Status, Tag

from .models import DiscoveryScan, DiscoveryResult
from .mappings import lookup_platform_from_oid


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


def create_device_in_nautobot(hostname, ip_str, vendor, model, serial, os_version, platform_info, config, discovery_scan):
    """Create a Device object in Nautobot from discovered data.

    Returns:
        tuple: (device, result_status, error_message)
    """
    try:
        resolved = resolve_nautobot_objects(
            hostname, ip_str, vendor, model, serial, os_version, platform_info, config
        )
        if not resolved:
            return None, "failed", "create_missing_objects is disabled in config"

        if resolved["device"]:
            device = resolved["device"]
            status = "existing"
            logger.info("Device %s already exists in Nautobot", hostname)
        else:
            device = Device.objects.create(
                name=hostname,
                platform=resolved["platform"],
                device_type=resolved["device_type"],
                role=resolved["role"],
                location=resolved["location"],
                status=resolved["status"],
                serial=serial or "",
                comments=f"Auto-discovered via device-auto-discovery plugin.\nOS: {os_version}\nVendor: {vendor}\nModel: {model}",
            )
            # Assign tags
            for tag_name in config.get("default_tags", ["auto-discovered"]):
                tag, _ = Tag.objects.get_or_create(name=tag_name)
                device.tags.add(tag)
            status = "new"
            logger.info("Created device %s in Nautobot", hostname)

        # Assign primary IP
        if ip_str:
            try:
                from nautobot.ipam.models import IPAddress
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


SNMP_OID_SYSNAME = "1.3.6.1.2.1.1.5.0"
SNMP_OID_SYSDescR = "1.3.6.1.2.1.1.1.0"
SNMP_OID_SYSOBJECTID = "1.3.6.1.2.1.1.2.0"
SNMP_OID_SYSCONTACT = "1.3.6.1.2.1.1.6.0"
SNMP_OID_SYSLOCATION = "1.3.6.1.2.1.1.7.0"


def snmp_get(ip_str, oid, community="public", timeout=3, retries=2, version="2c"):
    """Perform an SNMP GET request.

    Returns:
        string value or None.
    """
    try:
        from pysnmp.hlapi import (
            SnmpEngine,
            CommunityData,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
            getCmd,
        )

        engine = SnmpEngine()
        if version == "2c":
            cmdgen = getCmd(
                engine,
                CommunityData(community, mpModel=0),
                UdpTransportTarget((ip_str, 161), timeout=timeout, retries=retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
        else:
            cmdgen = None
            logger.debug("SNMPv3 not yet implemented for ip %s", ip_str)

        if cmdgen:
            error_indication, error_status, error_index, var_binds = next(cmdgen)
            if not error_indication and not error_status and var_binds:
                value = var_binds[0][1]
                return str(value)
    except ImportError:
        logger.warning("pysnmp not installed; SNMP discovery will not work.")
        return None
    except Exception as exc:
        logger.debug("SNMP GET failed for %s OID %s: %s", ip_str, oid, exc)
        return None
    return None


def snmp_discover_device(ip_str, config):
    """Discover device info via SNMP.

    Returns:
        dict with hostname, sysdescr, sysobjectid, platform_info, vendor, model, serial
        or None on failure.
    """
    community = config.get("snmp_community", "public")
    timeout = config.get("snmp_timeout", 3)
    retries = config.get("snmp_retries", 2)

    sys_name = snmp_get(ip_str, SNMP_OID_SYSNAME, community, timeout, retries)
    sys_descr = snmp_get(ip_str, SNMP_OID_SYSDescR, community, timeout, retries)
    sys_object_id = snmp_get(ip_str, SNMP_OID_SYSOBJECTID, community, timeout, retries)

    if not sys_name and not sys_descr:
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

    return {
        "hostname": sys_name or ip_str,
        "sys_descr": sys_descr or "",
        "sys_object_id": sys_object_id or "",
        "platform_info": platform_info,
        "vendor": vendor,
        "model": model,
        "serial": "",
        "os_version": sys_descr or "",
    }


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

        Discovered devices are automatically created in Nautobot
        with auto-generated Manufacturer, DeviceType, and Platform objects.
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

    def run(self, *, target_network, snmp_community, timeout, concurrency):
        config = get_plugin_config()
        config["snmp_community"] = snmp_community or config.get("snmp_community", "public")
        config["snmp_timeout"] = timeout
        config["snmp_retries"] = 2

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
                    error_message=error,
                )

                with lock:
                    if result_status == "new":
                        created += 1
                    elif result_status == "existing":
                        existing += 1
                    elif result_status == "failed":
                        failed += 1

                self.logger.info(
                    "SNMP: %s -> %s (%s)",
                    ip_str,
                    info["hostname"],
                    result_status,
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
            enable_ping, enable_snmp, enable_ssh, timeout, concurrency):
        config = get_plugin_config()
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

                        device, result_status, error = create_device_in_nautobot(
                            info["hostname"], ip_str, info["vendor"], info["model"],
                            info["serial"], info["os_version"], info["platform_info"],
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
                            platform_name=info["platform_info"]["platform_name"] if info["platform_info"] else "",
                            discovery_method="snmp",
                            result_status=result_status,
                            nautobot_device=device,
                            error_message=error,
                        )

                        if result_status == "new":
                            total_created += 1
                        elif result_status == "existing":
                            total_existing += 1

                        self.logger.info("SNMP: %s -> %s (%s)", ip_str, info["hostname"], result_status)

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
                            total_created += 1
                        elif result_status == "existing":
                            total_existing += 1
                        else:
                            total_failed += 1

                    self.logger.info("SSH: %s -> %s (%s)", ip_str, info["hostname"], result_status)

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
