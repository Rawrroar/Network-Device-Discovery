"""SNMP table walking and collection for device discovery.

Provides low-level SNMP WALK helpers and high-level collectors for
common MIB tables used during discovery:

- System scalars: sysName, sysDescr, sysObjectID, sysContact, sysLocation
- IF-MIB interface table (names, types, MACs, speeds, MTUs, status)
- IP-MIB address table and ARP (net-to-media) table
- ENTITY-MIB physical inventory (used for serial numbers)
- LLDP-MIB and CISCO-CDP-MIB neighbor tables

All collectors return plain Python structures so they can be stored
in ``DiscoveryResult.discovered_data`` (JSONField) and used to
populate Nautobot objects. A failure in any single table never
aborts discovery of the device.
"""

import asyncio
import logging
import threading

from netaddr import IPAddress

from .mappings import lookup_interface_type

logger = logging.getLogger(__name__.split(".")[0])


# ------------------------------------------------------------------ #
#  OIDs                                                               #
# ------------------------------------------------------------------ #

# SNMPv2-MIB / RFC 1213-MIB system group
OID_SYSNAME = "1.3.6.1.2.1.1.5.0"
OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"
OID_SYSOBJECTID = "1.3.6.1.2.1.1.2.0"
OID_SYSCONTACT = "1.3.6.1.2.1.1.4.0"
OID_SYSLOCATION = "1.3.6.1.2.1.1.6.0"
OID_SYSUPTIME = "1.3.6.1.2.1.1.3.0"

# IF-MIB
OID_IFTABLE = "1.3.6.1.2.1.2.2.1"  # ifIndex.ifType.ifMtu.ifSpeed.ifPhysAddress.ifAdminStatus.ifOperStatus
OID_IFDESCR = OID_IFTABLE + ".2"
OID_IFTYPE = OID_IFTABLE + ".3"
OID_IFMTU = OID_IFTABLE + ".4"
OID_IFSPEED = OID_IFTABLE + ".5"
OID_IFPHYSADDRESS = OID_IFTABLE + ".6"
OID_IFADMINSTATUS = OID_IFTABLE + ".7"
OID_IFOPERSTATUS = OID_IFTABLE + ".8"

OID_IFXTABLE = "1.3.6.1.2.1.31.1.1.1"
OID_IFNAME = OID_IFXTABLE + ".1"
OID_IFHISPEED = OID_IFXTABLE + ".15"
OID_IFALIAS = OID_IFXTABLE + ".18"

# IP-MIB
OID_IPADDRTABLE = "1.3.6.1.2.1.4.20.1"  # ipAdEntIfIndex(.2).ipAdEntNetMask(.3)
OID_IPADENTIFINDEX = OID_IPADDRTABLE + ".2"
OID_IPADENTNETMASK = OID_IPADDRTABLE + ".3"
OID_IPADDRESSTABLE = "1.3.6.1.2.1.4.34.1"  # ipAddressIfIndex(.1).ipAddressPrefix(.2)
OID_IPADDRESSIFINDEX = OID_IPADDRESSTABLE + ".1"
OID_IPNETTOMEDIATABLE = "1.3.6.1.2.1.4.22.1"  # ipNetToMediaIfIndex(.2).ipNetToMediaPhysAddress(.3)
OID_IPNETTOMEDIAIFINDEX = OID_IPNETTOMEDIATABLE + ".2"
OID_IPNETTOMEDIAPHYSADDRESS = OID_IPNETTOMEDIATABLE + ".3"

# ENTITY-MIB
OID_ENTPHYSTABLE = "1.3.6.1.2.1.47.1.1.1.1"
OID_ENTPHYSDESCR = OID_ENTPHYSTABLE + ".2"
OID_ENTPHYSCLASS = OID_ENTPHYSTABLE + ".5"
OID_ENTPHYSNAME = OID_ENTPHYSTABLE + ".7"
OID_ENTPHYSSERIALNUM = OID_ENTPHYSTABLE + ".11"
OID_ENTPHYSMODELNAME = OID_ENTPHYSTABLE + ".13"

# LLDP-MIB (1.0.8802.1.1.2)
OID_LLDPLOCPORTTABLE = "1.0.8802.1.1.2.1.3.7.1"  # lldpLocPortIfIndex(.4)
OID_LLDPLOCPORTIFINDEX = OID_LLDPLOCPORTTABLE + ".4"
OID_LLDPREMTABLE = "1.0.8802.1.1.2.1.4.1.1"
OID_LLDPREMCHASSISID = OID_LLDPREMTABLE + ".5"
OID_LLDPREMPORTID = OID_LLDPREMTABLE + ".7"
OID_LLDPREMSYSNAME = OID_LLDPREMTABLE + ".10"
OID_LLDPREMSYSDESC = OID_LLDPREMTABLE + ".11"

# CISCO-CDP-MIB
OID_CDPCACHETABLE = "1.3.6.1.4.1.9.9.23.1.2.1.1"
OID_CDPCACHEDEVICEID = OID_CDPCACHETABLE + ".6"
OID_CDPCACHEDEVICEPORT = OID_CDPCACHETABLE + ".7"
OID_CDPCACHEPLATFORM = OID_CDPCACHETABLE + ".8"

OPER_STATUS_UP = 1


# ------------------------------------------------------------------ #
#  Low-level SNMP helpers                                             #
# ------------------------------------------------------------------ #

_snmp_api_cache = {"resolved": False, "value": None}


def _load_snmp_api():
    """Detect the installed pysnmp API.

    Returns a dict of callables for either the classic synchronous API
    (pysnmp < 7) or the asyncio API (pysnmp >= 7), or None if pysnmp
    is not importable at all.
    """
    try:
        from pysnmp.hlapi import (  # noqa: PLC0415 - classic sync API, pysnmp < 7
            SnmpEngine,
            CommunityData,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
            getCmd,
            nextCmd,
        )

        return {
            "kind": "classic",
            "SnmpEngine": SnmpEngine,
            "CommunityData": CommunityData,
            "UdpTransportTarget": UdpTransportTarget,
            "ContextData": ContextData,
            "ObjectType": ObjectType,
            "ObjectIdentity": ObjectIdentity,
            "getCmd": getCmd,
            "nextCmd": nextCmd,
        }
    except ImportError:
        pass

    try:
        from pysnmp.hlapi.asyncio import (  # noqa: PLC0415 - asyncio API, pysnmp >= 7
            SnmpEngine,
            CommunityData,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
            get_cmd,
            walk_cmd,
        )

        return {
            "kind": "async",
            "SnmpEngine": SnmpEngine,
            "CommunityData": CommunityData,
            "UdpTransportTarget": UdpTransportTarget,
            "ContextData": ContextData,
            "ObjectType": ObjectType,
            "ObjectIdentity": ObjectIdentity,
            "get_cmd": get_cmd,
            "walk_cmd": walk_cmd,
        }
    except ImportError:
        return None


def _get_snmp_api():
    if not _snmp_api_cache["resolved"]:
        _snmp_api_cache["value"] = _load_snmp_api()
        _snmp_api_cache["resolved"] = True
    return _snmp_api_cache["value"]


def _community_kwargs(community):
    """Build kwargs for CommunityData (SNMPv2c)."""
    return {"mpModel": 0}


def _run_async(coro):
    """Run a coroutine synchronously, tolerating an already-running loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result = {}

    def _runner():
        result["value"] = asyncio.run(coro)

    thread = threading.Thread(target=_runner)
    thread.start()
    thread.join()
    return result["value"]


def _classic_get(api, ip_str, oid, community, timeout, retries):
    error_indication, error_status, error_index, var_binds = next(
        api["getCmd"](
            api["SnmpEngine"](),
            api["CommunityData"](community, **_community_kwargs(community)),
            api["UdpTransportTarget"]((ip_str, 161), timeout=timeout, retries=retries),
            api["ContextData"](),
            api["ObjectType"](api["ObjectIdentity"](oid)),
        )
    )
    if not error_indication and not error_status and var_binds:
        return str(var_binds[0][1])
    return None


async def _async_get_impl(api, ip_str, oid, community, timeout, retries):
    transport = await api["UdpTransportTarget"].create((ip_str, 161), timeout=timeout, retries=retries)
    error_indication, error_status, error_index, var_binds = await api["get_cmd"](
        api["SnmpEngine"](),
        api["CommunityData"](community, **_community_kwargs(community)),
        transport,
        api["ContextData"](),
        api["ObjectType"](api["ObjectIdentity"](oid)),
    )
    if not error_indication and not error_status and var_binds:
        return str(var_binds[0][1])
    return None


def _async_get(api, ip_str, oid, community, timeout, retries):
    return _run_async(_async_get_impl(api, ip_str, oid, community, timeout, retries))


def snmp_get(ip_str, oid, community="public", timeout=3, retries=2):
    """Perform an SNMP GET request (SNMPv2c).

    Returns:
        str value or None on failure.
    """
    api = _get_snmp_api()
    if not api:
        logger.warning("pysnmp not installed or unsupported; SNMP discovery will not work.")
        return None

    try:
        if api["kind"] == "classic":
            return _classic_get(api, ip_str, oid, community, timeout, retries)
        return _async_get(api, ip_str, oid, community, timeout, retries)
    except Exception as exc:
        logger.debug("SNMP GET failed for %s OID %s: %s", ip_str, oid, exc)
        return None


def _classic_walk(api, ip_str, oid, community, timeout, retries, max_rows):
    rows = []
    prefix = oid.rstrip(".") + "."
    for error_indication, error_status, error_index, var_binds in api["nextCmd"](
        api["SnmpEngine"](),
        api["CommunityData"](community, **_community_kwargs(community)),
        api["UdpTransportTarget"]((ip_str, 161), timeout=timeout, retries=retries),
        api["ContextData"](),
        api["ObjectType"](api["ObjectIdentity"](oid)),
        lexicographicMode=False,
        maxRows=max_rows,
    ):
        if error_indication or error_status:
            logger.debug("SNMP WALK error for %s OID %s: %s", ip_str, oid, error_indication or error_status)
            break
        for var_bind in var_binds:
            full_oid = str(var_bind[0])
            if not full_oid.startswith(prefix):
                return rows
            rows.append((full_oid, str(var_bind[1])))
    return rows


async def _async_walk_impl(api, ip_str, oid, community, timeout, retries, max_rows):
    transport = await api["UdpTransportTarget"].create((ip_str, 161), timeout=timeout, retries=retries)
    rows = []
    prefix = oid.rstrip(".") + "."
    async for error_indication, error_status, error_index, var_binds in api["walk_cmd"](
        api["SnmpEngine"](),
        api["CommunityData"](community, **_community_kwargs(community)),
        transport,
        api["ContextData"](),
        api["ObjectType"](api["ObjectIdentity"](oid)),
        lexicographicMode=False,
        maxRows=max_rows,
    ):
        if error_indication or error_status:
            logger.debug("SNMP WALK error for %s OID %s: %s", ip_str, oid, error_indication or error_status)
            break
        for var_bind in var_binds:
            full_oid = str(var_bind[0])
            if not full_oid.startswith(prefix):
                return rows
            rows.append((full_oid, str(var_bind[1])))
    return rows


def _async_walk(api, ip_str, oid, community, timeout, retries, max_rows):
    return _run_async(_async_walk_impl(api, ip_str, oid, community, timeout, retries, max_rows))


def snmp_walk(ip_str, oid, community="public", timeout=3, retries=2, max_rows=1000):
    """Walk a subtree via SNMP GETNEXT.

    Returns:
        list of (full_oid, value) tuples, or [] on any failure.
        The list is capped at ``max_rows`` rows.
    """
    api = _get_snmp_api()
    if not api:
        logger.warning("pysnmp not installed or unsupported; SNMP discovery will not work.")
        return []

    try:
        if api["kind"] == "classic":
            return _classic_walk(api, ip_str, oid, community, timeout, retries, max_rows)
        return _async_walk(api, ip_str, oid, community, timeout, retries, max_rows)
    except Exception as exc:
        logger.debug("SNMP WALK failed for %s OID %s: %s", ip_str, oid, exc)
        return []


def walk_columns(ip_str, oid, community, timeout, retries, max_rows):
    """Walk a table column and return {index_suffix: value}.

    The index suffix is the OID remainder after the column base OID.
    """
    column_map = {}
    for full_oid, value in snmp_walk(ip_str, oid, community, timeout, retries, max_rows):
        if full_oid.startswith(oid + "."):
            column_map[full_oid[len(oid) + 1 :]] = value
    return column_map


def mac_from_bytes(raw):
    """Format an OctetString MAC into 'aa:bb:cc:dd:ee:ff'.

    Returns None for empty or all-zero MACs.
    """
    if not raw:
        return None
    try:
        raw = raw.replace(":", "").replace("-", "")
        if len(raw) != 12:
            return None
        if int(raw, 16) == 0:
            return None
        return ":".join(raw[i : i + 2] for i in range(0, 12, 2)).lower()
    except (TypeError, ValueError):
        return None


def _if_type_name(code, speed=None):
    """Map a numeric IANA ifType to a Nautobot InterfaceTypeChoices value."""
    return lookup_interface_type(code, speed)


# ------------------------------------------------------------------ #
#  Collectors                                                         #
# ------------------------------------------------------------------ #


def collect_system(ip_str, config):
    """Collect system scalars (SNMPv2-MIB system group)."""
    community = config.get("snmp_community", "public")
    timeout = config.get("snmp_timeout", 3)
    retries = config.get("snmp_retries", 2)

    return {
        "sys_name": snmp_get(ip_str, OID_SYSNAME, community, timeout, retries) or "",
        "sys_descr": snmp_get(ip_str, OID_SYSDESCR, community, timeout, retries) or "",
        "sys_object_id": snmp_get(ip_str, OID_SYSOBJECTID, community, timeout, retries) or "",
        "sys_contact": snmp_get(ip_str, OID_SYSCONTACT, community, timeout, retries) or "",
        "sys_location": snmp_get(ip_str, OID_SYSLOCATION, community, timeout, retries) or "",
        "sys_uptime": snmp_get(ip_str, OID_SYSUPTIME, community, timeout, retries) or "",
    }


def collect_interfaces(ip_str, config, max_rows=1000):
    """Collect the IF-MIB interface table.

    Returns:
        list of dicts: {index, name, descr, type, mtu, speed, mac,
                        admin_status, oper_status, alias, high_speed}
    """
    community = config.get("snmp_community", "public")
    timeout = config.get("snmp_timeout", 3)
    retries = config.get("snmp_retries", 2)

    descr_map = walk_columns(ip_str, OID_IFDESCR, community, timeout, retries, max_rows)
    if not descr_map:
        return []

    type_map = walk_columns(ip_str, OID_IFTYPE, community, timeout, retries, max_rows)
    mtu_map = walk_columns(ip_str, OID_IFMTU, community, timeout, retries, max_rows)
    speed_map = walk_columns(ip_str, OID_IFSPEED, community, timeout, retries, max_rows)
    phys_map = walk_columns(ip_str, OID_IFPHYSADDRESS, community, timeout, retries, max_rows)
    admin_map = walk_columns(ip_str, OID_IFADMINSTATUS, community, timeout, retries, max_rows)
    oper_map = walk_columns(ip_str, OID_IFOPERSTATUS, community, timeout, retries, max_rows)
    name_map = walk_columns(ip_str, OID_IFNAME, community, timeout, retries, max_rows)
    high_speed_map = walk_columns(ip_str, OID_IFHISPEED, community, timeout, retries, max_rows)
    alias_map = walk_columns(ip_str, OID_IFALIAS, community, timeout, retries, max_rows)

    interfaces = []
    for index in descr_map:
        try:
            speed_kbps = None
            if index in high_speed_map:
                try:
                    speed_kbps = int(float(high_speed_map[index])) * 1000
                except (TypeError, ValueError):
                    speed_kbps = None
            if speed_kbps is None and index in speed_map:
                try:
                    speed_kbps = int(float(speed_map[index])) // 1000
                except (TypeError, ValueError):
                    speed_kbps = None
        except Exception:
            speed_kbps = None

        mac = mac_from_bytes(phys_map.get(index, ""))

        interfaces.append(
            {
                "index": index,
                "name": name_map.get(index) or descr_map[index],
                "descr": descr_map[index],
                "type": _if_type_name(type_map.get(index, ""), speed_kbps),
                "mtu": int(float(mtu_map[index])) if index in mtu_map else None,
                "speed": speed_kbps,
                "mac": mac or "",
                "admin_status": int(float(admin_map[index])) if index in admin_map else None,
                "oper_status": int(float(oper_map[index])) if index in oper_map else None,
                "alias": alias_map.get(index, ""),
                "high_speed": int(float(high_speed_map[index])) if index in high_speed_map else None,
            }
        )

    interfaces.sort(key=lambda iface: _int_or_str(iface["index"]))
    return interfaces


def collect_ip_addresses(ip_str, config, max_rows=1000):
    """Collect IP addresses from IP-MIB.

    Returns:
        list of dicts: {address, prefix_length, if_index}
    """
    community = config.get("snmp_community", "public")
    timeout = config.get("snmp_timeout", 3)
    retries = config.get("snmp_retries", 2)

    addresses = []

    # RFC 1213 ipAddrTable (index = IP address)
    ifindex_map = walk_columns(ip_str, OID_IPADENTIFINDEX, community, timeout, retries, max_rows)
    netmask_map = walk_columns(ip_str, OID_IPADENTNETMASK, community, timeout, retries, max_rows)
    if ifindex_map:
        for addr, if_index in ifindex_map.items():
            prefix_length = _netmask_to_prefix(netmask_map.get(addr, ""))
            if prefix_length is None:
                continue
            addresses.append(
                {
                    "address": addr,
                    "prefix_length": prefix_length,
                    "if_index": str(if_index),
                }
            )

    # IP-MIB ipAddressTable fallback (index = IPv4/IPv6 string)
    if not addresses:
        addr_ifindex_map = walk_columns(ip_str, OID_IPADDRESSIFINDEX, community, timeout, retries, max_rows)
        for addr, if_index in addr_ifindex_map.items():
            addresses.append(
                {
                    "address": addr,
                    "prefix_length": None,
                    "if_index": str(if_index),
                }
            )

    return addresses


def collect_arp_table(ip_str, config, max_rows=1000):
    """Collect the ARP (net-to-media) table from IP-MIB.

    Returns:
        list of dicts: {if_index, ip, mac}
    """
    community = config.get("snmp_community", "public")
    timeout = config.get("snmp_timeout", 3)
    retries = config.get("snmp_retries", 2)

    ifindex_map = walk_columns(ip_str, OID_IPNETTOMEDIAIFINDEX, community, timeout, retries, max_rows)
    phys_map = walk_columns(ip_str, OID_IPNETTOMEDIAPHYSADDRESS, community, timeout, retries, max_rows)

    entries = []
    for ip_addr, if_index in ifindex_map.items():
        mac = mac_from_bytes(phys_map.get(ip_addr, ""))
        if not mac:
            continue
        entries.append({"if_index": str(if_index), "ip": ip_addr, "mac": mac})
    return entries


def collect_physical(ip_str, config, max_rows=1000):
    """Collect the ENTITY-MIB physical inventory table.

    Returns:
        list of dicts: {index, class, name, descr, model, serial}
    """
    community = config.get("snmp_community", "public")
    timeout = config.get("snmp_timeout", 3)
    retries = config.get("snmp_retries", 2)

    descr_map = walk_columns(ip_str, OID_ENTPHYSDESCR, community, timeout, retries, max_rows)
    if not descr_map:
        return []

    class_map = walk_columns(ip_str, OID_ENTPHYSCLASS, community, timeout, retries, max_rows)
    name_map = walk_columns(ip_str, OID_ENTPHYSNAME, community, timeout, retries, max_rows)
    serial_map = walk_columns(ip_str, OID_ENTPHYSSERIALNUM, community, timeout, retries, max_rows)
    model_map = walk_columns(ip_str, OID_ENTPHYSMODELNAME, community, timeout, retries, max_rows)

    entities = []
    for index in descr_map:
        entities.append(
            {
                "index": index,
                "class": int(float(class_map[index])) if index in class_map else None,
                "name": name_map.get(index, ""),
                "descr": descr_map[index],
                "model": model_map.get(index, ""),
                "serial": serial_map.get(index, ""),
            }
        )
    return entities


def find_chassis_serial(physical):
    """Extract the most useful serial number from ENTITY-MIB data.

    Prefers the chassis (class 3), then any non-empty serial.
    Returns None if nothing found.
    """
    if not physical:
        return None
    for entity in physical:
        if entity.get("class") == 3 and entity.get("serial"):
            return entity["serial"]
    for entity in physical:
        if entity.get("serial"):
            return entity["serial"]
    return None


def collect_lldp_neighbors(ip_str, config, max_rows=1000):
    """Collect the LLDP-MIB remote table.

    Returns:
        list of dicts: {local_if_index, local_port_num, remote_name,
                        remote_port, remote_description, remote_ip}
    """
    community = config.get("snmp_community", "public")
    timeout = config.get("snmp_timeout", 3)
    retries = config.get("snmp_retries", 2)

    # Map local port number -> ifIndex
    local_port_ifindex = walk_columns(ip_str, OID_LLDPLOCPORTIFINDEX, community, timeout, retries, max_rows)

    sysname_map = walk_columns(ip_str, OID_LLDPREMSYSNAME, community, timeout, retries, max_rows)
    if not sysname_map:
        return []

    port_id_map = walk_columns(ip_str, OID_LLDPREMPORTID, community, timeout, retries, max_rows)
    sysdesc_map = walk_columns(ip_str, OID_LLDPREMSYSDESC, community, timeout, retries, max_rows)
    chassis_map = walk_columns(ip_str, OID_LLDPREMCHASSISID, community, timeout, retries, max_rows)

    neighbors = []
    for index, sys_name in sysname_map.items():
        # lldpRem index format: <timeMark>.<localPortNum>.<lldpRemIndex>
        parts = index.split(".")
        local_port_num = parts[1] if len(parts) >= 2 else ""
        local_if_index = local_port_ifindex.get(local_port_num, "")

        neighbors.append(
            {
                "protocol": "lldp",
                "local_if_index": local_if_index,
                "local_port_num": local_port_num,
                "remote_name": sys_name,
                "remote_port": port_id_map.get(index, ""),
                "remote_description": sysdesc_map.get(index, ""),
                "remote_ip": "",
                "remote_chassis_id": chassis_map.get(index, ""),
            }
        )
    return neighbors


def collect_cdp_neighbors(ip_str, config, max_rows=1000):
    """Collect the CISCO-CDP-MIB cache table.

    Returns:
        list of dicts with same shape as LLDP neighbors.
    """
    community = config.get("snmp_community", "public")
    timeout = config.get("snmp_timeout", 3)
    retries = config.get("snmp_retries", 2)

    device_map = walk_columns(ip_str, OID_CDPCACHEDEVICEID, community, timeout, retries, max_rows)
    if not device_map:
        return []

    port_map = walk_columns(ip_str, OID_CDPCACHEDEVICEPORT, community, timeout, retries, max_rows)
    platform_map = walk_columns(ip_str, OID_CDPCACHEPLATFORM, community, timeout, retries, max_rows)

    neighbors = []
    for index, device_id in device_map.items():
        # cdpCache index format: <ifIndex>.<cdpCacheDeviceIndex>
        parts = index.split(".")
        local_if_index = parts[0] if parts else ""
        neighbors.append(
            {
                "protocol": "cdp",
                "local_if_index": local_if_index,
                "local_port_num": "",
                "remote_name": device_id,
                "remote_port": port_map.get(index, ""),
                "remote_description": platform_map.get(index, ""),
                "remote_ip": "",
                "remote_chassis_id": "",
            }
        )
    return neighbors


def collect_neighbors(ip_str, config, max_rows=1000):
    """Collect both LLDP and CDP neighbors.

    Returns:
        list of neighbor dicts (see collect_lldp_neighbors).
    """
    return collect_lldp_neighbors(ip_str, config, max_rows) + collect_cdp_neighbors(ip_str, config, max_rows)


# ------------------------------------------------------------------ #
#  Orchestrator                                                       #
# ------------------------------------------------------------------ #


def discover_snmp_tables(ip_str, config):
    """Walk all configured common MIB tables for a host.

    Each collector is isolated so a single failure only drops one table.

    Returns:
        dict with keys: system, interfaces, ip_addresses, arp_table,
        physical, neighbors
    """
    max_rows = config.get("max_walk_oids", 1000)
    include_neighbors = config.get("include_neighbors", True)

    tables = {
        "system": {},
        "interfaces": [],
        "ip_addresses": [],
        "arp_table": [],
        "physical": [],
        "neighbors": [],
    }

    try:
        tables["system"] = collect_system(ip_str, config)
    except Exception as exc:
        logger.debug("SNMP system collection failed for %s: %s", ip_str, exc)

    try:
        tables["interfaces"] = collect_interfaces(ip_str, config, max_rows=max_rows)
    except Exception as exc:
        logger.debug("SNMP interface collection failed for %s: %s", ip_str, exc)

    try:
        tables["ip_addresses"] = collect_ip_addresses(ip_str, config, max_rows=max_rows)
    except Exception as exc:
        logger.debug("SNMP IP collection failed for %s: %s", ip_str, exc)

    try:
        tables["arp_table"] = collect_arp_table(ip_str, config, max_rows=max_rows)
    except Exception as exc:
        logger.debug("SNMP ARP collection failed for %s: %s", ip_str, exc)

    try:
        tables["physical"] = collect_physical(ip_str, config, max_rows=max_rows)
    except Exception as exc:
        logger.debug("SNMP physical collection failed for %s: %s", ip_str, exc)

    if include_neighbors:
        try:
            tables["neighbors"] = collect_neighbors(ip_str, config, max_rows=max_rows)
        except Exception as exc:
            logger.debug("SNMP neighbor collection failed for %s: %s", ip_str, exc)

    return tables


def _netmask_to_prefix(netmask):
    """Convert a dotted-quad netmask to a prefix length, or None."""
    if not netmask:
        return None
    try:
        return IPAddress(netmask).netmask_bits()
    except Exception:
        return None


def _int_or_str(value):
    """Sort key helper: try to compare as int, fall back to str."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return value
