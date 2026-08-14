"""SNMP table walking and collection for device discovery.

Provides low-level SNMP WALK helpers and high-level collectors for
common MIB tables used during discovery:

- System scalars: sysName, sysDescr, sysObjectID, sysContact, sysLocation
- IF-MIB interface table (names, types, MACs, speeds, MTUs, status)
- IP-MIB address table and ARP (net-to-media) table
- ENTITY-MIB physical inventory (used for serial numbers)
- LLDP-MIB and CISCO-CDP-MIB neighbor tables
- Q-BRIDGE-MIB dot1qVlanStaticTable (VLAN IDs and names)

Authentication is controlled by the config: SNMPv1/v2c community strings
(``snmp_community``) or SNMPv3 USM credentials (``snmp_version`` ``"3"``
plus ``snmpv3_username``, auth/priv protocol and key, optional context
name). See :func:`build_snmp_auth`.

All collectors return plain Python structures so they can be stored
in ``DiscoveryResult.discovered_data`` (JSONField) and used to
populate Nautobot objects. A failure in any single table never
aborts discovery of the device.
"""

import asyncio
import logging
import re
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

# Q-BRIDGE-MIB (RFC 4363) dot1qVlanStaticTable (index = dot1qVlanIndex / VLAN ID)
OID_VLANSTATICTABLE = "1.3.6.1.2.1.17.7.1.4.2.1"
OID_VLANSTATICEGRESSPORTS = OID_VLANSTATICTABLE + ".2"
OID_VLANSTATICNAME = OID_VLANSTATICTABLE + ".5"
OID_VLANSTATICUNTAGGEDPORTS = OID_VLANSTATICTABLE + ".6"
OID_VLANSTATICROWSTATUS = OID_VLANSTATICTABLE + ".7"

OPER_STATUS_UP = 1


# ------------------------------------------------------------------ #
#  SNMPv3 USM protocol OIDs                                           #
# ------------------------------------------------------------------ #

# Authentication protocol identifiers (RFC 3414 usmAuthProtocol).
USM_AUTH_PROTOCOLS = {
    "": None,
    "none": None,
    "noauth": None,
    "md5": (1, 3, 6, 1, 6, 3, 10, 1, 1, 2),
    "sha": (1, 3, 6, 1, 6, 3, 10, 1, 1, 3),
    "sha-224": (1, 3, 6, 1, 6, 3, 10, 1, 1, 4),
    "sha224": (1, 3, 6, 1, 6, 3, 10, 1, 1, 4),
    "sha-256": (1, 3, 6, 1, 6, 3, 10, 1, 1, 5),
    "sha256": (1, 3, 6, 1, 6, 3, 10, 1, 1, 5),
    "sha-384": (1, 3, 6, 1, 6, 3, 10, 1, 1, 6),
    "sha384": (1, 3, 6, 1, 6, 3, 10, 1, 1, 6),
    "sha-512": (1, 3, 6, 1, 6, 3, 10, 1, 1, 7),
    "sha512": (1, 3, 6, 1, 6, 3, 10, 1, 1, 7),
}

# Privacy/encryption protocol identifiers (RFC 3414 usmPrivProtocol plus
# the common AES-192/AES-256 variants).
USM_PRIV_PROTOCOLS = {
    "": None,
    "none": None,
    "nopriv": None,
    "des": (1, 3, 6, 1, 6, 3, 10, 1, 2, 2),
    "3des": (1, 3, 6, 1, 6, 3, 10, 1, 2, 3),
    "aes": (1, 3, 6, 1, 6, 3, 10, 1, 2, 4),
    "aes-128": (1, 3, 6, 1, 6, 3, 10, 1, 2, 4),
    "aes-192": (1, 3, 6, 1, 4, 1, 9, 12, 6, 1, 101),
    "aes-256": (1, 3, 6, 1, 4, 1, 9, 12, 6, 1, 102),
}


def build_snmp_auth(config):
    """Build the SNMP auth/context dict consumed by the low-level helpers.

    Reads ``snmp_version`` from the config: ``"3"`` selects SNMPv3 USM
    credentials (``snmpv3_username``, optional auth/priv protocol + key and
    context name), anything else falls back to a v1/v2c community string
    (``snmp_community``).

    Returns:
        dict with ``version`` (1, 2 or 3) plus either a ``community`` or the
        USM fields (``user``, ``auth_protocol``, ``auth_key``,
        ``priv_protocol``, ``priv_key``) and an optional ``context``.
    """
    version = str(config.get("snmp_version", "2c")).strip().lower()
    if version == "3":
        return {
            "version": 3,
            "context": config.get("snmpv3_context_name", ""),
            "user": config.get("snmpv3_username", ""),
            "auth_protocol": config.get("snmpv3_auth_protocol", "SHA"),
            "auth_key": config.get("snmpv3_auth_key", ""),
            "priv_protocol": config.get("snmpv3_priv_protocol", "AES"),
            "priv_key": config.get("snmpv3_priv_key", ""),
        }
    return {
        "version": 1 if version == "1" else 2,
        "context": "",
        "community": config.get("snmp_community", "public"),
    }


def _coerce_auth(auth):
    """Accept an auth dict (from build_snmp_auth) or a plain community string."""
    if isinstance(auth, dict):
        return auth
    return {"version": 2, "community": auth or "public", "context": ""}


def _auth_data(api, auth):
    """Build the pysnmp auth data: CommunityData (v1/v2c) or UsmUserData (v3).

    For SNMPv3, a protocol is only applied when the matching key is set, so
    a user without an auth key gets noAuth and one without a priv key gets
    noPriv (matching the usual noAuthNoPriv/authNoPriv/authPriv modes).
    """
    if auth.get("version") == 3:
        auth_key = auth.get("auth_key") or None
        priv_key = auth.get("priv_key") or None
        auth_protocol = None
        priv_protocol = None
        if auth_key:
            auth_protocol = USM_AUTH_PROTOCOLS.get(
                str(auth.get("auth_protocol", "SHA")).strip().lower()
            )
        if priv_key:
            priv_protocol = USM_PRIV_PROTOCOLS.get(
                str(auth.get("priv_protocol", "AES")).strip().lower()
            )
        return api["UsmUserData"](
            auth.get("user", ""),
            authKey=auth_key,
            privKey=priv_key,
            authProtocol=auth_protocol,
            privProtocol=priv_protocol,
        )
    return api["CommunityData"](
        auth.get("community", "public"),
        mpModel=0 if auth.get("version") == 1 else 1,
    )


def _context_data(api, auth):
    """Build the pysnmp ContextData, honoring an optional SNMPv3 context name."""
    return api["ContextData"](auth.get("context", ""))


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
            UsmUserData,
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
            "UsmUserData": UsmUserData,
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
            UsmUserData,
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
            "UsmUserData": UsmUserData,
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


def _classic_get(api, ip_str, oid, auth, timeout, retries):
    error_indication, error_status, error_index, var_binds = next(
        api["getCmd"](
            api["SnmpEngine"](),
            _auth_data(api, auth),
            api["UdpTransportTarget"]((ip_str, 161), timeout=timeout, retries=retries),
            _context_data(api, auth),
            api["ObjectType"](api["ObjectIdentity"](oid)),
        )
    )
    if not error_indication and not error_status and var_binds:
        return str(var_binds[0][1])
    return None


async def _async_get_impl(api, ip_str, oid, auth, timeout, retries):
    transport = await api["UdpTransportTarget"].create((ip_str, 161), timeout=timeout, retries=retries)
    error_indication, error_status, error_index, var_binds = await api["get_cmd"](
        api["SnmpEngine"](),
        _auth_data(api, auth),
        transport,
        _context_data(api, auth),
        api["ObjectType"](api["ObjectIdentity"](oid)),
    )
    if not error_indication and not error_status and var_binds:
        return str(var_binds[0][1])
    return None


def _async_get(api, ip_str, oid, auth, timeout, retries):
    return _run_async(_async_get_impl(api, ip_str, oid, auth, timeout, retries))


def snmp_get(ip_str, oid, auth="public", timeout=3, retries=2):
    """Perform an SNMP GET request (v1/v2c community or v3 USM).

    ``auth`` is either an auth dict from :func:`build_snmp_auth` or, for
    backward compatibility, a plain community string (treated as v2c).

    Returns:
        str value or None on failure.
    """
    api = _get_snmp_api()
    if not api:
        logger.warning("pysnmp not installed or unsupported; SNMP discovery will not work.")
        return None

    auth = _coerce_auth(auth)

    try:
        if api["kind"] == "classic":
            return _classic_get(api, ip_str, oid, auth, timeout, retries)
        return _async_get(api, ip_str, oid, auth, timeout, retries)
    except Exception as exc:
        logger.debug("SNMP GET failed for %s OID %s: %s", ip_str, oid, exc)
        return None


def _classic_walk(api, ip_str, oid, auth, timeout, retries, max_rows):
    rows = []
    prefix = oid.rstrip(".") + "."
    for error_indication, error_status, error_index, var_binds in api["nextCmd"](
        api["SnmpEngine"](),
        _auth_data(api, auth),
        api["UdpTransportTarget"]((ip_str, 161), timeout=timeout, retries=retries),
        _context_data(api, auth),
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


async def _async_walk_impl(api, ip_str, oid, auth, timeout, retries, max_rows):
    transport = await api["UdpTransportTarget"].create((ip_str, 161), timeout=timeout, retries=retries)
    rows = []
    prefix = oid.rstrip(".") + "."
    async for error_indication, error_status, error_index, var_binds in api["walk_cmd"](
        api["SnmpEngine"](),
        _auth_data(api, auth),
        transport,
        _context_data(api, auth),
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


def _async_walk(api, ip_str, oid, auth, timeout, retries, max_rows):
    return _run_async(_async_walk_impl(api, ip_str, oid, auth, timeout, retries, max_rows))


def snmp_walk(ip_str, oid, auth="public", timeout=3, retries=2, max_rows=1000):
    """Walk a subtree via SNMP GETNEXT.

    ``auth`` is either an auth dict from :func:`build_snmp_auth` or, for
    backward compatibility, a plain community string (treated as v2c).

    Returns:
        list of (full_oid, value) tuples, or [] on any failure.
        The list is capped at ``max_rows`` rows.
    """
    api = _get_snmp_api()
    if not api:
        logger.warning("pysnmp not installed or unsupported; SNMP discovery will not work.")
        return []

    auth = _coerce_auth(auth)

    try:
        if api["kind"] == "classic":
            return _classic_walk(api, ip_str, oid, auth, timeout, retries, max_rows)
        return _async_walk(api, ip_str, oid, auth, timeout, retries, max_rows)
    except Exception as exc:
        logger.debug("SNMP WALK failed for %s OID %s: %s", ip_str, oid, exc)
        return []


def walk_columns(ip_str, oid, auth, timeout, retries, max_rows):
    """Walk a table column and return {index_suffix: value}.

    The index suffix is the OID remainder after the column base OID.
    """
    column_map = {}
    for full_oid, value in snmp_walk(ip_str, oid, auth, timeout, retries, max_rows):
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
    auth = build_snmp_auth(config)
    timeout = config.get("snmp_timeout", 3)
    retries = config.get("snmp_retries", 2)

    return {
        "sys_name": snmp_get(ip_str, OID_SYSNAME, auth, timeout, retries) or "",
        "sys_descr": snmp_get(ip_str, OID_SYSDESCR, auth, timeout, retries) or "",
        "sys_object_id": snmp_get(ip_str, OID_SYSOBJECTID, auth, timeout, retries) or "",
        "sys_contact": snmp_get(ip_str, OID_SYSCONTACT, auth, timeout, retries) or "",
        "sys_location": snmp_get(ip_str, OID_SYSLOCATION, auth, timeout, retries) or "",
        "sys_uptime": snmp_get(ip_str, OID_SYSUPTIME, auth, timeout, retries) or "",
    }


def collect_interfaces(ip_str, config, max_rows=1000):
    """Collect the IF-MIB interface table.

    Returns:
        list of dicts: {index, name, descr, type, mtu, speed, mac,
                        admin_status, oper_status, alias, high_speed}
    """
    auth = build_snmp_auth(config)
    timeout = config.get("snmp_timeout", 3)
    retries = config.get("snmp_retries", 2)

    descr_map = walk_columns(ip_str, OID_IFDESCR, auth, timeout, retries, max_rows)
    if not descr_map:
        return []

    type_map = walk_columns(ip_str, OID_IFTYPE, auth, timeout, retries, max_rows)
    mtu_map = walk_columns(ip_str, OID_IFMTU, auth, timeout, retries, max_rows)
    speed_map = walk_columns(ip_str, OID_IFSPEED, auth, timeout, retries, max_rows)
    phys_map = walk_columns(ip_str, OID_IFPHYSADDRESS, auth, timeout, retries, max_rows)
    admin_map = walk_columns(ip_str, OID_IFADMINSTATUS, auth, timeout, retries, max_rows)
    oper_map = walk_columns(ip_str, OID_IFOPERSTATUS, auth, timeout, retries, max_rows)
    name_map = walk_columns(ip_str, OID_IFNAME, auth, timeout, retries, max_rows)
    high_speed_map = walk_columns(ip_str, OID_IFHISPEED, auth, timeout, retries, max_rows)
    alias_map = walk_columns(ip_str, OID_IFALIAS, auth, timeout, retries, max_rows)

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
    auth = build_snmp_auth(config)
    timeout = config.get("snmp_timeout", 3)
    retries = config.get("snmp_retries", 2)

    addresses = []

    # RFC 1213 ipAddrTable (index = IP address)
    ifindex_map = walk_columns(ip_str, OID_IPADENTIFINDEX, auth, timeout, retries, max_rows)
    netmask_map = walk_columns(ip_str, OID_IPADENTNETMASK, auth, timeout, retries, max_rows)
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
        addr_ifindex_map = walk_columns(ip_str, OID_IPADDRESSIFINDEX, auth, timeout, retries, max_rows)
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
    auth = build_snmp_auth(config)
    timeout = config.get("snmp_timeout", 3)
    retries = config.get("snmp_retries", 2)

    ifindex_map = walk_columns(ip_str, OID_IPNETTOMEDIAIFINDEX, auth, timeout, retries, max_rows)
    phys_map = walk_columns(ip_str, OID_IPNETTOMEDIAPHYSADDRESS, auth, timeout, retries, max_rows)

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
    auth = build_snmp_auth(config)
    timeout = config.get("snmp_timeout", 3)
    retries = config.get("snmp_retries", 2)

    descr_map = walk_columns(ip_str, OID_ENTPHYSDESCR, auth, timeout, retries, max_rows)
    if not descr_map:
        return []

    class_map = walk_columns(ip_str, OID_ENTPHYSCLASS, auth, timeout, retries, max_rows)
    name_map = walk_columns(ip_str, OID_ENTPHYSNAME, auth, timeout, retries, max_rows)
    serial_map = walk_columns(ip_str, OID_ENTPHYSSERIALNUM, auth, timeout, retries, max_rows)
    model_map = walk_columns(ip_str, OID_ENTPHYSMODELNAME, auth, timeout, retries, max_rows)

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


def find_chassis_model(physical):
    """Extract a product model from ENTITY-MIB data.

    Prefers the chassis (class 3) entity's model name, then its description;
    falls back to any entity with a model name or a usable description.

    Returns:
        str model, or None if nothing usable is found.
    """
    if not physical:
        return None

    def _clean(value):
        cleaned = (value or "").strip()
        if not cleaned:
            return ""
        # Drop parenthetical/boilerplate additions and trailing version markers.
        cleaned = re.split(r"\s*(?:\(\w+\)|\[.*\]|,)", cleaned, maxsplit=1)[0].strip()
        return cleaned

    candidates = []
    for entity in physical:
        model = _clean(entity.get("model"))
        if model:
            candidates.append(model)
    for entity in physical:
        if entity.get("class") == 3 and _clean(entity.get("descr")):
            candidates.append(_clean(entity["descr"]))

    # Most specific-looking candidate wins: chassis entity first.
    for entity in physical:
        if entity.get("class") == 3:
            model = _clean(entity.get("model"))
            if model:
                return model
    for entity in physical:
        if entity.get("class") == 3:
            descr = _clean(entity.get("descr"))
            if descr:
                return descr
    for model in candidates:
        return model
    return None


def collect_lldp_neighbors(ip_str, config, max_rows=1000):
    """Collect the LLDP-MIB remote table.

    Returns:
        list of dicts: {local_if_index, local_port_num, remote_name,
                        remote_port, remote_description, remote_ip}
    """
    auth = build_snmp_auth(config)
    timeout = config.get("snmp_timeout", 3)
    retries = config.get("snmp_retries", 2)

    # Map local port number -> ifIndex
    local_port_ifindex = walk_columns(ip_str, OID_LLDPLOCPORTIFINDEX, auth, timeout, retries, max_rows)

    sysname_map = walk_columns(ip_str, OID_LLDPREMSYSNAME, auth, timeout, retries, max_rows)
    if not sysname_map:
        return []

    port_id_map = walk_columns(ip_str, OID_LLDPREMPORTID, auth, timeout, retries, max_rows)
    sysdesc_map = walk_columns(ip_str, OID_LLDPREMSYSDESC, auth, timeout, retries, max_rows)
    chassis_map = walk_columns(ip_str, OID_LLDPREMCHASSISID, auth, timeout, retries, max_rows)

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
    auth = build_snmp_auth(config)
    timeout = config.get("snmp_timeout", 3)
    retries = config.get("snmp_retries", 2)

    device_map = walk_columns(ip_str, OID_CDPCACHEDEVICEID, auth, timeout, retries, max_rows)
    if not device_map:
        return []

    port_map = walk_columns(ip_str, OID_CDPCACHEDEVICEPORT, auth, timeout, retries, max_rows)
    platform_map = walk_columns(ip_str, OID_CDPCACHEPLATFORM, auth, timeout, retries, max_rows)

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


def collect_vlans(ip_str, config, max_rows=1000):
    """Collect the Q-BRIDGE-MIB dot1qVlanStaticTable.

    Each entry is indexed by its VLAN ID (dot1qVlanIndex). Only the name
    and row status columns are walked; the (potentially huge) port-membership
    bitmaps are skipped.

    Returns:
        list of dicts: {vid, name, row_status}
    """
    auth = build_snmp_auth(config)
    timeout = config.get("snmp_timeout", 3)
    retries = config.get("snmp_retries", 2)

    name_map = walk_columns(ip_str, OID_VLANSTATICNAME, auth, timeout, retries, max_rows)
    if not name_map:
        return []

    row_status_map = walk_columns(ip_str, OID_VLANSTATICROWSTATUS, auth, timeout, retries, max_rows)

    vlans = []
    for vid, name in name_map.items():
        try:
            vid_int = int(float(vid))
        except (TypeError, ValueError):
            continue
        if not 1 <= vid_int <= 4094:
            continue
        vlans.append(
            {
                "vid": vid_int,
                "name": name,
                "row_status": int(float(row_status_map[vid])) if vid in row_status_map else None,
            }
        )

    vlans.sort(key=lambda vlan: vlan["vid"])
    return vlans


# ------------------------------------------------------------------ #
#  Orchestrator                                                       #
# ------------------------------------------------------------------ #


def discover_snmp_tables(ip_str, config):
    """Walk all configured common MIB tables for a host.

    Each collector is isolated so a single failure only drops one table.

    Returns:
        dict with keys: system, interfaces, ip_addresses, arp_table,
        physical, neighbors, vlans
    """
    max_rows = config.get("max_walk_oids", 1000)
    include_neighbors = config.get("include_neighbors", True)
    include_vlans = config.get("include_vlans", True)

    tables = {
        "system": {},
        "interfaces": [],
        "ip_addresses": [],
        "arp_table": [],
        "physical": [],
        "neighbors": [],
        "vlans": [],
    }

    # Quick reachability probe: a host that does not answer SNMP at all
    # would otherwise burn a multi-second timeout on *every* scalar GET
    # and column walk below (~150s per silent host). One sysName GET is
    # enough to decide that SNMP is not available and skip the rest.
    auth = build_snmp_auth(config)
    timeout = config.get("snmp_timeout", 3)
    retries = config.get("snmp_retries", 2)
    if not snmp_get(ip_str, OID_SYSNAME, auth, timeout, retries):
        logger.debug("SNMP not responding on %s; skipping table walks", ip_str)
        return tables

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

    if include_vlans:
        try:
            tables["vlans"] = collect_vlans(ip_str, config, max_rows=max_rows)
        except Exception as exc:
            logger.debug("SNMP VLAN collection failed for %s: %s", ip_str, exc)

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
