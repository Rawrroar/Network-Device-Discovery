"""SNMP table walking and collection for device discovery.

Provides low-level SNMP WALK helpers and high-level collectors for
common MIB tables used during discovery:

- System scalars: sysName, sysDescr, sysObjectID, sysContact, sysLocation
- IF-MIB interface table (names, types, MACs, speeds, MTUs, status)
- IP-MIB address table (RFC 1213 ipAddrTable and IP-MIB ipAddressTable,
  IPv4 and IPv6) and ARP (net-to-media) table
- VRF tables: MPLS-VPN-MIB mplsVpnVrfTable plus both revisions of the
  Cisco CISCO-VRF-MIB, with optional per-context (per-VRF) IP walking
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
OID_IPADDRESSTABLE = "1.3.6.1.2.1.4.34.1"  # ipAddressIfIndex(.1).ipAddressType(.2).ipAddressPrefix(.3)
OID_IPADDRESSIFINDEX = OID_IPADDRESSTABLE + ".1"
OID_IPADDRESSTYPE = OID_IPADDRESSTABLE + ".2"
OID_IPADDRESSPREFIX = OID_IPADDRESSTABLE + ".3"  # pointer into ipAddressPrefixTable
OID_IPADDRESSPREFIXTABLE = "1.3.6.1.2.1.4.32.1"  # ipAddressPrefixIfIndex(.1).ipAddressPrefixLength(.4)
OID_IPADDRESSPREFIXLENGTH = OID_IPADDRESSPREFIXTABLE + ".4"
OID_IPNETTOMEDIATABLE = "1.3.6.1.2.1.4.22.1"  # ipNetToMediaIfIndex(.2).ipNetToMediaPhysAddress(.3)
OID_IPNETTOMEDIAIFINDEX = OID_IPNETTOMEDIATABLE + ".2"
OID_IPNETTOMEDIAPHYSADDRESS = OID_IPNETTOMEDIATABLE + ".3"

# MPLS-VPN-MIB (RFC 4382) - mplsVpnVrfTable (index = VRF name)
OID_MPLSVPNVRFTABLE = "1.3.6.1.3.118.1.2.2.1"
OID_MPLSVPNVRFNAME = OID_MPLSVPNVRFTABLE + ".1"
OID_MPLSVPNVRFDESCRIPTION = OID_MPLSVPNVRFTABLE + ".2"
OID_MPLSVPNVRFRD = OID_MPLSVPNVRFTABLE + ".3"
# mplsVpnInterfaceConfTable (index = VRF name . ifIndex)
OID_MPLSVPNINTERFACECONFTABLE = "1.3.6.1.3.118.1.2.1.1"
OID_MPLSVPNINTERFACECONFINDEX = OID_MPLSVPNINTERFACECONFTABLE + ".1"

# CISCO-VRF-MIB classic (1.3.6.1.4.1.9.9.276) - cvrfVrfTable (index = VRF name)
OID_CVRFVRFTABLE = "1.3.6.1.4.1.9.9.276.1.1.1.1"
OID_CVRFVRFNAME = OID_CVRFVRFTABLE + ".1"
OID_CVRFVRFINDEX = OID_CVRFVRFTABLE + ".2"

# CISCO-VRF-MIB v2 (1.3.6.1.4.1.9.9.711) - cvVrfTable (index = cvVrfIndex)
OID_CVVRFTABLE = "1.3.6.1.4.1.9.9.711.1.1.1.1"
OID_CVVRFINDEX = OID_CVVRFTABLE + ".1"
OID_CVVRFNAME = OID_CVVRFTABLE + ".2"
# cvVrfInterfaceTable (index = cvVrfIndex . ifIndex)
OID_CVVRFINTERFACETABLE = "1.3.6.1.4.1.9.9.711.1.2.1.1"
OID_CVVRFINTERFACEIFINDEX = OID_CVVRFINTERFACETABLE + ".1"

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
OID_LLDPREMMANADDRTABLE = "1.0.8802.1.1.2.1.4.2.1"  # lldpRemManAddrTable
OID_LLDPREMMANADDR = OID_LLDPREMMANADDRTABLE + ".3"  # lldpRemManAddr

# CISCO-CDP-MIB
OID_CDPCACHETABLE = "1.3.6.1.4.1.9.9.23.1.2.1.1"
OID_CDPCACHEDEVICEID = OID_CDPCACHETABLE + ".6"
OID_CDPCACHEDEVICEPORT = OID_CDPCACHETABLE + ".7"
OID_CDPCACHEPLATFORM = OID_CDPCACHETABLE + ".8"
OID_CDPCACHEADDRESS = OID_CDPCACHETABLE + ".9"

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


def lldp_remote_ip_from_index(index):
    """Parse a remote management address out of an lldpRemManAddr index.

    Index format: ``<timeMark>.<localPortNum>.<lldpRemIndex>.<addrSubtype>.<addr octets>``
    where addrSubtype 1 is IPv4 and 2 is IPv6. IPv6 octet indexes are not a
    valid textual IPv6 form, so only IPv4 is parsed here.

    Returns:
        str IPv4 address, or "" if none can be parsed.
    """
    if not index:
        return ""
    parts = index.split(".")
    if len(parts) < 5 or parts[3] != "1":
        return ""
    address = ".".join(parts[4:])
    try:
        return str(IPAddress(address))
    except Exception:
        return ""


def cdp_address_to_ip(value):
    """Convert a CDP cdpCacheAddress OctetString to an IPv4 string.

    The value is an OctetString rendered by pysnmp as colon-separated hex
    (e.g. ``"c0:a8:01:01"``). Returns "" when it is not a 4-octet IPv4.
    """
    if not value:
        return ""
    hexdigits = value.replace(":", "").replace("-", "").replace(".", "")
    if len(hexdigits) != 8:
        return ""
    try:
        octets = [int(hexdigits[i : i + 2], 16) for i in range(0, 8, 2)]
    except ValueError:
        return ""
    return ".".join(str(octet) for octet in octets)


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


def collect_ip_addresses(ip_str, config, max_rows=1000, context_name=""):
    """Collect IP addresses from IP-MIB.

    Walks both the RFC 1213 ``ipAddrTable`` and the IP-MIB
    ``ipAddressTable`` (which supports IPv4 and IPv6). Prefix lengths are
    resolved from ``ipAddressPrefixTable`` via the ``ipAddressPrefix``
    pointer, falling back to ``ipAdEntNetMask`` and finally to a host
    route (``/32`` / ``/128``), so rows are never silently dropped.

    When ``context_name`` is set (SNMPv3), the walk is performed in that
    SNMP context (typically a VRF) and every returned row is tagged with
    ``vrf=context_name``.

    Returns:
        list of dicts: {address, prefix_length, if_index, vrf}
    """
    auth = build_snmp_auth(config)
    timeout = config.get("snmp_timeout", 3)
    retries = config.get("snmp_retries", 2)
    if context_name:
        auth["context"] = context_name

    addresses = []
    seen = set()

    def _append(address, addr_type, prefix_length, if_index):
        if not address:
            return
        if prefix_length is None:
            prefix_length = 32 if addr_type == 1 else 128
        key = (address, str(if_index), context_name)
        if key in seen:
            return
        seen.add(key)
        addresses.append(
            {
                "address": address,
                "prefix_length": prefix_length,
                "if_index": str(if_index),
                "vrf": context_name or None,
            }
        )

    # IP-MIB ipAddressTable (index: ifIndex.ipAddressType.<addr octets>)
    ifindex_map = walk_columns(ip_str, OID_IPADDRESSIFINDEX, auth, timeout, retries, max_rows)
    if ifindex_map:
        prefix_ptr_map = walk_columns(ip_str, OID_IPADDRESSPREFIX, auth, timeout, retries, max_rows)
        prefix_length_map = walk_columns(ip_str, OID_IPADDRESSPREFIXLENGTH, auth, timeout, retries, max_rows)
        for suffix, if_index in ifindex_map.items():
            parsed_if, addr_type, address = _parse_ipaddress_table_index(suffix)
            prefix_length = None
            pointer = prefix_ptr_map.get(suffix)
            if pointer:
                prefix_length = _prefix_length_from_pointer(pointer, prefix_length_map)
            _append(address, addr_type, prefix_length, if_index or parsed_if)

    # RFC 1213 ipAddrTable (index = IP address) fills any gaps the
    # ipAddressTable did not report.
    netmask_map = walk_columns(ip_str, OID_IPADENTNETMASK, auth, timeout, retries, max_rows)
    for addr, if_index in walk_columns(ip_str, OID_IPADENTIFINDEX, auth, timeout, retries, max_rows).items():
        prefix_length = _netmask_to_prefix(netmask_map.get(addr, ""))
        _append(addr, 1, prefix_length, if_index)

    return addresses


def _parse_ipaddress_table_index(suffix):
    """Split an ipAddressTable index suffix into (if_index, addr_type, address).

    The ipAddressTable index is ``ipAddressIfIndex.ipAddressType.<addr
    octets>``, where IPv4 addresses use 4 dotted octets and IPv6
    addresses use 16. Returns ``(None, None, None)`` on failure.
    """
    parts = str(suffix).split(".")
    if len(parts) < 3:
        return None, None, None
    try:
        if_index = parts[0]
        addr_type = int(parts[1])
    except (TypeError, ValueError):
        return None, None, None
    octets = parts[2:]
    if addr_type == 1 and len(octets) == 4:
        return if_index, addr_type, ".".join(octets)
    if addr_type == 2 and len(octets) == 16:
        try:
            ipv6 = IPAddress(int.from_bytes(bytes(int(o) for o in octets), "big"))
        except (TypeError, ValueError):
            return None, None, None
        return if_index, addr_type, str(ipv6)
    return None, None, None


def _prefix_length_from_pointer(pointer, prefix_length_map):
    """Resolve a prefix length for an ``ipAddressPrefix`` pointer OID.

    The pointer value references an entry in ``ipAddressPrefixTable``;
    the matching ``ipAddressPrefixLength`` value is looked up by the
    table index extracted from the pointer. Returns None on failure.
    """
    if not pointer:
        return None
    value = str(pointer)
    suffix = ""
    for base in ("1.3.6.1.2.1.4.32.1.4", OID_IPADDRESSPREFIXTABLE):
        if value.startswith(base + "."):
            suffix = value[len(base) + 1 :]
            break
    if not suffix:
        return None
    # When the table base (without a column) was stripped, drop the
    # column component (ipAddressPrefixLength is column .4).
    if value.startswith(OID_IPADDRESSPREFIXTABLE + ".") and "." in suffix:
        suffix = suffix.split(".", 1)[1]
    if suffix not in prefix_length_map:
        return None
    try:
        return int(prefix_length_map[suffix])
    except (TypeError, ValueError):
        return None


def collect_vrfs(ip_str, config, max_rows=1000):
    """Collect VRF (virtual routing and forwarding) instances.

    Walks the standard MPLS-VPN-MIB (RFC 4382) plus both revisions of the
    Cisco CISCO-VRF-MIB (classic 1.3.6.1.4.1.9.9.276 and the newer
    1.3.6.1.4.1.9.9.711), merging results by VRF name. Interface
    membership is gathered from ``mplsVpnInterfaceConfTable`` and the
    Cisco ``cvVrfInterfaceTable``.

    Returns:
        list of dicts: {name, rd, description, interfaces: [if_index...]}
    """
    auth = build_snmp_auth(config)
    timeout = config.get("snmp_timeout", 3)
    retries = config.get("snmp_retries", 2)

    vrfs = {}

    def _add_vrf(name, rd="", description="", interfaces=None):
        if not name:
            return
        entry = vrfs.setdefault(name, {"name": name, "rd": "", "description": "", "interfaces": []})
        if rd and not entry["rd"]:
            entry["rd"] = rd
        if description and not entry["description"]:
            entry["description"] = description
        for if_index in interfaces or []:
            if if_index not in entry["interfaces"]:
                entry["interfaces"].append(if_index)

    # MPLS-VPN-MIB mplsVpnVrfTable (index and value = VRF name)
    name_map = walk_columns(ip_str, OID_MPLSVPNVRFNAME, auth, timeout, retries, max_rows)
    if name_map:
        desc_map = walk_columns(ip_str, OID_MPLSVPNVRFDESCRIPTION, auth, timeout, retries, max_rows)
        rd_map = walk_columns(ip_str, OID_MPLSVPNVRFRD, auth, timeout, retries, max_rows)
        for key, name in name_map.items():
            _add_vrf(name, rd=_format_rd(rd_map.get(key, "")), description=desc_map.get(key, ""))
        # Interface membership: mplsVpnInterfaceConfTable (index vrfName.ifIndex)
        for key, value in walk_columns(
            ip_str, OID_MPLSVPNINTERFACECONFINDEX, auth, timeout, retries, max_rows
        ).items():
            vrf_name = _decode_ascii_index(key, drop_last=True)
            if vrf_name:
                _add_vrf(vrf_name, interfaces=[value])

    # Cisco CISCO-VRF-MIB classic (cvrfVrfTable, index = VRF name)
    classic_name_map = walk_columns(ip_str, OID_CVRFVRFNAME, auth, timeout, retries, max_rows)
    for key, name in classic_name_map.items():
        _add_vrf(name)

    # Cisco CISCO-VRF-MIB v2 (cvVrfTable, index = cvVrfIndex)
    vrf_index_to_name = {}
    for key, name in walk_columns(ip_str, OID_CVVRFNAME, auth, timeout, retries, max_rows).items():
        _add_vrf(name)
        vrf_index_to_name[key] = name
    # v2 interface table: index cvVrfIndex.ifIndex, value = ifIndex
    for key, value in walk_columns(
        ip_str, OID_CVVRFINTERFACEIFINDEX, auth, timeout, retries, max_rows
    ).items():
        cvrf_index = str(key).split(".", 1)[0]
        name = vrf_index_to_name.get(cvrf_index)
        if name:
            _add_vrf(name, interfaces=[value])

    return list(vrfs.values())


def _decode_ascii_index(suffix, drop_last=False):
    """Decode an OctetString table index from its dotted byte codes.

    SNMP OctetString indexes are rendered as one sub-identifier per byte;
    this converts them back to text. When ``drop_last`` is set, a
    trailing integer component (e.g. an ifIndex in a ``(VRF, ifIndex)``
    index) is discarded first. Returns "" on failure.
    """
    parts = str(suffix).split(".")
    if drop_last and parts:
        parts = parts[:-1]
    if not parts:
        return ""
    try:
        return "".join(chr(int(part)) for part in parts)
    except (TypeError, ValueError):
        return ""


def _format_rd(raw):
    """Format an MPLS-VPN-MIB route distinguisher as a readable string.

    Accepts the RFC 4364 octet encodings (8-byte, 4-byte or 3-byte) or an
    already-formatted ``ASN:NN`` string. Returns "" for empty input.
    """
    if not raw:
        return ""
    raw = str(raw)
    if ":" in raw and all(ch in "0123456789:" for ch in raw):
        return raw[:64]
    try:
        b = bytes(ord(ch) & 0xFF for ch in raw)
    except Exception:
        return ""
    if len(b) == 8:
        rd_type = (b[0] << 8) | b[1]
        if rd_type == 0:
            number = (b[2] << 8) | b[3]
            ipv4 = ".".join(str(o) for o in b[4:8])
            return f"{number}:{ipv4}"
        if rd_type == 1:
            asn = (b[2] << 8) | b[3]
            return f"{asn}:{int.from_bytes(b[4:8], 'big')}"
        if rd_type == 2:
            return f"{int.from_bytes(b[2:6], 'big')}:{int.from_bytes(b[6:8], 'big')}"
        return f"0x{b.hex()}"
    if len(b) == 4:
        return f"{(b[0] << 8) | b[1]}:{(b[2] << 8) | b[3]}"
    if len(b) == 3:
        return f"{b[0]}:{int.from_bytes(b[1:3], 'big')}"
    return f"0x{b.hex()}"


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

    # Remote management addresses; the man-addr index prefixes the lldpRem
    # index (<timeMark>.<localPortNum>.<lldpRemIndex>) with an address subtype
    # and the address octets.
    manaddr_map = walk_columns(ip_str, OID_LLDPREMMANADDR, auth, timeout, retries, max_rows)
    remote_ip_by_key = {}
    for index, _value in manaddr_map.items():
        parts = index.split(".")
        if len(parts) < 5:
            continue
        address = lldp_remote_ip_from_index(index)
        if address:
            remote_ip_by_key.setdefault(".".join(parts[:3]), address)

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
                "remote_ip": remote_ip_by_key.get(index, ""),
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

    # CDP neighbor addresses; the index is <ifIndex>.<cdpCacheDeviceIndex>.<addrType>
    # where addrType 3 is an IPv4 address whose value is a 4-octet OctetString.
    addr_map = walk_columns(ip_str, OID_CDPCACHEADDRESS, auth, timeout, retries, max_rows)
    remote_ip_by_key = {}
    for index, value in addr_map.items():
        parts = index.split(".")
        if len(parts) < 3 or parts[2] != "3":
            continue
        address = cdp_address_to_ip(value)
        if address:
            remote_ip_by_key.setdefault(".".join(parts[:2]), address)

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
                "remote_ip": remote_ip_by_key.get(index, ""),
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
        dict with keys: system, interfaces, ip_addresses, vrfs, arp_table,
        physical, neighbors, vlans
    """
    max_rows = config.get("max_walk_oids", 1000)
    include_neighbors = config.get("include_neighbors", True)
    include_vlans = config.get("include_vlans", True)

    tables = {
        "system": {},
        "interfaces": [],
        "ip_addresses": [],
        "vrfs": [],
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
        tables["vrfs"] = collect_vrfs(ip_str, config, max_rows=max_rows)
    except Exception as exc:
        logger.debug("SNMP VRF collection failed for %s: %s", ip_str, exc)

    # With SNMPv3, walk the IP tables once per VRF name (used as the SNMP
    # context) so addresses living inside VRFs are captured and tagged.
    if tables["vrfs"] and str(config.get("snmp_version", "2c")).strip().lower() == "3":
        for vrf in tables["vrfs"]:
            vrf_name = vrf.get("name")
            if not vrf_name:
                continue
            try:
                context_ips = collect_ip_addresses(
                    ip_str, config, max_rows=max_rows, context_name=vrf_name
                )
            except Exception as exc:
                logger.debug("SNMP context IP collection failed for %s vrf %s: %s", ip_str, vrf_name, exc)
                continue
            for row in context_ips:
                if row.get("vrf"):
                    row["vrf"] = vrf_name
            tables["ip_addresses"].extend(context_ips)

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
