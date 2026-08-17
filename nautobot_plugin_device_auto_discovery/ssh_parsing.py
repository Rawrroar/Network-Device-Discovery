"""Pure parsing helpers for SSH-collected data commands (no Nautobot deps).

These helpers convert raw CLI output from ``data_commands`` into
VRF and IP address records. They intentionally import nothing but the
standard library so they can be unit-tested without a Django runtime.
"""

import re


def _looks_like_rd(value):
    """True if a token plausibly parses as a Route Distinguisher (contains a colon)."""
    return ":" in value


def _data_output(command_outputs, key):
    """Return the captured output for a command, or '' if invalid/absent."""
    text = command_outputs.get(key) or ""
    if not text:
        return ""
    lowered = text.lower()
    if "invalid" in lowered or "% unknown command" in lowered or "not found" in lowered:
        return ""
    return text


def parse_ssh_vrfs(command_outputs, vendor):
    """Extract VRF records from SSH data-command output.

    Supports Cisco (``show ip vrf``), Juniper (``show routing-instances``),
    Arista (``show vrf``), HPE/Comware (``display ip vpn-instance``) and
    Nokia SR OS (``show router instance``) output formats.

    Returns:
        list of dicts {"name": str, "rd": str or ""}.
    """
    vrfs = []
    seen = set()
    vendor = (vendor or "").lower()

    def add(name, rd=""):
        lowered = name.lower()
        if name and name not in seen and not lowered.startswith(("default", "global", "master", "_")):
            seen.add(name)
            vrfs.append({"name": name, "rd": rd or ""})

    cisco = _data_output(command_outputs, "show ip vrf")
    if cisco:
        for line in cisco.splitlines():
            parts = line.split()
            if len(parts) >= 3 and _looks_like_rd(parts[1]):
                add(parts[0], parts[1])

    junos = _data_output(command_outputs, "show routing-instances")
    if junos:
        for line in junos.splitlines():
            parts = line.split()
            if len(parts) >= 1 and parts[0].lower() not in ("instance", "type"):
                add(parts[0])

    arista = _data_output(command_outputs, "show vrf")
    if arista:
        for line in arista.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].lower() not in ("vrf", "name", "vrfs"):
                if _looks_like_rd(parts[1]) or parts[1].lower() in ("ipv4", "ipv6", "ipv4,", "ipv6,"):
                    add(parts[0], parts[1] if _looks_like_rd(parts[1]) else "")

    comware = _data_output(command_outputs, "display ip vpn-instance")
    if comware:
        for line in comware.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].lower() not in ("vpn-instance", "name", "id"):
                if _looks_like_rd(parts[1]):
                    add(parts[0], parts[1])

    nokia = _data_output(command_outputs, "show router instance")
    if nokia:
        for line in nokia.splitlines():
            parts = line.split()
            if len(parts) >= 1 and parts[0].lower() not in ("instance", "vrf", "name"):
                add(parts[0])

    return vrfs


def parse_ssh_ip_addresses(command_outputs, vendor):
    """Extract IP address rows from SSH data-command output.

    Returns:
        list of dicts {"address", "prefix_length", "if_index", "vrf"}.
        ``if_index`` is the interface name; ``vrf`` is None for the global
        routing table.
    """
    rows = []
    vendor = (vendor or "").lower()

    # Cisco "show ip vrf": build interface -> VRF map for joining.
    vrf_by_interface = {}
    cisco_vrf = _data_output(command_outputs, "show ip vrf")
    if cisco_vrf:
        for line in cisco_vrf.splitlines():
            parts = line.split()
            if len(parts) >= 3 and _looks_like_rd(parts[1]):
                for iface in parts[2:]:
                    vrf_by_interface[iface.rstrip(",")] = parts[0]

    def add(address, prefix, if_index, vrf=None):
        if not address or not if_index:
            return
        if vrf is None and if_index in vrf_by_interface:
            vrf = vrf_by_interface[if_index]
        rows.append(
            {
                "address": address,
                "prefix_length": int(prefix),
                "if_index": if_index,
                "vrf": vrf or None,
            }
        )

    if "cisco" in vendor:
        text = _data_output(command_outputs, "show ip interface brief")
        for line in text.splitlines():
            match = re.match(
                r"^\s*(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s*$",
                line,
            )
            if match:
                add(match.group(2), 32, match.group(1))
        text6 = _data_output(command_outputs, "show ipv6 interface brief")
        for line in text6.splitlines():
            match = re.match(r"^\s*(\S+)\s+\S+\s+\S+\s+([0-9a-fA-F:]+)(?:/(\d+))?\s*$", line)
            if match:
                add(match.group(2), match.group(3) or 64, match.group(1))
    elif "juniper" in vendor:
        text = _data_output(command_outputs, "show interfaces terse")
        current_if = ""
        for line in text.splitlines():
            match = re.match(r"^\s*(\S+)\s+\S+\s+\S+\s+inet(6)?\s+([0-9a-fA-F:.]+)/(\d+)\s*$", line)
            if match:
                current_if = match.group(1)
                add(match.group(3), match.group(4), current_if)
    elif "arista" in vendor:
        text = _data_output(command_outputs, "show ip interface brief")
        for line in text.splitlines():
            match = re.match(
                r"^\s*(\S+)\s+([0-9a-fA-F:.]+)/(\d+)\s+\S+\s+\S+\s*(\S*)\s*$",
                line,
            )
            if match:
                add(match.group(2), match.group(3), match.group(1), match.group(4) or None)
    elif "hp" in vendor or "hpe" in vendor or "comware" in vendor:
        text = _data_output(command_outputs, "display ip interface")
        current_if = ""
        for line in text.splitlines():
            iface = re.match(r"^\s*(\S+)\s+current state", line)
            if iface:
                current_if = iface.group(1)
            ipaddr = re.match(r"Internet Address is\s+([0-9a-fA-F:.]+)/(\d+)", line)
            if ipaddr and current_if:
                add(ipaddr.group(1), ipaddr.group(2), current_if)
    elif "nokia" in vendor:
        text = _data_output(command_outputs, "show router interface")
        for line in text.splitlines():
            match = re.match(r"^\s*(\S+)\s+\S+\s+([0-9a-fA-F:.]+)/(\d+)", line)
            if match:
                add(match.group(2), match.group(3), match.group(1))
    else:
        # Generic / Linux "ip addr" or Cisco-style interface brief.
        text = _data_output(command_outputs, "ip addr") or _data_output(
            command_outputs, "show ip interface brief"
        )
        current_if = ""
        for line in text.splitlines():
            iface = re.match(r"^\s*\d+:\s*([^:@\s]+)", line)
            if iface:
                current_if = iface.group(1)
            inet = re.search(r"\binet6?\s+([0-9a-fA-F:.]+)/(\d+)", line)
            if inet and current_if:
                add(inet.group(1), inet.group(2), current_if)
            brief = re.match(
                r"^\s*(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s*$",
                line,
            )
            if brief and not current_if:
                add(brief.group(2), 32, brief.group(1))

    return rows


def parse_ssh_routes(command_outputs, vendor):
    """Extract IP route/prefix records from SSH route-table command output.

    Supports Cisco (``show ip route [vrf <name>]``),
    Juniper (``show route [table <name>.inet.0]``),
    Arista (``show ip route [vrf <name>]``),
    HPE Comware (``display ip routing-table [vpn-instance <name>]``),
    Nokia SR OS (``show router [<vprn-id>] route-table``),
    Fortinet (``get router info routing-table all``),
    and generic Linux (``ip route``).

    Route commands in the profile may use a ``{vrf}`` placeholder that is
    filled with the VRF name at runtime; the parser uses the command key
    to infer VRF association.

    Returns:
        list of dicts: {dest, prefix_length, next_hop, protocol, interface, vrf}
    """
    routes = []
    seen = set()
    vendor = (vendor or "").lower()

    def _vrf_from_key(cmd_key):
        """Infer VRF name from the command key if it contains a VRF specifier."""
        key_lower = cmd_key.lower()
        for marker in ("vrf ", "vpn-instance ", "table ", "router "):
            idx = key_lower.find(marker)
            if idx >= 0:
                remainder = cmd_key[idx + len(marker) :].strip()
                if remainder:
                    return remainder.split()[0].rstrip("]")
        return None

    def add(dest, prefix_length, next_hop="", protocol="", interface="", vrf=None):
        prefix_length = int(prefix_length)
        key = (dest, prefix_length, next_hop, vrf or "")
        if key in seen:
            return
        seen.add(key)
        routes.append(
            {
                "dest": dest,
                "prefix_length": prefix_length,
                "next_hop": next_hop,
                "protocol": protocol,
                "interface": interface,
                "vrf": vrf,
            }
        )

    # Cisco IOS/IOS-XE: "show ip route [vrf <name>]"
    for cmd_key, text in command_outputs.items():
        if not text or "invalid" in text.lower():
            continue
        cmd_lower = cmd_key.lower()
        if cmd_lower.startswith("show ip route"):
            vrf = _vrf_from_key(cmd_key)
            _parse_cisco_routes(text, add, vrf=vrf)

    # Juniper: "show route [table <name>.inet.0]"
    for cmd_key, text in command_outputs.items():
        if not text or "invalid" in text.lower():
            continue
        cmd_lower = cmd_key.lower()
        if cmd_lower.startswith("show route") and "interface" not in cmd_lower:
            vrf = _vrf_from_key(cmd_key)
            _parse_juniper_routes(text, add, vrf=vrf)

    # HPE Comware: "display ip routing-table [vpn-instance <name>]"
    for cmd_key, text in command_outputs.items():
        if not text or "invalid" in text.lower():
            continue
        cmd_lower = cmd_key.lower()
        if cmd_lower.startswith("display ip routing-table"):
            vrf = _vrf_from_key(cmd_key)
            _parse_comware_routes(text, add, vrf=vrf)

    # Nokia SR OS: "show router [<vprn-id>] route-table"
    for cmd_key, text in command_outputs.items():
        if not text or "invalid" in text.lower():
            continue
        cmd_lower = cmd_key.lower()
        if cmd_lower.startswith("show router") and "route-table" in cmd_lower:
            vrf = _vrf_from_key(cmd_key)
            _parse_nokia_routes(text, add, vrf=vrf)

    # Fortinet: "get router info routing-table all"
    for cmd_key, text in command_outputs.items():
        if not text or "invalid" in text.lower():
            continue
        if "routing-table" in cmd_key.lower():
            _parse_fortinet_routes(text, add)

    # Generic / Linux "ip route"
    for cmd_key, text in command_outputs.items():
        if not text or "invalid" in text.lower():
            continue
        if cmd_key.lower() == "ip route":
            _parse_linux_routes(text, add)

    return routes


def _parse_cisco_routes(text, add, vrf=None):
    """Parse Cisco 'show ip route [vrf <name>]' output.

    Route codes: C=connected, L=local, S=static, O=OSPF, B=BGP, etc.
    Format: ``<code>  <prefix>/<len> [<AD/metric>] via <nhop>, <age>, <iface>``
    Connected: ``<code>  <prefix>/<len> is directly connected, <iface>``
    """
    proto_map = {
        "C": "connected",
        "L": "local",
        "S": "static",
        "R": "rip",
        "O": "ospf",
        "IA": "ospf",
        "OE1": "ospf",
        "OE2": "ospf",
        "B": "bgp",
        "D": "eigrp",
        "EX": "eigrp",
        "i": "isis",
        "N1": "isis",
        "N2": "isis",
    }
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("Codes:", "Gateway", "Known", "VRF:")):
            continue
        # Match: CODE  prefix/len [AD/metric] via nhop, age, iface
        # or:   CODE  prefix/len is directly connected, iface
        m = re.match(
            r"^\s*(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3}/\d+)\s+(?:\[.*?\]\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})[^,]*,?\s*(\S*)|is directly connected,\s*(\S+))",
            stripped,
        )
        if m:
            code = m.group(1).rstrip("*")
            prefix = m.group(2)
            next_hop = m.group(3) or ""
            iface = m.group(5) or m.group(4) or ""
            proto = proto_map.get(code, code.lower())
            dest, pfx = prefix.split("/")
            add(dest, pfx, next_hop=next_hop, protocol=proto, interface=iface, vrf=vrf)
            continue
        # Simpler match without AD/metric bracket
        m2 = re.match(
            r"^\s*(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3}/\d+)\s+via\s+(\S+)",
            stripped,
        )
        if m2:
            code = m2.group(1).rstrip("*")
            prefix = m2.group(2)
            next_hop = m2.group(3)
            proto = proto_map.get(code, code.lower())
            dest, pfx = prefix.split("/")
            add(dest, pfx, next_hop=next_hop, protocol=proto, vrf=vrf)


def _parse_juniper_routes(text, add, vrf=None):
    """Parse Juniper 'show route' output.

    Format: ``<prefix>  *[<Protocol>/<Pref>] <age>`` then next line ``> to <nhop> via <iface>``
    """
    proto_map = {
        "direct": "connected",
        "local": "local",
        "static": "static",
        "ospf": "ospf",
        "bgp": "bgp",
        "isis": "isis",
        "rip": "rip",
    }
    lines = text.splitlines()
    i = 0
    current_prefix = None
    current_proto = ""
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line:
            continue
        # Destination line: prefix  *[Protocol/Pref] age
        m = re.match(
            r"^(\d{1,3}(?:\.\d{1,3}){3}/\d+)\s+\*\[([^\]/]+)/\d+\]",
            line,
        )
        if not m:
            m = re.match(
                r"^([0-9a-fA-F:.]+/\d+)\s+\*\[([^\]/]+)/\d+\]",
                line,
            )
        if m:
            current_prefix = m.group(1)
            proto_raw = m.group(2).lower()
            current_proto = proto_map.get(proto_raw, proto_raw)
            # Check for next-hop on same line
            dest, pfx = current_prefix.split("/")
            nhop_match = re.search(r">\s*to\s+(\S+)", line)
            if nhop_match:
                add(dest, pfx, next_hop=nhop_match.group(1), protocol=current_proto, vrf=vrf)
                current_prefix = None
            continue
        # Next-hop line: > to <nhop> via <iface> or > via <iface> (direct)
        if current_prefix:
            nhop_match = re.match(r">\s*to\s+(\S+)(?:\s+via\s+(\S+))?", line)
            if nhop_match:
                dest, pfx = current_prefix.split("/")
                add(dest, pfx, next_hop=nhop_match.group(1), protocol=current_proto, interface=nhop_match.group(2) or "", vrf=vrf)
                current_prefix = None
                continue
            # Directly connected: > via <iface> (no "to" next-hop)
            via_match = re.match(r">\s*via\s+(\S+)", line)
            if via_match:
                dest, pfx = current_prefix.split("/")
                add(dest, pfx, next_hop="", protocol=current_proto, interface=via_match.group(1), vrf=vrf)
                current_prefix = None


def _parse_comware_routes(text, add, vrf=None):
    """Parse HPE Comware 'display ip routing-table' output.

    Tabular format with header line ``Destination/Mask   Proto   Pre   Cost    NextHop         Interface``.
    """
    for line in text.splitlines():
        m = re.match(
            r"^\s*(\d{1,3}(?:\.\d{1,3}){3}/\d+)\s+(\S+)\s+\d+\s+\d+\s+(\S+)\s+(\S+)",
            line,
        )
        if m:
            dest, pfx = m.group(1).split("/")
            add(dest, pfx, next_hop=m.group(3), protocol=m.group(2).lower(), interface=m.group(4), vrf=vrf)


def _parse_nokia_routes(text, add, vrf=None):
    """Parse Nokia SR OS 'show router route-table' output.

    Table delimited by dashed lines. Columns: Dest Prefix, Type, Proto, Age, Pref, NextHop, Metric.
    """
    in_table = False
    for line in text.splitlines():
        if line.startswith("---"):
            in_table = not in_table
            continue
        if not in_table:
            continue
        m = re.match(
            r"^\s*(\d{1,3}(?:\.\d{1,3}){3}/\d+)\s+\S+\s+(\S+)\s+\S+\s+\d+\s+(\S+)",
            line,
        )
        if m:
            dest, pfx = m.group(1).split("/")
            add(dest, pfx, next_hop=m.group(3), protocol=m.group(2).lower(), vrf=vrf)


def _parse_fortinet_routes(text, add):
    """Parse Fortinet 'get router info routing-table all' output.

    Lines like: ``S*   0.0.0.0/0    [10/0] via 10.0.0.1, port1`` or
    ``C       10.0.0.0/24    is directly connected, port1``.
    """
    for line in text.splitlines():
        stripped = line.strip()
        m = re.match(
            r"^\s*\S+\s+(\d{1,3}(?:\.\d{1,3}){3}/\d+)\s+\[.*?\]\s+via\s+(\S+),\s*(\S+)",
            stripped,
        )
        if m:
            dest, pfx = m.group(1).split("/")
            add(dest, pfx, next_hop=m.group(2), protocol="static", interface=m.group(3))
            continue
        m2 = re.match(
            r"^\s*\S+\s+(\d{1,3}(?:\.\d{1,3}){3}/\d+)\s+is directly connected,\s*(\S+)",
            stripped,
        )
        if m2:
            dest, pfx = m2.group(1).split("/")
            add(dest, pfx, protocol="connected", interface=m2.group(2))


def _parse_linux_routes(text, add):
    """Parse Linux 'ip route' output.

    Format: ``default via 10.0.0.1 dev eth0`` or ``10.0.0.0/24 dev eth0 proto kernel ...``.
    """
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("default"):
            if stripped.startswith("default"):
                m = re.match(r"default\s+via\s+(\S+)\s+dev\s+(\S+)", stripped)
                if m:
                    add("0.0.0.0", "0", next_hop=m.group(1), protocol="static", interface=m.group(2))
            continue
        m = re.match(
            r"(\d{1,3}(?:\.\d{1,3}){3}/\d+)\s+(?:via\s+(\S+)\s+)?dev\s+(\S+)",
            stripped,
        )
        if m:
            dest, pfx = m.group(1).split("/")
            add(dest, pfx, next_hop=m.group(2) or "", protocol="connected", interface=m.group(3))
