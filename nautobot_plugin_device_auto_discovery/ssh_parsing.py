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
