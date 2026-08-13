"""SNMP OID to Platform mapping table.

Maps SNMP sysObjectID prefixes to Nautobot Platform names,
manufacturer names, and platform network driver strings.
"""

# Format: (oid_prefix, platform_name, manufacturer_name, network_driver)
SNMP_OID_MAPPING = [
    # Cisco
    ("1.3.6.1.4.1.9.1.675", "Cisco IOS-XE", "Cisco", "ios"),
    ("1.3.6.1.4.1.9.1.657", "Cisco IOSv", "Cisco", "ios"),
    ("1.3.6.1.4.1.9.1.644", "Cisco IOS-XR", "Cisco", "ios_xr"),
    ("1.3.6.1.4.1.9.1.649", "Cisco NX-OS", "Cisco", "nxos"),
    ("1.3.6.1.4.1.9.1.129", "Cisco IOS", "Cisco", "ios"),
    ("1.3.6.1.4.1.9.1.746", "Cisco SD-WAN vEdge", "Cisco", "ios"),
    # Juniper
    ("1.3.6.1.4.1.2636.1.1.1", "Juniper Junos", "Juniper Networks", "junos"),
    # Arista
    ("1.3.6.1.4.1.30065.3.1", "Arista EOS", "Arista Networks", "eos"),
    # HP / HPE
    ("1.3.6.1.4.1.11.2.3.7.11", "HPE Comware", "HPE", "hp_comware"),
    ("1.3.6.1.4.1.11.2.9.1.1", "HPE ProCurve", "HPE", "hp_procurve"),
    # Nokia / Alcatel-Lucent
    ("1.3.6.1.4.1.2011.5.2", "Nokia SR OS", "Nokia", "nokia_sros"),
    ("1.3.6.1.4.1.2011.6.1", "Nokia SR Linux", "Nokia", "nokia_srl"),
    # F5
    ("1.3.6.1.4.1.3021.7", "F5 TMOS", "F5 Networks", "bigip"),
    # Palo Alto
    ("1.3.6.1.4.1.25461.2", "Palo Alto PAN-OS", "Palo Alto Networks", "panos"),
    # Fortinet
    ("1.3.6.1.4.1.12356.101", "Fortinet FortiOS", "Fortinet", "fortios"),
    # Ubiquiti
    ("1.3.6.1.4.1.41112.1.3", "Ubiquiti EdgeOS", "Ubiquiti", "edgeos"),
    ("1.3.6.1.4.1.41112.1.5", "Ubiquiti EdgeMAX", "Ubiquiti", "edgeos"),
    # Linux hosts
    ("1.3.6.1.4.1.8072.3.2.10", "Linux", "Linux", "linux"),
]


def lookup_platform_from_oid(sys_object_id):
    """Look up platform info from an SNMP sysObjectID.

    Returns:
        dict with keys: platform_name, manufacturer_name, network_driver,
        or None if no match found.
    """
    if not sys_object_id:
        return None
    sys_object_id = str(sys_object_id).strip()
    for oid_prefix, platform_name, manufacturer_name, network_driver in SNMP_OID_MAPPING:
        if sys_object_id.startswith(oid_prefix):
            return {
                "platform_name": platform_name,
                "manufacturer_name": manufacturer_name,
                "network_driver": network_driver,
            }
    return None


# Map numeric IANA ifType (RFC 2863) values to Nautobot dcim.InterfaceTypeChoices.
IF_TYPE_MAPPING = {
    6: "ethernet-csmacd",
    24: "softwareLoopback",
    53: "propVirtual",
    131: "tunnel",
    135: "l2vlan",
    136: "l3ipvlan",
    161: "ieee8023adLag",
}


def lookup_interface_type(if_type_code):
    """Map an IANA ifType code to a Nautobot InterfaceTypeChoices value.

    Returns:
        str type value, or "other" if unknown.
    """
    try:
        return IF_TYPE_MAPPING.get(int(if_type_code), "other")
    except (TypeError, ValueError):
        return "other"
