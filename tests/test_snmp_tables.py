"""Tests for the SNMP table walking/collection module."""

from unittest import TestCase
from unittest.mock import patch

from nautobot_plugin_device_auto_discovery import snmp_tables
from nautobot_plugin_device_auto_discovery.mappings import lookup_interface_type
from nautobot_plugin_device_auto_discovery.snmp_tables import (
    _auth_data,
    _decode_ascii_index,
    _format_rd,
    _parse_ipaddress_table_index,
    build_snmp_auth,
    collect_arp_table,
    collect_cdp_neighbors,
    collect_interfaces,
    collect_ip_addresses,
    collect_lldp_neighbors,
    collect_physical,
    collect_system,
    collect_vlans,
    collect_vrfs,
    discover_snmp_tables,
    find_chassis_model,
    find_chassis_serial,
    mac_from_bytes,
)

CONFIG = {"snmp_community": "public", "snmp_timeout": 1, "snmp_retries": 1}


class MACFormattingTests(TestCase):
    def test_mac_parsed_from_colon_form(self):
        self.assertEqual(mac_from_bytes("00:11:22:33:44:55"), "00:11:22:33:44:55")

    def test_mac_parsed_from_hex_form(self):
        self.assertEqual(mac_from_bytes("001122334455"), "00:11:22:33:44:55")

    def test_all_zero_mac_rejected(self):
        self.assertIsNone(mac_from_bytes("00:00:00:00:00:00"))

    def test_empty_mac_rejected(self):
        self.assertIsNone(mac_from_bytes(""))
        self.assertIsNone(mac_from_bytes(None))

    def test_invalid_mac_rejected(self):
        self.assertIsNone(mac_from_bytes("not-a-mac"))


class InterfaceTypeMappingTests(TestCase):
    def test_ethernet_without_speed(self):
        self.assertEqual(lookup_interface_type(6), "other")

    def test_ethernet_refined_by_speed(self):
        self.assertEqual(lookup_interface_type(6, 100000), "100base-tx")
        self.assertEqual(lookup_interface_type(6, 1000000), "1000base-t")
        self.assertEqual(lookup_interface_type(6, 10000000), "10gbase-t")

    def test_lag(self):
        self.assertEqual(lookup_interface_type(161), "lag")

    def test_loopback(self):
        self.assertEqual(lookup_interface_type(24), "virtual")

    def test_unknown_type_falls_back(self):
        self.assertEqual(lookup_interface_type(999), "other")
        self.assertEqual(lookup_interface_type("nonsense"), "other")
        self.assertEqual(lookup_interface_type(None), "other")


def _column_map(*mappings):
    """Build the OID -> {index: value} table used to fake walk_columns."""
    return {oid: data for oid, data in mappings}


class CollectInterfacesTests(TestCase):
    def test_merges_if_table_columns(self):
        columns = _column_map(
            (snmp_tables.OID_IFDESCR, {"1": "GigabitEthernet0/0/1", "2": "GigabitEthernet0/0/2"}),
            (snmp_tables.OID_IFTYPE, {"1": "6", "2": "161"}),
            (snmp_tables.OID_IFMTU, {"1": "1500", "2": "1500"}),
            (snmp_tables.OID_IFSPEED, {"1": "1000000000", "2": "10000000"}),
            (snmp_tables.OID_IFPHYSADDRESS, {"1": "00:11:22:33:44:55", "2": "00:0a:0b:0c:0d:0e"}),
            (snmp_tables.OID_IFADMINSTATUS, {"1": "1", "2": "1"}),
            (snmp_tables.OID_IFOPERSTATUS, {"1": "1", "2": "2"}),
            (snmp_tables.OID_IFNAME, {"1": "GigabitEthernet0/0/1", "2": "Port-channel1"}),
            (snmp_tables.OID_IFHISPEED, {"1": "1000", "2": "10"}),
            (snmp_tables.OID_IFALIAS, {"1": "Uplink", "2": ""}),
        )

        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.walk_columns",
            side_effect=lambda ip_str, oid, *a, **k: columns.get(oid, {}),
        ):
            interfaces = collect_interfaces("192.0.2.1", CONFIG)

        self.assertEqual(len(interfaces), 2)
        first, second = interfaces

        self.assertEqual(first["name"], "GigabitEthernet0/0/1")
        self.assertEqual(first["type"], "1000base-t")  # ifType 6 + ifHighSpeed 1000 Mbps
        self.assertEqual(first["mtu"], 1500)
        self.assertEqual(first["speed"], 1000000)  # ifHighSpeed 1000 Mbps -> Kbps
        self.assertEqual(first["mac"], "00:11:22:33:44:55")
        self.assertEqual(first["oper_status"], 1)
        self.assertEqual(first["alias"], "Uplink")

        self.assertEqual(second["name"], "Port-channel1")
        self.assertEqual(second["type"], "lag")
        self.assertEqual(second["speed"], 10000)  # ifHighSpeed 10 Mbps -> Kbps

    def test_empty_table_returns_empty(self):
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.walk_columns",
            return_value={},
        ):
            self.assertEqual(collect_interfaces("192.0.2.1", CONFIG), [])

    def test_name_falls_back_to_descr(self):
        columns = _column_map(
            (snmp_tables.OID_IFDESCR, {"1": "GigabitEthernet0/0/1"}),
        )
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.walk_columns",
            side_effect=lambda ip_str, oid, *a, **k: columns.get(oid, {}),
        ):
            interfaces = collect_interfaces("192.0.2.1", CONFIG)
        self.assertEqual(interfaces[0]["name"], "GigabitEthernet0/0/1")
        self.assertEqual(interfaces[0]["type"], "other")


class CollectIPAddressesTests(TestCase):
    def test_ip_addr_table_with_netmask(self):
        columns = _column_map(
            (snmp_tables.OID_IPADENTIFINDEX, {"10.0.0.1": "1", "10.0.0.2": "1", "192.168.1.1": "2"}),
            (snmp_tables.OID_IPADENTNETMASK, {"10.0.0.1": "255.255.255.0", "10.0.0.2": "255.255.255.0", "192.168.1.1": "255.255.255.255"}),
        )
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.walk_columns",
            side_effect=lambda ip_str, oid, *a, **k: columns.get(oid, {}),
        ):
            addresses = collect_ip_addresses("192.0.2.1", CONFIG)

        self.assertEqual(len(addresses), 3)
        by_addr = {a["address"]: a for a in addresses}
        self.assertEqual(by_addr["10.0.0.1"]["prefix_length"], 24)
        self.assertEqual(by_addr["10.0.0.1"]["if_index"], "1")
        self.assertEqual(by_addr["192.168.1.1"]["prefix_length"], 32)

    def test_ip_address_table_fallback(self):
        # ipAddressTable index is ifIndex.ipAddressType.<addr octets>
        columns = _column_map(
            (snmp_tables.OID_IPADENTIFINDEX, {}),
            (snmp_tables.OID_IPADENTNETMASK, {}),
            (
                snmp_tables.OID_IPADDRESSIFINDEX,
                {
                    "3.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1": "3",
                    "1.1.10.0.0.5": "1",
                },
            ),
        )
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.walk_columns",
            side_effect=lambda ip_str, oid, *a, **k: columns.get(oid, {}),
        ):
            addresses = collect_ip_addresses("192.0.2.1", CONFIG)

        self.assertEqual(len(addresses), 2)
        by_addr = {a["address"]: a for a in addresses}
        self.assertEqual(by_addr["2001:db8::1"]["if_index"], "3")
        self.assertEqual(by_addr["2001:db8::1"]["prefix_length"], 128)
        self.assertEqual(by_addr["10.0.0.5"]["prefix_length"], 32)
        self.assertIsNone(by_addr["10.0.0.5"]["vrf"])

    def test_ip_address_table_prefix_from_pointer(self):
        columns = _column_map(
            (snmp_tables.OID_IPADDRESSIFINDEX, {"1.1.192.0.2.1": "1", "2.1.192.0.2.5": "2"}),
            (
                snmp_tables.OID_IPADDRESSPREFIX,
                {"1.1.192.0.2.1": "1.3.6.1.2.1.4.32.1.1.1.24.192.0.2.0"},
            ),
            (snmp_tables.OID_IPADDRESSPREFIXLENGTH, {"1.24.192.0.2.0": "24"}),
        )
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.walk_columns",
            side_effect=lambda ip_str, oid, *a, **k: columns.get(oid, {}),
        ):
            addresses = collect_ip_addresses("192.0.2.1", CONFIG)

        by_addr = {a["address"]: a for a in addresses}
        self.assertEqual(by_addr["192.0.2.1"]["prefix_length"], 24)
        # No pointer -> host route fallback
        self.assertEqual(by_addr["192.0.2.5"]["prefix_length"], 32)

    def test_ip_address_context_tags_vrf(self):
        columns = _column_map(
            (snmp_tables.OID_IPADDRESSIFINDEX, {"1.1.10.0.0.5": "1"}),
        )
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.walk_columns",
            side_effect=lambda ip_str, oid, *a, **k: columns.get(oid, {}),
        ):
            addresses = collect_ip_addresses("192.0.2.1", CONFIG, context_name="RED")
        self.assertEqual(addresses[0]["vrf"], "RED")

    def test_parse_ipaddress_table_index(self):
        self.assertEqual(_parse_ipaddress_table_index("1.1.10.0.0.5"), ("1", 1, "10.0.0.5"))
        self.assertEqual(
            _parse_ipaddress_table_index("3.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1"),
            ("3", 2, "2001:db8::1"),
        )
        self.assertEqual(_parse_ipaddress_table_index("junk"), (None, None, None))
        self.assertEqual(_parse_ipaddress_table_index("1.1.10.0"), (None, None, None))


class CollectVRFTests(TestCase):
    def test_collect_vrfs_merges_mibs(self):
        columns = _column_map(
            # mplsVpnVrfTable: index/value = VRF name octets
            (snmp_tables.OID_MPLSVPNVRFNAME, {"82.69.68": "RED"}),
            (snmp_tables.OID_MPLSVPNVRFDESCRIPTION, {"82.69.68": "Red VRF"}),
            (snmp_tables.OID_MPLSVPNVRFRD, {"82.69.68": "1:100"}),
            # mplsVpnInterfaceConfTable: index vrfName.ifIndex
            (snmp_tables.OID_MPLSVPNINTERFACECONFINDEX, {"82.69.68.5": "5"}),
            # Cisco CISCO-VRF-MIB classic
            (snmp_tables.OID_CVRFVRFNAME, {"1": "GREEN"}),
            # Cisco CISCO-VRF-MIB v2 (711)
            (snmp_tables.OID_CVVRFNAME, {"1": "BLUE"}),
            (snmp_tables.OID_CVVRFINTERFACEIFINDEX, {"1.2": "2"}),
        )
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.walk_columns",
            side_effect=lambda ip_str, oid, *a, **k: columns.get(oid, {}),
        ):
            vrfs = collect_vrfs("192.0.2.1", CONFIG)

        by_name = {v["name"]: v for v in vrfs}
        self.assertEqual(set(by_name), {"RED", "GREEN", "BLUE"})
        self.assertEqual(by_name["RED"]["rd"], "1:100")
        self.assertEqual(by_name["RED"]["description"], "Red VRF")
        self.assertEqual(by_name["RED"]["interfaces"], ["5"])
        self.assertEqual(by_name["BLUE"]["interfaces"], ["2"])

    def test_format_rd(self):
        # Type 0: 2-byte type + 2-byte number + 4-byte IPv4
        self.assertEqual(_format_rd("\x00\x00\x00\x64\xc0\x00\x02\x01"), "100:192.0.2.1")
        # Type 1: 2-byte type + 2-byte ASN + 4-byte assigned number
        self.assertEqual(_format_rd("\x00\x01\x00\x01\x00\x00\x30\x39"), "1:12345")
        # 4-byte: 2-byte ASN + 2-byte number
        self.assertEqual(_format_rd("\x00\x64\x00\x01"), "100:1")
        # 3-byte: 1-byte type + 2-byte number
        self.assertEqual(_format_rd("\x01\x00\x64"), "1:100")
        # Pass-through
        self.assertEqual(_format_rd("65000:10"), "65000:10")
        self.assertEqual(_format_rd(""), "")

    def test_decode_ascii_index(self):
        self.assertEqual(_decode_ascii_index("82.69.68"), "RED")
        self.assertEqual(_decode_ascii_index("82.69.68.5", drop_last=True), "RED")


class CollectARPTests(TestCase):
    def test_filters_incomplete_and_zero_macs(self):
        columns = _column_map(
            (snmp_tables.OID_IPNETTOMEDIAIFINDEX, {"10.0.0.1": "1", "10.0.0.2": "1", "10.0.0.3": "1"}),
            (snmp_tables.OID_IPNETTOMEDIAPHYSADDRESS, {"10.0.0.1": "aa:bb:cc:dd:ee:01", "10.0.0.2": "00:00:00:00:00:00", "10.0.0.3": ""}),
        )
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.walk_columns",
            side_effect=lambda ip_str, oid, *a, **k: columns.get(oid, {}),
        ):
            entries = collect_arp_table("192.0.2.1", CONFIG)

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["ip"], "10.0.0.1")
        self.assertEqual(entries[0]["mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(entries[0]["if_index"], "1")


class CollectPhysicalTests(TestCase):
    def setUp(self):
        self.columns = _column_map(
            (snmp_tables.OID_ENTPHYSDESCR, {"1": "WS-C9300-48P Chassis", "2": "WS-C9300-48P Port", "3": "Fan Tray"}),
            (snmp_tables.OID_ENTPHYSCLASS, {"1": "3", "2": "9", "3": "7"}),
            (snmp_tables.OID_ENTPHYSNAME, {"1": "Chassis", "2": "", "3": ""}),
            (snmp_tables.OID_ENTPHYSSERIALNUM, {"1": "FCW2134ABCD", "2": "", "3": "FAN123"}),
            (snmp_tables.OID_ENTPHYSMODELNAME, {"1": "WS-C9300-48P", "2": "", "3": ""}),
        )

    def test_physical_table_collection(self):
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.walk_columns",
            side_effect=lambda ip_str, oid, *a, **k: self.columns.get(oid, {}),
        ):
            physical = collect_physical("192.0.2.1", CONFIG)

        self.assertEqual(len(physical), 3)
        self.assertEqual(physical[0]["class"], 3)
        self.assertEqual(physical[0]["serial"], "FCW2134ABCD")

    def test_find_chassis_serial_prefers_chassis(self):
        physical = [
            {"class": 9, "serial": ""},
            {"class": 3, "serial": "FCW2134ABCD"},
            {"class": 7, "serial": "FAN123"},
        ]
        self.assertEqual(find_chassis_serial(physical), "FCW2134ABCD")

    def test_find_chassis_serial_falls_back(self):
        physical = [
            {"class": 3, "serial": ""},
            {"class": 9, "serial": "MOD-42"},
        ]
        self.assertEqual(find_chassis_serial(physical), "MOD-42")

    def test_find_chassis_serial_none(self):
        self.assertIsNone(find_chassis_serial([]))
        self.assertIsNone(find_chassis_serial([{"class": 3, "serial": ""}]))

    def test_find_chassis_model_prefers_chassis_model_name(self):
        physical = [
            {"class": 9, "model": "PSU-900", "descr": "Power Supply 900W"},
            {"class": 3, "model": "WS-C2960-24TT-L", "descr": "Catalyst 2960 24-Port"},
        ]
        self.assertEqual(find_chassis_model(physical), "WS-C2960-24TT-L")

    def test_find_chassis_model_falls_back_to_chassis_descr(self):
        physical = [
            {"class": 3, "model": "", "descr": "UniFi U7 Pro"},
        ]
        self.assertEqual(find_chassis_model(physical), "UniFi U7 Pro")

    def test_find_chassis_model_uses_any_entity_model(self):
        physical = [
            {"class": 3, "model": "", "descr": "Chassis"},
            {"class": 7, "model": "UCG-Fiber", "descr": "Cloud Gateway"},
        ]
        self.assertEqual(find_chassis_model(physical), "UCG-Fiber")

    def test_find_chassis_model_none(self):
        self.assertIsNone(find_chassis_model([]))
        self.assertIsNone(find_chassis_model([{"class": 3, "model": "", "descr": ""}]))


class CollectNeighborsTests(TestCase):
    def test_lldp_neighbors_resolve_local_interface(self):
        columns = _column_map(
            (snmp_tables.OID_LLDPLOCPORTIFINDEX, {"1": "5", "2": "6"}),
            (snmp_tables.OID_LLDPREMSYSNAME, {"0.1.3": "neighbor-01", "0.2.7": "neighbor-02"}),
            (snmp_tables.OID_LLDPREMPORTID, {"0.1.3": "GigabitEthernet0/0/1", "0.2.7": "xe-0/0/2"}),
            (snmp_tables.OID_LLDPREMSYSDESC, {"0.1.3": "Juniper Junos", "0.2.7": "Cisco IOS-XE"}),
            (snmp_tables.OID_LLDPREMCHASSISID, {"0.1.3": "00:11:22:33:44:55", "0.2.7": "0c:0d:0e:0f:10:11"}),
        )
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.walk_columns",
            side_effect=lambda ip_str, oid, *a, **k: columns.get(oid, {}),
        ):
            neighbors = collect_lldp_neighbors("192.0.2.1", CONFIG)

        self.assertEqual(len(neighbors), 2)
        first = neighbors[0]
        self.assertEqual(first["protocol"], "lldp")
        self.assertEqual(first["local_port_num"], "1")
        self.assertEqual(first["local_if_index"], "5")
        self.assertEqual(first["remote_name"], "neighbor-01")
        self.assertEqual(first["remote_port"], "GigabitEthernet0/0/1")
        self.assertEqual(first["remote_description"], "Juniper Junos")
        self.assertEqual(first["remote_chassis_id"], "00:11:22:33:44:55")

    def test_lldp_no_table_returns_empty(self):
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.walk_columns",
            return_value={},
        ):
            self.assertEqual(collect_lldp_neighbors("192.0.2.1", CONFIG), [])

    def test_cdp_neighbors(self):
        columns = _column_map(
            (snmp_tables.OID_CDPCACHEDEVICEID, {"6.1": "sw-dist-1", "6.2": "sw-dist-2"}),
            (snmp_tables.OID_CDPCACHEDEVICEPORT, {"6.1": "GigabitEthernet0/1", "6.2": "GigabitEthernet0/2"}),
            (snmp_tables.OID_CDPCACHEPLATFORM, {"6.1": "Cisco Catalyst 9300", "6.2": "Cisco Catalyst 9300"}),
        )
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.walk_columns",
            side_effect=lambda ip_str, oid, *a, **k: columns.get(oid, {}),
        ):
            neighbors = collect_cdp_neighbors("192.0.2.1", CONFIG)

        self.assertEqual(len(neighbors), 2)
        first = neighbors[0]
        self.assertEqual(first["protocol"], "cdp")
        self.assertEqual(first["local_if_index"], "6")
        self.assertEqual(first["remote_name"], "sw-dist-1")
        self.assertEqual(first["remote_port"], "GigabitEthernet0/1")
        self.assertEqual(first["remote_description"], "Cisco Catalyst 9300")


class CollectVlansTests(TestCase):
    def test_dot1q_vlan_static_table(self):
        columns = _column_map(
            (snmp_tables.OID_VLANSTATICNAME, {"1": "default", "10": "Management", "20": "Users"}),
            (snmp_tables.OID_VLANSTATICROWSTATUS, {"1": "1", "10": "1", "20": "1"}),
        )
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.walk_columns",
            side_effect=lambda ip_str, oid, *a, **k: columns.get(oid, {}),
        ):
            vlans = collect_vlans("192.0.2.1", CONFIG)

        self.assertEqual(len(vlans), 3)
        self.assertEqual(vlans[0]["vid"], 1)
        self.assertEqual(vlans[0]["name"], "default")
        self.assertEqual(vlans[1]["vid"], 10)
        self.assertEqual(vlans[1]["name"], "Management")
        self.assertEqual(vlans[1]["row_status"], 1)

    def test_empty_table_returns_empty(self):
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.walk_columns",
            return_value={},
        ):
            self.assertEqual(collect_vlans("192.0.2.1", CONFIG), [])

    def test_sorted_by_vid(self):
        columns = _column_map(
            (snmp_tables.OID_VLANSTATICNAME, {"100": "v100", "2": "v2", "50": "v50"}),
        )
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.walk_columns",
            side_effect=lambda ip_str, oid, *a, **k: columns.get(oid, {}),
        ):
            vlans = collect_vlans("192.0.2.1", CONFIG)
        self.assertEqual([v["vid"] for v in vlans], [2, 50, 100])

    def test_invalid_vid_skipped(self):
        columns = _column_map(
            (snmp_tables.OID_VLANSTATICNAME, {"1": "ok", "4095": "out-of-range", "nonsense": "bad"}),
        )
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.walk_columns",
            side_effect=lambda ip_str, oid, *a, **k: columns.get(oid, {}),
        ):
            vlans = collect_vlans("192.0.2.1", CONFIG)
        self.assertEqual(len(vlans), 1)
        self.assertEqual(vlans[0]["vid"], 1)


class CollectSystemTests(TestCase):
    def test_system_scalars(self):
        values = {
            snmp_tables.OID_SYSNAME: "switch-001",
            snmp_tables.OID_SYSDESCR: "Cisco Catalyst 9300, IOS-XE 17.3",
            snmp_tables.OID_SYSOBJECTID: "1.3.6.1.4.1.9.1.675",
            snmp_tables.OID_SYSCONTACT: "noc@example.com",
            snmp_tables.OID_SYSLOCATION: "DC1 Row 3",
            snmp_tables.OID_SYSUPTIME: "1234567",
        }

        def fake_snmp_get(ip_str, oid, *a, **k):
            return values.get(oid)

        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.snmp_get",
            side_effect=fake_snmp_get,
        ):
            system = collect_system("192.0.2.1", CONFIG)

        self.assertEqual(system["sys_name"], "switch-001")
        self.assertEqual(system["sys_contact"], "noc@example.com")
        self.assertEqual(system["sys_location"], "DC1 Row 3")


def _fake_api():
    """Minimal stand-in for the pysnmp API dict used by _auth_data."""
    return {
        "CommunityData": lambda *a, **k: ("community", a, k),
        "UsmUserData": lambda *a, **k: ("usm", a, k),
    }


class SNMPv3AuthTests(TestCase):
    def test_build_snmp_auth_defaults_to_v2c(self):
        auth = build_snmp_auth({"snmp_community": "secret"})
        self.assertEqual(auth["version"], 2)
        self.assertEqual(auth["community"], "secret")
        self.assertEqual(auth["context"], "")

    def test_build_snmp_auth_explicit_v1(self):
        auth = build_snmp_auth({"snmp_version": "1", "snmp_community": "ro"})
        self.assertEqual(auth["version"], 1)

    def test_build_snmp_auth_v3(self):
        auth = build_snmp_auth(
            {
                "snmp_version": "3",
                "snmpv3_username": "discover",
                "snmpv3_auth_protocol": "SHA-256",
                "snmpv3_auth_key": "auth-pass",
                "snmpv3_priv_protocol": "AES-192",
                "snmpv3_priv_key": "priv-pass",
                "snmpv3_context_name": "ctx-1",
            }
        )
        self.assertEqual(auth["version"], 3)
        self.assertEqual(auth["user"], "discover")
        self.assertEqual(auth["auth_protocol"], "SHA-256")
        self.assertEqual(auth["priv_protocol"], "AES-192")
        self.assertEqual(auth["context"], "ctx-1")

    def test_auth_data_uses_community_for_v2c(self):
        result = _auth_data(_fake_api(), build_snmp_auth({"snmp_community": "public"}))
        self.assertEqual(result[0], "community")
        self.assertEqual(result[1], ("public",))
        self.assertEqual(result[2]["mpModel"], 1)

    def test_auth_data_uses_community_for_v1(self):
        result = _auth_data(_fake_api(), build_snmp_auth({"snmp_version": "1", "snmp_community": "ro"}))
        self.assertEqual(result[2]["mpModel"], 0)

    def test_auth_data_uses_usm_for_v3(self):
        auth = build_snmp_auth(
            {
                "snmp_version": "3",
                "snmpv3_username": "discover",
                "snmpv3_auth_protocol": "SHA",
                "snmpv3_auth_key": "auth-pass",
                "snmpv3_priv_protocol": "AES",
                "snmpv3_priv_key": "priv-pass",
            }
        )
        result = _auth_data(_fake_api(), auth)
        self.assertEqual(result[0], "usm")
        self.assertEqual(result[1], ("discover",))
        self.assertEqual(result[2]["authProtocol"], (1, 3, 6, 1, 6, 3, 10, 1, 1, 3))  # SHA
        self.assertEqual(result[2]["privProtocol"], (1, 3, 6, 1, 6, 3, 10, 1, 2, 4))  # AES

    def test_auth_data_noauth_nopriv_without_keys(self):
        auth = build_snmp_auth({"snmp_version": "3", "snmpv3_username": "nopriv"})
        result = _auth_data(_fake_api(), auth)
        self.assertIsNone(result[2]["authProtocol"])
        self.assertIsNone(result[2]["privProtocol"])
        self.assertIsNone(result[2]["authKey"])
        self.assertIsNone(result[2]["privKey"])

    def test_auth_data_auth_only_without_priv_key(self):
        auth = build_snmp_auth({"snmp_version": "3", "snmpv3_username": "u", "snmpv3_auth_key": "auth-pass"})
        result = _auth_data(_fake_api(), auth)
        self.assertIsNotNone(result[2]["authProtocol"])
        self.assertIsNone(result[2]["privProtocol"])

    def test_collect_system_passes_v3_auth_to_snmp_get(self):
        captured = []

        def fake_snmp_get(ip_str, oid, auth, timeout, retries):
            captured.append((ip_str, oid, auth))
            return "value"

        config = dict(CONFIG)
        config["snmp_version"] = "3"
        config["snmpv3_username"] = "discover"
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.snmp_get",
            side_effect=fake_snmp_get,
        ):
            collect_system("192.0.2.1", config)

        self.assertTrue(captured)
        self.assertEqual(captured[0][2]["version"], 3)
        self.assertEqual(captured[0][2]["user"], "discover")

    def test_discover_tables_uses_v3_auth_probe(self):
        captured = {}

        def fake_snmp_get(ip_str, oid, auth, timeout, retries):
            captured["auth"] = auth
            return None

        config = dict(CONFIG)
        config["snmp_version"] = "3"
        config["snmpv3_username"] = "discover"
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.snmp_get",
            side_effect=fake_snmp_get,
        ):
            discover_snmp_tables("192.0.2.1", config)

        self.assertEqual(captured["auth"]["version"], 3)
        self.assertEqual(captured["auth"]["user"], "discover")


class DiscoverTablesTests(TestCase):
    def test_collector_failure_is_isolated(self):
        columns = _column_map(
            (snmp_tables.OID_IFDESCR, {"1": "GigabitEthernet0/0/1"}),
            (snmp_tables.OID_IFNAME, {"1": "GigabitEthernet0/0/1"}),
        )

        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.walk_columns",
            side_effect=lambda ip_str, oid, *a, **k: columns.get(oid, {}),
        ):
            with patch(
                "nautobot_plugin_device_auto_discovery.snmp_tables.snmp_get",
                return_value=None,
            ):
                with patch(
                    "nautobot_plugin_device_auto_discovery.snmp_tables.collect_neighbors",
                    side_effect=RuntimeError("LLDP agent unreachable"),
                ):
                    tables = discover_snmp_tables("192.0.2.1", CONFIG)

        self.assertEqual(len(tables["interfaces"]), 1)
        self.assertEqual(tables["neighbors"], [])
        self.assertIn("system", tables)
        self.assertIn("physical", tables)

    def test_neighbors_skipped_when_disabled(self):
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.snmp_get",
            return_value=None,
        ):
            with patch(
                "nautobot_plugin_device_auto_discovery.snmp_tables.collect_neighbors",
                return_value=[{"remote_name": "nope"}],
            ) as mocked:
                config = dict(CONFIG)
                config["include_neighbors"] = False
                tables = discover_snmp_tables("192.0.2.1", config)

        self.assertEqual(tables["neighbors"], [])
        mocked.assert_not_called()

    def test_vlans_collected(self):
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.snmp_get",
            return_value=None,
        ):
            with patch(
                "nautobot_plugin_device_auto_discovery.snmp_tables.collect_vlans",
                return_value=[{"vid": 10, "name": "Management"}],
            ) as mocked:
                tables = discover_snmp_tables("192.0.2.1", CONFIG)

        self.assertEqual(tables["vlans"], [{"vid": 10, "name": "Management"}])
        mocked.assert_called_once()

    def test_vlans_skipped_when_disabled(self):
        with patch(
            "nautobot_plugin_device_auto_discovery.snmp_tables.snmp_get",
            return_value=None,
        ):
            with patch(
                "nautobot_plugin_device_auto_discovery.snmp_tables.collect_vlans",
                return_value=[{"vid": 10, "name": "Management"}],
            ) as mocked:
                config = dict(CONFIG)
                config["include_vlans"] = False
                tables = discover_snmp_tables("192.0.2.1", config)

        self.assertEqual(tables["vlans"], [])
        mocked.assert_not_called()
