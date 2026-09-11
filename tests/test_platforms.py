"""Tests for expanded platform support: Aruba AOS-CX/ArubaOS, Cisco WLC, Brocade FastIron."""

from django.test import TestCase

from nautobot_plugin_device_auto_discovery.jobs import (
    VENDOR_KEYWORDS,
    detect_vendor_from_descr,
    parse_model_from_descr,
)
from nautobot_plugin_device_auto_discovery.mappings import lookup_platform_from_oid
from nautobot_plugin_device_auto_discovery.ssh_parsing import (
    parse_ssh_ip_addresses,
    parse_ssh_routes,
    parse_ssh_vrfs,
)
from nautobot_plugin_device_auto_discovery.ssh_profiles import SSH_PROFILES
from nautobot_plugin_device_auto_discovery.jobs import _parse_ssh_output


class NewOidMappingTests(TestCase):
    """sysObjectID prefix mappings for the new platforms."""

    def test_aruba_aos_cx(self):
        info = lookup_platform_from_oid("1.3.6.1.4.1.47196.1.1.1.2.63")
        self.assertIsNotNone(info)
        self.assertEqual(info["platform_name"], "Aruba AOS-CX")
        self.assertEqual(info["manufacturer_name"], "HPE")
        self.assertEqual(info["network_driver"], "aruba_os-cx")

    def test_arubaos_controller(self):
        info = lookup_platform_from_oid("1.3.6.1.4.1.14823.1.1.2")
        self.assertIsNotNone(info)
        self.assertEqual(info["platform_name"], "ArubaOS")
        self.assertEqual(info["network_driver"], "aruba_os")

    def test_aruba_instant(self):
        info = lookup_platform_from_oid("1.3.6.1.4.1.14823.1.2.5")
        self.assertEqual(info["platform_name"], "Aruba Instant")

    def test_cisco_wlc_aireos(self):
        info = lookup_platform_from_oid("1.3.6.1.4.1.9.1.828.1")
        self.assertEqual(info["platform_name"], "Cisco WLC AireOS")
        self.assertEqual(info["network_driver"], "cisco_wlc")

    def test_cisco_wlc_9800(self):
        info = lookup_platform_from_oid("1.3.6.1.4.1.9.1.1226.1")
        self.assertEqual(info["platform_name"], "Cisco WLC 9800 IOS-XE")

    def test_brocade_fastiron(self):
        info = lookup_platform_from_oid("1.3.6.1.4.1.1991.1.3.49")
        self.assertEqual(info["platform_name"], "Brocade FastIron")
        self.assertEqual(info["manufacturer_name"], "Ruckus")
        self.assertEqual(info["network_driver"], "ruckus_fastiron")

    def test_brocade_generic_prefix(self):
        info = lookup_platform_from_oid("1.3.6.1.4.1.1991.1.1.2.1")
        self.assertEqual(info["platform_name"], "Brocade FastIron")

    def test_aruba_prefix_more_specific_than_hpe(self):
        # Aruba OIDs must not be swallowed by a broader HPE prefix
        info = lookup_platform_from_oid("1.3.6.1.4.1.14823.1.1.99")
        self.assertEqual(info["platform_name"], "ArubaOS")


class NewVendorDetectionTests(TestCase):
    """Banner/sysDescr vendor detection for the new platforms."""

    def test_aruba_detected(self):
        self.assertEqual(detect_vendor_from_descr("ArubaOS-CX Software Version 10.10"), "Aruba")
        self.assertEqual(detect_vendor_from_descr("Aruba Controller"), "Aruba")

    def test_cisco_wlc_detected(self):
        self.assertEqual(detect_vendor_from_descr("Cisco Controller AIR-CT5508"), "Cisco WLC")
        self.assertEqual(detect_vendor_from_descr("Cisco AireOS WLC"), "Cisco WLC")

    def test_brocade_detected(self):
        self.assertEqual(detect_vendor_from_descr("Brocade ICX7450-48"), "Brocade")
        self.assertEqual(detect_vendor_from_descr("Ruckus ICX 7250"), "Brocade")
        self.assertEqual(detect_vendor_from_descr("FastIron Stackable"), "Brocade")

    def test_keywords_registered(self):
        self.assertIn("Aruba", VENDOR_KEYWORDS.values())
        self.assertIn("Cisco WLC", VENDOR_KEYWORDS.values())
        self.assertIn("Brocade", VENDOR_KEYWORDS.values())

    def test_cisco_wlc_does_not_shadow_plain_cisco(self):
        # A plain IOS banner must still resolve to plain "Cisco"
        self.assertEqual(detect_vendor_from_descr("Cisco IOS Software, C2960"), "Cisco")
        # And a WLC banner resolves to Cisco WLC
        self.assertEqual(detect_vendor_from_descr("Cisco Controller"), "Cisco WLC")


class NewModelParsingTests(TestCase):
    """sysDescr model extraction for the new platforms."""

    def test_cisco_wlc_model(self):
        self.assertEqual(parse_model_from_descr("Cisco AIR-CT5520-K9", "Cisco WLC"), "AIR-CT5520-K9")
        self.assertEqual(parse_model_from_descr("C9800-40-K9 wireless", "Cisco WLC"), "C9800-40-K9")

    def test_aruba_model(self):
        self.assertEqual(parse_model_from_descr("Aruba 6300M Switch", "Aruba"), "6300M")
        self.assertIn(parse_model_from_descr("ArubaOS 8.10 on Aruba 7205", "Aruba"), ["7205"])

    def test_brocade_model(self):
        self.assertEqual(parse_model_from_descr("Brocade ICX7450-48 Router", "Brocade"), "ICX7450-48")
        self.assertEqual(parse_model_from_descr("Ruckus ICX 7250-48", "Brocade"), "ICX")


class NewSSHProfileTests(TestCase):
    """SSH profile structure + parser behavior for the new platforms."""

    def test_profiles_present_and_well_formed(self):
        for vendor in ("Aruba", "Cisco WLC", "Brocade"):
            profile = SSH_PROFILES[vendor]
            self.assertIn("commands", profile)
            self.assertIn("parsers", profile)
            for key in ("hostname", "model", "serial", "os_version"):
                self.assertTrue(profile["parsers"][key], f"{vendor} missing {key} parser")

    def test_vendor_keywords_match_banners(self):
        import re

        for vendor, profile in (("Aruba", SSH_PROFILES["Aruba"]), ("Cisco WLC", SSH_PROFILES["Cisco WLC"]), ("Brocade", SSH_PROFILES["Brocade"])):
            for keyword in profile["vendor_keywords"]:
                self.assertTrue(re.search(keyword, vendor, re.IGNORECASE), f"{keyword} should match {vendor}")

    def test_aruba_output_parsing(self):
        output = (
            "aruba-sw1>\n"
            "ArubaOS-CX Software Version 10.10.1100\n"
            "Serial number  TW28KMZ01A\n"
            "Product Model JL665A\n"
            "aruba-sw1#"
        )
        hostname, model, serial, os_version = _parse_ssh_output(output, "Aruba")
        self.assertEqual(hostname, "aruba-sw1")
        self.assertEqual(model, "JL665A")
        self.assertEqual(serial, "TW28KMZ01A")
        self.assertIn("10.10", os_version)

    def test_cisco_wlc_output_parsing(self):
        output = (
            "(Cisco Controller) >\n"
            "System Name. . . . . . . . . . . . . . wlc-01\n"
            "Product Model. . . . . . . . . . . . . AIR-CT5520-K9\n"
            "Product Serial Number. . . . . . . . . FOC2101S2ZZ\n"
            "Product Version. . . . . . . . . . . . 8.10.190.0\n"
            "(Cisco Controller) >"
        )
        hostname, model, serial, os_version = _parse_ssh_output(output, "Cisco WLC")
        self.assertEqual(hostname, "wlc-01")
        self.assertEqual(model, "AIR-CT5520-K9")
        self.assertEqual(serial, "FOC2101S2ZZ")
        self.assertEqual(os_version, "8.10.190.0")

    def test_brocade_output_parsing(self):
        output = (
            "icx-sw1>\n"
            "Brocade ICX7450-48 Router\n"
            "Serial Number: BZM3127K00T\n"
            "SW: Version 08.0.95dT213\n"
            "icx-sw1#"
        )
        hostname, model, serial, os_version = _parse_ssh_output(output, "Brocade")
        self.assertEqual(hostname, "icx-sw1")
        self.assertTrue(model.startswith("ICX"))
        self.assertEqual(serial, "BZM3127K00T")
        self.assertIn("08.0", os_version)


class NewDataParsingTests(TestCase):
    """VRF/IP/route parsing for the new vendor outputs."""

    def test_aruba_ip_addresses_cidr_style(self):
        outputs = {
            "show ip interface brief": (
                "Interface  IP Address/Fmask   Admin  Oper  VRF\n"
                "1/1/1      10.20.0.1/24       up     up    default\n"
                "1/1/2      unassigned         down   down  default\n"
            )
        }
        rows = parse_ssh_ip_addresses(outputs, "Aruba")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["address"], "10.20.0.1")
        self.assertEqual(rows[0]["prefix_length"], 24)
        self.assertEqual(rows[0]["if_index"], "1/1/1")

    def test_brocade_ip_addresses_plain_style(self):
        outputs = {
            "show ip interface brief": (
                "Interface     IP-Address OK? Method Status  Protocol\n"
                "ve 1          192.168.1.10     YES manual up     up\n"
            )
        }
        rows = parse_ssh_ip_addresses(outputs, "Brocade")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["address"], "192.168.1.10")
        self.assertEqual(rows[0]["prefix_length"], 32)
        self.assertEqual(rows[0]["if_index"], "ve 1")

    def test_fastiron_vrfs_from_show_run_vrf(self):
        outputs = {
            "show run vrf": (
                "vrf CUST_A\n rd 65000:100\n address-family ipv4\n exit-address-family\n"
                "vrf MGMT\n"
            )
        }
        vrfs = parse_ssh_vrfs(outputs, "Brocade")
        names = {v["name"] for v in vrfs}
        self.assertIn("CUST_A", names)

    def test_brocade_routes_cisco_style(self):
        outputs = {
            "show ip route": (
                "B  10.50.0.0/16 [200/0] via 10.0.0.2, 2h20m, ve 100\n"
                "C  10.20.0.0/24 is directly connected, ve 10\n"
            )
        }
        routes = parse_ssh_routes(outputs, "Brocade")
        prefixes = {(r["dest"], r["prefix_length"]) for r in routes}
        self.assertIn(("10.50.0.0", 16), prefixes)
        self.assertIn(("10.20.0.0", 24), prefixes)
