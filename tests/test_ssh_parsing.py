"""Tests for the SSH data-command parsing helpers (no Django required)."""

from unittest import TestCase

from nautobot_plugin_device_auto_discovery.ssh_parsing import (
    parse_ssh_ip_addresses,
    parse_ssh_vrfs,
)


class ParseSSHVRFsTests(TestCase):
    def test_cisco_show_ip_vrf(self):
        outputs = {
            "show ip vrf": (
                "Name                             Default RD            Interfaces\n"
                "RED                              65000:1               Gi0/0/1\n"
                "BLUE                             2:2                   Loopback100\n"
            )
        }
        vrfs = parse_ssh_vrfs(outputs, "Cisco")
        by_name = {v["name"]: v for v in vrfs}
        self.assertEqual(set(by_name), {"RED", "BLUE"})
        self.assertEqual(by_name["RED"]["rd"], "65000:1")

    def test_juniper_show_routing_instances(self):
        outputs = {
            "show routing-instances": (
                "Instance               Type\n"
                "default                forwarding\n"
                "RED                    vrf\n"
                "CUSTOM                 vrf\n"
            )
        }
        vrfs = parse_ssh_vrfs(outputs, "Juniper Networks")
        by_name = {v["name"]: v for v in vrfs}
        self.assertEqual(set(by_name), {"RED", "CUSTOM"})

    def test_arista_show_vrf(self):
        outputs = {
            "show vrf": (
                "VRF              RD            Protocols  State\n"
                "TEST             100:1         IPv4       Active\n"
            )
        }
        vrfs = parse_ssh_vrfs(outputs, "Arista Networks")
        self.assertEqual(vrfs, [{"name": "TEST", "rd": "100:1"}])

    def test_invalid_output_ignored(self):
        outputs = {"show ip vrf": "% Invalid input detected at '^' marker."}
        self.assertEqual(parse_ssh_vrfs(outputs, "Cisco"), [])


class ParseSSHIPAddressesTests(TestCase):
    def test_cisco_ipv4_and_ipv6_brief(self):
        outputs = {
            "show ip interface brief": (
                "Interface             IP-Address      OK? Method Status                Protocol\n"
                "GigabitEthernet0/0    10.0.0.1        YES NVRAM  up                    up\n"
                "Loopback1             10.0.0.99       YES manual administratively down down\n"
            ),
            "show ipv6 interface brief": (
                "Interface                  Status       Protocol  Address\n"
                "GigabitEthernet0/0         up           up        FE80::1/64\n"
            ),
        }
        rows = parse_ssh_ip_addresses(outputs, "Cisco")
        by_addr = {r["address"]: r for r in rows}
        self.assertEqual(by_addr["10.0.0.1"]["if_index"], "GigabitEthernet0/0")
        self.assertEqual(by_addr["10.0.0.1"]["prefix_length"], 32)
        self.assertEqual(by_addr["FE80::1"]["prefix_length"], 64)

    def test_cisco_interface_to_vrf_join(self):
        outputs = {
            "show ip vrf": (
                "Name                             Default RD            Interfaces\n"
                "RED                              65000:1               Gi0/0/1\n"
            ),
            "show ip interface brief": (
                "Interface             IP-Address      OK? Method Status                Protocol\n"
                "Gi0/0/1               10.1.1.1        YES manual up                    up\n"
                "Gi0/0/2               10.0.0.1        YES manual up                    up\n"
            ),
        }
        rows = parse_ssh_ip_addresses(outputs, "Cisco")
        by_addr = {r["address"]: r for r in rows}
        self.assertEqual(by_addr["10.1.1.1"]["vrf"], "RED")
        self.assertIsNone(by_addr["10.0.0.1"]["vrf"])

    def test_arista_ip_interface_brief(self):
        outputs = {
            "show ip interface brief": (
                "Interface         IP Address       Status       Protocol   VRF\n"
                "Management1       10.0.0.2/24      up           up         default\n"
                "Vlan100           10.1.0.1/24      up           up         TEST\n"
            )
        }
        rows = parse_ssh_ip_addresses(outputs, "Arista Networks")
        by_addr = {r["address"]: r for r in rows}
        self.assertEqual(by_addr["10.0.0.2"]["prefix_length"], 24)
        self.assertEqual(by_addr["10.1.0.1"]["vrf"], "TEST")

    def test_juniper_interfaces_terse(self):
        outputs = {
            "show interfaces terse": (
                "ge-0/0/0.0                up    up   inet     192.168.1.1/24\n"
                "ge-0/0/0.0                up    up   inet6    fe80::1/64\n"
            )
        }
        rows = parse_ssh_ip_addresses(outputs, "Juniper Networks")
        by_addr = {r["address"]: r for r in rows}
        self.assertEqual(by_addr["192.168.1.1"]["prefix_length"], 24)
        self.assertEqual(by_addr["192.168.1.1"]["if_index"], "ge-0/0/0.0")

    def test_linux_ip_addr(self):
        outputs = {
            "ip addr": (
                "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n"
                "    inet 192.168.1.5/24 brd 192.168.1.255 scope global eth0\n"
                "    inet6 fe80::5054:ff:fe12:3456/64 scope link\n"
            )
        }
        rows = parse_ssh_ip_addresses(outputs, "Unknown")
        by_addr = {r["address"]: r for r in rows}
        self.assertEqual(by_addr["192.168.1.5"]["prefix_length"], 24)
        self.assertEqual(by_addr["192.168.1.5"]["if_index"], "eth0")
        self.assertEqual(by_addr["fe80::5054:ff:fe12:3456"]["if_index"], "eth0")

    def test_empty_outputs(self):
        self.assertEqual(parse_ssh_ip_addresses({}, "Cisco"), [])
