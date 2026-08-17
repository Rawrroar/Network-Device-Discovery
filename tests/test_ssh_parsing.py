"""Tests for the SSH data-command parsing helpers (no Django required)."""

from unittest import TestCase

from nautobot_plugin_device_auto_discovery.ssh_parsing import (
    parse_ssh_ip_addresses,
    parse_ssh_routes,
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


class ParseSSHRoutesTests(TestCase):
    def test_cisco_global_route_table(self):
        outputs = {
            "show ip route": (
                "Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP\n"
                "       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area\n"
                "\n"
                "Gateway of last resort is 10.0.0.1 to network 0.0.0.0\n"
                "\n"
                "S*    0.0.0.0/0 [1/0] via 10.0.0.1\n"
                "      10.0.0.0/8 is variably subnetted, 4 subnets, 2 masks\n"
                "C        10.0.0.0/30 is directly connected, GigabitEthernet0/0\n"
                "L        10.0.0.2/32 is directly connected, GigabitEthernet0/0\n"
                "O        10.1.1.0/24 [110/20] via 10.0.0.1, 01:23:45, GigabitEthernet0/0\n"
                "B        172.16.0.0/16 [20/0] via 10.0.0.1, 2d03h\n"
            ),
        }
        routes = parse_ssh_routes(outputs, "Cisco")
        by_key = {(r["dest"], r["prefix_length"]): r for r in routes}

        self.assertIn(("0.0.0.0", 0), by_key)
        self.assertEqual(by_key[("0.0.0.0", 0)]["next_hop"], "10.0.0.1")
        self.assertEqual(by_key[("0.0.0.0", 0)]["protocol"], "static")

        self.assertIn(("10.0.0.0", 30), by_key)
        self.assertEqual(by_key[("10.0.0.0", 30)]["protocol"], "connected")

        self.assertIn(("10.1.1.0", 24), by_key)
        self.assertEqual(by_key[("10.1.1.0", 24)]["next_hop"], "10.0.0.1")
        self.assertEqual(by_key[("10.1.1.0", 24)]["protocol"], "ospf")

        self.assertIn(("172.16.0.0", 16), by_key)
        self.assertEqual(by_key[("172.16.0.0", 16)]["protocol"], "bgp")

    def test_cisco_vrf_route_table(self):
        outputs = {
            "show ip route vrf CUSTOMER1": (
                "Routing Table: CUSTOMER1\n"
                "Codes: L - local, C - connected, S - static, B - BGP\n"
                "\n"
                "C    10.10.10.0/24 is directly connected, GigabitEthernet0/1\n"
                "S    192.168.0.0/16 [1/0] via 10.10.10.1\n"
                "O    172.16.0.0/16 [110/20] via 10.10.10.2\n"
            ),
        }
        routes = parse_ssh_routes(outputs, "Cisco")
        by_key = {(r["dest"], r["prefix_length"]): r for r in routes}

        self.assertEqual(len(routes), 3)
        self.assertEqual(by_key[("10.10.10.0", 24)]["vrf"], "CUSTOMER1")
        self.assertEqual(by_key[("192.168.0.0", 16)]["vrf"], "CUSTOMER1")
        self.assertEqual(by_key[("172.16.0.0", 16)]["vrf"], "CUSTOMER1")
        self.assertEqual(by_key[("192.168.0.0", 16)]["next_hop"], "10.10.10.1")

    def test_juniper_routes(self):
        outputs = {
            "show route": (
                "inet.0: 4 destinations, 5 routes (4 active, 0 holddown, 0 hidden)\n"
                "\n"
                "0.0.0.0/0          *[Static/5] 5d 02:14:33\n"
                "                    > to 10.0.0.1 via ge-0/0/0.0\n"
                "10.0.0.0/30        *[Direct/0] 5d 02:14:33\n"
                "                    > via ge-0/0/0.0\n"
                "172.16.0.0/16      *[BGP/170] 2d 03:12:05, metric 0\n"
                "                    > to 10.0.0.1 via ge-0/0/0.0\n"
            ),
        }
        routes = parse_ssh_routes(outputs, "Juniper Networks")
        by_key = {(r["dest"], r["prefix_length"]): r for r in routes}

        self.assertIn(("0.0.0.0", 0), by_key)
        self.assertEqual(by_key[("0.0.0.0", 0)]["next_hop"], "10.0.0.1")
        self.assertEqual(by_key[("0.0.0.0", 0)]["protocol"], "static")

        self.assertIn(("10.0.0.0", 30), by_key)
        self.assertEqual(by_key[("10.0.0.0", 30)]["protocol"], "connected")

        self.assertIn(("172.16.0.0", 16), by_key)
        self.assertEqual(by_key[("172.16.0.0", 16)]["protocol"], "bgp")

    def test_comware_routes(self):
        outputs = {
            "display ip routing-table": (
                "Destination/Mask   Proto   Pre   Cost    NextHop         Interface\n"
                "0.0.0.0/0         Static  60    0       10.0.0.1        GE1/0/1\n"
                "10.0.0.0/30       Direct  0     0       10.0.0.2        GE1/0/1\n"
                "172.16.0.0/16     OSPF    10    20      10.0.0.1        GE1/0/1\n"
            ),
        }
        routes = parse_ssh_routes(outputs, "HPE")
        by_key = {(r["dest"], r["prefix_length"]): r for r in routes}

        self.assertEqual(len(routes), 3)
        self.assertEqual(by_key[("0.0.0.0", 0)]["next_hop"], "10.0.0.1")
        self.assertEqual(by_key[("0.0.0.0", 0)]["protocol"], "static")
        self.assertEqual(by_key[("10.0.0.0", 30)]["protocol"], "direct")
        self.assertEqual(by_key[("172.16.0.0", 16)]["protocol"], "ospf")

    def test_nokia_routes(self):
        outputs = {
            "show router route-table": (
                "===============================================================================\n"
                "IPv4 Route Table (Router: Base)\n"
                "===============================================================================\n"
                "Dest Prefix       Type    Proto   Age       Pref    NextHop[Interface Name] Metric\n"
                "-------------------------------------------------------------------------------\n"
                "0.0.0.0/0         Remote  BGP     02d03h    170     10.0.0.1               0\n"
                "10.0.0.0/30       Local   Local   05d02h    0       to-104                 0\n"
                "172.16.0.0/16     Remote  OSPF    01d12h    10      10.0.0.1               20\n"
                "-------------------------------------------------------------------------------\n"
                "No. of Routes: 3\n"
            ),
        }
        routes = parse_ssh_routes(outputs, "Nokia")
        by_key = {(r["dest"], r["prefix_length"]): r for r in routes}

        self.assertEqual(len(routes), 3)
        self.assertEqual(by_key[("0.0.0.0", 0)]["protocol"], "bgp")
        self.assertEqual(by_key[("10.0.0.0", 30)]["protocol"], "local")
        self.assertEqual(by_key[("172.16.0.0", 16)]["protocol"], "ospf")

    def test_linux_ip_route(self):
        outputs = {
            "ip route": (
                "default via 192.168.1.1 dev eth0\n"
                "10.0.0.0/24 via 10.0.0.1 dev eth1\n"
                "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.5\n"
            ),
        }
        routes = parse_ssh_routes(outputs, "Unknown")
        by_key = {(r["dest"], r["prefix_length"]): r for r in routes}

        self.assertIn(("0.0.0.0", 0), by_key)
        self.assertEqual(by_key[("0.0.0.0", 0)]["next_hop"], "192.168.1.1")
        self.assertEqual(by_key[("0.0.0.0", 0)]["protocol"], "static")

        self.assertIn(("10.0.0.0", 24), by_key)
        self.assertEqual(by_key[("10.0.0.0", 24)]["next_hop"], "10.0.0.1")

    def test_empty_outputs(self):
        self.assertEqual(parse_ssh_routes({}, "Cisco"), [])

    def test_invalid_output_ignored(self):
        outputs = {"show ip route": "% Invalid input detected at '^' marker."}
        self.assertEqual(parse_ssh_routes(outputs, "Cisco"), [])
