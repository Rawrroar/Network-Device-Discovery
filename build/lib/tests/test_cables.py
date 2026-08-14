"""Tests for cable linking from LLDP/CDP neighbor data."""

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from nautobot.dcim.models import Cable, Device, DeviceType, Interface, Location, LocationType, Manufacturer
from nautobot.extras.models import Role, Status
from nautobot.ipam.models import IPAddress, Namespace, Prefix

from nautobot_plugin_device_auto_discovery.jobs import (
    _build_interface_index_map,
    _find_device_by_neighbor_name,
    _find_interface_by_ip,
    _resolve_remote_interface,
    get_cable_status,
    link_neighbors_to_cables,
    neighbor_management_ip,
)
from nautobot_plugin_device_auto_discovery.models import DiscoveryScan, DiscoveryResult


class CableLinkingTestBase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.location_type = LocationType.objects.create(name="Cable Test Type", nestable=True)
        cls.location = Location.objects.create(
            name="Cable Test Location",
            location_type=cls.location_type,
            status=Status.objects.get_for_model(Location).first(),
        )
        cls.role = Role.objects.create(name="Cable Test Role", color="green")
        cls.device_status = Status.objects.get_for_model(Device).first()

        mfr = Manufacturer.objects.create(name="Cisco")
        dt = DeviceType.objects.create(model="Test 9300", manufacturer=mfr)

        cls.device_a = Device.objects.create(
            name="leaf-a",
            device_type=dt,
            role=cls.role,
            location=cls.location,
            status=cls.device_status,
        )
        cls.device_b = Device.objects.create(
            name="leaf-b",
            device_type=dt,
            role=cls.role,
            location=cls.location,
            status=cls.device_status,
        )
        cls.iface_a = Interface.objects.create(device=cls.device_a, name="GigabitEthernet0/0/1")
        cls.iface_b = Interface.objects.create(device=cls.device_b, name="GigabitEthernet0/0/2")

        cable_status = Status.objects.get_for_model(Cable).filter(name="Connected").first()
        if not cable_status:
            cable_status = Status.objects.create(name="Connected", color="green")
            cable_status.content_types.add(ContentType.objects.get_for_model(Cable))

        cls.namespace, _ = Namespace.objects.get_or_create(name="Cable Test Namespace")
        cls.prefix = Prefix.objects.create(
            prefix="10.99.0.0/24",
            namespace=cls.namespace,
            status=Status.objects.get_for_model(Prefix).first(),
        )

    @staticmethod
    def _make_scan():
        return DiscoveryScan.objects.create(
            name="Cable Test Scan",
            scan_method=DiscoveryScan.ScanMethod.SNMP,
            target_network="10.99.0.0/24",
            status="completed",
        )


class NeighborResolutionTests(CableLinkingTestBase):
    def test_find_device_by_exact_name(self):
        self.assertEqual(_find_device_by_neighbor_name("leaf-b"), self.device_b)

    def test_find_device_by_short_name(self):
        self.assertEqual(_find_device_by_neighbor_name("leaf-b.example.com"), self.device_b)

    def test_find_device_unknown_name(self):
        self.assertIsNone(_find_device_by_neighbor_name("does-not-exist"))
        self.assertIsNone(_find_device_by_neighbor_name(""))

    def test_find_interface_by_ip(self):
        ip_obj = IPAddress.objects.create(
            address="10.99.0.10/24",
            namespace=self.namespace,
            status=Status.objects.get_for_model(IPAddress).first(),
        )
        ip_obj.assigned_object = self.iface_b
        ip_obj.save()
        self.assertEqual(_find_interface_by_ip("10.99.0.10"), self.iface_b)
        self.assertIsNone(_find_interface_by_ip("10.99.0.99"))
        self.assertIsNone(_find_interface_by_ip("not-an-ip"))

    def test_resolve_remote_by_ip_takes_priority(self):
        ip_obj = IPAddress.objects.create(
            address="10.99.0.11/24",
            namespace=self.namespace,
            status=Status.objects.get_for_model(IPAddress).first(),
        )
        ip_obj.assigned_object = self.iface_b
        ip_obj.save()
        neighbor = {"remote_ip": "10.99.0.11", "remote_name": "wrong-name", "remote_port": "GiX"}
        self.assertEqual(_resolve_remote_interface(neighbor), self.iface_b)

    def test_resolve_remote_by_name_and_port(self):
        neighbor = {
            "remote_ip": "",
            "remote_name": "leaf-b",
            "remote_port": "GigabitEthernet0/0/2",
        }
        self.assertEqual(_resolve_remote_interface(neighbor), self.iface_b)

    def test_resolve_remote_unresolvable(self):
        self.assertIsNone(_resolve_remote_interface({"remote_ip": "", "remote_name": "", "remote_port": ""}))

    def test_build_interface_index_map(self):
        mapping = _build_interface_index_map(
            self.device_a,
            [{"index": "1", "name": "GigabitEthernet0/0/1"}, {"index": "2", "name": "GigabitEthernet0/0/2"}],
        )
        self.assertEqual(mapping.get("1"), self.iface_a)
        self.assertEqual(len(mapping), 1)

    def test_neighbor_management_ip_prefers_remote_ip(self):
        neighbor = {"remote_ip": "10.99.0.42", "remote_name": "ignored"}
        self.assertEqual(neighbor_management_ip(neighbor), "10.99.0.42")

    def test_neighbor_management_ip_uses_primary_ip_of_matching_device(self):
        ip_obj = IPAddress.objects.create(
            address="10.99.0.50/24",
            namespace=self.namespace,
            status=Status.objects.get_for_model(IPAddress).first(),
        )
        self.device_b.primary_ip4 = ip_obj
        self.device_b.save()
        self.assertEqual(neighbor_management_ip({"remote_ip": "", "remote_name": "leaf-b"}), "10.99.0.50")

    def test_neighbor_management_ip_unresolvable(self):
        self.assertIsNone(neighbor_management_ip({"remote_ip": "", "remote_name": "no-such-host-anywhere"}))

    def test_get_cable_status_returns_connected(self):
        self.assertEqual(get_cable_status().name, "Connected")


class LinkNeighborsToCablesTests(CableLinkingTestBase):
    def test_creates_cable_when_both_ends_resolvable(self):
        scan = self._make_scan()
        DiscoveryResult.objects.create(
            scan=scan,
            ip_address="10.99.0.1",
            hostname="leaf-a",
            discovery_method="snmp",
            result_status=DiscoveryResult.ResultStatus.NEW,
            nautobot_device=self.device_a,
            discovered_data={
                "interfaces": [{"index": "1", "name": "GigabitEthernet0/0/1"}],
                "neighbors": [
                    {
                        "protocol": "lldp",
                        "local_if_index": "1",
                        "remote_name": "leaf-b",
                        "remote_port": "GigabitEthernet0/0/2",
                        "remote_ip": "",
                    }
                ],
            },
        )
        created = link_neighbors_to_cables(scan, {"create_cables": True})
        self.assertEqual(created, 1)

        cable = Cable.objects.get(termination_a_id=self.iface_a.pk, termination_b_id=self.iface_b.pk)
        self.assertEqual(cable.status.name, "Connected")
        self.assertEqual(cable.label, f"auto-discovery {scan.name}")
        scan.refresh_from_db()

    def test_is_idempotent(self):
        scan = self._make_scan()
        DiscoveryResult.objects.create(
            scan=scan,
            ip_address="10.99.0.1",
            hostname="leaf-a",
            discovery_method="snmp",
            result_status=DiscoveryResult.ResultStatus.NEW,
            nautobot_device=self.device_a,
            discovered_data={
                "interfaces": [{"index": "1", "name": "GigabitEthernet0/0/1"}],
                "neighbors": [
                    {
                        "protocol": "lldp",
                        "local_if_index": "1",
                        "remote_name": "leaf-b",
                        "remote_port": "GigabitEthernet0/0/2",
                        "remote_ip": "",
                    }
                ],
            },
        )
        self.assertEqual(link_neighbors_to_cables(scan, {"create_cables": True}), 1)
        self.assertEqual(link_neighbors_to_cables(scan, {"create_cables": True}), 0)
        self.assertEqual(Cable.objects.filter(termination_a_id=self.iface_a.pk).count(), 1)

    def test_creates_nothing_when_disabled(self):
        scan = self._make_scan()
        DiscoveryResult.objects.create(
            scan=scan,
            ip_address="10.99.0.1",
            hostname="leaf-a",
            discovery_method="snmp",
            result_status=DiscoveryResult.ResultStatus.NEW,
            nautobot_device=self.device_a,
            discovered_data={
                "interfaces": [{"index": "1", "name": "GigabitEthernet0/0/1"}],
                "neighbors": [
                    {
                        "protocol": "lldp",
                        "local_if_index": "1",
                        "remote_name": "leaf-b",
                        "remote_port": "GigabitEthernet0/0/2",
                        "remote_ip": "",
                    }
                ],
            },
        )
        self.assertEqual(link_neighbors_to_cables(scan, {"create_cables": False}), 0)
        self.assertEqual(Cable.objects.count(), 0)

    def test_skips_unresolvable_neighbors(self):
        scan = self._make_scan()
        DiscoveryResult.objects.create(
            scan=scan,
            ip_address="10.99.0.1",
            hostname="leaf-a",
            discovery_method="snmp",
            result_status=DiscoveryResult.ResultStatus.NEW,
            nautobot_device=self.device_a,
            discovered_data={
                "interfaces": [{"index": "1", "name": "GigabitEthernet0/0/1"}],
                "neighbors": [
                    {
                        "protocol": "lldp",
                        "local_if_index": "1",
                        "remote_name": "no-such-device",
                        "remote_port": "Gi1",
                        "remote_ip": "",
                    }
                ],
            },
        )
        self.assertEqual(link_neighbors_to_cables(scan, {"create_cables": True}), 0)
        self.assertEqual(Cable.objects.count(), 0)

    def test_skips_result_without_device(self):
        scan = self._make_scan()
        DiscoveryResult.objects.create(
            scan=scan,
            ip_address="10.99.0.1",
            hostname="leaf-a",
            discovery_method="snmp",
            result_status=DiscoveryResult.ResultStatus.NEW,
            discovered_data={
                "interfaces": [],
                "neighbors": [],
            },
        )
        self.assertEqual(link_neighbors_to_cables(scan, {"create_cables": True}), 0)
        self.assertEqual(Cable.objects.count(), 0)
