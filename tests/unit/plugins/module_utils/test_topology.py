from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import importlib.util
from pathlib import Path
import sys
import unittest


MODULE = (
    Path(__file__).resolve().parents[4]
    / "plugins"
    / "module_utils"
    / "topology.py"
)
SPEC = importlib.util.spec_from_file_location("checkpoint_topology", MODULE)
assert SPEC and SPEC.loader
topology = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = topology
SPEC.loader.exec_module(topology)


def domain(name: str = "Domain-A", cma: str = "CMA-A") -> dict:
    return {
        "name": name,
        "domain-type": "domain",
        "servers": [
            {
                "name": "Log-A",
                "type": "log server",
                "ipv4-address": "198.51.100.20",
                "active": True,
            },
            {
                "name": cma,
                "type": "management server",
                "ipv4-address": "198.51.100.10",
                "active": True,
            },
        ],
    }


def cluster(uid: str = "cluster-1", name: str = "Cluster-A") -> dict:
    return {
        "uid": uid,
        "name": name,
        "type": "CpmiGatewayCluster",
        "cluster-member-names": ["Member-A", "Member-B"],
        "policy": {"access-policy-name": "Policy-A"},
        "version": "R82",
    }


def member(uid: str, name: str, address: str) -> dict:
    return {
        "uid": uid,
        "name": name,
        "type": "cluster-member",
        "ipv4-address": address,
    }


def detail(
    uid: str = "cluster-1",
    name: str = "Cluster-A",
    rows: list[dict] | None = None,
) -> dict:
    if rows is None:
        rows = [
            {"name": "Member-A", "ip-address": "192.0.2.10"},
            {"name": "Member-B", "ip-address": "192.0.2.11"},
        ]
    return {
        "uid": uid,
        "name": name,
        "type": "simple-cluster",
        "cluster-members": rows,
    }


def domain_data(
    domain_row: dict | None = None,
    cluster_row: dict | None = None,
    cluster_detail: dict | None = None,
) -> dict:
    cluster_row = cluster_row or cluster()
    cluster_detail = cluster_detail or detail()
    return {
        "domain": domain_row or domain(),
        "objects": [
            cluster_row,
            member("member-1", "Member-A", "192.0.2.10"),
            member("member-2", "Member-B", "192.0.2.11"),
        ],
        "cluster_details": {cluster_row["uid"]: cluster_detail},
    }


class TopologyTests(unittest.TestCase):
    def test_resolves_exact_two_member_cluster(self) -> None:
        result = topology.resolve_targets(
            [domain_data()],
            ["192.0.2.10", "192.0.2.11"],
        )
        self.assertEqual(result["domain"], "Domain-A")
        self.assertEqual(result["cma_name"], "CMA-A")
        self.assertEqual(result["cluster_name"], "Cluster-A")
        self.assertEqual(result["policy_package"], "Policy-A")
        self.assertEqual(len(result["members"]), 2)

    def test_invalid_target_is_rejected(self) -> None:
        with self.assertRaises(topology.TopologyError) as caught:
            topology.resolve_targets([domain_data()], ["Take 107"])
        self.assertEqual(caught.exception.category, "INVALID_INPUT")

    def test_clm_is_not_selected_as_cma(self) -> None:
        identity = topology.domain_identity(domain())
        self.assertEqual(identity.cma_name, "CMA-A")

    def test_multiple_active_cmas_fail_closed(self) -> None:
        row = domain()
        row["servers"].append(
            {
                "name": "CMA-B",
                "type": "management server",
                "ipv4-address": "198.51.100.11",
                "active": True,
            }
        )
        with self.assertRaises(topology.TopologyError) as caught:
            topology.resolve_targets([domain_data(domain_row=row)], ["192.0.2.10"])
        self.assertEqual(caught.exception.category, "DISCOVERY_INCOMPLETE")

    def test_member_without_name_fails_closed(self) -> None:
        broken = detail(
            rows=[
                {"name": "Member-A", "ip-address": "192.0.2.10"},
                {"ip-address": "192.0.2.11"},
            ]
        )
        with self.assertRaises(topology.TopologyError) as caught:
            topology.resolve_targets(
                [domain_data(cluster_detail=broken)],
                ["192.0.2.10", "192.0.2.11"],
            )
        self.assertEqual(caught.exception.category, "DISCOVERY_INCOMPLETE")

    def test_duplicate_member_name_fails_closed(self) -> None:
        broken = detail(
            rows=[
                {"name": "Member-A", "ip-address": "192.0.2.10"},
                {"name": "member-a", "ip-address": "192.0.2.11"},
            ]
        )
        with self.assertRaises(topology.TopologyError) as caught:
            topology.resolve_targets(
                [domain_data(cluster_detail=broken)],
                ["192.0.2.10", "192.0.2.11"],
            )
        self.assertEqual(caught.exception.category, "DISCOVERY_INCOMPLETE")

    def test_duplicate_member_address_fails_closed(self) -> None:
        broken = detail(
            rows=[
                {"name": "Member-A", "ip-address": "192.0.2.10"},
                {"name": "Member-B", "ip-address": "192.0.2.10"},
            ]
        )
        with self.assertRaises(topology.TopologyError) as caught:
            topology.resolve_targets(
                [domain_data(cluster_detail=broken)],
                ["192.0.2.10"],
            )
        self.assertEqual(caught.exception.category, "DISCOVERY_INCOMPLETE")

    def test_missing_cluster_detail_fails_closed(self) -> None:
        data = domain_data()
        data["cluster_details"] = {}
        with self.assertRaises(topology.TopologyError) as caught:
            topology.resolve_targets([data], ["192.0.2.10"])
        self.assertEqual(caught.exception.category, "DISCOVERY_INCOMPLETE")

    def test_partial_address_match_is_not_success(self) -> None:
        with self.assertRaises(topology.TopologyError) as caught:
            topology.resolve_targets(
                [domain_data()],
                ["192.0.2.10", "192.0.2.99"],
            )
        self.assertEqual(caught.exception.category, "NOT_FOUND")

    def test_addresses_from_different_clusters_are_ambiguous(self) -> None:
        first = domain_data()
        second_cluster = cluster("cluster-2", "Cluster-B")
        second_cluster["cluster-member-names"] = ["Member-C", "Member-D"]
        second_detail = detail(
            "cluster-2",
            "Cluster-B",
            [
                {"name": "Member-C", "ip-address": "192.0.2.20"},
                {"name": "Member-D", "ip-address": "192.0.2.21"},
            ],
        )
        first["objects"].extend(
            [
                second_cluster,
                member("member-3", "Member-C", "192.0.2.20"),
                member("member-4", "Member-D", "192.0.2.21"),
            ]
        )
        first["cluster_details"]["cluster-2"] = second_detail
        with self.assertRaises(topology.TopologyError) as caught:
            topology.resolve_targets(
                [first],
                ["192.0.2.10", "192.0.2.20"],
            )
        self.assertEqual(caught.exception.category, "AMBIGUOUS")

    def test_duplicate_match_across_domains_is_ambiguous(self) -> None:
        second = domain_data(domain_row=domain("Domain-B", "CMA-B"))
        with self.assertRaises(topology.TopologyError) as caught:
            topology.resolve_targets(
                [domain_data(), second],
                ["192.0.2.10", "192.0.2.11"],
            )
        self.assertEqual(caught.exception.category, "AMBIGUOUS")

    def test_preferred_domain_disambiguates_duplicate(self) -> None:
        second = domain_data(domain_row=domain("Domain-B", "CMA-B"))
        result = topology.resolve_targets(
            [domain_data(), second],
            ["192.0.2.10", "192.0.2.11"],
            preferred_domain="Domain-B",
        )
        self.assertEqual(result["domain"], "Domain-B")

    def test_unknown_preferred_domain_is_rejected(self) -> None:
        with self.assertRaises(topology.TopologyError) as caught:
            topology.resolve_targets(
                [domain_data()],
                ["192.0.2.10", "192.0.2.11"],
                preferred_domain="Domain-Z",
            )
        self.assertEqual(caught.exception.category, "INVALID_INPUT")

    def test_ipv6_addresses_are_structured(self) -> None:
        found = topology.addresses(
            {
                "ipv4-address": "192.0.2.10",
                "comments": "ignore 192.0.2.200",
                "interfaces": [{"ipv6-address": "2001:db8::10"}],
            }
        )
        self.assertEqual(found, {"192.0.2.10", "2001:db8::10"})

    def test_preferred_domain_trims_whitespace_and_matches_cma(self) -> None:
        second = domain_data(domain_row=domain("Domain-B", "CMA-B"))
        for preferred in ("  Domain-B ", " CMA-B  "):
            with self.subTest(preferred=preferred):
                result = topology.resolve_targets(
                    [domain_data(), second],
                    ["192.0.2.10", "192.0.2.11"],
                    preferred_domain=preferred,
                )
                self.assertEqual(result["domain"], "Domain-B")

    def test_match_outside_preferred_domain_is_invalid_input(self) -> None:
        other_cluster = cluster("cluster-2", "Cluster-B")
        other_cluster["cluster-member-names"] = ["Member-C", "Member-D"]
        other_detail = detail(
            "cluster-2",
            "Cluster-B",
            [
                {"name": "Member-C", "ip-address": "192.0.2.20"},
                {"name": "Member-D", "ip-address": "192.0.2.21"},
            ],
        )
        other = domain_data(
            domain_row=domain("Domain-B", "CMA-B"),
            cluster_row=other_cluster,
            cluster_detail=other_detail,
        )
        with self.assertRaises(topology.TopologyError) as caught:
            topology.resolve_targets(
                [domain_data(), other],
                ["192.0.2.10", "192.0.2.11"],
                preferred_domain="Domain-B",
            )
        self.assertEqual(caught.exception.category, "INVALID_INPUT")
        self.assertIn("outside preferred domain", str(caught.exception))

    def test_zero_member_result_is_incomplete(self) -> None:
        empty = detail(rows=[])
        with self.assertRaises(topology.TopologyError) as caught:
            topology.resolve_targets(
                [domain_data(cluster_detail=empty)],
                ["192.0.2.10"],
            )
        self.assertEqual(caught.exception.category, "DISCOVERY_INCOMPLETE")

    def test_duplicate_domain_name_is_incomplete(self) -> None:
        with self.assertRaises(topology.TopologyError) as caught:
            topology.resolve_targets(
                [domain_data(), domain_data()],
                ["192.0.2.10", "192.0.2.11"],
            )
        self.assertEqual(caught.exception.category, "DISCOVERY_INCOMPLETE")

    def test_global_domain_is_ignored(self) -> None:
        global_row = {
            "domain": {"name": "Global", "domain-type": "global domain"},
            "objects": [],
            "cluster_details": {},
        }
        result = topology.resolve_targets(
            [global_row, domain_data()],
            ["192.0.2.10", "192.0.2.11"],
        )
        self.assertEqual(result["domain"], "Domain-A")

    def test_non_regular_domain_type_is_incomplete(self) -> None:
        row = domain_data()
        row["domain"]["domain-type"] = "mds"
        with self.assertRaises(topology.TopologyError) as caught:
            topology.resolve_targets([row], ["192.0.2.10", "192.0.2.11"])
        self.assertEqual(caught.exception.category, "DISCOVERY_INCOMPLETE")

    def test_ipv6_cluster_resolves_end_to_end(self) -> None:
        cluster_row = cluster()
        data = {
            "domain": domain(),
            "objects": [
                cluster_row,
                {
                    "uid": "member-1",
                    "name": "Member-A",
                    "type": "cluster-member",
                    "ipv6-address": "2001:db8::10",
                },
                {
                    "uid": "member-2",
                    "name": "Member-B",
                    "type": "cluster-member",
                    "ipv6-address": "2001:db8::11",
                },
            ],
            "cluster_details": {
                "cluster-1": detail(
                    rows=[
                        {"name": "Member-A", "ipv6-address": "2001:db8::10"},
                        {"name": "Member-B", "ipv6-address": "2001:db8::11"},
                    ]
                )
            },
        }
        result = topology.resolve_targets(
            [data],
            ["2001:db8::10", "2001:db8::11"],
        )
        self.assertEqual(result["matched_ips"], ["2001:db8::10", "2001:db8::11"])

    def test_standalone_gateway_is_outside_scope(self) -> None:
        data = {
            "domain": domain(),
            "objects": [
                {
                    "uid": "gateway-1",
                    "name": "Gateway-A",
                    "type": "simple-gateway",
                    "ipv4-address": "192.0.2.50",
                }
            ],
            "cluster_details": {},
        }
        with self.assertRaises(topology.TopologyError) as caught:
            topology.resolve_targets([data], ["192.0.2.50"])
        self.assertEqual(caught.exception.category, "NOT_FOUND")

    def test_three_member_cluster_is_outside_scope(self) -> None:
        three = detail(
            rows=[
                {"name": "Member-A", "ip-address": "192.0.2.10"},
                {"name": "Member-B", "ip-address": "192.0.2.11"},
                {"name": "Member-C", "ip-address": "192.0.2.12"},
            ]
        )
        with self.assertRaises(topology.TopologyError) as caught:
            topology.resolve_targets(
                [domain_data(cluster_detail=three)],
                ["192.0.2.10", "192.0.2.11"],
            )
        self.assertEqual(caught.exception.category, "UNSUPPORTED_TOPOLOGY")


if __name__ == "__main__":
    unittest.main()
