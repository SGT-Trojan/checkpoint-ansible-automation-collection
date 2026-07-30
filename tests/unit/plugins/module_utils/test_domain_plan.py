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
    / "domain_plan.py"
)
SPEC = importlib.util.spec_from_file_location("checkpoint_domain_plan", MODULE)
assert SPEC and SPEC.loader
domain_plan = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = domain_plan
SPEC.loader.exec_module(domain_plan)


def server(
    name: str = "CMA-A",
    address: str = "198.51.100.10",
    active: object = True,
    server_type: str = "management server",
) -> dict:
    result = {
        "name": name,
        "type": server_type,
        "ipv4-address": address,
    }
    if active != "absent":
        result["active"] = active
    return result


def domain(
    name: str = "Domain-A",
    servers: list[dict] | None = None,
    domain_type: str = "domain",
) -> dict:
    return {
        "uid": f"uid-{name}",
        "name": name,
        "domain-type": domain_type,
        "servers": servers if servers is not None else [server()],
    }


class DomainPlanTests(unittest.TestCase):
    def assert_category(self, category: str, records: object) -> None:
        with self.assertRaises(domain_plan.DomainPlanError) as caught:
            domain_plan.build_domain_plan(records)
        self.assertEqual(caught.exception.category, category)

    def test_global_domains_are_excluded(self) -> None:
        result = domain_plan.build_domain_plan(
            [
                domain("Global", [], "global domain"),
                domain("Domain-A"),
            ]
        )
        self.assertEqual([item["name"] for item in result], ["Domain-A"])

    def test_non_regular_domain_type_fails_closed(self) -> None:
        row = domain("System Data")
        row["domain-type"] = "mds"
        self.assert_category("DISCOVERY_INCOMPLETE", [row])

    def test_missing_domain_type_fails_closed(self) -> None:
        row = domain("Domain-A")
        row.pop("domain-type")
        self.assert_category("DISCOVERY_INCOMPLETE", [row])

    def test_duplicate_names_are_ambiguous_case_insensitively(self) -> None:
        self.assert_category(
            "AMBIGUOUS",
            [domain("Domain-A"), domain("domain-a")],
        )

    def test_logging_server_is_not_selected_as_cma(self) -> None:
        row = domain(
            servers=[
                server(
                    "CLM-A",
                    "198.51.100.20",
                    True,
                    "dedicated log management server",
                ),
                server("CMA-A", "198.51.100.10", True),
            ]
        )
        result = domain_plan.build_domain_plan([row])
        self.assertEqual(result[0]["cma_name"], "CMA-A")

    def test_multiple_active_cmas_are_ambiguous(self) -> None:
        self.assert_category(
            "AMBIGUOUS",
            [
                domain(
                    servers=[
                        server("CMA-A", "198.51.100.10", True),
                        server("CMA-B", "198.51.100.11", True),
                    ]
                )
            ],
        )

    def test_no_active_cma_is_discovery_incomplete(self) -> None:
        self.assert_category(
            "DISCOVERY_INCOMPLETE",
            [domain(servers=[server(active=False)])],
        )

    def test_malformed_active_state_is_discovery_incomplete(self) -> None:
        self.assert_category(
            "DISCOVERY_INCOMPLETE",
            [domain(servers=[server(active="yes")])],
        )

    def test_conflicting_duplicate_cma_state_fails_closed(self) -> None:
        row = domain(servers=[server(active=True)])
        row["domain-servers"] = [server(active=False)]
        self.assert_category("DISCOVERY_INCOMPLETE", [row])

    def test_identical_duplicate_cma_rows_are_deduplicated(self) -> None:
        row = domain(servers=[server(active=True)])
        row["domain-servers"] = [server(active=True)]
        result = domain_plan.build_domain_plan([row])
        self.assertEqual(result[0]["cma_name"], "CMA-A")

    def test_single_unknown_active_server_preserves_safe_fallback(self) -> None:
        result = domain_plan.build_domain_plan(
            [domain(servers=[server(active="absent")])]
        )
        self.assertEqual(result[0]["cma_name"], "CMA-A")

    def test_multiple_unknown_active_servers_fail_closed(self) -> None:
        self.assert_category(
            "DISCOVERY_INCOMPLETE",
            [
                domain(
                    servers=[
                        server("CMA-A", "198.51.100.10", "absent"),
                        server("CMA-B", "198.51.100.11", "absent"),
                    ]
                )
            ],
        )

    def test_malformed_cma_address_is_discovery_incomplete(self) -> None:
        self.assert_category(
            "DISCOVERY_INCOMPLETE",
            [domain(servers=[server(address="not-an-address")])],
        )

    def test_ipv6_cma_address_is_normalized(self) -> None:
        row = domain(servers=[server(address="2001:0db8::10")])
        row["servers"][0]["ipv6-address"] = row["servers"][0].pop("ipv4-address")
        result = domain_plan.build_domain_plan([row])
        self.assertEqual(result[0]["cma_address"], "2001:db8::10")

    def test_empty_regular_domain_set_is_discovery_incomplete(self) -> None:
        self.assert_category(
            "DISCOVERY_INCOMPLETE",
            [domain("Global", [], "global-domain")],
        )

    def test_sort_and_session_aliases_are_stable(self) -> None:
        first = domain("zeta", [server("CMA-Z", "198.51.100.12")])
        second = domain("Alpha", [server("CMA-A", "198.51.100.10")])
        result = domain_plan.build_domain_plan([first, second])
        self.assertEqual(
            [
                (item["session_name"], item["name"])
                for item in result
            ],
            [
                ("checkpoint_domain_session_0001", "Alpha"),
                ("checkpoint_domain_session_0002", "zeta"),
            ],
        )
        self.assertIs(result[0]["domain"], second)

    def test_empty_name_is_discovery_incomplete(self) -> None:
        self.assert_category("DISCOVERY_INCOMPLETE", [domain("")])

    def test_non_object_row_is_invalid_input(self) -> None:
        self.assert_category("INVALID_INPUT", [domain(), "not-a-domain"])

    def test_non_list_input_is_invalid_input(self) -> None:
        self.assert_category("INVALID_INPUT", (domain(),))


if __name__ == "__main__":
    unittest.main()
