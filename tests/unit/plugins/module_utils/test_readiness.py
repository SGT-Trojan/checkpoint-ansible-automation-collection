from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import importlib.util
from pathlib import Path
import sys
from types import ModuleType
import unittest


ROOT = Path(__file__).resolve().parents[4]
PACKAGE = (
    "ansible_collections.sgt_trojan.checkpoint_automation."
    "plugins.module_utils"
)
for package in (
    "ansible_collections",
    "ansible_collections.sgt_trojan",
    "ansible_collections.sgt_trojan.checkpoint_automation",
    "ansible_collections.sgt_trojan.checkpoint_automation.plugins",
    PACKAGE,
):
    sys.modules.setdefault(package, ModuleType(package))


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


load_module(
    ROOT / "plugins" / "module_utils" / "cluster_observations.py",
    f"{PACKAGE}.cluster_observations",
)
readiness = load_module(
    ROOT / "plugins" / "module_utils" / "readiness.py",
    "checkpoint_readiness",
)


def member(
    name: str,
    address: str,
    state: str,
    *,
    pnotes_ok: object = True,
    interfaces_ok: object = True,
    icap_ok: object = True,
) -> dict:
    return {
        "name": name,
        "address": address,
        "cluster_state": state,
        "pnotes_ok": pnotes_ok,
        "interfaces_ok": interfaces_ok,
        "icap_ok": icap_ok,
        "required_interfaces": 2,
        "required_secured_interfaces": 1,
        "declared_virtual_interfaces": 1,
        "interfaces": [
            {
                "name": "eth0",
                "markers": ["S"],
                "sync": True,
                "monitored": True,
            },
            {
                "name": "eth1",
                "markers": [],
                "sync": False,
                "monitored": True,
            },
        ],
        "virtual_interfaces": [{"name": "eth1", "ip": "192.0.2.254"}],
    }


def healthy_members() -> list[dict]:
    return [
        member("Member-A", "192.0.2.10", "ACTIVE"),
        member("Member-B", "192.0.2.11", "STANDBY"),
    ]


class ReadinessTests(unittest.TestCase):
    def test_healthy_two_member_cluster_is_ready(self) -> None:
        result = readiness.decide_readiness(
            healthy_members(),
            icap_mode="required",
            expected_active="192.0.2.10",
            expected_standby="Member-B",
        )
        self.assertTrue(result["ready"])
        self.assertEqual(result["active_member"]["name"], "Member-A")
        self.assertEqual(result["standby_member"]["name"], "Member-B")

    def test_one_active_and_zero_standby_fails(self) -> None:
        members = healthy_members()
        members[1]["cluster_state"] = "DOWN"
        result = readiness.decide_readiness(members)
        self.assertFalse(result["ready"])
        self.assertIn(
            "expected exactly one STANDBY member, observed 0",
            result["reasons"],
        )

    def test_decorated_active_state_is_not_accepted(self) -> None:
        members = healthy_members()
        members[0]["cluster_state"] = "ACTIVE(!)"
        result = readiness.decide_readiness(members)
        self.assertFalse(result["ready"])
        self.assertIn(
            "Member-A: unsupported ClusterXL state ACTIVE(!)",
            result["reasons"],
        )

    def test_two_active_members_fail(self) -> None:
        members = healthy_members()
        members[1]["cluster_state"] = "ACTIVE"
        result = readiness.decide_readiness(members)
        self.assertFalse(result["ready"])
        self.assertIn(
            "expected exactly one ACTIVE member, observed 2",
            result["reasons"],
        )

    def test_required_icap_needs_explicit_true(self) -> None:
        for value in (None, False, "true"):
            members = healthy_members()
            members[1]["icap_ok"] = value
            with self.subTest(value=value):
                result = readiness.decide_readiness(
                    members,
                    icap_mode="required",
                )
                self.assertFalse(result["ready"])

    def test_optional_and_disabled_icap_do_not_gate(self) -> None:
        for mode in ("optional", "disabled"):
            members = healthy_members()
            members[0]["icap_ok"] = False
            members[1]["icap_ok"] = None
            with self.subTest(mode=mode):
                self.assertTrue(
                    readiness.decide_readiness(members, icap_mode=mode)["ready"]
                )

    def test_pnotes_and_interfaces_require_literal_true(self) -> None:
        for key in ("pnotes_ok", "interfaces_ok"):
            members = healthy_members()
            members[0][key] = "true"
            with self.subTest(key=key):
                self.assertFalse(readiness.decide_readiness(members)["ready"])

    def test_wrong_expected_owner_fails(self) -> None:
        result = readiness.decide_readiness(
            healthy_members(),
            expected_active="Member-B",
        )
        self.assertFalse(result["ready"])
        self.assertIn("expected ACTIVE member 'Member-B' was not observed", result["reasons"])

    def test_exact_interface_baseline_passes(self) -> None:
        members = healthy_members()
        baseline = healthy_members()
        result = readiness.decide_readiness(
            members,
            baseline_members=baseline,
        )
        self.assertTrue(result["ready"])
        self.assertTrue(result["baseline_checked"])

    def test_interface_identity_drift_fails(self) -> None:
        members = healthy_members()
        baseline = healthy_members()
        members[1]["virtual_interfaces"][0]["ip"] = "192.0.2.253"
        result = readiness.decide_readiness(
            members,
            baseline_members=baseline,
        )
        self.assertFalse(result["ready"])
        self.assertIn(
            "Member-B: cluster interface identity differs from baseline",
            result["reasons"],
        )

    def test_incomplete_baseline_interface_inventory_is_rejected(self) -> None:
        baseline = healthy_members()
        del baseline[0]["interfaces"]
        with self.assertRaises(readiness.ReadinessError) as caught:
            readiness.decide_readiness(
                healthy_members(),
                baseline_members=baseline,
            )
        self.assertEqual(caught.exception.category, "OBSERVATION_INCOMPLETE")

    def test_baseline_member_identity_must_match(self) -> None:
        baseline = healthy_members()
        baseline[1]["address"] = "192.0.2.99"
        result = readiness.decide_readiness(
            healthy_members(),
            baseline_members=baseline,
        )
        self.assertFalse(result["ready"])
        self.assertIn(
            "current member identities do not match the baseline",
            result["reasons"],
        )

    def test_duplicate_name_or_address_is_invalid(self) -> None:
        for key in ("name", "address"):
            members = healthy_members()
            members[1][key] = members[0][key]
            with self.subTest(key=key), self.assertRaises(
                readiness.ReadinessError
            ) as caught:
                readiness.decide_readiness(members)
            self.assertEqual(caught.exception.category, "INVALID_INPUT")

    def test_member_count_is_exact(self) -> None:
        for members in ([], healthy_members()[:1], healthy_members() * 2):
            with self.subTest(count=len(members)), self.assertRaises(
                readiness.ReadinessError
            ) as caught:
                readiness.decide_readiness(members)
            self.assertEqual(caught.exception.category, "UNSUPPORTED_TOPOLOGY")

    def test_invalid_icap_mode_is_rejected(self) -> None:
        with self.assertRaises(readiness.ReadinessError) as caught:
            readiness.decide_readiness(healthy_members(), icap_mode="skip")
        self.assertEqual(caught.exception.category, "INVALID_INPUT")

    def test_invalid_member_address_is_rejected(self) -> None:
        members = healthy_members()
        members[0]["address"] = "not-an-address"
        with self.assertRaises(readiness.ReadinessError) as caught:
            readiness.decide_readiness(members)
        self.assertEqual(caught.exception.category, "INVALID_INPUT")

    def test_ipv6_member_addresses_are_normalized(self) -> None:
        members = healthy_members()
        members[0]["address"] = "2001:0db8::10"
        result = readiness.decide_readiness(
            members,
            expected_active="2001:db8::10",
        )
        self.assertTrue(result["ready"])
        self.assertEqual(result["active_member"]["address"], "2001:db8::10")

        result = readiness.decide_readiness(
            members,
            expected_active="2001:0db8:0:0:0:0:0:10",
        )
        self.assertTrue(result["ready"])


if __name__ == "__main__":
    unittest.main()
