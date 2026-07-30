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
load_module(
    ROOT / "plugins" / "module_utils" / "readiness.py",
    f"{PACKAGE}.readiness",
)
ansible_package = ModuleType("ansible")
ansible_module_utils = ModuleType("ansible.module_utils")
ansible_basic = ModuleType("ansible.module_utils.basic")
ansible_basic.AnsibleModule = object
sys.modules.setdefault("ansible", ansible_package)
sys.modules.setdefault("ansible.module_utils", ansible_module_utils)
sys.modules.setdefault("ansible.module_utils.basic", ansible_basic)
observe_wrapper = load_module(
    ROOT / "plugins" / "modules" / "cp_automation_cluster_observe.py",
    "cluster_observe_wrapper",
)
readiness_wrapper = load_module(
    ROOT / "plugins" / "modules" / "cp_automation_readiness_decide.py",
    "readiness_decide_wrapper",
)


class ExitJson(Exception):
    def __init__(self, payload: dict):
        super().__init__()
        self.payload = payload


class FailJson(Exception):
    def __init__(self, payload: dict):
        super().__init__()
        self.payload = payload


class FakeAnsibleModule:
    params: dict = {}
    init_kwargs: dict = {}

    def __init__(self, **kwargs):
        type(self).init_kwargs = kwargs
        self.params = dict(type(self).params)
        self.check_mode = True

    def exit_json(self, **kwargs):
        raise ExitJson(kwargs)

    def fail_json(self, **kwargs):
        raise FailJson(kwargs)


STATE = """
1 (local) 192.0.2.10 100% ACTIVE Member-A
2 192.0.2.11 0% STANDBY Member-B
Active PNOTEs: None
"""
INTERFACES = """
Required interfaces: 2
Required secured interfaces: 1
Interface Name: Status
eth0 (S) UP
eth1 UP
S - sync
Virtual cluster interfaces: 1
eth1 192.0.2.254
"""


def structured_members() -> list[dict]:
    base = {
        "pnotes_ok": True,
        "interfaces_ok": True,
        "icap_ok": True,
        "required_interfaces": 2,
        "required_secured_interfaces": 1,
        "declared_virtual_interfaces": 1,
        "interfaces": [
            {"name": "eth0", "markers": ["S"], "sync": True, "monitored": True},
            {"name": "eth1", "markers": [], "sync": False, "monitored": True},
        ],
        "virtual_interfaces": [{"name": "eth1", "ip": "192.0.2.254"}],
    }
    return [
        dict(base, name="Member-A", address="192.0.2.10", cluster_state="ACTIVE"),
        dict(base, name="Member-B", address="192.0.2.11", cluster_state="STANDBY"),
    ]


class ReadinessModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_observe = observe_wrapper.AnsibleModule
        self.original_readiness = readiness_wrapper.AnsibleModule
        observe_wrapper.AnsibleModule = FakeAnsibleModule
        readiness_wrapper.AnsibleModule = FakeAnsibleModule

    def tearDown(self) -> None:
        observe_wrapper.AnsibleModule = self.original_observe
        readiness_wrapper.AnsibleModule = self.original_readiness

    def test_observation_wrapper_is_read_only(self) -> None:
        FakeAnsibleModule.params = {
            "name": "Member-A",
            "address": "192.0.2.10",
            "cluster_state_output": STATE,
            "cluster_interfaces_output": INTERFACES,
            "icap_cpwd_output": "",
            "icap_listener_output": "",
            "icap_process_output": "",
        }
        with self.assertRaises(ExitJson) as caught:
            observe_wrapper.run_module()
        self.assertFalse(caught.exception.payload["changed"])
        observation = caught.exception.payload["observation"]
        self.assertEqual(observation["cluster_state"], "ACTIVE")
        self.assertIsNone(observation["icap_ok"])
        self.assertTrue(FakeAnsibleModule.init_kwargs["supports_check_mode"])

    def test_observation_identity_mismatch_fails_closed(self) -> None:
        FakeAnsibleModule.params = {
            "name": "Member-Z",
            "address": "192.0.2.10",
            "cluster_state_output": STATE,
            "cluster_interfaces_output": INTERFACES,
            "icap_cpwd_output": "",
            "icap_listener_output": "",
            "icap_process_output": "",
        }
        with self.assertRaises(FailJson) as caught:
            observe_wrapper.run_module()
        self.assertEqual(caught.exception.payload["category"], "IDENTITY_MISMATCH")
        self.assertFalse(caught.exception.payload["changed"])

    def test_observation_wrapper_rejects_empty_name_and_invalid_address(self) -> None:
        for name, address in (("", "192.0.2.10"), ("Member-A", "invalid")):
            FakeAnsibleModule.params = {
                "name": name,
                "address": address,
                "cluster_state_output": STATE,
                "cluster_interfaces_output": INTERFACES,
                "icap_cpwd_output": "",
                "icap_listener_output": "",
                "icap_process_output": "",
            }
            with self.subTest(name=name, address=address), self.assertRaises(
                FailJson
            ) as caught:
                observe_wrapper.run_module()
            self.assertEqual(
                caught.exception.payload["category"],
                "OBSERVATION_INVALID",
            )
            self.assertFalse(caught.exception.payload["changed"])

    def test_readiness_wrapper_returns_healthy_result(self) -> None:
        FakeAnsibleModule.params = {
            "members": structured_members(),
            "icap_mode": "required",
            "baseline_members": None,
            "expected_active": "Member-A",
            "expected_standby": "Member-B",
            "fail_on_not_ready": True,
        }
        with self.assertRaises(ExitJson) as caught:
            readiness_wrapper.run_module()
        self.assertTrue(caught.exception.payload["readiness"]["ready"])
        self.assertFalse(caught.exception.payload["changed"])
        self.assertTrue(FakeAnsibleModule.init_kwargs["supports_check_mode"])

    def test_readiness_wrapper_fails_on_not_ready_by_default(self) -> None:
        members = structured_members()
        members[1]["cluster_state"] = "DOWN"
        FakeAnsibleModule.params = {
            "members": members,
            "icap_mode": "optional",
            "baseline_members": None,
            "expected_active": "",
            "expected_standby": "",
            "fail_on_not_ready": True,
        }
        with self.assertRaises(FailJson) as caught:
            readiness_wrapper.run_module()
        self.assertEqual(caught.exception.payload["category"], "NOT_READY")
        self.assertFalse(caught.exception.payload["readiness"]["ready"])

    def test_readiness_wrapper_can_report_without_failing(self) -> None:
        members = structured_members()
        members[1]["cluster_state"] = "DOWN"
        FakeAnsibleModule.params = {
            "members": members,
            "icap_mode": "optional",
            "baseline_members": None,
            "expected_active": "",
            "expected_standby": "",
            "fail_on_not_ready": False,
        }
        with self.assertRaises(ExitJson) as caught:
            readiness_wrapper.run_module()
        self.assertFalse(caught.exception.payload["readiness"]["ready"])


if __name__ == "__main__":
    unittest.main()
