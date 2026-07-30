from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import importlib.util
from pathlib import Path
import sys
from types import ModuleType
import unittest


ROOT = Path(__file__).resolve().parents[4]


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


TOPOLOGY_NAME = (
    "ansible_collections.sgt_trojan.checkpoint_automation."
    "plugins.module_utils.topology"
)
for package in (
    "ansible_collections",
    "ansible_collections.sgt_trojan",
    "ansible_collections.sgt_trojan.checkpoint_automation",
    "ansible_collections.sgt_trojan.checkpoint_automation.plugins",
    "ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils",
):
    sys.modules.setdefault(package, ModuleType(package))
load_module(ROOT / "plugins" / "module_utils" / "topology.py", TOPOLOGY_NAME)
ansible_package = ModuleType("ansible")
ansible_module_utils = ModuleType("ansible.module_utils")
ansible_basic = ModuleType("ansible.module_utils.basic")
ansible_basic.AnsibleModule = object
sys.modules.setdefault("ansible", ansible_package)
sys.modules.setdefault("ansible.module_utils", ansible_module_utils)
sys.modules.setdefault("ansible.module_utils.basic", ansible_basic)
wrapper = load_module(
    ROOT / "plugins" / "modules" / "cp_automation_target_resolve.py",
    "target_resolve_wrapper",
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


def valid_domain_data() -> list[dict]:
    return [
        {
            "domain": {
                "name": "Domain-A",
                "domain-type": "domain",
                "servers": [
                    {
                        "name": "CMA-A",
                        "type": "management server",
                        "ipv4-address": "198.51.100.10",
                        "active": True,
                    }
                ],
            },
            "objects": [
                {
                    "uid": "cluster-1",
                    "name": "Cluster-A",
                    "type": "simple-cluster",
                    "cluster-member-names": ["Member-A", "Member-B"],
                },
                {
                    "uid": "member-1",
                    "name": "Member-A",
                    "type": "cluster-member",
                    "ipv4-address": "192.0.2.10",
                },
                {
                    "uid": "member-2",
                    "name": "Member-B",
                    "type": "cluster-member",
                    "ipv4-address": "192.0.2.11",
                },
            ],
            "cluster_details": {
                "cluster-1": {
                    "uid": "cluster-1",
                    "name": "Cluster-A",
                    "cluster-members": [
                        {"name": "Member-A", "ip-address": "192.0.2.10"},
                        {"name": "Member-B", "ip-address": "192.0.2.11"},
                    ],
                }
            },
        }
    ]


class TargetResolveModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original = wrapper.AnsibleModule
        wrapper.AnsibleModule = FakeAnsibleModule

    def tearDown(self) -> None:
        wrapper.AnsibleModule = self.original

    def test_success_is_read_only_and_returns_resolved_shape(self) -> None:
        FakeAnsibleModule.params = {
            "target_ips": ["192.0.2.10", "192.0.2.11"],
            "domain_data": valid_domain_data(),
            "preferred_domain": "Domain-A",
        }
        with self.assertRaises(ExitJson) as caught:
            wrapper.run_module()
        self.assertFalse(caught.exception.payload["changed"])
        self.assertEqual(
            caught.exception.payload["resolved"]["cluster_name"],
            "Cluster-A",
        )
        self.assertTrue(FakeAnsibleModule.init_kwargs["supports_check_mode"])
        domain_spec = FakeAnsibleModule.init_kwargs["argument_spec"]["domain_data"]
        self.assertEqual(
            set(domain_spec["options"]),
            {"domain", "objects", "cluster_details"},
        )

    def test_failure_preserves_stable_category(self) -> None:
        FakeAnsibleModule.params = {
            "target_ips": ["not-an-address"],
            "domain_data": valid_domain_data(),
            "preferred_domain": "",
        }
        with self.assertRaises(FailJson) as caught:
            wrapper.run_module()
        self.assertFalse(caught.exception.payload["changed"])
        self.assertEqual(caught.exception.payload["category"], "INVALID_INPUT")


if __name__ == "__main__":
    unittest.main()
