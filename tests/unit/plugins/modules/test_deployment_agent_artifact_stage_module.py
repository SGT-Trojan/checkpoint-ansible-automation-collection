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


sys.modules.setdefault(
    (
        "ansible_collections.sgt_trojan.checkpoint_automation.plugins."
        "module_utils.deployment_agent_reconcile"
    ),
    load_module(
        ROOT / "plugins/module_utils/deployment_agent_reconcile.py",
        f"{PACKAGE}.deployment_agent_reconcile",
    ),
)
sys.modules.setdefault(
    (
        "ansible_collections.sgt_trojan.checkpoint_automation.plugins."
        "module_utils.deployment_agent_execution_preflight"
    ),
    load_module(
        ROOT / "plugins/module_utils/deployment_agent_execution_preflight.py",
        f"{PACKAGE}.deployment_agent_execution_preflight",
    ),
)
utility = load_module(
    ROOT / "plugins/module_utils/deployment_agent_artifact_staging.py",
    f"{PACKAGE}.deployment_agent_artifact_staging",
)

sys.modules.setdefault("ansible", ModuleType("ansible"))
sys.modules.setdefault("ansible.module_utils", ModuleType("ansible.module_utils"))
ansible_basic = sys.modules.setdefault(
    "ansible.module_utils.basic", ModuleType("ansible.module_utils.basic")
)
ansible_basic.AnsibleModule = object
wrapper = load_module(
    ROOT / "plugins/modules/cp_automation_deployment_agent_artifact_stage.py",
    "deployment_agent_artifact_stage_wrapper",
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
    check_mode = False

    def __init__(self, **kwargs):
        type(self).init_kwargs = kwargs
        self.params = dict(type(self).params)
        self.check_mode = type(self).check_mode

    def exit_json(self, **kwargs):
        raise ExitJson(kwargs)

    def fail_json(self, **kwargs):
        raise FailJson(kwargs)


class DeploymentAgentArtifactStageModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_module = wrapper.AnsibleModule
        self.original_stage = wrapper.stage_deployment_agent_artifact
        wrapper.AnsibleModule = FakeAnsibleModule
        FakeAnsibleModule.params = {
            "lease": {},
            "update_plan": {},
            "member_target_id": "member-a",
            "member_address": "198.51.100.10",
            "member_targets": [],
            "runtime_commit": "1" * 40,
            "tls_validation_enabled": True,
            "lab_tls_exception_acknowledged": False,
            "staging_root": "/var/lib/checkpoint-automation/staging",
        }
        FakeAnsibleModule.check_mode = False

    def tearDown(self) -> None:
        wrapper.AnsibleModule = self.original_module
        wrapper.stage_deployment_agent_artifact = self.original_stage

    def test_success_preserves_changed_and_staging_evidence(self) -> None:
        wrapper.stage_deployment_agent_artifact = lambda **kwargs: {
            "changed": True,
            "staging": {"sha256": "a" * 64},
            "authorization": {"authorized": True},
        }
        with self.assertRaises(ExitJson) as caught:
            wrapper.run_module()
        self.assertTrue(caught.exception.payload["changed"])
        self.assertEqual(
            caught.exception.payload["staging"]["sha256"], "a" * 64
        )
        self.assertTrue(FakeAnsibleModule.init_kwargs["supports_check_mode"])
        self.assertTrue(
            FakeAnsibleModule.init_kwargs["argument_spec"]["staging_root"]["required"]
        )

    def test_check_mode_is_forwarded_and_failure_is_unchanged(self) -> None:
        FakeAnsibleModule.check_mode = True

        def reject(**kwargs):
            self.assertTrue(kwargs["check_mode"])
            raise utility.DeploymentAgentArtifactStagingError(
                "EXECUTION_MODE_INVALID", "offline rejection"
            )

        wrapper.stage_deployment_agent_artifact = reject
        with self.assertRaises(FailJson) as caught:
            wrapper.run_module()
        self.assertEqual(
            caught.exception.payload["category"], "EXECUTION_MODE_INVALID"
        )
        self.assertFalse(caught.exception.payload["changed"])


if __name__ == "__main__":
    unittest.main()
