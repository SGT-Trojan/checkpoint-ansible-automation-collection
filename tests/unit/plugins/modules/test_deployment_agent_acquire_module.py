from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type


import importlib.util
from datetime import datetime, timezone
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
    "ansible_collections.check_point",
    "ansible_collections.check_point.gaia",
    "ansible_collections.check_point.gaia.plugins",
    "ansible_collections.check_point.gaia.plugins.module_utils",
):
    sys.modules.setdefault(package, ModuleType(package))


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


deployment_agent = load(
    ROOT / "plugins/module_utils/deployment_agent.py",
    f"{PACKAGE}.deployment_agent",
)
acquisition = load(
    ROOT / "plugins/module_utils/deployment_agent_acquisition.py",
    f"{PACKAGE}.deployment_agent_acquisition",
)
sys.modules.setdefault("ansible", ModuleType("ansible"))
sys.modules.setdefault("ansible.module_utils", ModuleType("ansible.module_utils"))
basic = sys.modules.setdefault(
    "ansible.module_utils.basic", ModuleType("ansible.module_utils.basic")
)
connection = sys.modules.setdefault(
    "ansible.module_utils.connection", ModuleType("ansible.module_utils.connection")
)
basic.AnsibleModule = object
connection.Connection = object
vendor = ModuleType(
    "ansible_collections.check_point.gaia.plugins.module_utils.checkpoint"
)
vendor.send_request = lambda *args: (500, {})
sys.modules[vendor.__name__] = vendor
wrapper = load(
    ROOT / "plugins/modules/cp_automation_deployment_agent_acquire.py",
    "deployment_agent_acquire_wrapper",
)


class ExitJson(Exception):
    def __init__(self, payload):
        self.payload = payload


class FailJson(Exception):
    def __init__(self, payload):
        self.payload = payload


class FakeModule:
    params = {}
    init_kwargs = {}

    def __init__(self, **kwargs):
        type(self).init_kwargs = kwargs
        self.params = dict(type(self).params)
        self._socket_path = "/offline/socket"
        self.check_mode = True

    def exit_json(self, **kwargs):
        raise ExitJson(kwargs)

    def fail_json(self, **kwargs):
        raise FailJson(kwargs)


class DeploymentAgentAcquireModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original = (
            wrapper.AnsibleModule,
            wrapper.Connection,
            wrapper.acquire,
            wrapper._require_direct_gaia_controller,
            wrapper._current_epoch,
        )
        wrapper.AnsibleModule = FakeModule
        wrapper.Connection = lambda path: ("connection", path)
        wrapper._require_direct_gaia_controller = lambda: None
        wrapper._current_epoch = lambda: datetime(
            2026, 8, 28, 14, 0, tzinfo=timezone.utc
        ).timestamp()
        FakeModule.params = {
            "member_address": "192.0.2.10",
            "version": None,
            "authorization_expires_at": "2026-08-28T14:05:00Z",
            "timeout_seconds": 30,
            "poll_interval_seconds": 2,
        }

    def tearDown(self) -> None:
        (
            wrapper.AnsibleModule,
            wrapper.Connection,
            wrapper.acquire,
            wrapper._require_direct_gaia_controller,
            wrapper._current_epoch,
        ) = self.original

    def test_success_is_read_only_typed_and_address_bound(self) -> None:
        captured = {}

        def fake_acquire(**kwargs):
            captured.update(kwargs)
            return {
                "task_id": "sanitized",
                "polls": 1,
                "enabled": True,
                "build": 2771,
                "cloud_state": "current",
            }

        wrapper.acquire = fake_acquire
        with self.assertRaises(ExitJson) as caught:
            wrapper.run_module()
        self.assertFalse(caught.exception.payload["changed"])
        self.assertEqual(
            caught.exception.payload["observation"]["member_address"],
            "192.0.2.10",
        )
        self.assertTrue(FakeModule.init_kwargs["supports_check_mode"])
        spec = FakeModule.init_kwargs["argument_spec"]
        for forbidden in ("script", "command", "path", "args", "environment"):
            self.assertNotIn(forbidden, spec)
        self.assertEqual(captured["timeout_seconds"], 30)

    def test_invalid_inputs_fail_before_connection(self) -> None:
        hostile = (
            ("member_address", "member.example.invalid"),
            ("timeout_seconds", 4),
            ("poll_interval_seconds", 0),
            ("authorization_expires_at", "not-a-time"),
            ("version", "../1"),
        )
        for key, value in hostile:
            with self.subTest(key=key):
                FakeModule.params[key] = value
                wrapper.Connection = lambda path: self.fail("must not connect")
                with self.assertRaises(FailJson) as caught:
                    wrapper.run_module()
                self.assertEqual(
                    caught.exception.payload["category"],
                    "ACQUISITION_INVALID",
                )
                FakeModule.params = {
                    "member_address": "192.0.2.10",
                    "version": None,
                    "authorization_expires_at": "2026-08-28T14:05:00Z",
                    "timeout_seconds": 30,
                    "poll_interval_seconds": 2,
                }

    def test_expired_and_unbounded_authorization_fail_before_connection(self) -> None:
        wrapper.Connection = lambda path: self.fail("must not connect")
        for value in (
            "2026-08-28T14:00:00Z",
            "2026-08-28T14:15:01Z",
            "2999-01-01T00:00:00Z",
        ):
            with self.subTest(value=value):
                FakeModule.params["authorization_expires_at"] = value
                with self.assertRaises(FailJson) as caught:
                    wrapper.run_module()
                self.assertEqual(
                    caught.exception.payload["category"],
                    "ACQUISITION_INVALID",
                )

    def test_acquisition_failure_preserves_task_identity(self) -> None:
        def fail_acquire(**kwargs):
            raise acquisition.DeploymentAgentAcquisitionError(
                "ACQUISITION_TIMEOUT",
                "fixed operation timed out",
                task_id="63c53f94-319d-444a-8c43-ec2584bcf985",
            )

        wrapper.acquire = fail_acquire
        with self.assertRaises(FailJson) as caught:
            wrapper.run_module()
        self.assertEqual(caught.exception.payload["category"], "ACQUISITION_TIMEOUT")
        self.assertIn("task_id", caught.exception.payload)
        self.assertFalse(caught.exception.payload["changed"])


if __name__ == "__main__":
    unittest.main()
