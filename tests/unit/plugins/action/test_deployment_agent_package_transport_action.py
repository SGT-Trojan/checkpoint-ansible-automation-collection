from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[4]
PACKAGE = (
    "ansible_collections.sgt_trojan.checkpoint_automation."
    "plugins.module_utils"
)
for package_name in (
    "ansible_collections",
    "ansible_collections.sgt_trojan",
    "ansible_collections.sgt_trojan.checkpoint_automation",
    "ansible_collections.sgt_trojan.checkpoint_automation.plugins",
    PACKAGE,
):
    sys.modules.setdefault(package_name, ModuleType(package_name))


class FakeActionBase:
    def run(self, tmp=None, task_vars=None):
        return {}


sys.modules.setdefault("ansible", ModuleType("ansible"))
sys.modules.setdefault("ansible.plugins", ModuleType("ansible.plugins"))
ansible_action = sys.modules.setdefault(
    "ansible.plugins.action", ModuleType("ansible.plugins.action")
)
ansible_action.ActionBase = FakeActionBase


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


utility_name = f"{PACKAGE}.deployment_agent_package_transport"
utility = sys.modules.get(utility_name)
if utility is None:
    for dependency in (
        "deployment_agent_reconcile",
        "deployment_agent_execution_preflight",
        "deployment_agent_artifact_staging",
    ):
        full_name = f"{PACKAGE}.{dependency}"
        if full_name not in sys.modules:
            sys.modules[full_name] = load_module(
                ROOT / f"plugins/module_utils/{dependency}.py", full_name
            )
    utility = load_module(
        ROOT / "plugins/module_utils/deployment_agent_package_transport.py",
        utility_name,
    )

action = load_module(
    ROOT / "plugins/action/cp_automation_deployment_agent_package_transport.py",
    "deployment_agent_package_transport_action",
)


class FakeConnection:
    transport = "ssh"

    def __init__(self):
        self._play_context = SimpleNamespace(remote_addr="198.51.100.10")
        self.host_key_checking = True

    def get_option(self, name):
        if name != "host_key_checking":
            raise KeyError(name)
        return self.host_key_checking


class DeploymentAgentPackageTransportActionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.instance = action.ActionModule()
        self.instance._connection = FakeConnection()
        self.arguments = {
            "lease": {},
            "update_plan": {},
            "staging": {},
            "member_targets": [],
            "runtime_commit": "1" * 40,
            "tls_validation_enabled": True,
            "lab_tls_exception_acknowledged": False,
        }
        self.instance._task = SimpleNamespace(
            args=self.arguments,
            check_mode=False,
        )

    def test_streams_bounded_chunks_and_publishes_only_final_result(self) -> None:
        content = b"x" * (action.CHUNK_SIZE + 1)
        temporary = tempfile.TemporaryFile()
        temporary.write(content)
        temporary.seek(0)
        value = os.fstat(temporary.fileno())
        metadata = (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        plan = {
            "checksum_sha256": hashlib.sha256(content).hexdigest(),
            "artifact_size": len(content),
        }
        authorization = {
            "expires_at": "2999-01-01T00:00:00Z",
        }
        original_prepare = action.prepare_deployment_agent_package_transport
        action.prepare_deployment_agent_package_transport = lambda **kwargs: (
            os.dup(temporary.fileno()),
            metadata,
            plan,
            authorization,
        )
        calls = []

        def execute(**kwargs):
            calls.append(kwargs["module_args"])
            if kwargs["module_args"]["_final"]:
                return {
                    "changed": True,
                    "transport": {"sha256": plan["checksum_sha256"]},
                    "authorization": {"authorized": True},
                }
            return {"changed": True, "progress": {"offset": action.CHUNK_SIZE}}

        self.instance._execute_module = execute
        try:
            result = self.instance.run(
                task_vars={
                    "inventory_hostname": "member-a",
                    "ansible_host": "198.51.100.10",
                }
            )
        finally:
            action.prepare_deployment_agent_package_transport = original_prepare
            temporary.close()
        self.assertTrue(result["changed"])
        self.assertEqual(len(calls), 2)
        self.assertFalse(calls[0]["_final"])
        self.assertTrue(calls[1]["_final"])
        self.assertEqual(base64.b64decode(calls[0]["_content_base64"]), content[:-1])
        self.assertEqual(base64.b64decode(calls[1]["_content_base64"]), content[-1:])
        self.assertNotIn("progress", result)

    def test_rejects_connection_target_host_key_and_argument_substitution(self) -> None:
        task_vars = {
            "inventory_hostname": "member-a",
            "ansible_host": "198.51.100.10",
        }
        self.instance._connection.transport = "httpapi"
        self.assertEqual(
            self.instance.run(task_vars=task_vars)["category"],
            "TRANSPORT_INVALID",
        )
        self.instance._connection.transport = "ssh"
        self.instance._connection.host_key_checking = False
        self.assertEqual(
            self.instance.run(task_vars=task_vars)["category"],
            "SSH_HOST_KEY_VALIDATION_INVALID",
        )
        self.instance._connection.host_key_checking = True
        task_vars["ansible_host"] = "198.51.100.11"
        self.assertEqual(
            self.instance.run(task_vars=task_vars)["category"],
            "TARGET_MISMATCH",
        )
        task_vars["ansible_host"] = "198.51.100.10"
        self.instance._task.args = {**self.arguments, "remote_path": "/tmp/hostile"}
        self.assertEqual(
            self.instance.run(task_vars=task_vars)["category"],
            "TRANSPORT_INPUT_INVALID",
        )


if __name__ == "__main__":
    unittest.main()
