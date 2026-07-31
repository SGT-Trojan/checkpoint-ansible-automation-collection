from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import ModuleType
import unittest

from plugins.module_utils import deployment_agent_package
from plugins.module_utils import deployment_agent_reconcile
from plugins.module_utils import deployment_agent_update

for package_name in (
    "ansible_collections",
    "ansible_collections.sgt_trojan",
    "ansible_collections.sgt_trojan.checkpoint_automation",
    "ansible_collections.sgt_trojan.checkpoint_automation.plugins",
    "ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils",
):
    sys.modules.setdefault(package_name, ModuleType(package_name))
sys.modules[
    (
        "ansible_collections.sgt_trojan.checkpoint_automation.plugins."
        "module_utils.deployment_agent_reconcile"
    )
] = deployment_agent_reconcile

from plugins.module_utils import deployment_agent_execution_preflight  # noqa: E402

sys.modules[
    (
        "ansible_collections.sgt_trojan.checkpoint_automation.plugins."
        "module_utils.deployment_agent_execution_preflight"
    )
] = deployment_agent_execution_preflight

from plugins.module_utils import deployment_agent_artifact_staging  # noqa: E402


NOW = datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)
EXPIRED = datetime(2026, 7, 30, 12, 6, tzinfo=timezone.utc)
COMMIT = "1" * 40
CONTENT = b"synthetic deployment agent package"
MEMBERS = [
    {"target_id": "member-a", "member_address": "198.51.100.10"},
    {"target_id": "member-b", "member_address": "198.51.100.11"},
]


def _rehash_plan(plan: dict) -> dict:
    changed = dict(plan)
    changed.pop("plan_sha256", None)
    encoded = json.dumps(
        changed, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    changed["plan_sha256"] = hashlib.sha256(encoded).hexdigest()
    return changed


class DeploymentAgentArtifactStagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.source = root / "DeploymentAgent_00002771.tgz"
        self.source.write_bytes(CONTENT)
        self.staging_root = root / "stage"
        self.staging_root.mkdir()
        checksum = hashlib.sha256(CONTENT).hexdigest()
        binding = deployment_agent_package.bind_deployment_agent_package(
            {
                "name": "update-agent",
                "action": "upgrade",
                "package_type": "deployment_agent",
                "package_name": self.source.name,
                "target_ids": ["member-a", "member-b"],
                "requires_present": [],
                "requires_absent": [],
                "source_path": str(self.source),
                "checksum_sha256": checksum,
                "artifact_size": len(CONTENT),
            },
            2771,
            2771,
        )
        self.plan = deployment_agent_update.plan_deployment_agent_update(
            binding,
            [
                {
                    "target_id": "member-a",
                    "enabled": True,
                    "build": 2700,
                    "cloud_state": "update_available",
                },
                {
                    "target_id": "member-b",
                    "enabled": True,
                    "build": 2700,
                    "cloud_state": "update_available",
                },
            ],
            "member-a",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def lease(self, plan=None) -> dict:
        selected = plan or self.plan
        return {
            "lease_id": "63c53f94-319d-444a-8c43-ec2584bcf985",
            "issued_at": "2026-07-30T11:55:00Z",
            "expires_at": "2026-07-30T12:05:00Z",
            "operation": "deployment_agent_update",
            "execution_mode": "mutating",
            "tls_validation_mode": "strict",
            "candidate_commit": COMMIT,
            "plan_sha256": selected["plan_sha256"],
            "binding_sha256": selected["binding_sha256"],
            "member_targets": copy.deepcopy(MEMBERS),
        }

    def stage(self, plan=None, **overrides):
        selected = plan or self.plan
        values = {
            "lease": self.lease(selected),
            "update_plan": selected,
            "member_target_id": "member-a",
            "member_address": "198.51.100.10",
            "member_targets": copy.deepcopy(MEMBERS),
            "runtime_commit": COMMIT,
            "tls_validation_enabled": True,
            "lab_tls_exception_acknowledged": False,
            "staging_root": str(self.staging_root),
            "check_mode": False,
            "now": NOW,
            "clock": lambda: NOW,
        }
        values.update(overrides)
        return deployment_agent_artifact_staging.stage_deployment_agent_artifact(
            **values
        )

    def assert_category(self, category, callback):
        with self.assertRaises(
            deployment_agent_artifact_staging.DeploymentAgentArtifactStagingError
        ) as caught:
            callback()
        self.assertEqual(caught.exception.category, category)

    def test_stages_exact_read_only_content_and_is_idempotent(self) -> None:
        first = self.stage()
        self.assertTrue(first["changed"])
        staged = Path(first["staging"]["path"])
        self.assertEqual(staged.read_bytes(), CONTENT)
        self.assertEqual(staged.stat().st_mode & 0o777, 0o400)
        self.assertEqual(first["staging"]["sha256"], self.plan["checksum_sha256"])
        self.assertNotIn("member-a", str(first["authorization"]))
        self.assertFalse(self.stage()["changed"])

    def test_check_mode_commit_and_target_substitution_fail_before_staging(self) -> None:
        for category, override in (
            ("EXECUTION_MODE_INVALID", {"check_mode": True}),
            ("COMMIT_MISMATCH", {"runtime_commit": "2" * 40}),
            ("TARGET_MISMATCH", {"member_target_id": "member-b"}),
            ("TARGET_MISMATCH", {"member_address": "198.51.100.11"}),
        ):
            self.assert_category(
                category, lambda override=override: self.stage(**override)
            )
        self.assertEqual(list(self.staging_root.iterdir()), [])

    def test_source_content_symlink_and_parent_symlink_fail_closed(self) -> None:
        self.source.write_bytes(b"x" * len(CONTENT))
        self.assert_category("ARTIFACT_MISMATCH", self.stage)
        self.source.unlink()
        self.source.symlink_to(self.staging_root)
        self.assert_category("SYMLINK_REJECTED", self.stage)
        self.source.unlink()
        self.source.write_bytes(CONTENT)

        real_root = Path(self.temporary.name) / "real-stage"
        real_root.mkdir()
        linked_root = Path(self.temporary.name) / "linked-stage"
        linked_root.symlink_to(real_root, target_is_directory=True)
        self.assert_category(
            "PATH_UNSAFE", lambda: self.stage(staging_root=str(linked_root))
        )

    def test_destination_collision_and_symlink_are_never_replaced(self) -> None:
        name = f"{self.plan['checksum_sha256']}-{self.source.name}"
        collision = self.staging_root / name
        collision.write_bytes(b"hostile")
        self.assert_category("DESTINATION_COLLISION", self.stage)
        self.assertEqual(collision.read_bytes(), b"hostile")
        collision.unlink()
        collision.write_bytes(CONTENT)
        collision.chmod(0o600)
        self.assert_category("DESTINATION_COLLISION", self.stage)
        collision.unlink()
        collision.symlink_to(self.source)
        self.assert_category("DESTINATION_COLLISION", self.stage)
        self.assertTrue(collision.is_symlink())

    def test_group_writable_staging_root_is_rejected(self) -> None:
        self.staging_root.chmod(0o770)
        self.assert_category("PATH_UNSAFE", self.stage)
        self.assertEqual(list(self.staging_root.iterdir()), [])

    def test_expiry_during_copy_removes_temporary_content(self) -> None:
        times = iter((NOW, EXPIRED))
        self.assert_category(
            "LEASE_EXPIRED", lambda: self.stage(clock=lambda: next(times))
        )
        self.assertEqual(list(self.staging_root.iterdir()), [])

    def test_oversize_and_package_identity_tampering_are_rejected(self) -> None:
        oversize = dict(self.plan)
        oversize["artifact_size"] = (
            deployment_agent_artifact_staging.MAX_ARTIFACT_SIZE + 1
        )
        oversize = _rehash_plan(oversize)
        self.assert_category(
            "ARTIFACT_TOO_LARGE",
            lambda: self.stage(plan=oversize, lease=self.lease(oversize)),
        )

        hostile = dict(self.plan)
        hostile["package_name"] = "other.tgz"
        hostile = _rehash_plan(hostile)
        self.assert_category(
            "PACKAGE_IDENTITY_INVALID",
            lambda: self.stage(plan=hostile, lease=self.lease(hostile)),
        )

    def test_staged_path_is_content_addressed_and_bounded(self) -> None:
        result = self.stage()
        expected_name = f"{self.plan['checksum_sha256']}-{self.source.name}"
        self.assertEqual(Path(result["staging"]["path"]).name, expected_name)
        self.assertEqual(
            set(result["staging"]), {"path", "size", "sha256", "plan_sha256"}
        )
        leftovers = [
            path.name
            for path in self.staging_root.iterdir()
            if path.name.startswith(".deployment-agent-stage-")
        ]
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
