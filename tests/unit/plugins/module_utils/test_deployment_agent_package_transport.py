from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

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

sys.modules[
    (
        "ansible_collections.sgt_trojan.checkpoint_automation.plugins."
        "module_utils.deployment_agent_artifact_staging"
    )
] = deployment_agent_artifact_staging

from plugins.module_utils import deployment_agent_package_transport  # noqa: E402


NOW = datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)
EXPIRED = datetime(2026, 7, 30, 12, 6, tzinfo=timezone.utc)
COMMIT = "1" * 40
CONTENT = b"synthetic deployment agent binary package"
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


class DeploymentAgentPackageTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.home = root / "remote-home"
        self.home.mkdir(mode=0o700)
        package_name = "DeploymentAgent_00002771.tgz"
        checksum = hashlib.sha256(CONTENT).hexdigest()
        source = root / package_name
        source.write_bytes(CONTENT)
        binding = deployment_agent_package.bind_deployment_agent_package(
            {
                "name": "update-agent",
                "action": "upgrade",
                "package_type": "deployment_agent",
                "package_name": package_name,
                "target_ids": ["member-a", "member-b"],
                "requires_present": [],
                "requires_absent": [],
                "source_path": str(source),
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
        self.staged = root / f"{checksum}-{package_name}"
        self.staged.write_bytes(CONTENT)
        self.staged.chmod(0o400)
        self.staging = {
            "path": str(self.staged),
            "size": len(CONTENT),
            "sha256": checksum,
            "plan_sha256": self.plan["plan_sha256"],
        }

    def tearDown(self) -> None:
        if self.staged.is_symlink():
            self.staged.unlink()
        elif self.staged.exists():
            self.staged.chmod(0o600)
        self.temporary.cleanup()

    def lease(self, **overrides) -> dict:
        value = {
            "lease_id": "63c53f94-319d-444a-8c43-ec2584bcf985",
            "issued_at": "2026-07-30T11:55:00Z",
            "expires_at": "2026-07-30T12:05:00Z",
            "operation": "deployment_agent_update",
            "execution_mode": "mutating",
            "tls_validation_mode": "strict",
            "candidate_commit": COMMIT,
            "plan_sha256": self.plan["plan_sha256"],
            "binding_sha256": self.plan["binding_sha256"],
            "member_targets": copy.deepcopy(MEMBERS),
        }
        value.update(overrides)
        return value

    def values(self, **overrides):
        values = {
            "lease": self.lease(),
            "update_plan": self.plan,
            "staging": self.staging,
            "member_target_id": "member-a",
            "member_address": "198.51.100.10",
            "member_targets": copy.deepcopy(MEMBERS),
            "runtime_commit": COMMIT,
            "tls_validation_enabled": True,
            "lab_tls_exception_acknowledged": False,
            "ssh_host_key_checking_enabled": True,
            "check_mode": False,
            "now": NOW,
        }
        values.update(overrides)
        return values

    def assert_category(self, category, callback):
        with self.assertRaises(
            deployment_agent_package_transport.DeploymentAgentPackageTransportError
        ) as caught:
            callback()
        self.assertEqual(caught.exception.category, category)

    def prepare(self, **overrides):
        return deployment_agent_package_transport.prepare_deployment_agent_package_transport(
            **self.values(**overrides)
        )

    def receive(self, content, offset=0, final=True, **overrides):
        values = {
            **self.values(
                offset=offset,
                content_base64=base64.b64encode(content).decode("ascii"),
                final=final,
                clock=lambda: NOW,
            ),
            **overrides,
        }
        with patch.object(
            deployment_agent_package_transport.pwd,
            "getpwuid",
            return_value=SimpleNamespace(pw_dir=str(self.home)),
        ):
            return deployment_agent_package_transport.receive_deployment_agent_package_chunk(
                **values
            )

    def transport_directory(self) -> Path:
        collection_directory = (
            self.home / deployment_agent_package_transport.TRANSFER_DIRECTORY
        )
        collection_directory.mkdir(mode=0o700)
        package_directory = (
            collection_directory
            / deployment_agent_package_transport.PACKAGE_DIRECTORY
        )
        package_directory.mkdir(mode=0o700)
        return package_directory

    def test_prepares_retained_exact_staged_source(self) -> None:
        source_fd, metadata, plan, authorization = self.prepare()
        try:
            self.assertEqual(os.read(source_fd, len(CONTENT)), CONTENT)
            self.assertEqual(metadata[3], len(CONTENT))
            self.assertEqual(plan["plan_sha256"], self.plan["plan_sha256"])
            self.assertNotIn("member-a", str(authorization))
        finally:
            os.close(source_fd)

    def test_check_commit_target_ssh_and_staging_substitution_fail_closed(self) -> None:
        for category, override in (
            ("EXECUTION_MODE_INVALID", {"check_mode": True}),
            ("COMMIT_MISMATCH", {"runtime_commit": "2" * 40}),
            ("TARGET_MISMATCH", {"member_target_id": "member-b"}),
            (
                "SSH_HOST_KEY_VALIDATION_INVALID",
                {"ssh_host_key_checking_enabled": False},
            ),
        ):
            self.assert_category(
                category, lambda override=override: self.prepare(**override)
            )
        hostile = dict(self.staging)
        hostile["plan_sha256"] = "0" * 64
        self.assert_category(
            "STAGING_MISMATCH", lambda: self.prepare(staging=hostile)
        )

    def test_staged_content_mode_and_symlink_are_rejected(self) -> None:
        self.staged.chmod(0o600)
        self.assert_category("STAGING_MISMATCH", self.prepare)
        self.staged.unlink()
        self.staged.symlink_to(self.home)
        self.assert_category("STAGING_MISMATCH", self.prepare)

    def test_transport_size_ceiling_and_final_marker_fail_closed(self) -> None:
        oversize = dict(self.plan)
        oversize["artifact_size"] = (
            deployment_agent_package_transport.MAX_TRANSPORT_SIZE + 1
        )
        oversize = _rehash_plan(oversize)
        self.assert_category(
            "ARTIFACT_TOO_LARGE",
            lambda: self.prepare(update_plan=oversize),
        )
        self.assert_category(
            "TRANSFER_FINAL_INVALID",
            lambda: self.receive(CONTENT, final=False),
        )

    def test_publishes_only_exact_content_and_is_idempotent(self) -> None:
        first = self.receive(CONTENT)
        published = Path(first["transport"]["path"])
        self.assertTrue(first["changed"])
        self.assertEqual(published.read_bytes(), CONTENT)
        self.assertEqual(published.stat().st_mode & 0o777, 0o400)
        self.assertEqual(first["transport"]["sha256"], self.plan["checksum_sha256"])
        self.assertFalse(self.receive(CONTENT)["changed"])

    def test_chunk_replay_offset_and_noncanonical_content_fail_closed(self) -> None:
        split = len(CONTENT) // 2
        first = self.receive(CONTENT[:split], final=False)
        self.assertEqual(first["progress"]["offset"], split)
        self.assert_category(
            "TRANSFER_REPLAYED",
            lambda: self.receive(CONTENT[:split], final=False),
        )
        self.assert_category(
            "TRANSFER_OFFSET_MISMATCH",
            lambda: self.receive(CONTENT[split:], offset=split - 1, final=False),
        )
        values = self.values(
            offset=0,
            content_base64="not-base64",
            final=True,
            clock=lambda: NOW,
        )
        self.assert_category(
            "TRANSFER_CHUNK_INVALID",
            lambda: deployment_agent_package_transport.receive_deployment_agent_package_chunk(
                **values
            ),
        )

    def test_wrong_content_never_publishes(self) -> None:
        self.assert_category(
            "TRANSFER_CHECKSUM_MISMATCH",
            lambda: self.receive(b"x" * len(CONTENT)),
        )
        published = (
            self.home
            / ".checkpoint-automation"
            / "deployment-agent"
            / f"{self.plan['checksum_sha256']}-{self.plan['package_name']}"
        )
        self.assertFalse(published.exists())
        temporary = published.parent / f".transport-{self.lease()['lease_id']}"
        self.assertFalse(temporary.exists())

    def test_expiry_during_write_fails_without_publication(self) -> None:
        times = iter((NOW, NOW, EXPIRED))
        self.assert_category(
            "LEASE_EXPIRED",
            lambda: self.receive(CONTENT, clock=lambda: next(times)),
        )
        published = (
            self.home
            / ".checkpoint-automation"
            / "deployment-agent"
            / f"{self.plan['checksum_sha256']}-{self.plan['package_name']}"
        )
        self.assertFalse(published.exists())

    def test_destination_collision_is_never_replaced(self) -> None:
        previous_umask = os.umask(0o022)
        try:
            directory = self.transport_directory()
        finally:
            os.umask(previous_umask)
        collision = directory / (
            f"{self.plan['checksum_sha256']}-{self.plan['package_name']}"
        )
        collision.write_bytes(b"hostile")
        self.assert_category(
            "DESTINATION_COLLISION", lambda: self.receive(CONTENT)
        )
        self.assertEqual(collision.read_bytes(), b"hostile")

    def test_unsafe_transport_parent_precedes_destination_collision(self) -> None:
        directory = self.transport_directory()
        directory.parent.chmod(0o755)
        collision = directory / (
            f"{self.plan['checksum_sha256']}-{self.plan['package_name']}"
        )
        collision.write_bytes(b"hostile")
        self.assert_category("REMOTE_PATH_UNSAFE", lambda: self.receive(CONTENT))
        self.assertEqual(collision.read_bytes(), b"hostile")


if __name__ == "__main__":
    unittest.main()
