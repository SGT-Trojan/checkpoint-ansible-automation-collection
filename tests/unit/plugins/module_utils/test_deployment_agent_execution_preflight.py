from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import copy
from datetime import datetime, timezone
import sys
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


NOW = datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)
COMMIT = "1" * 40
MEMBERS = [
    {"target_id": "member-a", "member_address": "198.51.100.10"},
    {"target_id": "member-b", "member_address": "198.51.100.11"},
]


def plan(selected_build: int = 2700) -> dict:
    binding = deployment_agent_package.bind_deployment_agent_package(
        {
            "name": "update-agent",
            "action": "upgrade",
            "package_type": "deployment_agent",
            "package_name": "DeploymentAgent_00002771.tgz",
            "target_ids": ["member-a", "member-b"],
            "requires_present": [],
            "requires_absent": [],
            "source_path": "/srv/packages/DeploymentAgent_00002771.tgz",
            "checksum_sha256": "a" * 64,
            "artifact_size": 8192,
        },
        2771,
        2771,
    )
    return deployment_agent_update.plan_deployment_agent_update(
        binding,
        [
            {
                "target_id": "member-a",
                "enabled": True,
                "build": selected_build,
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


def lease(update_plan: dict) -> dict:
    return {
        "lease_id": "63c53f94-319d-444a-8c43-ec2584bcf985",
        "issued_at": "2026-07-30T11:55:00Z",
        "expires_at": "2026-07-30T12:05:00Z",
        "operation": "deployment_agent_update",
        "execution_mode": "mutating",
        "tls_validation_mode": "strict",
        "candidate_commit": COMMIT,
        "plan_sha256": update_plan["plan_sha256"],
        "binding_sha256": update_plan["binding_sha256"],
        "member_targets": copy.deepcopy(MEMBERS),
    }


def artifact(update_plan: dict) -> dict:
    return {
        "path": update_plan["source_path"],
        "size": update_plan["artifact_size"],
        "sha256": update_plan["checksum_sha256"],
    }


class DeploymentAgentExecutionPreflightTests(unittest.TestCase):
    def authorize(self, update_plan=None, **overrides):
        selected_plan = update_plan or plan()
        values = {
            "lease": lease(selected_plan),
            "update_plan": selected_plan,
            "artifact_observation": artifact(selected_plan),
            "member_target_id": "member-a",
            "member_address": "198.51.100.10",
            "member_targets": copy.deepcopy(MEMBERS),
            "runtime_commit": COMMIT,
            "tls_validation_enabled": True,
            "lab_tls_exception_acknowledged": False,
            "check_mode": False,
            "now": NOW,
        }
        values.update(overrides)
        return deployment_agent_execution_preflight.authorize_deployment_agent_execution(
            **values
        )

    def assert_category(self, category, callback):
        with self.assertRaises(
            deployment_agent_execution_preflight.DeploymentAgentExecutionPreflightError
        ) as caught:
            callback()
        self.assertEqual(caught.exception.category, category)

    def test_authorizes_only_sanitized_exact_selected_plan(self):
        result = self.authorize()
        self.assertTrue(result["authorized"])
        self.assertEqual(result["operation"], "deployment_agent_update")
        self.assertEqual(result["candidate_commit"], COMMIT)
        self.assertNotIn("member-a", str(result))
        self.assertNotIn("198.51.100.10", str(result))
        self.assertNotIn("/srv/packages", str(result))

    def test_check_mode_wrong_operation_and_nonmutating_lease_fail(self):
        self.assert_category(
            "EXECUTION_MODE_INVALID", lambda: self.authorize(check_mode=True)
        )
        for field, value, category in (
            ("operation", "deployment_agent_observation", "OPERATION_INVALID"),
            ("execution_mode", "read_only", "EXECUTION_MODE_INVALID"),
        ):
            update_plan = plan()
            changed = lease(update_plan)
            changed[field] = value
            self.assert_category(
                category,
                lambda changed=changed, update_plan=update_plan: self.authorize(
                    update_plan=update_plan, lease=changed
                ),
            )

    def test_lease_shape_identity_commit_and_time_are_exact(self):
        update_plan = plan()
        cases = [
            ({}, "LEASE_INVALID"),
            (dict(lease(update_plan), extra=True), "LEASE_INVALID"),
            (dict(lease(update_plan), lease_id="not-a-uuid"), "LEASE_INVALID"),
            (dict(lease(update_plan), expires_at="2026-07-30T12:20:01Z"), "LEASE_INVALID"),
            (dict(lease(update_plan), expires_at="2026-07-30T12:00:00Z"), "LEASE_EXPIRED"),
        ]
        for changed, category in cases:
            self.assert_category(
                category,
                lambda changed=changed: self.authorize(
                    update_plan=update_plan, lease=changed
                ),
            )
        self.assert_category(
            "COMMIT_MISMATCH", lambda: self.authorize(runtime_commit="2" * 40)
        )

    def test_plan_and_artifact_tampering_fail_closed(self):
        update_plan = plan()
        changed_plan = dict(update_plan)
        changed_plan["artifact_size"] += 1
        self.assert_category(
            "PLAN_MISMATCH",
            lambda: self.authorize(
                update_plan=changed_plan, lease=lease(update_plan)
            ),
        )
        for field, value in (
            ("path", "/srv/packages/other.tgz"),
            ("size", 8193),
            ("sha256", "b" * 64),
        ):
            changed_artifact = artifact(update_plan)
            changed_artifact[field] = value
            self.assert_category(
                "ARTIFACT_MISMATCH",
                lambda changed_artifact=changed_artifact: self.authorize(
                    artifact_observation=changed_artifact
                ),
            )
        changed_lease = lease(update_plan)
        changed_lease["plan_sha256"] = "b" * 64
        self.assert_category(
            "PLAN_MISMATCH", lambda: self.authorize(lease=changed_lease)
        )

    def test_exact_selected_member_mapping_is_required(self):
        hostile = [
            ({"member_target_id": "member-b"}, "TARGET_MISMATCH"),
            ({"member_address": "198.51.100.11"}, "TARGET_MISMATCH"),
            ({"member_targets": MEMBERS[:1]}, "TARGET_INVALID"),
            (
                {
                    "member_targets": [
                        MEMBERS[0],
                        {"target_id": "member-b", "member_address": "198.51.100.12"},
                    ]
                },
                "TARGET_MISMATCH",
            ),
        ]
        for override, category in hostile:
            self.assert_category(
                category, lambda override=override: self.authorize(**override)
            )

    def test_tls_controls_and_no_change_plan_are_rejected(self):
        self.assert_category(
            "TLS_VALIDATION_INVALID",
            lambda: self.authorize(tls_validation_enabled=False),
        )
        update_plan = plan()
        lab_lease = lease(update_plan)
        lab_lease["tls_validation_mode"] = "lab_unverified"
        self.assertTrue(
            self.authorize(
                lease=lab_lease,
                tls_validation_enabled=False,
                lab_tls_exception_acknowledged=True,
            )["authorized"]
        )
        complete = plan(selected_build=2771)
        self.assert_category(
            "UPDATE_NOT_REQUIRED",
            lambda: self.authorize(
                update_plan=complete,
                lease=lease(complete),
                artifact_observation=artifact(complete),
            ),
        )


if __name__ == "__main__":
    unittest.main()
