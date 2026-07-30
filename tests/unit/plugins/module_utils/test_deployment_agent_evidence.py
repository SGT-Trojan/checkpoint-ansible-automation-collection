from __future__ import annotations

import copy
import hashlib
import json
import sys
from types import ModuleType
import unittest

from plugins.module_utils import deployment_agent_package
from plugins.module_utils import deployment_agent_reconcile
from plugins.module_utils import deployment_agent_update


for package in (
    "ansible_collections",
    "ansible_collections.sgt_trojan",
    "ansible_collections.sgt_trojan.checkpoint_automation",
    "ansible_collections.sgt_trojan.checkpoint_automation.plugins",
    "ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils",
):
    sys.modules.setdefault(package, ModuleType(package))
prefix = (
    "ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils."
)
sys.modules[prefix + "deployment_agent_reconcile"] = deployment_agent_reconcile

from plugins.module_utils import deployment_agent_reacquire  # noqa: E402

sys.modules[prefix + "deployment_agent_reacquire"] = deployment_agent_reacquire

from plugins.module_utils import deployment_agent_evidence  # noqa: E402


def update_plan(peer_build: int = 2700) -> dict:
    step = {
        "name": "update_deployment_agent",
        "action": "upgrade",
        "package_type": "deployment_agent",
        "package_name": "DeploymentAgent_00002771.tgz",
        "target_ids": ["member-a", "member-b"],
        "requires_present": [],
        "requires_absent": [],
        "source_path": "/srv/packages/DeploymentAgent_00002771.tgz",
        "checksum_sha256": "a" * 64,
        "artifact_size": 8192,
    }
    binding = deployment_agent_package.bind_deployment_agent_package(
        step, 2771, 2771
    )
    return deployment_agent_update.plan_deployment_agent_update(
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
                "build": peer_build,
                "cloud_state": "unknown",
            },
        ],
        "member-a",
    )


def target_states(peer_build: int = 2700) -> list[dict]:
    return [
        {
            "target_id": "member-a",
            "enabled": True,
            "build": 2771,
            "cloud_state": "current",
        },
        {
            "target_id": "member-b",
            "enabled": True,
            "build": peer_build,
            "cloud_state": "update_available",
        },
    ]


class DeploymentAgentEvidenceTests(unittest.TestCase):
    def assert_category(self, category: str, callback) -> None:
        with self.assertRaises(
            deployment_agent_evidence.DeploymentAgentEvidenceError
        ) as caught:
            callback()
        self.assertEqual(caught.exception.category, category)

    def test_pending_evidence_chain_is_exact_and_deterministic(self) -> None:
        source = update_plan()
        reacquisition = (
            deployment_agent_reacquire.plan_deployment_agent_reacquisition(source)
        )
        result = deployment_agent_evidence.compose_deployment_agent_evidence(
            source, reacquisition, target_states()
        )
        self.assertEqual(
            result["source_reacquisition_plan_sha256"],
            reacquisition["reacquisition_plan_sha256"],
        )
        self.assertEqual(
            result["reconciliation"]["status"], "next_target_pending"
        )
        digest = result.pop("evidence_chain_sha256")
        encoded = json.dumps(
            result,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        self.assertEqual(digest, hashlib.sha256(encoded).hexdigest())

    def test_complete_evidence_chain(self) -> None:
        source = update_plan(peer_build=2771)
        reacquisition = (
            deployment_agent_reacquire.plan_deployment_agent_reacquisition(source)
        )
        result = deployment_agent_evidence.compose_deployment_agent_evidence(
            source, reacquisition, target_states(peer_build=2771)
        )
        self.assertEqual(result["reconciliation"]["status"], "complete")

    def test_reacquisition_tampering_fails_closed(self) -> None:
        source = update_plan()
        for field, value in (
            ("target_order", ["member-b", "member-a"]),
            ("request_count", 3),
            ("reacquisition_plan_sha256", "b" * 64),
        ):
            reacquisition = (
                deployment_agent_reacquire.plan_deployment_agent_reacquisition(
                    source
                )
            )
            reacquisition[field] = value
            with self.subTest(field=field):
                self.assert_category(
                    "REACQUISITION_MISMATCH",
                    lambda reacquisition=reacquisition: (
                        deployment_agent_evidence.compose_deployment_agent_evidence(
                            source, reacquisition, target_states()
                        )
                    ),
                )

    def test_update_plan_tampering_fails_closed(self) -> None:
        source = update_plan()
        reacquisition = (
            deployment_agent_reacquire.plan_deployment_agent_reacquisition(source)
        )
        source["plan_sha256"] = "b" * 64
        self.assert_category(
            "PLAN_MISMATCH",
            lambda: deployment_agent_evidence.compose_deployment_agent_evidence(
                source, reacquisition, target_states()
            ),
        )

    def test_selected_exact_build_is_required(self) -> None:
        source = update_plan()
        reacquisition = (
            deployment_agent_reacquire.plan_deployment_agent_reacquisition(source)
        )
        states = target_states()
        states[0]["build"] = 2770
        self.assert_category(
            "EXPECTED_BUILD_MISMATCH",
            lambda: deployment_agent_evidence.compose_deployment_agent_evidence(
                source, reacquisition, states
            ),
        )

    def test_peer_drift_is_rejected(self) -> None:
        source = update_plan()
        reacquisition = (
            deployment_agent_reacquire.plan_deployment_agent_reacquisition(source)
        )
        self.assert_category(
            "PEER_DRIFT",
            lambda: deployment_agent_evidence.compose_deployment_agent_evidence(
                source, reacquisition, target_states(peer_build=2701)
            ),
        )

    def test_inputs_are_not_modified(self) -> None:
        source = update_plan()
        reacquisition = (
            deployment_agent_reacquire.plan_deployment_agent_reacquisition(source)
        )
        states = target_states()
        originals = copy.deepcopy((source, reacquisition, states))
        deployment_agent_evidence.compose_deployment_agent_evidence(
            source, reacquisition, states
        )
        self.assertEqual((source, reacquisition, states), originals)


if __name__ == "__main__":
    unittest.main()
