from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import copy
import hashlib
import json
import unittest

from plugins.module_utils import deployment_agent_package
from plugins.module_utils import deployment_agent_reconcile
from plugins.module_utils import deployment_agent_update


def package_step() -> dict:
    return {
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


def update_plan(selected_build: int = 2700, peer_build: int = 2700) -> dict:
    binding = deployment_agent_package.bind_deployment_agent_package(
        package_step(), 2771, 2771
    )
    states = [
        {
            "target_id": "member-a",
            "enabled": True,
            "build": selected_build,
            "cloud_state": "update_available",
        },
        {
            "target_id": "member-b",
            "enabled": True,
            "build": peer_build,
            "cloud_state": "unknown",
        },
    ]
    return deployment_agent_update.plan_deployment_agent_update(
        binding, states, "member-a"
    )


def reconciled_states(peer_build: int = 2700) -> list[dict]:
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


class DeploymentAgentReconcileTests(unittest.TestCase):
    def assert_category(self, category: str, callback) -> None:
        with self.assertRaises(
            deployment_agent_reconcile.DeploymentAgentReconcileError
        ) as caught:
            callback()
        self.assertEqual(caught.exception.category, category)

    def test_pending_reconciliation_is_exact_and_deterministic(self) -> None:
        result = deployment_agent_reconcile.reconcile_deployment_agent_update(
            update_plan(), reconciled_states()
        )
        self.assertEqual(result["status"], "next_target_pending")
        self.assertEqual(result["completed_target_id"], "member-a")
        self.assertEqual(result["next_target_id"], "member-b")
        self.assertEqual(result["selected_build"], 2771)
        self.assertEqual(result["peer_build"], 2700)
        digest = result.pop("reconciliation_sha256")
        encoded = json.dumps(
            result,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        self.assertEqual(digest, hashlib.sha256(encoded).hexdigest())

    def test_both_expected_builds_are_complete(self) -> None:
        result = deployment_agent_reconcile.reconcile_deployment_agent_update(
            update_plan(peer_build=2771), reconciled_states(peer_build=2771)
        )
        self.assertEqual(result["status"], "complete")
        self.assertIsNone(result["next_target_id"])

    def test_plan_digest_and_semantics_are_reverified(self) -> None:
        cases = []
        digest = update_plan()
        digest["plan_sha256"] = "b" * 64
        cases.append((digest, "PLAN_MISMATCH"))
        peer = update_plan()
        peer["peer_observed_build"] = 2701
        cases.append((peer, "PLAN_MISMATCH"))
        operation = update_plan()
        operation["operation"] = "other"
        cases.append((operation, "PLAN_INVALID"))
        contradiction = update_plan()
        contradiction["execution_required"] = False
        canonical = {
            key: value
            for key, value in contradiction.items()
            if key != "plan_sha256"
        }
        contradiction["plan_sha256"] = hashlib.sha256(
            json.dumps(
                canonical,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()
        cases.append((contradiction, "PLAN_INVALID"))
        for plan, category in cases:
            with self.subTest(category=category):
                self.assert_category(
                    category,
                    lambda plan=plan: (
                        deployment_agent_reconcile.reconcile_deployment_agent_update(
                            plan, reconciled_states()
                        )
                    ),
                )

    def test_selected_target_requires_exact_expected_build(self) -> None:
        for build in (2770, 2772):
            observed = reconciled_states()
            observed[0]["build"] = build
            with self.subTest(build=build):
                self.assert_category(
                    "EXPECTED_BUILD_MISMATCH",
                    lambda observed=observed: (
                        deployment_agent_reconcile.reconcile_deployment_agent_update(
                            update_plan(), observed
                        )
                    ),
                )

    def test_peer_build_must_remain_unchanged(self) -> None:
        for build in (2699, 2701, 2771):
            with self.subTest(build=build):
                self.assert_category(
                    "PEER_DRIFT",
                    lambda build=build: (
                        deployment_agent_reconcile.reconcile_deployment_agent_update(
                            update_plan(), reconciled_states(peer_build=build)
                        )
                    ),
                )

    def test_disabled_selected_or_peer_fails_closed(self) -> None:
        for index, category in (
            (0, "TARGET_NOT_READY"),
            (1, "PEER_NOT_READY"),
        ):
            observed = reconciled_states()
            observed[index]["enabled"] = False
            with self.subTest(index=index):
                self.assert_category(
                    category,
                    lambda observed=observed: (
                        deployment_agent_reconcile.reconcile_deployment_agent_update(
                            update_plan(), observed
                        )
                    ),
                )

    def test_state_shape_identity_and_build_fail_closed(self) -> None:
        cases = []
        duplicate = reconciled_states()
        duplicate[1]["target_id"] = "member-a"
        cases.append((duplicate, "TARGET_AMBIGUOUS"))
        extra = reconciled_states()
        extra[0]["raw"] = "secret"
        cases.append((extra, "TARGET_INVALID"))
        wrong = reconciled_states()
        wrong[1]["target_id"] = "member-c"
        cases.append((wrong, "TARGET_MISMATCH"))
        boolean = reconciled_states()
        boolean[0]["build"] = True
        cases.append((boolean, "BUILD_INVALID"))
        for observed, category in cases:
            with self.subTest(category=category):
                self.assert_category(
                    category,
                    lambda observed=observed: (
                        deployment_agent_reconcile.reconcile_deployment_agent_update(
                            update_plan(), observed
                        )
                    ),
                )

    def test_inputs_are_not_modified(self) -> None:
        plan = update_plan()
        states = reconciled_states()
        original_plan = copy.deepcopy(plan)
        original_states = copy.deepcopy(states)
        deployment_agent_reconcile.reconcile_deployment_agent_update(plan, states)
        self.assertEqual(plan, original_plan)
        self.assertEqual(states, original_states)


if __name__ == "__main__":
    unittest.main()
