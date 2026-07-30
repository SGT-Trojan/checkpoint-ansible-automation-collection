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
sys.modules[
    (
        "ansible_collections.sgt_trojan.checkpoint_automation.plugins."
        "module_utils.deployment_agent_reconcile"
    )
] = deployment_agent_reconcile

from plugins.module_utils import deployment_agent_reacquire  # noqa: E402


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


def update_plan(selected: str = "member-a", selected_build: int = 2700) -> dict:
    binding = deployment_agent_package.bind_deployment_agent_package(
        package_step(), 2771, 2771
    )
    states = [
        {
            "target_id": "member-a",
            "enabled": True,
            "build": selected_build if selected == "member-a" else 2700,
            "cloud_state": "update_available",
        },
        {
            "target_id": "member-b",
            "enabled": True,
            "build": selected_build if selected == "member-b" else 2700,
            "cloud_state": "unknown",
        },
    ]
    return deployment_agent_update.plan_deployment_agent_update(
        binding, states, selected
    )


class DeploymentAgentReacquireTests(unittest.TestCase):
    def assert_category(self, category: str, callback) -> None:
        with self.assertRaises(
            deployment_agent_reacquire.DeploymentAgentReacquireError
        ) as caught:
            callback()
        self.assertEqual(caught.exception.category, category)

    def test_plan_is_exact_ordered_and_deterministic(self) -> None:
        source = update_plan()
        result = deployment_agent_reacquire.plan_deployment_agent_reacquisition(
            source
        )
        self.assertEqual(result["operation"], "deployment_agent_status_observation")
        self.assertEqual(result["execution_mode"], "read_only")
        self.assertEqual(result["target_order"], ["member-a", "member-b"])
        self.assertEqual(result["request_count"], 2)
        self.assertEqual(result["source_plan_sha256"], source["plan_sha256"])
        digest = result.pop("reacquisition_plan_sha256")
        encoded = json.dumps(
            result,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        self.assertEqual(digest, hashlib.sha256(encoded).hexdigest())

    def test_selected_then_peer_order_is_preserved(self) -> None:
        result = deployment_agent_reacquire.plan_deployment_agent_reacquisition(
            update_plan(selected="member-b")
        )
        self.assertEqual(result["target_order"], ["member-b", "member-a"])

    def test_noop_plan_still_requires_two_observations(self) -> None:
        result = deployment_agent_reacquire.plan_deployment_agent_reacquisition(
            update_plan(selected_build=2771)
        )
        self.assertEqual(result["request_count"], 2)
        self.assertEqual(result["target_order"], ["member-a", "member-b"])

    def test_plan_digest_tampering_fails_closed(self) -> None:
        for field, value, category in (
            ("plan_sha256", "b" * 64, "PLAN_MISMATCH"),
            ("peer_observed_build", 2701, "PLAN_MISMATCH"),
            ("operation", "other", "PLAN_INVALID"),
        ):
            source = update_plan()
            source[field] = value
            with self.subTest(field=field):
                self.assert_category(
                    category,
                    lambda source=source: (
                        deployment_agent_reacquire.plan_deployment_agent_reacquisition(
                            source
                        )
                    ),
                )

    def test_redigested_semantic_contradiction_fails_closed(self) -> None:
        source = update_plan()
        source["execution_required"] = False
        canonical = {
            key: value for key, value in source.items() if key != "plan_sha256"
        }
        source["plan_sha256"] = hashlib.sha256(
            json.dumps(
                canonical,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()
        self.assert_category(
            "PLAN_INVALID",
            lambda: deployment_agent_reacquire.plan_deployment_agent_reacquisition(
                source
            ),
        )

    def test_old_or_extended_plan_shape_fails_closed(self) -> None:
        for field in ("peer_observed_build", "unexpected"):
            source = update_plan()
            if field == "unexpected":
                source[field] = True
            else:
                source.pop(field)
            with self.subTest(field=field):
                self.assert_category(
                    "PLAN_INVALID",
                    lambda source=source: (
                        deployment_agent_reacquire.plan_deployment_agent_reacquisition(
                            source
                        )
                    ),
                )

    def test_input_is_not_modified(self) -> None:
        source = update_plan()
        original = copy.deepcopy(source)
        deployment_agent_reacquire.plan_deployment_agent_reacquisition(source)
        self.assertEqual(source, original)


if __name__ == "__main__":
    unittest.main()
