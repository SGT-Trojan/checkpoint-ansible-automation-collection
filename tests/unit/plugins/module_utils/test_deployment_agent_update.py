from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import copy
import hashlib
import json
import unittest

from plugins.module_utils import deployment_agent_package
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


def binding() -> dict:
    return deployment_agent_package.bind_deployment_agent_package(
        package_step(), 2771, 2771
    )


def states() -> list[dict]:
    return [
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
            "cloud_state": "unknown",
        },
    ]


class DeploymentAgentUpdateTests(unittest.TestCase):
    def assert_category(self, category: str, callback) -> None:
        with self.assertRaises(
            deployment_agent_update.DeploymentAgentUpdateError
        ) as caught:
            callback()
        self.assertEqual(caught.exception.category, category)

    def test_update_plan_is_exact_and_deterministic(self) -> None:
        result = deployment_agent_update.plan_deployment_agent_update(
            binding(), states(), "member-a"
        )
        self.assertTrue(result["execution_required"])
        self.assertEqual(result["operation"], "installer_agent_install")
        self.assertEqual(result["selected_target_id"], "member-a")
        self.assertEqual(result["peer_target_id"], "member-b")
        self.assertEqual(result["observed_build"], 2700)
        self.assertEqual(result["peer_observed_build"], 2700)
        self.assertEqual(result["expected_build"], 2771)
        digest = result.pop("plan_sha256")
        encoded = json.dumps(
            result,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        self.assertEqual(digest, hashlib.sha256(encoded).hexdigest())

    def test_expected_build_is_noop_plan(self) -> None:
        observed = states()
        observed[0]["build"] = 2771
        result = deployment_agent_update.plan_deployment_agent_update(
            binding(), observed, "member-a"
        )
        self.assertFalse(result["execution_required"])

    def test_binding_digest_is_reverified(self) -> None:
        for field, value in (
            ("binding_sha256", "b" * 64),
            ("expected_build", 2800),
            ("operation", "other"),
        ):
            candidate = binding()
            candidate[field] = value
            expected = (
                "BINDING_INVALID"
                if field == "operation"
                else "BINDING_MISMATCH"
            )
            with self.subTest(field=field):
                self.assert_category(
                    expected,
                    lambda candidate=candidate: (
                        deployment_agent_update.plan_deployment_agent_update(
                            candidate, states(), "member-a"
                        )
                    ),
                )

    def test_target_state_shape_and_identity_fail_closed(self) -> None:
        cases = []
        duplicate = states()
        duplicate[1]["target_id"] = "member-a"
        cases.append((duplicate, "TARGET_AMBIGUOUS"))
        missing = states()[:1]
        cases.append((missing, "TARGET_INVALID"))
        extra_key = states()
        extra_key[0]["raw"] = "secret"
        cases.append((extra_key, "TARGET_INVALID"))
        mismatched = states()
        mismatched[1]["target_id"] = "member-c"
        cases.append((mismatched, "TARGET_MISMATCH"))
        for observed, category in cases:
            with self.subTest(category=category):
                self.assert_category(
                    category,
                    lambda observed=observed: (
                        deployment_agent_update.plan_deployment_agent_update(
                            binding(), observed, "member-a"
                        )
                    ),
                )

    def test_selected_target_must_be_bound_and_normalized(self) -> None:
        for selected in ("member-c", " member-a", 7):
            with self.subTest(selected=selected):
                self.assert_category(
                    "TARGET_MISMATCH" if selected == "member-c" else "PLAN_INVALID",
                    lambda selected=selected: (
                        deployment_agent_update.plan_deployment_agent_update(
                            binding(), states(), selected
                        )
                    ),
                )

    def test_disabled_selected_or_peer_fails_closed(self) -> None:
        for index, category in (
            (0, "TARGET_NOT_READY"),
            (1, "PEER_NOT_READY"),
        ):
            observed = states()
            observed[index]["enabled"] = False
            with self.subTest(index=index):
                self.assert_category(
                    category,
                    lambda observed=observed: (
                        deployment_agent_update.plan_deployment_agent_update(
                            binding(), observed, "member-a"
                        )
                    ),
                )

    def test_build_drift_and_invalid_state_fail_closed(self) -> None:
        cases = []
        drift = states()
        drift[1]["build"] = 2772
        cases.append((drift, "BUILD_DRIFT"))
        boolean = states()
        boolean[0]["build"] = True
        cases.append((boolean, "BUILD_INVALID"))
        cloud = states()
        cloud[0]["cloud_state"] = "current-ish"
        cases.append((cloud, "TARGET_INVALID"))
        for observed, category in cases:
            with self.subTest(category=category):
                self.assert_category(
                    category,
                    lambda observed=observed: (
                        deployment_agent_update.plan_deployment_agent_update(
                            binding(), observed, "member-a"
                        )
                    ),
                )

    def test_inputs_are_not_modified(self) -> None:
        package_binding = binding()
        observed = states()
        original_binding = copy.deepcopy(package_binding)
        original_states = copy.deepcopy(observed)
        deployment_agent_update.plan_deployment_agent_update(
            package_binding, observed, "member-a"
        )
        self.assertEqual(package_binding, original_binding)
        self.assertEqual(observed, original_states)
