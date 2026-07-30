from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import copy
import hashlib
import json
import sys
import unittest

from tests.unit.plugins.module_utils.test_deployment_agent_next import (
    deployment_agent_evidence,
    deployment_agent_next,
    deployment_agent_reacquire,
    evidence_inputs,
    prefix,
)

sys.modules[prefix + "deployment_agent_next"] = deployment_agent_next

from plugins.module_utils import deployment_agent_completion  # noqa: E402


def completion_inputs():
    first_plan, first_reacquisition, first_states, first_evidence = (
        evidence_inputs()
    )
    second_plan = deployment_agent_next.plan_next_deployment_agent_update(
        first_plan,
        first_reacquisition,
        first_states,
        first_evidence,
    )
    second_reacquisition = (
        deployment_agent_reacquire.plan_deployment_agent_reacquisition(second_plan)
    )
    final_states = [
        {
            "target_id": "member-a",
            "enabled": True,
            "build": 2771,
            "cloud_state": "current",
        },
        {
            "target_id": "member-b",
            "enabled": True,
            "build": 2771,
            "cloud_state": "current",
        },
    ]
    final_evidence = deployment_agent_evidence.compose_deployment_agent_evidence(
        second_plan,
        second_reacquisition,
        final_states,
    )
    return (
        first_plan,
        first_reacquisition,
        first_states,
        first_evidence,
        second_reacquisition,
        final_states,
        final_evidence,
    )


class DeploymentAgentCompletionTests(unittest.TestCase):
    def assert_category(self, category: str, callback) -> None:
        with self.assertRaises(
            deployment_agent_completion.DeploymentAgentCompletionError
        ) as caught:
            callback()
        self.assertEqual(caught.exception.category, category)

    def test_completion_is_exact_and_deterministic(self) -> None:
        inputs = completion_inputs()
        result = deployment_agent_completion.attest_deployment_agent_completion(
            *inputs
        )
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["completed_target_ids"], ["member-a", "member-b"])
        self.assertEqual(result["expected_build"], 2771)
        digest = result.pop("completion_sha256")
        encoded = json.dumps(
            result,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        self.assertEqual(digest, hashlib.sha256(encoded).hexdigest())

    def test_first_evidence_tampering_fails_closed(self) -> None:
        inputs = list(completion_inputs())
        inputs[3]["evidence_chain_sha256"] = "b" * 64
        self.assert_category(
            "EVIDENCE_MISMATCH",
            lambda: deployment_agent_completion.attest_deployment_agent_completion(
                *inputs
            ),
        )

    def test_second_reacquisition_tampering_fails_closed(self) -> None:
        inputs = list(completion_inputs())
        inputs[4]["request_count"] = 3
        self.assert_category(
            "REACQUISITION_MISMATCH",
            lambda: deployment_agent_completion.attest_deployment_agent_completion(
                *inputs
            ),
        )

    def test_final_evidence_tampering_fails_closed(self) -> None:
        inputs = list(completion_inputs())
        inputs[6]["evidence_chain_sha256"] = "b" * 64
        self.assert_category(
            "EVIDENCE_MISMATCH",
            lambda: deployment_agent_completion.attest_deployment_agent_completion(
                *inputs
            ),
        )

    def test_final_selected_build_must_be_exact(self) -> None:
        inputs = list(completion_inputs())
        inputs[5][1]["build"] = 2770
        self.assert_category(
            "EXPECTED_BUILD_MISMATCH",
            lambda: deployment_agent_completion.attest_deployment_agent_completion(
                *inputs
            ),
        )

    def test_final_peer_drift_fails_closed(self) -> None:
        inputs = list(completion_inputs())
        inputs[5][0]["build"] = 2770
        self.assert_category(
            "PEER_DRIFT",
            lambda: deployment_agent_completion.attest_deployment_agent_completion(
                *inputs
            ),
        )

    def test_inputs_are_not_modified(self) -> None:
        inputs = completion_inputs()
        originals = copy.deepcopy(inputs)
        deployment_agent_completion.attest_deployment_agent_completion(*inputs)
        self.assertEqual(inputs, originals)


if __name__ == "__main__":
    unittest.main()
