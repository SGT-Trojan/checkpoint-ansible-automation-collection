from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import copy
import hashlib
import json
import sys
from types import ModuleType
import unittest

collections = sys.modules.setdefault(
    "ansible_collections", ModuleType("ansible_collections")
)
sgt_trojan = sys.modules.setdefault(
    "ansible_collections.sgt_trojan", ModuleType("sgt_trojan")
)
checkpoint = sys.modules.setdefault(
    "ansible_collections.sgt_trojan.checkpoint_automation",
    ModuleType("checkpoint_automation"),
)
plugins = sys.modules.setdefault(
    "ansible_collections.sgt_trojan.checkpoint_automation.plugins",
    ModuleType("plugins"),
)
imported_utils = __import__("plugins.module_utils", fromlist=["module_utils"])
sys.modules[
    "ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils"
] = imported_utils
collections.sgt_trojan = sgt_trojan
sgt_trojan.checkpoint_automation = checkpoint
checkpoint.plugins = plugins
plugins.module_utils = imported_utils

from plugins.module_utils import deployment_agent_reconcile  # noqa: E402

prefix = (
    "ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils."
)
sys.modules[prefix + "deployment_agent_reconcile"] = deployment_agent_reconcile

from plugins.module_utils import deployment_agent_reacquire  # noqa: E402

sys.modules[prefix + "deployment_agent_reacquire"] = deployment_agent_reacquire

from plugins.module_utils import deployment_agent_evidence  # noqa: E402

sys.modules[prefix + "deployment_agent_evidence"] = deployment_agent_evidence
from tests.unit.plugins.module_utils.test_deployment_agent_evidence import (
    target_states,
    update_plan,
)

from plugins.module_utils import deployment_agent_next  # noqa: E402


def evidence_inputs(peer_build: int = 2700):
    source = update_plan(peer_build=peer_build)
    reacquisition = (
        deployment_agent_reacquire.plan_deployment_agent_reacquisition(source)
    )
    states = target_states(peer_build=peer_build)
    evidence = deployment_agent_evidence.compose_deployment_agent_evidence(
        source, reacquisition, states
    )
    return source, reacquisition, states, evidence


class DeploymentAgentNextTests(unittest.TestCase):
    def assert_category(self, category: str, callback) -> None:
        with self.assertRaises(deployment_agent_next.DeploymentAgentNextError) as caught:
            callback()
        self.assertEqual(caught.exception.category, category)

    def test_pending_peer_plan_is_exact_and_deterministic(self) -> None:
        source, reacquisition, states, evidence = evidence_inputs()
        result = deployment_agent_next.plan_next_deployment_agent_update(
            source, reacquisition, states, evidence
        )
        self.assertEqual(result["selected_target_id"], "member-b")
        self.assertEqual(result["peer_target_id"], "member-a")
        self.assertEqual(result["observed_build"], 2700)
        self.assertEqual(result["peer_observed_build"], 2771)
        self.assertTrue(result["execution_required"])
        digest = result.pop("plan_sha256")
        encoded = json.dumps(
            result, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        self.assertEqual(digest, hashlib.sha256(encoded).hexdigest())

    def test_complete_evidence_fails_closed(self) -> None:
        inputs = evidence_inputs(peer_build=2771)
        self.assert_category(
            "UPDATE_COMPLETE",
            lambda: deployment_agent_next.plan_next_deployment_agent_update(*inputs),
        )

    def test_evidence_tampering_fails_closed(self) -> None:
        source, reacquisition, states, evidence = evidence_inputs()
        evidence["evidence_chain_sha256"] = "b" * 64
        self.assert_category(
            "EVIDENCE_MISMATCH",
            lambda: deployment_agent_next.plan_next_deployment_agent_update(
                source, reacquisition, states, evidence
            ),
        )

    def test_reacquisition_tampering_fails_closed(self) -> None:
        source, reacquisition, states, evidence = evidence_inputs()
        reacquisition["request_count"] = 3
        self.assert_category(
            "REACQUISITION_MISMATCH",
            lambda: deployment_agent_next.plan_next_deployment_agent_update(
                source, reacquisition, states, evidence
            ),
        )

    def test_state_drift_fails_closed(self) -> None:
        source, reacquisition, states, evidence = evidence_inputs()
        states[1]["build"] = 2701
        self.assert_category(
            "PEER_DRIFT",
            lambda: deployment_agent_next.plan_next_deployment_agent_update(
                source, reacquisition, states, evidence
            ),
        )

    def test_update_plan_tampering_fails_closed(self) -> None:
        source, reacquisition, states, evidence = evidence_inputs()
        source["plan_sha256"] = "b" * 64
        self.assert_category(
            "PLAN_MISMATCH",
            lambda: deployment_agent_next.plan_next_deployment_agent_update(
                source, reacquisition, states, evidence
            ),
        )

    def test_inputs_are_not_modified(self) -> None:
        inputs = evidence_inputs()
        originals = copy.deepcopy(inputs)
        deployment_agent_next.plan_next_deployment_agent_update(*inputs)
        self.assertEqual(inputs, originals)


if __name__ == "__main__":
    unittest.main()
