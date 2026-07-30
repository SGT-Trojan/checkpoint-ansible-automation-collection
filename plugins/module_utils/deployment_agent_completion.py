# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Attest completion of both Deployment Agent member updates offline."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import hashlib
import json
from typing import Any

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_evidence import (
    DeploymentAgentEvidenceError,
    validate_deployment_agent_evidence,
)
from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_next import (
    DeploymentAgentNextError,
    plan_next_deployment_agent_update,
)


class DeploymentAgentCompletionError(ValueError):
    """The two-member evidence chain does not prove exact completion."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def attest_deployment_agent_completion(
    first_update_plan: object,
    first_reacquisition_plan: object,
    first_target_states: object,
    first_evidence: object,
    second_reacquisition_plan: object,
    final_target_states: object,
    final_evidence: object,
) -> dict[str, Any]:
    """Return deterministic completion evidence for exactly two updates."""

    try:
        second_update_plan = plan_next_deployment_agent_update(
            first_update_plan,
            first_reacquisition_plan,
            first_target_states,
            first_evidence,
        )
        verified_final = validate_deployment_agent_evidence(
            second_update_plan,
            second_reacquisition_plan,
            final_target_states,
            final_evidence,
        )
    except (DeploymentAgentNextError, DeploymentAgentEvidenceError) as error:
        raise DeploymentAgentCompletionError(error.category, str(error)) from error

    reconciliation = verified_final["reconciliation"]
    if reconciliation["status"] != "complete":
        raise DeploymentAgentCompletionError(
            "UPDATE_INCOMPLETE",
            "final evidence does not report both members complete",
        )

    result: dict[str, Any] = {
        "status": "complete",
        "first_update_plan_sha256": first_update_plan["plan_sha256"],
        "first_evidence_chain_sha256": first_evidence["evidence_chain_sha256"],
        "second_update_plan_sha256": second_update_plan["plan_sha256"],
        "final_evidence_chain_sha256": verified_final["evidence_chain_sha256"],
        "expected_build": second_update_plan["expected_build"],
        "completed_target_ids": sorted(
            (
                second_update_plan["selected_target_id"],
                second_update_plan["peer_target_id"],
            )
        ),
    }
    encoded = json.dumps(
        result,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    result["completion_sha256"] = hashlib.sha256(encoded).hexdigest()
    return result
