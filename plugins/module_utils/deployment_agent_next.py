# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Derive the pending peer's Deployment Agent update plan offline."""

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
from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_reconcile import (
    DeploymentAgentReconcileError,
    validate_deployment_agent_update_plan,
)


class DeploymentAgentNextError(ValueError):
    """The evidence chain cannot safely derive a pending peer plan."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def plan_next_deployment_agent_update(
    update_plan: object,
    reacquisition_plan: object,
    target_states: object,
    evidence: object,
) -> dict[str, Any]:
    """Return a fixed peer plan only when exact evidence says it is pending."""

    try:
        source = validate_deployment_agent_update_plan(update_plan)
        verified = validate_deployment_agent_evidence(
            update_plan,
            reacquisition_plan,
            target_states,
            evidence,
        )
    except (DeploymentAgentReconcileError, DeploymentAgentEvidenceError) as error:
        raise DeploymentAgentNextError(error.category, str(error)) from error

    reconciliation = verified["reconciliation"]
    if reconciliation["status"] != "next_target_pending":
        raise DeploymentAgentNextError(
            "UPDATE_COMPLETE",
            "evidence reports no pending peer update",
        )
    if reconciliation["next_target_id"] != source["peer_target_id"]:
        raise DeploymentAgentNextError(
            "EVIDENCE_MISMATCH",
            "pending target does not match the source plan peer",
        )

    result: dict[str, Any] = {
        "operation": source["operation"],
        "execution_required": True,
        "selected_target_id": source["peer_target_id"],
        "peer_target_id": source["selected_target_id"],
        "observed_build": reconciliation["peer_build"],
        "peer_observed_build": reconciliation["selected_build"],
        "required_build": source["required_build"],
        "expected_build": source["expected_build"],
        "package_name": source["package_name"],
        "source_path": source["source_path"],
        "checksum_sha256": source["checksum_sha256"],
        "artifact_size": source["artifact_size"],
        "binding_sha256": source["binding_sha256"],
    }
    encoded = json.dumps(
        result,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    result["plan_sha256"] = hashlib.sha256(encoded).hexdigest()
    return result
