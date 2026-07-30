# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Compose fixed reacquisition and exact-build reconciliation evidence offline."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import hashlib
import json
from typing import Any

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_reacquire import (
    DeploymentAgentReacquireError,
    validate_deployment_agent_reacquisition,
)
from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_reconcile import (
    DeploymentAgentReconcileError,
    reconcile_deployment_agent_update,
)


class DeploymentAgentEvidenceError(ValueError):
    """The offline reacquisition and reconciliation evidence is inconsistent."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def compose_deployment_agent_evidence(
    update_plan: object,
    reacquisition_plan: object,
    target_states: object,
) -> dict[str, Any]:
    """Return one deterministic evidence chain without acquisition or transport."""

    try:
        verified_reacquisition = validate_deployment_agent_reacquisition(
            update_plan,
            reacquisition_plan,
        )
        reconciliation = reconcile_deployment_agent_update(
            update_plan,
            target_states,
        )
    except (DeploymentAgentReacquireError, DeploymentAgentReconcileError) as error:
        raise DeploymentAgentEvidenceError(error.category, str(error)) from error

    result: dict[str, Any] = {
        "source_reacquisition_plan_sha256": verified_reacquisition[
            "reacquisition_plan_sha256"
        ],
        "reconciliation": reconciliation,
    }
    encoded = json.dumps(
        result,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    result["evidence_chain_sha256"] = hashlib.sha256(encoded).hexdigest()
    return result


def validate_deployment_agent_evidence(
    update_plan: object,
    reacquisition_plan: object,
    target_states: object,
    evidence: object,
) -> dict[str, Any]:
    """Require the exact evidence chain derived from the supplied inputs."""

    expected = compose_deployment_agent_evidence(
        update_plan,
        reacquisition_plan,
        target_states,
    )
    if not isinstance(evidence, dict) or evidence != expected:
        raise DeploymentAgentEvidenceError(
            "EVIDENCE_MISMATCH",
            "evidence chain does not match the supplied offline inputs",
        )
    return dict(evidence)
