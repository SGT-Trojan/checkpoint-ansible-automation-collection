# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Plan two fixed Deployment Agent status reacquisitions without transport."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import hashlib
import json
from typing import Any

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_reconcile import (
    DeploymentAgentReconcileError,
    validate_deployment_agent_update_plan,
)


class DeploymentAgentReacquireError(ValueError):
    """The source update plan cannot authorize fixed offline reacquisition data."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


REACQUISITION_KEYS = frozenset(
    {
        "operation",
        "execution_mode",
        "target_order",
        "request_count",
        "source_plan_sha256",
        "reacquisition_plan_sha256",
    }
)


def plan_deployment_agent_reacquisition(update_plan: object) -> dict[str, Any]:
    """Return selected-then-peer read-only observation data."""

    try:
        plan = validate_deployment_agent_update_plan(update_plan)
    except DeploymentAgentReconcileError as error:
        raise DeploymentAgentReacquireError(error.category, str(error)) from error

    result: dict[str, Any] = {
        "operation": "deployment_agent_status_observation",
        "execution_mode": "read_only",
        "target_order": [
            plan["selected_target_id"],
            plan["peer_target_id"],
        ],
        "request_count": 2,
        "source_plan_sha256": plan["plan_sha256"],
    }
    encoded = json.dumps(
        result,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    result["reacquisition_plan_sha256"] = hashlib.sha256(encoded).hexdigest()
    return result


def validate_deployment_agent_reacquisition(
    update_plan: object,
    reacquisition_plan: object,
) -> dict[str, Any]:
    """Require the exact reacquisition plan derived from one update plan."""

    expected = plan_deployment_agent_reacquisition(update_plan)
    if (
        not isinstance(reacquisition_plan, dict)
        or set(reacquisition_plan) != REACQUISITION_KEYS
        or reacquisition_plan != expected
    ):
        raise DeploymentAgentReacquireError(
            "REACQUISITION_MISMATCH",
            "reacquisition plan does not match the source update plan",
        )
    return dict(reacquisition_plan)
