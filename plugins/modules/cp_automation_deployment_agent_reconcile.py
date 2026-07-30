#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type


DOCUMENTATION = r"""
---
module: cp_automation_deployment_agent_reconcile
short_description: Reconcile one Deployment Agent update offline
version_added: "0.1.0"
description:
  - Revalidates one deterministic Deployment Agent update plan.
  - Requires exact normalized post-update state for both bound targets.
  - Requires the selected target at the expected build and the peer unchanged.
  - Returns deterministic evidence that the peer is pending or both are complete.
  - Performs no filesystem, staging, lease, network, or target operation.
options:
  update_plan:
    description: Exact output from C(cp_automation_deployment_agent_update_plan).
    type: dict
    required: true
  target_states:
    description:
      - Two normalized post-update Deployment Agent states.
      - Each contains only C(target_id), C(enabled), C(build), and C(cloud_state).
    type: list
    elements: dict
    required: true
author:
  - SGT-Trojan contributors (@SGT-Trojan)
notes:
  - Supports check mode and always reports C(changed=false).
  - Reconciliation data does not authorize live access or another update.
"""

EXAMPLES = r"""
- name: Reconcile one completed update from offline evidence
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_reconcile:
    update_plan: "{{ checkpoint_deployment_agent_update.plan }}"
    target_states: "{{ checkpoint_deployment_agent_post_update_states }}"
  register: checkpoint_deployment_agent_reconciliation
"""

RETURN = r"""
reconciliation:
  description: Deterministic exact-build and peer-drift reconciliation.
  type: dict
  returned: success
category:
  description: Stable fail-closed validation category.
  type: str
  returned: failure
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_reconcile import (
    DeploymentAgentReconcileError,
    reconcile_deployment_agent_update,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "update_plan": {"type": "dict", "required": True},
            "target_states": {
                "type": "list",
                "elements": "dict",
                "required": True,
            },
        },
        supports_check_mode=True,
    )
    try:
        reconciliation = reconcile_deployment_agent_update(
            module.params["update_plan"],
            module.params["target_states"],
        )
    except DeploymentAgentReconcileError as error:
        module.fail_json(msg=str(error), category=error.category, changed=False)
    module.exit_json(changed=False, reconciliation=reconciliation)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
