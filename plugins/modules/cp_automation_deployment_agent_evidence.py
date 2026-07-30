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
module: cp_automation_deployment_agent_evidence
short_description: Compose Deployment Agent update evidence offline
version_added: "0.1.0"
description:
  - Revalidates one update plan and its exact fixed reacquisition plan.
  - Reconciles exact normalized state for both update-plan targets.
  - Binds the reacquisition-plan digest to deterministic reconciliation evidence.
  - Performs no filesystem, acquisition, lease, network, target, or update action.
options:
  update_plan:
    description: Exact output from C(cp_automation_deployment_agent_update_plan).
    type: dict
    required: true
  reacquisition_plan:
    description: Exact output from C(cp_automation_deployment_agent_reacquire_plan).
    type: dict
    required: true
  target_states:
    description: Two normalized post-update Deployment Agent states.
    type: list
    elements: dict
    required: true
author:
  - SGT-Trojan contributors (@SGT-Trojan)
notes:
  - Supports check mode and always reports C(changed=false).
  - Composed evidence does not prove acquisition provenance or authorize live access.
"""

EXAMPLES = r"""
- name: Compose fixed reacquisition and reconciliation evidence offline
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_evidence:
    update_plan: "{{ checkpoint_deployment_agent_update.plan }}"
    reacquisition_plan: "{{ checkpoint_deployment_agent_reacquisition.reacquisition_plan }}"
    target_states: "{{ checkpoint_deployment_agent_post_update_states }}"
  register: checkpoint_deployment_agent_evidence
"""

RETURN = r"""
evidence:
  description: Deterministic reacquisition and exact-build evidence chain.
  type: dict
  returned: success
category:
  description: Stable fail-closed validation category.
  type: str
  returned: failure
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_evidence import (
    DeploymentAgentEvidenceError,
    compose_deployment_agent_evidence,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "update_plan": {"type": "dict", "required": True},
            "reacquisition_plan": {"type": "dict", "required": True},
            "target_states": {
                "type": "list",
                "elements": "dict",
                "required": True,
            },
        },
        supports_check_mode=True,
    )
    try:
        evidence = compose_deployment_agent_evidence(
            module.params["update_plan"],
            module.params["reacquisition_plan"],
            module.params["target_states"],
        )
    except DeploymentAgentEvidenceError as error:
        module.fail_json(msg=str(error), category=error.category, changed=False)
    module.exit_json(changed=False, evidence=evidence)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
