#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r"""
---
module: cp_automation_deployment_agent_next_plan
short_description: Derive the pending peer Deployment Agent update plan offline
version_added: "0.1.0"
description:
  - Revalidates one complete offline evidence chain and its source inputs.
  - Derives a second update plan only when the source peer is exactly pending.
  - Fails closed when evidence reports both members complete.
  - Performs no filesystem, acquisition, lease, network, target, or update action.
options:
  update_plan: {description: Source update plan., type: dict, required: true}
  reacquisition_plan: {description: Exact reacquisition plan., type: dict, required: true}
  target_states: {description: Two normalized post-update states., type: list, elements: dict, required: true}
  evidence: {description: Exact composed evidence chain., type: dict, required: true}
author:
  - SGT-Trojan contributors (@SGT-Trojan)
notes:
  - Supports check mode and always reports C(changed=false).
  - A derived plan is data and does not authorize live access.
"""

EXAMPLES = r"""
- name: Derive the pending peer plan offline
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_next_plan:
    update_plan: "{{ checkpoint_deployment_agent_update.plan }}"
    reacquisition_plan: "{{ checkpoint_deployment_agent_reacquisition.reacquisition_plan }}"
    target_states: "{{ checkpoint_deployment_agent_post_update_states }}"
    evidence: "{{ checkpoint_deployment_agent_evidence.evidence }}"
"""

RETURN = r"""
plan:
  description: Deterministic pending-peer update plan.
  type: dict
  returned: success
category:
  description: Stable fail-closed validation category.
  type: str
  returned: failure
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_next import (
    DeploymentAgentNextError,
    plan_next_deployment_agent_update,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "update_plan": {"type": "dict", "required": True},
            "reacquisition_plan": {"type": "dict", "required": True},
            "target_states": {"type": "list", "elements": "dict", "required": True},
            "evidence": {"type": "dict", "required": True},
        },
        supports_check_mode=True,
    )
    try:
        plan = plan_next_deployment_agent_update(
            module.params["update_plan"],
            module.params["reacquisition_plan"],
            module.params["target_states"],
            module.params["evidence"],
        )
    except DeploymentAgentNextError as error:
        module.fail_json(msg=str(error), category=error.category, changed=False)
    module.exit_json(changed=False, plan=plan)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
