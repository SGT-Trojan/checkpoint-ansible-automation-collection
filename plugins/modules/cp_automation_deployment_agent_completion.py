#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r"""
---
module: cp_automation_deployment_agent_completion
short_description: Attest exact two-member Deployment Agent completion offline
version_added: "0.1.0"
description:
  - Rederives the pending-peer update plan from the first exact evidence chain.
  - Revalidates the second fixed reacquisition and final exact evidence chain.
  - Succeeds only when final reconciliation reports both members complete.
  - Performs no filesystem, acquisition, lease, network, target, or update action.
options:
  first_update_plan: {description: First member update plan., type: dict, required: true}
  first_reacquisition_plan: {description: First fixed reacquisition plan., type: dict, required: true}
  first_target_states: {description: States after the first update., type: list, elements: dict, required: true}
  first_evidence: {description: Exact first evidence chain., type: dict, required: true}
  second_reacquisition_plan: {description: Second fixed reacquisition plan., type: dict, required: true}
  final_target_states: {description: States after the second update., type: list, elements: dict, required: true}
  final_evidence: {description: Exact final evidence chain., type: dict, required: true}
author:
  - SGT-Trojan contributors (@SGT-Trojan)
notes:
  - Supports check mode and always reports C(changed=false).
  - Completion evidence is data and does not authorize live access.
"""

EXAMPLES = r"""
- name: Attest two-member completion offline
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_completion:
    first_update_plan: "{{ checkpoint_deployment_agent_update.plan }}"
    first_reacquisition_plan: "{{ checkpoint_deployment_agent_reacquisition.reacquisition_plan }}"
    first_target_states: "{{ checkpoint_deployment_agent_first_post_update_states }}"
    first_evidence: "{{ checkpoint_deployment_agent_first_evidence.evidence }}"
    second_reacquisition_plan: "{{ checkpoint_deployment_agent_second_reacquisition.reacquisition_plan }}"
    final_target_states: "{{ checkpoint_deployment_agent_final_states }}"
    final_evidence: "{{ checkpoint_deployment_agent_final_evidence.evidence }}"
"""

RETURN = r"""
completion:
  description: Deterministic exact-completion attestation.
  type: dict
  returned: success
category:
  description: Stable fail-closed validation category.
  type: str
  returned: failure
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_completion import (
    DeploymentAgentCompletionError,
    attest_deployment_agent_completion,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "first_update_plan": {"type": "dict", "required": True},
            "first_reacquisition_plan": {"type": "dict", "required": True},
            "first_target_states": {
                "type": "list",
                "elements": "dict",
                "required": True,
            },
            "first_evidence": {"type": "dict", "required": True},
            "second_reacquisition_plan": {"type": "dict", "required": True},
            "final_target_states": {
                "type": "list",
                "elements": "dict",
                "required": True,
            },
            "final_evidence": {"type": "dict", "required": True},
        },
        supports_check_mode=True,
    )
    try:
        completion = attest_deployment_agent_completion(
            module.params["first_update_plan"],
            module.params["first_reacquisition_plan"],
            module.params["first_target_states"],
            module.params["first_evidence"],
            module.params["second_reacquisition_plan"],
            module.params["final_target_states"],
            module.params["final_evidence"],
        )
    except DeploymentAgentCompletionError as error:
        module.fail_json(msg=str(error), category=error.category, changed=False)
    module.exit_json(changed=False, completion=completion)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
