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
module: cp_automation_deployment_agent_update_plan
short_description: Plan one bound Deployment Agent update offline
version_added: "0.1.0"
description:
  - Validates one package binding and normalized state for its two targets.
  - Selects exactly one target and binds it to the fixed Deployment Agent
    install operation and expected build.
  - Returns a deterministic plan for a later separately reviewed executor.
  - Performs no filesystem, staging, lease, network, or target operation.
options:
  package_binding:
    description: Exact output from C(cp_automation_deployment_agent_package_bind).
    type: dict
    required: true
  target_states:
    description:
      - Two normalized Deployment Agent states.
      - Each state contains only C(target_id), C(enabled), C(build), and
        C(cloud_state).
    type: list
    elements: dict
    required: true
  selected_target_id:
    description: One exact target identity from the package binding.
    type: str
    required: true
author:
  - SGT-Trojan contributors (@SGT-Trojan)
notes:
  - Supports check mode and always reports C(changed=false).
  - A returned plan is data and does not authorize live access by itself.
"""

EXAMPLES = r"""
- name: Plan one offline Deployment Agent update
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_update_plan:
    package_binding: "{{ checkpoint_deployment_agent_package_binding }}"
    target_states: "{{ checkpoint_deployment_agent_states }}"
    selected_target_id: member-a
  register: checkpoint_deployment_agent_update
"""

RETURN = r"""
plan:
  description: Deterministic fixed-operation update plan.
  type: dict
  returned: success
category:
  description: Stable fail-closed validation category.
  type: str
  returned: failure
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_update import (
    DeploymentAgentUpdateError,
    plan_deployment_agent_update,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "package_binding": {"type": "dict", "required": True},
            "target_states": {
                "type": "list",
                "elements": "dict",
                "required": True,
            },
            "selected_target_id": {"type": "str", "required": True},
        },
        supports_check_mode=True,
    )
    try:
        plan = plan_deployment_agent_update(
            module.params["package_binding"],
            module.params["target_states"],
            module.params["selected_target_id"],
        )
    except DeploymentAgentUpdateError as error:
        module.fail_json(msg=str(error), category=error.category, changed=False)
    module.exit_json(changed=False, plan=plan)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
