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
module: cp_automation_deployment_agent_reacquire_plan
short_description: Plan fixed Deployment Agent status reacquisition offline
version_added: "0.1.0"
description:
  - Revalidates one deterministic Deployment Agent update plan.
  - Fixes exactly two read-only status observations in selected-then-peer order.
  - Returns data for later separately authorized acquisition and reconciliation.
  - Performs no filesystem, lease, network, target, or update operation.
options:
  update_plan:
    description: Exact output from C(cp_automation_deployment_agent_update_plan).
    type: dict
    required: true
author:
  - SGT-Trojan contributors (@SGT-Trojan)
notes:
  - Supports check mode and always reports C(changed=false).
  - The returned target order does not authorize acquisition or live access.
"""

EXAMPLES = r"""
- name: Plan two post-update status observations offline
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_reacquire_plan:
    update_plan: "{{ checkpoint_deployment_agent_update.plan }}"
  register: checkpoint_deployment_agent_reacquisition
"""

RETURN = r"""
reacquisition_plan:
  description: Deterministic selected-then-peer read-only observation plan.
  type: dict
  returned: success
category:
  description: Stable fail-closed validation category.
  type: str
  returned: failure
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_reacquire import (
    DeploymentAgentReacquireError,
    plan_deployment_agent_reacquisition,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={"update_plan": {"type": "dict", "required": True}},
        supports_check_mode=True,
    )
    try:
        plan = plan_deployment_agent_reacquisition(module.params["update_plan"])
    except DeploymentAgentReacquireError as error:
        module.fail_json(msg=str(error), category=error.category, changed=False)
    module.exit_json(changed=False, reacquisition_plan=plan)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
