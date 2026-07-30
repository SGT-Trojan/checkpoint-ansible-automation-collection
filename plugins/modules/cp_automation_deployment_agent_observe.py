#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later
#
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r"""
---
module: cp_automation_deployment_agent_observe
short_description: Normalize Check Point Deployment Agent status
version_added: "0.1.0"
description:
  - Parses complete C(show installer status all) output into bounded,
    non-secret Deployment Agent state.
  - Requires exactly one Agent field and one positive numeric Build number.
  - Does not connect to Gaia or run a command.
options:
  status_output:
    description:
      - Complete output from C(show installer status all).
      - The value is hidden from normal Ansible logging.
    type: str
    required: true
author:
  - SGT-Trojan contributors (@SGT-Trojan)
notes:
  - Supports check mode and always reports C(changed=false).
"""

EXAMPLES = r"""
- name: Normalize previously acquired Deployment Agent status
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_observe:
    status_output: "{{ deployment_agent_status_output }}"
  register: deployment_agent_state
"""

RETURN = r"""
observation:
  description: Enabled state, numeric build, and bounded cloud state.
  type: dict
  returned: success
category:
  description: Stable status parsing failure category.
  type: str
  returned: failure
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent import (
    DeploymentAgentError,
    parse_status,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "status_output": {
                "type": "str",
                "required": True,
                "no_log": True,
            },
        },
        supports_check_mode=True,
    )
    try:
        observation = parse_status(module.params["status_output"])
    except DeploymentAgentError as error:
        module.fail_json(
            msg=str(error),
            category=error.category,
            changed=False,
        )
    module.exit_json(changed=False, observation=observation)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
