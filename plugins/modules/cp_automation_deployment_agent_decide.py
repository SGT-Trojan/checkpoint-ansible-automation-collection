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
module: cp_automation_deployment_agent_decide
short_description: Evaluate normalized Check Point Deployment Agent state
version_added: "0.1.0"
description:
  - Compares one normalized Deployment Agent observation with a required
    minimum build and, when supplied, one exact expected build.
  - Build readiness is numeric. Cloud-status prose is returned as evidence but
    never overrides the required build.
  - The module does not acquire status, stage files, or update the agent.
options:
  observation:
    description:
      - Normalized observation returned by
        C(cp_automation_deployment_agent_observe).
      - Requires only C(enabled), C(build), and C(cloud_state).
    type: dict
    required: true
    suboptions:
      enabled:
        description: Whether the Deployment Agent reports C(Enabled).
        type: bool
        required: true
      build:
        description: Positive numeric Deployment Agent build.
        type: int
        required: true
      cloud_state:
        description: Bounded interpretation of the optional build note.
        type: str
        required: true
        choices:
          - current
          - update_available
          - unknown
  required_build:
    description: Minimum acceptable Deployment Agent build.
    type: int
    required: true
  expected_build:
    description:
      - Exact build required after a controlled offline update.
      - When omitted, any build at or above C(required_build) is accepted.
    type: int
author:
  - SGT-Trojan contributors (@SGT-Trojan)
notes:
  - Supports check mode and always reports C(changed=false).
"""

EXAMPLES = r"""
- name: Require the approved minimum Deployment Agent build
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_decide:
    observation: "{{ deployment_agent_observation }}"
    required_build: 2771
  register: deployment_agent_gate

- name: Reconcile one exact offline update result
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_decide:
    observation: "{{ deployment_agent_observation }}"
    required_build: 2771
    expected_build: 2771
"""

RETURN = r"""
decision:
  description: Readiness result with normalized build evidence and reasons.
  type: dict
  returned: success
category:
  description: Stable invalid-input category.
  type: str
  returned: failure
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent import (
    DeploymentAgentError,
    decide,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "observation": {
                "type": "dict",
                "required": True,
                "options": {
                    "enabled": {"type": "bool", "required": True},
                    "build": {"type": "int", "required": True},
                    "cloud_state": {
                        "type": "str",
                        "required": True,
                        "choices": (
                            "current",
                            "update_available",
                            "unknown",
                        ),
                    },
                },
            },
            "required_build": {"type": "int", "required": True},
            "expected_build": {"type": "int"},
        },
        supports_check_mode=True,
    )
    try:
        decision = decide(
            module.params["observation"],
            module.params["required_build"],
            module.params["expected_build"],
        )
    except DeploymentAgentError as error:
        module.fail_json(
            msg=str(error),
            category=error.category,
            changed=False,
        )
    module.exit_json(changed=False, decision=decision)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
