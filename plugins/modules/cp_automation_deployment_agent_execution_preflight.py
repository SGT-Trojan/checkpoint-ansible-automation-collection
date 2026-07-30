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
module: cp_automation_deployment_agent_execution_preflight
short_description: Authorize one exact Deployment Agent update plan
version_added: "0.1.0"
description:
  - Revalidates one update plan, fresh artifact observation, exact two-member
    runtime binding, approved candidate commit, TLS mode, and short lease.
  - Performs no filesystem or network operation and does not execute the plan.
options:
  lease:
    description: Exact short-lived private execution authorization.
    type: dict
    required: true
  update_plan:
    description: Exact output from the offline update planner.
    type: dict
    required: true
  artifact_observation:
    description: Fresh path, size, and SHA-256 artifact observation.
    type: dict
    required: true
  member_target_id:
    description: Current inventory identity; must be the selected plan member.
    type: str
    required: true
  member_address:
    description: Current inventory-bound member IP address.
    type: str
    required: true
  member_targets:
    description: Exact runtime target identity and address bindings.
    type: list
    elements: dict
    required: true
  runtime_commit:
    description: Full commit hash of the executing collection checkout.
    type: str
    required: true
  tls_validation_enabled:
    description: Effective HTTPAPI certificate-validation state.
    type: bool
    required: true
  lab_tls_exception_acknowledged:
    description: Literal lab-only TLS exception acknowledgment.
    type: bool
    required: true
author:
  - SGT-Trojan contributors (@SGT-Trojan)
notes:
  - This preflight is intentionally rejected in check mode.
  - Success is sanitized authorization data, not execution.
"""

EXAMPLES = r"""
- name: Revalidate one independently approved update immediately before execution
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_execution_preflight:
    lease: "{{ checkpoint_deployment_agent_execution_lease }}"
    update_plan: "{{ checkpoint_deployment_agent_update.plan }}"
    artifact_observation: "{{ checkpoint_deployment_agent_artifact.artifact }}"
    member_target_id: "{{ inventory_hostname }}"
    member_address: "{{ ansible_host }}"
    member_targets: "{{ checkpoint_deployment_agent_execution_targets }}"
    runtime_commit: "{{ checkpoint_deployment_agent_runtime_commit }}"
    tls_validation_enabled: "{{ ansible_httpapi_validate_certs }}"
    lab_tls_exception_acknowledged: false
  delegate_to: localhost
"""

RETURN = r"""
authorization:
  description: Sanitized exact-plan authorization without target addresses.
  type: dict
  returned: success
category:
  description: Stable failure category.
  type: str
  returned: failure
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_execution_preflight import (
    DeploymentAgentExecutionPreflightError,
    authorize_deployment_agent_execution,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "lease": {"type": "dict", "required": True},
            "update_plan": {"type": "dict", "required": True},
            "artifact_observation": {"type": "dict", "required": True},
            "member_target_id": {"type": "str", "required": True},
            "member_address": {"type": "str", "required": True},
            "member_targets": {
                "type": "list",
                "elements": "dict",
                "required": True,
            },
            "runtime_commit": {"type": "str", "required": True},
            "tls_validation_enabled": {"type": "bool", "required": True},
            "lab_tls_exception_acknowledged": {
                "type": "bool",
                "required": True,
            },
        },
        supports_check_mode=True,
    )
    try:
        authorization = authorize_deployment_agent_execution(
            check_mode=module.check_mode,
            **module.params,
        )
    except DeploymentAgentExecutionPreflightError as error:
        module.fail_json(msg=str(error), category=error.category, changed=False)
    module.exit_json(changed=False, authorization=authorization)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
