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
module: cp_automation_deployment_agent_artifact_stage
short_description: Stage one preflight-authorized Deployment Agent artifact
version_added: "0.1.0"
description:
  - Revalidates one exact update plan and controller-local artifact before use.
  - Runs the existing execution preflight before creating any staged content.
  - Copies from a retained no-follow descriptor into a content-addressed,
    read-only file beneath one pre-existing controller-local staging directory.
  - Rechecks lease expiry immediately before temporary-file creation and
    atomic publication.
  - Performs no firewall request and never executes the Deployment Agent update.
options:
  lease:
    description: Exact short-lived private execution authorization.
    type: dict
    required: true
  update_plan:
    description: Exact output from the offline update planner.
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
  staging_root:
    description:
      - Pre-existing canonical controller-local directory.
      - Every path component must be a genuine directory, not a symbolic link.
      - The final directory must be owned by the executing user and must not be
        group-writable or other-writable.
    type: path
    required: true
author:
  - SGT-Trojan contributors (@SGT-Trojan)
notes:
  - This mutating module is intentionally rejected in check mode.
  - The staged path is controller-local input for a future reviewed transport.
"""

EXAMPLES = r"""
- name: Stage one exact artifact without contacting the firewall
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_artifact_stage:
    lease: "{{ checkpoint_deployment_agent_execution_lease }}"
    update_plan: "{{ checkpoint_deployment_agent_update.plan }}"
    member_target_id: "{{ inventory_hostname }}"
    member_address: "{{ ansible_host }}"
    member_targets: "{{ checkpoint_deployment_agent_execution_targets }}"
    runtime_commit: "{{ checkpoint_deployment_agent_runtime_commit }}"
    tls_validation_enabled: "{{ ansible_httpapi_validate_certs }}"
    lab_tls_exception_acknowledged: false
    staging_root: /var/lib/checkpoint-automation/staging
  delegate_to: localhost
"""

RETURN = r"""
staging:
  description: Content-addressed controller-local path and exact package evidence.
  type: dict
  returned: success
authorization:
  description: Sanitized execution-preflight result.
  type: dict
  returned: success
category:
  description: Stable fail-closed staging category.
  type: str
  returned: failure
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_artifact_staging import (
    DeploymentAgentArtifactStagingError,
    stage_deployment_agent_artifact,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "lease": {"type": "dict", "required": True},
            "update_plan": {"type": "dict", "required": True},
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
            "staging_root": {"type": "path", "required": True},
        },
        supports_check_mode=True,
    )
    try:
        result = stage_deployment_agent_artifact(
            check_mode=module.check_mode,
            **module.params,
        )
    except DeploymentAgentArtifactStagingError as error:
        module.fail_json(msg=str(error), category=error.category, changed=False)
    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
