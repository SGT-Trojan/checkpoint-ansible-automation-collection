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
module: cp_automation_deployment_agent_package_transport
short_description: Transport one lease-bound Deployment Agent package
version_added: "0.1.0"
description:
  - Revalidates one content-addressed staged package on the controller.
  - Streams bounded chunks to only the selected, lease-bound firewall member.
  - Rechecks the complete authorization and expiry before every remote write.
  - Rejects packages larger than 128 MiB at this transport boundary.
  - Publishes only an exact SHA-256-matching package beneath a fixed owner-only
    directory in the connected account home.
  - Performs no Deployment Agent update request or task polling.
options:
  lease:
    description: Exact short-lived private execution authorization.
    type: dict
    required: true
  update_plan:
    description: Exact output from the offline update planner.
    type: dict
    required: true
  staging:
    description: Exact content-addressed controller staging evidence.
    type: dict
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
    description: Effective HTTPAPI certificate-validation state for later use.
    type: bool
    required: true
  lab_tls_exception_acknowledged:
    description: Literal lab-only TLS exception acknowledgment.
    type: bool
    required: true
  _member_target_id:
    description: Internal action-managed selected inventory identity.
    type: str
    required: true
  _member_address:
    description: Internal action-managed connected member address.
    type: str
    required: true
  _ssh_host_key_checking_enabled:
    description: Internal action-observed SSH host-key validation state.
    type: bool
    required: true
  _offset:
    description: Internal action-managed exact byte offset.
    type: int
    required: true
  _content_base64:
    description: Internal action-managed canonical bounded package chunk.
    type: str
    required: true
  _final:
    description: Internal action-managed exact-size completion marker.
    type: bool
    required: true
author:
  - SGT-Trojan contributors (@SGT-Trojan)
notes:
  - Requires the SSH connection plugin with host-key checking enabled.
  - This mutating transport is intentionally rejected in check mode.
  - The action plugin supplies internal chunk fields to the remote module.
  - The published package is data for a separately reviewed update executor.
"""

EXAMPLES = r"""
- name: Transport the exact staged package without installing it
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_package_transport:
    lease: "{{ checkpoint_deployment_agent_execution_lease }}"
    update_plan: "{{ checkpoint_deployment_agent_update.plan }}"
    staging: "{{ checkpoint_deployment_agent_staging }}"
    member_targets: "{{ checkpoint_deployment_agent_execution_targets }}"
    runtime_commit: "{{ checkpoint_deployment_agent_runtime_commit }}"
    tls_validation_enabled: true
    lab_tls_exception_acknowledged: false
"""

RETURN = r"""
transport:
  description: Content-addressed firewall-local package evidence.
  type: dict
  returned: success
authorization:
  description: Sanitized execution-preflight result.
  type: dict
  returned: success
category:
  description: Stable fail-closed transport category.
  type: str
  returned: failure
"""

from datetime import datetime, timezone

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_package_transport import (
    DeploymentAgentPackageTransportError,
    receive_deployment_agent_package_chunk,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "lease": {"type": "dict", "required": True},
            "update_plan": {"type": "dict", "required": True},
            "staging": {"type": "dict", "required": True},
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
            "_member_target_id": {"type": "str", "required": True},
            "_member_address": {"type": "str", "required": True},
            "_ssh_host_key_checking_enabled": {"type": "bool", "required": True},
            "_offset": {"type": "int", "required": True},
            "_content_base64": {"type": "str", "required": True, "no_log": True},
            "_final": {"type": "bool", "required": True},
        },
        supports_check_mode=True,
    )
    internal = {
        key[1:]: value
        for key, value in module.params.items()
        if key.startswith("_")
    }
    public = {
        key: value
        for key, value in module.params.items()
        if not key.startswith("_")
    }
    try:
        result = receive_deployment_agent_package_chunk(
            check_mode=module.check_mode,
            now=datetime.now(timezone.utc),
            **public,
            **internal,
        )
    except DeploymentAgentPackageTransportError as error:
        module.fail_json(msg=str(error), category=error.category, changed=False)
    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
