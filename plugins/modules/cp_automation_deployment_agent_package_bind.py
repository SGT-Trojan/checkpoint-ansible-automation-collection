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
module: cp_automation_deployment_agent_package_bind
short_description: Bind a validated Deployment Agent package to build policy
version_added: "0.1.0"
description:
  - Accepts one normalized Deployment Agent install or upgrade step returned
    by C(cp_automation_package_validate).
  - Binds its exact path, file name, size, SHA-256, and two target identities
    to a required minimum build and exact expected build.
  - Returns data for a later reviewed staging or update boundary.
  - Performs no filesystem, network, staging, or update operation.
options:
  package_step:
    description:
      - One normalized step from the C(validation.steps) result of
        C(cp_automation_package_validate).
      - The step must use C(package_type=deployment_agent).
    type: dict
    required: true
  required_build:
    description: Minimum Deployment Agent build accepted by the package plan.
    type: int
    required: true
  expected_build:
    description:
      - Exact build required after the approved offline update.
      - Must be greater than or equal to C(required_build).
    type: int
    required: true
author:
  - SGT-Trojan contributors (@SGT-Trojan)
notes:
  - Supports check mode and always reports C(changed=false).
"""

EXAMPLES = r"""
- name: Bind the validated offline Deployment Agent package
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_package_bind:
    package_step: "{{ checkpoint_package_contract.validation.steps[0] }}"
    required_build: 2771
    expected_build: 2771
  register: checkpoint_deployment_agent_package
"""

RETURN = r"""
binding:
  description:
    - Exact package, target, and numeric build binding.
    - Includes a deterministic C(binding_sha256) over the other binding fields.
  type: dict
  returned: success
category:
  description: Stable fail-closed validation category.
  type: str
  returned: failure
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_package import (
    DeploymentAgentPackageError,
    bind_deployment_agent_package,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "package_step": {"type": "dict", "required": True},
            "required_build": {"type": "int", "required": True},
            "expected_build": {"type": "int", "required": True},
        },
        supports_check_mode=True,
    )
    try:
        binding = bind_deployment_agent_package(
            module.params["package_step"],
            module.params["required_build"],
            module.params["expected_build"],
        )
    except DeploymentAgentPackageError as error:
        module.fail_json(
            msg=str(error),
            category=error.category,
            changed=False,
        )
    module.exit_json(changed=False, binding=binding)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
