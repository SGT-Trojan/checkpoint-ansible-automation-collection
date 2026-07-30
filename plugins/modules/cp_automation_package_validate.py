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
module: cp_automation_package_validate
short_description: Validate an offline Check Point package contract
version_added: "0.1.0"
description:
  - Validates exact package identity, mandatory SHA-256, action semantics,
    declared package prerequisites, and major-upgrade restore capacity.
  - Requires every step to declare its exact target IDs and one complete
    installed-package inventory observation for each target.
  - Accepts only the documented conservative package types and rejects an
    identity containing any case-insensitive Blink substring when relabelled
    as a non-major type.
  - Consumes structured observations and performs no filesystem or network I/O.
  - Makes no changes and is safe in check mode.
options:
  package_steps:
    description: Ordered package action contracts.
    type: list
    elements: dict
    required: true
  artifacts:
    description: Exact precomputed file path, size, and SHA-256 observations.
    type: list
    elements: dict
    required: true
  target_states:
    description:
      - Structured observations bound to an exact step and target identity.
      - Each observation must set C(installed_packages_complete=true).
      - Only an acquisition path that proves complete inventory may set the
        completeness flag.
    type: list
    elements: dict
    required: true
author:
  - SGT-Trojan contributors (@SGT-Trojan)
"""

EXAMPLES = r"""
- name: Validate a package plan before any live lease
  sgt_trojan.checkpoint_automation.cp_automation_package_validate:
    package_steps: "{{ checkpoint_package_steps }}"
    artifacts: "{{ checkpoint_package_artifacts }}"
    target_states: "{{ checkpoint_package_target_states }}"
  register: checkpoint_package_contract
"""

RETURN = r"""
validation:
  description: Normalized, validated package contract and sanitized counts.
  type: dict
  returned: success
category:
  description: Stable fail-closed validation category.
  type: str
  returned: failure
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.package_validation import (
    PackageValidationError,
    validate_package_contract,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "package_steps": {
                "type": "list",
                "elements": "dict",
                "required": True,
            },
            "artifacts": {
                "type": "list",
                "elements": "dict",
                "required": True,
            },
            "target_states": {
                "type": "list",
                "elements": "dict",
                "required": True,
            },
        },
        supports_check_mode=True,
    )
    try:
        result = validate_package_contract(
            module.params["package_steps"],
            module.params["artifacts"],
            module.params["target_states"],
        )
    except PackageValidationError as error:
        module.fail_json(
            msg=str(error),
            category=error.category,
            changed=False,
        )
    module.exit_json(changed=False, validation=result)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
