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
module: cp_automation_target_resolve
short_description: Resolve member addresses to one managed Check Point cluster
version_added: "0.1.0"
description:
  - Resolves requested gateway addresses against complete Management API facts.
  - Fails when discovery is incomplete, ambiguous, or not a two-member cluster.
  - Performs no network calls and makes no changes.
options:
  target_ips:
    description: Member addresses that must belong to one managed cluster.
    type: list
    elements: str
    required: true
  domain_data:
    description:
      - Complete regular-domain records and their gateway, server, and cluster facts.
      - Pagination must be completed before calling this module.
    type: list
    elements: dict
    required: true
    suboptions:
      domain:
        description: Raw domain record including its management servers.
        type: dict
        required: true
      objects:
        description: Complete gateways-and-servers result for the domain.
        type: list
        elements: dict
        required: true
      cluster_details:
        description: Full cluster records keyed by cluster UID.
        type: dict
        required: true
  preferred_domain:
    description: Optional exact domain or active CMA name.
    type: str
    default: ""
author:
  - SGT-Trojan contributors (@SGT-Trojan)
"""

EXAMPLES = r"""
- name: Resolve the requested cluster
  sgt_trojan.checkpoint_automation.cp_automation_target_resolve:
    target_ips:
      - 192.0.2.10
      - 192.0.2.11
    domain_data: "{{ checkpoint_domain_data }}"
    preferred_domain: Domain-A
  register: resolved_cluster
"""

RETURN = r"""
resolved:
  description: Exact domain, CMA, cluster, policy, and member identity.
  type: dict
  returned: success
category:
  description: Stable failure category when resolution is rejected.
  type: str
  returned: failure
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.topology import (
    TopologyError,
    resolve_targets,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "target_ips": {
                "type": "list",
                "elements": "str",
                "required": True,
            },
            "domain_data": {
                "type": "list",
                "elements": "dict",
                "required": True,
                "options": {
                    "domain": {"type": "dict", "required": True},
                    "objects": {
                        "type": "list",
                        "elements": "dict",
                        "required": True,
                    },
                    "cluster_details": {"type": "dict", "required": True},
                },
            },
            "preferred_domain": {
                "type": "str",
                "default": "",
            },
        },
        supports_check_mode=True,
    )
    try:
        resolved = resolve_targets(
            module.params["domain_data"],
            module.params["target_ips"],
            module.params["preferred_domain"],
        )
    except TopologyError as error:
        module.fail_json(
            msg=str(error),
            category=error.category,
            changed=False,
        )
    module.exit_json(changed=False, resolved=resolved)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
