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
module: cp_automation_artifact_observe
short_description: Observe one exact localhost package artifact
version_added: "0.1.0"
description:
  - Opens one canonical absolute expected path without following symbolic links
    in any path component.
  - Requires a positive-size regular file, streams SHA-256 in bounded chunks,
    performs two exact-size hash passes on one descriptor, and revalidates
    descriptor and path identity, mode, size, mtime, and ctime.
  - Bounds both actual bytes and read calls per pass. The read-call budget is
    derived from expected size with conservative slack for legal short reads.
  - Success is a point-in-time observation and does not authorize later use of
    the path. A mutating consumer must reobserve immediately before use and
    hash and consume the retained descriptor, or atomically stage and consume
    an immutable content-addressed copy.
  - Requires POSIX/Linux-style O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC, O_NONBLOCK,
    and directory-relative open support on the controller.
  - Returns no file content, performs no network request, and makes no changes.
  - Must be invoked through the localhost-pinned artifact observation role.
options:
  expected_path:
    description: One canonical absolute local package path.
    type: path
    required: true
author:
  - SGT-Trojan contributors (@SGT-Trojan)
"""

EXAMPLES = r"""
- name: Observe one local package artifact
  ansible.builtin.include_role:
    name: sgt_trojan.checkpoint_automation.checkpoint_artifact_observation
  vars:
    checkpoint_artifact_expected_path: /srv/checkpoint/packages/package.tgz
"""

RETURN = r"""
artifact:
  description:
    - Exact path, positive byte size, and lowercase SHA-256 at observation time.
    - Does not authorize a future path read or eliminate post-return TOCTOU.
  type: dict
  returned: success
category:
  description: Stable fail-closed observation category.
  type: str
  returned: failure
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.artifact_observation import (
    ArtifactObservationError,
    observe_artifact,
)


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "expected_path": {"type": "path", "required": True},
        },
        supports_check_mode=True,
    )
    try:
        artifact = observe_artifact(module.params["expected_path"])
    except ArtifactObservationError as error:
        module.fail_json(
            msg=str(error),
            category=error.category,
            changed=False,
        )
    module.exit_json(changed=False, artifact=artifact)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
