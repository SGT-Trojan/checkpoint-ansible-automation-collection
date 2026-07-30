from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.utils.verify_collection_policy import (
    PolicyVerificationError,
    verify_collection_policy,
)


class CollectionPolicyVerifierTests(unittest.TestCase):
    def _root(self, yaml_text: str = "", python_text: str = ""):
        temporary = TemporaryDirectory()
        root = Path(temporary.name)
        (root / "roles" / "sample" / "tasks").mkdir(parents=True)
        (root / "plugins" / "module_utils").mkdir(parents=True)
        (root / "roles" / "sample" / "tasks" / "main.yml").write_text(
            yaml_text or "- name: Safe\n  ansible.builtin.assert:\n    that: true\n",
            encoding="utf-8",
        )
        (root / "plugins" / "module_utils" / "sample.py").write_text(
            python_text or "from pathlib import Path\n",
            encoding="utf-8",
        )
        return temporary, root

    def test_accepts_supported_vendor_and_local_actions(self) -> None:
        temporary, root = self._root(
            "- name: Facts\n"
            "  check_point.gaia.cp_gaia_features_facts:\n"
            "- name: Local\n"
            "  sgt_trojan.checkpoint_automation.cp_automation_target_resolve:\n"
        )
        self.addCleanup(temporary.cleanup)
        self.assertEqual(verify_collection_policy(root), (1, 1))

    def test_rejects_command_like_actions_in_nested_sections(self) -> None:
        for action in (
            "command",
            "ansible.builtin.shell",
            "ansible.legacy.command",
            "ansible.legacy.shell",
            "ansible.legacy.raw",
            "ansible.legacy.script",
            "raw",
            "ansible.builtin.script",
        ):
            with self.subTest(action=action):
                temporary, root = self._root(
                    "- name: Nested\n"
                    "  block:\n"
                    "    - name: Escape\n"
                    f"      {action}:\n"
                    "        cmd: prohibited\n"
                )
                self.addCleanup(temporary.cleanup)
                with self.assertRaises(PolicyVerificationError):
                    verify_collection_policy(root)

    def test_rejects_deprecated_vendor_and_alternate_actions(self) -> None:
        for yaml_text in (
            "- name: Legacy\n  checkpoint_command:\n",
            "- name: Legacy\n  check_point.mgmt.checkpoint_command:\n",
            "- name: Legacy\n  check_point.gaia.checkpoint_facts:\n",
            "- name: Alternate\n  action: ansible.builtin.command prohibited\n",
            "- name: Alternate\n  local_action: command prohibited\n",
        ):
            with self.subTest(yaml_text=yaml_text):
                temporary, root = self._root(yaml_text)
                self.addCleanup(temporary.cleanup)
                with self.assertRaises(PolicyVerificationError):
                    verify_collection_policy(root)

    def test_rejects_subprocess_import_forms(self) -> None:
        for python_text in (
            "import subprocess\n",
            "import subprocess as process\n",
            "from subprocess import run\n",
        ):
            with self.subTest(python_text=python_text):
                temporary, root = self._root(python_text=python_text)
                self.addCleanup(temporary.cleanup)
                with self.assertRaises(PolicyVerificationError):
                    verify_collection_policy(root)

    def test_rejects_os_system_aliases(self) -> None:
        for python_text in (
            "import os\nos.system('prohibited')\n",
            "import os as operating_system\noperating_system.system('prohibited')\n",
            "from os import system\nsystem('prohibited')\n",
            "from os import system as execute\nexecute('prohibited')\n",
        ):
            with self.subTest(python_text=python_text):
                temporary, root = self._root(python_text=python_text)
                self.addCleanup(temporary.cleanup)
                with self.assertRaises(PolicyVerificationError):
                    verify_collection_policy(root)

    def test_rejects_dynamic_python_escape_forms(self) -> None:
        for python_text in (
            "__import__('subprocess')\n",
            "__import__('os').system('prohibited')\n",
            "import importlib\nimportlib.import_module('subprocess')\n",
            "import importlib\nimportlib.import_module('os').system('prohibited')\n",
            "from importlib import import_module as load\nload('subprocess')\n",
            "import os.path\nos.system('prohibited')\n",
            "from os import *\nsystem('prohibited')\n",
            "import os\ngetattr(os, 'system')('prohibited')\n",
            "import os\nos.popen('prohibited')\n",
            "from os import popen as execute\nexecute('prohibited')\n",
        ):
            with self.subTest(python_text=python_text):
                temporary, root = self._root(python_text=python_text)
                self.addCleanup(temporary.cleanup)
                with self.assertRaises(PolicyVerificationError):
                    verify_collection_policy(root)

    def test_scans_yaml_suffix_and_shipped_tests(self) -> None:
        temporary, root = self._root()
        self.addCleanup(temporary.cleanup)
        (root / "playbooks").mkdir()
        (root / "tests" / "integration").mkdir(parents=True)
        (root / "tests" / "unit").mkdir()
        (root / "playbooks" / "safe.yaml").write_text(
            "- name: Safe\n  hosts: localhost\n  tasks: []\n",
            encoding="utf-8",
        )
        (root / "tests" / "integration" / "safe.yaml").write_text(
            "- name: Safe\n  hosts: localhost\n  tasks: []\n",
            encoding="utf-8",
        )
        (root / "tests" / "unit" / "safe.py").write_text(
            "from pathlib import Path\n",
            encoding="utf-8",
        )
        self.assertEqual(verify_collection_policy(root), (3, 2))

    def test_non_string_yaml_action_key_fails_cleanly(self) -> None:
        temporary, root = self._root("- name: Invalid\n  true: value\n")
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(
            PolicyVerificationError,
            "task action keys must be strings",
        ):
            verify_collection_policy(root)

    def test_mixed_type_yaml_action_keys_fail_cleanly_with_location(self) -> None:
        temporary, root = self._root(
            "- name: Invalid\n  true: value\n  debug:\n    msg: value\n"
        )
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(
            PolicyVerificationError,
            r"roles/sample/tasks/main\.yml\[0\]: "
            r"task action keys must be strings",
        ):
            verify_collection_policy(root)


if __name__ == "__main__":
    unittest.main()
