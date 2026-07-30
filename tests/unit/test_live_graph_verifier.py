from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

from pathlib import Path
import tempfile
import unittest

import yaml

from tests.utils.verify_live_readonly_graph import (
    APPROVED_ACTIONS,
    GraphVerificationError,
    GraphVerifier,
    PAGINATION_RECURSION_GUARDS,
    verify_live_graph,
)


ROOT = Path(__file__).resolve().parents[2]


class GraphFixture:
    def __init__(self, playbook: list) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "playbooks").mkdir()
        self.write("playbooks/root.yml", playbook)

    def write(self, relative: str, value: object) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")

    def close(self) -> None:
        self.temporary.cleanup()


class LiveGraphVerifierTests(unittest.TestCase):
    def assert_rejected(
        self,
        playbook: list,
        approved: frozenset[str],
        prepare=None,
    ) -> None:
        fixture = GraphFixture(playbook)
        try:
            if prepare:
                prepare(fixture)
            verifier = GraphVerifier(
                fixture.root,
                approved_actions=approved,
                required_actions=approved,
            )
            with self.assertRaises(GraphVerificationError):
                verifier.verify(Path("playbooks/root.yml"))
        finally:
            fixture.close()

    def test_shipped_graph_is_complete_and_exact(self) -> None:
        report = verify_live_graph(ROOT)
        self.assertEqual(set(report.actions), set(APPROVED_ACTIONS))
        self.assertIn("playbooks/live_readonly_managed_discovery.yml", report.files)
        self.assertIn("playbooks/resolve_managed_cluster.yml", report.files)
        self.assertTrue(
            any(
                path.endswith("checkpoint_live_readonly_preflight/tasks/main.yml")
                for path in report.files
            )
        )

    def test_dynamic_and_external_task_includes_are_rejected(self) -> None:
        include = "ansible.builtin.include_tasks"
        for target in ("{{ selected_tasks }}", "../../outside.yml", "https://invalid/tasks.yml"):
            playbook = [
                {
                    "hosts": "localhost",
                    "tasks": [{"name": "include", include: target}],
                }
            ]
            with self.subTest(target=target):
                self.assert_rejected(playbook, frozenset({include}))

    def test_dynamic_external_and_short_roles_are_rejected(self) -> None:
        include = "ansible.builtin.include_role"
        for role_name in (
            "{{ selected_role }}",
            "other.collection.role",
            "checkpoint_mds_domains",
        ):
            playbook = [
                {
                    "hosts": "localhost",
                    "tasks": [
                        {
                            "name": "include",
                            include: {"name": role_name},
                        }
                    ],
                }
            ]
            with self.subTest(role_name=role_name):
                self.assert_rejected(playbook, frozenset({include}))

    def test_action_and_local_action_forms_are_rejected_at_depth(self) -> None:
        for alternate in ("action", "local_action"):
            playbook = [
                {
                    "hosts": "localhost",
                    "tasks": [
                        {
                            "name": "outer",
                            "block": [
                                {
                                    "name": "inner",
                                    "block": [
                                        {
                                            "name": "alternate",
                                            alternate: "ansible.builtin.assert",
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
            with self.subTest(alternate=alternate):
                self.assert_rejected(playbook, frozenset())

    def test_unapproved_module_is_found_through_literal_nested_include(self) -> None:
        include = "ansible.builtin.include_tasks"
        playbook = [
            {
                "hosts": "localhost",
                "tasks": [{"name": "include", include: "nested.yml"}],
            }
        ]

        def prepare(fixture):
            fixture.write(
                "playbooks/nested.yml",
                [
                    {
                        "name": "outer",
                        "block": [
                            {
                                "name": "inner",
                                "block": [
                                    {
                                        "name": "mutation",
                                        "check_point.mgmt.cp_mgmt_install_software_package": {},
                                    }
                                ],
                            }
                        ],
                    }
                ],
            )

        self.assert_rejected(playbook, frozenset({include}), prepare)

    def test_import_playbook_must_be_literal_local_and_fully_verified(self) -> None:
        action = "ansible.builtin.import_playbook"
        for target in ("{{ selected_play }}", "../../outside.yml"):
            playbook = [{action: target}]
            with self.subTest(target=target):
                self.assert_rejected(playbook, frozenset({action}))

    def test_arbitrary_two_file_include_cycle_is_rejected(self) -> None:
        include = "ansible.builtin.include_tasks"
        playbook = [
            {
                "hosts": "localhost",
                "tasks": [{"name": "start", include: "first.yml"}],
            }
        ]

        def prepare(fixture):
            fixture.write(
                "playbooks/first.yml",
                [{"name": "second", include: "second.yml"}],
            )
            fixture.write(
                "playbooks/second.yml",
                [{"name": "first", include: "first.yml"}],
            )

        self.assert_rejected(playbook, frozenset({include}), prepare)

    def test_unapproved_task_self_cycle_is_rejected(self) -> None:
        include = "ansible.builtin.include_tasks"
        playbook = [
            {
                "hosts": "localhost",
                "tasks": [{"name": "start", include: "nested.yml"}],
            }
        ]

        def prepare(fixture):
            fixture.write(
                "playbooks/nested.yml",
                [{"name": "again", include: "nested.yml", "when": ["true"]}],
            )

        self.assert_rejected(playbook, frozenset({include}), prepare)

    def test_each_shipped_pagination_self_recursion_is_guarded(self) -> None:
        report = verify_live_graph(ROOT)
        verifier = GraphVerifier(ROOT)
        for relative, expected_guard in PAGINATION_RECURSION_GUARDS.items():
            with self.subTest(relative=relative):
                self.assertIn(relative, report.files)
                path = ROOT / relative
                task = yaml.safe_load(path.read_text(encoding="utf-8"))[-1]
                self.assertEqual(
                    task["ansible.builtin.include_tasks"],
                    path.name,
                )
                verifier._validate_recursion_edge(path, path, task)
                self.assertEqual(task["when"], [expected_guard])

    def test_approved_recursion_guard_change_is_rejected(self) -> None:
        verifier = GraphVerifier(ROOT)
        for relative in PAGINATION_RECURSION_GUARDS:
            with self.subTest(relative=relative):
                path = ROOT / relative
                task = yaml.safe_load(path.read_text(encoding="utf-8"))[-1]
                task["when"] = ["checkpoint_next_offset | int > 0"]
                with self.assertRaises(GraphVerificationError):
                    verifier._validate_recursion_edge(path, path, task)


if __name__ == "__main__":
    unittest.main()
