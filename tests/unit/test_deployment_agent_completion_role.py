from __future__ import annotations

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "roles" / "checkpoint_deployment_agent_completion"
TASKS = ROLE / "tasks" / "main.yml"
DEFAULTS = ROLE / "defaults" / "main.yml"
INTEGRATION = (
    ROOT / "tests" / "integration" / "deployment_agent_completion_syntax.yml"
)
COMPOSITION = (
    ROOT
    / "tests"
    / "integration"
    / "deployment_agent_completion_composition.yml"
)
TASK_METADATA = {
    "always",
    "become",
    "become_user",
    "block",
    "changed_when",
    "check_mode",
    "delegate_to",
    "environment",
    "failed_when",
    "ignore_errors",
    "loop",
    "loop_control",
    "name",
    "no_log",
    "register",
    "rescue",
    "run_once",
    "tags",
    "vars",
    "when",
}


def task_actions(tasks):
    actions = []
    for task in tasks:
        nested = False
        for section in ("block", "rescue", "always"):
            if section in task:
                actions.extend(task_actions(task[section]))
                nested = True
        action_keys = [key for key in task if key not in TASK_METADATA]
        if nested:
            if action_keys:
                raise AssertionError(
                    "block task mixes nested sections and an action"
                )
            continue
        if len(action_keys) != 1:
            raise AssertionError(
                "task must contain exactly one action: " + repr(task)
            )
        actions.append(action_keys[0])
    return actions


class DeploymentAgentCompletionRoleTests(unittest.TestCase):
    def test_role_composes_only_the_offline_completion_boundary(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        ignored = {"name", "register", "changed_when"}
        actions = [next(key for key in task if key not in ignored) for task in tasks]
        self.assertEqual(
            actions,
            [
                "ansible.builtin.assert",
                (
                    "sgt_trojan.checkpoint_automation."
                    "cp_automation_deployment_agent_completion"
                ),
                "ansible.builtin.set_fact",
            ],
        )
        content = TASKS.read_text(encoding="utf-8")
        for prohibited in (
            "cp_automation_deployment_agent_acquire",
            "checkpoint_deployment_agent_live_lease",
            "ansible.builtin.command",
            "ansible.builtin.shell",
            "ansible.builtin.raw",
            "ansible.builtin.script",
        ):
            self.assertNotIn(prohibited, content)

    def test_role_requires_genuine_localhost_and_structured_inputs(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        conditions = str(tasks[0]["ansible.builtin.assert"]["that"])
        for expected in (
            'inventory_hostname == "localhost"',
            'ansible_connection | default("local")',
            'ansible_host | default("localhost")',
            "completion_first_update_plan is mapping",
            "completion_first_target_states is sequence",
            "completion_first_target_states is not string",
            "completion_first_target_states | length > 0",
            "completion_final_target_states is sequence",
            "completion_final_target_states is not string",
            "completion_final_target_states | length > 0",
            "completion_final_evidence is mapping",
            "completion_final_evidence | length > 0",
        ):
            self.assertIn(expected, conditions)

    def test_defaults_are_empty_and_publish_is_unchanged(self) -> None:
        defaults = yaml.safe_load(DEFAULTS.read_text(encoding="utf-8"))
        self.assertEqual(
            set(defaults),
            {
                "checkpoint_deployment_agent_completion_first_update_plan",
                (
                    "checkpoint_deployment_agent_completion_"
                    "first_reacquisition_plan"
                ),
                "checkpoint_deployment_agent_completion_first_target_states",
                "checkpoint_deployment_agent_completion_first_evidence",
                (
                    "checkpoint_deployment_agent_completion_"
                    "second_reacquisition_plan"
                ),
                "checkpoint_deployment_agent_completion_final_target_states",
                "checkpoint_deployment_agent_completion_final_evidence",
            },
        )
        self.assertTrue(all(value in ({}, []) for value in defaults.values()))
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        self.assertFalse(tasks[-1]["changed_when"])

    def test_syntax_fixture_resolves_role_only_on_localhost(self) -> None:
        plays = yaml.safe_load(INTEGRATION.read_text(encoding="utf-8"))
        self.assertEqual(len(plays), 1)
        play = plays[0]
        self.assertEqual(play["hosts"], "localhost")
        self.assertEqual(play["connection"], "local")
        self.assertFalse(play["gather_facts"])
        self.assertEqual(len(play["tasks"]), 1)
        self.assertEqual(
            play["tasks"][0]["ansible.builtin.include_role"]["name"],
            (
                "sgt_trojan.checkpoint_automation."
                "checkpoint_deployment_agent_completion"
            ),
        )

    def test_composition_fixture_is_exactly_offline(self) -> None:
        plays = yaml.safe_load(COMPOSITION.read_text(encoding="utf-8"))
        self.assertEqual(len(plays), 1)
        play = plays[0]
        self.assertEqual(play["hosts"], "localhost")
        self.assertEqual(play["connection"], "local")
        self.assertFalse(play["gather_facts"])
        actions = task_actions(play["tasks"])
        self.assertEqual(
            actions,
            [
                (
                    "sgt_trojan.checkpoint_automation."
                    "cp_automation_deployment_agent_package_bind"
                ),
                (
                    "sgt_trojan.checkpoint_automation."
                    "cp_automation_deployment_agent_update_plan"
                ),
                (
                    "sgt_trojan.checkpoint_automation."
                    "cp_automation_deployment_agent_reacquire_plan"
                ),
                (
                    "sgt_trojan.checkpoint_automation."
                    "cp_automation_deployment_agent_evidence"
                ),
                (
                    "sgt_trojan.checkpoint_automation."
                    "cp_automation_deployment_agent_next_plan"
                ),
                (
                    "sgt_trojan.checkpoint_automation."
                    "cp_automation_deployment_agent_reacquire_plan"
                ),
                (
                    "sgt_trojan.checkpoint_automation."
                    "cp_automation_deployment_agent_evidence"
                ),
                "ansible.builtin.include_role",
                "ansible.builtin.assert",
                "ansible.builtin.include_role",
                "ansible.builtin.fail",
                "ansible.builtin.assert",
            ],
        )
        content = COMPOSITION.read_text(encoding="utf-8")
        for prohibited in (
            "cp_automation_deployment_agent_acquire",
            "checkpoint_deployment_agent_live_lease",
            "ansible.builtin.command",
            "ansible.builtin.shell",
            "ansible.builtin.raw",
            "ansible.builtin.script",
        ):
            self.assertNotIn(prohibited, content)


if __name__ == "__main__":
    unittest.main()
