from __future__ import annotations

from pathlib import Path
import unittest

from tests.utils.verify_live_readonly_graph import (
    DEPLOYMENT_AGENT_APPROVED_ACTIONS,
    verify_deployment_agent_live_graph,
)


ROOT = Path(__file__).resolve().parents[2]


class DeploymentAgentLiveGraphTests(unittest.TestCase):
    def test_shipped_deployment_agent_graph_is_complete_and_exact(self) -> None:
        report = verify_deployment_agent_live_graph(ROOT)
        self.assertEqual(
            set(report.actions),
            set(DEPLOYMENT_AGENT_APPROVED_ACTIONS),
        )
        self.assertIn(
            "playbooks/live_readonly_deployment_agent.yml",
            report.files,
        )
        self.assertIn(
            (
                "roles/checkpoint_deployment_agent_observation/"
                "tasks/main.yml"
            ),
            report.files,
        )
        for forbidden in (
            "ansible.builtin.command",
            "ansible.builtin.shell",
            "ansible.builtin.raw",
            "check_point.gaia.cp_gaia_run_script",
        ):
            self.assertNotIn(forbidden, report.actions)


if __name__ == "__main__":
    unittest.main()
