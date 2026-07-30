from __future__ import annotations

from pathlib import Path
import unittest

from tests.utils.verify_live_readonly_graph import (
    PACKAGE_STATE_APPROVED_ACTIONS,
    verify_package_state_live_graph,
)


ROOT = Path(__file__).resolve().parents[2]


class PackageStateLiveGraphTests(unittest.TestCase):
    def test_shipped_package_state_graph_is_complete_and_exact(self) -> None:
        report = verify_package_state_live_graph(ROOT)
        self.assertEqual(
            set(report.actions),
            set(PACKAGE_STATE_APPROVED_ACTIONS),
        )
        self.assertIn(
            "playbooks/live_readonly_package_state.yml",
            report.files,
        )
        self.assertIn(
            (
                "roles/checkpoint_package_state_acquisition/"
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
