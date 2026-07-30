from __future__ import annotations

import unittest

from tests.utils.run_deployment_agent_completion_focus import (
    LAYOUT_TEST,
    TEST_MODULES,
    build_suite,
)


class DeploymentAgentCompletionFocusTests(unittest.TestCase):
    def test_focus_suite_is_exact_and_unique(self) -> None:
        suite = build_suite()
        self.assertEqual(suite.countTestCases(), 68)
        self.assertEqual(len(TEST_MODULES), len(set(TEST_MODULES)))
        self.assertNotIn(LAYOUT_TEST.rsplit(".", 1)[0], TEST_MODULES)


if __name__ == "__main__":
    unittest.main()
