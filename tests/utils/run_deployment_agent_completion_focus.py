from __future__ import annotations

from pathlib import Path
import sys
import unittest


COLLECTION_ROOT = Path(__file__).resolve().parents[2]
if str(COLLECTION_ROOT) not in sys.path:
    sys.path.insert(0, str(COLLECTION_ROOT))

TEST_MODULES = (
    "tests.unit.test_deployment_agent_completion_role",
    "tests.unit.plugins.modules.test_deployment_agent_completion_module",
    "tests.unit.plugins.modules.test_deployment_agent_evidence_module",
    "tests.unit.plugins.modules.test_deployment_agent_next_plan_module",
    "tests.unit.plugins.modules.test_deployment_agent_package_bind_module",
    "tests.unit.plugins.modules.test_deployment_agent_reacquire_plan_module",
    "tests.unit.plugins.modules.test_deployment_agent_update_plan_module",
    "tests.unit.plugins.module_utils.test_deployment_agent_completion",
    "tests.unit.plugins.module_utils.test_deployment_agent_evidence",
    "tests.unit.plugins.module_utils.test_deployment_agent_next",
    "tests.unit.plugins.module_utils.test_deployment_agent_package",
    "tests.unit.plugins.module_utils.test_deployment_agent_reacquire",
    "tests.unit.plugins.module_utils.test_deployment_agent_update",
)
LAYOUT_TEST = (
    "tests.unit.test_collection_layout.CollectionLayoutTests."
    "test_required_public_documents_exist"
)


def build_suite() -> unittest.TestSuite:
    loader = unittest.defaultTestLoader
    suite = loader.loadTestsFromNames(TEST_MODULES)
    suite.addTests(loader.loadTestsFromName(LAYOUT_TEST))
    return suite


def main() -> int:
    result = unittest.TextTestRunner(verbosity=2).run(build_suite())
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
