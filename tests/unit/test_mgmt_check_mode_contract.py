from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import json
from pathlib import Path
import tempfile
import unittest

from tests.utils.verify_mgmt_check_mode import (
    MODULE_CONTRACT,
    PINNED_VERSION,
    VendorContractError,
    verify_task_policy,
    verify_vendor_sources,
)


ROOT = Path(__file__).resolve().parents[2]


class MgmtCheckModeContractTests(unittest.TestCase):
    def test_all_local_vendor_calls_have_explicit_check_mode(self) -> None:
        verify_task_policy(ROOT)

    def test_synthetic_vendor_sources_match_ast_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module_root = root / "plugins" / "modules"
            module_root.mkdir(parents=True)
            (root / "MANIFEST.json").write_text(
                json.dumps(
                    {"collection_info": {"version": PINNED_VERSION}}
                ),
                encoding="utf-8",
            )
            for filename, contract in MODULE_CONTRACT.items():
                support = repr(contract["supports_check_mode"])
                helper = contract["direct_helper"]
                (module_root / filename).write_text(
                    "def main():\n"
                    "    module = AnsibleModule("
                    f"supports_check_mode={support})\n"
                    f"    {helper}(module)\n",
                    encoding="utf-8",
                )
            verify_vendor_sources(root)

    def test_wrong_vendor_version_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "MANIFEST.json").write_text(
                '{"collection_info": {"version": "different"}}',
                encoding="utf-8",
            )
            with self.assertRaises(VendorContractError):
                verify_vendor_sources(root)


if __name__ == "__main__":
    unittest.main()
