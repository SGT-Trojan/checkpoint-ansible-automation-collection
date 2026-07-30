from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.utils.verify_package_inventory_capability import (
    MODULE_FILENAME,
    MODULE_NAME,
    PINNED_VERSION,
    PackageInventoryCapabilityError,
    verify_package_inventory_capability,
)


class PackageInventoryCapabilityTests(unittest.TestCase):
    def _vendor_root(
        self,
        *,
        options: str = "display: {type: dict}\n  targets: {type: list}",
        returns: str | None = None,
        command: str = "show-software-packages-per-targets",
        command_argument: str = "command",
        sibling: str = "",
        helper: str = "api_command",
        version: str = PINNED_VERSION,
    ):
        temporary = TemporaryDirectory()
        root = Path(temporary.name)
        module_root = root / "plugins" / "modules"
        module_root.mkdir(parents=True)
        (root / "MANIFEST.json").write_text(
            json.dumps({"collection_info": {"version": version}}),
            encoding="utf-8",
        )
        return_yaml = returns or (
            f"{MODULE_NAME}:\n"
            "  description: Generic output.\n"
            "  returned: always\n"
            "  type: dict\n"
        )
        (module_root / MODULE_FILENAME).write_text(
            f'DOCUMENTATION = """\nmodule: {MODULE_NAME}\noptions:\n'
            f"  {options}\n"
            '"""\n'
            f'RETURN = """\n{return_yaml}"""\n'
            "def main():\n"
            f"    command = {command!r}\n"
            f"    result = {helper}(module, {command_argument})\n"
            "    module.exit_json(**result)\n"
            f"{sibling}",
            encoding="utf-8",
        )
        return temporary, root

    def test_exact_pinned_incomplete_contract_is_accepted(self) -> None:
        temporary, root = self._vendor_root()
        self.addCleanup(temporary.cleanup)
        verify_package_inventory_capability(root)

    def test_wrong_version_or_command_is_rejected(self) -> None:
        for arguments in (
            {"version": "different"},
            {"command": "different"},
        ):
            with self.subTest(arguments=arguments):
                temporary, root = self._vendor_root(**arguments)
                self.addCleanup(temporary.cleanup)
                with self.assertRaises(PackageInventoryCapabilityError):
                    verify_package_inventory_capability(root)

    def test_pagination_or_completeness_contract_requires_reassessment(self) -> None:
        for options, returns in (
            (
                "display: {type: dict}\n  targets: {type: list}\n"
                "  limit: {type: int}",
                None,
            ),
            (
                "display: {type: dict}\n  targets: {type: list}",
                f"{MODULE_NAME}:\n"
                "  description: Output.\n"
                "  type: dict\n"
                "  contains:\n"
                "    complete: {type: bool}\n",
            ),
        ):
            with self.subTest(options=options, returns=returns):
                temporary, root = self._vendor_root(
                    options=options,
                    returns=returns,
                )
                self.addCleanup(temporary.cleanup)
                with self.assertRaises(PackageInventoryCapabilityError):
                    verify_package_inventory_capability(root)

    def test_non_generic_helper_requires_reassessment(self) -> None:
        temporary, root = self._vendor_root(helper="api_call_facts")
        self.addCleanup(temporary.cleanup)
        with self.assertRaises(PackageInventoryCapabilityError):
            verify_package_inventory_capability(root)

    def test_call_argument_and_sibling_function_require_reassessment(self) -> None:
        for arguments in (
            {"command_argument": "'different-command'"},
            {
                "sibling": (
                    "\ndef complete_inventory():\n"
                    "    return api_command(module, command)\n"
                )
            },
        ):
            with self.subTest(arguments=arguments):
                temporary, root = self._vendor_root(**arguments)
                self.addCleanup(temporary.cleanup)
                with self.assertRaises(PackageInventoryCapabilityError):
                    verify_package_inventory_capability(root)

    def test_additional_pagination_vocabulary_requires_reassessment(self) -> None:
        for marker in ("count", "next", "page", "page_size", "pages"):
            with self.subTest(marker=marker):
                temporary, root = self._vendor_root(
                    options=(
                        "display:\n"
                        "    type: dict\n"
                        "    suboptions:\n"
                        f"      {marker}: {{type: int}}\n"
                        "  targets: {type: list}"
                    )
                )
                self.addCleanup(temporary.cleanup)
                with self.assertRaises(PackageInventoryCapabilityError):
                    verify_package_inventory_capability(root)


if __name__ == "__main__":
    unittest.main()
