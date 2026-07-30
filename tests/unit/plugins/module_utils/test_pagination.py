from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import importlib.util
from pathlib import Path
import sys
import unittest


MODULE = (
    Path(__file__).resolve().parents[4]
    / "plugins"
    / "module_utils"
    / "pagination.py"
)
SPEC = importlib.util.spec_from_file_location("checkpoint_pagination", MODULE)
assert SPEC and SPEC.loader
pagination = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pagination
SPEC.loader.exec_module(pagination)


def page(offset: int, rows: list[dict], total: object = 3, key: str = "objects") -> dict:
    return {"offset": offset, "response": {key: rows, "total": total}}


class PaginationTests(unittest.TestCase):
    def test_merges_complete_ordered_pages(self) -> None:
        result = pagination.merge_pages(
            [
                page(0, [{"uid": "1"}, {"uid": "2"}]),
                page(2, [{"uid": "3"}]),
            ],
            ["objects", "domains"],
        )
        self.assertEqual(result["total"], 3)
        self.assertEqual([row["uid"] for row in result["objects"]], ["1", "2", "3"])
        self.assertEqual(result["result_key"], "objects")

    def test_accepts_zero_object_result(self) -> None:
        result = pagination.merge_pages(
            [page(0, [], total=0, key="domains")],
            ["objects", "domains"],
        )
        self.assertEqual(result["objects"], [])
        self.assertEqual(result["total"], 0)

    def test_changed_total_fails(self) -> None:
        with self.assertRaises(pagination.PaginationError):
            pagination.merge_pages(
                [
                    page(0, [{"uid": "1"}], total=2),
                    page(1, [{"uid": "2"}], total=3),
                ],
                ["objects"],
            )

    def test_offset_gap_fails(self) -> None:
        with self.assertRaises(pagination.PaginationError):
            pagination.merge_pages(
                [
                    page(0, [{"uid": "1"}], total=2),
                    page(2, [{"uid": "2"}], total=2),
                ],
                ["objects"],
            )

    def test_early_empty_page_fails(self) -> None:
        with self.assertRaises(pagination.PaginationError):
            pagination.merge_pages(
                [page(0, [], total=2)],
                ["objects"],
            )

    def test_incomplete_final_count_fails(self) -> None:
        with self.assertRaises(pagination.PaginationError):
            pagination.merge_pages(
                [page(0, [{"uid": "1"}], total=2)],
                ["objects"],
            )

    def test_duplicate_object_across_pages_fails(self) -> None:
        with self.assertRaises(pagination.PaginationError):
            pagination.merge_pages(
                [
                    page(0, [{"uid": "1"}], total=2),
                    page(1, [{"uid": "1"}], total=2),
                ],
                ["objects"],
            )

    def test_duplicate_uid_cannot_hide_behind_type(self) -> None:
        with self.assertRaises(pagination.PaginationError):
            pagination.merge_pages(
                [
                    page(
                        0,
                        [
                            {"uid": "1", "type": "host"},
                            {"uid": "1", "type": "gateway"},
                        ],
                        total=2,
                    )
                ],
                ["objects"],
            )

    def test_name_identity_preserves_object_type(self) -> None:
        result = pagination.merge_pages(
            [
                page(
                    0,
                    [
                        {"name": "Object-A", "type": "host"},
                        {"name": "object-a", "type": "gateway"},
                    ],
                    total=2,
                )
            ],
            ["objects"],
        )
        self.assertEqual(result["total"], 2)

    def test_response_from_to_must_match_returned_rows(self) -> None:
        first = page(0, [{"uid": "1"}], total=2)
        first["response"].update({"from": 1, "to": 1})
        second = page(1, [{"uid": "2"}], total=2)
        second["response"].update({"from": 2, "to": 2})
        result = pagination.merge_pages([first, second], ["objects"])
        self.assertEqual(result["total"], 2)

        for response_from, response_to in (
            (-1, 1),
            (0, 1),
            (1, 2),
            (True, 1),
            ("1", 1),
            (None, None),
        ):
            with self.subTest(
                response_from=response_from,
                response_to=response_to,
            ):
                candidate = page(0, [{"uid": "1"}], total=1)
                candidate["response"].update(
                    {"from": response_from, "to": response_to}
                )
                with self.assertRaises(pagination.PaginationError):
                    pagination.merge_pages([candidate], ["objects"])

        incomplete = page(0, [{"uid": "1"}], total=1)
        incomplete["response"]["from"] = 1
        with self.assertRaises(pagination.PaginationError):
            pagination.merge_pages([incomplete], ["objects"])

    def test_response_offset_must_match_requested_offset(self) -> None:
        for response_offset in (1, -1, True, "0"):
            with self.subTest(response_offset=response_offset):
                candidate = page(0, [{"uid": "1"}], total=1)
                candidate["response"]["offset"] = response_offset
                with self.assertRaises(pagination.PaginationError):
                    pagination.merge_pages([candidate], ["objects"])

    def test_integer_string_total_is_normalized(self) -> None:
        result = pagination.merge_pages(
            [page(0, [{"name": "Object-A"}], total="1")],
            ["objects"],
        )
        self.assertEqual(result["total"], 1)

    def test_result_key_change_fails(self) -> None:
        with self.assertRaises(pagination.PaginationError):
            pagination.merge_pages(
                [
                    page(0, [{"uid": "1"}], total=2, key="objects"),
                    page(1, [{"uid": "2"}], total=2, key="domains"),
                ],
                ["objects", "domains"],
            )

    def test_multiple_result_lists_fail(self) -> None:
        response = {"objects": [], "domains": [], "total": 0}
        with self.assertRaises(pagination.PaginationError):
            pagination.merge_pages(
                [{"offset": 0, "response": response}],
                ["objects", "domains"],
            )

    def test_non_object_row_fails(self) -> None:
        with self.assertRaises(pagination.PaginationError):
            pagination.merge_pages(
                [page(0, ["not-an-object"], total=1)],
                ["objects"],
            )

    def test_object_without_identity_fails(self) -> None:
        with self.assertRaises(pagination.PaginationError):
            pagination.merge_pages(
                [page(0, [{"type": "simple-cluster"}], total=1)],
                ["objects"],
            )

    def test_boolean_and_fractional_totals_fail(self) -> None:
        for total in (True, 1.5, "1.0", -1):
            with self.subTest(total=total):
                with self.assertRaises(pagination.PaginationError):
                    pagination.merge_pages(
                        [page(0, [{"uid": "1"}], total=total)],
                        ["objects"],
                    )

    def test_duplicate_or_empty_result_keys_fail(self) -> None:
        for keys in ([], ["objects", "objects"], [""]):
            with self.subTest(keys=keys):
                with self.assertRaises(pagination.PaginationError):
                    pagination.merge_pages(
                        [page(0, [], total=0)],
                        keys,
                    )


if __name__ == "__main__":
    unittest.main()
