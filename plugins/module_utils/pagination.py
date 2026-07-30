# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Validation and merging for explicitly paged Management API results."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import json
from typing import Any, Iterable


class PaginationError(ValueError):
    """A paged response is incomplete or internally inconsistent."""


def _total(response: dict[str, Any]) -> int:
    raw = response.get("total")
    if isinstance(raw, bool):
        raise PaginationError("pagination total must be a non-negative integer")
    try:
        value = int(raw)
    except (TypeError, ValueError) as error:
        raise PaginationError("pagination total must be a non-negative integer") from error
    if value < 0 or str(raw).strip() != str(value):
        raise PaginationError("pagination total must be a non-negative integer")
    return value


def _rows(
    response: dict[str, Any],
    result_keys: tuple[str, ...],
) -> tuple[str, list[dict[str, Any]]]:
    matches = [key for key in result_keys if isinstance(response.get(key), list)]
    if len(matches) != 1:
        raise PaginationError(
            f"response must contain exactly one result list from {result_keys}"
        )
    key = matches[0]
    raw_rows = response[key]
    if not all(isinstance(row, dict) for row in raw_rows):
        raise PaginationError(f"result list {key!r} contains a non-object row")
    return key, raw_rows


def _identity(row: dict[str, Any]) -> tuple[str, str, str]:
    uid = str(row.get("uid") or "").strip()
    name = str(row.get("name") or row.get("domain-name") or "").strip()
    if uid:
        return "uid", uid, ""
    if name:
        object_type = str(
            row.get("type") or row.get("domain-type") or ""
        ).strip()
        return "name", name.casefold(), object_type.casefold()
    raise PaginationError("paged object has neither UID nor name")


def merge_pages(
    pages: Iterable[dict[str, Any]],
    result_keys: Iterable[str],
) -> dict[str, Any]:
    """Validate ordered page envelopes and return their complete object list."""

    keys = tuple(str(key).strip() for key in result_keys if str(key).strip())
    if not keys or len(set(keys)) != len(keys):
        raise PaginationError("result_keys must contain distinct non-empty values")

    page_list = list(pages)
    if not page_list:
        raise PaginationError("at least one page is required")

    expected_offset = 0
    expected_total: int | None = None
    selected_key = ""
    merged: list[dict[str, Any]] = []
    seen_objects: set[tuple[str, str, str]] = set()
    seen_pages: set[str] = set()

    for index, envelope in enumerate(page_list):
        if not isinstance(envelope, dict):
            raise PaginationError(f"page {index} is not an object")
        offset = envelope.get("offset")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise PaginationError(f"page {index} has an invalid offset")
        if offset != expected_offset:
            raise PaginationError(
                f"page {index} starts at offset {offset}, expected {expected_offset}"
            )
        response = envelope.get("response")
        if not isinstance(response, dict):
            raise PaginationError(f"page {index} has no response object")

        if "offset" in response:
            response_offset = response["offset"]
            if (
                isinstance(response_offset, bool)
                or not isinstance(response_offset, int)
                or response_offset < 0
            ):
                raise PaginationError(
                    f"page {index} response has an invalid offset"
                )
            if response_offset != offset:
                raise PaginationError(
                    f"page {index} response offset {response_offset} "
                    f"does not match requested offset {offset}"
                )

        total = _total(response)
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            raise PaginationError("pagination total changed between pages")

        key, rows = _rows(response, keys)
        position_fields = {"from", "to"} & response.keys()
        if position_fields:
            if position_fields != {"from", "to"}:
                raise PaginationError(
                    f"page {index} response must provide both from and to"
                )
            response_from = response["from"]
            response_to = response["to"]
            if any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                for value in (response_from, response_to)
            ):
                raise PaginationError(
                    f"page {index} response has invalid from/to values"
                )
            if rows:
                expected_from = offset + 1
                expected_to = offset + len(rows)
                if (response_from, response_to) != (
                    expected_from,
                    expected_to,
                ):
                    raise PaginationError(
                        f"page {index} response range "
                        f"{response_from}-{response_to} does not match "
                        f"requested rows {expected_from}-{expected_to}"
                    )
        if selected_key and key != selected_key:
            raise PaginationError("pagination result key changed between pages")
        selected_key = key

        signature = json.dumps(rows, sort_keys=True, separators=(",", ":"))
        if signature in seen_pages:
            raise PaginationError("pagination repeated a page")
        seen_pages.add(signature)

        if not rows and len(merged) < total:
            raise PaginationError(
                f"pagination stopped at {len(merged)} of {total} objects"
            )
        for row in rows:
            identity = _identity(row)
            if identity in seen_objects:
                raise PaginationError(
                    f"pagination repeated object {identity[1]!r}"
                )
            seen_objects.add(identity)
            merged.append(row)
        if len(merged) > total:
            raise PaginationError(
                f"pagination returned {len(merged)} objects for total {total}"
            )
        expected_offset = len(merged)

    if expected_total is None:
        raise PaginationError("pagination did not provide a total")
    if len(merged) != expected_total:
        raise PaginationError(
            f"pagination returned {len(merged)} of {expected_total} objects"
        )
    return {
        "result_key": selected_key,
        "total": expected_total,
        "objects": merged,
    }
