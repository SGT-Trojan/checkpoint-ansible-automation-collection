# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Race-resistant localhost package artifact observation."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import errno
import hashlib
import os
from pathlib import PurePosixPath
import stat
from typing import Any


CHUNK_SIZE = 1024 * 1024
READ_CALL_FACTOR = 4
READ_CALL_SLACK = 8
REQUIRED_OPEN_FLAGS = (
    "O_DIRECTORY",
    "O_NOFOLLOW",
    "O_CLOEXEC",
    "O_NONBLOCK",
    "O_PATH",
)
PLATFORM_SUPPORTED = all(hasattr(os, name) for name in REQUIRED_OPEN_FLAGS) and (
    os.open in getattr(os, "supports_dir_fd", set())
)
DIRECTORY_FLAGS = (
    getattr(os, "O_PATH", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
FILE_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


class ArtifactObservationError(ValueError):
    """The expected artifact path or observed file is unsafe."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def _fail(category: str, message: str) -> None:
    raise ArtifactObservationError(category, message)


def _require_platform() -> None:
    if not PLATFORM_SUPPORTED:
        _fail(
            "PLATFORM_UNSUPPORTED",
            "controller lacks required no-follow openat capabilities",
        )


def _canonical_path(value: object) -> tuple[str, tuple[str, ...]]:
    if not isinstance(value, str) or not value.strip():
        _fail("PATH_INVALID", "expected_path must be a non-empty string")
    if value != value.strip() or "\x00" in value or "\n" in value or "\r" in value:
        _fail("PATH_INVALID", "expected_path contains prohibited text")
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or value.startswith("//")
        or value == "/"
        or value.endswith("/")
        or ".." in path.parts
        or str(path) != value
    ):
        _fail("PATH_INVALID", "expected_path must be one canonical absolute file path")
    components = tuple(part for part in path.parts if part != "/")
    if not components or any(part in {"", ".", ".."} for part in components):
        _fail("PATH_INVALID", "expected_path must identify one canonical file")
    return value, components


def _open_expected(components: tuple[str, ...]) -> int:
    directory_fd = -1
    try:
        directory_fd = os.open("/", DIRECTORY_FLAGS)
        for component in components[:-1]:
            try:
                next_fd = os.open(component, DIRECTORY_FLAGS, dir_fd=directory_fd)
            except OSError as error:
                raise ArtifactObservationError(
                    "PARENT_COMPONENT_INVALID",
                    "expected artifact parent component is unavailable or unsafe",
                ) from error
            previous_fd = directory_fd
            directory_fd = -1
            try:
                os.close(previous_fd)
            except OSError as error:
                try:
                    os.close(next_fd)
                except OSError:
                    pass
                raise ArtifactObservationError(
                    "PARENT_COMPONENT_INVALID",
                    "expected artifact parent transition could not be secured",
                ) from error
            directory_fd = next_fd
        try:
            file_fd = os.open(components[-1], FILE_FLAGS, dir_fd=directory_fd)
        except OSError as error:
            category = (
                "SYMLINK_REJECTED"
                if error.errno == errno.ELOOP
                else "ARTIFACT_UNAVAILABLE"
            )
            raise ArtifactObservationError(
                category,
                (
                    "expected artifact is a prohibited symbolic link"
                    if category == "SYMLINK_REJECTED"
                    else "expected artifact is unavailable"
                ),
            ) from error
        previous_fd = directory_fd
        directory_fd = -1
        try:
            os.close(previous_fd)
        except OSError as error:
            try:
                os.close(file_fd)
            except OSError:
                pass
            raise ArtifactObservationError(
                "PARENT_COMPONENT_INVALID",
                "expected artifact parent cleanup could not be secured",
            ) from error
    except ArtifactObservationError:
        if directory_fd >= 0:
            try:
                os.close(directory_fd)
            except OSError:
                pass
        raise
    except OSError as error:
        if directory_fd >= 0:
            try:
                os.close(directory_fd)
            except OSError:
                pass
        raise ArtifactObservationError(
            "PARENT_COMPONENT_INVALID",
            "expected artifact parent component is unavailable or unsafe",
        ) from error
    return file_fd


def _metadata(file_fd: int) -> tuple[int, int, int, int, int, int]:
    value = os.fstat(file_fd)
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _stable_identity(
    before: tuple[int, int, int, int, int, int],
    after: tuple[int, int, int, int, int, int],
) -> bool:
    return before == after


def _hash_exact(file_fd: int, expected_size: int) -> str:
    os.lseek(file_fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = expected_size
    minimum_calls = (expected_size + CHUNK_SIZE - 1) // CHUNK_SIZE
    read_call_budget = (minimum_calls * READ_CALL_FACTOR) + READ_CALL_SLACK
    read_calls = 0
    while remaining:
        if read_calls >= read_call_budget:
            _fail(
                "READ_BUDGET_EXHAUSTED",
                "artifact read-call budget exhausted before observed size",
            )
        requested = min(CHUNK_SIZE, remaining)
        chunk = os.read(file_fd, requested)
        read_calls += 1
        if not chunk:
            _fail("ARTIFACT_CHANGED", "artifact ended before its observed size")
        if len(chunk) > requested:
            _fail("ARTIFACT_CHANGED", "artifact read exceeded its observed size")
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(file_fd, 1):
        _fail("ARTIFACT_CHANGED", "artifact grew beyond its observed size")
    return digest.hexdigest()


def observe_artifact(expected_path: object) -> dict[str, Any]:
    """Hash one exact local regular file while rejecting links and races."""

    _require_platform()
    path, components = _canonical_path(expected_path)
    file_fd = _open_expected(components)
    try:
        before = _metadata(file_fd)
        if not stat.S_ISREG(before[2]):
            _fail("NOT_REGULAR_FILE", "expected artifact is not a regular file")
        if before[3] <= 0:
            _fail("SIZE_INVALID", "expected artifact size must be positive")
        first_digest = _hash_exact(file_fd, before[3])
        between = _metadata(file_fd)
        if not _stable_identity(before, between):
            _fail(
                "ARTIFACT_CHANGED",
                "artifact metadata changed after the first hash pass",
            )
        second_digest = _hash_exact(file_fd, before[3])
        after = _metadata(file_fd)
    except OSError as error:
        raise ArtifactObservationError(
            "ARTIFACT_UNAVAILABLE",
            "expected artifact could not be read completely",
        ) from error
    finally:
        os.close(file_fd)

    if not _stable_identity(before, after):
        _fail(
            "ARTIFACT_CHANGED",
            "artifact identity, mode, size, mtime, or ctime changed while hashing",
        )
    if first_digest != second_digest:
        _fail("ARTIFACT_CHANGED", "artifact content changed between hash passes")

    reopened_fd = _open_expected(components)
    try:
        reopened = _metadata(reopened_fd)
    except OSError as error:
        raise ArtifactObservationError(
            "ARTIFACT_UNAVAILABLE",
            "expected artifact could not be revalidated",
        ) from error
    finally:
        os.close(reopened_fd)
    if not stat.S_ISREG(reopened[2]) or not _stable_identity(before, reopened):
        _fail("ARTIFACT_CHANGED", "artifact path changed while hashing")

    return {
        "path": path,
        "size": before[3],
        "sha256": second_digest,
    }
