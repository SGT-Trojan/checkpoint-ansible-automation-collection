# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Stage one exact Deployment Agent artifact without executing an update."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

from datetime import datetime, timezone
import errno
import hashlib
import os
from pathlib import PurePosixPath
import secrets
import stat
from typing import Any, Callable

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_execution_preflight import (
    DeploymentAgentExecutionPreflightError,
    authorize_deployment_agent_execution,
)
from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_reconcile import (
    DeploymentAgentReconcileError,
    validate_deployment_agent_update_plan,
)


CHUNK_SIZE = 1024 * 1024
MAX_ARTIFACT_SIZE = 4 * 1024 * 1024 * 1024
MAX_PACKAGE_NAME_BYTES = 180
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
SYNC_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
SOURCE_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
DESTINATION_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


class DeploymentAgentArtifactStagingError(ValueError):
    """The requested artifact staging operation is unsafe."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def _fail(category: str, message: str) -> None:
    raise DeploymentAgentArtifactStagingError(category, message)


def _require_platform() -> None:
    if not PLATFORM_SUPPORTED:
        _fail(
            "PLATFORM_UNSUPPORTED",
            "controller lacks required no-follow openat capabilities",
        )


def _canonical_components(value: object, label: str) -> tuple[str, tuple[str, ...]]:
    if not isinstance(value, str) or not value or value != value.strip():
        _fail("PATH_INVALID", f"{label} must be one canonical absolute path")
    if "\x00" in value or "\n" in value or "\r" in value:
        _fail("PATH_INVALID", f"{label} contains prohibited text")
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or value.startswith("//")
        or value == "/"
        or value.endswith("/")
        or ".." in path.parts
        or str(path) != value
    ):
        _fail("PATH_INVALID", f"{label} must be one canonical absolute path")
    components = tuple(part for part in path.parts if part != "/")
    if not components or any(part in {"", ".", ".."} for part in components):
        _fail("PATH_INVALID", f"{label} must identify one canonical path")
    return value, components


def _open_directory(components: tuple[str, ...], label: str) -> int:
    directory_fd = -1
    try:
        directory_fd = os.open("/", DIRECTORY_FLAGS)
        for component in components:
            next_fd = os.open(component, DIRECTORY_FLAGS, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
    except OSError as error:
        if directory_fd >= 0:
            try:
                os.close(directory_fd)
            except OSError:
                pass
        raise DeploymentAgentArtifactStagingError(
            "PATH_UNSAFE", f"{label} is unavailable or contains an unsafe component"
        ) from error
    return directory_fd


def _open_source(components: tuple[str, ...]) -> int:
    parent_fd = _open_directory(components[:-1], "source parent")
    try:
        return os.open(components[-1], SOURCE_FLAGS, dir_fd=parent_fd)
    except OSError as error:
        category = "SYMLINK_REJECTED" if error.errno == errno.ELOOP else "SOURCE_UNAVAILABLE"
        raise DeploymentAgentArtifactStagingError(
            category, "source artifact is unavailable or unsafe"
        ) from error
    finally:
        os.close(parent_fd)


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


def _hash_source(file_fd: int, expected_size: int) -> str:
    os.lseek(file_fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = expected_size
    calls = 0
    call_budget = ((expected_size + CHUNK_SIZE - 1) // CHUNK_SIZE) * 4 + 8
    while remaining:
        if calls >= call_budget:
            _fail("READ_BUDGET_EXHAUSTED", "source read-call budget was exhausted")
        chunk = os.read(file_fd, min(CHUNK_SIZE, remaining))
        calls += 1
        if not chunk:
            _fail("SOURCE_CHANGED", "source ended before its bound size")
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(file_fd, 1):
        _fail("SOURCE_CHANGED", "source grew beyond its bound size")
    return digest.hexdigest()


def _copy_source(file_fd: int, destination_fd: int, expected_size: int) -> str:
    os.lseek(file_fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = expected_size
    calls = 0
    call_budget = ((expected_size + CHUNK_SIZE - 1) // CHUNK_SIZE) * 4 + 8
    while remaining:
        if calls >= call_budget:
            _fail("READ_BUDGET_EXHAUSTED", "staging read-call budget was exhausted")
        chunk = os.read(file_fd, min(CHUNK_SIZE, remaining))
        calls += 1
        if not chunk:
            _fail("SOURCE_CHANGED", "source ended during staging")
        digest.update(chunk)
        view = memoryview(chunk)
        while view:
            written = os.write(destination_fd, view)
            if written <= 0:
                _fail("STAGING_FAILED", "staged artifact write did not progress")
            view = view[written:]
        remaining -= len(chunk)
    if os.read(file_fd, 1):
        _fail("SOURCE_CHANGED", "source grew during staging")
    return digest.hexdigest()


def _current_time(clock: Callable[[], datetime]) -> datetime:
    current = clock()
    if current.tzinfo is None or current.utcoffset() is None:
        _fail("AUTHORIZATION_INVALID", "staging clock must be timezone-aware")
    return current.astimezone(timezone.utc)


def _require_unexpired(authorization: dict[str, Any], clock: Callable[[], datetime]) -> None:
    try:
        expires_at = datetime.strptime(
            authorization["expires_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except (KeyError, TypeError, ValueError) as error:
        raise DeploymentAgentArtifactStagingError(
            "AUTHORIZATION_INVALID", "preflight expiry is malformed"
        ) from error
    if expires_at <= _current_time(clock):
        _fail("LEASE_EXPIRED", "lease expired before artifact staging mutation")


def _validate_existing(
    directory_fd: int, name: str, expected_size: int, expected_sha256: str
) -> None:
    try:
        file_fd = os.open(name, SOURCE_FLAGS, dir_fd=directory_fd)
    except OSError as error:
        category = "DESTINATION_COLLISION"
        raise DeploymentAgentArtifactStagingError(
            category, "staged destination exists but is unavailable or unsafe"
        ) from error
    try:
        value = os.fstat(file_fd)
        metadata = _metadata(file_fd)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_size != expected_size
            or stat.S_IMODE(value.st_mode) != 0o400
            or value.st_uid != os.geteuid()
            or value.st_nlink != 1
        ):
            _fail("DESTINATION_COLLISION", "staged destination identity does not match")
        if _hash_source(file_fd, expected_size) != expected_sha256:
            _fail("DESTINATION_COLLISION", "staged destination content does not match")
        if _metadata(file_fd) != metadata:
            _fail("DESTINATION_COLLISION", "staged destination changed during validation")
    finally:
        os.close(file_fd)


def stage_deployment_agent_artifact(
    lease: object,
    update_plan: object,
    member_target_id: object,
    member_address: object,
    member_targets: object,
    runtime_commit: object,
    tls_validation_enabled: object,
    lab_tls_exception_acknowledged: object,
    staging_root: object,
    check_mode: object,
    now: datetime | None = None,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Preflight, revalidate, and atomically stage one content-addressed artifact."""

    _require_platform()
    try:
        plan = validate_deployment_agent_update_plan(update_plan)
    except DeploymentAgentReconcileError as error:
        raise DeploymentAgentArtifactStagingError(error.category, str(error)) from error
    source_path, source_components = _canonical_components(
        plan["source_path"], "source_path"
    )
    root_path, root_components = _canonical_components(staging_root, "staging_root")
    package_name = plan["package_name"]
    if (
        not isinstance(package_name, str)
        or PurePosixPath(package_name).name != package_name
        or package_name in {".", ".."}
        or len(package_name.encode("utf-8")) > MAX_PACKAGE_NAME_BYTES
        or PurePosixPath(source_path).name != package_name
    ):
        _fail("PACKAGE_IDENTITY_INVALID", "package name does not match source path")
    expected_size = plan["artifact_size"]
    if expected_size > MAX_ARTIFACT_SIZE:
        _fail("ARTIFACT_TOO_LARGE", "artifact exceeds the staging byte limit")

    source_fd = _open_source(source_components)
    temporary_name = ""
    destination_fd = -1
    root_fd = -1
    selected_clock = clock or (lambda: datetime.now(timezone.utc))
    try:
        before = _metadata(source_fd)
        if not stat.S_ISREG(before[2]) or before[3] != expected_size:
            _fail("ARTIFACT_MISMATCH", "source type or size does not match the plan")
        first_digest = _hash_source(source_fd, expected_size)
        if first_digest != plan["checksum_sha256"] or _metadata(source_fd) != before:
            _fail("ARTIFACT_MISMATCH", "source content does not match the plan")
        observation = {
            "path": source_path,
            "size": expected_size,
            "sha256": first_digest,
        }
        try:
            authorization = authorize_deployment_agent_execution(
                lease=lease,
                update_plan=plan,
                artifact_observation=observation,
                member_target_id=member_target_id,
                member_address=member_address,
                member_targets=member_targets,
                runtime_commit=runtime_commit,
                tls_validation_enabled=tls_validation_enabled,
                lab_tls_exception_acknowledged=lab_tls_exception_acknowledged,
                check_mode=check_mode,
                now=now,
            )
        except DeploymentAgentExecutionPreflightError as error:
            raise DeploymentAgentArtifactStagingError(
                error.category, str(error)
            ) from error

        root_fd = _open_directory(root_components, "staging_root")
        root_stat = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(root_stat.st_mode)
            or root_stat.st_uid != os.geteuid()
            or stat.S_IMODE(root_stat.st_mode) & 0o022
        ):
            _fail(
                "PATH_UNSAFE",
                "staging_root must be owner-controlled and not group/other writable",
            )
        destination_name = f"{plan['checksum_sha256']}-{package_name}"
        try:
            _validate_existing(
                root_fd, destination_name, expected_size, plan["checksum_sha256"]
            )
        except DeploymentAgentArtifactStagingError as error:
            if error.category != "DESTINATION_COLLISION" or not isinstance(
                error.__cause__, FileNotFoundError
            ):
                raise
        else:
            return {
                "changed": False,
                "staging": {
                    "path": f"{root_path}/{destination_name}",
                    "size": expected_size,
                    "sha256": plan["checksum_sha256"],
                    "plan_sha256": plan["plan_sha256"],
                },
                "authorization": authorization,
            }

        _require_unexpired(authorization, selected_clock)
        temporary_name = f".deployment-agent-stage-{secrets.token_hex(16)}"
        destination_fd = os.open(
            temporary_name, DESTINATION_FLAGS, 0o600, dir_fd=root_fd
        )
        second_digest = _copy_source(source_fd, destination_fd, expected_size)
        after = _metadata(source_fd)
        if second_digest != plan["checksum_sha256"] or after != before:
            _fail("SOURCE_CHANGED", "source changed while staging")
        os.fchmod(destination_fd, 0o400)
        os.fsync(destination_fd)
        os.close(destination_fd)
        destination_fd = -1
        _require_unexpired(authorization, selected_clock)
        try:
            os.link(
                temporary_name,
                destination_name,
                src_dir_fd=root_fd,
                dst_dir_fd=root_fd,
                follow_symlinks=False,
            )
            changed = True
        except FileExistsError:
            _validate_existing(
                root_fd, destination_name, expected_size, plan["checksum_sha256"]
            )
            changed = False
        os.unlink(temporary_name, dir_fd=root_fd)
        temporary_name = ""
        sync_fd = os.open(".", SYNC_DIRECTORY_FLAGS, dir_fd=root_fd)
        try:
            os.fsync(sync_fd)
        finally:
            os.close(sync_fd)
        return {
            "changed": changed,
            "staging": {
                "path": f"{root_path}/{destination_name}",
                "size": expected_size,
                "sha256": plan["checksum_sha256"],
                "plan_sha256": plan["plan_sha256"],
            },
            "authorization": authorization,
        }
    except OSError as error:
        raise DeploymentAgentArtifactStagingError(
            "STAGING_FAILED", "artifact staging filesystem operation failed"
        ) from error
    finally:
        if destination_fd >= 0:
            try:
                os.close(destination_fd)
            except OSError:
                pass
        if temporary_name and root_fd >= 0:
            try:
                os.unlink(temporary_name, dir_fd=root_fd)
            except OSError:
                pass
        if root_fd >= 0:
            try:
                os.close(root_fd)
            except OSError:
                pass
        os.close(source_fd)
