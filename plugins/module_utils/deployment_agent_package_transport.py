# Copyright (c) 2026 SGT-Trojan contributors
# GNU General Public License v3.0 or later
# SPDX-License-Identifier: GPL-3.0-or-later

"""Lease-bound Deployment Agent package transport without update execution."""

from __future__ import (absolute_import, division, print_function)
from __future__ import annotations

__metaclass__ = type

import base64
import binascii
from datetime import datetime, timezone
import errno
import os
from pathlib import PurePosixPath
import pwd
import stat
from typing import Any, Callable

from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_artifact_staging import (
    DeploymentAgentArtifactStagingError,
    MAX_ARTIFACT_SIZE,
    SOURCE_FLAGS,
    SYNC_DIRECTORY_FLAGS,
    _canonical_components,
    _hash_source,
    _metadata,
    _open_directory,
    _open_source,
    _validate_existing,
)
from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_execution_preflight import (
    DeploymentAgentExecutionPreflightError,
    authorize_deployment_agent_execution,
)
from ansible_collections.sgt_trojan.checkpoint_automation.plugins.module_utils.deployment_agent_reconcile import (
    DeploymentAgentReconcileError,
    validate_deployment_agent_update_plan,
)


CHUNK_SIZE = 256 * 1024
MAX_TRANSPORT_SIZE = 128 * 1024 * 1024
TRANSFER_DIRECTORY = ".checkpoint-automation"
PACKAGE_DIRECTORY = "deployment-agent"
STAGING_KEYS = frozenset({"path", "size", "sha256", "plan_sha256"})
TEMPORARY_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
APPEND_FLAGS = (
    os.O_WRONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


class DeploymentAgentPackageTransportError(ValueError):
    """The requested package transport operation is unsafe."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def _fail(category: str, message: str) -> None:
    raise DeploymentAgentPackageTransportError(category, message)


def _clock_time(clock: Callable[[], datetime]) -> datetime:
    current = clock()
    if current.tzinfo is None or current.utcoffset() is None:
        _fail("AUTHORIZATION_INVALID", "transport clock must be timezone-aware")
    return current.astimezone(timezone.utc)


def require_unexpired(
    authorization: dict[str, Any], clock: Callable[[], datetime]
) -> None:
    """Reject authorization that has expired before the next bounded mutation."""

    try:
        expires_at = datetime.strptime(
            authorization["expires_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except (KeyError, TypeError, ValueError) as error:
        raise DeploymentAgentPackageTransportError(
            "AUTHORIZATION_INVALID", "preflight expiry is malformed"
        ) from error
    if expires_at <= _clock_time(clock):
        _fail("LEASE_EXPIRED", "lease expired during package transport")


def _plan(value: object) -> dict[str, Any]:
    try:
        plan = validate_deployment_agent_update_plan(value)
    except DeploymentAgentReconcileError as error:
        raise DeploymentAgentPackageTransportError(
            error.category, str(error)
        ) from error
    if plan["artifact_size"] > min(MAX_ARTIFACT_SIZE, MAX_TRANSPORT_SIZE):
        _fail("ARTIFACT_TOO_LARGE", "artifact exceeds the transport byte limit")
    return plan


def _staging(value: object, plan: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != STAGING_KEYS:
        _fail("STAGING_MISMATCH", "staging evidence has an unexpected shape")
    expected_name = f"{plan['checksum_sha256']}-{plan['package_name']}"
    path = value["path"]
    if (
        value["size"] != plan["artifact_size"]
        or value["sha256"] != plan["checksum_sha256"]
        or value["plan_sha256"] != plan["plan_sha256"]
        or not isinstance(path, str)
        or PurePosixPath(path).name != expected_name
    ):
        _fail("STAGING_MISMATCH", "staging evidence does not match the update plan")
    _canonical_components(path, "staging.path")
    return dict(value)


def _authorize(
    lease: object,
    plan: dict[str, Any],
    member_target_id: object,
    member_address: object,
    member_targets: object,
    runtime_commit: object,
    tls_validation_enabled: object,
    lab_tls_exception_acknowledged: object,
    check_mode: object,
    now: datetime | None,
) -> dict[str, Any]:
    observation = {
        "path": plan["source_path"],
        "size": plan["artifact_size"],
        "sha256": plan["checksum_sha256"],
    }
    try:
        return authorize_deployment_agent_execution(
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
        raise DeploymentAgentPackageTransportError(
            error.category, str(error)
        ) from error


def prepare_deployment_agent_package_transport(
    lease: object,
    update_plan: object,
    staging: object,
    member_target_id: object,
    member_address: object,
    member_targets: object,
    runtime_commit: object,
    tls_validation_enabled: object,
    lab_tls_exception_acknowledged: object,
    ssh_host_key_checking_enabled: object,
    check_mode: object,
    now: datetime | None = None,
) -> tuple[int, tuple[int, int, int, int, int, int], dict[str, Any], dict[str, Any]]:
    """Open and validate the exact staged source retained for chunk transport."""

    if ssh_host_key_checking_enabled is not True:
        _fail(
            "SSH_HOST_KEY_VALIDATION_INVALID",
            "package transport requires SSH host-key validation",
        )
    plan = _plan(update_plan)
    staged = _staging(staging, plan)
    components = _canonical_components(staged["path"], "staging.path")[1]
    try:
        source_fd = _open_source(components)
    except DeploymentAgentArtifactStagingError as error:
        raise DeploymentAgentPackageTransportError(
            "STAGING_MISMATCH", "staged source is unavailable or unsafe"
        ) from error
    try:
        before = _metadata(source_fd)
        value = os.fstat(source_fd)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_size != plan["artifact_size"]
            or stat.S_IMODE(value.st_mode) != 0o400
            or value.st_uid != os.geteuid()
            or value.st_nlink != 1
        ):
            _fail("STAGING_MISMATCH", "staged source identity is unsafe")
        try:
            first_digest = _hash_source(source_fd, plan["artifact_size"])
            second_digest = _hash_source(source_fd, plan["artifact_size"])
        except DeploymentAgentArtifactStagingError as error:
            raise DeploymentAgentPackageTransportError(
                "STAGING_MISMATCH", "staged source could not be read safely"
            ) from error
        if (
            first_digest != plan["checksum_sha256"]
            or second_digest != first_digest
            or _metadata(source_fd) != before
        ):
            _fail("STAGING_MISMATCH", "staged source content is inconsistent")
        authorization = _authorize(
            lease,
            plan,
            member_target_id,
            member_address,
            member_targets,
            runtime_commit,
            tls_validation_enabled,
            lab_tls_exception_acknowledged,
            check_mode,
            now,
        )
        os.lseek(source_fd, 0, os.SEEK_SET)
        return source_fd, before, plan, authorization
    except Exception:
        os.close(source_fd)
        raise


def _decode_chunk(value: object) -> bytes:
    if not isinstance(value, str) or len(value) > ((CHUNK_SIZE + 2) // 3) * 4:
        _fail("TRANSFER_CHUNK_INVALID", "transport chunk exceeds the encoded limit")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise DeploymentAgentPackageTransportError(
            "TRANSFER_CHUNK_INVALID", "transport chunk is not canonical base64"
        ) from error
    if (
        not decoded
        or len(decoded) > CHUNK_SIZE
        or base64.b64encode(decoded).decode("ascii") != value
    ):
        _fail("TRANSFER_CHUNK_INVALID", "transport chunk is empty or non-canonical")
    return decoded


def _secure_child_directory(parent_fd: int, name: str) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    except OSError as error:
        raise DeploymentAgentPackageTransportError(
            "REMOTE_PATH_UNSAFE", "fixed transport directory could not be created"
        ) from error
    try:
        directory_fd = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
    except OSError as error:
        raise DeploymentAgentPackageTransportError(
            "REMOTE_PATH_UNSAFE", "fixed transport directory is unsafe"
        ) from error
    value = os.fstat(directory_fd)
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != os.geteuid()
        or stat.S_IMODE(value.st_mode) != 0o700
    ):
        os.close(directory_fd)
        _fail(
            "REMOTE_PATH_UNSAFE",
            "fixed transport directory must be owner-only",
        )
    return directory_fd


def _transport_directory() -> tuple[str, int]:
    try:
        home = pwd.getpwuid(os.geteuid()).pw_dir
    except (KeyError, OSError) as error:
        raise DeploymentAgentPackageTransportError(
            "REMOTE_PATH_UNSAFE", "remote account home directory is unavailable"
        ) from error
    home_path, components = _canonical_components(home, "remote account home")
    try:
        home_fd = _open_directory(components, "remote account home")
    except DeploymentAgentArtifactStagingError as error:
        raise DeploymentAgentPackageTransportError(
            "REMOTE_PATH_UNSAFE", "remote account home directory is unsafe"
        ) from error
    try:
        home_stat = os.fstat(home_fd)
        if (
            home_stat.st_uid != os.geteuid()
            or stat.S_IMODE(home_stat.st_mode) & 0o022
        ):
            _fail(
                "REMOTE_PATH_UNSAFE",
                "remote account home must be owner-controlled",
            )
        collection_fd = _secure_child_directory(home_fd, TRANSFER_DIRECTORY)
    finally:
        os.close(home_fd)
    try:
        package_fd = _secure_child_directory(collection_fd, PACKAGE_DIRECTORY)
    finally:
        os.close(collection_fd)
    return f"{home_path}/{TRANSFER_DIRECTORY}/{PACKAGE_DIRECTORY}", package_fd


def _write_all(file_fd: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(file_fd, view)
        if written <= 0:
            _fail("TRANSFER_WRITE_FAILED", "remote transport write did not progress")
        view = view[written:]


def receive_deployment_agent_package_chunk(
    lease: object,
    update_plan: object,
    staging: object,
    member_target_id: object,
    member_address: object,
    member_targets: object,
    runtime_commit: object,
    tls_validation_enabled: object,
    lab_tls_exception_acknowledged: object,
    ssh_host_key_checking_enabled: object,
    offset: object,
    content_base64: object,
    final: object,
    check_mode: object,
    now: datetime | None = None,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Append one authorized chunk and publish only an exact complete package."""

    if ssh_host_key_checking_enabled is not True:
        _fail(
            "SSH_HOST_KEY_VALIDATION_INVALID",
            "package transport requires SSH host-key validation",
        )
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        _fail("TRANSFER_OFFSET_INVALID", "transport offset must be non-negative")
    if final not in (True, False):
        _fail("TRANSFER_CHUNK_INVALID", "final must be a boolean")
    chunk = _decode_chunk(content_base64)
    plan = _plan(update_plan)
    _staging(staging, plan)
    if offset + len(chunk) > plan["artifact_size"]:
        _fail("TRANSFER_SIZE_MISMATCH", "transport chunk exceeds the bound size")
    if final is not (offset + len(chunk) == plan["artifact_size"]):
        _fail("TRANSFER_FINAL_INVALID", "final marker does not match bound size")
    authorization = _authorize(
        lease,
        plan,
        member_target_id,
        member_address,
        member_targets,
        runtime_commit,
        tls_validation_enabled,
        lab_tls_exception_acknowledged,
        check_mode,
        now,
    )
    selected_clock = clock or (lambda: datetime.now(timezone.utc))
    require_unexpired(authorization, selected_clock)

    root_path = ""
    root_fd = -1
    file_fd = -1
    temporary_name = f".transport-{authorization['lease_id']}"
    destination_name = f"{plan['checksum_sha256']}-{plan['package_name']}"
    try:
        root_path, root_fd = _transport_directory()
        if offset == 0:
            try:
                file_fd = os.open(
                    temporary_name, TEMPORARY_FLAGS, 0o600, dir_fd=root_fd
                )
            except FileExistsError as error:
                raise DeploymentAgentPackageTransportError(
                    "TRANSFER_REPLAYED",
                    "this lease already has an incomplete transport",
                ) from error
        else:
            try:
                file_fd = os.open(temporary_name, APPEND_FLAGS, dir_fd=root_fd)
            except OSError as error:
                category = (
                    "TRANSFER_MISSING"
                    if error.errno == errno.ENOENT
                    else "REMOTE_PATH_UNSAFE"
                )
                raise DeploymentAgentPackageTransportError(
                    category, "incomplete transport is unavailable or unsafe"
                ) from error
        value = os.fstat(file_fd)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_uid != os.geteuid()
            or value.st_nlink != 1
            or stat.S_IMODE(value.st_mode) != 0o600
            or value.st_size != offset
        ):
            _fail(
                "TRANSFER_OFFSET_MISMATCH",
                "incomplete transport identity or offset does not match",
            )
        require_unexpired(authorization, selected_clock)
        os.lseek(file_fd, 0, os.SEEK_END)
        _write_all(file_fd, chunk)
        os.fsync(file_fd)
        require_unexpired(authorization, selected_clock)
        new_offset = offset + len(chunk)
        if not final:
            return {
                "changed": True,
                "progress": {
                    "offset": new_offset,
                    "size": plan["artifact_size"],
                    "plan_sha256": plan["plan_sha256"],
                },
                "authorization": authorization,
            }

        os.close(file_fd)
        file_fd = -1
        file_fd = os.open(temporary_name, SOURCE_FLAGS, dir_fd=root_fd)
        before = _metadata(file_fd)
        if (
            before[3] != plan["artifact_size"]
            or _hash_source(file_fd, plan["artifact_size"])
            != plan["checksum_sha256"]
            or _metadata(file_fd) != before
        ):
            _fail(
                "TRANSFER_CHECKSUM_MISMATCH",
                "complete remote transport does not match the bound package",
            )
        os.fchmod(file_fd, 0o400)
        os.fsync(file_fd)
        os.close(file_fd)
        file_fd = -1
        require_unexpired(authorization, selected_clock)
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
            try:
                _validate_existing(
                    root_fd,
                    destination_name,
                    plan["artifact_size"],
                    plan["checksum_sha256"],
                )
            except DeploymentAgentArtifactStagingError as error:
                raise DeploymentAgentPackageTransportError(
                    "DESTINATION_COLLISION",
                    "published package identity does not match",
                ) from error
            changed = False
        os.unlink(temporary_name, dir_fd=root_fd)
        sync_fd = os.open(".", SYNC_DIRECTORY_FLAGS, dir_fd=root_fd)
        try:
            os.fsync(sync_fd)
        finally:
            os.close(sync_fd)
        return {
            "changed": changed,
            "transport": {
                "path": f"{root_path}/{destination_name}",
                "size": plan["artifact_size"],
                "sha256": plan["checksum_sha256"],
                "plan_sha256": plan["plan_sha256"],
            },
            "authorization": authorization,
        }
    except DeploymentAgentPackageTransportError as error:
        if (
            error.category
            in {
                "DESTINATION_COLLISION",
                "LEASE_EXPIRED",
                "TRANSFER_CHECKSUM_MISMATCH",
            }
            and root_fd >= 0
        ):
            try:
                os.unlink(temporary_name, dir_fd=root_fd)
            except OSError:
                pass
        raise
    except OSError as error:
        raise DeploymentAgentPackageTransportError(
            "TRANSFER_WRITE_FAILED", "remote package transport failed"
        ) from error
    finally:
        if file_fd >= 0:
            try:
                os.close(file_fd)
            except OSError:
                pass
        if root_fd >= 0:
            try:
                os.close(root_fd)
            except OSError:
                pass
