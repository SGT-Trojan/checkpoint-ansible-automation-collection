# Package Observation and Acquisition Boundary

This milestone certifies only local package artifact observation. It does not
acquire target package inventory, restore-point capacity, transport a package,
contact a Check Point API, or execute a package action.

## Pinned vendor-source audit

The offline audit inspected the locally pinned `check_point.mgmt` 6.9.0 and
`check_point.gaia` 7.0.0 module sources and documentation.
CI revalidates the Management-side limitation directly from pinned source with
`tests/utils/verify_package_inventory_capability.py`. The gate pins the exact
version and module-local documented options and return root, recognizes common
pagination/completion/task markers recursively, binds the literal command to
the direct generic helper call, and rejects sibling functions. Shared
documentation fragments and helper internals are not inferred as completeness
proof; a version or checked module-local contract change requires deliberate
reassessment and never silently enables acquisition.

| Required observation | Pinned supported content | Finding |
|---|---|---|
| Complete installed-package inventory for each exact target | `cp_mgmt_show_software_packages_per_targets` | The read-only command can request installed package state for named targets, but its module contract has no pagination fields, completeness flag, or bounded asynchronous task envelope. Its response therefore cannot truthfully set `installed_packages_complete: true` yet. |
| Repository inventory | `cp_mgmt_repository_package_facts` | Provides paginated Management repository objects, not the complete installed CPUSE inventory of an exact gateway target. |
| Current restore-point free capacity | `cp_gaia_diagnostics_facts`, `cp_gaia_asset_facts`, `cp_gaia_scheduled_snapshot_facts` | Diagnostics exposes generic OS disk facts, asset facts exposes hardware, and scheduled-snapshot facts exposes scheduler policy such as configured reserve. None documents current space available for restore points. |

The equivalent Gaia CLI observations come from
`show installer packages`/`show installer packages installed` and
`show snapshots`. Those command paths are not carried into this
collection. A future custom acquisition would require a
typed supported API transport, a fixed internal operation, strict bounded
response and completeness validation, and no caller-supplied command, script,
or path. Until that contract is implemented and tested, both observations
remain fail-closed and no role claims them.

## Local artifact observer

`cp_automation_artifact_observe` observes one exact controller-local package
path. `checkpoint_artifact_observation` pins it to a genuine local connection
and rejects an inventory-defined remote `localhost`.

The observer:

- accepts one lexically canonical absolute expected path;
- opens every parent directory and the final file with no-follow semantics;
- opens the final path nonblocking so a FIFO cannot stall type validation;
- requires a positive-size regular file;
- performs two SHA-256 passes on the same descriptor, reading exactly the
  initial positive size in chunks no larger than 1 MiB and probing one extra
  byte after each pass to reject growth;
- bounds data-read calls per pass from the ceiling of size divided by 1 MiB,
  with conservative factor and fixed slack for legitimate short reads;
- requires both pass digests to match without loading the package into memory;
- compares descriptor device, inode, mode, size, nanosecond mtime, and
  nanosecond ctime before and after hashing;
- reopens the expected path with the same no-follow traversal and requires the
  same identity, mode, size, mtime, and ctime;
- returns only path, byte size, and lowercase SHA-256; and
- always reports `changed: false` and supports check mode.

Symbolic links in any component, missing paths, non-regular or empty files,
read failures, exhausted read-call budgets, metadata drift, and path
replacement fail closed. Both actual bytes and read calls are bounded; the
contract does not equate requested bytes with bytes actually returned. The
module does not expose file content and does not validate a remote MDS or
gateway copy. Its result is shaped for the existing transport-free package
validator.

Success is only a point-in-time observation. It does not authorize a later
consumer to reopen or consume the path, and the two-pass design does not
remove post-return TOCTOU. A future mutating transport must reobserve
immediately before use and either validate, hash, and consume from the same
retained descriptor, or create and consume an immutable/content-addressed
staged copy in one bounded operation.

The controller must provide POSIX/Linux-style `O_DIRECTORY`, `O_NOFOLLOW`,
`O_CLOEXEC`, and `O_NONBLOCK` flags plus directory-relative `open`. Missing
capabilities fail explicitly as `PLATFORM_UNSUPPORTED`; no-follow traversal
is never weakened for portability.

This content remains read-only and cannot authorize a live package operation.
