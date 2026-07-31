# Package Observation and Acquisition Boundary

This milestone certifies local package artifact observation and an
offline-tested target package-state acquisition contract. It does not authorize
live target access, transport a package, or execute a package action.

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

The sanitized original workflow obtains installed CPUSE inventory from
`show installer packages installed` and parses restore-point capacity from
`show snapshots`. `cp_automation_package_state_acquire` now carries those two
read-only observations behind one typed Gaia HTTPAPI module. Its internal
`run-script` payload is fixed collection content: callers cannot provide a
script, command, path, argument, variable, or environment entry.

The module submits the fixed operation once, polls only its returned task ID
within caller-selected hard bounds and the expiry returned by the immediately
preceding live preflight. It checks that expiry before and after submission and
each poll, and shortens its sleep at the lease boundary. Responses arriving
after expiry are rejected. It requires canonical base64 and UTF-8 output,
and validates an exact ordered section envelope. It sets
`installed_packages_complete: true` only after the CPUSE command returns zero,
no incomplete-inventory warning is present, and every line matches one complete
CPUSE format observed in the retained workflow evidence. The parser accepts
either headed tables whose rows have a recognized Hotfix, Blink Version,
Major Version, Minor Version, or Upgrade type, or status rows made of one
package identity followed by the literal `Installed`. Consecutive CPUSE title
lines may introduce each headed table, and multiple headed sections are
combined. It never mixes the table and status-row forms. Package
identities must be unique and bounded. On an inventory-format failure, the
role may expose one fixed parser-branch reason such as
`TYPED_HEADER_UNSUPPORTED` or `STATUS_MULTI_COLUMN`, plus at most 17
allowlisted line-kind tokens such as `TITLE`, `HEADER_OTHER`, or
`MULTI_TYPE`. It never returns a package line, package identity, line length,
raw command output, or arbitrary exception text.
Restore capacity must appear exactly once with an explicit
supported unit. CPUSE bare binary prefixes such as `G` and byte-suffixed forms
such as `GB` and `GiB` are accepted. Existing `B`, `iB`, `byte`, and
prefixed byte-word spellings remain supported. A failure marker still rejects the entire
snapshot observation. Fractional values are converted to bytes by rounding
down.

`checkpoint_package_state_acquisition` binds the fixed operation to one
explicit Gaia HTTPAPI TLS mode. Strict validation is the normal and
production-supported path. A lease-bound `lab_unverified` mode exists only for
controlled lab observation and requires a separate literal acknowledgment.
The role derives `target_id` from
`inventory_hostname`, binds `member_address` to `ansible_host`, checks the
`expert_api_runScript` feature, and publishes only the five target-state fields
accepted by `cp_automation_package_validate`. The inventory alias must therefore
be the exact target identity used by the package step. The leased executor
requires `/etc/ansible/hosts` to be absent on the controller because Check Point
Gaia 7.0.0 reads that hardcoded source to enable Management API proxy mode. The
role also rejects `ansible_checkpoint_target`. The acquisition module rechecks
the controller proxy source immediately before opening its persistent
connection. These controls keep requests on the leased direct-member
connection. In `lab_unverified` mode, the feature
probe, fixed operation, and task polling all lack server-identity and MITM
protection. Certificate validation remains required before production
certification.

Gaia can return a temporary non-200 response before a newly submitted task is
visible to `show-task`. The acquisition retries only this initial visibility
window, with at most 40 polls. The operation timeout and lease expiry can stop
it sooner. `run-script` is never replayed, and any non-200 response after the
task first becomes visible fails immediately.

Each member host receives `checkpoint_package_target_state`. After every member
has completed the role, a controller task can build the validator input without
changing field names:

```yaml
- name: Collect package target states on the controller
  ansible.builtin.set_fact:
    checkpoint_package_target_states: >-
      {{ groups["checkpoint_package_state_members"]
      | map("extract", hostvars, "checkpoint_package_target_state")
      | list }}
  run_once: true
  delegate_to: localhost
  no_log: true
  changed_when: false
```

The supplied `checkpoint_package_state_step_name` must match one package-step
`name`, and every inventory alias must appear in that step's `target_ids` list.
The role does not aggregate hosts or call the validator itself.

`playbooks/live_readonly_package_state.yml` is the only shipped live entry point
for this role. It requires check mode and a separate 15-minute lease, binds the
lease to exactly two inventory members, runs them serially, and repeats
preflight immediately before each Gaia request. The role rejects direct use
without those lease inputs. The code accepts leases up to 15 minutes; shorter
leases can be issued for a particular lab run without changing that ceiling.

This boundary passed controlled two-member lab validation in check mode with
`lab_unverified` TLS. Both members completed serially with `changed: false`;
package inventory and restore capacity were parsed and published without a
mutation. Strict certificate validation is still pending. Package transport and
execution remain separate and unimplemented.

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

The controller must provide Linux-style `O_PATH`, `O_DIRECTORY`, `O_NOFOLLOW`,
`O_CLOEXEC`, and `O_NONBLOCK` flags plus directory-relative `open`. Missing
capabilities fail explicitly as `PLATFORM_UNSUPPORTED`; no-follow traversal
is never weakened for portability.

No new live lease may use this content before independent hostile review.
