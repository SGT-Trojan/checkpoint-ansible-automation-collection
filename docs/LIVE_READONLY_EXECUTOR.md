# Constrained Live Read-Only Executor

The collection supplies three live read-only entry points:

- `playbooks/live_readonly_managed_discovery.yml` for Management API discovery.
- `playbooks/live_readonly_package_state.yml` for installed-package inventory
  and restore-point free capacity on exactly two Gaia members.
- `playbooks/live_readonly_deployment_agent.yml` for Deployment Agent status on
  exactly two Gaia members.

All three require Ansible check mode and a separate short-lived lease. The Gaia
executors run members serially and recheck their lease immediately before Gaia
feature discovery and again before the fixed observation request.
The fixed operation rejects submissions and poll responses that cross the
validated lease expiry.
It cannot accept a command, script, path, package action, or mutation option.

The executor does not authorize Gaia readiness acquisition yet.

## Safety boundary

The managed-discovery preflight module performs no network request and accepts
no credential value. It requires all of these conditions:

- Ansible is running with `--check`.
- The lease has exactly the documented fields, a UUIDv4, `managed_discovery`
  operation, and `read_only` execution mode.
- Lease times use RFC3339 UTC `Z`, are current within 30 seconds of clock skew,
  and span no more than 15 minutes.
- The actual `checkpoint_mds_api_host` management IP and exactly two unique
  requested member IPs match the lease after IP normalization. Scoped IPv6 is
  rejected and IPv4-mapped IPv6 is compared as IPv4.
- Management username and secret presence flags are both literal booleans
  computed from the inventory host that owns the coordinator or domain session
  used by that request. Values remain in inventory/Vault and are never passed
  to the preflight module.
- Delegated preflight work is pinned to `ansible.builtin.local`. The preflight
  rejects an inventory-defined `localhost` that selects a remote connection or
  non-loopback host.

Success returns only `authorized`, the lease ID, operation, expiry, target
count, and a SHA-256 target fingerprint. It does not return addresses or
credential data.
Failure uses stable categories: `LEASE_INVALID`, `LEASE_EXPIRED`,
`TARGET_INVALID`, `TARGET_MISMATCH`, `CREDENTIALS_INVALID`,
`MUTATION_BLOCKED`, or `TARGET_PROXY_UNSUPPORTED`.

The lease is a short-lived operational interlock, not a replacement for
workstation access control, Ansible Vault, API least privilege, or change
approval.

The current executors certify username/password inventory paths only.
API-key authentication remains fail-closed until it has a separate
credential-presence contract and offline coverage.

## Package-state lease

Keep this lease in an ignored local variable file. Its target set must
match the two `ansible_host` values in
`checkpoint_package_state_members` exactly:

```yaml
checkpoint_package_state_live_lease:
  lease_id: 63c53f94-319d-444a-8c43-ec2584bcf985
  issued_at: "2026-07-29T12:00:00Z"
  expires_at: "2026-07-29T12:10:00Z"
  operation: package_state_observation
  execution_mode: read_only
  tls_validation_mode: strict
  member_targets:
    - 198.51.100.10
    - 198.51.100.11

checkpoint_package_state_step_name: example-package-step
```

Run only the leased entry point:

```bash
ansible-playbook --check \
  playbooks/live_readonly_package_state.yml \
  -i inventory.local.yml \
  -e @lease.local.yml
```

The inventory aliases become validator target IDs, so they must match the
`target_ids` in the package step. Credentials stay in inventory or Vault. The
preflight receives only two literal booleans stating whether the trimmed Gaia
username and secret are populated. Inventory must not define
`ansible_checkpoint_target`. The controller must not have
`/etc/ansible/hosts`; the pinned Gaia plugin reads that hardcoded source to
enable Management API proxy mode outside the leased direct-member boundary.

## TLS validation modes

`strict` is the default operational choice and the only mode intended for
production. Set `ansible_httpapi_validate_certs: true`, leave
`checkpoint_package_state_lab_tls_exception_acknowledged: false`, and trust
the issuing CA with `ansible_httpapi_ca_path` when a private CA is used.

`lab_unverified` is a temporary lab-only exception. The entire observation
session is unverified, including feature discovery, fixed `run-script`, and
task polling. Server identity and MITM protection are absent. It is not a
production configuration and is not certified. The exception still requires
check mode, a current lease, exactly two targets, direct HTTPS, and every other
executor gate. The in-tree lease ceiling remains 15 minutes; the planned lab
run will use a shorter 12-minute lease.

Use all three settings together. Any mismatch fails before the first request:

```yaml
# LAB ONLY - do not use for production
ansible_httpapi_validate_certs: false
checkpoint_package_state_lab_tls_exception_acknowledged: true

checkpoint_package_state_live_lease:
  lease_id: 63c53f94-319d-444a-8c43-ec2584bcf985
  issued_at: "2026-07-29T12:00:00Z"
  expires_at: "2026-07-29T12:12:00Z"
  operation: package_state_observation
  execution_mode: read_only
  tls_validation_mode: lab_unverified
  member_targets:
    - 198.51.100.10
    - 198.51.100.11
```

Certificate validation remains a required pending live test before production
certification. Fix the endpoint certificate and return to `strict`; do not carry
the acknowledgment into a strict lease. The completed lab observations used
12-minute leases within the 15-minute ceiling.

The role protects acquired package state with `no_log` and publishes
`checkpoint_package_target_state` on each member. The executor does not write
an evidence file or authorize package staging, install, upgrade, removal,
reboot, failover, or policy activity.

## Managed-discovery lease

Keep the lease outside the repository in an ignored local variable file. Its
shape is:

```yaml
checkpoint_live_lease:
  lease_id: 63c53f94-319d-444a-8c43-ec2584bcf985
  issued_at: "2026-07-29T12:00:00Z"
  expires_at: "2026-07-29T12:10:00Z"
  operation: managed_discovery
  execution_mode: read_only
  management_target: 192.0.2.5
  member_targets:
    - 198.51.100.10
    - 198.51.100.11
```

The addresses are documentation-only examples. A real lease contains private
topology and must never be committed or copied into automation status.

The constrained invocation requires both check mode and the live executor:

```bash
ansible-playbook --check \
  playbooks/live_readonly_managed_discovery.yml \
  -i inventory.local.yml \
  -e @lease.local.yml
```

Running the underlying discovery playbook directly bypasses the live interlock
and stops at the authorization guards before its first Management API request.
The System Data and per-domain roles rerun the complete preflight immediately
before every vendor request, so an expired lease stops later pagination and
detail calls.

## Build-time graph trust boundary

The runtime module deliberately does not accept a caller-supplied action list:
such a list cannot prove what Ansible executes. Instead, CI and release builds
run the structured verifier rooted at the live executor:

```bash
python3 tests/utils/verify_live_readonly_graph.py --collection-root .
```

The verifier parses YAML and recursively resolves only literal, collection-local
`ansible.builtin.import_playbook`, `ansible.builtin.include_tasks`, and
`ansible.builtin.include_role` targets. It traverses roles, handlers,
dependencies, blocks, rescue and always sections to arbitrary depth. Dynamic
or external targets, short/external roles, `action`/`local_action`, malformed
tasks, non-FQCN actions, and any action outside the exact approved read-only
graph fail closed. Active traversal cycles also fail closed except for the
three literal domain, gateway, and simple-cluster pagination self-includes;
each exception requires its exact bounded next-offset/total guard. This is a
build-time integrity proof; runtime preflight continues to enforce only lease,
target, credential-presence, local-execution, and check-mode gates.

The pinned `check_point.mgmt` 6.9.0 sources are also inspected offline:

```bash
python3 tests/utils/verify_mgmt_check_mode.py \
  --vendor-root /path/to/ansible_collections/check_point/mgmt \
  --collection-root .
```

`cp_mgmt_domain_facts` and `cp_mgmt_simple_cluster_facts` declare check-mode
support and are invoked with `check_mode: true`.
`cp_mgmt_show_gateways_and_servers` does not declare check-mode support and is
therefore invoked explicitly with `check_mode: false`; the executor's lease,
graph, and no-mutation controls remain mandatory around that read-only show
request.

## Evidence lifecycle

This milestone neither writes nor consumes a live evidence directory. No
evidence gate or atomicity claim is part of the runtime contract. Evidence
handling remains deferred until a bounded producer/consumer design can define
initial-empty versus revalidation behavior and atomic no-follow file handling.
This avoids presenting an unused directory check as an execution control.

## Current certification state

Lease, target, request-session credential-presence, local-execution, ordering,
structured graph, and no-mutation gates are hostile-tested offline. Syntax,
sanity, build, and package-content checks must also pass before a controlled
request is considered. This milestone does not itself authorize or perform a
live request.
