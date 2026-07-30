# Constrained Live Read-Only Executor

`playbooks/live_readonly_managed_discovery.yml` is the only live entry point
currently supplied by this collection. Its first play runs on localhost and
must complete `checkpoint_live_readonly_preflight` before the imported managed
discovery can make a Management API request.

The executor does not authorize Gaia readiness acquisition yet. No Gaia request
belongs in this executor until its credential requirements and inventory
binding receive the same offline coverage.

## Safety boundary

The preflight module performs no network request and accepts no credential
value. It requires all of these conditions:

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
or `MUTATION_BLOCKED`.

The lease is a short-lived operational interlock, not a replacement for
workstation access control, Ansible Vault, API least privilege, or change
approval.

The current executor certifies the username/password inventory path only.
API-key authentication remains fail-closed until it has a separate
credential-presence contract and offline coverage.

## Runtime lease

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
