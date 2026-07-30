# Managed Target Discovery

This workflow resolves two member addresses to one managed Check Point cluster.
It reads the MDS System Data domain, opens a separate Management API session for
each regular domain, gathers complete gateway and cluster facts, and fails if
the result is incomplete or ambiguous. It does not change Check Point state.

## Install

Install the exact dependency set used by the current test matrix:

```bash
ansible-galaxy collection install -r requirements.yml
```

The workflow uses `check_point.mgmt` 6.9.0. The Management API version is a
separate server-side value and must be supplied without a leading `v`.

## Inventory

Start from [managed_target_inventory.yml](../examples/managed_target_inventory.yml).
The example uses documentation addresses and must be changed for your MDS.

The host `mds_system` belongs to both groups:

- `checkpoint_mds_system` must contain exactly one host.
- `checkpoint_api_sessions` holds connection settings shared by the System Data
  alias and every regular-domain alias created at runtime.

Place discovery controls used by `localhost` or dynamic domain hosts under
`all.vars`, as shown in the example. Host variables under `mds_system` are
visible only to the System Data play.

Store `vault_checkpoint_username` and `vault_checkpoint_password` in an Ansible
Vault file. To use an API key instead, remove both user/password variables and
set `ansible_api_key` from Vault. Do not configure both authentication methods.

Keep certificate validation enabled. Add the issuing CA to the automation
host's trust store instead of setting `ansible_httpapi_validate_certs: false`.
The package-state executor's lease-bound lab exception does not apply to this
managed-discovery workflow.

## Targets

Copy [managed_target_vars.yml](../examples/managed_target_vars.yml) and replace
the documentation addresses with both cluster-member addresses. The optional
`checkpoint_preferred_domain` must match a discovered regular-domain or active
CMA name; matching is case-insensitive.

```yaml
checkpoint_target_ips:
  - 198.51.100.10
  - 198.51.100.11
checkpoint_preferred_domain: Example-Domain
```

A comma-separated string is not accepted. The list form prevents ambiguous
input parsing.

## Run

From an installed collection:

```bash
ansible-playbook sgt_trojan.checkpoint_automation.resolve_managed_cluster \
  -i managed_target_inventory.yml \
  -e @managed_target_vars.yml \
  -e @vault.yml --ask-vault-pass
```

From this source checkout, first place it under an
`ansible_collections/sgt_trojan/checkpoint_automation` path or build and install
the collection archive.

`--check` is supported. The vendor's read-only
`cp_mgmt_show_gateways_and_servers` module does not declare check-mode support,
so that one task explicitly runs with `check_mode: false`; its vendor helper
marks `show-*` commands unchanged. No mutating module receives that exception.

## Result

The final localhost fact is `checkpoint_resolved_target`. It contains the
resolved domain, active CMA, cluster identity, member identities and addresses,
policy metadata when supplied by the API, and version metadata when supplied by
the API. A calling playbook can import this collection playbook and use that
fact in later plays.

The workflow stops instead of returning a partial target when:

- System Data pagination is incomplete or changes between pages;
- no regular domain or authoritative active CMA is available;
- a domain page is missing, repeated, or internally inconsistent;
- a full cluster detail does not match its summary UID;
- one planned domain host fails to publish a complete result;
- the addresses match no supported two-member cluster; or
- more than one cluster or domain matches.

## Role Boundaries

`checkpoint_mds_domains` gathers and validates every System Data page, then
creates the domain-session plan.

`checkpoint_domain_inventory` runs once per isolated regular-domain alias. It
gathers gateway/server pages, simple-cluster summaries, and full details.

`checkpoint_target_resolution` verifies that every planned domain completed,
aggregates the records, and invokes `cp_automation_target_resolve` locally.

These roles are reusable, but the four-play collection playbook is the reference
composition because Ansible can only use hosts created by `add_host` in a later
play.

## Current Scope

This milestone resolves exactly two-member managed clusters. Standalone
gateways and clusters with another member count remain explicit parity work and
are not silently treated as supported. Live certification is still pending.
