# Architecture

## Scope

This collection reproduces the Check Point technical workflow independently of
ServiceNow. Ticket creation, approval records, and platform-specific task state
remain the responsibility of the calling system.

The collection exposes structured results that an external orchestrator can
use for approvals, tester pauses, recovery tasks, and audit notes.

## Rules

1. Use supported `check_point.mgmt.cp_mgmt_*` and
   `check_point.gaia.cp_gaia_*` modules when they meet the required behavior.
2. Do not use deprecated `checkpoint_*` modules.
3. Do not wrap a working upstream module in a custom module.
4. Do not launch repository Python helpers through `command` or `shell`.
5. Return structured facts, decisions, evidence paths, and change status.
6. Stop when target, package, member, policy, or state is missing or ambiguous.
7. Change the standby member first.
8. Require explicit execution controls for mutating operations.
9. Keep CDT, Management API, and direct CPUSE paths separate.
10. Preserve exact package identity and checksums through every phase.

## Layers

### Upstream modules

Management Web API and Gaia REST API operations provided by the vendor
collections.

### Custom modules

Missing Check Point operations and project-specific safety gates. Shared
transport, parsing, package identity, and result handling live in
`plugins/module_utils`.

### Roles

Roles compose modules into readiness, rolling JHF, major-upgrade, Deployment
Agent, and evidence workflows.

### Calling orchestrator

The caller decides when a workflow may start or resume. It may be a command-line
playbook, Automation Controller, ServiceNow, or another change system.

## Management context isolation

The Management HTTPAPI plugin selects a Multi-Domain context during login. A
persistent connection does not switch domains just because a later task changes
`ansible_checkpoint_domain`. The discovery workflow therefore creates one
opaque inventory alias per regular domain. Every alias may point to the same
MDS address, but it owns a separate authenticated connection and a fixed domain
name.

Credentials and TLS settings belong in inventory group variables or Ansible
Vault. Dynamic hosts contain only non-secret connection metadata and the raw
domain record. A task must never alternate domain names on one persistent
connection.

## Managed target discovery

Managed-cluster resolution uses four stages:

1. Query every page of full domain facts from an explicit System Data session.
2. Validate the complete result and create one isolated session per regular
   domain.
3. In every domain, collect all gateway/server and simple-cluster pages, then
   expand each cluster and verify the returned UID against its summary UID.
4. Aggregate every domain result locally and resolve the requested addresses to
   exactly one supported target.

Pagination advances by the number of rows actually returned. Declared totals,
request offsets, response `offset`, and one-based inclusive `from`/`to` metadata
are checked when present. A stable name order reduces movement between pages,
but it is not a server-side snapshot; high-risk execution will require two
identical discovery passes before mutation.

## Cluster readiness

Readiness is split into acquisition, parsing, and decision layers. The pure
`cp_automation_cluster_observe` module parses one member ClusterXL, interface,
and optional ICAP evidence. The pure `cp_automation_readiness_decide` module
then requires exactly one ACTIVE and one STANDBY member and applies expected
owner, ICAP, and interface-baseline gates.

The parser and decision modules make no network calls. The acquisition role
uses a typed fixed Gaia HTTPAPI operation and accepts no caller-supplied
command text. This boundary keeps arbitrary remote execution out of module
inputs and lets hostile fixtures test the complete decision logic offline.

## Live read-only boundary

The live managed-discovery entry point begins with a localhost preflight. A
short UTC lease, exact runtime IP targets, computed credential-presence flags,
genuine local connection, and Ansible check mode must all agree before
authorization exists. Management API roles independently require that
authorization before their first request, using credentials from the actual
coordinator or domain session host.

The authorization result contains a target fingerprint but no addresses or
credential values. A structured build-time YAML call-graph verifier recursively
proves the exact literal read-only graph; runtime preflight does not claim that
a caller-provided action list can prove execution. Evidence handling is not yet
part of this executor because there is no bounded atomic producer/consumer
lifecycle. Gaia acquisition is not yet authorized by this executor.

## Execution boundary

Modules perform bounded operations. Human approval, tester pauses, duplicate-run
control, and durable workflow resumption are role and orchestrator concerns.

No module may silently broaden its target from one cluster or member to another.
