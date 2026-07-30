# Deployment Agent

The Deployment Agent is part of Check Point's CPUSE package workflow. An old
agent can block a package install even when the package itself is valid.

This collection treats agent work as its own maintenance path. It does not
combine an agent update with a rolling JHF or major upgrade.

## Current modules

`cp_automation_deployment_agent_acquire` runs one fixed read-only Gaia
operation and returns normalized state. It accepts no command, script, path,
argument, or environment option. `cp_automation_deployment_agent_observe`
parses status acquired by another approved transport.
`cp_automation_deployment_agent_decide` compares either observation with:

- the minimum build allowed for the planned package; and
- an optional exact build expected after an offline update.

The result is data. `ready: false` does not fail the Ansible task, so a role can
record the reason and choose the approved remediation path. Invalid or
ambiguous input does fail the task.

`cp_automation_deployment_agent_package_bind` joins one normalized
`deployment_agent` step from `cp_automation_package_validate` to the numeric
build policy. It requires the exact package path, file name, size, SHA-256, two
target identities, minimum build, and expected build. The result includes a
deterministic binding digest for later staging and execution checks.

```yaml
- name: Bind the validated offline Deployment Agent package
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_package_bind:
    package_step: "{{ checkpoint_package_contract.validation.steps[0] }}"
    required_build: 2771
    expected_build: 2771
  register: checkpoint_deployment_agent_package
```

The binder does not read or stage the package and does not contact a gateway.
Artifact observation and the generic package validator must run first.
It also rejects double-root paths such as `//srv/package.tgz`, even if an
earlier generic validation result contains one.

`cp_automation_deployment_agent_update_plan` revalidates that exact binding,
requires normalized state for both bound targets, and selects exactly one
enabled target. It rejects disabled peers, target ambiguity, a changed binding
digest, and observed builds above the bound expected build. The result fixes
the selected target, peer, package evidence, expected build, vendor operation,
and a deterministic plan digest:

```yaml
- name: Plan one bound update without contacting a target
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_update_plan:
    package_binding: "{{ checkpoint_deployment_agent_package.binding }}"
    target_states: "{{ checkpoint_deployment_agent_target_states }}"
    selected_target_id: member-a
  register: checkpoint_deployment_agent_update
```

This module is transport-free. It never reads or stages the package, opens a
lease, contacts a firewall, or performs the returned operation. A plan is data
for a later separately reviewed executor and does not authorize live access.

`cp_automation_deployment_agent_reconcile` consumes that exact plan plus new
normalized state for both members. It requires the selected member at the exact
expected build, requires the peer to remain enabled and at its pre-update
build, and returns deterministic evidence that the peer is pending or that both
members are complete:

```yaml
- name: Reconcile previously acquired post-update state offline
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_reconcile:
    update_plan: "{{ checkpoint_deployment_agent_update.plan }}"
    target_states: "{{ checkpoint_deployment_agent_post_update_states }}"
  register: checkpoint_deployment_agent_reconciliation
```

This reconciler also performs no acquisition or live action. Its
`next_target_id` is evidence, not authorization to update that target.

`cp_automation_deployment_agent_reacquire_plan` revalidates the same update
plan and fixes exactly two read-only observations in selected-then-peer order.
It exposes no operation, address, path, argument, timeout, lease, or transport
option:

```yaml
- name: Plan fixed post-update observations offline
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_reacquire_plan:
    update_plan: "{{ checkpoint_deployment_agent_update.plan }}"
  register: checkpoint_deployment_agent_reacquisition
```

The returned order and digest are data for later separately authorized calls
to the existing fixed acquisition module. They do not open a lease, contact a
target, or authorize either observation.

`cp_automation_deployment_agent_evidence` requires that exact reacquisition
plan, the source update plan, and two normalized post-update states. It binds
the reacquisition-plan digest to exact-build reconciliation under one
deterministic evidence-chain digest:

```yaml
- name: Compose post-update evidence offline
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_evidence:
    update_plan: "{{ checkpoint_deployment_agent_update.plan }}"
    reacquisition_plan: >-
      {{ checkpoint_deployment_agent_reacquisition.reacquisition_plan }}
    target_states: "{{ checkpoint_deployment_agent_post_update_states }}"
  register: checkpoint_deployment_agent_evidence
```

The composer validates consistency; it does not prove where state came from
and performs no acquisition or live action.

`cp_automation_deployment_agent_next_plan` revalidates that entire offline
chain and derives a swapped second-member plan only when reconciliation says
the original peer is pending. Complete evidence fails closed with
`UPDATE_COMPLETE`. The derived plan remains data and does not authorize live
access or an update.

`cp_automation_deployment_agent_completion` rederives that second-member plan
from the complete first evidence chain, validates its exact fixed reacquisition
and final evidence chain, and emits a deterministic completion digest only
when both members reconcile at the expected build. It performs no acquisition,
transport, lease, filesystem, or update action.

`checkpoint_deployment_agent_completion` is the localhost-only composition
role for that attestor. It accepts only the seven structured offline inputs,
rejects remote or inventory-redirected localhost execution, invokes no
acquisition or live module, and publishes only the sanitized completion
attestation with `changed: false`. CI resolves the installed role by its
collection FQCN in a localhost-only syntax check; that check uses inert defaults
and does not execute the role or contact a target.

CI also executes a localhost-only synthetic completion chain. It composes the
approved package binding, plan, reacquisition, evidence, pending-peer, and
completion boundaries from fixed data. The fixture contains no acquisition,
lease, transport, filesystem, update executor, or target action.
It also changes only the final evidence digest and requires the completion role
to reject that tampering with the exact `EVIDENCE_MISMATCH` category.
The fixed completion-chain focus runner selects exactly 68 unit tests and is
executed directly in CI, so its focused evidence is reproducible without
reconstructing a command from progress prose.

`checkpoint_deployment_agent_package_binding` composes those offline steps. It
runs only for genuine localhost, accepts one package step, observes one exact
local path, validates the two target states and checksum, requires the
validated step name to match, and publishes the bound package data. It opens no
live lease and contacts no firewall.

```yaml
- name: Normalize previously acquired status
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_observe:
    status_output: "{{ deployment_agent_status_output }}"
  register: deployment_agent_state

- name: Check the Deployment Agent requirement
  sgt_trojan.checkpoint_automation.cp_automation_deployment_agent_decide:
    observation: "{{ deployment_agent_state.observation }}"
    required_build: 2771
  register: deployment_agent_gate

- name: Stop before package work when the agent is not ready
  ansible.builtin.assert:
    that:
      - deployment_agent_gate.decision.ready
    fail_msg: "Deployment Agent maintenance is required before package work."
```

## Status evidence

The parser is built for the complete Clish command:

```text
show installer status all
```

The shorter `show installer status` command is not used. On some Gaia versions
it can display a command menu instead of the full status.

The parser keeps only three fields:

| Field | Meaning |
|---|---|
| `enabled` | Whether the status has exactly one `Agent: Enabled` field |
| `build` | The one positive numeric `Build number` |
| `cloud_state` | `current`, `update_available`, or `unknown` from the build note |

Readiness uses the numeric build. Text such as `agent build is up to date` is
only evidence about the cloud source and cannot make an older build pass.

Duplicate Agent or Build fields, missing fields, non-ASCII build digits,
control text, and oversized output fail closed. License text, cloud timestamps,
host prompts, and other status lines are not returned.

## Live read-only observation

`checkpoint_deployment_agent_observation` runs the fixed status request against
exactly two inventory members, one at a time. It checks a short-lived lease
before the Gaia feature lookup and checks it again before status acquisition.
The lease for this role must use:

```yaml
checkpoint_deployment_agent_live_lease:
  lease_id: "00000000-0000-4000-8000-000000000000"
  issued_at: "2026-07-30T12:00:00Z"
  expires_at: "2026-07-30T12:12:00Z"
  operation: deployment_agent_observation
  execution_mode: read_only
  tls_validation_mode: strict
  member_targets:
    - 192.0.2.10
    - 192.0.2.11
```

Create a new UUIDv4 and current timestamps for each run. A lease can last no
more than 15 minutes. The runtime inventory addresses must match the two leased
addresses exactly.

For strict TLS, set:

```yaml
ansible_httpapi_validate_certs: true
checkpoint_deployment_agent_lab_tls_exception_acknowledged: false
```

For an isolated lab that cannot yet validate the server certificate, use:

```yaml
checkpoint_deployment_agent_live_lease:
  tls_validation_mode: lab_unverified
checkpoint_deployment_agent_lab_tls_exception_acknowledged: true
ansible_httpapi_validate_certs: false
```

This exception is for the isolated lab only. Server identity and MITM
protection are absent. Certificate validation remains a required pending live
test.

The role also requires a positive numeric build:

```yaml
checkpoint_deployment_agent_step_name: pre-package-agent-check
checkpoint_deployment_agent_required_build: 2771
checkpoint_deployment_agent_expected_build: null
```

It publishes `checkpoint_deployment_agent_target_state` with the inventory
target ID, normalized status, and numeric readiness decision. It never returns
the raw Gaia output. Use the constrained entry point with Ansible check mode:

```bash
ansible-playbook --check \
  -i examples/deployment_agent_inventory.yml \
  playbooks/live_readonly_deployment_agent.yml \
  -e @deployment-agent-lease.yml
```

Start from `examples/deployment_agent_inventory.yml`. The inventory group must
be named `checkpoint_deployment_agent_members` and contain exactly two direct
Gaia HTTPAPI hosts. The vendor proxy variable
`ansible_checkpoint_target` is rejected.

## Work still pending

The read-only acquisition path is inventory-bound, offline-tested, and observed
successfully against both lab members with `lab_unverified`. The run proved the
bounded flow, not a ready decision or strict certificate validation. Update
work remains in separate review boundaries:

1. add a separately reviewed, lease-bound executor and artifact staging;
2. add bounded reconnect and separately authorized execution of the fixed
   reacquisition plan around exact-build reconciliation;
3. run idempotent and older-to-current lab tests; and
4. test with strict certificate validation.

The update path will use the Check Point operation:

```text
installer agent install <approved-local-path>
```

The path will come from validated, staged artifact state. It will not be an
arbitrary command option. The module will then reacquire status and require the
expected build. An interrupted connection during the update will be treated as
an unknown outcome that must be reconciled, not as permission to submit the
update again.

Deployment Agent update has not been live-certified in this collection.
