# Cluster Readiness

The readiness layer has two transport-free decision modules and one bounded
acquisition module:

- `cp_automation_cluster_observe` parses one member read-only output.
- `cp_automation_readiness_decide` evaluates exactly two observations.
- `cp_automation_readiness_acquire` gathers one fixed evidence envelope.

The parser and decision module do not connect to a firewall or run an
operation. The acquisition module is a typed network module over the supported
`check_point.gaia` HTTPAPI helper. It accepts no command, script, path,
environment, or arguments from a caller.

## Member observation

`cp_automation_cluster_observe` accepts these parameters:

| Parameter | Meaning |
|---|---|
| `name` | Expected ClusterXL member name |
| `address` | Expected member management IPv4 or IPv6 address |
| `cluster_state_output` | Complete `cphaprob state` output |
| `cluster_interfaces_output` | Complete `cphaprob -a if` output |
| `icap_cpwd_output` | Optional CICAP watchdog evidence |
| `icap_listener_output` | Optional TCP 1344 listener evidence |
| `icap_process_output` | Optional c-icap process evidence |

The parser requires one local row and exactly two unique ClusterXL member rows.
PNOTE health is true only when the output contains exactly one `Active PNOTEs:`
line and it explicitly reports `None`.

Interface health requires all declared counts, an exact monitored-row count,
every monitored row at `UP`, an exact secured sync-row count, and unique
interface identities. Markers such as `(S)` and `(S-LS)` are attributes, not
statuses. Non-monitored rows remain in evidence but do not count as required.

ICAP is `null` when no evidence is supplied. When evidence is supplied, health
requires one CICAP watchdog row explicitly in state `E`, a TCP socket in
`LISTEN` state on port 1344, and a process whose observed executable position
is `c-icap`. A different executable whose arguments merely mention `c-icap`
does not count.

```yaml
- name: Parse member A evidence
  sgt_trojan.checkpoint_automation.cp_automation_cluster_observe:
    name: Member-A
    address: 192.0.2.10
    cluster_state_output: "{{ member_a_state_output }}"
    cluster_interfaces_output: "{{ member_a_interfaces_output }}"
  register: member_a_observation
```

## Readiness decision

`cp_automation_readiness_decide` requires exactly two observations with unique
names and addresses. A ready result requires exactly one ACTIVE and one STANDBY,
clean PNOTEs and interfaces on both, the requested owners when supplied, and an
an exact interface baseline match when a two-member baseline is supplied. The
baseline covers every monitored and non-monitored interface name, its markers
and monitoring role, the declared counts, and every virtual interface name and
address. Current `UP` status is evaluated separately on each observation.

`icap_mode: required` needs explicit ICAP health on both members. Missing or
skipped evidence never passes required mode. Optional and disabled modes do not
make ICAP a readiness gate.

The module fails an unhealthy task by default. Set `fail_on_not_ready: false`
only to record a negative sample when another layer will enforce the gate.

```yaml
- name: Require the expected cluster shape
  sgt_trojan.checkpoint_automation.cp_automation_readiness_decide:
    members:
      - "{{ member_a_observation.observation }}"
      - "{{ member_b_observation.observation }}"
    icap_mode: required
    expected_active: Member-A
    expected_standby: Member-B
    baseline_members: "{{ checkpoint_initial_member_observations }}"
```

Both modules support check mode and always report `changed: false`.

## Acquisition boundary

`checkpoint_readiness_acquisition` binds the observation address directly to
`ansible_host`; it does not accept a separate member-address variable. It
requires TLS-verified `ansible.netcommon.httpapi` with
`ansible_network_os: check_point.gaia.checkpoint`, then passes the acquired
sections to the parser without exposing them in normal task output.

The package-state executor's lab-only TLS exception does not apply to this
readiness role.

The role requires `ansible_host` to be an IPv4 or IPv6 address literal;
hostnames are rejected before the operation is submitted.

The fixed operation uses the Gaia `run-script` endpoint through the vendor
HTTPAPI `send_request` helper. It is not a native ClusterXL facts endpoint.
Gaia reports this capability as `expert_api_runScript`; the API user's role
must grant `expert_api_runscript` for `run-script` and `expert_api_misc` for
`show-task`, and `expert_api_features` for `show-features`. See Check Point's
[role feature list](https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_Gaia_AdminGuide/Content/Topics-GAG/Roles-Available-Features.htm).

The payload cannot be overridden. It follows Check Point's
[shell-script guidance](https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_Gaia_AdminGuide/Content/Topics-GAG/Running-Check-Point-Commands-in-Shell-Scripts.htm)
by loading `/etc/profile.d/CP.sh` before Check Point commands. It accepts either
`ss` or `netstat` for fixed listener evidence. It gathers ClusterXL state,
ClusterXL interfaces, CICAP watchdog rows, TCP listeners, and PID/argument
process rows.

The module polls only the task identity returned by the operation. It requires
a UUID-shaped identity, one `/run-script` task, known task states, HTTP and task
status 200, progress 100, return value zero, canonical base64 UTF-8 within the
configured bound, and five ordered non-empty sections with zero command return
codes. Once Gaia returns a task identity, every later failure preserves it. If
the initial response is lost, a remote task might exist without a known UUID.
Reconcile a timed-out task before retrying because a retry starts a new fixed
read-only task; it does not resume or cancel the earlier task. The module
reports `changed: false` and performs the same acquisition in check mode.

This fixed environment is for non-VSX cluster members. VSX context selection is
not implemented and must fail a future platform gate before this role can run.

This milestone is offline-tested only. Do not target a Gaia host until the
separate constrained live executor and its safety gates are complete.
