# Vendor Module Reuse

The collection uses released Check Point modules directly when they meet the
workflow contract. The first certified dependency set is:

- `check_point.mgmt` 6.9.0;
- `check_point.gaia` 7.0.0; and
- Ansible Core 2.16, followed by compatibility testing through 2.21.

Collection metadata permits later compatible releases within the same major
version, but live certification always records exact versions.
`ansible.netcommon` 8.x supplies the HTTPAPI connection plugin used by the
Gaia inventory examples; it is an explicit dependency because it is not part
of `ansible-core` and Check Point Gaia 7.0.0 does not declare it. The install
requirements also pin its resolved `ansible.utils` dependency to 6.0.3 so the
verified dependency graph can be reproduced exactly.

## Reuse Map

| Capability | Vendor modules | Local responsibility |
|---|---|---|
| MDS domains | `cp_mgmt_domain_facts` | Complete pagination, active CMA selection, CLM exclusion, and cross-domain resolution |
| Gateways and clusters | `cp_mgmt_show_gateways_and_servers`, `cp_mgmt_simple_cluster_facts`, `cp_mgmt_cluster_members_facts` | Exact identity, ambiguity rejection, and two-member scope |
| SIC | `cp_mgmt_test_sic_status` | Required-state verdict |
| Platform and version | `cp_mgmt_get_platform`, `cp_gaia_version_facts` | Expected-version verdict and reconciliation |
| Interfaces | `cp_mgmt_get_interfaces`, `cp_gaia_physical_interfaces_facts` | Required-interface and topology verdict |
| Diagnostics | `cp_gaia_diagnostics_facts`, `cp_gaia_asset_facts` | CPUSE, storage, and rollback-capacity gates |
| Repository import | `cp_mgmt_add_repository_package` | Global-domain context, exact identity, and idempotence guard |
| Repository inventory | `cp_mgmt_repository_package_facts` | Pagination and exact package matching |
| Target packages | `cp_mgmt_show_software_packages_per_targets` | Package identity and final-state verdict |
| Package verification | `cp_mgmt_verify_software_package` | Correct read-only change reporting and task reconciliation |
| API install or upgrade | `cp_mgmt_install_software_package` | Prechecks, strategy guard, polling, sequencing, and recovery |
| API uninstall | `cp_mgmt_uninstall_software_package` | Not used for the certified per-member removal path until safe semantics are proven |
| Management tasks | `cp_mgmt_task_facts` | Nested task-envelope handling and bounded polling |
| Policy | `cp_mgmt_verify_policy`, `cp_mgmt_install_policy` | Mixed-version and final-policy acceptance rules |
| Gaia capabilities | `cp_gaia_api_versions_facts`, `cp_gaia_features_facts` | Availability gate before Gaia API use |
| ClusterXL readiness acquisition | `cp_gaia_features_facts`, Gaia HTTPAPI `send_request` helper | Role-feature gate, typed fixed `run-script` payload, bounded task polling, and strict evidence validation |
| Installed packages and restore capacity | `cp_gaia_features_facts`, Gaia HTTPAPI `send_request` helper | `checkpoint_package_state_acquisition` inventory binding, fixed `cp_automation_package_state_acquire` operation, and strict recognized-format/capacity parsing |
| Deployment Agent | Gaia HTTPAPI `send_request` helper; no dedicated resource module in the pinned collections | Inventory-bound `checkpoint_deployment_agent_observation`, fixed `cp_automation_deployment_agent_acquire`, numeric build decision, offline package binding, update, reconnect, and reconciliation |
| Gaia reboot | `cp_gaia_run_reboot`, `cp_gaia_task_facts` | Check-mode block, timeout, reconnect, and health samples |
| Gaia file creation | `cp_gaia_put_file` | Text only; not used for binary Deployment Agent packages |

Package transport remains pending. Before transport is introduced,
`cp_automation_package_validate` provides the offline, structured contract for
exact package identity, SHA-256, action semantics, declared target
prerequisites, and major-upgrade restore capacity. It does not replace vendor
repository, verification, or install modules and does not perform acquisition.
The pinned-source acquisition audit also found that
`cp_mgmt_show_software_packages_per_targets` does not expose a pagination or
completeness contract, while the available Gaia diagnostics, asset, and
scheduled-snapshot facts do not document current restore-point free capacity.
The fixed `cp_automation_package_state_acquire` gap module addresses those two
missing target observations through the supported Gaia HTTPAPI helper. It may
mark installed inventory complete only after its exact command and strict
parser succeed. `checkpoint_package_state_acquisition` binds it to one exact
inventory host and produces validator-ready state. Its leased read-only executor
is not firewall-certified yet. Controller-local artifact
metadata remains separate in `cp_automation_artifact_observe`.

Deprecated `checkpoint_*` modules are prohibited. `cp_mgmt_show_task` is also
prohibited; use `cp_mgmt_task_facts`.

The pinned Management and Gaia collections do not provide a dedicated
Deployment Agent status or update module. The local
`cp_automation_deployment_agent_observe` and
`cp_automation_deployment_agent_decide` modules therefore own status
normalization and the numeric build contract. Neither runs a command. Fixed
acquisition is provided by `cp_automation_deployment_agent_acquire`.
`checkpoint_deployment_agent_observation` binds that operation to a short
two-member lease and direct Gaia inventory. Offline package binding, update
planning, reacquisition planning, reconciliation, evidence, and completion
attestation are available. Live update execution remains pending.
Controller-local content-addressed artifact staging is available behind the
execution preflight. The released `cp_gaia_put_file` text-content contract is
not sufficient for this binary package, so firewall transport remains pending.

## Safety Limits

`cp_mgmt_show_gateways_and_servers` is a read-only command and the vendor
helper returns `changed: false`, but version 6.9.0 does not declare check-mode
support. The discovery role runs that one task with `check_mode: false` so
`ansible-playbook --check` still gathers facts. This exception does not permit
mutating command modules to bypass check mode.

Management command modules generally execute every time they are called, report
`changed: true`, and do not support check mode. Roles must compare current and
desired state first and must skip those calls during `ansible_check_mode`.

The released Gaia 7.0.0 operation helper does not reliably stop mutating
operations in check mode even though some modules advertise check-mode support.
Roles must hard-block `cp_gaia_run_reboot`, `cp_gaia_run_script`, and
`cp_gaia_put_file` during `--check`.

Gaia task polling has a fixed iteration limit. Package and upgrade workflows
need a custom bounded poller with a caller-selected timeout and no automatic
replay of the mutation.

`cp_gaia_run_script` and `cp_mgmt_run_script` are not substitutes for domain
modules. The collection will not use generic script execution to hide CDT,
CPUSE, MVC, ClusterXL, or package-staging behavior.

The readiness and package-state acquisition exceptions are narrower than
`cp_gaia_run_script`: `cp_automation_readiness_acquire`,
`cp_automation_package_state_acquire`, and
`cp_automation_deployment_agent_acquire` have no caller-supplied script, command,
path, arguments, or environment. Each sends one fixed internal operation
through the Gaia `run-script` endpoint using the supported HTTPAPI helper,
validates the exact asynchronous task and section envelope, and returns
`changed: false`.

These modules reuse the same Gaia `run-script` endpoint helper without exposing
the generic `cp_gaia_run_script` module or accepting caller-supplied script
content. The fixed operation and strict response parser are the read-only
boundary.

A calling role must first verify the `expert_api_runScript` feature record and
bind the expected member address to its HTTPAPI inventory host. The API role
needs `expert_api_runscript`, `expert_api_misc`, and `expert_api_features`.
The readiness and package-state roles both enforce these controls. These are
endpoint reuse contracts, not native readiness or CPUSE facts APIs.
