# Vendor Module Reuse

The collection uses released Check Point modules directly when they meet the
workflow contract. The first certified dependency set is:

- `check_point.mgmt` 6.9.0;
- `check_point.gaia` 7.0.0; and
- Ansible Core 2.16, followed by compatibility testing through 2.21.

Collection metadata permits later compatible releases within the same major
version, but live certification always records exact versions.

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
| Gaia reboot | `cp_gaia_run_reboot`, `cp_gaia_task_facts` | Check-mode block, timeout, reconnect, and health samples |
| Gaia file creation | `cp_gaia_put_file` | Text only; large package staging remains custom |

Package transport remains pending. Before transport is introduced,
`cp_automation_package_validate` provides the offline, structured contract for
exact package identity, SHA-256, action semantics, declared target
prerequisites, and major-upgrade restore capacity. It does not replace vendor
repository, verification, or install modules and does not perform acquisition.
The pinned-source acquisition audit also found that
`cp_mgmt_show_software_packages_per_targets` does not expose a pagination or
completeness contract, while the available Gaia diagnostics, asset, and
scheduled-snapshot facts do not document current restore-point free capacity.
The collection therefore does not mark either target observation complete.
Only controller-local artifact metadata is currently acquired, through the
no-follow `cp_automation_artifact_observe` gap module.

Deprecated `checkpoint_*` modules are prohibited. `cp_mgmt_show_task` is also
prohibited; use `cp_mgmt_task_facts`.

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

The readiness acquisition exception is narrower than
`cp_gaia_run_script`: `cp_automation_readiness_acquire` has no caller-supplied
script, command, path, arguments, or environment. It sends one fixed internal
operation through the Gaia `run-script` endpoint using the supported HTTPAPI
helper, requires the `expert_api_runScript` feature record and the
`expert_api_runscript`, `expert_api_misc`, and `expert_api_features` Gaia role
permissions, validates the exact asynchronous task and section envelope, and
returns `changed: false`. This is an endpoint reuse, not a native ClusterXL
facts API.
