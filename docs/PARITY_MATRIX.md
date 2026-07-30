# Workflow Parity Matrix

This matrix tracks behavior from the established Check Point automation
workflow as it moves into this collection.

| Capability | Upstream module | Custom content | Offline tests | Live test |
|---|---|---|---|---|
| MDS, domain, cluster, member, and policy resolution | Vendor facts modules provide source records | `cp_automation_target_resolve` | 24 passing | Pending |
| Management API pagination completeness | Vendor modules expose `limit` and `offset` | `cp_automation_pages_merge` | 13 passing | Pending |
| Constrained live managed-discovery executor | Existing read-only vendor facts only | `cp_automation_live_preflight`, lease and inventory-bound role | Offline hostile gates passing | Pending |
| Cluster and gateway readiness | Gaia HTTPAPI helper with fixed `run-script` operation | `cp_automation_readiness_acquire`, `cp_automation_cluster_observe`, `cp_automation_readiness_decide` | 50 passing | Pending |
| Package identity, checksum, action, and prerequisites | Pinned vendor facts remain insufficient; fixed Gaia HTTPAPI helper reused | `cp_automation_artifact_observe`, `checkpoint_package_state_acquisition`, `cp_automation_package_state_live_preflight`, `cp_automation_package_state_acquire`, and `cp_automation_package_validate` | Hostile artifact, acquisition, inventory-binding, and contract fixtures passing | Package-state acquisition passed on two lab members in check mode with `lab_unverified`; strict TLS and end-to-end validation pending |
| Deployment Agent readiness and update | Gaia HTTPAPI helper reused; no dedicated module in the pinned Management or Gaia collections | `checkpoint_deployment_agent_observation`, `checkpoint_deployment_agent_package_binding`, `cp_automation_deployment_agent_live_preflight`, `cp_automation_deployment_agent_acquire`, `cp_automation_deployment_agent_observe`, `cp_automation_deployment_agent_decide`, and `cp_automation_deployment_agent_package_bind`; update remains pending | Lease, inventory binding, fixed acquisition, graph, parser, numeric decision, package binding, and offline composition fixtures passing | Two-member read-only observation passed with the lab TLS exception; strict TLS and update pending |
| CDT candidate generation and guarded execution | None expected | Required | Pending | Pending |
| Management API package workflow | `check_point.mgmt.cp_mgmt_*` | Safety and reconciliation gates | Pending | Pending |
| Direct CPUSE fallback | Under review | Required | Pending | Pending |
| Failover and original-owner restoration | Under review | Required | Pending | Pending |
| Major-upgrade policy and MVC | Under review | Required | Pending | Pending |
| Support capture, diff, and final postcheck | Under review | Required | Pending | Pending |
| Phase recovery and idempotent resume | None | Roles and state contract | Pending | Pending |

The target resolver is deliberately transport-free. Calling roles must provide
complete paginated domain and gateway facts plus full detail for every relevant
cluster. The module rejects partial data, duplicate domains, ambiguous matches,
missing member identity, and clusters outside the certified two-member scope.

## Inherited Live Workflows

The collection must reproduce these previously tested transitions:

| Workflow | Starting state | Expected state |
|---|---|---|
| CDT JHF install | R81.20 build 634 with no separately installed JHF | Take 76 on both members |
| CDT JHF removal | R81.20 Take 76 | No separately installed JHF |
| CDT major upgrade | R81.20 build 634 with no separately installed JHF | R82 build 777 with embedded Take 60 |
| CDT current JHF | R82 build 777 Take 60 | Take 107 on both members |
| Management API JHF install | R81.20 build 634 with no separately installed JHF | Take 76 on both members |
| API workflow uninstall | R81.20 Take 76 | No separately installed JHF through the guarded direct fallback |
| Management API major upgrade | R81.20 build 634 with no separately installed JHF | R82 build 777 with embedded Take 60 |
| Deployment Agent no-change | Build 2771 on both members | Unchanged and idempotent |
| Deployment Agent recovery | Older build 2672 on one rebuilt member | Build 2771 and successful upgrade continuation |

A separately installed JHF is different from the fixes embedded in the base
image. The matrix never uses the product-like shorthand "Take 0".

## Safety Contract

Every mutating workflow must:

1. Resolve one two-member cluster and capture distinct active and standby
   identities.
2. Select the standby member from captured state, never list position.
3. Require a package SHA-1 or SHA-256 and verify it before and after staging.
4. Resolve one exact package identity and reject missing, ambiguous, or
   inconsistent results.
5. Require one enabled CDT candidate whose cluster, member name, and address
   match the approved plan.
6. Check SIC, licensing, Deployment Agent, CPUSE, PNOTEs, interfaces, policy,
   ICAP mode, storage, and rollback capacity.
7. Require an explicit mutation control in addition to normal Ansible
   execution.
8. Detect real reboots, reconnect within a bound, collect repeated health
   samples, and verify the exact final version and Take.
9. Pause after first-member failover and require explicit tester approval
   before changing member two.
10. Reject unknown resume phases, stopped execution, and zero-phase runs as
    incomplete.
11. Restore original ownership and verify final Access Control and Threat
    Prevention policy state.

## Evidence Contract

Each live run must retain:

- the sanitized activity plan and resolved topology;
- initial active and standby state and intended member order;
- package source, size, and hashes;
- CDT candidates or Management API repository and task identity;
- structured per-phase module results with target identity and timestamps;
- reboot and health samples;
- tester pause, approval, and continuation records;
- failure phase, remediation decision, and resumed phase;
- baseline and final support captures and their comparison;
- final policy, MVC, ICAP, package, version, Take, and ownership checks; and
- a final summary with a SHA-256 manifest.

Evidence directories use mode `0700` and files use mode `0600`. Evidence
validation rejects credentials, API or session tokens, and private topology.

## Failure Tests

The acceptance suite must reproduce:

1. a changed SSH host key after upgrade without blindly trusting the new key;
2. an API task failure after a member actually rebooted successfully, followed
   by exact image and completed-member reconciliation;
3. MDS package conversion or root-cache capacity exhaustion;
4. empty, malformed, or API-error policy responses;
5. ambiguous package aliases and wrong CDT candidate identity;
6. missing captured cluster state;
7. transient no-JSON responses while polling an existing task, without
   repeating the mutation;
8. invalid resume phases, operator stops, and zero-phase execution;
9. tester results other than explicit approval; and
10. a skipped or unavailable required ICAP check.

## Acceptance Program

1. Run the complete Ansible sanity suite, unit tests, check-mode tests, and
   hostile fixtures for every custom module.
2. Prove playbooks use modules and roles, with no helper execution through
   `command`, `shell`, `script`, `raw`, or subprocess wrappers.
3. Prove repeated discovery and completed-state runs return `changed: false`.
4. Run the complete read-only resolver and readiness suite.
5. Execute CDT Take 76 install, removal, and R81.20-to-R82 upgrade cycles.
6. Execute the CDT R82 Take 60-to-107 cycle.
7. Execute Management API Take 76 install, guarded uninstall fallback, and
   major upgrade cycles.
8. Execute Deployment Agent idempotence and one real older-to-current update
   when a valid baseline is available.
9. Inject every failure case and prove exact-phase continuation without
   repeating completed member work.
10. Finish every cycle with policy, ICAP, package, version, ClusterXL,
    interface, ownership, and evidence-manifest validation.

Standalone gateways, clusters with more than two members, unlisted releases,
API-only rolling uninstall, and arbitrary historical JHFs remain outside the
inherited certification boundary.

No capability is complete until its contract, negative tests, and required live
cycle have passed.
