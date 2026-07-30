# Project Status

The collection is under active development. The current milestone adds
read-only package and Deployment Agent observation, package binding, and a
complete offline Deployment Agent planning and evidence chain. It does not yet
perform a firewall update or upgrade.

## Available

- MDS domain discovery with explicit pagination and bounded concurrency
- Exact two-member cluster resolution
- Readiness observation and decision modules
- Controller-local package size and SHA-256 observation
- Inventory-bound CPUSE package-state acquisition and normalization
- Package identity, prerequisite, action, and checksum validation
- Lease-bound read-only Deployment Agent observation
- Deployment Agent package binding and deterministic update planning
- Exact-build reconciliation, reacquisition planning, and member sequencing
- Evidence composition and final two-member completion attestation
- Fail-closed lease, commit, plan, artifact, member, and TLS execution preflight
- Preflight-gated controller-local content-addressed artifact staging
- Synthetic completion and tamper-rejection integration tests
- CI checks for supported vendor contracts and prohibited execution paths

The package-state and Deployment Agent observation paths have completed
read-only runs against the two-member lab cluster using the documented lab TLS
exception. Strict certificate validation remains pending.

## Not Yet Available

- Deployment Agent package transport to a firewall or fixed update transport
- CDT candidate generation or execution
- Management API package installation or upgrade
- Direct CPUSE fallback
- Reboot and bounded reconnection handling
- Cluster failover or original-owner restoration
- Mixed-version policy and MVC handling
- Durable resume-state orchestration
- Final support capture and live evidence manifests

The missing operations remain disabled. The collection does not substitute
shell, command, raw, or script tasks for unsupported vendor APIs.

## Current Boundary

The Deployment Agent chain now includes controller-local artifact staging
behind the execution preflight. Staging revalidates the source on a retained
descriptor, repeats lease expiry checks around its bounded filesystem
mutation, and publishes a read-only content-addressed copy. It performs no
firewall request. A returned plan, preflight authorization, or staged path does
not perform or independently authorize a live update. Future execution still
requires separately reviewed firewall transport, repeated lease checks,
bounded polling, and post-update build verification.

See [Deployment Agent](docs/DEPLOYMENT_AGENT.md) for the module contracts,
[Workflow parity](docs/PARITY_MATRIX.md) for full scope, and
[Package observation boundary](docs/PACKAGE_ACQUISITION.md) for package-state
limits.

## Next Milestone

Add the reviewed lease-bound Deployment Agent executor, then prove no-change
idempotence and an older-to-current update in the lab before beginning CDT
execution work.
