# Project Status

The collection is under active development. The current milestone covers
discovery, readiness checks, package-plan validation, and local package
observation. It does not yet perform a firewall update or upgrade.

## Available

- MDS domain discovery with explicit pagination and bounded concurrency
- Exact two-member cluster resolution
- Readiness observation and decision modules
- Offline package-plan validation
- Local package size and SHA-256 observation
- A constrained read-only discovery playbook
- CI checks for supported vendor-module contracts and prohibited execution
  paths

## Not Yet Available

- Complete installed-package inventory and restore-point capacity acquisition
- Package staging, installation, removal, or major-version upgrades
- Deployment Agent and CDT execution
- Cluster failover or ownership restoration
- Mixed-version policy and MVC handling
- Resume-state orchestration and final evidence capture

The missing items remain disabled. The collection does not substitute shell,
command, raw, or script tasks for unsupported vendor APIs.

## Current Boundary

The pinned `check_point.mgmt` package query does not provide a documented
completeness signal for installed target packages. The pinned Gaia modules do
not expose current restore-point capacity. The collection therefore does not
claim either observation is complete and does not authorize package execution.

See [Workflow parity](docs/PARITY_MATRIX.md) for the detailed coverage matrix
and [Package observation boundary](docs/PACKAGE_ACQUISITION.md) for the current
acquisition limits.

## Next Milestone

Add a supported, bounded way to acquire complete target package inventory and
restore-point capacity. Any live test will remain read-only until that data can
be collected and validated without an execution escape hatch.
