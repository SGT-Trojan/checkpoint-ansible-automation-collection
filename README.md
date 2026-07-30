# Check Point Automation Collection

This companion collection provides reusable Ansible modules and roles for
guarded Check Point firewall maintenance. It separates the firewall workflow
from any ticketing or change-management platform.

The collection will cover:

- target discovery across an MDS and its domains;
- readiness and package validation;
- rolling JHF installation and removal;
- major version upgrades;
- Deployment Agent maintenance;
- CDT and Management API deployment backends;
- controlled failover and ownership restoration;
- policy and MVC handling;
- recovery from a saved phase; and
- final health checks and evidence capture.

Supported upstream modules from `check_point.mgmt.cp_mgmt_*` and
`check_point.gaia.cp_gaia_*` are used directly. Custom modules cover the
remaining behavior. The workflow does not call helper scripts through
`ansible.builtin.command` or `ansible.builtin.shell`.

## Status

The collection is under active development. Do not use it on a production
firewall until the live parity matrix is complete.

## Requirements

- Python 3.10 or later
- Ansible Core 2.16 through 2.21
- `check_point.mgmt` 6.9.x
- `check_point.gaia` 7.x

Install collection dependencies:

```bash
ansible-galaxy collection install -r requirements.yml
```

Build the collection:

```bash
ansible-galaxy collection build .
```

## Design

See [Managed target discovery](docs/MANAGED_TARGET_DISCOVERY.md),
[Cluster readiness](docs/CLUSTER_READINESS.md),
[Offline package validation](docs/PACKAGE_VALIDATION.md),
[Package observation boundary](docs/PACKAGE_ACQUISITION.md),
[Constrained live read-only executor](docs/LIVE_READONLY_EXECUTOR.md),
[Architecture](docs/ARCHITECTURE.md),
[Vendor module reuse](docs/UPSTREAM_MODULES.md), and
[Workflow parity](docs/PARITY_MATRIX.md).

## License

Documentation, tests, roles, and repository tooling are licensed under Apache
License 2.0. Ansible module and module utility files are licensed under GPL-3.0
or later, as marked in those files and required by Ansible's module runtime.
See [LICENSE](LICENSE) and [LICENSES/GPL-3.0-or-later.txt](LICENSES/GPL-3.0-or-later.txt).
