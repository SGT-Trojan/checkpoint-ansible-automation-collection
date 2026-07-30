# Offline Package Validation

`cp_automation_package_validate` is a transport-free decision module for the
package contract inherited from the original workflow. It does not inspect
files, run commands, query a Check Point endpoint, or perform an action.
ServiceNow remains an external orchestration boundary.

The caller supplies structured observations acquired by a separately reviewed
transport:

- package steps with exact action, package identity, prerequisites, and
  published SHA-256, plus a non-empty exact `target_ids` list;
- artifact observations with an absolute canonical path, positive byte size,
  and computed SHA-256; and
- target observations bound to an exact package-step name, with exact
  installed-package identities and optional restore-point capacity in bytes.

The controller-local artifact portion can now be produced by
`cp_automation_artifact_observe` through the localhost-pinned
`checkpoint_artifact_observation` role. The offline-tested
`checkpoint_package_state_acquisition` role binds
`cp_automation_package_state_acquire` to an exact Gaia inventory host and
produces validator-ready target inventory and restore-capacity fields. Its
leased read-only entry point is not firewall-certified yet. The boundary is
documented in
[Package Observation and Acquisition Boundary](PACKAGE_ACQUISITION.md).

Both target and artifact results are point-in-time observations, not
authorization to consume a future path. Any future mutating transport must
reobserve immediately before use and validate, hash, and consume from the same
retained descriptor, or create and consume an immutable/content-addressed
staged copy in one bounded operation.

## Fail-closed contract

- Actions are exactly `install`, `upgrade`, or `remove`.
- Package types are limited to `jhf`, `hotfix`, `deployment_agent`, `wrapper`,
  `blink`, `blink_image`, and `major_upgrade`. Any case-insensitive `blink`
  substring in the package filename or source path cannot be relabelled as a
  non-major type. False-positive rejection is intentional fail-closed
  behavior; this is a rejection rule, not fuzzy type inference.
- Install and upgrade require a package filename matching the basename of one
  exact source path. SHA-256 is mandatory and must match exactly one artifact
  observation; SHA-1 alone is not accepted for new collection workflows.
- Every supplied artifact must belong to exactly one install or upgrade step.
  Missing, duplicate, or unused artifacts are rejected.
- Remove requires an explicit package identity different from the workflow
  step name and must not declare a source artifact or checksum.
- Required-present and required-absent identifiers are exact, case-sensitive,
  unique, and disjoint. Every target observation for that step must satisfy
  them; observations cannot drift between steps or reference an unknown step.
- Every action, including an action with no declared package prerequisite,
  requires observations for exactly its declared target IDs. Missing, extra,
  duplicate, and cross-step target observations fail closed.
- Every target observation must set the literal boolean
  `installed_packages_complete: true` before required-absent checks can run.
  Only a separately reviewed acquisition that proves a complete installed
  package inventory may set this flag; partial or best-effort inventory must
  leave it false and therefore cannot authorize validation.
- Blink/major-upgrade actions require a positive minimum restore-point byte
  count and a complete capacity observation meeting it on every target.
- Unknown fields, fuzzy aliases, inferred package names, free-form commands,
  and incomplete observations fail closed.

The result is `changed: false` and contains only the normalized contract and
counts. The separate package-state lease authorizes observation only. Artifact
consumption and every mutation control remain separate future milestones.
Independent review and a short-lived local lease are required before each live
observation.
