# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to
adhere to [Semantic Versioning](https://semver.org/).

Add user-facing changes under `## Unreleased` as you make them. On each push to
the default branch, `auto-version.yaml` publishes to npm and promotes the
`## Unreleased` block into a new dated `## [version]` section below it (see
`.github/scripts/version-bump.sh`); when `## Unreleased` is empty, Claude drafts
the prose from the release's commits.

## Unreleased

### Added

- `agent-sandbox gc [--dry-run]` prunes stale sandbox networks with no live
  containers, reclaiming dead sessions' subnets; `--dry-run` previews the count
  a real run would remove.
- `agent-sandbox down <project>` tears down one session's stack by compose
  project name — containers, networks and volumes — failing loud on a missing
  project argument, on a project with nothing to tear down, and on any volume
  that survives the teardown.
- Two default library-owned compose services with generic contracts, opt-out via
  the Workload record (`hardener: false` / `audit: false`, compose profiles):
  - `hardener` — a transient root init service that executes every executable in
    the read-only `/run/hardener-hooks.d` mount (empty by default = no-op
    success) to write hardened config into a volume the workload mounts
    read-only at `/run/hardened-config`; any hook failure aborts the launch
    before the workload starts (`service_completed_successfully` gate).
  - `audit` — a tamper-evident append-only audit sink (`sandbox/audit_sink.py`):
    a per-session HMAC secret minted on its own volume chains every appended
    record, so edits, reordering, or interior drops are detectable; the workload
    mounts neither the log nor the secret.
