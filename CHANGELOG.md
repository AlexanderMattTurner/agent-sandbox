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

### Changed

- The library's structured trace events now have a single source of truth,
  `config/trace-events.json`, mirrored by `sandbox/trace-events.bash` and pinned
  equal to it (with an emitter check) by a contract test. The event set is trimmed
  to those the library actually emits (firewall, hardener, audit); consumer-only
  events belong in a consumer overlay, not the library.

### Added

- `secret_env` Workload field: credentials delivered as files at
  `/run/secrets/<name>` (mode 0400, owned by the workload user) instead of
  environment variables. Values are streamed over an exec's stdin into a
  per-container tmpfs after create, so they are invisible to `docker inspect`
  (no env, no argv, no mount source), never touch the host state dir or a
  compose file, and die with the container on teardown. Names must be
  env-var-shaped (`^[A-Za-z_][A-Za-z0-9_]*$`); values may contain newlines and
  arrive byte-exact. The consumer contract is file-based: the workload reads
  each value from its `/run/secrets` path.
- `tty` Workload field (default false): run the entrypoint under an interactive
  `docker exec -it`, refusing the launch fail-closed when the launcher's stdin is
  not a terminal.
- Workload `env` is now delivered via a 0600 env-file consumed only while the
  container is created, then unlinked — so secrets no longer persist in the
  on-disk session compose override (they remain visible on the live container via
  `docker inspect`). Values must be single-line; a newline is refused.
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
