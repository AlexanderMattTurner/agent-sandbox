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

- Persistent sessions (issue #33): `ephemeral: false` is now a real lifecycle.
  - `session_id` Workload field: a stable identity making the compose project
    name the deterministic `agent-sandbox-<session_id>` (mutually exclusive with
    the low-level `AGENT_SANDBOX_PROJECT_NAME` override). Running the same
    `session_id` against its stopped stack **re-attaches** — same volumes,
    seeding skipped, this leg's commits extracted onto the same review branch; a
    still-running session is refused. A stale seed (the checkout moved since)
    warns and continues; the new `run --reseed` flag is the loud, destructive
    opt-in to discard and re-seed.
  - `resume_from` Workload field: seed a FRESH session reproducing where a prior
    session left off — the workspace is seeded from the prior session's recorded
    base commit, its review branch's commits are replayed on top (an
    uncommitted-changes fold is soft-reset back into an uncommitted overlay), and
    the new work extracts onto a new review branch.
  - Audit continuity: before teardown the launcher now exports the audit sink's
    chained `audit.jsonl` and per-session HMAC `audit.secret` (owner-only) beside
    the egress log; on resume the prior log is mounted read-only at
    `/var/log/agent-sandbox/audit.prior.jsonl` in the new audit container, so the
    prior chain stays verifiable while the new session mints a fresh secret.
  - Seed-mode sessions record a session manifest
    (`sessions/<project>/session.json`, owner-only) carrying identity and seed
    provenance (base commit, extract base, review branch, repo root, outcome).
- `seed_from_git.ref` now accepts any commit-ish (branch, tag, sha), seeding that
  ref's committed tree (no WIP capture); `HEAD` keeps its tracked-tree +
  uncommitted-delta behavior. An unresolvable ref refuses the launch.
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
