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
