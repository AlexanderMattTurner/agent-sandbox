# Provenance

`agent-sandbox` is the isolation substrate extracted from
[`claude-guard`](https://github.com/alexandermattturner/claude-guard) — the same author.
This file records where each extracted file came from and the transform applied, so the
lineage is auditable even though git blame does not cross the repo boundary (a clean copy
was chosen over `git subtree` because the de-claude transform rewrites identifiers
throughout, invalidating line-level blame anyway).

## De-claude transform (applied uniformly on copy)

- Identifiers: `CLAUDE_GUARD_*` env vars → `AGENT_SANDBOX_*`; `cg_*` shell functions
  (`cg_error`, `cg_info`, `cg_ok`, `cg_trace`, …) → `as_*`.
- Paths: `~/.config/claude-guard/*` → `~/.config/agent-sandbox/*`;
  `.worktrees/claude-*` → `.worktrees/sandbox-*`; `.git/claude-seed-*` → `.git/sandbox-seed-*`;
  git author `agent@claude-guard.local` → `agent@agent-sandbox.local`.
- Claude/inference-specific blocks are stripped (they become the claude-guard _adapter_),
  never silently simplified. The security enforcement core (proxy allowlist, seccomp,
  egress rules, DNS pinning) is copied **byte-for-byte** apart from those identifier renames.

## File origins

| agent-sandbox path                                                                           | claude-guard origin                               | transform                                                                                |
| -------------------------------------------------------------------------------------------- | ------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `schema/workload.schema.json`                                                                | (new) the Workload contract                       | authored                                                                                 |
| `workloads/demo-bash.json`                                                                   | (new) non-claude demo workload                    | authored                                                                                 |
| `bin/agent-sandbox`                                                                          | generic slice of `bin/claude-guard` orchestration | new code reproducing the fail-closed gate sequence                                       |
| `bin/lib/backend.bash`                                                                       | (new) runtime backend seam                        | authored                                                                                 |
| `bin/lib/runtime-detect.bash`                                                                | `bin/lib/runtime-detect.bash`                     | de-claude                                                                                |
| `bin/lib/sandbox-runtime.bash`                                                               | `bin/lib/sandbox-runtime.bash`                    | de-claude                                                                                |
| `bin/lib/sandbox-net.bash`                                                                   | `bin/lib/sandbox-net.bash`                        | de-claude                                                                                |
| `bin/lib/overmounts.bash`                                                                    | `bin/lib/overmounts.bash`                         | de-claude + workload-driven protected paths                                              |
| `bin/lib/ephemeral.bash`                                                                     | `bin/lib/ephemeral.bash`                          | de-claude                                                                                |
| `bin/lib/worktree-seed.bash`                                                                 | `bin/lib/worktree-seed.bash`                      | de-claude                                                                                |
| `bin/lib/{flock,docker-labels,msg,session-name,json}.bash`                                   | same paths in `bin/lib/`                          | de-claude (transitive helpers)                                                           |
| `sandbox/init-firewall.bash`                                                                 | `.devcontainer/init-firewall.bash`                | de-claude; inference/monitor blocks stripped; DNS+squid+ipset core byte-for-byte         |
| `sandbox/{firewall-lib,ip-validation,dns-resolver,squid-config,egress-rules,conntrack}.bash` | `.devcontainer/` same names                       | de-claude; enforcement core byte-for-byte                                                |
| `sandbox/{trace,trace-events,launch-trace,launch-marks}.bash`                                | `.devcontainer/` + `bin/lib/`                     | de-claude                                                                                |
| `sandbox/entrypoint.bash`                                                                    | `.devcontainer/entrypoint.bash`                   | generic hardening only; claude blocks stripped                                           |
| `sandbox/{seccomp-default,seccomp-firewall}.json`                                            | `.devcontainer/` same names                       | **byte-for-byte**                                                                        |
| `sandbox/domain-allowlist.json`                                                              | `.devcontainer/domain-allowlist.json`             | generic infra domains; `inference_providers` removed                                     |
| `sandbox/Dockerfile`                                                                         | `.devcontainer/Dockerfile`                        | firewall/workload image; claude install layers removed                                   |
| `sandbox/docker-compose.yml`                                                                 | `.devcontainer/docker-compose.yml`                | firewall + hardener + workload; monitor/audit/ccr dropped                                |
| `config/trace-events.json`                                                                   | `config/trace-events.json`                        | library-owned subset (runtime/net/firewall/seed layers) — SSOT that claude-guard imports |
| `config/session-volume-roles.json`                                                           | `config/session-volume-roles.json`                | copy                                                                                     |
