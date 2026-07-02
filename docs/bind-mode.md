# Bind mode: the contract

What `workspace_mount` does and — more importantly — does **not** protect. This is
the prose companion to the `workspace_mount` / `overmount_paths` field descriptions
in [`schema/workload.schema.json`](../schema/workload.schema.json); authoring basics
live in [`docs/usage.md`](usage.md).

## What bind mode is

Setting `workspace_mount` binds a host directory **read-write** at the container's
`/workspace`. The workload operates directly on that host directory: every write it
makes lands on the host **immediately and permanently**, while the session is still
running.

```json
{
  "image": "buildpack-deps:stable-scm",
  "entrypoint": ["bash", "-lc", "make build"],
  "workspace_mount": "/home/you/checkout",
  "egress_allowlist": [],
  "ephemeral": true
}
```

## What bind mode does NOT protect

- **There is no review-branch quarantine.** Seed mode extracts the workload's
  commits onto a `review_branch` for you to inspect before anything touches your
  tree; bind mode has no such gate. A destructive or malicious write is on your
  host the moment it happens — teardown does not undo it.
- **Everything under the bind is writable by default.** The read-only
  `overmount_paths` binds (default `.git/hooks`, `node_modules`) are the **only**
  kernel-enforced guard; every other path under `workspace_mount` is fair game for
  the workload.
- **The rest of the sandbox posture still applies** (deny-all egress, runtime
  isolation, ephemeral volumes) — but none of it constrains what the workload
  writes into the bound directory.

If you want the workload's changes gated behind review, use seed mode
(`seed_from_git`) instead.

## The overmount guarantee

Each `overmount_paths` entry that exists under the host workspace is re-mounted
**read-only on top of** the base bind. A read-only bind is kernel-enforced: even
in-container root cannot write through it. Before handing the sandbox over, the
launcher **proves** each applicable overmount is unwritable for the workload user
(a batched in-container write probe); a writable or unverifiable guardrail refuses
the launch and tears the stack down — with no extract quarantine behind it, an
unproven guardrail is an unguarded host checkout.

Why `.git/hooks` is in the default set: in bind mode a compromised workload could
plant `/workspace/.git/hooks/pre-commit`, which then runs **on the host** the next
time you invoke git in that checkout — a breakout that outlives the session and,
living in `.git`, never shows in `git diff`. `node_modules` locks the tooling the
workload imports. (Full rationale: the header of
[`bin/lib/overmounts.bash`](../bin/lib/overmounts.bash).)

## Missing-path policy

A declared path that does not exist under the host workspace gets **no** bind at
all, so nothing would guard it. The launcher resolves this by who declared it:

- **Explicit `overmount_paths` entry missing** → the launch is **refused** (and the
  stack torn down). An explicit declaration is you stating a security requirement;
  silently skipping it would launch with less protection than you asked for.
- **Default-set path missing** (no `overmount_paths` field) → a **warning** per
  missing path, and the launch proceeds — most checkouts legitimately ship without
  `node_modules`.
- **No overmount applies at all** (explicit `[]`, or nothing exists) → the launch
  proceeds and prints a marker stating that nothing under `/workspace` is mounted
  read-only, so the absence of protection is never silent.

## Seed vs. bind: mutually exclusive

A record carrying both `workspace_mount` and `seed_from_git` has no coherent write
path (direct host writes vs. review-branch quarantine), so the schema **and** the
launcher reject it — pick one mode per record.

## Hostile-path refusals

`agent-sandbox run` validates the bind source before anything comes up. Refused,
each with a loud error:

| Source                                       | Why                                                                                                 |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Relative path                                | compose resolves a relative bind against the compose _file's_ directory, not your working directory |
| Symlink (dangling included)                  | the bind would mount the target, so the record's path and the mounted path diverge                  |
| Missing path, or not a directory             | Docker would fabricate a root-owned directory at that host path                                     |
| Resolves to or under the library's state dir | the workload could rewrite session artifacts (the egress log copy, WIP patches)                     |

A literal `$` in the path is fine: the launcher compose-escapes it (`$$`) so
compose's interpolation pass leaves it verbatim.
