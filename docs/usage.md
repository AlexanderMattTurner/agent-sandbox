# Usage

How to author a Workload record and run it through `agent-sandbox`. The Workload
contract is defined in [`schema/workload.schema.json`](../schema/workload.schema.json);
this document is the prose companion to it. Security posture (the topology
invariant, the deny-all boundary, the tamper-evident egress log) is stated at its
source — the header comment of [`sandbox/docker-compose.yml`](../sandbox/docker-compose.yml)
and the field descriptions in the schema — and is only summarized here.

---

## A. Authoring a Workload

A Workload is a single JSON object handed to `agent-sandbox run`. It carries
everything the launcher needs and **no** workload-specific bootstrap: the image
brings its own command. Required fields: `image`, `entrypoint`, `egress_allowlist`,
`ephemeral`. Everything else has a schema default.

A minimal record:

```json
{
  "image": "buildpack-deps:stable-scm",
  "entrypoint": [
    "bash",
    "-lc",
    "echo hello; curl -fsS https://pypi.org/simple/ >/dev/null"
  ],
  "egress_allowlist": ["pypi.org", "files.pythonhosted.org"],
  "ephemeral": true
}
```

### `image` (required, string)

The container image the workload payload runs in (e.g. an agent image). This is
distinct from the firewall image, which the library owns and builds itself.

### `entrypoint` (required, array of strings, non-empty)

The argv the sandbox execs once the firewall is healthy. **No install/bootstrap
step belongs here** — the workload brings its own command. The launcher reads the
argv element-by-element, so an element may itself contain newlines (a multi-line
`bash -c` script is the common case).

### `env` (object, name → value)

A `name -> value` map exported into the workload container. Notes:

- **Values must be single-line.** The env-file is line-based; a value containing a
  newline is refused loudly.
- **Secrets are not persisted in the on-disk compose override.** `env` is delivered
  via a `0600` env-file that compose consumes only while the container is created,
  then the launcher unlinks it. It never lands in the session override on disk.
- **Residual visibility.** Once baked into the container, the values remain visible
  on the live container via `docker inspect` (compose-native secrets are tracked
  separately). Treat `env` as convenient config, not as a hardened secret store.

### `tty` (boolean, default `false`)

When `true`, allocate an interactive TTY for the entrypoint (`docker exec -it`) and
attach the launcher's stdin. This **requires a real terminal**: if the launcher's
stdin is not a TTY, the launch fails loudly (checked before anything comes up, so a
healthy stack is never torn down just to fail the attach). Default `false` is the
non-interactive case (CI).

### `user` (string, default `"1000"`)

The uid or name the workload runs as. Must be unprivileged: the workload container
drops **all** capabilities, runs read-only, and runs with `no-new-privileges`. The
seed/extract steps run as this same user so the review branch is authored correctly.

### `workspace_mount` (string)

**Absolute** host path bound read-write to the container's `/workspace` (**bind
mode**) — the workload's writes land directly on the host, with no review-branch
quarantine; see [`docs/bind-mode.md`](bind-mode.md) for exactly what is and isn't
protected. Mutually exclusive with `seed_from_git`: a record carrying both is
rejected by the schema and refused by the launcher (see
[Seed vs. bind](#seed-vs-bind) below). The launcher also refuses a relative,
missing, non-directory, or symlinked source, and one resolving inside the
library's own state dir.

### `overmount_paths` (array of strings, default `[".git/hooks", "node_modules"]`)

Workspace-relative paths mounted **read-only on top of** the `/workspace` bind, so
the workload can read but never write them. The read-only bind is kernel-enforced —
even in-container root cannot write it.

- **Bind-mode only.** In seed mode `/workspace` is a named volume and the workload's
  writes are already gated by the review-branch extract, so overmounts have no
  effect there.
- **The absent-vs-`[]` distinction matters.** _Absent_ = the schema default
  `[".git/hooks", "node_modules"]`. An explicit `[]` = **no** overmounts.
- Why the defaults: `.git/hooks` is a container→host code-execution guard (in bind
  mode the host checkout is mounted read-write; without this, a compromised workload
  could plant `/workspace/.git/hooks/pre-commit` that runs **on the host** the next
  time you invoke git there). `node_modules` locks the tooling the workload imports.

In bind mode the launcher **proves** the overmounts are truly read-only for the
workload user before handing over; an unverifiable or writable guardrail refuses the
launch. A declared path that doesn't exist under the host workspace gets no bind at
all: a missing **explicit** entry refuses the launch, a missing **default** path only
warns (see [`docs/bind-mode.md`](bind-mode.md) for the full policy).

### `egress_allowlist` (required, array)

The allowed destinations, as **hostnames — never IPs** (an IP entry is rejected;
enforcement is name-level at the forward proxy). The firewall boots **deny-all**; a
workload reaches only what it declares here. Two entry forms:

- A **bare string** grants full access (`rw`): all HTTP methods, TLS spliced
  end-to-end.

  ```json
  "egress_allowlist": ["pypi.org", "files.pythonhosted.org"]
  ```

- An **object** `{ "host": "...", "access": "ro" }` restricts a host to `GET`/`HEAD`
  only. `access` defaults to `"rw"`.

  ```json
  "egress_allowlist": [
    { "host": "github.com", "access": "ro" },
    { "host": "api.internal.example", "access": "rw" }
  ]
  ```

**`ro` requires the workload image to trust the sandbox proxy CA.** The `ro` tier is
enforced by the proxy decrypting the connection (squid `ssl_bump`); an image that
does not trust the sandbox proxy CA will fail TLS to `ro` hosts. `rw` hosts are
spliced (no decryption) and need no CA trust.

An empty allowlist (`[]`) is a deliberate, valid choice — it boots a firewall that
resolves and routes nothing.

### `ephemeral` (required, boolean)

When `true`, the workload's volumes are throwaway and torn down on exit. The
guarantee is **verified, not assumed**: teardown fails loud on any surviving volume.
When `false`, volumes are kept after the session (the launcher prints the
`docker volume ls` filter to find them).

### `seed_from_git` (object: `ref` + `review_branch`)

Seed the workspace from a git ref **inside** the sandbox; the workload's committed
writes are extracted onto `review_branch` **on the host**, never onto the host
working tree.

```json
"seed_from_git": {
  "ref": "HEAD",
  "review_branch": "sandbox/demo-review"
}
```

- `ref` — the git ref the sandbox workspace is seeded from. **This build supports
  only `HEAD`** (the current checkout's tracked tree plus uncommitted delta); any
  other ref is refused. `agent-sandbox run` must be invoked from inside a git
  checkout.
- `review_branch` — the host branch the workload's committed writes land on for
  review.

<a id="seed-vs-bind"></a>

#### Seed vs. bind — which to use

|                                    | **Seed** (`seed_from_git`)                               | **Bind** (`workspace_mount`)                                  |
| ---------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------- |
| `/workspace` backing               | named volume, seeded from git                            | host path, bind-mounted                                       |
| Workload writes reach the host via | extract onto `review_branch` (review gate)               | direct writes to the bound path                               |
| Overmount guardrails               | not applicable (writes gated by extract)                 | **active** (default `.git/hooks`, `node_modules`)             |
| Use when                           | you want a reviewable branch and the host tree untouched | you want the workload to operate directly on a host directory |

Prefer **seed** when the point is to review the workload's diff before it touches
your tree. Reach for **bind** when the workload must read/write a real host
directory in place — and rely on `overmount_paths` to keep the dangerous paths
read-only.

### `hardener` (boolean, default `true`)

Runs a transient root init service that executes every executable in the read-only
`/run/hardener-hooks.d` mount (empty by default = no-op success) and writes hardened
config into a volume the workload mounts read-only at `/run/hardened-config`. Any
hook failure aborts the launch before the workload starts. Set `false` to drop the
service from the stack entirely. See [hardener hooks](#hardener-hooks) for wiring.

### `audit` (boolean, default `true`)

Runs a tamper-evident append-only audit sink: it mints a per-session HMAC secret and
chains appended records so edits, reordering, or interior drops are detectable. The
workload mounts neither the log nor the secret. Set `false` to drop the service.

### `backend` (string, `local` | `hosted`, default `local`)

The runtime backend seam. `local` runs the Kata → gVisor → runc auto-downgrade
ladder on the local Docker engine. `hosted` (a managed remote sandbox) is a
documented interface stub. Every backend must enforce the allowlist at a forward
proxy and keep the proxy log as the egress log.

### The `profiles/` copy-from catalog

[`profiles/dev-common.json`](../profiles/dev-common.json) is an **opt-in catalog**
of curated `host -> access` entries (common software-development hosts: forges,
package registries, docs — all `ro`) that you copy fields **from** into a record's
`egress_allowlist`. **It is a starting point, not a default:** nothing in
`profiles/` is loaded automatically — the firewall boots deny-all, and a workload
reaches only what its own `egress_allowlist` declares.

The catalog stores a `{ "domains": { "<host>": "<access>" } }` map, whereas
`egress_allowlist` is a **list**; copying an entry means translating, e.g.
`"github.com": "ro"` becomes `{ "host": "github.com", "access": "ro" }`. Whatever
you assemble is validated against the schema at `run`.

---

## B. Running a Workload

`agent-sandbox` has four verbs:

```
agent-sandbox run [--extra-compose FILE]... <workload.json>
agent-sandbox expand <host>[:ro|rw] [--project NAME]
agent-sandbox gc [--dry-run]
agent-sandbox down <project>
```

### `run` — launch a session

```bash
agent-sandbox run workloads/demo-bash.json
```

The launch sequence, each step fail-closed: validate the record → select a runtime
via the backend ladder → allocate a per-session subnet → build/ensure the firewall
image → bring up the firewall + workload stack and wait for firewall health →
(bind mode) verify the read-only guardrails → seed the workspace from git → exec the
entrypoint → extract commits onto the review branch → export the egress log → tear
down. A malformed record, an unusable runtime, or a missing firewall stack refuses
to launch rather than proceeding half-isolated.

`run` returns the **workload's** exit status when the session machinery succeeded;
machinery failures return non-zero themselves.

#### `--extra-compose FILE` (repeatable)

Merges `FILE` after the library's compose file set on **every** compose invocation
of the session (in the order given, last). This is the seam for consumer-owned
companion services and service extensions. A file that isn't a readable path refuses
the launch (a silently-dropped overlay would boot the stack without its companion
services).

```bash
agent-sandbox run --extra-compose ./my-sidecar.compose.yml workloads/demo-bash.json
```

### Environment variables

- **`AGENT_SANDBOX_PROJECT_NAME`** — pins the compose project name (default: a random
  per-session name). Pin it so consumer lifecycle tooling can find the stack by
  label (and so `expand`/`down` can target it by name).
- **`AGENT_SANDBOX_STATE_DIR`** — the base directory for per-session host artifacts
  that outlive the containers. Session state lives at
  `$AGENT_SANDBOX_STATE_DIR/sessions/<project>/`. Default:
  `${XDG_STATE_HOME:-$HOME/.local/state}/agent-sandbox`.

### Where the egress log lands

Before teardown destroys the firewall's volume, the launcher copies squid's
`access.log` (the tamper-evident egress log) out of the firewall container to:

```
$AGENT_SANDBOX_STATE_DIR/sessions/<project>/egress.log
```

If the export fails it warns loudly (the session then has no host-side audit record)
but does not block teardown of an otherwise-complete session. The same session
directory also holds the seed's WIP patch and the extracted worktree/mbox for seed
runs.

### The review-branch flow (seed mode)

1. You run from inside a git checkout with `seed_from_git.ref = "HEAD"`.
2. The launcher seeds `/workspace` in the sandbox from `HEAD` plus your uncommitted
   delta.
3. The workload runs and **commits** its changes inside the sandbox.
4. On exit, the launcher extracts those commits onto `review_branch` **on the host**
   — never onto your working tree — and prints a merge hint.

If the extract fails, the session's containers and volumes are **kept** (the
workload's work is never destroyed with them) and the launch returns non-zero.

### `expand` — widen a running session's allowlist

```bash
agent-sandbox expand docs.example.com:ro
agent-sandbox expand api.example.com:rw --project agent-sandbox-1a2b3c4d
```

Adds one host to a **running** session's egress allowlist without resetting the
firewall. Default access is `ro` (GET/HEAD only). The grant is **session-scoped** —
make it permanent by adding the host to the Workload record's `egress_allowlist`.
With several sessions up, name one with `--project` (or `AGENT_SANDBOX_PROJECT_NAME`);
an ambiguous match refuses rather than guessing.

### `gc` — prune stale sandbox networks

```bash
agent-sandbox gc --dry-run   # preview
agent-sandbox gc             # reclaim
```

Prunes sandbox networks with no live containers, reclaiming dead sessions' subnets.
`--dry-run` previews what a real run would remove.

### `down` — tear down one session

```bash
agent-sandbox down agent-sandbox-1a2b3c4d
```

Tears down one session's stack by compose project name — containers, networks **and**
volumes — and **fails loud** if any volume survives, so "down" can never silently
mean "still persisted". A project name that matches nothing is itself an error (a
typo must not look like a clean teardown).

### Extension hooks

Both hook mechanisms run **fail-closed** (a non-zero hook aborts the launch) and both
run with elevated context. **The hook directories are a trust boundary: treat their
contents as trusted code.** Security rationale lives at its source — see the service
comments in [`sandbox/docker-compose.yml`](../sandbox/docker-compose.yml) and
[`sandbox/init-firewall.bash`](../sandbox/init-firewall.bash).

<a id="hardener-hooks"></a>

#### Hardener hooks

The hardener service runs **every executable** in `/run/hardener-hooks.d`, each
writing hardened config into the shared volume the workload mounts read-only at
`/run/hardened-config`. To supply hooks, point `HARDENER_HOOKS_DIR` at a host
directory; compose bind-mounts it read-only into the hardener. The default is
`/dev/null` (treated as a non-directory = **no hooks = no-op success**). A hook
exiting non-zero aborts the launch before the workload starts.

**The hardener runs as root.** Anything you place in the hooks dir executes as root
in a network-less container — trust it accordingly.

```bash
HARDENER_HOOKS_DIR=/path/to/hooks agent-sandbox run workloads/demo-bash.json
```

#### Firewall hooks

After the base deny-all rules and the supervised DNS refresher are live (and before
the firewall is marked ready), the firewall runs every executable in
`FIREWALL_HOOKS_DIR` (default `/run/firewall-hooks.d`). This is the seam for a
consumer to add its own iptables/ipset policy without forking the firewall script. A
non-executable/non-regular entry, or any hook failure, refuses to mark the firewall
ready (fail closed). Populate the directory by mounting it into the firewall via an
`--extra-compose` overlay (and setting `FIREWALL_HOOKS_DIR` if you use a different
path).

**Firewall hooks run as root inside the firewall network namespace** — they can
rewrite the entire egress policy. Treat the hooks dir as fully trusted.
