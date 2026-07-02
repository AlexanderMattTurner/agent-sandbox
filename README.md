# agent-sandbox

A library for running an **untrusted Workload** — an arbitrary container image and
command — inside a hardware-isolated, deny-all-egress sandbox. You describe the
workload as a small JSON record; the launcher selects a runtime, allocates a private
subnet, brings up a **name-level-allowlist firewall** in front of it, waits for the
firewall to be healthy, then execs the workload. The workload sits on an
`internal` Docker network with no route off it — its only path out is the firewall's
forward proxy — so the allowlist is unbypassable and the proxy's access log is a
complete, **tamper-evident egress log** of everything the workload sent.

The isolation is layered: a runtime ladder that auto-downgrades **Kata → gVisor →
runc** (strongest available wins), a firewall that boots **deny-all** and admits only
the hostnames the Workload declares (with a per-host `ro` GET/HEAD tier), and an
**ephemeral** teardown whose "everything is gone" guarantee is _verified_ — teardown
fails loud on any surviving volume. The workspace is either **seeded from git** (the
workload's commits are extracted onto a review branch, never onto your working tree)
or **bind-mounted** from a host path (with dangerous paths held read-only). No
workload-specific logic lives in the library.

- **Authoring and running a Workload:** [`docs/usage.md`](docs/usage.md)
- **Bind mode — what is and isn't protected:** [`docs/bind-mode.md`](docs/bind-mode.md)
- **The Workload contract (every field):** [`schema/workload.schema.json`](schema/workload.schema.json)
- **How the isolation is built as topology:** the header comment of
  [`sandbox/docker-compose.yml`](sandbox/docker-compose.yml)
- **Lineage from `claude-guard`:** [`PROVENANCE.md`](PROVENANCE.md)

```bash
agent-sandbox run workloads/demo-bash.json     # run a Workload record
agent-sandbox down <project>                    # tear one session down (verified)
```
