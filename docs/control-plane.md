# Control-plane attachment contract

How a consumer attaches its own control-plane services (a policy "gate", hook
relays) to a sandbox session, using only the library's public seams:
`--extra-compose` overlays, the `control_plane` Workload field
(`schema/workload.schema.json`), and the shared `control-plane` volume.

## Rendezvous: static IPs, not service names

The `sandbox` network is `internal: true` and the workload's DNS is pinned to
the firewall's resolver (static records, NXDOMAIN default) — compose service
aliases do **not** resolve inside the workload. A consumer control-plane
service therefore joins `networks: sandbox` at a **static IP** in the session
subnet: `.2` firewall, `.3` workload, and `.4` audit are taken; **`.5`–`.9`
are reserved for consumer control-plane services.** Publish the chosen address
as rendezvous config on the shared volume (below) rather than hardcoding it in
the workload image.

## The shared `/run/control-plane` volume

The library compose declares a named `control-plane` volume, mounted
**read-only** in the workload at `/run/control-plane` (exported to it as
`CONTROL_PLANE_DIR`). Consumer services mount the same volume **read-write**
in their `--extra-compose` overlay. The asymmetry is the trust boundary: a
consumer publishes, the workload can read but never forge.

Two kinds of files live there:

- **Ready markers** — `<name>.ready`, one per service named in
  `control_plane.require`.
- **Rendezvous config** — small files published beside the marker, e.g.
  `gate.addr` carrying `172.30.0.5:9400`, so in-workload hook clients discover
  the gate without baked-in addresses.

## Ready barrier

`control_plane.require: ["gate", ...]` lists the services that must be up
before the workload's entrypoint runs. After `up`, the launcher polls (1s) for
`/run/control-plane/<name>.ready` for **every** name; the entrypoint is only
exec'd once all exist. On timeout — `AGENT_SANDBOX_READY_TIMEOUT` seconds,
default 60 — the launch **fails closed**: the stack is torn down and the error
names the missing marker(s). Write the marker last, after the service is
genuinely able to serve (bind the port, then `touch`).

## Egress grants

A consumer service that must reach an external backend (a verdict API, a
telemetry sink) declares `control_plane.egress_grants`:

```json
{ "egress_grants": [{ "uid": 7777, "hosts": ["gate-api.example.com"] }] }
```

Requirements and semantics:

- The service must run with `network_mode: service:firewall` (it shares the
  firewall's network namespace) as the granted, non-zero `uid` — the grant is
  an `iptables -m owner --uid-owner` match and exists only in that namespace.
- The grant is **packet-layer only**: packets from that uid to the hosts'
  resolved IPs on **443** are ACCEPTed; every other part of the deny-all
  posture is unchanged.
- **Resolution is not reachability.** Grant hosts are pinned in the firewall's
  resolver so the granted service can connect by name, but they are **not**
  added to squid's allowlist nor to the workload-reachable `allowed-domains`
  set — workload packets to those IPs are still dropped, and workload CONNECTs
  to those names are still refused by the proxy.
- Grant IPs are resolved once at firewall boot (same batched resolver, same
  DNS-rebinding rejection as the allowlist) and pinned for the session.

## Audit relay topology

The workload never holds the audit secret. A consumer gate service mounts the
`audit-secret` volume read-only and relays records to the audit sink at `.4`,
so hook events become HMAC-chained audit records without the workload being
able to forge or rewrite them — tamper evidence against the workload is
preserved even when the events originate inside it.

## Reference consumer

`agent-control-plane-core` is the consumer this contract was shaped against:
its `bin/*-hook.mjs` clients run inside the workload, forward normalized
`ToolCallEvent`s to its gate service (discovered via `CONTROL_PLANE_DIR`
rendezvous config), and render the returned `Verdict` natively; the gate holds
the audit-relay and egress-grant privileges the workload must not.
