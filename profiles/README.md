# Egress profiles

Curated `host -> access` maps (`"ro"` = GET/HEAD only, `"rw"` = all methods) a
Workload author can copy entries from into a record's `egress_allowlist`. Nothing
here is loaded by default: the firewall boots **deny-all**, and a workload reaches
only what its own `egress_allowlist` declares (see `schema/workload.schema.json`).

- `dev-common.json` — common software-development hosts (forges, package
  registries, docs), all read-only.
