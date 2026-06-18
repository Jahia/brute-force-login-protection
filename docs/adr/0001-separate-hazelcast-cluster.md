# ADR 0001: Separate Embedded Hazelcast Cluster

**Status:** Accepted

**Date:** 2025-06-18

**Context:** The brute-force protection system requires distributed, cluster-aware state to coordinate bans across Jahia nodes. Jahia v8.2 already ships with Hazelcast (managed via Cellar) for its own clustering needs. The module could either reuse Jahia's embedded Hazelcast instance or operate its own separate cluster.

**Decision:** Operate a **separate, dedicated Hazelcast instance** bound to `cluster.hazelcastbflp.bindPort` (Jahia's base port + 2, typically `5703`).

**Rationale:**

- **Blast radius isolation:** Failures in the brute-force protection cluster (e.g., discovery misconfiguration, JVM OOM due to unbounded ban maps) do not cascade into Jahia's core clustering infrastructure.
- **Independent lifecycle:** The module can be deployed, redeployed, or undeployed without disrupting Jahia's session replication and other critical cluster services.
- **Operational clarity:** Separate logs, config files, and monitoring make it easier to diagnose clustering issues specific to brute-force detection.

**Trade-offs:**

- **Operational complexity:** A second cluster topology must be provisioned, monitored, and maintained.
- **Port collision hazard:** If another Jahia module also claims base port + 2, manual configuration (`cluster.hazelcastbflp.bindPort` property) is required to avoid startup failures.
- **Memory overhead:** Two JVM Hazelcast instances consume more heap than a single shared instance.

**Alternatives considered:**

1. **Reuse Jahia's Cellar-managed cluster:** Lower operational overhead but tighter coupling; cluster-wide failures would affect both session state and brute-force bans.
2. **Use a remote Hazelcast server (not embedded):** More operational complexity (external service, network latency); not justified for this use case.
3. **No clustering (single-node Hazelcast):** Bans would not survive cluster failover; unacceptable for production.

**Related ADRs:** [0004 — Hazelcast⇄JCR Consistency Model](./0004-hazelcast-jcr-consistency-model.md)

**References:**
- `hazelcast/HazelcastConf.java` — cluster configuration and port binding
- `META-INF/configurations/hazelcast-bflp.xml` — Hazelcast instance setup
- README.md — "Prerequisites" and "Cluster behaviour" sections
