# ADR 0004: Hazelcast⇄JCR Eventual Consistency Model

**Status:** Accepted with Known Issues (Startup Reconciliation Implemented)

**Date:** 2025-06-18

**Context:** Bans must persist across cluster restarts. Hazelcast is in-memory and volatile; JCR is persistent. The module needs a strategy to ensure bans survive a full cluster shutdown and rejoin when the cluster comes back online. This requires synchronizing state between two systems with different durability guarantees.

**Decision:** Bans live authoritatively in the in-memory Hazelcast `bflp:bans` map. When a ban is issued or updated, the module **best-effort mirrors it to JCR**. On startup, a reconciliation pass compares Hazelcast and JCR to detect and repair divergence. This is an **eventual consistency** model with the following guarantees:

- A ban will eventually be persisted to JCR (but may briefly exist only in Hazelcast after issuance)
- A ban will eventually be restored to Hazelcast after a restart (if the JCR mirror succeeded)
- **On startup, stale JCR bans (expired TTL) are dropped and live bans are restored**
- Bans in Hazelcast have TTL-based auto-expiry; bans in JCR do not auto-expire without reconciliation

**Rationale:**

- **Hot-path performance:** Keeping bans in Hazelcast allows O(1) lookups on every request without JCR overhead.
- **Durability:** JCR mirroring ensures bans survive cluster restarts, which is critical for compliance and operational continuity.
- **Failure decoupling:** A JCR write failure does not block the hot-path auth valve; the ban is still enforced in-memory even if the mirror fails.
- **Reconciliation at startup:** Comparing Hazelcast and JCR on component activation (once, at low cost) repairs divergence and prevents stale JCR bans from being rehydrated as active. The reconciliation is best-effort: any JCR failure is logged and swallowed so a JCR hiccup never blocks component activation.

**Trade-offs and Known Issues:**

1. **Silent divergence on JCR write failure:** If a Hazelcast write succeeds but the JCR mirror fails (e.g., JCR session I/O error), the ban exists in-memory but is lost forever when the cluster restarts. This is **rare but possible**. Mitigation: the module logs `WARN` on JCR mirror write failures; set up alerts on these logs.

2. **Reconciliation overhead on startup:** Comparing all JCR bans against the Hazelcast state on every node join adds latency to component activation (typically <100ms for reasonable ban volumes). In very large deployments (tens of thousands of bans), reconciliation may take longer; async offloading is not currently implemented.

**Mitigation Strategies:**

- **Monitor JCR write failures:** The module logs `WARN` on JCR mirror write failures; set up alerts on these logs.
- **Manual audit:** Periodically query both Hazelcast (via GraphQL `bruteForceLoginProtectionBannedIps`) and JCR (`/settings/bruteforceloginprotection/bans/*`) to detect divergence.
- **Manual unban:** If divergence is detected, operators can manually unban via the admin UI to correct the Hazelcast state.
- **Startup reconciliation verification:** The reconciliation pass logs reconciliation details (`BFLP: startup ban reconciliation`); inspect logs after cluster join to confirm stale JCR bans were dropped and live bans were restored.
- **Operational discipline:** In a rolling-restart scenario, let Hazelcast fully converge (all members joined) before traffic resumes.

**Alternatives Considered:**

1. **JCR-authoritative:** Read and write bans only to JCR, consulting it on hot-path. Rejected because JCR latency (~50–200ms) is unacceptable for every request.

2. **Hazelcast-only, accept data loss:** No JCR mirror; bans are lost on restart. Rejected because it violates the requirement that bans be durable.

3. **Distributed transaction (2PC):** Coordinate Hazelcast and JCR writes atomically. Rejected because Hazelcast does not support distributed transactions with JCR; the complexity is unjustified for this use case.

4. **Startup reconciliation:** On startup, compare Hazelcast and JCR; if divergence is detected, merge the states. Possible mitigation for the future but not currently implemented.

**Future Improvements:**

- **Async reconciliation:** Offload reconciliation to a background thread to avoid blocking component activation in very large deployments.
- **JCR TTL metadata:** Extend the JCR node type to include `ban_ttl_seconds` metadata so expired bans can be auto-purged without requiring a Hazelcast comparison.
- **Cluster status alerting:** Surface JCR write failure metrics in the `bruteForceLoginProtectionClusterStatus` GraphQL field for operator alerting dashboards.

**Related ADRs:** [0001 — Separate Hazelcast Cluster](./0001-separate-hazelcast-cluster.md), [0002 — Fail-Open Enforcement](./0002-fail-open-enforcement.md)

**Clarification:** ADR 0002 (fail-open when Hazelcast is down) and ADR 0004 (eventual consistency model) are complementary:
- **Hot path (every request):** JCR is not consulted; bans are enforced only via Hazelcast (fail-open if Hazelcast is unreachable).
- **Cold path (on startup):** JCR is reconciled with Hazelcast once at component activation to restore bans that survived a full cluster shutdown.

**References:**
- `core/BruteForceTracker.java:512–548` — Hazelcast write and JCR mirror logic
- `core/UnbanScheduler.java:78–82` — TTL-based expiry without JCR cleanup
- CHANGELOG.md — "Known Limitations" section
