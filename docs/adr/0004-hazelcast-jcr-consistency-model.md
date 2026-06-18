# ADR 0004: Hazelcast⇄JCR Eventual Consistency Model

**Status:** Accepted with Known Issues

**Date:** 2025-06-18

**Context:** Bans must persist across cluster restarts. Hazelcast is in-memory and volatile; JCR is persistent. The module needs a strategy to ensure bans survive a full cluster shutdown and rejoin when the cluster comes back online. This requires synchronizing state between two systems with different durability guarantees.

**Decision:** Bans live authoritatively in the in-memory Hazelcast `bflp:bans` map. When a ban is issued or updated, the module **best-effort mirrors it to JCR**. On startup, any persisted bans in JCR are reloaded into Hazelcast. This is an **eventual consistency** model with the following guarantees:

- A ban will eventually be persisted to JCR (but may briefly exist only in Hazelcast after issuance)
- A ban will eventually be restored to Hazelcast after a restart (if the JCR mirror succeeded)
- Bans in Hazelcast have TTL-based auto-expiry; bans in JCR do not auto-expire

**Rationale:**

- **Hot-path performance:** Keeping bans in Hazelcast allows O(1) lookups on every request without JCR overhead.
- **Durability:** JCR mirroring ensures bans survive cluster restarts, which is critical for compliance and operational continuity.
- **Failure decoupling:** A JCR write failure does not block the hot-path auth valve; the ban is still enforced in-memory even if the mirror fails.

**Trade-offs and Known Issues:**

1. **Silent divergence:** If a Hazelcast write succeeds but the JCR mirror fails (e.g., JCR session I/O error), the ban exists in-memory but is lost forever when the cluster restarts. This is **rare but possible**.

2. **Stale JCR bans on restart:** When Hazelcast TTL expires a ban (typically after days), the JCR record lingers indefinitely. On the next cluster restart, stale JCR bans are reloaded into Hazelcast, temporarily re-activating expired bans until they age out again in Hazelcast. This can delay the actual unban by up to the duration of a Hazelcast TTL cycle.

3. **No startup reconciliation:** The module does not compare Hazelcast and JCR state at startup to detect divergence. A full reconciliation pass would be expensive and is not currently implemented.

**Mitigation Strategies:**

- **Monitor JCR write failures:** The module logs `WARN` on JCR mirror write failures; set up alerts on these logs.
- **Manual audit:** Periodically query both Hazelcast (via GraphQL `bruteForceLoginProtectionBannedIps`) and JCR (`/settings/bruteforceloginprotection/bans/*`) to detect divergence.
- **Manual unban:** If divergence is detected, operators can manually unban via the admin UI to correct the Hazelcast state.
- **Operational discipline:** In a rolling-restart scenario, let Hazelcast fully converge (all members joined) before traffic resumes to minimize reloading of stale bans.

**Alternatives Considered:**

1. **JCR-authoritative:** Read and write bans only to JCR, consulting it on hot-path. Rejected because JCR latency (~50–200ms) is unacceptable for every request.

2. **Hazelcast-only, accept data loss:** No JCR mirror; bans are lost on restart. Rejected because it violates the requirement that bans be durable.

3. **Distributed transaction (2PC):** Coordinate Hazelcast and JCR writes atomically. Rejected because Hazelcast does not support distributed transactions with JCR; the complexity is unjustified for this use case.

4. **Startup reconciliation:** On startup, compare Hazelcast and JCR; if divergence is detected, merge the states. Possible mitigation for the future but not currently implemented.

**Future Improvements:**

- Implement startup reconciliation to drop expired JCR bans on cluster join.
- Extend the JCR node type to include TTL metadata so expired bans can be auto-purged.
- Raise JCR mirror failures from `WARN` to `ERROR` and surface in the cluster status GraphQL field for operator alerting.

**Related ADRs:** [0001 — Separate Hazelcast Cluster](./0001-separate-hazelcast-cluster.md), [0002 — Fail-Open Enforcement](./0002-fail-open-enforcement.md)

**References:**
- `core/BruteForceTracker.java:512–548` — Hazelcast write and JCR mirror logic
- `core/UnbanScheduler.java:78–82` — TTL-based expiry without JCR cleanup
- CHANGELOG.md — "Known Limitations" section
