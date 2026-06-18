# ADR 0002: Fail-Open Enforcement When Hazelcast Is Down

**Status:** Accepted

**Date:** 2025-06-18

**Context:** The auth valve must check every login request to enforce active bans against banned IPs. Hazelcast is in-memory and requires low-latency lookup; it will occasionally be unavailable (e.g., cluster partitions, temporary network isolation, member crash). The module must decide: when Hazelcast is down, should the valve continue to block requests (fail-closed) or allow all requests through (fail-open)?

**Decision:** **Fail open.** When Hazelcast is unreachable, the valve does not consult the JCR mirror and allows all authentication attempts to proceed. No bans are enforced.

**Rationale:**

- **Prioritizes availability over security:** A temporary cluster partition should not block all logins; availability is typically the higher priority.
- **Avoids hot-path JCR overhead:** Consulting JCR on every request would introduce unacceptable latency; the JCR mirror is best-effort and not authoritative.
- **Limits attack surface:** A malicious actor cannot trigger a denial-of-service by repeatedly crashing the Hazelcast cluster to disable all ban enforcement.
- **Anti-DoS protection:** In a sustained brute-force attack, failing open for a few seconds is preferable to a cascading JCR storm that degrades login performance for all users.

**Trade-offs:**

- **Temporary vulnerability:** While Hazelcast is down, banned IPs are not blocked; a sophisticated attacker could temporarily partition the cluster to bypass protection.
- **Window of exposure is small:** Most deployments experience cluster outages lasting seconds to minutes, not hours; the attack window is brief.
- **Monitoring required:** Operators should alert on Hazelcast cluster health and investigate partitions; relying on fail-open is not a substitute for cluster stability.

**Alternatives considered:**

1. **Fail-closed:** Query JCR as a fallback. Rejected because JCR write latency (~50–200ms per request) would be unacceptable in a brute-force scenario when many requests are being checked.
2. **Strict consistency:** Require all nodes to sync with Hazelcast before allowing auth. Rejected for the same reason; would create a scalability bottleneck.
3. **Read-only JCR fallback:** Cache recently-banned IPs in memory and check them if Hazelcast is down. Possible but adds complexity; the brief window of exposure (seconds) does not justify it for most deployments.

**Recommendations:**

- **Monitor Hazelcast health:** Integrate cluster status into your observability stack (Prometheus, DataDog, etc.).
- **Alert on cluster problems:** Notify operators of member crashes, partition events, or discovery failures.
- **Graceful degradation guidance:** Document the fail-open behavior so operators understand the expected behavior during outages.

**Related ADRs:** [0004 — Hazelcast⇄JCR Consistency Model](./0004-hazelcast-jcr-consistency-model.md)

**References:**
- `sources/AuthValveFailureSource.java` — valve enforcement logic
- `core/BruteForceTracker.java` — hot-path ban lookup
- README.md — "Gotchas" section
