# ADR 0003: AuthValve Position-Zero Short-Circuit for Ban Enforcement

**Status:** Accepted

**Date:** 2025-06-18

**Context:** Jahia's authentication pipeline is a chain of `AuthValve` instances, each with a priority/position. The brute-force module inserts a valve to enforce bans. The valve must decide where to hook into the chain: early (position 0, before other valves) or late (after all authentication has been attempted)?

**Decision:** Insert the enforcement valve at **position 0**, the earliest position in the auth pipeline, to short-circuit all authentication requests from banned IPs before any other valves run.

**Rationale:**

- **Efficient rejection:** Banned IPs are rejected immediately, without the overhead of running subsequent authentication checks (LDAP queries, OAuth roundtrips, etc.).
- **Uniform enforcement:** All authentication schemes (form login, HTTP Basic, API tokens, SSO valves) are blocked equally; there is no bypass for any auth mechanism.
- **Denial-of-service protection:** Early rejection prevents a brute-force bot from consuming downstream resources (LDAP, OAuth provider) while being blocked.

**Trade-offs:**

- **Broad blast radius:** A ban applies to *all* requests from a banned IP, not just login attempts. This can affect:
  - Legitimate users behind shared egress (NAT, corporate proxy, mobile carrier) if they share an IP with a bot
  - Legitimate services or monitoring tools if they happen to originate from a banned IP
  - Users in geographic regions where many IPs are pooled (mobile networks, hosting providers)
- **No per-scheme granularity:** The valve blocks at the IP level, regardless of authentication method. Custom modules cannot override this to allow a specific scheme through.

**Alternatives considered:**

1. **Late-pipeline valve (after all auth):** Only fail requests that actually failed authentication. Rejected because it wastes downstream auth resources on every attempt from a bot.
2. **Per-scheme hooks:** Allow custom `AuthFailureDetector` SPIs to decide whether to block a specific auth scheme. Rejected for simplicity; position-0 is easier to reason about.
3. **Configurable position:** Allow operators to choose position via a property. Rejected; the security/performance trade-off should be fixed by the module, not delegated.

**Risk Mitigation:**

- **Whitelist capability:** The module provides a CIDR-based IP whitelist (`whitelistIps` setting) to exempt known good IPs and IP ranges (corporate offices, monitoring endpoints).
- **Manual unban:** Operators can manually unban an IP via the admin UI if legitimate traffic is blocked.
- **Short ban durations:** Default ban times are configurable (default 600 seconds = 10 minutes); even if an innocent IP is blocked, the window is brief.
- **Audit trail:** All bans and unbans are logged; operators can review the history to catch accidental blocks.

**Related ADRs:** [0001 — Separate Hazelcast Cluster](./0001-separate-hazelcast-cluster.md)

**References:**
- `sources/AuthValveFailureSource.java` — position constant and short-circuit logic
- README.md — "Configuration" section (whitelist)
- Jahia AuthValve documentation
