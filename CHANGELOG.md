# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.2-SNAPSHOT] — Unreleased

- (nothing yet)

## [3.1.1] — 2026-07-02

### Fixed

- **Module update no longer hangs on Hazelcast partition migrations:** on bundle stop the module now *terminates* its dedicated Hazelcast member instead of performing a graceful shutdown. Graceful shutdown blocked the OSGi bundle refresh until all partition replicas were migrated — which could stall indefinitely (`Remaining migration tasks in queue => N … completedMigrations=0`) when the base+2 port was partially firewalled or the cluster could not repartition, freezing production module updates. Safe because all Hazelcast state is reconstructible: bans are JCR-mirrored and restored at startup, failure windows are transient (see ADR 0005).

### Changed

- **Docs:** README gains an "Updating the module in a cluster" procedure (stop-everywhere → update → start, plus the bidirectional base+2 port requirement); new ADR 0005 records the terminate-on-deactivate decision.

## [3.1.0] — 2026-07-02

### Added

- **IP blocklist (static + Tor exit nodes):** New proactive blocking enforced at the auth valve, in front of any downstream authentication work:
  - **Static blocklist:** `blocklist_ips` global setting — comma-separated IPs/CIDRs (IPv4/IPv6) that are always blocked while the protection service is activated. Entries are validated strictly at save time.
  - **Tor exit-node blocklist:** when `tor_blocklist_enabled=true`, each cluster node periodically downloads the TorDNSEL exit-addresses export (`tor_blocklist_url`, default `https://check.torproject.org/exit-addresses`; `tor_blocklist_refresh_seconds`, clamped to [300, 604800]) and blocks matching client IPs. On fetch failure the last successfully fetched list stays enforced; the error and list age are surfaced in the admin UI. Blocklist enforcement is in-memory per node and keeps working even while Hazelcast is unavailable.
  - **Whitelist precedence:** whitelisted IPs are never blocked (self-lockout safety valve).
  - **Auditing:** blocked attempts are logged at INFO and recorded as a new `BLOCKED` audit event, throttled to one entry per IP per hour.
  - **Admin UI:** new "Blocklist" tab with the static list, Tor settings, live per-node status (entry counts, last fetch, age, last error) and a "Fetch now" button.
  - **GraphQL:** `saveGlobalSettings` gains `blocklistIps`, `torBlocklistEnabled`, `torBlocklistUrl`, `torBlocklistRefreshSeconds`; new `blocklistStatus` query and `refreshTorBlocklist` mutation.
- **Startup reconciliation of JCR bans:** On cluster node join, the module now reconciles the authoritative Hazelcast `bflp:bans` map with the JCR mirror. Stale JCR ban nodes (expired TTL) are dropped; live bans whose Hazelcast TTL did not survive a full cluster restart are restored into the map. This is best-effort; any JCR failure is logged and does not block component activation (see ADR 0004).
- **Test mutations:** New GraphQL mutations `bruteForceLoginProtectionTestEmail` and `bruteForceLoginProtectionTestWebhook` allow operators to synchronously verify email and webhook integrations without triggering a live ban event.

### Changed

- **saveGlobalSettings mutation:** Now accepts `trustedProxyCidrs` parameter (list of CIDR entries) to validate the remote socket address against when honoring `X-Forwarded-For` headers (improves reverse-proxy support for multi-CIDR setups).
- **Docs and ADRs:** Updated AGENTS.md GraphQL API table to list all query/mutation signatures and arguments. ADR 0004 now reflects the implemented startup reconciliation pass (moved from "Future Improvements" to "Rationale").

## [3.0.0] — 2025-12-31

### Breaking Changes

**Do not upgrade without re-entering configuration.**

- **JCR schema rewrite:** The old `jnt:serverSettingsBruteForceLoginProtection` node type and legacy properties (`nb_failed_login_max`, `time_to_idle`) are no longer read. Settings must be re-entered via the admin UI or the new GraphQL mutations.
- **GraphQL schema rewrite:** The legacy `bruteForceLoginProtectionSettings` endpoint is replaced by `bruteForceLoginProtectionGlobalSettings` + `bruteForceLoginProtectionJails`. Clients must migrate queries and mutations.
- **OSGi ConfigurationAdmin migration:** Starting from v3.0.0-SNAPSHOT, global settings and jail definitions are stored in `karaf/etc/` (ConfigurationAdmin) rather than JCR. Existing v3-SNAPSHOT in-flight instances must re-enter their settings; JCR values are no longer read at startup.

### Added

- **Per-jail configuration:** Multiple independent jails with separate thresholds (`maxRetry`, `findTimeSeconds`) and ban durations (`banTimeSeconds`).
- **Persistent bans with recidive escalation:** Bans survive cluster restarts; repeat offenders face exponentially longer bans, capped by `maxBanTimeSeconds`. Escalation is driven by `recidiveFactor`.
- **Sliding-window detection:** Count failed logins within a configurable time window (`findTime`), not just consecutive failures.
- **Pluggable SPIs:** New extension points allow custom modules to:
  - Register `AuthFailureDetector` implementations for new authentication schemes.
  - Register `BanAction` implementations for custom ban reactions (email, webhook, custom integrations).
  - Publish login failures via `FailureSource` SPIs.
- **Audit log:** Every ban, unban, and configuration change is recorded and searchable from the admin UI; bounded by `audit_log_max_entries`.
- **Cluster-aware distributed state:** Bans are shared across Jahia nodes via an embedded Hazelcast instance (separate from Jahia's own cluster). Per-IP state is protected by optimistic locking (CAS) and TTL auto-expiry.
- **Broad auth coverage:** Out-of-the-box detection for form login (all SSO valves via `VALVE_RESULT`), HTTP Basic, Personal API tokens (`Authorization: APIToken`), and legacy `jahiatoken` header.
- **Built-in ban actions:**
  - **In-process block:** Bans are enforced by the auth valve at position 0, short-circuiting all requests from banned IPs.
  - **Email notification:** SMTP throttled per-IP to prevent mail-flood DoS.
  - **Webhook POST:** HMAC-SHA256 signed (`X-BFLP-Signature` header) with SSRF guards (https-only, loopback/private/AWS-metadata rejected).
- **Admin UI:** React tabbed interface (General, Jails, Bans, Audit, Integrations) with GraphQL backing.
- **Cluster security hardening:** Optional per-install group password (auto-generated or custom) and mutual-TLS for Hazelcast cluster traffic.
- **Reverse proxy support:** Configurable trusted proxy CIDR allowlist for `X-Forwarded-For` header validation (right-to-left chain walk).
- **Resilient ignore patterns:** ReDoS-hardened regex engine with bounded compilation time and fail-closed timeout semantics.

### Fixed

- (initial release of v3; no prior v3 bugs noted)

### Security

- All user inputs are validated and sanitized (CIDR, LDAP filter escaping, JCR filter escaping).
- Webhook secret is encrypted at rest in the OSGi `.cfg` file using Jahia's `EncryptionUtils` with `{enc}` prefix.
- Webhook HTTP receiver addresses are validated to reject SSRF targets (loopback, private ranges, AWS metadata).
- HMAC-SHA256 webhook signatures are computed over the raw body; receivers must use constant-time comparison.
- X-Forwarded-For parsing is safe against IP-literal spoofing and truncation attacks.
- Manual ban duration is clamped by `maxBanTimeSeconds` to prevent unbounded escalation.
- Java deserialization uses an explicit allowlist for Hazelcast serialization.
- Cluster secret is created with restrictive POSIX permissions (`rw-------`).

### Known Limitations

- **IP-keyed counting only:** Per-account brute-force controls require pairing with a Jahia account-lockout mechanism; no optional username-keyed jail exists yet.
- **Fail-open enforcement:** When Hazelcast is down, all bans are disabled (the JCR mirror is not consulted on the hot path); this is a deliberate anti-DoS choice to avoid hot-path JCR overhead.
- **Dual source of truth:** Bans live in Hazelcast and are mirrored to JCR; silent divergence is possible if a cluster restarts with stale JCR nodes or if a Hazelcast write succeeds while the JCR mirror fails.
- **Separate embedded cluster:** The module operates its own Hazelcast instance (bound at base port + 2) rather than reusing Jahia's Cellar-managed cluster; this isolates blast radius at the cost of operational complexity (port collision hazard).

### Dependencies

- **Hazelcast 3.12.13:** Embedded cluster for distributed state; EOL upstream, planned migration to 4.x/5.x.
- **Jahia 8.2+:** Requires Jahia 8.2 with cluster mode enabled (`cluster.activated=true`).
- **Java 17:** Build and runtime.
- **GraphQL DXM Provider:** For admin UI query/mutation endpoints.
