# brute-force-login-protection — 3.0.0 release notes

_Release date: 2026-05-23_

## Highlights

- **Broader authentication coverage.** HTTP Basic auth, Personal API tokens
  (`Authorization: APIToken …`) and the legacy `jahiatoken` header are now
  tracked alongside form login and SSO valves. Previously these schemes
  bypassed the failure listener entirely.
- **New `AuthFailureDetector` SPI.** Third-party modules can register their own
  detectors via OSGi DS to handle custom authentication schemes without
  patching the core module. See *Extending — adding a new auth-failure
  detector* in the README.
- **OSGi `ConfigurationAdmin` storage.** Global settings and jail definitions
  now live in `karaf/etc/` rather than JCR. Existing v3 snapshot installs must
  re-enter their settings — JCR values are no longer read.
- **Cluster hardening.** The embedded Hazelcast instance now ships with an
  auto-generated per-install group password and optional mutual-TLS between
  members (`-Dbflp.cluster.keystore=…` and friends).
- **Trusted-proxy gating.** `trustProxyHeader` alone no longer honours
  `X-Forwarded-For` — the socket address of the incoming request must also
  match one of the CIDR entries in `trustedProxyCidrs`. A one-time warning is
  logged when the flag is on but the list is empty.
- **Signed webhooks.** The webhook integration POSTs an `X-BFLP-Signature`
  HMAC-SHA256 header. URL validation rejects private / loopback / link-local /
  multicast targets and the AWS metadata IP. Plain `http://` is opt-in via
  `-Dbflp.webhook.allowHttp=true`.

## New SPI

```java
public interface AuthFailureDetector {
    FailureSignal detect(AuthFailureContext context);
    default int order() { return 500; }
}
```

Built-in detector orders:

| Order | Detector | Covers |
|-------|----------|--------|
| 100 | `FormLoginFailureDetector` | `LoginEngineAuthValveImpl` + every `SsoValve` subclass (anything that sets `VALVE_RESULT`) |
| 200 | `BasicAuthFailureDetector` | `Authorization: Basic …` |
| 300 | `ApiTokenAuthFailureDetector` | `Authorization: APIToken …` (personal-api-tokens) |
| 400 | `JahiaTokenAuthFailureDetector` | legacy `jahiatoken` header (`TokenAuthValveImpl`) |

The valve breaks on the first non-null `FailureSignal`, so each request records
at most one failure. Detector exceptions are isolated — one buggy custom
detector cannot break the chain.

## Breaking changes (recap from earlier 3.0.0 snapshots)

- JCR settings schema and GraphQL schema rewritten — no automatic migration.
- The old `nb_failed_login_max` / `time_to_idle` /
  `bruteForceLoginProtectionSettings` GraphQL endpoint is removed; use jails
  and `bruteForceLoginProtectionGlobalSettings`.
- Settings now live in OSGi `ConfigurationAdmin`, not JCR.
- Bearer tokens are never captured as usernames in audit events.

## Prerequisites

Jahia **cluster mode must be enabled** (`cluster.activated=true` in
`jahia.node.properties`, or `CLUSTER_ENABLED=true` in Docker) — the bundle
depends on `com.hazelcast.*` packages that Jahia only exports when clustering
is active.

## Quality

- 44 / 44 unit tests pass.
- Sonar quality gate: **OK** (0 new issues, 0 % maintainability debt ratio).
- Cypress smoke tests cover form login, HTTP Basic, and APIToken flows.
