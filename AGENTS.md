# brute-force-login-protection

Jahia OSGi module that detects brute-force login attempts and bans offending IPs across a Jahia cluster, in the spirit of fail2ban. Admin UI at `/jahia/administration/bruteForceLoginProtection`.

## Key Facts

- **artifactId**: `brute-force-login-protection` | **version**: `3.0.0-SNAPSHOT`
- **Java package**: `org.jahia.modules.bruteforceloginprotection`
- **jahia-depends**: `default,graphql-dxm-provider,serverSettings`
- **No Blueprint/Spring** — pure OSGi DS (`@Component` annotations only)
- **Distributed state** via embedded Hazelcast (separate cluster from Jahia's own one)
- **fail2ban-style** sliding-window detection, per-jail policy, persistent bans, recidive escalation

## Architecture

Package layout: `hazelcast/`, `spi/`, `core/`, `actions/`, `sources/`, `graphql/types/`. The ~15 most important classes:

| Class | Role |
|-------|------|
| `hazelcast.HazelcastInstanceManager` | Manages the dedicated Hazelcast instance + the three module maps; exposes cluster status |
| `hazelcast.HazelcastConf` | Hazelcast system-property names (`cluster.hazelcastbflp.bindPort` = base + 2) |
| `hazelcast.ClassLoaderAwareSerializer` | Custom serializer letting Hazelcast deserialize module classes with the bundle's classloader |
| `spi.FailureSource` | SPI marker for anything that produces login-failure events |
| `spi.FailureRecorder` | SPI: receives `FailureEvent`s and updates the sliding window |
| `spi.BanAction` | SPI: a pluggable action invoked when an IP is banned, ordered by `priority()` (low first) |
| `sources.AuthValveFailureSource` | OSGi `BaseAuthValve` that intercepts logins; on failed auth publishes a `FailureEvent` to the recorder, and on every request checks the ban map and rejects when the IP is banned |
| `core.BruteForceTracker` | Central orchestrator: records failures, evaluates jails, issues bans, fires `BanAction`s, unbans on expiry |
| `core.SettingsService` | Reads/writes the JCR settings tree, exposes typed `GlobalSettings` + `JailConfig` snapshots |
| `core.RecidiveCalculator` | Computes escalated ban duration from `banCount` and `recidiveFactor`, capped by `maxBanTimeSeconds` |
| `core.UnbanScheduler` | Periodic task that expires bans and clears stale failure windows |
| `core.AuditLogger` | Append-only audit trail persisted under `auditLog`, bounded by `audit_log_max_entries` |
| `actions.InProcessBlockAction` | Default ban action (priority `0`); writes the ban into the distributed map so the valve enforces it |
| `actions.EmailBanAction` | Sends a notification (priority `10`); throttled per-IP |
| `actions.WebhookBanAction` | POSTs JSON to a configured URL (priority `20`); signs the body with HMAC-SHA256 in header `X-BFLP-Signature` |
| `graphql.BruteForceLoginProtectionQueryExtension` / `MutationExtension` | GraphQL surface, all gated by `@GraphQLRequiresPermission("admin")` |
| `graphql.types.*` | DTOs returned by GraphQL (`GqlGlobalSettings`, `GqlJail`, `GqlBannedIp`, `GqlFailureWindow`, `GqlAuditEntry`, `GqlBanActionInfo`, `GqlClusterStatus`) |
| `CidrMatcher` | IPv4 and IPv6 CIDR whitelist matching using byte-level mask comparison |

## GraphQL API

| Operation | Name | Returns |
|-----------|------|---------|
| Query | `bruteForceLoginProtectionGlobalSettings` | `GqlGlobalSettings` |
| Query | `bruteForceLoginProtectionJails` | `[GqlJail]` |
| Query | `bruteForceLoginProtectionBannedIps` | `[GqlBannedIp]` |
| Query | `bruteForceLoginProtectionTrackedWindows` | `[GqlFailureWindow]` |
| Query | `bruteForceLoginProtectionAuditLog(limit?)` | `[GqlAuditEntry]` |
| Query | `bruteForceLoginProtectionBanActions` | `[GqlBanActionInfo]` (name, class, priority) |
| Query | `bruteForceLoginProtectionClusterStatus` | `GqlClusterStatus { running, nodes }` |
| Mutation | `bruteForceLoginProtectionSaveGlobalSettings(activated, whitelistIps, ignorePatterns, trustProxyHeader, emailEnabled, emailRecipient, webhookUrl, webhookSecret, auditLogMaxEntries, recidiveFactor, maxBanTimeSeconds)` | Boolean |
| Mutation | `bruteForceLoginProtectionSaveJail(name!, enabled, maxRetry, findTimeSeconds, banTimeSeconds)` | Boolean |
| Mutation | `bruteForceLoginProtectionDeleteJail(name!)` | Boolean |
| Mutation | `bruteForceLoginProtectionUnbanIp(ip!)` | Boolean |
| Mutation | `bruteForceLoginProtectionBanIp(ip!, jail?, durationSeconds?, reason?)` | Boolean |
| Mutation | `bruteForceLoginProtectionFlush` | Boolean (clears bans + windows in cluster + JCR) |
| Mutation | `bruteForceLoginProtectionClearAuditLog` | Boolean |

`webhookSecret` follows a tri-state convention: `null` leaves the stored secret untouched, `""` clears it, any other string replaces it.

## Settings persistence

Settings root: `/settings/bruteforceloginprotection` (type `jnt:bruteForceLoginProtection`). Children are autocreated.

| Path | Node type | Purpose |
|------|-----------|---------|
| `.` | `jnt:bruteForceLoginProtection` | Global settings (activated, whitelist, ignore patterns, proxy header trust, email + webhook config, audit cap, recidive factor, max ban time) |
| `./jails/<name>` | `jnt:bruteForceLoginProtectionJail` | Per-jail config: `enabled`, `max_retry`, `find_time_seconds`, `ban_time_seconds` |
| `./bans/<id>` | `jnt:bruteForceLoginProtectionBan` | Persistent ban record: `ip`, `jail`, `source`, `banned_at`, `banned_until`, `ban_count` (recidive counter), `reason` |
| `./auditLog/<id>` | `jnt:bruteForceLoginProtectionAuditEntry` | `timestamp`, `event`, `ip`, `jail`, `source`, `details` |

Container node types `jnt:bruteForceLoginProtectionJails`, `…Bans`, `…AuditLog` (all `jnt:contentFolder`) hold the children.

`SettingsService` is the single writer; `BruteForceTracker` reads via cached snapshots and reloads on mutation.

## Distributed state

Hazelcast runs as a separate embedded instance, configured by `META-INF/configurations/hazelcast-bflp.xml`. It binds on `${cluster.hazelcastbflp.bindPort}` = Jahia's `cluster.hazelcast.bindPort` **base + 2** (default `5703`).

Three IMaps:

| Map name | Stores |
|----------|--------|
| `bflp:windows` | Per-IP sliding `FailureWindow` (deque of failure timestamps, jail name) |
| `bflp:bans` | Active bans, keyed by IP; backs the AuthValve hot-path check |
| `bflp:notifMarkers` | One marker per (IP, channel) so email/webhook notifications are throttled across nodes |

`HazelcastInstanceManager` lifecycle: builds the config from XML, registers `ClassLoaderAwareSerializer` for the module's value types, joins the cluster via TCP/IP using the same member list as Jahia (port offset applied). Bans persist via JCR (`bans` children) and are restored on startup, so a node joining late catches up.

## SPI for extensions

Three extension points, all consumed by `BruteForceTracker`:

- **`FailureSource`** — declarative tag for any component that publishes login failures. Built-in: `AuthValveFailureSource` (Jahia AuthValve). Custom sources call `FailureRecorder.recordFailure(FailureEvent)`.
- **`FailureRecorder`** — single OSGi service; updates the sliding window for an IP/jail and triggers ban evaluation when the count in the window exceeds `maxRetry`.
- **`BanAction`** — pluggable side-effect, ordered by `priority()` (ascending). All matching actions run on every ban event. Shipped implementations:

  | Class | Priority | What it does |
  |-------|----------|---|
  | `InProcessBlockAction` | `0` | Writes the ban into the `bflp:bans` map (this is what actually blocks logins) |
  | `EmailBanAction` | `10` | Sends a notification email, throttled per IP via `bflp:notifMarkers` |
  | `WebhookBanAction` | `20` | POSTs a JSON payload to the configured webhook; if `webhook_secret` is set, signs the body with HMAC-SHA256 in header `X-BFLP-Signature: sha256=<hex>` |

Custom modules just need to publish an OSGi `@Component` implementing `BanAction` to participate.

## Build

```bash
JAVA_HOME=/usr/local/graalvm mvn clean install sonar:sonar   # Full build + SonarQube scan (needs Java 17)
mvn clean install                                             # Full build only (Java 11 ok)
mvn test                                                      # JUnit only
yarn build              # Frontend only
yarn watch              # Frontend dev watch
yarn lint               # ESLint (src/javascript)
yarn lint:fix           # ESLint with auto-fix
```

- Node v22.6.0, Yarn v1.22.21 (classic, `nodeLinker: node-modules`)
- GraalVM Java 17 at `/usr/local/graalvm/` — required for `sonar-maven-plugin:3.10.0.2594` (class file 61.0)
- SonarQube project key: `org.jahia.community:brute-force-login-protection`
- Frontend entry: `src/javascript/index.js` → React component under `src/javascript/BruteForceLoginProtection/`, tabbed UI in `BruteForceLoginProtection/tabs/` (`GeneralTab`, `JailsTab`, `BansTab`, `AuditTab`, `IntegrationsTab`)
- CSS modules use `bflp_` prefix (e.g. `bflp_alert--success`, `bflp_emptyState`)

## Tests

**JUnit** (`src/test/java`):
- `CidrMatcherTest` — IPv4/IPv6 whitelist semantics
- `core.FailureWindowTest` — sliding-window eviction, find-time logic
- `core.BruteForceTrackerTest` — failure aggregation, ban issuance, ban-action dispatch
- `core.RecidiveCalculatorTest` — escalation curve and `maxBanTimeSeconds` cap

Run with `mvn test` (no Jahia runtime needed; uses Mockito for OSGi services).

**Cypress E2E** (`tests/`):

```bash
cd tests
cp .env.example .env          # fill JAHIA_IMAGE, JAHIA_LICENSE
yarn install
./ci.build.sh                 # builds Docker image + copies SNAPSHOT JAR → artifacts/
./ci.startup.sh               # waits for Jahia readiness, provisions module, then runs Cypress
yarn report:merge && yarn report:html   # merge mochawesome JSON → HTML report
```

- Tests: `tests/cypress/e2e/01-bruteForceLoginProtection.cy.ts`
- Fixtures updated to the v3 schema: `tests/cypress/fixtures/graphql/query/` (7 queries) and `…/mutation/` (7 mutations)
- `afterEach` calls `flush` to prevent state bleed between tests
- Provisioning (`assets/provisioning.yml`) installs `graphql-dxm-provider` + `serverSettings`
- Blocking test uses `cy.clearCookies()` before unauthenticated requests; `cy.login()` at the end restores the session so `afterEach`'s `cy.apollo()` works

## Gotchas

- **Requires Jahia cluster mode.** Hazelcast (`com.hazelcast.*`) is only exported by Jahia when clustering is active. Without it the bundle fails to resolve at install time with `missing requirement osgi.wiring.package=com.hazelcast.core`. Enable via `cluster.activated=true` in `jahia.node.properties` (tarball) or `CLUSTER_ENABLED=true` (Docker). A "cluster of one" is fine for dev/test.
- **Breaking change from v2.x.** Both the JCR schema (new node types, no `nb_failed_login_max` / `time_to_idle`) and the GraphQL schema are incompatible. No automatic migration — v2 settings must be re-entered.
- **Hazelcast port collision.** The module binds at `bindPort + 2`. If another Jahia module (e.g. `distributed-sessions`) already claims that offset, the cluster fails to form — override `cluster.hazelcastbflp.bindPort` explicitly in `jahia.properties`.
- **`bantime` vs `findTime`.** `find_time_seconds` is the sliding window size used to *count* failures, `ban_time_seconds` is how long a ban lasts. They are independent — a long ban time with a short find-time is fine.
- **Recidive escalation.** Re-banning the same IP increments `ban_count`; the next ban duration is roughly `banTime * (recidiveFactor ^ (banCount-1))`, capped by `max_ban_time_seconds` (default 7d). Set `recidiveFactor = 1.0` to disable escalation.
- **Webhook signature.** Receivers MUST compare against header `X-BFLP-Signature: sha256=<hex>`, computed as HMAC-SHA256 of the raw body using `webhook_secret`. Empty secret = no signature header sent.
- **`webhookSecret` tri-state.** `null` keeps the stored secret, `""` clears it, anything else overwrites it. Don't echo the current secret back to the UI — the UI sends `null` to mean "unchanged".
- **`X-Forwarded-For` is not trusted by default.** Set `trust_x_forwarded_for=true` only when Jahia sits behind a trusted reverse proxy; otherwise attackers can rotate the header to evade the counter.
- **`CidrMatcher` handles both IPv4 and IPv6** — whitelist entries must be valid CIDR notation (`192.168.0.0/24`, `2001:db8::/32`).
- **CND nodetype name is `jnt:bruteForceLoginProtection`** (the old v1 name `jnt:serverSettingsBruteForceLoginProtection` is long gone).
- **Frontend CSS class selectors use CSS Modules** — match with `[class*="bflp_..."]` in Cypress tests.
- **`yarn run lint`** may fail with lockfile errors; run ESLint directly: `./node/node ./node_modules/.bin/eslint src/javascript`.
- **Email throttle** — block-notification email is throttled per-IP via `bflp:notifMarkers` (cluster-wide) to prevent mail-flood DoS.
