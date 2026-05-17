# brute-force-login-protection

Jahia OSGi module that blocks IPs after repeated failed login attempts. Admin UI at `/jahia/administration/bruteForceLoginProtection`.

## Key Facts

- **artifactId**: `brute-force-login-protection` | **version**: `2.0.2-SNAPSHOT`
- **Java package**: `org.jahia.modules.bruteforceloginprotection`
- **jahia-depends**: `default,graphql-dxm-provider,serverSettings`
- **No Blueprint/Spring** — pure OSGi DS (`@Component` annotations only); `META-INF/spring/` was removed

## Architecture

| Class | Role |
|-------|------|
| `BruteForceLoginProtectionAuthValve` | OSGi AuthValve; intercepts logins, checks cache, enforces block |
| `BruteForceLoginProtectionCacheManager` | In-memory EhCache for IP entries; TTI is configurable at runtime via `setTimeToIdle(int)` |
| `BruteForceLoginProtectionConstants` | All string keys + `DEFAULT_TIME_TO_IDLE = 3600`, `MAX_CACHE_ENTRIES = 100_000`, `NOTIFICATION_THROTTLE_SECONDS = 3600` |
| `CidrMatcher` | IPv4 **and** IPv6 CIDR whitelist matching using byte-level mask comparison |
| `IpCacheEntry` / `SettingCacheEntry` | Cache value objects; `SettingCacheEntry.value` is `Serializable` (not `Object`) |
| `BruteForceLoginProtectionMutationExtension` | GraphQL mutations (save settings, flush cache, unblock IP) |
| `BruteForceLoginProtectionQueryExtension` | GraphQL queries (get settings, get tracked IPs) |

## GraphQL API

| Operation | Name |
|-----------|------|
| Query | `bruteForceLoginProtectionSettings` → `{activated, nbFailedLoginMax, whitelistIps, timeToIdle, trustProxyHeader}` |
| Query | `bruteForceLoginProtectionTrackedIps` → `[{ip, nbFailedLogins, blocked}]` |
| Mutation | `bruteForceLoginProtectionSaveSettings(activated, nbFailedLoginMax, whitelistIps, timeToIdle?, trustProxyHeader?)` → Boolean |
| Mutation | `bruteForceLoginProtectionFlushCache` → Boolean |
| Mutation | `bruteForceLoginProtectionUnblockIp(ip)` → Boolean |

## Settings persistence

Settings node path: `/settings/bruteforceloginprotection` (type `jnt:bruteForceLoginProtection`).

| JCR property | Java constant | Default |
|---|---|---|
| `activated` | `PROPERTY_ACTIVATED` | `false` |
| `nb_failed_login_max` | `PROPERTY_NB_FAILED_LOGIN_MAX` | `6` |
| `whitelist_ips` | `PROPERTY_WHITELIST_IPS` | `127.0.0.1/32,::1/128` |
| `time_to_idle` | `PROPERTY_TIME_TO_IDLE` | `3600` |
| `trust_x_forwarded_for` | `PROPERTY_TRUST_PROXY_HEADER` | `false` |

`saveSettings` mutation: writes to JCR, then calls `cacheManager.setTimeToIdle(n)` live (no restart needed), then flushes the EhCache. On `start()`, `CacheManager` reads `time_to_idle` from JCR via `readTimeToIdleFromJcr()` with fallback to `DEFAULT_TIME_TO_IDLE`.

## Build

```bash
JAVA_HOME=/usr/local/graalvm mvn clean install sonar:sonar   # Full build + SonarQube scan (needs Java 17)
mvn clean install                                             # Full build only (Java 11 ok)
yarn build              # Frontend only
yarn watch              # Frontend dev watch
yarn lint               # ESLint (src/javascript)
yarn lint:fix           # ESLint with auto-fix
```

- Node v22.6.0, Yarn v1.22.21 (classic, `nodeLinker: node-modules`)
- GraalVM Java 17 at `/usr/local/graalvm/` — required for `sonar-maven-plugin:3.10.0.2594` (class file 61.0)
- SonarQube project key: `org.jahia.community:brute-force-login-protection`
- Frontend entry: `src/javascript/index.js` → React component under `src/javascript/BruteForceLoginProtection/`
- CSS modules use `bflp_` prefix (e.g. `bflp_alert--success`, `bflp_emptyState`)
- `.eslintrc.js` exists at project root (was missing; extends `@jahia/eslint-config`, disables `react/prop-types`)

## Tests (Cypress Docker)

```bash
cd tests
cp .env.example .env          # fill JAHIA_IMAGE, JAHIA_LICENSE
yarn install
./ci.build.sh                 # builds Docker image + copies SNAPSHOT JAR → artifacts/
./ci.startup.sh               # waits for Jahia readiness, provisions module, then runs Cypress
yarn report:merge && yarn report:html   # merge mochawesome JSON → HTML report
```

- Tests: `tests/cypress/e2e/01-bruteForceLoginProtection.cy.ts`
- GraphQL fixtures: `tests/cypress/fixtures/graphql/` (5 files: 2 queries, 3 mutations); `saveSettings.graphql` has optional `$timeToIdle: Int`
- `afterEach` flushes cache to prevent state bleed between tests
- Provisioning (`assets/provisioning.yml`) installs `graphql-dxm-provider` + `serverSettings`
- Blocking test uses `cy.clearCookies()` before unauthenticated requests — mandatory so the existing admin session cookie doesn't bypass the AuthValve
- `cy.login()` at the end of the blocking test restores the session so `afterEach`'s `cy.apollo()` works

## Gotchas

- `CidrMatcher` handles both IPv4 and IPv6 — whitelist entries must be valid CIDR notation
- Settings are stored via JCR (serverSettings), cache is in-memory only — flushing cache does not reset TTI
- The `definitions.cnd` nodetype was renamed from `jnt:serverSettingsBruteForceLoginProtection` → `jnt:bruteForceLoginProtection`; old name is gone
- Frontend CSS class selectors use CSS Modules — match with `[class*="bflp_..."]` in Cypress tests
- `yarn run lint` may fail with lockfile errors; run ESLint directly: `./node/node ./node_modules/.bin/eslint src/javascript`
- `BruteForceLoginProtectionAuthValve` overrides `equals`/`hashCode` (delegates to `super`) to satisfy SonarQube S2160
- `SettingCacheEntry.value` is `Serializable` — use `.longValue()` / `.intValue()` instead of primitive casts when setting JCR `long` properties from boxed `Integer`
- `X-Forwarded-For` is **not** trusted by default — set `trust_x_forwarded_for=true` (or `trustProxyHeader` mutation arg) only when Jahia sits behind a trusted reverse proxy; otherwise attackers can rotate the header to evade the counter
- `BruteForceLoginProtectionCacheManager` skips `setMaxEntriesLocalHeap(MAX_CACHE_ENTRIES)` when Jahia's EhCache manager already declares a global `maxBytesLocalHeap` pool — required to avoid `InvalidConfigurationException` at module activation
- Block-notification email is throttled per-IP via `NOTIFICATION_THROTTLE_SECONDS` (1h) to prevent mail-flood DoS
