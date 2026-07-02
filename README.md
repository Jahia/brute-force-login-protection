# brute-force-login-protection

Detects and blocks brute-force login attempts against a Jahia server, in the spirit of fail2ban. Supports IPv4 and IPv6.

## Features

- **Sliding-window detection** — count failed logins per IP within a configurable time window (`findTime`), not just consecutive failures.
- **Per-jail configuration** — multiple jails, each with their own thresholds and ban durations.
- **Persistent bans with recidive escalation** — bans survive restarts; repeat offenders get progressively longer bans, capped by a configurable maximum.
- **Pluggable failure sources, auth detectors and ban actions** — `FailureSource`, `AuthFailureDetector` and `BanAction` SPIs let other modules contribute events, recognise new authentication schemes, or react to bans (block in-process, email, webhook, custom).
- **Broad auth coverage out of the box** — form login (and every SSO valve that sets `VALVE_RESULT`), HTTP Basic, Personal API tokens (`Authorization: APIToken …`) and the legacy `jahiatoken` header are all tracked.
- **Built-in actions**: in-process block, email notification (throttled), webhook POST signed with HMAC-SHA256 (`X-BFLP-Signature` header).
- **Cluster-aware** — state is shared across Jahia nodes via an embedded Hazelcast instance.
- **Audit log** — every ban, unban, and config change is recorded and visible from the UI.
- **React admin UI** with tabs for General settings, Jails, Bans, Audit log, and Integrations.

## Prerequisites

**Jahia cluster mode must be enabled.** The module depends on Hazelcast (`com.hazelcast.*`) at the OSGi level for distributed state. Those packages are only exported by Jahia when clustering is active, so the bundle will fail to resolve in standalone mode with:

```
Unable to resolve brute-force-login-protection: missing requirement osgi.wiring.package=com.hazelcast.core
```

Enable cluster mode in one of these ways before deploying:

- **Tarball/installer:** set `cluster.activated=true` in `digital-factory-config/jahia/jahia.node.properties` and restart.
- **Docker image:** set the environment variable `CLUSTER_ENABLED=true`.

A single-node "cluster of one" is fine for dev/test — the Hazelcast instance simply won't have peers.

### Cluster security (optional but recommended in production)

The dedicated Hazelcast instance ships with two opt-in hardening options:

- **Per-install group password.** On first start the module generates a random 32-byte secret and
  stores it in `<jahia-var>/karaf/etc/bflp-cluster-secret.properties` (POSIX permissions `rw-------`
  where supported). The password is exposed via the system property `bflp.cluster.password`. To use
  your own password, set `-Dbflp.cluster.password=...` before starting Jahia and the secret file is
  ignored.
- **TLS for cluster traffic.** Set the following system properties to enable mutual-TLS over the
  Hazelcast members. **Without them, cluster traffic is sent in plaintext.**

  | Property | Purpose |
  |----------|---------|
  | `bflp.cluster.keystore` | Path to the keystore (`.jks` / `.p12`). Required to enable TLS. |
  | `bflp.cluster.keystorePassword` | Keystore password. |
  | `bflp.cluster.truststore` | Path to the truststore. |
  | `bflp.cluster.truststorePassword` | Truststore password. |

## Installation

- In Jahia, go to **Administration → Server settings → System components → Modules**
- Upload the JAR `brute-force-login-protection-X.X.X.jar`
- Check that the module is started

## Configuration

Go to **Administration → Server settings → Configuration → Brute force login protection**.

- **General** — toggle the protection on/off, define the IP whitelist (CIDR), ignore patterns for usernames, trust of `X-Forwarded-For`, recidive factor, max ban time, audit log size.
- **Jails** — create/edit/delete jails. Each jail has: `enabled`, `maxRetry`, `findTimeSeconds`, `banTimeSeconds`.
- **Bans** — view currently banned IPs, manually ban an IP, or unban one.
- **Audit** — browse recent events, clear the log.
- **Integrations** — configure the email recipient and the webhook URL/secret.

### Where settings are stored

Global settings and jail definitions are persisted as OSGi configuration under
`<jahia-var>/karaf/etc/`. Bans and the audit log remain JCR-backed (they are runtime
state, not configuration).

| Kind | PID | Example filename |
|------|-----|------------------|
| Global settings (singleton) | `org.jahia.community.bruteforceloginprotection.global` | `org.jahia.community.bruteforceloginprotection.global.cfg` |
| Jail definition (factory) | `org.jahia.community.bruteforceloginprotection.jail` | `org.jahia.community.bruteforceloginprotection.jail-login.cfg` |

A jail `.cfg` MUST contain a `name=<jail-id>` property — that string is the jail
identifier seen by the engine and the admin UI. The filename discriminator after
`jail-` is only used by Felix to uniquely key the configuration on disk.

Operator-pasted plaintext is supported for `webhook_secret`: the module re-encrypts
it on the next save (prefix `{enc}`). The GraphQL mutation honours the same
tri-state contract as before — `null` keeps the stored secret, `""` clears it, any
other value replaces it.

Default example `.cfg` files are shipped under `src/main/resources/META-INF/configurations/`
and are dropped into `karaf/etc/` on first deploy.

**Configuration file protection:** Shipped `.cfg` files MUST start with the exact line `# default configuration - won't be overridden` to prevent Jahia's module extender from overwriting operator changes deployed to `karaf/etc` on every module restart or redeployment.

### Cluster behaviour

OSGi `ConfigurationAdmin` storage is per-node. In a Jahia cluster you must either:

- rely on **Karaf Cellar** to synchronise `karaf/etc/` across nodes (the default
  for clusters already running this module — Cellar is shipped with Jahia
  clustering), or
- ensure all nodes mount/share the same `digital-factory-data/karaf/etc/` directory.

No additional Hazelcast broadcasting of settings is performed by the module.

### Updating the module in a cluster

The recommended procedure for updating (or uninstalling) the module on a multi-node
cluster is **stop everywhere first, then update, then start**:

1. Stop (or uninstall) the module bundle on **all** nodes. The last member to stop has
   no migration targets, so every stop returns immediately.
2. Deploy the new version on all nodes.
3. Start the module everywhere. Each node re-joins the dedicated Hazelcast cluster and
   restores active bans from the JCR mirror (startup reconciliation, ADR 0004).

Rolling node-by-node updates also work — since 3.1.1 the module *terminates* its
Hazelcast member on bundle stop instead of waiting for partition migrations
(ADR 0005), so an update can no longer hang on `Remaining migration tasks in
queue => N` when the base+2 port is partially firewalled or the cluster cannot
repartition. The trade-off is a brief loss of replica redundancy for state that is
reconstructible anyway (bans are JCR-mirrored; failure windows are transient).

Whatever the procedure, make sure the module's Hazelcast port (Jahia's
`cluster.hazelcast.bindPort` + 2, e.g. 7862 when Jahia uses 7860) is open **in both
directions** between all cluster nodes.

### Webhook receiver guidance

When verifying the `X-BFLP-Signature` header on the receiver side, **always use a constant-time
comparison** to prevent timing attacks on the HMAC. Concretely:

- Java: `java.security.MessageDigest.isEqual(expectedBytes, providedBytes)`
- Python: `hmac.compare_digest(expected, provided)`
- Node.js: `crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(provided))`

The webhook URL is validated server-side to prevent SSRF: only `https://` is accepted by default,
private/loopback/link-local/multicast targets and the AWS metadata IP are rejected. Set
`-Dbflp.webhook.allowHttp=true` to allow plain `http://` for trusted on-premise receivers.

### Trusted reverse proxies (X-Forwarded-For)

`trustProxyHeader` alone is no longer sufficient to honour `X-Forwarded-For`: in addition, the
remote socket address of the incoming request must match one of the CIDR entries configured in
`trustedProxyCidrs`. If the list is empty while the flag is on, the module logs a one-time warning
and falls back to the raw socket address.

Configure Jahia's mail server settings to receive notification emails.

## Extending — adding a new auth-failure detector

The auth pipeline valve dispatches every authenticated request through an ordered
chain of `AuthFailureDetector` services. A custom module that wants to track a new
authentication scheme just needs to register one:

```java
@Component(service = AuthFailureDetector.class, immediate = true)
public class MySchemeFailureDetector implements AuthFailureDetector {
    @Override
    public FailureSignal detect(AuthFailureContext context) {
        if (context.isAuthenticated()) return null;
        String header = context.getRequest().getHeader("X-My-Scheme");
        if (header == null) return null;
        return FailureSignal.builder("my-scheme-valve")
                .extra("authScheme", "my-scheme")
                .build();
    }

    @Override
    public int order() { return 50; } // run before built-ins (100-400)
}
```

Built-in detector orders: form login = `100`, HTTP Basic = `200`, APIToken = `300`,
legacy `jahiatoken` = `400`. Use `< 100` to pre-empt a built-in or `> 1000` to act
as a fallback. The valve breaks on the first non-null `FailureSignal` so each
request records at most one failure event.

Never copy bearer-token strings into `FailureSignal.username` — usernames land in
the audit log.

## Upgrading from 2.x

**v3.0.0 is a breaking change.** Both the JCR settings schema and the GraphQL schema were rewritten — there is no automatic migration. After upgrading the bundle, settings must be re-entered from the admin UI. The old `nb_failed_login_max` / `time_to_idle` / `bruteForceLoginProtectionSettings` GraphQL endpoint no longer exists; use jails and `bruteForceLoginProtectionGlobalSettings` instead.

In addition, starting from v3.0.0-SNAPSHOT the global settings and jail definitions
moved out of JCR and into OSGi `ConfigurationAdmin` (see *Where settings are stored*
above). Existing in-flight v3 snapshot installs must re-enter their settings — JCR
values are no longer read.
