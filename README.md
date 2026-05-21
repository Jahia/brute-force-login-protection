# brute-force-login-protection

Detects and blocks brute-force login attempts against a Jahia server, in the spirit of fail2ban. Supports IPv4 and IPv6.

## Features

- **Sliding-window detection** — count failed logins per IP within a configurable time window (`findTime`), not just consecutive failures.
- **Per-jail configuration** — multiple jails, each with their own thresholds and ban durations.
- **Persistent bans with recidive escalation** — bans survive restarts; repeat offenders get progressively longer bans, capped by a configurable maximum.
- **Pluggable failure sources and ban actions** — `FailureSource` and `BanAction` SPIs let other modules contribute events or react to bans (block in-process, email, webhook, custom).
- **Built-in actions**: in-process block, email notification (throttled), webhook POST signed with HMAC-SHA256 (`X-BFLP-Signature` header).
- **Cluster-aware** — state is shared across Jahia nodes via an embedded Hazelcast instance.
- **Audit log** — every ban, unban, and config change is recorded and visible from the UI.
- **React admin UI** with tabs for General settings, Jails, Bans, Audit log, and Integrations.

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

Configure Jahia's mail server settings to receive notification emails.

## Upgrading from 2.x

**v3.0.0 is a breaking change.** Both the JCR settings schema and the GraphQL schema were rewritten — there is no automatic migration. After upgrading the bundle, settings must be re-entered from the admin UI. The old `nb_failed_login_max` / `time_to_idle` / `bruteForceLoginProtectionSettings` GraphQL endpoint no longer exists; use jails and `bruteForceLoginProtectionGlobalSettings` instead.
