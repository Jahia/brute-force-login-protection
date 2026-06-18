# Security Policy

## Reporting a Vulnerability

Security information can be found in our [security.txt file](https://academy.jahia.com/.well-known/security.txt).

## Known Dependabot alerts — accepted risk

### `com.hazelcast:hazelcast-all` (GHSA: missing permission checks on Hazelcast client protocol)

The `hazelcast-all` dependency in `pom.xml` is declared at **`provided`** scope: it
is only used for compile-time symbol resolution. At runtime, the Hazelcast bundle
is supplied by the host Jahia platform via OSGi `Import-Package`. Bumping the
version in this `pom.xml` therefore does **not** change which Hazelcast classes
execute in production.

Mitigation for this CVE lives in the Jahia distribution, not in this module:
upgrade Jahia to a release whose embedded Hazelcast is on a patched line
(`5.2.5+`, `5.3.5+`, or `5.4.0+`). This module's OSGi import range may need to
be widened in lockstep when Jahia ships a Hazelcast 5.x.

The Dependabot version-update PRs for `com.hazelcast:hazelcast-all` are
suppressed in `.github/dependabot.yml`. The corresponding security alert on the
GitHub Security tab is left in place as a tracking flag and should be dismissed
manually with a "tolerable risk — fixed in the host platform" rationale.

## Audit Log — PII Retention and Access Controls

The module stores an audit trail of all bans, unbans, and configuration changes in the JCR audit log (`/settings/bruteforceloginprotection/auditLog`). This trail includes client-supplied usernames, which may include:

- **Legitimate usernames** when login attempts are made against known accounts
- **Mistyped passwords** if users accidentally enter a password in the username field
- **Personal identifiable information** if usernames are email addresses or other PII

### Retention Limits

The audit log is **bounded by the `audit_log_max_entries` setting** (default: 1000 entries). When the limit is reached, the oldest entries are automatically purged. Operators can also manually clear the log via the **Audit** tab in the admin UI.

### Access Control Recommendations

**Lock down read access** to the audit log node (`/settings/bruteforceloginprotection/auditLog`) at the JCR level:

- Only administrators should have read/list permissions on audit data
- Consider implementing a separate "auditor" role with read-only access if your organization requires non-admin audit visibility
- Restrict write access (ban/unban/config changes) to a minimal set of operators via the `bruteForceLoginProtectionAdmin` permission required by all GraphQL mutations (declared in `roles.xml`, can be granted independently of full `administrationAccess`)

### GDPR Considerations

If your Jahia instance is subject to GDPR (or similar data protection regulations):

- The audit log qualifies as **personal data** (usernames, IP addresses, timestamps)
- **Retention policy:** Configure `audit_log_max_entries` to align with your data retention requirements (e.g., set it to a value that represents ~30 days of typical login-attempt volume if you retain for 30 days)
- **Data subject access requests:** Establish a procedure to export audit entries on request (export via the UI or direct JCR query)
- **Deletion:** The manual **Clear Audit Log** button in the UI is the primary deletion mechanism; consider disabling it via permission controls if you need an immutable audit trail
- **Mistyped passwords:** Instruct users never to enter passwords in the username field; this will reduce accidental PII capture, but recognize that mistakes will still occur

### Webhook and Email Notifications

Webhook payloads and email notifications also contain IP addresses and may reference usernames (via the ban reason or jail name). The webhook secret is encrypted at rest in the OSGi `.cfg` file (using Jahia's `EncryptionUtils` with an `{enc}` prefix). Ensure webhook receivers are:

- **Encrypted in transit** (HTTPS/TLS; the module rejects plaintext `http://` for remote receivers by default)
- **Restricted to trusted endpoints** (use allowlists to prevent SSRF)
- **Configured to handle PII securely** (do not log full payloads to stdout; encrypt at rest if persisted)
- **Using constant-time comparison** when validating the `X-BFLP-Signature: sha256=<hex>` header to prevent timing attacks
