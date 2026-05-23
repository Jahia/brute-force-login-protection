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
