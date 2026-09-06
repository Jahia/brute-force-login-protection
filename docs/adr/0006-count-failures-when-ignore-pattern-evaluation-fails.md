# ADR 0006: Count The Failure When Ignore-Pattern Evaluation Cannot Complete

**Status:** Accepted

**Date:** 2026-09-06

**Context:**

`ignore_patterns` lets an operator exempt usernames (service accounts, monitoring principals) from
failure counting. `BruteForceTracker.recordEvent` consults it before anything else it does with a
failure: a match returns early, so no failure window is incremented, no audit entry is written, and
no ban can be issued.

Matching runs on a bounded, interruptible executor with a 50 ms budget, because the pattern is
operator-supplied and the username is attacker-supplied. Two conditions can leave that match
undecided: the budget expires (`TimeoutException`), or the pool and its queue are full
(`RejectedExecutionException`). The module must decide what an *undecided* match means.

**This ADR deliberately avoids the words "fail open" and "fail closed."** In
[ADR 0002](./0002-fail-open-enforcement.md), "fail open" means *stop blocking* — the permissive,
less-secure direction. For an **exemption** check the valence inverts: the permissive branch is the
one that *grants* the exemption. Those two readings of the same phrase are not a stylistic matter.
The original implementation of this branch was commented "Fail closed", sincerely meaning "be
strict", and implemented the permissive direction — which is
[GHSA-7qgr-2hqv-r344](https://github.com/Jahia/brute-force-login-protection/security/advisories/GHSA-7qgr-2hqv-r344).
The decision below is therefore named by its **effect**.

**Decision:** **Count the failure.** When the module cannot determine whether a username matches an
ignore pattern, it treats the pattern as **not matched** and proceeds exactly as it would for any
other failed login: the window is incremented, an audit entry is written, and a ban may follow.
This applies to all three "cannot evaluate" conditions — timeout, executor saturation, and executor
absent/shut down.

**Rationale:**

- **The two errors are not symmetric.** Wrongly counting a failure the operator wanted exempted is
  visible (an audit entry, a throttled WARN naming the pattern) and reversible with a single
  `unbanIp`. Wrongly skipping one destroys both the control and the record that would have shown it
  was needed; nobody can reconstruct it after the fact.
- **The permissive branch was attacker-reachable.** The username is `request.getParameter("username")`
  — fully attacker-controlled. Granting an exemption on timeout handed the attacker a per-request
  opt-out of the entire counter, triggered by their own input.
- **Consistency with the existing `INTERRUPTED` disposition.** `matchesIgnorePattern` already
  returned "not matched" on thread interruption. The timeout and saturation paths were the outliers.
- **Saturation is the worse of the two.** It needs no catastrophic pattern, and rejection is
  node-global rather than scoped to a username — so it stopped *every* ignore pattern resolving at
  once. A blanket exemption is the last thing that condition should produce.

**Trade-offs:**

- **A legitimately exempt account can be banned.** If an operator's pattern is expensive enough to
  time out, the account it protects starts accruing failures. The WARN states this consequence and
  names `unbanIp`.
- **Bans are keyed on IP, not username.** With `trust_x_forwarded_for=false` (the default) every
  client behind a reverse proxy presents the load balancer's address, so a ban can have far wider
  blast radius than the account that caused it. This is why the whitelist now takes precedence at
  enforcement time (see below) — without a working escape hatch this trade-off would not be
  acceptable.
- **`cancel(true)` is retained.** Counting must not be paid for with a burning thread:
  `InterruptibleCharSequence` still aborts a runaway match. Correct counting and bounded CPU are
  independent properties and the fix keeps both.

**Alternatives considered:**

1. **Truncate the username to a length cap before matching, instead of changing the disposition.**
   Rejected on measurement. `(.*a){20}` reaches ~101 s at **32 characters**, so a cap low enough to
   bound the cost (~16) would break every realistic principal — LDAP DNs run to ~150 characters,
   JWT `sub` claims and email-shaped service accounts to 60–80. Truncation would also change the
   semantics of the anchored `Matcher.matches()` and could make a truncated string newly match a
   `^prefix-.*$` pattern, creating a fresh exemption bypass.
2. **Rely on the save-time ReDoS lint instead.** Rejected as insufficient on its own.
   `RegexSafetyCheck` is a character scanner and is incomplete by construction: both of its checks
   key on `)`, so a groupless `.*.*.*.*.*.*.*.*.*.*x` is never examined despite costing ~5.7 s at 30
   characters. It was also bypassable via hand-edited `.cfg` files. Both gaps are now narrowed (a
   `){n}` rule, and the lint applied on load), but the lint remains defence-in-depth, not the
   control.
3. **Count the failure but suppress ban issuance on the saturation path.** Considered because
   saturation is load-correlated and could convert a login-failure spike into simultaneous bans.
   Rejected for now: it adds a third disposition threading through `recordEvent` for a scenario in
   which the IP would usually be banned by failure volume anyway, and the whitelist escape hatch
   plus the throttled WARN cover the operator's needs. Revisit if field reports show otherwise.

**Consequences for enforcement:**

`isIpCurrentlyBanned` now returns `false` for a whitelisted IP. Previously the whitelist was
consulted only when *recording* a failure, so adding an address to `whitelist_ips` did not lift a
ban it had already accrued — leaving no remedy but to wait out a recidive-escalated TTL of up to
seven days, from behind the very valve that gates the admin UI offering `unbanIp`.
`BlocklistService` already gave the whitelist precedence; bans now match. A manual `banIp` of a
whitelisted address is still recorded but not enforced.

**Recommendations:**

- **Alert on the skip WARN.** `BFLP: ignore-pattern '…' not evaluated (…)` means an exemption is
  not being applied and bans may follow. It is throttled to one line per 60 s across all patterns.
- **Prefer simple, anchored ignore patterns.** `^service-.*$` costs nothing. Avoid repeating a group
  that contains `*` or `+`.
- **Keep `whitelist_ips` accurate**, especially for reverse proxies and monitoring sources — it is
  now the reliable way to undo an over-broad ban.

**Related ADRs:** [0002 — Fail-Open Enforcement When Hazelcast Is Down](./0002-fail-open-enforcement.md)
— note the terminology caveat above: 0002 concerns *enforcement*, where the permissive direction is
the accepted one for availability reasons; this ADR concerns *detection*, where it is not.

**References:**
- `core/BruteForceTracker.java` — `awaitMatchResult`, `submitMatchTask`, `isIpCurrentlyBanned`
- `core/RegexSafetyCheck.java` — best-effort save-time and load-time lint
- `core/GlobalConfigHolder.java` — `safeIgnorePatterns` (drop-and-warn on load)
- GHSA-7qgr-2hqv-r344
