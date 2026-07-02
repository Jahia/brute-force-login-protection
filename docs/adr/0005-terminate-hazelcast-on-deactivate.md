# ADR 0005: Terminate (Not Gracefully Shut Down) Hazelcast on Bundle Deactivation

**Status:** Accepted

**Date:** 2026-07-02

**Context:** On bundle stop, `HazelcastInstanceManager` originally called `HazelcastInstance.shutdown()` — Hazelcast's *graceful* shutdown, which blocks until every partition replica owned by the leaving member has been migrated to the remaining cluster members, capped by `hazelcast.graceful.shutdown.max.wait` (600 s by default). In production, module updates were observed to hang with the surviving node logging `Remaining migration tasks in queue => N … completedMigrations=0` indefinitely: the queued migrations never execute (typical causes: the base+2 port is firewalled in one direction between nodes, or the leaving bundle's classloader is being torn down mid-update so migration serialization cannot proceed). Because the OSGi `@Deactivate` method blocks inside `shutdown()`, the Felix bundle refresh — and therefore the whole module update — stalls with it.

**Decision:** Call `HazelcastInstance.getLifecycleService().terminate()` on deactivation instead of `shutdown()`. Terminate leaves the cluster immediately without waiting for replica migration.

**Rationale:** Graceful shutdown exists to avoid losing the leaving member's share of the distributed data. This module does not need that guarantee, because none of its Hazelcast state is authoritative-and-irrecoverable:

- `bflp:bans` is mirrored to JCR on every ban and restored by the startup reconciliation pass (ADR 0004). A ban whose replica is lost during a member's departure is re-seeded from JCR when the member returns; the other members' own replicas are untouched.
- `bflp:windows` holds transient sliding-window failure counters that rebuild naturally within one `findTime` window.
- `bflp:notifMarkers` only throttles notifications; losing a marker means at most one duplicate email/webhook.

This is the same trade-off already accepted for reads in ADR 0002 (fail-open): availability of the platform — here, the ability to update the module without hanging a production node — outweighs perfect continuity of reconstructible protection state.

**Consequences:**

- Module updates and restarts no longer block on cluster repartitioning; bundle stop is immediate.
- A member's departure may briefly reduce replica redundancy until Hazelcast repartitions among the remaining members — acceptable per the rationale above.
- Rolling updates remain supported, but the recommended procedure is still stop-everywhere → update → start (see README "Updating the module in a cluster"), which avoids mixed-version members entirely.
