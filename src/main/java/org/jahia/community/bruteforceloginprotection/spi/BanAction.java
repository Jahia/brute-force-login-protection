package org.jahia.community.bruteforceloginprotection.spi;

import org.jahia.community.bruteforceloginprotection.core.BanContext;

/**
 * Pluggable extension point for custom reactions to IP ban/unban events. Implementations are
 * discovered via OSGi service registry and executed in priority order (ascending).
 *
 * <p><b>Ordering and Execution:</b> All registered {@code BanAction} services run on every ban
 * or unban event, ordered by {@link #priority()} from lowest to highest. Actions run
 * <b>after</b> the ban is recorded in Hazelcast. For example:
 * <ul>
 *   <li>{@code InProcessBlockAction} (priority 0) writes the ban into the distributed map</li>
 *   <li>{@code EmailBanAction} (priority 10) sends a notification</li>
 *   <li>{@code WebhookBanAction} (priority 20) POSTs to a remote endpoint</li>
 * </ul>
 *
 * <p><b>Threading and Blocking:</b> All action methods are called synchronously on the
 * {@link org.jahia.community.bruteforceloginprotection.core.BruteForceTracker} event thread.
 * Actions MUST NOT block indefinitely, throw uncaught exceptions, or perform
 * long-lived I/O operations; such operations should be dispatched to background thread pools
 * instead. If {@code onBan()} or {@code onUnban()} throws, the exception is logged and
 * subsequent actions in the priority chain continue executing.
 *
 * <p><b>Custom Implementation Example:</b>
 * <pre>
 * &#64;Component(service = BanAction.class, immediate = true)
 * public class MyCustomBanAction implements BanAction {
 *     &#64;Override
 *     public String getName() {
 *         return "my-custom-action";
 *     }
 *
 *     &#64;Override
 *     public int priority() {
 *         return 50; // Run after InProcessBlockAction, before EmailBanAction
 *     }
 *
 *     &#64;Override
 *     public void onBan(BanContext context) {
 *         // Dispatch async notification to external system
 *         executorService.execute(() -> {
 *             try {
 *                 notifyExternalSystem(context.getBannedIp());
 *             } catch (Exception e) {
 *                 LOGGER.warn("Failed to notify external system", e);
 *             }
 *         });
 *     }
 *
 *     &#64;Override
 *     public void onUnban(BanContext context) {
 *         // Clean up state if needed
 *     }
 * }
 * </pre>
 */
public interface BanAction {
    /**
     * Returns a unique name for this action (e.g., "email-notifier", "webhook-poster").
     * Used for logging and introspection via the admin UI.
     */
    String getName();

    /**
     * Returns the execution priority. Actions are ordered by priority ascending (lowest first).
     * Use <code>0–20</code> for built-in actions, <code>1–49</code> for custom early actions,
     * <code>50+</code> for custom late actions.
     */
    int priority();

    /**
     * Called when an IP is banned. Runs synchronously after the ban is recorded in Hazelcast.
     * Must not block indefinitely or throw uncaught exceptions.
     *
     * @param context contains the IP, jail name, ban reason, and timestamps
     */
    void onBan(BanContext context);

    /**
     * Called when a ban expires or is manually removed. Runs synchronously after the ban is
     * removed from Hazelcast. Must not block indefinitely or throw uncaught exceptions.
     *
     * @param context contains the IP, jail name, and unban reason (if manual)
     */
    void onUnban(BanContext context);
}
