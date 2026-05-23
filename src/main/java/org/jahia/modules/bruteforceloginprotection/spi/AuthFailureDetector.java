package org.jahia.modules.bruteforceloginprotection.spi;

/**
 * Extension point for detecting authentication failures from the Jahia auth pipeline.
 *
 * <p>BFLP wraps the pipeline as a valve at position 0 and, after the chain returns, asks every
 * registered detector whether the request represents a failed authentication attempt. The first
 * detector to return a non-null {@link FailureSignal} feeds it into the failure recorder.</p>
 *
 * <p>To plug in a new authentication scheme, register an OSGi component:</p>
 * <pre>
 * &#64;Component(service = AuthFailureDetector.class)
 * public class MySchemeDetector implements AuthFailureDetector {
 *     public FailureSignal detect(AuthFailureContext ctx) {
 *         if (ctx.isAuthenticated()) {
 *             return null;
 *         }
 *         if (!"MyScheme".equals(ctx.getRequest().getHeader("X-Auth-Scheme"))) {
 *             return null;
 *         }
 *         return FailureSignal.builder("my-scheme").extra("authScheme", "myscheme").build();
 *     }
 * }
 * </pre>
 *
 * <p>Implementations must be cheap and side-effect free — they run on every request that
 * reaches the auth pipeline.</p>
 */
public interface AuthFailureDetector {

    /**
     * Inspect the post-chain pipeline state and decide whether to record a failure.
     *
     * @param context post-chain pipeline state — never null
     * @return a partial failure description, or {@code null} if this detector does not match
     */
    FailureSignal detect(AuthFailureContext context);

    /**
     * Lower {@link #order()} values run first; detectors with equal order run in arbitrary OSGi
     * service-ranking order. Built-in detectors use values from 100 (form login) to 400.
     * Custom detectors that need to win over built-ins should return a value below 100; those
     * that should only run as a fallback should return a value above 1000.
     */
    default int order() {
        return 500;
    }
}
