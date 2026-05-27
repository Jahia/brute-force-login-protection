package org.jahia.modules.bruteforceloginprotection.actions;

import org.apache.commons.lang.StringUtils;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Locale;

/**
 * Validates webhook URLs to mitigate SSRF: rejects non-HTTP(S) schemes, URLs with userinfo,
 * and any URL whose host resolves to a loopback, link-local, site-local, multicast,
 * any-local, or cloud-metadata address. The validator is invoked both at settings-save
 * time and immediately before each outbound request.
 *
 * <p>{@link #validateAndResolve(String)} resolves the host exactly once and returns the
 * validated address so the caller can pin its connection to it. {@code WebhookBanAction} pins
 * the connection for {@code http} (defeating DNS rebinding, the primary use of which targets the
 * plaintext cloud-metadata endpoint). For {@code https}, connection-time pinning is intentionally
 * not applied because supplying an IP literal as the connect host breaks TLS SNI and certificate
 * hostname verification; that path relies on validation immediately before connect plus disabled
 * redirects, leaving a small residual rebinding window documented here.</p>
 */
public final class WebhookUrlValidator {

    private static final String ALLOW_HTTP_PROPERTY = "bflp.webhook.allowHttp";
    private static final String AWS_METADATA_IPV4 = "169.254.169.254";

    private WebhookUrlValidator() {
        // utility
    }

    public static void validateUrl(String url) {
        validateAndResolve(url);
    }

    /**
     * Validates {@code url} and returns the single resolved {@link InetAddress} the caller should
     * connect to. The host is resolved exactly <strong>once</strong> here and every returned
     * address is checked, so a caller that pins its connection to the returned IP closes the
     * DNS-rebinding TOCTOU window between validation and connection (see {@code WebhookBanAction}).
     *
     * @throws IllegalArgumentException if the URL is malformed, uses a disallowed scheme, carries
     *         userinfo, or resolves to any forbidden (internal / metadata) address.
     */
    public static InetAddress validateAndResolve(String url) {
        if (StringUtils.isBlank(url)) {
            throw new IllegalArgumentException("Webhook URL must not be blank");
        }
        final URI uri;
        try {
            uri = new URI(url);
        } catch (Exception e) {
            throw new IllegalArgumentException("Webhook URL is not a valid URI: " + e.getMessage(), e);
        }
        String scheme = uri.getScheme();
        if (scheme == null) {
            throw new IllegalArgumentException("Webhook URL must include a scheme");
        }
        scheme = scheme.toLowerCase(Locale.ROOT);
        boolean allowHttp = Boolean.parseBoolean(System.getProperty(ALLOW_HTTP_PROPERTY, "false"));
        if (!"https".equals(scheme) && !(allowHttp && "http".equals(scheme))) {
            throw new IllegalArgumentException("Webhook URL must use https"
                    + (allowHttp ? " or http" : "") + " (got: " + scheme + ")");
        }
        if (StringUtils.isNotBlank(uri.getUserInfo())) {
            throw new IllegalArgumentException("Webhook URL must not contain userinfo");
        }
        String host = uri.getHost();
        if (StringUtils.isBlank(host)) {
            throw new IllegalArgumentException("Webhook URL must include a host");
        }
        InetAddress[] resolved;
        try {
            resolved = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Webhook host could not be resolved: " + host, e);
        }
        for (InetAddress addr : resolved) {
            if (isForbidden(addr)) {
                throw new IllegalArgumentException("Webhook host resolves to a forbidden address ("
                        + addr.getHostAddress() + ")");
            }
        }
        return resolved[0];
    }

    private static boolean isForbidden(InetAddress addr) {
        if (addr.isLoopbackAddress()
                || addr.isLinkLocalAddress()
                || addr.isSiteLocalAddress()
                || addr.isAnyLocalAddress()
                || addr.isMulticastAddress()) {
            return true;
        }
        if (AWS_METADATA_IPV4.equals(addr.getHostAddress())) {
            return true;
        }
        byte[] bytes = addr.getAddress();
        if (addr instanceof Inet6Address && bytes.length == 16) {
            return isForbiddenIpv6(bytes);
        }
        return false;
    }

    private static boolean isForbiddenIpv6(byte[] bytes) {
        int first = bytes[0] & 0xFF;
        // IPv6 Unique Local Address (fc00::/7) — first byte 0xfc or 0xfd.
        if ((first & 0xFE) == 0xFC) {
            return true;
        }
        // IPv6 link-local fe80::/10
        if ((first & 0xFF) == 0xFE && (bytes[1] & 0xC0) == 0x80) {
            return true;
        }
        return isForbiddenMappedV4(bytes);
    }

    private static boolean isForbiddenMappedV4(byte[] bytes) {
        // IPv4-mapped IPv6 (::ffff:x.x.x.x): first 10 bytes zero, bytes[10]=bytes[11]=0xff
        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) {
                return false;
            }
        }
        if ((bytes[10] & 0xFF) != 0xFF || (bytes[11] & 0xFF) != 0xFF) {
            return false;
        }
        try {
            byte[] v4 = new byte[]{bytes[12], bytes[13], bytes[14], bytes[15]};
            return isForbidden(InetAddress.getByAddress(v4));
        } catch (UnknownHostException e) {
            // 4-byte address never throws; defensive only
            return true;
        }
    }
}
