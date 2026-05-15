package org.jahia.modules.bruteforceloginprotection;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.jcr.RepositoryException;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang.StringUtils;
import org.jahia.modules.bruteforceloginprotection.cache.BruteForceLoginProtectionCacheManager;
import org.jahia.modules.bruteforceloginprotection.cache.IpCacheEntry;
import org.jahia.modules.bruteforceloginprotection.cache.SettingCacheEntry;
import org.jahia.params.valves.AuthValveContext;
import org.jahia.params.valves.BaseAuthValve;
import org.jahia.params.valves.LoginEngineAuthValveImpl;
import org.jahia.pipelines.Pipeline;
import org.jahia.pipelines.PipelineException;
import org.jahia.pipelines.valves.ValveContext;
import org.jahia.services.content.JCRCallback;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.JCRTemplate;
import org.jahia.services.mail.MailService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author fbourasse
 */
@Component(service = {}, immediate = true)
public final class BruteForceLoginProtectionAuthValve extends BaseAuthValve {

    private static final long serialVersionUID = -6551768415414069547L;
    private static final Logger LOGGER = LoggerFactory.getLogger(BruteForceLoginProtectionAuthValve.class);
    private static final String REMOTE_ADDRESS_HEADER = "x-forwarded-for";
    private static final String KEY_SEPARATOR = ",";
    public static final String AUTH_VALVE_ID = "bruteForceLoginProtectionAuthValve";
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy/MM/dd 'at' HH:mm:ss z");
    private final MailService mailService;

    @Reference
    private BruteForceLoginProtectionCacheManager bruteForceLoginProtectionCacheManager;

    @Reference(target = "(type=authentication)")
    private Pipeline authPipeline;

    public BruteForceLoginProtectionAuthValve() {
        super();
        mailService = MailService.getInstance();
    }

    @Activate
    public void start() {
        setId(BruteForceLoginProtectionAuthValve.AUTH_VALVE_ID);
        removeValve(authPipeline);
        addValve(authPipeline, 0, null, null);
    }

    @Deactivate
    public void stop() {
        removeValve(authPipeline);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof BruteForceLoginProtectionAuthValve)) {
            return false;
        }
        return super.equals(obj);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

    @Override
    public void invoke(Object context, ValveContext valveContext) throws PipelineException {
        final AuthValveContext authContext = (AuthValveContext) context;
        final HttpServletRequest request = authContext.getRequest();
        if (handleLoginAttempt(request)) {
            return;
        }
        valveContext.invokeNext(context);
        checkAuthValveResult(request);
    }

    private boolean handleLoginAttempt(HttpServletRequest request) {
        final String remoteAddress = retrieveRemoteAddress(request);
        if (remoteAddress == null) {
            return false;
        }
        final IpCacheEntry ipCacheEntry = bruteForceLoginProtectionCacheManager.getCacheEntryByIp(remoteAddress);
        if (ipCacheEntry == null) {
            return false;
        }
        try {
            if (shouldBlock(remoteAddress, ipCacheEntry)) {
                handleBlockedLogin(request, remoteAddress, ipCacheEntry);
                return true;
            }
        } catch (RepositoryException ex) {
            LOGGER.error("Impossible to retrieve the settings of the brute force login protection", ex);
        }
        return false;
    }

    private boolean shouldBlock(String remoteAddress, IpCacheEntry ipCacheEntry) throws RepositoryException {
        return Boolean.TRUE.equals(JCRTemplate.getInstance().doExecuteWithSystemSessionAsUser(null, null, null, new JCRCallback<Boolean>() {
            @Override
            public Boolean doInJCR(JCRSessionWrapper session) throws RepositoryException {
                final String whiteListIpsStr;
                final Long nbFailedLoginMax;
                final Boolean activated;
                final SettingCacheEntry whitelistIpsCacheEntry = bruteForceLoginProtectionCacheManager.getCacheEntryByProperty(BruteForceLoginProtectionConstants.PROPERTY_WHITELIST_IPS);
                final SettingCacheEntry nbFailedLoginMaxCacheEntry = bruteForceLoginProtectionCacheManager.getCacheEntryByProperty(BruteForceLoginProtectionConstants.PROPERTY_NB_FAILED_LOGIN_MAX);
                final SettingCacheEntry activatedCacheEntry = bruteForceLoginProtectionCacheManager.getCacheEntryByProperty(BruteForceLoginProtectionConstants.PROPERTY_ACTIVATED);
                if (whitelistIpsCacheEntry == null || nbFailedLoginMaxCacheEntry == null || activatedCacheEntry == null) {
                    final JCRNodeWrapper bruteForceLoginProtectionNode = session.getNode(BruteForceLoginProtectionConstants.NODE_PATH);
                    whiteListIpsStr = bruteForceLoginProtectionNode.getPropertyAsString(BruteForceLoginProtectionConstants.PROPERTY_WHITELIST_IPS);
                    nbFailedLoginMax = bruteForceLoginProtectionNode.getProperty(BruteForceLoginProtectionConstants.PROPERTY_NB_FAILED_LOGIN_MAX).getLong();
                    activated = bruteForceLoginProtectionNode.getProperty(BruteForceLoginProtectionConstants.PROPERTY_ACTIVATED).getBoolean();
                    bruteForceLoginProtectionCacheManager.cacheSetting(new SettingCacheEntry(BruteForceLoginProtectionConstants.PROPERTY_WHITELIST_IPS, whiteListIpsStr));
                    bruteForceLoginProtectionCacheManager.cacheSetting(new SettingCacheEntry(BruteForceLoginProtectionConstants.PROPERTY_NB_FAILED_LOGIN_MAX, nbFailedLoginMax));
                    bruteForceLoginProtectionCacheManager.cacheSetting(new SettingCacheEntry(BruteForceLoginProtectionConstants.PROPERTY_ACTIVATED, activated));
                } else {
                    whiteListIpsStr = whitelistIpsCacheEntry.getValue().toString();
                    nbFailedLoginMax = (Long) nbFailedLoginMaxCacheEntry.getValue();
                    activated = (Boolean) activatedCacheEntry.getValue();
                }
                final List<CidrMatcher> whitelistIps = getCidrMatcherList(whiteListIpsStr);
                return activated && !isRemoteAddressWhitelisted(remoteAddress, whitelistIps) && ipCacheEntry.getNbFailedLogins() >= nbFailedLoginMax;
            }
        }));
    }

    private void handleBlockedLogin(HttpServletRequest request, String remoteAddress, IpCacheEntry ipCacheEntry) {
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("The IP {} has tried too many unsuccessful logins, preventing any further attempts", sanitizeForLog(remoteAddress));
        }
        if (!mailService.isEnabled() || !ipCacheEntry.markNotificationSent()) {
            return;
        }
        bruteForceLoginProtectionCacheManager.cacheIp(ipCacheEntry);
        if (!bruteForceLoginProtectionCacheManager.tryRecordNotification(remoteAddress,
                BruteForceLoginProtectionConstants.NOTIFICATION_THROTTLE_SECONDS)) {
            return;
        }
        final String serverName = request.getServerName();
        final String sender = mailService.defaultSender();
        final String recipient = mailService.defaultRecipient();
        final String subject = "[%s] Login blocked for IP %s";
        final String body = "Hi,\n"
                + "\n"
                + "The IP %s has tried too many unsuccessful logins, preventing any further attempts.\n"
                + "\n"
                + "    Connection IP     : %s\n"
                + "\n"
                + "\n"
                + "This email is meant to raise awareness about the security of your services \n"
                + "and to help you to protect them.\n"
                + "\n"
                + "Regards,";
        mailService.sendMessage(sender, recipient, null, null, String.format(subject, serverName, remoteAddress),
                String.format(body, remoteAddress, remoteAddress));
    }

    private void checkAuthValveResult(HttpServletRequest request) {
        final Object valveResult = request.getAttribute(LoginEngineAuthValveImpl.VALVE_RESULT);
        if (valveResult != null && (LoginEngineAuthValveImpl.BAD_PASSWORD.equals(valveResult)
                || LoginEngineAuthValveImpl.UNKNOWN_USER.equals(valveResult))) {

            final String remoteAddress = retrieveRemoteAddress(request);
            if (remoteAddress == null) {
                return;
            }
            String site = request.getParameter("site");
            if (StringUtils.isEmpty(site)) {
                site = "systemsite";
            }

            IpCacheEntry ipCacheEntry = bruteForceLoginProtectionCacheManager.getCacheEntryByIp(remoteAddress);
            if (ipCacheEntry == null) {
                ipCacheEntry = new IpCacheEntry(remoteAddress);
            }

            final int nbFailedLogins = ipCacheEntry.incrementNbFailedLogins();
            bruteForceLoginProtectionCacheManager.cacheIp(ipCacheEntry);

            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("Incorrect login from {} on the server {}, site {}, at {}: {} times",
                        sanitizeForLog(remoteAddress),
                        sanitizeForLog(request.getServerName()),
                        sanitizeForLog(site),
                        ZonedDateTime.now(ZoneId.systemDefault()).format(DATE_FORMAT),
                        nbFailedLogins);
            }
        }
    }

    private String retrieveRemoteAddress(HttpServletRequest request) {
        if (isTrustProxyHeaderEnabled()) {
            final String headerValue = request.getHeader(REMOTE_ADDRESS_HEADER);
            if (StringUtils.isNotBlank(headerValue)) {
                final String[] parts = headerValue.split(KEY_SEPARATOR);
                final String first = parts[0].trim();
                if (!first.isEmpty()) {
                    return first;
                }
            }
        }
        return request.getRemoteAddr();
    }

    private boolean isTrustProxyHeaderEnabled() {
        final SettingCacheEntry cached = bruteForceLoginProtectionCacheManager.getCacheEntryByProperty(
                BruteForceLoginProtectionConstants.PROPERTY_TRUST_PROXY_HEADER);
        if (cached != null) {
            return Boolean.TRUE.equals(cached.getValue());
        }
        try {
            final Boolean value = JCRTemplate.getInstance().doExecuteWithSystemSessionAsUser(null, null, null, session -> {
                if (!session.nodeExists(BruteForceLoginProtectionConstants.NODE_PATH)) {
                    return Boolean.FALSE;
                }
                final JCRNodeWrapper node = session.getNode(BruteForceLoginProtectionConstants.NODE_PATH);
                if (!node.hasProperty(BruteForceLoginProtectionConstants.PROPERTY_TRUST_PROXY_HEADER)) {
                    return Boolean.FALSE;
                }
                return node.getProperty(BruteForceLoginProtectionConstants.PROPERTY_TRUST_PROXY_HEADER).getBoolean();
            });
            final Boolean resolved = value != null ? value : Boolean.FALSE;
            bruteForceLoginProtectionCacheManager.cacheSetting(new SettingCacheEntry(
                    BruteForceLoginProtectionConstants.PROPERTY_TRUST_PROXY_HEADER, resolved));
            return resolved;
        } catch (RepositoryException e) {
            LOGGER.debug("Could not read trust_x_forwarded_for from JCR, defaulting to false", e);
            return false;
        }
    }

    private static boolean isRemoteAddressWhitelisted(String remoteAddress, List<CidrMatcher> whitelistIps) {
        for (CidrMatcher matcher : whitelistIps) {
            if (matcher.matches(remoteAddress)) {
                return true;
            }
        }
        return false;
    }

    private static List<CidrMatcher> getCidrMatcherList(String whitelistIps) {
        if (StringUtils.isBlank(whitelistIps)) {
            return Collections.emptyList();
        }
        final List<CidrMatcher> matchers = new ArrayList<>();
        for (String subnet : StringUtils.split(whitelistIps, KEY_SEPARATOR)) {
            final String trimmed = StringUtils.trimToNull(subnet);
            if (trimmed != null) {
                try {
                    matchers.add(new CidrMatcher(trimmed));
                } catch (IllegalArgumentException ex) {
                    LOGGER.warn("Ignoring invalid CIDR entry in whitelist: {}", trimmed, ex);
                }
            }
        }
        return matchers;
    }

    private static String sanitizeForLog(String value) {
        if (value == null) {
            return null;
        }
        return value.replaceAll("[\r\n]", "");
    }
}
