package org.jahia.modules.bruteforceloginprotection;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import javax.jcr.RepositoryException;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang.StringUtils;
import org.jahia.modules.bruteforceloginprotection.cache.BruteForceLoginProtectionCacheManager;
import org.jahia.modules.bruteforceloginprotection.cache.IpCacheEntry;
import org.jahia.modules.bruteforceloginprotection.cache.SettingCacheEntry;
import org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants;
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
    private static final String LOGIN_URI = "/cms/login";
    public static final String AUTH_VALVE_ID = "bruteForceLoginProtectionAuthValve";
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd 'at' HH:mm:ss z");
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
    public void invoke(Object context, ValveContext valveContext) throws PipelineException {
        final AuthValveContext authContext = (AuthValveContext) context;
        final HttpServletRequest request = authContext.getRequest();
        final String requestURI = request.getRequestURI();
        final boolean isLogin = LOGIN_URI.equals(requestURI);
        if (isLogin && handleLoginAttempt(request)) {
            return;
        }
        valveContext.invokeNext(context);
        if (isLogin) {
            checkAuthValveResult(request);
        }
    }

    private boolean handleLoginAttempt(HttpServletRequest request) {
        final String remoteAddress = retrieveRemoteAddress(request);
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
                return activated && !isRemoteAddressWhitelisted(remoteAddress, whitelistIps, true) && ipCacheEntry.getNbFailedLogins() >= nbFailedLoginMax;
            }
        }));
    }

    private void handleBlockedLogin(HttpServletRequest request, String remoteAddress, IpCacheEntry ipCacheEntry) {
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info(String.format("The IP %s has tried to much unsuccessful logins, preventing any further tried", remoteAddress).replaceAll("[\r\n]", ""));
        }
        if (ipCacheEntry.isNotificationSent() || !mailService.isEnabled()) {
            return;
        }
        ipCacheEntry.setNotificationSent(true);
        bruteForceLoginProtectionCacheManager.cacheIp(ipCacheEntry);
        final String serverName = request.getServerName();
        final String sender = mailService.defaultSender();
        final String recipient = mailService.defaultRecipient();
        final String subject = "[%s] Login blocked for IP %s";
        final String body = "Hi,\n"
                + "\n"
                + "The IP %s has tried to much unsuccessful logins, preventing any further tried.\n"
                + "\n"
                + "    Connection IP     : %s\n"
                + "\n"
                + "\n"
                + "This email is meant to raise awareness about the secuirty of your services \n"
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
            String site = request.getParameter("site");
            if (StringUtils.isEmpty(site)) {
                site = "systemsite";
            }

            IpCacheEntry ipCacheEntry = bruteForceLoginProtectionCacheManager.getCacheEntryByIp(remoteAddress);
            if (ipCacheEntry == null) {
                ipCacheEntry = new IpCacheEntry(remoteAddress);
            }

            int nbFailedLogins = ipCacheEntry.getNbFailedLogins() + 1;
            ipCacheEntry.setNbFailedLogins(nbFailedLogins);
            bruteForceLoginProtectionCacheManager.cacheIp(ipCacheEntry);

            final String serverName = request.getServerName();
            final Date loginDate = new Date();
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info(String.format("Incorrect login from %s on the server %s, site %s, at %s: %d times", remoteAddress, serverName, site, dateFormat.format(loginDate), nbFailedLogins).replaceAll("[\r\n]", ""));
            }
        }
    }

    private String retrieveRemoteAddress(HttpServletRequest request) {
        String remoteAddress = request.getHeader(REMOTE_ADDRESS_HEADER);
        if (remoteAddress == null) {
            remoteAddress = request.getRemoteAddr();
        }
        return remoteAddress;
    }

    private static boolean isRemoteAddressWhitelisted(String remoteAddress, List<CidrMatcher> whitelistIps, boolean useFirstRemoteAddress) {
        final String[] remoteAddresses = remoteAddress.split(KEY_SEPARATOR);
        final String remoteAddressToCheck = useFirstRemoteAddress
                ? remoteAddresses[0].trim()
                : remoteAddresses[remoteAddresses.length - 1].trim();
        for (CidrMatcher matcher : whitelistIps) {
            if (matcher.matches(remoteAddressToCheck)) {
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
}
