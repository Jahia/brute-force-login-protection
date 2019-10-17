package org.jahia.modules.bruteforceloginprotection;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import javax.jcr.RepositoryException;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.net.util.SubnetUtils;
import org.jahia.modules.bruteforceloginprotection.cache.IpCacheEntry;
import org.jahia.modules.bruteforceloginprotection.cache.IpCacheManager;
import org.jahia.modules.bruteforceloginprotection.flow.BruteForceLoginProtectionHandler;
import org.jahia.params.valves.AuthValveContext;
import org.jahia.params.valves.AutoRegisteredBaseAuthValve;
import org.jahia.params.valves.LoginEngineAuthValveImpl;
import org.jahia.pipelines.PipelineException;
import org.jahia.pipelines.valves.ValveContext;
import org.jahia.services.content.JCRCallback;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.mail.MailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.jahia.services.content.JCRTemplate;

/**
 *
 * @author fbourasse
 */
public final class MyCustomAuthValve extends AutoRegisteredBaseAuthValve {

    private static final long serialVersionUID = -6551768415414069547L;
    private static final Logger LOGGER = LoggerFactory.getLogger(MyCustomAuthValve.class);
    private static final String REMOTE_ADDRESS_HEADER = "x-forwarded-for";
    private static final String KEY_SEPARATOR = ",";
    private static final String LOGIN_URI = "/cms/login";
    private static final int NB_MAX_FAILED_LOGIN = 6;
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd 'at' HH:mm:ss z");
    private MailService mailService;
    private IpCacheManager ipCacheManager;

    @Override
    public void invoke(Object context, ValveContext valveContext) throws PipelineException {
        // Retrieve the context, the current request and the header value
        final AuthValveContext authContext = (AuthValveContext) context;
        final HttpServletRequest request = authContext.getRequest();
        final String requestURI = request.getRequestURI();
        if (LOGIN_URI.equals(requestURI)) {
            final String remoteAddress = retrieveRemoteAddress(request);

            final IpCacheEntry ipCacheEntry = ipCacheManager.getCacheEntryByIp(remoteAddress);
            if (ipCacheEntry != null && ipCacheEntry.getNbFailedLogins() >= NB_MAX_FAILED_LOGIN) {
                try {
                    final boolean toBlock = JCRTemplate.getInstance().doExecuteWithSystemSessionAsUser(null, null, null, new JCRCallback<Boolean>() {

                        @Override
                        public Boolean doInJCR(JCRSessionWrapper session) throws RepositoryException {
                            final JCRNodeWrapper bruteForceLoginProtectionNode = session.getNode(BruteForceLoginProtectionHandler.NODE_PATH);
                            final String whiteListIpsStr = bruteForceLoginProtectionNode.getPropertyAsString(BruteForceLoginProtectionHandler.PROPERTY_WHITELIST_IPS);
                            final List<SubnetUtils> whitelistIps = getSubnetUtilsList(whiteListIpsStr);

                            return bruteForceLoginProtectionNode.getProperty(BruteForceLoginProtectionHandler.PROPERTY_ACTIVATED).getBoolean()
                                    && !isRemoteAddressWhitelisted(remoteAddress, whitelistIps, true);
                        }
                    });

                    if (toBlock) {
                        if (LOGGER.isInfoEnabled()) {
                            LOGGER.info(String.format("The IP %s has tried to much unsuccessful logins, preventing any further tried", remoteAddress).replaceAll("[\r\n]", ""));
                        }
                        if (mailService.isEnabled()) {
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
                        return;
                    }
                } catch (RepositoryException ex) {
                    LOGGER.error("Impossible to retrieve the settings of the brute force login protection", ex);
                }
            }
        }
        // invoke next valve to get the final result
        valveContext.invokeNext(context);
        if (LOGIN_URI.equals(requestURI)) {
            checkAuthValveResult(request);
        }

    }

    public void setMailService(MailService mailService) {
        this.mailService = mailService;
    }

    public void setIpCacheManager(IpCacheManager ipCacheManager) {
        this.ipCacheManager = ipCacheManager;
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

            IpCacheEntry ipCacheEntry = ipCacheManager.getCacheEntryByIp(remoteAddress);
            if (ipCacheEntry == null) {
                ipCacheEntry = new IpCacheEntry(remoteAddress);
            }

            int nbFailedLogins = ipCacheEntry.getNbFailedLogins() + 1;
            ipCacheEntry.setNbFailedLogins(nbFailedLogins);
            ipCacheManager.cacheIp(ipCacheEntry);

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

    private static boolean isRemoteAddressWhitelisted(String remoteAddress, List<SubnetUtils> whitelistIps, boolean useFirstRemoteAddress) {
        boolean isInRange = false;
        int index = 0;
        final String[] remoteAddresses = remoteAddress.split(KEY_SEPARATOR);
        final String remoteAddressToCheck;
        if (useFirstRemoteAddress) {
            remoteAddressToCheck = remoteAddresses[0];
        } else {
            remoteAddressToCheck = remoteAddresses[remoteAddresses.length - 1];
        }
        while (!isInRange && index < whitelistIps.size()) {
            final SubnetUtils utils = whitelistIps.get(index);
            try {
                isInRange = utils.getInfo().isInRange(remoteAddressToCheck);
            } catch (IllegalArgumentException ex) {
                LOGGER.warn("Impossible to check remote address", ex);
            }
            index++;
        }
        return isInRange;
    }

    private static List<SubnetUtils> getSubnetUtilsList(String whitelistIps) {
        if (StringUtils.isBlank(whitelistIps)) {
            return Collections.emptyList();
        }
        final List<SubnetUtils> subnets = new ArrayList<>();
        for (String subnet : StringUtils.split(whitelistIps, KEY_SEPARATOR)) {
            if (StringUtils.isNotEmpty(subnet)) {
                final SubnetUtils subnetUtils = new SubnetUtils(subnet);
                subnetUtils.setInclusiveHostCount(true);
                subnets.add(subnetUtils);
            }
        }
        return subnets;
    }
}