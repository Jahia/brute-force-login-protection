package org.jahia.modules.bruteforceloginprotection.flow;

import java.io.Serializable;
import javax.jcr.RepositoryException;
import org.apache.commons.lang.StringUtils;
import org.apache.jackrabbit.commons.webdav.JcrRemotingConstants;
import org.apache.jackrabbit.core.fs.FileSystem;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.decorator.JCRSiteNode;
import org.jahia.services.render.RenderContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.RequestContext;

public class BruteForceLoginProtectionHandler implements Serializable {

    private static final long serialVersionUID = -6552768415414069547L;
    private static final Logger LOGGER = LoggerFactory.getLogger(BruteForceLoginProtectionHandler.class);
    private static final String NODE_TYPE = "jnt:bruteForceLoginProtection";
    private static final long NB_MAX_FAILED_LOGIN = 6L;
    public static final String PROPERTY_ACTIVATED = "activated";
    public static final String PROPERTY_NB_FAILED_LOGIN_MAX = "nb_failed_login_max";
    public static final String PROPERTY_WHITELIST_IPS = "whitelist_ips";
    public static final String NODE_NAME = "bruteforceloginprotection";
    public static final String NODE_SETTINGS_PATH = JcrRemotingConstants.ROOT_ITEM_PATH + "settings";
    public static final String NODE_PATH = NODE_SETTINGS_PATH + FileSystem.SEPARATOR + NODE_NAME;

    public void store(RequestContext ctx) {
        try {
            final JCRSiteNode currentSite = getRenderContext(ctx).getSite();
            final JCRSessionWrapper session = currentSite.getSession();
            final JCRNodeWrapper settingsNode = session.getNode(NODE_SETTINGS_PATH);
            if (settingsNode.hasNode(NODE_NAME)) {
                final JCRNodeWrapper bruteForceLoginProtectionNode = settingsNode.getNode(NODE_NAME);
                final String activatedStr = ctx.getRequestParameters().get(PROPERTY_ACTIVATED);
                final String whiteListIps = ctx.getRequestParameters().get(PROPERTY_WHITELIST_IPS);
                final Integer nbFailedLoginMax = ctx.getRequestParameters().getInteger(PROPERTY_NB_FAILED_LOGIN_MAX);
                bruteForceLoginProtectionNode.setProperty(PROPERTY_ACTIVATED, activatedStr != null);
                if (!StringUtils.isEmpty(whiteListIps)) {
                    bruteForceLoginProtectionNode.setProperty(PROPERTY_WHITELIST_IPS, whiteListIps);
                }
                if (nbFailedLoginMax != null) {
                    bruteForceLoginProtectionNode.setProperty(PROPERTY_NB_FAILED_LOGIN_MAX, nbFailedLoginMax);
                }
                session.save();
            } else if (LOGGER.isInfoEnabled()) {
                LOGGER.info(String.format("The node %s does not exist, impossible to save", NODE_PATH));
            }
        } catch (RepositoryException ex) {
            LOGGER.error("Impossible to verify the current site", ex);
        }
    }

    public JCRNodeWrapper getBruteForceLoginProtectionNode(RequestContext ctx) {
        JCRNodeWrapper bruteForceLoginProtectionNode = null;
        try {
            final JCRSiteNode currentSite = getRenderContext(ctx).getSite();
            final JCRSessionWrapper session = currentSite.getSession();
            final JCRNodeWrapper settingsNode = session.getNode(NODE_SETTINGS_PATH);
            if (settingsNode.hasNode(NODE_NAME)) {
                bruteForceLoginProtectionNode = settingsNode.getNode(NODE_NAME);
            } else {
                bruteForceLoginProtectionNode = settingsNode.addNode(NODE_NAME, NODE_TYPE);
                bruteForceLoginProtectionNode.setProperty(PROPERTY_WHITELIST_IPS, "127.0.0.1/32");
                bruteForceLoginProtectionNode.setProperty(PROPERTY_ACTIVATED, false);
                bruteForceLoginProtectionNode.setProperty(PROPERTY_NB_FAILED_LOGIN_MAX, NB_MAX_FAILED_LOGIN);
                session.save();
            }
        } catch (RepositoryException ex) {
            LOGGER.error("Impossible to verify the current site", ex);
        }
        return bruteForceLoginProtectionNode;

    }

    private RenderContext getRenderContext(RequestContext ctx) {
        return (RenderContext) ctx.getExternalContext().getRequestMap().get("renderContext");
    }
}
