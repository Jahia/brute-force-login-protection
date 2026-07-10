package org.jahia.community.bruteforceloginprotection.core;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * D2 — regression guard confirming the shipped {@code brute-force-login-protection-administrator}
 * role bundles {@code bruteForceLoginProtectionAdmin} together with {@code administrationAccess}:
 * out of the box, granting this module's admin role still requires granting full
 * administrationAccess too (an operator must author a separate custom role to get true
 * decoupling). Locks in current behavior as a documented divergence, not a bug to fix.
 */
public class RolesXmlPermissionTest {

    @Test
    public void administratorRoleBundlesBothPermissions() throws Exception {
        File rolesXml = new File("src/main/import/roles.xml");
        assertThat(rolesXml).exists();

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        Document doc = factory.newDocumentBuilder().parse(rolesXml);

        NodeList roleNodes = doc.getElementsByTagName("brute-force-login-protection-administrator");
        assertThat(roleNodes.getLength()).isEqualTo(1);

        Element role = (Element) roleNodes.item(0);
        String permissionNames = role.getAttribute("j:permissionNames");

        assertThat(permissionNames).isEqualTo("administrationAccess bruteForceLoginProtectionAdmin");
    }
}
