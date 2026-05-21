package org.jahia.modules.bruteforceloginprotection.spi;

import org.jahia.modules.bruteforceloginprotection.core.BanContext;

public interface BanAction {
    String getName();

    int priority();

    void onBan(BanContext context);

    void onUnban(BanContext context);
}
