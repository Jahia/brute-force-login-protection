import {DocumentNode} from 'graphql';

describe('Brute Force Login Protection', () => {
    const adminPath = '/jahia/administration/bruteForceLoginProtection';

    /* eslint-disable @typescript-eslint/no-var-requires */
    const getGlobalSettings: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getGlobalSettings.graphql');
    const getJails: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getJails.graphql');
    const getBannedIps: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getBannedIps.graphql');
    const getAuditLog: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getAuditLog.graphql');
    const getClusterStatus: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getClusterStatus.graphql');
    const getConfigReady: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getConfigReady.graphql');
    const saveGlobalSettings: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/mutation/saveGlobalSettings.graphql');
    const saveJail: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/mutation/saveJail.graphql');
    const deleteJail: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/mutation/deleteJail.graphql');
    const banIp: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/mutation/banIp.graphql');
    const unbanIp: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/mutation/unbanIp.graphql');
    const flush: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/mutation/flush.graphql');
    const clearAuditLog: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/mutation/clearAuditLog.graphql');
    /* eslint-enable @typescript-eslint/no-var-requires */

    before(() => {
        cy.login();
    });

    // Cypress retries .should() until it passes or the assertion timeout elapses; the
    // GraphQL mutations that write global + per-jail config are async on the OSGi side
    // (ConfigurationAdmin event dispatch), so any test that depends on the new config
    // being live must wait on this probe before exercising the ban path.
    const waitForConfigReady = (jail: string): void => {
        cy.apollo({query: getConfigReady, variables: {jail}})
            .its('data.bruteForceLoginProtection.configReady')
            .should((r: {globalReady: boolean; jailReady: boolean}) => {
                expect(r.globalReady, 'global config holder must have received an update').to.eq(true);
                expect(r.jailReady, `jail "${jail}" must be registered`).to.eq(true);
            });
    };

    afterEach(() => {
        cy.apollo({mutation: flush});
    });

    it('returns global settings via GraphQL', () => {
        cy.apollo({query: getGlobalSettings})
            .its('data.bruteForceLoginProtection.globalSettings')
            .should(settings => {
                expect(settings).to.have.property('activated');
                expect(settings).to.have.property('whitelistIps');
                expect(settings).to.have.property('ignorePatterns');
                expect(settings).to.have.property('trustProxyHeader');
                expect(settings).to.have.property('recidiveFactor');
                expect(settings).to.have.property('maxBanTimeSeconds');
            });
    });

    it('saves global settings via GraphQL and returns true', () => {
        cy.apollo({
            mutation: saveGlobalSettings,
            variables: {
                activated: true,
                whitelistIps: '127.0.0.1/32,::1/128',
                recidiveFactor: 2.0,
                maxBanTimeSeconds: 86400
            }
        })
            .its('data.bruteForceLoginProtection.saveGlobalSettings')
            .should('eq', true);
    });

    it('saves global settings and reads them back consistently', () => {
        cy.apollo({
            mutation: saveGlobalSettings,
            variables: {
                activated: true,
                whitelistIps: '127.0.0.1/32,::1/128,192.168.0.0/24',
                trustProxyHeader: true,
                recidiveFactor: 3.0,
                maxBanTimeSeconds: 7200
            }
        });
        cy.apollo({query: getGlobalSettings})
            .its('data.bruteForceLoginProtection.globalSettings')
            .should(settings => {
                expect(settings.activated).to.eq(true);
                expect(settings.whitelistIps).to.include('192.168.0.0/24');
                expect(settings.trustProxyHeader).to.eq(true);
                expect(settings.recidiveFactor).to.eq(3.0);
                expect(settings.maxBanTimeSeconds).to.eq(7200);
            });
    });

    it('lists jails and includes the bootstrapped login jail', () => {
        cy.apollo({query: getJails})
            .its('data.bruteForceLoginProtection.jails')
            .should((jails: Array<{name: string}>) => {
                expect(jails).to.be.an('array');
                const names = jails.map(j => j.name);
                expect(names).to.include('login');
            });
    });

    it('creates and updates a jail', () => {
        cy.apollo({
            mutation: saveJail,
            variables: {
                name: 'test',
                enabled: true,
                maxRetry: 3,
                findTimeSeconds: 60,
                banTimeSeconds: 120
            }
        })
            .its('data.bruteForceLoginProtection.saveJail')
            .should('eq', true);

        cy.apollo({query: getJails})
            .its('data.bruteForceLoginProtection.jails')
            .should((jails: Array<{name: string; maxRetry: number}>) => {
                const found = jails.find(j => j.name === 'test');
                expect(found, 'jail "test" must exist').to.exist;
                expect(found.maxRetry).to.eq(3);
            });
    });

    it('deletes a jail', () => {
        cy.apollo({
            mutation: saveJail,
            variables: {name: 'test', enabled: true, maxRetry: 3, findTimeSeconds: 60, banTimeSeconds: 120}
        });
        cy.apollo({mutation: deleteJail, variables: {name: 'test'}})
            .its('data.bruteForceLoginProtection.deleteJail')
            .should('eq', true);

        cy.apollo({query: getJails})
            .its('data.bruteForceLoginProtection.jails')
            .should((jails: Array<{name: string}>) => {
                const names = jails.map(j => j.name);
                expect(names).to.not.include('test');
            });
    });

    it('banIp + unbanIp round-trip', () => {
        cy.apollo({
            mutation: banIp,
            variables: {ip: '10.0.0.99', jail: 'login', durationSeconds: 60, reason: 'cypress test'}
        })
            .its('data.bruteForceLoginProtection.banIp')
            .should('eq', true);

        cy.apollo({query: getBannedIps})
            .its('data.bruteForceLoginProtection.bannedIps')
            .should((bans: Array<{ip: string}>) => {
                const ips = bans.map(b => b.ip);
                expect(ips).to.include('10.0.0.99');
            });

        cy.apollo({mutation: unbanIp, variables: {ip: '10.0.0.99'}})
            .its('data.bruteForceLoginProtection.unbanIp')
            .should('eq', true);

        cy.apollo({query: getBannedIps})
            .its('data.bruteForceLoginProtection.bannedIps')
            .should((bans: Array<{ip: string}>) => {
                const ips = bans.map(b => b.ip);
                expect(ips).to.not.include('10.0.0.99');
            });
    });

    it('audit log records the ban', () => {
        cy.apollo({
            mutation: banIp,
            variables: {ip: '10.0.0.100', jail: 'login', durationSeconds: 60, reason: 'cypress audit test'}
        });

        cy.apollo({query: getAuditLog, variables: {limit: 10}})
            .its('data.bruteForceLoginProtection.auditLog')
            .should((entries: Array<{event: string; ip: string}>) => {
                const banned = entries.filter(e => e.event === 'BAN' && e.ip === '10.0.0.100');
                expect(banned.length, 'at least one BAN audit entry for the IP').to.be.greaterThan(0);
            });
    });

    it('clears the audit log', () => {
        cy.apollo({mutation: clearAuditLog})
            .its('data.bruteForceLoginProtection.clearAuditLog')
            .should('eq', true);

        cy.apollo({query: getAuditLog, variables: {limit: 10}})
            .its('data.bruteForceLoginProtection.auditLog')
            .should((entries: unknown[]) => {
                expect(entries).to.be.an('array').that.has.length(0);
            });
    });

    it('returns cluster status with hazelcast running', () => {
        cy.apollo({query: getClusterStatus})
            .its('data.bruteForceLoginProtection.clusterStatus')
            .should(status => {
                expect(status.hazelcastRunning).to.eq(true);
                expect(status.nodeCount).to.be.greaterThan(0);
            });
    });

    it('blocks login from an IP after reaching the max failed attempts', () => {
        cy.login();

        cy.apollo({mutation: flush});

        // Activate protection + tighten the "login" jail so the test runs quickly
        cy.apollo({
            mutation: saveGlobalSettings,
            variables: {
                activated: true,
                whitelistIps: '',
                recidiveFactor: 1.0,
                maxBanTimeSeconds: 60
            }
        });
        cy.apollo({
            mutation: saveJail,
            variables: {
                name: 'login',
                enabled: true,
                maxRetry: 2,
                findTimeSeconds: 60,
                banTimeSeconds: 15
            }
        });

        // Block until the OSGi listeners have processed both mutations — otherwise the
        // tracker reads default config (activated=false / maxRetry=6) and the ban never fires.
        waitForConfigReady('login');

        cy.logout();
        cy.clearCookies();

        for (let i = 0; i < 2; i++) {
            cy.request({
                method: 'POST',
                url: '/cms/login',
                form: true,
                body: {username: 'root', password: 'bad_password', redirect: '/'},
                followRedirect: false,
                failOnStatusCode: false
            });
        }

        // Even valid credentials must now fail — the IP is banned
        cy.request({
            method: 'POST',
            url: '/cms/login',
            form: true,
            body: {
                username: 'root',
                password: Cypress.env('SUPER_USER_PASSWORD') || 'root1234'
            },
            followRedirect: true,
            failOnStatusCode: false
        });

        cy.intercept(adminPath).as('page');
        cy.visit(adminPath, {failOnStatusCode: false});
        cy.wait('@page').its('response.statusCode').should('equal', 401);

        // Wait out the (short) ban window
        cy.wait(20000);

        cy.login();
        cy.visit(adminPath, {failOnStatusCode: false});
        cy.wait('@page').its('response.statusCode').should('equal', 200);
    });

    it('blocks HTTP Basic auth from an IP after reaching the max failed attempts', () => {
        cy.login();

        cy.apollo({mutation: flush});

        cy.apollo({
            mutation: saveGlobalSettings,
            variables: {
                activated: true,
                whitelistIps: '',
                recidiveFactor: 1.0,
                maxBanTimeSeconds: 60
            }
        });
        cy.apollo({
            mutation: saveJail,
            variables: {
                name: 'login',
                enabled: true,
                maxRetry: 2,
                findTimeSeconds: 60,
                banTimeSeconds: 15
            }
        });

        waitForConfigReady('login');

        cy.logout();
        cy.clearCookies();

        const badAuth = 'Basic ' + btoa('root:bad_password');

        for (let i = 0; i < 2; i++) {
            cy.request({
                method: 'GET',
                url: adminPath,
                headers: {Authorization: badAuth},
                followRedirect: false,
                failOnStatusCode: false
            });
        }

        // Even valid Basic credentials must now fail — the IP is banned
        const goodAuth = 'Basic ' + btoa('root:' + (Cypress.env('SUPER_USER_PASSWORD') || 'root1234'));
        cy.request({
            method: 'GET',
            url: adminPath,
            headers: {Authorization: goodAuth},
            followRedirect: false,
            failOnStatusCode: false
        }).its('status').should('equal', 401);

        // Audit log captured the BAN, and at least one failure carries source=basic-auth-valve

        cy.logout();
        cy.clearCookies();
        cy.wait(20000);
        cy.login();
        cy.apollo({query: getAuditLog, variables: {limit: 50}})
            .its('data.bruteForceLoginProtection.auditLog')
            .should((entries: Array<{event: string; source: string; ip: string}>) => {
                const bans = entries.filter(e => e.event === 'BAN');
                expect(bans.length, 'at least one BAN event recorded').to.be.greaterThan(0);
                const basic = entries.filter(e => e.source === 'basic-auth-valve');
                expect(basic.length, 'at least one audit entry sourced from basic-auth-valve').to.be.greaterThan(0);
            });

        // Wait out the (short) ban window so subsequent tests can re-authenticate
        // eslint-disable-next-line cypress/no-unnecessary-waiting
        cy.wait(20000);
    });

    it('blocks Personal API token auth from an IP after reaching the max failed attempts', () => {
        cy.login();

        cy.apollo({mutation: flush});

        cy.apollo({
            mutation: saveGlobalSettings,
            variables: {
                activated: true,
                whitelistIps: '',
                recidiveFactor: 1.0,
                maxBanTimeSeconds: 60
            }
        });
        cy.apollo({
            mutation: saveJail,
            variables: {
                name: 'login',
                enabled: true,
                maxRetry: 2,
                findTimeSeconds: 60,
                banTimeSeconds: 15
            }
        });

        waitForConfigReady('login');

        cy.logout();
        cy.clearCookies();

        // TokenAuthValve listens on /modules/graphql + /modules/api/* by default; an invalid
        // token silently leaves currentUser=guest, so BFLP detects it post-invokeNext.
        const tokenPath = '/modules/graphql';
        const badToken = 'APIToken not-a-real-token-xxxxxxxxxxxxxxxxxxxx';

        for (let i = 0; i < 2; i++) {
            cy.request({
                method: 'POST',
                url: tokenPath,
                headers: {Authorization: badToken, 'Content-Type': 'application/json'},
                body: {query: '{ __typename }'},
                followRedirect: false,
                failOnStatusCode: false
            });
        }

        // Third attempt with the same (still-invalid) token must be rejected by the ban gate,
        // not by token verification — but either way the request stays unauthenticated.
        cy.request({
            method: 'POST',
            url: tokenPath,
            headers: {Authorization: badToken, 'Content-Type': 'application/json'},
            body: {query: '{ __typename }'},
            followRedirect: false,
            failOnStatusCode: false
        });

        // Wait out the ban window before logging in to read the audit log — the test runner's
        // own IP is the one we just banned.
        cy.logout();
        cy.clearCookies();
        cy.wait(20000);
        cy.login();
        cy.apollo({query: getAuditLog, variables: {limit: 50}})
            .its('data.bruteForceLoginProtection.auditLog')
            .should((entries: Array<{event: string; source: string; ip: string}>) => {
                const bans = entries.filter(e => e.event === 'BAN');
                expect(bans.length, 'at least one BAN event recorded').to.be.greaterThan(0);
                const apiToken = entries.filter(e => e.source === 'api-token-valve');
                expect(apiToken.length, 'at least one audit entry sourced from api-token-valve').to.be.greaterThan(0);
            });

        // eslint-disable-next-line cypress/no-unnecessary-waiting
        cy.wait(20000);
    });

    /* ---------------- UI smoke tests (defensive, text-based selectors) ---------------- */

    it('shows the admin panel with the main tabs', () => {
        cy.login();
        cy.visit(adminPath);

        // Tabs labelled General / Jails / Bans / Audit log / Integrations
        cy.contains(/General/i).should('be.visible');
        cy.contains(/Jails/i).should('be.visible');
        cy.contains(/Bans/i).should('be.visible');
        cy.contains(/Audit log/i).should('be.visible');
    });

    it('shows the Save button in the General tab', () => {
        cy.login();
        cy.visit(adminPath);
        cy.contains('button', /Save/i).should('be.visible');
    });

    it('shows the Flush all danger button', () => {
        cy.login();
        cy.visit(adminPath);
        cy.contains('button', /Flush all/i).should('be.visible');
    });
});
