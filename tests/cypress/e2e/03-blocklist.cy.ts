import {DocumentNode} from 'graphql';

/**
 * E2E coverage for the IP blocklist feature: static CIDR list + dynamic Tor exit-address list.
 *
 * Deliberately NOT tested here: actually being blocked by the blocklist. Unlike bans there is no
 * unban escape hatch — a mistake would lock the harness out of Jahia for the rest of the run.
 * The enforcement decision (including whitelist precedence) is unit-tested in
 * BlocklistServiceTest / AuthValveBlocklistTest; what this spec proves end-to-end is the
 * settings round-trip, validation, status reporting, whitelist-precedence safety, and the UI.
 */
describe('Brute Force Login Protection — blocklist', () => {
    const adminPath = '/jahia/administration/bruteForceLoginProtection';

    // Whitelist covering loopback + the docker bridge networks the Cypress runner can appear from,
    // so the self-lockout safety test below can never lock the harness out.
    const SAFE_WHITELIST = '127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16';

    /* eslint-disable @typescript-eslint/no-var-requires */
    const getGlobalSettings: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getGlobalSettings.graphql');
    const getBlocklistStatus: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getBlocklistStatus.graphql');
    const getConfigReady: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getConfigReady.graphql');
    const saveGlobalSettings: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/mutation/saveGlobalSettings.graphql');
    const refreshTorBlocklist: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/mutation/refreshTorBlocklist.graphql');
    const flush: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/mutation/flush.graphql');
    /* eslint-enable @typescript-eslint/no-var-requires */

    before(() => {
        cy.login();
    });

    const waitForGlobalConfigReady = (): void => {
        cy.apollo({query: getConfigReady, variables: {jail: 'login'}})
            .its('data.bruteForceLoginProtection.configReady.globalReady')
            .should('eq', true);
    };

    afterEach(() => {
        // Restore safe defaults so no blocklist state bleeds into other specs.
        cy.apollo({
            mutation: saveGlobalSettings,
            variables: {
                activated: false,
                whitelistIps: '127.0.0.1/32,::1/128',
                blocklistIps: '',
                torBlocklistEnabled: false
            }
        });
        cy.apollo({mutation: flush});
    });

    it('round-trips blocklist settings through saveGlobalSettings/getGlobalSettings', () => {
        cy.apollo({
            mutation: saveGlobalSettings,
            variables: {
                blocklistIps: '203.0.113.0/24,198.51.100.7/32',
                torBlocklistEnabled: true,
                torBlocklistUrl: 'https://check.torproject.org/exit-addresses',
                torBlocklistRefreshSeconds: 3600
            }
        })
            .its('data.bruteForceLoginProtection.saveGlobalSettings')
            .should('eq', true);

        cy.apollo({query: getGlobalSettings})
            .its('data.bruteForceLoginProtection.globalSettings')
            .should(settings => {
                expect(settings.blocklistIps).to.include('203.0.113.0/24');
                expect(settings.torBlocklistEnabled).to.eq(true);
                expect(settings.torBlocklistUrl).to.include('torproject.org');
                expect(settings.torBlocklistRefreshSeconds).to.eq(3600);
            });
    });

    it('reports the static entry count in blocklistStatus', () => {
        cy.apollo({
            mutation: saveGlobalSettings,
            variables: {blocklistIps: '203.0.113.0/24,2001:db8::/32'}
        });
        waitForGlobalConfigReady();

        cy.apollo({query: getBlocklistStatus})
            .its('data.bruteForceLoginProtection.blocklistStatus')
            .should(status => {
                expect(status.staticEntryCount).to.eq(2);
                expect(status).to.have.property('torEnabled');
                expect(status).to.have.property('torEntryCount');
                expect(status).to.have.property('torLastError');
            });
    });

    it('rejects an invalid static blocklist entry with a GraphQL error', () => {
        cy.apollo({
            mutation: saveGlobalSettings,
            variables: {blocklistIps: '203.0.113.0/24,not-a-cidr'},
            errorPolicy: 'all'
        }).then((result: {graphQLErrors?: Array<{message: string}>; errors?: Array<{message: string}>}) => {
            const errs = result.graphQLErrors ?? result.errors ?? [];
            expect(errs, 'invalid CIDR must be rejected').to.have.length.greaterThan(0);
        });
    });

    it('rejects a non-http(s) Tor blocklist URL with a GraphQL error', () => {
        cy.apollo({
            mutation: saveGlobalSettings,
            variables: {torBlocklistUrl: 'ftp://mirror.internal/exit-addresses'},
            errorPolicy: 'all'
        }).then((result: {graphQLErrors?: Array<{message: string}>; errors?: Array<{message: string}>}) => {
            const errs = result.graphQLErrors ?? result.errors ?? [];
            expect(errs, 'non-http scheme must be rejected').to.have.length.greaterThan(0);
        });
    });

    it('whitelist always wins: an all-covering blocklist does not lock out a whitelisted client', () => {
        cy.apollo({
            mutation: saveGlobalSettings,
            variables: {
                activated: true,
                whitelistIps: SAFE_WHITELIST,
                blocklistIps: '0.0.0.0/0,::/0'
            }
        })
            .its('data.bruteForceLoginProtection.saveGlobalSettings')
            .should('eq', true);
        waitForGlobalConfigReady();

        // A fresh unauthenticated session must still be able to log in.
        cy.clearCookies();
        cy.login();
        cy.apollo({query: getGlobalSettings})
            .its('data.bruteForceLoginProtection.globalSettings')
            .should(settings => {
                expect(settings.activated).to.eq(true);
            });
    });

    it('refreshTorBlocklist reports a structured result and updates the attempt timestamp', () => {
        cy.apollo({
            mutation: saveGlobalSettings,
            variables: {torBlocklistEnabled: true}
        });
        waitForGlobalConfigReady();

        // The fetch hits an external service (or fails offline) — assert the plumbing,
        // not the network: a structured result and a recorded attempt.
        cy.apollo({mutation: refreshTorBlocklist})
            .its('data.bruteForceLoginProtection.refreshTorBlocklist')
            .should(result => {
                expect(result).to.have.property('success');
                expect(result).to.have.property('message');
            });

        cy.apollo({query: getBlocklistStatus})
            .its('data.bruteForceLoginProtection.blocklistStatus')
            .should(status => {
                expect(status.torLastAttemptTime, 'an attempt must have been recorded').to.be.greaterThan(0);
            });
    });

    it('refreshTorBlocklist fails cleanly when the Tor blocklist is disabled', () => {
        cy.apollo({
            mutation: saveGlobalSettings,
            variables: {torBlocklistEnabled: false}
        });
        waitForGlobalConfigReady();

        cy.apollo({mutation: refreshTorBlocklist})
            .its('data.bruteForceLoginProtection.refreshTorBlocklist')
            .should(result => {
                expect(result.success).to.eq(false);
            });
    });

    it('shows the Blocklist tab with its form in the admin UI', () => {
        cy.login();
        cy.visit(adminPath);
        cy.get('[role="tab"]').contains(/Blocklist/i).click();
        cy.get('#bflp-blk-static').should('be.visible');
        cy.get('#bflp-blk-tor-url').should('be.visible');
        cy.contains('button', /Fetch now/i).should('be.visible');
    });
});
