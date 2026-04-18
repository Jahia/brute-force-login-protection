import {DocumentNode} from 'graphql';

describe('Brute Force Login Protection', () => {
    const adminPath = '/jahia/administration/bruteForceLoginProtection';

    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const getSettings: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getSettings.graphql');
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const getTrackedIps: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getTrackedIps.graphql');
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const saveSettings: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/mutation/saveSettings.graphql');
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const flushCache: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/mutation/flushCache.graphql');
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const unblockIp: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/mutation/unblockIp.graphql');

    before(() => {
        cy.login();
    });

    afterEach(() => {
        cy.apollo({mutation: flushCache});
    });

    it('returns settings via GraphQL', () => {
        cy.apollo({query: getSettings})
            .its('data.bruteForceLoginProtectionSettings')
            .should(settings => {
                expect(settings).to.have.property('activated');
                expect(settings).to.have.property('nbFailedLoginMax');
                expect(settings).to.have.property('whitelistIps');
                expect(settings).to.have.property('timeToIdle');
            });
    });

    it('saves settings via GraphQL and returns true', () => {
        cy.apollo({
            mutation: saveSettings,
            variables: {
                activated: true,
                nbFailedLoginMax: 5,
                whitelistIps: '127.0.0.1/32,::1/128'
            }
        })
            .its('data.bruteForceLoginProtectionSaveSettings')
            .should('eq', true);
    });

    it('saves settings and reads them back consistently', () => {
        const threshold = 8;
        cy.apollo({
            mutation: saveSettings,
            variables: {
                activated: true,
                nbFailedLoginMax: threshold,
                whitelistIps: '127.0.0.1/32,::1/128,192.168.0.0/24'
            }
        });
        cy.apollo({query: getSettings})
            .its('data.bruteForceLoginProtectionSettings')
            .should(settings => {
                expect(settings.activated).to.eq(true);
                expect(settings.nbFailedLoginMax).to.eq(threshold);
                expect(settings.whitelistIps).to.include('192.168.0.0/24');
            });
    });

    it('saves timeToIdle via GraphQL and reads it back consistently', () => {
        const tti = 1800;
        cy.apollo({
            mutation: saveSettings,
            variables: {
                activated: true,
                nbFailedLoginMax: 6,
                whitelistIps: '127.0.0.1/32,::1/128',
                timeToIdle: tti
            }
        });
        cy.apollo({query: getSettings})
            .its('data.bruteForceLoginProtectionSettings')
            .should(settings => {
                expect(settings.timeToIdle).to.eq(tti);
            });
    });

    it('flushes the cache via GraphQL and returns true', () => {
        cy.apollo({mutation: flushCache})
            .its('data.bruteForceLoginProtectionFlushCache')
            .should('eq', true);
    });

    it('returns an empty tracked IPs list via GraphQL when no failures occurred', () => {
        cy.apollo({mutation: flushCache});
        cy.apollo({query: getTrackedIps})
            .its('data.bruteForceLoginProtectionTrackedIps')
            .should('be.an', 'array');
    });

    it('unblocks an IP via GraphQL and returns true', () => {
        cy.apollo({
            mutation: unblockIp,
            variables: {ip: '10.0.0.1'}
        })
            .its('data.bruteForceLoginProtectionUnblockIp')
            .should('eq', true);
    });

    it('shows the admin panel with all form fields', () => {
        cy.login();
        cy.visit(adminPath);

        cy.get('#bflp-max').should('be.visible');
        cy.get('#bflp-whitelist').should('be.visible');
        cy.get('#bflp-tti').should('be.visible');
    });

    it('shows the save button in the admin panel', () => {
        cy.login();
        cy.visit(adminPath);

        cy.contains('button', 'Save').should('be.visible');
    });

    it('shows the tracked IPs section with flush cache button', () => {
        cy.login();
        cy.visit(adminPath);

        cy.contains('button', 'Flush cache').should('be.visible');
    });

    it('updates the failed login threshold via the UI and saves successfully', () => {
        cy.login();
        cy.visit(adminPath);

        cy.get('#bflp-max').should('be.visible');
        cy.get('#bflp-max').clear();
        cy.get('#bflp-max').type('10');

        cy.contains('button', 'Save').click();

        cy.get('[class*="bflp_alert--success"]').should('be.visible');
    });

    it('disables the service via the UI toggle and saves', () => {
        cy.login();
        cy.visit(adminPath);

        // Ensure service is enabled first via GraphQL
        cy.apollo({
            mutation: saveSettings,
            variables: {
                activated: true,
                nbFailedLoginMax: 6,
                whitelistIps: '127.0.0.1/32,::1/128'
            }
        });
        cy.reload();

        cy.get('input[type="checkbox"]').first().uncheck({force: true});
        cy.contains('button', 'Save').click();

        cy.get('[class*="bflp_alert--success"]').should('be.visible');
    });

    it('shows an empty state message when no IPs are tracked', () => {
        cy.login();
        cy.visit(adminPath);

        cy.apollo({mutation: flushCache});
        cy.contains('button', 'Refresh').click();

        cy.get('[class*="bflp_emptyState"]').should('be.visible');
    });

    it('blocks login from an IP after reaching the max failed attempts configured via UI', () => {
        cy.login();
        
        // Start from a clean tracked-IPs state
        cy.apollo({mutation: flushCache});
        
        const tti = 15;
        cy.apollo({
            mutation: saveSettings,
            variables: {
                activated: true,
                nbFailedLoginMax: 2,
                whitelistIps: '127.0.0.1/32,::1/128',
                timeToIdle: tti
            }
        })
        
        // Drop the session so subsequent requests trigger real authentication
        cy.logout();
        cy.clearCookies();
        
        // Attempt 2 failed logins with incorrect credentials
        for (let i = 0; i < 2; i++) {
            // Correct credentials must also fail — the IP is now blocked
            cy.request({
                method: 'POST',
                url: '/cms/login',
                form: true,
                body: {
                    username: 'root',
                    password: 'bad_password',
                    redirect: '/'
                },
                followRedirect: false,
                failOnStatusCode: false
            })
        }
        
        // Correct credentials must also fail — the IP is now blocked
        cy.request({
            method: 'POST',
            url: '/cms/login',
            form: true,
            body: {
                username: 'root',
                password: Cypress.env('SUPER_USER_PASSWORD') || 'root1234',
            },
            followRedirect: true,
            failOnStatusCode: false
        });

        cy.intercept(adminPath).as('page')
        cy.visit(adminPath, { failOnStatusCode: false })
        cy.wait('@page').its('response.statusCode').should('equal', 401)


        cy.wait(15000);
        
        // Restore admin session so afterEach can run cy.apollo()
        cy.login();
        cy.visit(adminPath, { failOnStatusCode: false })
        cy.wait('@page').its('response.statusCode').should('equal', 200)
    });
});
