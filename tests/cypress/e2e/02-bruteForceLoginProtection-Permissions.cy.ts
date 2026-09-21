import { DocumentNode } from 'graphql'
import { createUser, deleteUser, grantRoles } from '@jahia/cypress'

/**
 * Regression tests for the fine-grained `bruteForceLoginProtectionAdmin` permission.
 *
 * These guard against the gate being silently removed or mismatched across the stack:
 *  - Backend: `@GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")` is enforced on every
 *    query/mutation in BruteForceLoginProtectionQueryExtension / MutationExtension as a root-node
 *    ACL check (`session.getNode("/").hasPermission("bruteForceLoginProtectionAdmin")`).
 *  - Frontend: `requiredPermission: 'bruteForceLoginProtectionAdmin'` in register.jsx gates the module's
 *    ENTRY in the administration console. It does not grant entry to the console itself — that is
 *    gated on `administrationAccess` — so the permission is sufficient for GraphQL but not for the UI.
 *  - RBAC content: the module ships the assignable `brute-force-login-protection-administrator` role
 *    (src/main/import/roles.xml) granting ONLY `administrationAccess` + that permission.
 *
 * The "allowed" user is granted that role and nothing else — never `admin` — so the tests prove
 * fine-grained granularity, not merely that a full administrator can pass.
 */
describe('Brute Force Login Protection — permission enforcement', () => {
    const ROLE_NAME = 'brute-force-login-protection-administrator'
    // SUPPORT-646 (F20 residual/D2): a genuinely DECOUPLED role -- granting ONLY
    // bruteForceLoginProtectionAdmin, with no administrationAccess at all. It proves the
    // permission is independently sufficient for the GRAPHQL API; it is NOT sufficient for the
    // admin UI, and cannot be (see the Admin UI authorization block below). This is an API-only
    // role -- e.g. a service account that reads or mutates the module's GraphQL without being a
    // console administrator.
    const MODULE_ONLY_ROLE_NAME = 'brute-force-login-protection-module-only'
    const DENIED_USER = 'bflpDeniedUser'
    const ALLOWED_USER = 'bflpAllowedUser'
    const MODULE_ONLY_USER = 'bflpModuleOnlyUser'
    const PASSWORD = 'BflpPerm9PwdTest'
    const ADMIN_PATH = '/jahia/administration/bruteForceLoginProtection'

    /* eslint-disable @typescript-eslint/no-var-requires */
    const getGlobalSettings: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getGlobalSettings.graphql')
    const getBlocklistStatus: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getBlocklistStatus.graphql')
    /* eslint-enable @typescript-eslint/no-var-requires */

    const errorsOf = (result: { graphQLErrors?: Array<{ message: string }>; errors?: Array<{ message: string }> }) =>
        result.graphQLErrors ?? result.errors ?? []

    const queryGlobalSettingsAs = (username: string) => {
        cy.apolloClient({ username, password: PASSWORD })
        return cy.apollo({ query: getGlobalSettings })
    }

    before(() => {
        cy.login()
        createUser(DENIED_USER, PASSWORD)
        createUser(ALLOWED_USER, PASSWORD)
        createUser(MODULE_ONLY_USER, PASSWORD)
        // The annotation resolves the permission on the JCR root node, so grant the
        // module-shipped single-permission role on `/`.
        grantRoles('/', [ROLE_NAME], ALLOWED_USER, 'USER')
        grantRoles('/', [MODULE_ONLY_ROLE_NAME], MODULE_ONLY_USER, 'USER')
    })

    after(() => {
        cy.apolloClient() // reset the current Apollo client back to root
        cy.login()
        deleteUser(DENIED_USER)
        deleteUser(ALLOWED_USER)
        deleteUser(MODULE_ONLY_USER)
    })

    describe('GraphQL API authorization', () => {
        it('denies the gated query for a user without the permission', () => {
            queryGlobalSettingsAs(DENIED_USER).then((result: never) => {
                const errs = errorsOf(result)
                expect(errs, 'denial errors').to.have.length.greaterThan(0)
                expect(errs.map((e: { message: string }) => e.message).join(' ')).to.contain('Permission denied')
            })
        })

        it('allows the gated query for a user granted only the module permission', () => {
            queryGlobalSettingsAs(ALLOWED_USER).then((result: never) => {
                expect(errorsOf(result), 'should have no errors').to.have.length(0)
                expect(
                    (result as { data: { bruteForceLoginProtection: { globalSettings: { activated: boolean } } } }).data
                        .bruteForceLoginProtection.globalSettings,
                ).to.have.property('activated')
            })
        })

        it('denies blocklistStatus for a user without the permission', () => {
            cy.apolloClient({ username: DENIED_USER, password: PASSWORD })
            cy.apollo({ query: getBlocklistStatus }).then((result: never) => {
                const errs = errorsOf(result)
                expect(errs, 'denial errors').to.have.length.greaterThan(0)
                expect(errs.map((e: { message: string }) => e.message).join(' ')).to.contain('Permission denied')
            })
        })

        it('allows blocklistStatus for a user granted only the module permission', () => {
            cy.apolloClient({ username: ALLOWED_USER, password: PASSWORD })
            cy.apollo({ query: getBlocklistStatus }).then((result: never) => {
                expect(errorsOf(result), 'should have no errors').to.have.length(0)
                expect(
                    (
                        result as {
                            data: { bruteForceLoginProtection: { blocklistStatus: { staticEntryCount: number } } }
                        }
                    ).data.bruteForceLoginProtection.blocklistStatus,
                ).to.have.property('staticEntryCount')
            })
        })

        // F20 residual: unlike the tests above (which grant the SHIPPED role bundling both
        // administrationAccess + bruteForceLoginProtectionAdmin), this isolates the module
        // permission alone via the decoupled brute-force-login-protection-module-only role.
        it('allows the gated query for a user granted ONLY bruteForceLoginProtectionAdmin (no administrationAccess)', () => {
            queryGlobalSettingsAs(MODULE_ONLY_USER).then((result: never) => {
                expect(errorsOf(result), 'should have no errors').to.have.length(0)
                expect(
                    (result as { data: { bruteForceLoginProtection: { globalSettings: { activated: boolean } } } }).data
                        .bruteForceLoginProtection.globalSettings,
                ).to.have.property('activated')
            })
        })
    })

    describe('Admin UI authorization', () => {
        it('hides the admin panel from a user without the permission', () => {
            cy.login(DENIED_USER, PASSWORD)
            cy.visit(ADMIN_PATH, { failOnStatusCode: false })
            cy.contains('button', /Flush all/i).should('not.exist')
        })

        it('shows the admin panel to a user granted only the module permission', () => {
            cy.login(ALLOWED_USER, PASSWORD)
            cy.visit(ADMIN_PATH)
            cy.contains('button', /Flush all/i).should('be.visible')
        })

        // The module permission alone is NOT sufficient to reach the admin UI, and cannot be:
        // register.jsx attaches this route with targets ['administration-server-configuration:10'],
        // so `requiredPermission: 'bruteForceLoginProtectionAdmin'` only gates the menu ENTRY once
        // you are already inside the administration console — whose route tree Jahia gates on
        // `administrationAccess`. A user holding only bruteForceLoginProtectionAdmin therefore
        // loads the console shell (the module's JS and GraphQL both answer 200) but is never
        // offered the entry, so the panel never renders.
        //
        // This asserted the opposite until SEC-362's test pass. The premise was unreachable by
        // construction, so the test could only ever have passed if the permission gate had been
        // removed. It is inverted rather than deleted because the real constraint is worth
        // guarding: it documents that `…-module-only` is an API-ONLY role, and it would fail if
        // someone "fixed" it by quietly adding administrationAccess to that role (which would make
        // it permission-identical to the shipped …-administrator role).
        //
        // What stops this absence assertion from being vacuous (it would also "pass" on a page
        // that never loaded) is the test immediately above: identical visit, identical selector,
        // one variable — administrationAccess — asserting the button IS visible. That pair is the
        // control, which is why this does not reach for a separate, brittle shell selector.
        it('does NOT expose the admin panel to a user granted ONLY bruteForceLoginProtectionAdmin (no administrationAccess)', () => {
            cy.login(MODULE_ONLY_USER, PASSWORD)
            cy.visit(ADMIN_PATH, { failOnStatusCode: false })
            cy.contains('button', /Flush all/i).should('not.exist')
        })
    })
})
