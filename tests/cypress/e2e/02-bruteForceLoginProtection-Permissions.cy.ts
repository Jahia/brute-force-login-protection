import {DocumentNode} from 'graphql';
import {createUser, deleteUser, grantRoles} from '@jahia/cypress';

/**
 * Regression tests for the fine-grained `bruteForceLoginProtectionAdmin` permission.
 *
 * These guard against the gate being silently removed or mismatched across the stack:
 *  - Backend: `@GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")` is enforced on every
 *    query/mutation in BruteForceLoginProtectionQueryExtension / MutationExtension as a root-node
 *    ACL check (`session.getNode("/").hasPermission("bruteForceLoginProtectionAdmin")`).
 *  - Frontend: `requiredPermission: 'bruteForceLoginProtectionAdmin'` in register.jsx gates the admin route.
 *  - RBAC content: the module ships the assignable `brute-force-login-protection-administrator` role
 *    (src/main/import/roles.xml) granting ONLY `administrationAccess` + that permission.
 *
 * The "allowed" user is granted that role and nothing else — never `admin` — so the tests prove
 * fine-grained granularity, not merely that a full administrator can pass.
 */
describe('Brute Force Login Protection — permission enforcement', () => {
    const ROLE_NAME = 'brute-force-login-protection-administrator';
    const DENIED_USER = 'bflpDeniedUser';
    const ALLOWED_USER = 'bflpAllowedUser';
    const PASSWORD = 'BflpPerm9PwdTest';
    const ADMIN_PATH = '/jahia/administration/bruteForceLoginProtection';

    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const getGlobalSettings: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getGlobalSettings.graphql');

    const errorsOf = (result: {graphQLErrors?: Array<{message: string}>; errors?: Array<{message: string}>}) =>
        result.graphQLErrors ?? result.errors ?? [];

    const queryGlobalSettingsAs = (username: string) => {
        cy.apolloClient({username, password: PASSWORD});
        return cy.apollo({query: getGlobalSettings});
    };

    before(() => {
        cy.login();
        createUser(DENIED_USER, PASSWORD);
        createUser(ALLOWED_USER, PASSWORD);
        // The annotation resolves the permission on the JCR root node, so grant the
        // module-shipped single-permission role on `/`.
        grantRoles('/', [ROLE_NAME], ALLOWED_USER, 'USER');
    });

    after(() => {
        cy.apolloClient(); // reset the current Apollo client back to root
        cy.login();
        deleteUser(DENIED_USER);
        deleteUser(ALLOWED_USER);
    });

    describe('GraphQL API authorization', () => {
        it('denies the gated query for a user without the permission', () => {
            queryGlobalSettingsAs(DENIED_USER).then((result: never) => {
                const errs = errorsOf(result);
                expect(errs, 'denial errors').to.have.length.greaterThan(0);
                expect(errs.map((e: {message: string}) => e.message).join(' ')).to.contain('Permission denied');
            });
        });

        it('allows the gated query for a user granted only the module permission', () => {
            queryGlobalSettingsAs(ALLOWED_USER).then((result: never) => {
                expect(errorsOf(result), 'should have no errors').to.have.length(0);
                expect((result as {data: {bruteForceLoginProtection: {globalSettings: {activated: boolean}}}})
                    .data.bruteForceLoginProtection.globalSettings).to.have.property('activated');
            });
        });
    });

    describe('Admin UI authorization', () => {
        it('hides the admin panel from a user without the permission', () => {
            cy.login(DENIED_USER, PASSWORD);
            cy.visit(ADMIN_PATH, {failOnStatusCode: false});
            cy.contains('button', /Flush all/i).should('not.exist');
        });

        it('shows the admin panel to a user granted only the module permission', () => {
            cy.login(ALLOWED_USER, PASSWORD);
            cy.visit(ADMIN_PATH);
            cy.contains('button', /Flush all/i).should('be.visible');
        });
    });
});
