import { DocumentNode } from 'graphql'

/**
 * Live regression coverage for JAHIA-SEC-362 / GHSA-7qgr-2hqv-r344.
 *
 * `ignorePatterns` is an EXEMPTION list: a match means "do not count this login failure". The
 * timeout branch of the match used to return MATCHED, so a username crafted to make the operator's
 * own regex backtrack past the 50 ms budget was silently exempted — never counted, never banned,
 * never audited. The harder an attacker hit it, the less was recorded.
 *
 * This spec reproduces the two-arm measurement from the advisory: same source IP, same
 * configuration, ONE variable — the username. The discriminator is `trackedWindows.failuresInWindow`
 * via the module's own GraphQL, never the HTTP status: Jahia answers 200 for a wrong password, so
 * both arms return 200 and the status code proves nothing.
 *
 * `whitelistIps` MUST be emptied on every arm. The shipped default whitelists loopback and
 * `isWhitelisted()` returns BEFORE the ignore-pattern test, so a whitelisted runner IP would
 * produce a zero identical to the bug and fake a pass.
 */
describe('Brute Force Login Protection — ignore patterns', () => {
    /* eslint-disable @typescript-eslint/no-var-requires */
    const getTrackedWindows: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getTrackedWindows.graphql')
    const getConfigReady: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getConfigReady.graphql')
    const saveGlobalSettings: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/mutation/saveGlobalSettings.graphql')
    const saveJail: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/mutation/saveJail.graphql')
    const flush: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/mutation/flush.graphql')
    /* eslint-enable @typescript-eslint/no-var-requires */

    // The ONLY pattern measured to defeat Java's regex optimiser on this JVM. The textbook
    // catastrophic payloads (^(a+)+$, (a*)*$, (a|a)+$, (x+x+)+y) all resolve in ~0 ms here, so
    // using one of them would make this spec silently vacuous — it would pass either way.
    const BACKTRACKING_PATTERN = '(.*a){20}'
    // The trailing '!' makes a full match IMPOSSIBLE, which is what forces the exhaustive
    // backtrack — a matching input would short-circuit and never reach the budget.
    //
    // That has a consequence worth stating: if the pattern were ever to resolve *fast* on some
    // JVM, the failure would be counted for the ordinary NOT_MATCHED reason and this test would
    // pass without exercising the timeout at all. Backtracking cost here is exponential in the
    // username length, and the advisory measured >20 s at n=30, so n=40 puts the blow-up far
    // enough beyond the 50 ms budget that the timeout is certain rather than merely likely.
    // (Kept well under the 256-char match cap, which would otherwise skip the regex entirely.)
    const BACKTRACKING_USERNAME = 'a'.repeat(40) + '!'

    // maxRetry is deliberately well above the attempts any single arm fires: this spec measures the
    // COUNTER, not the ban, and banning the Cypress runner mid-spec would break the follow-up login.
    const MAX_RETRY = 10

    before(() => {
        cy.login()
    })

    afterEach(() => {
        cy.apollo({ mutation: flush })
    })

    // The config mutations are async on the OSGi side; wait for them to go live before driving traffic.
    const waitForConfigReady = (jail: string): void => {
        cy.apollo({ query: getConfigReady, variables: { jail } })
            .its('data.bruteForceLoginProtection.configReady')
            .should((r: { globalReady: boolean; jailReady: boolean }) => {
                expect(r.globalReady, 'global config holder must have received an update').to.eq(true)
                expect(r.jailReady, `jail "${jail}" must be registered`).to.eq(true)
            })
    }

    const activate = (ignorePatterns: string[]): void => {
        cy.apollo({
            mutation: saveGlobalSettings,
            variables: {
                activated: true,
                // Emptied on purpose — see the file header.
                whitelistIps: '',
                ignorePatterns,
                // Cleared so a leftover value from spec 04 cannot exempt /cms/login here.
                ignorePaths: [],
                recidiveFactor: 1.0,
                maxBanTimeSeconds: 60,
            },
        })
        cy.apollo({
            mutation: saveJail,
            variables: { name: 'login', enabled: true, maxRetry: MAX_RETRY, findTimeSeconds: 60, banTimeSeconds: 15 },
        })
        waitForConfigReady('login')
    }

    // Fire N failed form logins carrying `username`. Every one answers 200 (Jahia renders the
    // login-error page for a wrong password), which is exactly why the status is not the signal.
    const failedLogins = (username: string, times: number): void => {
        for (let i = 0; i < times; i++) {
            cy.request({
                method: 'POST',
                url: '/cms/login',
                form: true,
                body: { username, password: 'bad_password', redirect: '/' },
                followRedirect: false,
                failOnStatusCode: false,
            })
        }
    }

    const countedFailures = (): Cypress.Chainable<number> =>
        cy
            .apollo({ query: getTrackedWindows })
            .its('data.bruteForceLoginProtection.trackedWindows')
            .then((windows: Array<{ jail: string; failuresInWindow: number }>) => {
                const login = (windows || []).find((w) => w.jail === 'login')
                return login ? login.failuresInWindow : 0
            })

    // Drive `attempts` failed logins for `username` under `patterns`, from a clean, logged-out
    // state, and hand back the number of failures the module actually counted.
    const measure = (patterns: string[], username: string, attempts: number): Cypress.Chainable<number> => {
        cy.login()
        cy.apollo({ mutation: flush })
        activate(patterns)

        cy.logout()
        cy.clearCookies()

        failedLogins(username, attempts)

        cy.login()
        return countedFailures()
    }

    it('counts a failure whose ignore-pattern match times out (JAHIA-SEC-362)', () => {
        // THE REGRESSION. Before the fix this measured 0: the timed-out match returned MATCHED,
        // which means "exempt", so the attacker was never counted and never banned.
        measure([BACKTRACKING_PATTERN], BACKTRACKING_USERNAME, 2).should((counted: number) => {
            expect(
                counted,
                'a timed-out ignore-pattern must NOT exempt the failure — it must be counted',
            ).to.be.greaterThan(0)
        })
    })

    it('counts an ordinary username under the same configuration (positive control)', () => {
        // Same rig, same IP, same pattern list — only the username differs. This is what makes the
        // arm above an observation rather than an absence: it proves the counter works at all here.
        measure([BACKTRACKING_PATTERN], 'controluser2', 2).should((counted: number) => {
            expect(counted, 'an ordinary username must be counted normally').to.be.greaterThan(0)
        })
    })

    it('still exempts a username that genuinely matches a linear-time pattern', () => {
        // The fix must not break the feature it hardens: a pattern that completes and matches
        // still exempts the failure entirely, so no window is created.
        measure(['^service-.*'], 'service-account', 2).should((counted: number) => {
            expect(counted, 'a real, fast pattern match must still exempt the failure').to.eq(0)
        })
    })

    it('never exempts an over-long username, even against a pattern that matches everything', () => {
        // Usernames beyond the 256-char match cap are not handed to the regex engine at all, so
        // they cannot be used to burn the match budget — and are never exempted.
        measure(['.*'], 'b'.repeat(300), 2).should((counted: number) => {
            expect(counted, 'an over-long username must be counted despite a catch-all pattern').to.be.greaterThan(0)
        })
    })
})
