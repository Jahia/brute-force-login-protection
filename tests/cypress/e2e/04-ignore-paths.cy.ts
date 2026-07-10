import { DocumentNode } from 'graphql'

/**
 * Positively exercises the `ignorePaths` global setting: requests whose URI contains a configured
 * substring are exempt from failure DETECTION, while ban ENFORCEMENT still applies.
 *
 * Target endpoint: `/modules/graphql`. This is deliberate. A failed auth on a *browser-facing* path
 * (the admin UI, a page) makes Jahia internally FORWARD to the login page, so by the time the
 * detector runs the request URI is the login path ("/"), not the URL that was requested — such a
 * path cannot be targeted by URI substring. An API endpoint like `/modules/graphql` is rendered in
 * place with no forward, so its request URI is stable and matchable — the same shape as the real
 * motivating case (a machine fetch of `…/modules-repository.moduleList.json` carrying a wrong
 * Authorization header). We drive it with a bad HTTP Basic header, exactly like that incident.
 */
describe('Brute Force Login Protection — ignore paths', () => {
    const apiPath = '/modules/graphql'

    /* eslint-disable @typescript-eslint/no-var-requires */
    const getGlobalSettings: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getGlobalSettings.graphql')
    const getBannedIps: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getBannedIps.graphql')
    const getTrackedWindows: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getTrackedWindows.graphql')
    const getConfigReady: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/query/getConfigReady.graphql')
    const saveGlobalSettings: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/mutation/saveGlobalSettings.graphql')
    const saveJail: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/mutation/saveJail.graphql')
    const flush: DocumentNode = require('graphql-tag/loader!../fixtures/graphql/mutation/flush.graphql')
    /* eslint-enable @typescript-eslint/no-var-requires */

    const badAuth = 'Basic ' + btoa('root:bad_password')

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

    const activate = (ignorePaths: string[], maxRetry: number, banTimeSeconds: number): void => {
        // saveGlobalSettings (carrying ignorePaths) is sent before saveJail; by the time the jail
        // update is observable via configReady, the earlier global update has propagated too.
        cy.apollo({
            mutation: saveGlobalSettings,
            variables: { activated: true, whitelistIps: '', ignorePaths, recidiveFactor: 1.0, maxBanTimeSeconds: 60 },
        })
        cy.apollo({
            mutation: saveJail,
            variables: { name: 'login', enabled: true, maxRetry, findTimeSeconds: 60, banTimeSeconds },
        })
        waitForConfigReady('login')
    }

    // Fire N unauthenticated Basic-auth failures at the stable API endpoint.
    const hammerApi = (times: number): void => {
        for (let i = 0; i < times; i++) {
            cy.request({
                method: 'GET',
                url: apiPath,
                headers: { Authorization: badAuth },
                followRedirect: false,
                failOnStatusCode: false,
            })
        }
    }

    it('persists ignorePaths through saveGlobalSettings/getGlobalSettings', () => {
        cy.apollo({
            mutation: saveGlobalSettings,
            variables: { ignorePaths: ['modules-repository.moduleList.json', apiPath] },
        })
            .its('data.bruteForceLoginProtection.saveGlobalSettings')
            .should('eq', true)

        cy.apollo({ query: getGlobalSettings })
            .its('data.bruteForceLoginProtection.globalSettings.ignorePaths')
            .should((paths: string[]) => {
                expect(paths).to.include('modules-repository.moduleList.json')
                expect(paths).to.include(apiPath)
            })
    })

    it('does NOT accrue failures for requests to an ignored path, even past maxRetry', () => {
        cy.login()
        cy.apollo({ mutation: flush })
        // apiPath is in ignorePaths → those requests are exempt from detection.
        activate([apiPath], 5, 15)

        cy.logout()
        cy.clearCookies()

        // Six failed Basic-auth requests (> maxRetry of 5) to the ignored path.
        hammerApi(6)

        // The runner IP is NOT banned (exemption worked), so we can log back in and inspect state.
        cy.login()

        cy.apollo({ query: getBannedIps })
            .its('data.bruteForceLoginProtection.bannedIps')
            .should((bans: unknown[]) => {
                expect(bans, 'no ban should have formed from ignored-path traffic').to.be.an('array').that.has.length(0)
            })

        // Stronger than "not banned": the failures were never even recorded into a window.
        cy.apollo({ query: getTrackedWindows })
            .its('data.bruteForceLoginProtection.trackedWindows')
            .should((windows: unknown[]) => {
                expect(windows, 'ignored-path failures must not be tracked at all').to.be.an('array').that.has.length(0)
            })
    })

    it('DOES detect failures on the same endpoint when it is not in ignorePaths (control)', () => {
        cy.login()
        cy.apollo({ mutation: flush })
        // Same endpoint, same bad requests — but ignorePaths does not match apiPath this time.
        activate(['this-token-matches-no-path'], 5, 15)

        cy.logout()
        cy.clearCookies()

        // Two failures, below maxRetry (5): no ban, but a tracking window must appear.
        hammerApi(2)

        cy.login()

        cy.apollo({ query: getTrackedWindows })
            .its('data.bruteForceLoginProtection.trackedWindows')
            .should((windows: Array<{ jail: string; failuresInWindow: number }>) => {
                expect(windows, 'non-ignored-path failures must be tracked')
                    .to.be.an('array')
                    .that.has.length.greaterThan(0)
                const login = windows.find((w) => w.jail === 'login')
                expect(login, 'a window for the login jail must exist').to.exist
                expect(login.failuresInWindow, 'both failures counted').to.be.greaterThan(0)
            })

        cy.apollo({ query: getBannedIps })
            .its('data.bruteForceLoginProtection.bannedIps')
            .should((bans: unknown[]) => {
                expect(bans, 'still under maxRetry, so no ban yet').to.be.an('array').that.has.length(0)
            })
    })

    it('still ENFORCES bans while ignorePaths is configured (enforcement is independent of detection)', () => {
        cy.login()
        cy.apollo({ mutation: flush })
        // apiPath is ignored for detection; ban via a non-ignored path (form login) to prove that
        // configuring ignorePaths does not weaken enforcement.
        activate([apiPath], 2, 15)

        cy.logout()
        cy.clearCookies()

        // Two bad form logins on /cms/login (NOT ignored) → the runner IP gets banned.
        for (let i = 0; i < 2; i++) {
            cy.request({
                method: 'POST',
                url: '/cms/login',
                form: true,
                body: { username: 'root', password: 'bad_password', redirect: '/' },
                followRedirect: false,
                failOnStatusCode: false,
            })
        }

        // The banned IP is still rejected (401) specifically on the IGNORED path (apiPath) --
        // this is the one thing this spec exists to prove: ignorePaths only exempts DETECTION,
        // never ENFORCEMENT, even on the exact path that is configured as ignored.
        cy.request({
            method: 'GET',
            url: apiPath,
            headers: { Authorization: badAuth },
            followRedirect: false,
            failOnStatusCode: false,
        })
            .its('status')
            .should('equal', 401)

        // Recover: wait out the short ban window, then log in so afterEach's flush can run.
        cy.logout()
        cy.clearCookies()
        // eslint-disable-next-line cypress/no-unnecessary-waiting
        cy.wait(20000)
        cy.login()
    })
})
