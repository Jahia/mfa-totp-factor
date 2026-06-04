/**
 * HTTP-level coverage for the /cms/login gate (TotpLoginGateFilter):
 *
 * Jahia's legacy /cms/login endpoint authenticates with username/password only (no MFA),
 * so on a site that ENFORCES TOTP enrollment it is a second-factor bypass. With the gate
 * enabled (loginGate.enabled, PID org.jahia.modules.totp), /cms/login must return 403
 * while enrollment is enforced — unless the client IP, read from the FIRST X-Forwarded-For
 * entry, matches the configured whitelist (loginGate.ipWhitelist).
 *
 * The gate config is flipped through the provisioning API (editConfiguration) and reverted
 * in after(), so the other specs always run with the gate at its default (disabled).
 */
import {createSite, deleteSite} from '@jahia/cypress';
import gql from 'graphql-tag';

const SITE_KEY = 'sample-totp-gate';

const ROOT = {username: 'root', password: Cypress.env('SUPER_USER_PASSWORD') as string};

/** Flip the gate config live (ConfigAdmin → @Modified hot-reload, which also clears the gate's cache). */
const setGateConfig = (enabled: boolean, ipWhitelist: string) => {
    cy.request({
        method: 'POST',
        url: '/modules/api/provisioning',
        auth: {user: ROOT.username, pass: ROOT.password},
        headers: {'Content-Type': 'application/json'},
        body: [{
            editConfiguration: 'org.jahia.modules.totp',
            properties: {'loginGate.enabled': String(enabled), 'loginGate.ipWhitelist': ipWhitelist}
        }]
    });
    // Give ConfigAdmin a moment to dispatch the @Modified event to the filter.
    cy.wait(2000);
};

const setEnforced = (enforced: boolean) => cy.apollo({
    mutation: gql`
        mutation Set($siteKey: String!, $enforced: Boolean!) {
            upa { mfaFactors { totp { setSiteSettings(siteKey: $siteKey, enabled: true, enforced: $enforced) {
                enforced
            } } } }
        }`,
    variables: {siteKey: SITE_KEY, enforced}
});

const requestLogin = (headers: Record<string, string> = {}, qs: Record<string, string> = {}) => cy.request({
    url: '/cms/login',
    qs,
    headers,
    failOnStatusCode: false
});

describe('/cms/login gate while TOTP enrollment is enforced (HTTP)', () => {
    before(() => {
        deleteSite(SITE_KEY);
        createSite(SITE_KEY, {
            locale: 'en',
            languages: 'en',
            templateSet: 'user-password-authentication-template-set-test-module',
            serverName: 'localhost'
        });
        cy.apolloClient(ROOT);
        setEnforced(true);
        // Whitelist a TEST-NET-3 range; the cypress container's real IP is never in it.
        setGateConfig(true, '203.0.113.0/24');
    });

    after(() => {
        // ALWAYS revert: a leftover enabled gate would 403 cy.login() in every other spec.
        setGateConfig(false, '');
        cy.apolloClient(ROOT);
        setEnforced(false);
        deleteSite(SITE_KEY);
    });

    it('blocks /cms/login with 403 when enrollment is enforced and the IP is not whitelisted', () => {
        requestLogin().then(res => {
            expect(res.status, 'no X-Forwarded-For, socket IP not whitelisted').to.eq(403);
        });
    });

    it('allows a whitelisted X-Forwarded-For client through', () => {
        requestLogin({'X-Forwarded-For': '203.0.113.7'}).then(res => {
            expect(res.status, 'whitelisted client IP').to.eq(200);
        });
    });

    it('uses the FIRST X-Forwarded-For entry (the original client), not the proxies', () => {
        requestLogin({'X-Forwarded-For': '203.0.113.50, 198.51.100.9'}).then(res => {
            expect(res.status, 'first entry whitelisted → allowed').to.eq(200);
        });
        requestLogin({'X-Forwarded-For': '198.51.100.9, 203.0.113.50'}).then(res => {
            expect(res.status, 'first entry NOT whitelisted → blocked').to.eq(403);
        });
    });

    it('gates per-site via the site parameter (uncached path)', () => {
        requestLogin({}, {site: SITE_KEY}).then(res => {
            expect(res.status, 'explicit enforcing site context').to.eq(403);
        });
    });

    it('stands down as soon as the gate is disabled', () => {
        setGateConfig(false, '');
        requestLogin().then(res => {
            expect(res.status, 'gate off → default behavior').to.eq(200);
        });
        // Re-arm for symmetry with after() (which reverts unconditionally).
        setGateConfig(true, '203.0.113.0/24');
    });
});
