/**
 * HTTP-level coverage for the shared /cms/login gate (MfaLoginGateFilter, in the
 * mfa-factors-extensions bundle):
 *
 * Jahia's legacy /cms/login endpoint authenticates with username/password only (no MFA),
 * so on a site that ENFORCES enrollment for any factor it is a second-factor bypass. Two modes
 * close it while enrollment is enforced:
 *
 *  - explicit hard gate (loginGate.enabled, PID org.jahia.modules.mfa.extensions): /cms/login
 *    returns 403 — unless the client IP, read from the FIRST X-Forwarded-For entry, matches
 *    the configured whitelist (loginGate.ipWhitelist);
 *  - automatic (gate disabled): /cms/login stays reachable ONLY when the operator explicitly
 *    configured it as the login URL; a configured custom login page is served as a 302, and a
 *    missing login URL blocks with 403 (the default screen would silently void the factor).
 *
 * This spec drives enforcement through the TOTP factor (a convenient enforcing factor), but
 * the gate itself is factor-agnostic. The gate config is flipped through the provisioning API
 * (editConfiguration) and reverted in after(), so the other specs always run with the gate at
 * its default (disabled) and no enforcement (= no automatic gating either).
 */
import {createSite, deleteSite} from '@jahia/cypress';
import gql from 'graphql-tag';
import {setGlobalEnforcement, setGlobalMfaUrls} from './utils';

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
            editConfiguration: 'org.jahia.modules.mfa.extensions',
            properties: {'loginGate.enabled': String(enabled), 'loginGate.ipWhitelist': ipWhitelist}
        }]
    });
    // Give ConfigAdmin a moment to dispatch the @Modified event to the filter.
    cy.wait(2000);
};

const setSiteEnabled = (enabled: boolean) => cy.apollo({
    mutation: gql`
        mutation Set($siteKey: String!, $enabled: Boolean!) {
            upa { mfaFactors { totp { setSiteSettings(siteKey: $siteKey, enabled: $enabled) {
                enabled
            } } } }
        }`,
    variables: {siteKey: SITE_KEY, enabled}
});

const requestLogin = (headers: Record<string, string> = {}, qs: Record<string, string> = {}) => cy.request({
    url: '/cms/login',
    qs,
    headers,
    failOnStatusCode: false,
    followRedirect: false
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
        // The gate now requires the GLOBAL enforcement policy AND the factor enabled on a site.
        setSiteEnabled(true);
        setGlobalEnforcement('totp', 0);
        // Whitelist a TEST-NET-3 range; the cypress container's real IP is never in it.
        setGateConfig(true, '203.0.113.0/24');
    });

    after(() => {
        // ALWAYS revert: a leftover enabled gate (or enforcement policy) would break every
        // other spec's logins.
        setGateConfig(false, '');
        setGlobalMfaUrls('', '');
        setGlobalEnforcement('', 0);
        cy.apolloClient(ROOT);
        setSiteEnabled(false);
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

    // --- Automatic mode (hard gate disabled, enforcement still active) ----------------------

    it('still blocks /cms/login with the gate disabled when no login URL is configured', () => {
        setGateConfig(false, '');
        requestLogin().then(res => {
            expect(res.status, 'enforcement + default screen reachable = silent MFA bypass').to.eq(403);
        });
    });

    it('redirects /cms/login to the configured custom login page', () => {
        setGlobalMfaUrls(`/sites/${SITE_KEY}/login.html`);
        requestLogin().then(res => {
            expect(res.status).to.eq(302);
            expect(res.headers.location).to.contain(`/sites/${SITE_KEY}/login.html`);
        });
        // An explicit redirect param survives the hop to the custom page.
        requestLogin({}, {redirect: '/jahia/dashboard'}).then(res => {
            expect(res.status).to.eq(302);
            expect(res.headers.location).to.contain('redirect=%2Fjahia%2Fdashboard');
        });
    });

    it('keeps /cms/login reachable when the operator explicitly configured it as the login URL', () => {
        setGlobalMfaUrls('/cms/login');
        requestLogin().then(res => {
            expect(res.status, 'the default screen is a deliberate choice here').to.eq(200);
        });
    });

    it('stands down entirely once enforcement is cleared', () => {
        setGlobalMfaUrls('', '');
        setGlobalEnforcement('', 0);
        requestLogin().then(res => {
            expect(res.status, 'no enforcement → no bypass to close').to.eq(200);
        });
        // Re-arm for symmetry with after() (which reverts unconditionally).
        setGlobalEnforcement('totp', 0);
        setGateConfig(true, '203.0.113.0/24');
    });
});
