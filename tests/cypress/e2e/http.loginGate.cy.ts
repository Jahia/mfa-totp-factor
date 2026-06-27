/**
 * HTTP-level coverage for the shared /cms/login gate (MfaLoginGateFilter, in the
 * mfa-factors-extensions bundle):
 *
 * Jahia's legacy /cms/login endpoint authenticates with username/password only (no MFA),
 * so on a site that ENFORCES enrollment for any factor it is a second-factor bypass. Two modes
 * close it while enrollment is enforced:
 *
 *  - explicit hard gate (loginGate.enabled, PID org.jahia.modules.mfa.extensions): /cms/login is
 *    rerouted to the configured MFA login page (302), or returns 403 when no distinct login page
 *    is configured - unless the client IP, read from the FIRST X-Forwarded-For entry, matches the
 *    configured whitelist (loginGate.ipWhitelist);
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

// A password-login POST (form-encoded), like a browser submitting the legacy login form. The creds
// are bogus on purpose: the auth-valve gate must intercept BEFORE Jahia processes them, so the
// outcome must not depend on whether the credentials are valid.
const postLogin = (headers: Record<string, string> = {}, extraBody: Record<string, string> = {}) => cy.request({
    method: 'POST',
    url: '/cms/login',
    form: true,
    body: {site: SITE_KEY, username: 'gate-probe', password: 'irrelevant', ...extraBody},
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

    it('reroutes a non-whitelisted client to the configured login page (hard gate, not a 403)', () => {
        // Hard gate still ENABLED (from before()); now a login page is configured, so a blocked
        // non-whitelisted client is sent there instead of getting a bare 403.
        setGlobalMfaUrls(`/sites/${SITE_KEY}/login.html`);
        requestLogin().then(res => {
            expect(res.status, 'hard gate reroutes instead of 403').to.eq(302);
            expect(res.headers.location).to.contain(`/sites/${SITE_KEY}/login.html`);
        });
        // Reset so the automatic-mode cases below start with no login URL configured.
        setGlobalMfaUrls('', '');
    });

    it('blocks a password POST to /cms/login BEFORE authentication (closes the MFA bypass)', () => {
        // The crux: Jahia authenticates a /cms/login POST in its auth pipeline, which runs before the
        // servlet filter - so the auth valve must intercept it. A non-whitelisted POST with credentials
        // must be rerouted to the MFA login page (BEFORE auth), NOT processed and sent to
        // failureRedirect, and must NOT issue a persistent-auth (jid) cookie.
        setGlobalMfaUrls(`/sites/${SITE_KEY}/login.html`);
        postLogin({'X-Forwarded-For': '8.8.8.8'}, {failureRedirect: '/failure.html', redirect: '/success.html'})
            .then(res => {
                expect(res.status).to.eq(302);
                expect(res.headers.location, 'rerouted to the MFA login page, not the auth-failure redirect')
                    .to.contain(`/sites/${SITE_KEY}/login.html`);
                const cookies = ([] as string[]).concat(res.headers['set-cookie'] || []);
                expect(cookies.some(c => c.startsWith('jid=')), 'no persistent auth cookie was issued').to.eq(false);
            });
        // A whitelisted client keeps the emergency door (the gate must not break legitimate admin
        // login). With bogus creds the login still fails downstream, so we only assert the valve did
        // NOT reroute it to the MFA login page - the location may be undefined (no redirect) or the
        // auth-failure target, but never the gate's login URL. Coerce to '' so the matcher is safe
        // on an absent Location header.
        postLogin({'X-Forwarded-For': '203.0.113.7'}, {redirect: '/success.html'}).then(res => {
            expect(res.headers.location || '', 'whitelisted client is processed normally (not gate-rerouted)')
                .to.not.contain(`/sites/${SITE_KEY}/login.html`);
        });
        setGlobalMfaUrls('', '');
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
