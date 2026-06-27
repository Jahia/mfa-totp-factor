/**
 * E2E for the `redirect=` round trip through the custom MFA login page:
 *
 *  1. server side — an unauthenticated hit on a protected URL 302s to the configured global
 *     login page WITH a `redirect=` param carrying the URL the user asked for
 *     (MfaLoginLogoutProvider reads it from the servlet ERROR/FORWARD dispatch attributes);
 *  2. client side — after completing the sign-in flow on the login page, the login UI sends
 *     the user to that `redirect=` target instead of the site root (services/redirect.tsx,
 *     same-origin validated).
 *
 * The global login URL is reverted in after() — a leftover would reroute every other
 * spec's 401s to a page this spec deletes.
 */
import {deleteUser, jfaker} from '@jahia/cypress';
import {
    createSiteWithTotpLoginPage,
    createUserForMFA,
    deleteTotpLoginSite,
    fillOtp,
    getTotpLoginPageURL,
    installTotpMFAConfig,
    setGlobalEnforcement,
    setGlobalMfaUrls,
    setSiteTotpSettings,
    totpCode,
} from './utils';

const SITE_KEY = 'sample-login-redirect';

describe('Login redirect round trip (custom login URL)', () => {
    let username: string;
    let password: string;

    before(() => {
        createSiteWithTotpLoginPage(SITE_KEY);
        installTotpMFAConfig();
        // installTotpMFAConfig points UPA's OWN loginUrl (org.jahia.modules.upa) at a different
        // sample site; its login-URL provider would then win over MfaLoginLogoutProvider and serve
        // a URL without the redirect= param this spec asserts. Clear it so the global
        // mfa.extensions provider is the sole source for this spec's 401 handling.
        cy.request({
            method: 'POST',
            url: '/modules/api/provisioning',
            auth: {user: 'root', pass: Cypress.env('SUPER_USER_PASSWORD') as string},
            headers: {'Content-Type': 'application/json'},
            body: [{editConfiguration: 'org.jahia.modules.upa', properties: {loginUrl: ''}}],
        });
        setSiteTotpSettings(SITE_KEY, true);
        setGlobalEnforcement('totp', 0);
        setGlobalMfaUrls(getTotpLoginPageURL(SITE_KEY));
    });

    after(() => {
        setGlobalMfaUrls('', '');
        setGlobalEnforcement('', 0);
        deleteTotpLoginSite(SITE_KEY);
    });

    beforeEach(() => {
        username = jfaker.internet.username();
        password = jfaker.internet.password();
        createUserForMFA(username, password, jfaker.internet.email());
        cy.logout();
    });

    afterEach(() => {
        try {
            deleteUser(username);
        } catch (_e) {
            // ignore
        }
    });

    it('401 on a protected URL redirects to the login page with the target in redirect=', () => {
        cy.request({
            url: '/jahia/dashboard',
            followRedirect: false,
        }).then(response => {
            expect(response.status).to.eq(302);
            expect(response.headers.location).to.contain(getTotpLoginPageURL(SITE_KEY));
            expect(response.headers.location).to.contain('redirect=%2Fjahia%2Fdashboard');
        });
    });

    it('completing the sign-in flow lands on the redirect target, not the site root', () => {
        const target = `/sites/${SITE_KEY}/home.html`;
        cy.visit(`${getTotpLoginPageURL(SITE_KEY)}?redirect=${encodeURIComponent(target)}`);

        // Inline TOTP enrollment (enforced, no grace): password -> QR -> code -> backup codes.
        cy.get('[data-testid="login-username"]', {timeout: 30000}).type(username);
        cy.get('[data-testid="login-password"]').type(password);
        cy.get('[data-testid="login-submit"]').click();
        cy.get('[data-testid="enroll-qr"]', {timeout: 30000}).should('be.visible');
        cy.get('[data-testid="enroll-secret"]')
            .invoke('text')
            .then(rawSecret => {
                const secret = rawSecret.replace(/\s+/g, '');
                fillOtp('enroll-code-input', totpCode(secret));
            });
        cy.get('[data-testid="enroll-backup-ack"]', {timeout: 30000}).click();

        // The post-authentication redirect honours the (validated) redirect param.
        cy.location('pathname', {timeout: 15000}).should('eq', target);
    });
});
