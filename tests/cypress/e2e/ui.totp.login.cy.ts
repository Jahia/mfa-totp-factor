/**
 * Login-flow tests for the TOTP UI module (mfa-totp-factor-login-ui).
 *
 * Each test:
 *   - Provisions a fresh user enrolled in TOTP via GraphQL (so we don't have to
 *     drive the dashboard UI just to land an enrolled user).
 *   - Visits the per-site login page that renders the totpui:authentication view.
 *   - Submits username + password through the rendered form.
 *   - Submits a freshly-computed TOTP code (or a backup code) into the verify form.
 *   - Asserts the post-login redirect actually happens.
 *
 * The MFA Karaf config is installed once in `before()` and points loginUrl at
 * /sites/sample-totp-ui/myLoginPage.html with totp as the only enabled factor.
 */
import {deleteSite, deleteUser, jfaker} from '@jahia/cypress';
import {
    createSiteWithTotpLoginPage,
    createUserForMFA,
    enrollUserInTotp,
    getTotpLoginPageURL,
    installTotpMFAConfig,
    totpCode,
} from './utils';

const SITE_KEY = 'sample-totp-ui';

// Each test runs against a fresh user so per-user replay-protection counters never
// leak across specs. The username/password/secret triplet is captured per test.
describe('TOTP login UI', () => {
    let username: string;
    let password: string;
    let email: string;
    let secret: string;
    let backupCodes: string[];

    before(() => {
        createSiteWithTotpLoginPage(SITE_KEY);
        installTotpMFAConfig();
    });

    after(() => {
        try {
            deleteSite(SITE_KEY);
        } catch (_e) {
            // ignore
        }
    });

    beforeEach(() => {
        username = jfaker.internet.username();
        password = jfaker.internet.password();
        email = jfaker.internet.email();
        createUserForMFA(username, password, email);
        enrollUserInTotp(username, password).then((result) => {
            secret = result.secret;
            backupCodes = result.backupCodes;
        });
        cy.logout();
    });

    afterEach(() => {
        try {
            deleteUser(username);
        } catch (_e) {
            // ignore
        }
    });

    it('signs in with username/password + a fresh TOTP code', () => {
        cy.visit(getTotpLoginPageURL(SITE_KEY));

        // Stage 1: username/password form is rendered by LoginForm.client.tsx
        cy.get('[data-testid="login-username"]', {timeout: 30000}).should('be.visible');
        cy.get('[data-testid="login-username"]').type(username);
        cy.get('[data-testid="login-password"]').type(password);
        cy.get('[data-testid="login-submit"]').click();

        // Stage 2: TOTP code prompt rendered by TotpCodeVerificationForm.client.tsx.
        // Wait the full step boundary so the code we submit is on a counter strictly
        // greater than the one consumed by enrollUserInTotp(), avoiding replay rejection.
        cy.get('[data-testid="verification-code"]', {timeout: 30000}).should('be.visible');
        cy.wait(31000);
        cy.wrap(null).then(() => {
            const liveCode = totpCode(secret);
            cy.get('[data-testid="verification-code"]').type(liveCode);
            cy.get('[data-testid="verification-submit"]').click();
        });

        // Stage 3: client-side redirect lands on the site root (contextPath + "/").
        // Sanity-check by querying the GraphQL currentUser through the now-authenticated
        // browser cookie — bypasses any "is the dashboard loaded?" assertion.
        cy.location('pathname', {timeout: 15000}).should('not.contain', '/myLoginPage.html');
    });

    it('rejects a wrong TOTP code, then accepts a fresh one', () => {
        cy.visit(getTotpLoginPageURL(SITE_KEY));

        cy.get('[data-testid="login-username"]', {timeout: 30000}).should('be.visible');
        cy.get('[data-testid="login-username"]').type(username);
        cy.get('[data-testid="login-password"]').type(password);
        cy.get('[data-testid="login-submit"]').click();

        cy.get('[data-testid="verification-code"]', {timeout: 30000}).should('be.visible');

        // Wrong code → error message inline, form stays open.
        cy.get('[data-testid="verification-code"]').type('000000');
        cy.get('[data-testid="verification-submit"]').click();
        cy.get('[data-testid="error-message"]', {timeout: 15000}).should('be.visible');

        // Recover: wait a step, clear input, submit a fresh code.
        cy.wait(31000);
        cy.get('[data-testid="verification-code"]').clear();
        cy.wrap(null).then(() => {
            cy.get('[data-testid="verification-code"]').type(totpCode(secret));
            cy.get('[data-testid="verification-submit"]').click();
        });
        cy.location('pathname', {timeout: 15000}).should('not.contain', '/myLoginPage.html');
    });

    it('signs in with a backup code instead of an authenticator code', () => {
        cy.visit(getTotpLoginPageURL(SITE_KEY));

        cy.get('[data-testid="login-username"]', {timeout: 30000}).should('be.visible');
        cy.get('[data-testid="login-username"]').type(username);
        cy.get('[data-testid="login-password"]').type(password);
        cy.get('[data-testid="login-submit"]').click();

        cy.get('[data-testid="verification-code"]', {timeout: 30000}).should('be.visible');

        // Toggle into backup-code mode. The same submit button verifies; the server's
        // totp.verify accepts either form.
        cy.get('[data-testid="toggle-backup-code"]').click();
        cy.get('[data-testid="verification-backup-code"]').should('be.visible');

        const backupCode = backupCodes[0];
        expect(backupCode, 'enrollUserInTotp returned at least one backup code').to.be.a('string');
        cy.get('[data-testid="verification-backup-code"]').type(backupCode);
        cy.get('[data-testid="verification-submit"]').click();

        cy.location('pathname', {timeout: 15000}).should('not.contain', '/myLoginPage.html');
    });
});
