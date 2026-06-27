/**
 * E2E for INLINE enrollment at sign-in (global enforcement):
 *
 * With the global policy enforcing totp (enforcedFactors=totp, graceDays=0 under PID
 * org.jahia.modules.mfa.extensions) and TOTP enabled on the site, a fresh user with NO factor
 * configured who signs in with a valid password lands on the inline enrollment step instead of
 * being bounced to the (auth-walled) dashboard:
 *   username/password → QR + secret → first authenticator code → the server persists the
 *   enrollment AND verifies the code through the standard chokepoint in the same request →
 *   one-shot backup codes → acknowledge → authenticated.
 *
 * The global policy is reverted in after() — a leftover enforcement would push every other
 * spec's users through inline enrollment.
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
    setSiteTotpSettings,
    totpCode,
} from './utils';

const SITE_KEY = 'sample-totp-enroll';

describe('TOTP inline enrollment at sign-in (UI)', () => {
    let username: string;
    let password: string;

    before(() => {
        createSiteWithTotpLoginPage(SITE_KEY);
        installTotpMFAConfig();
        // Per-site activation + global enforcement with no grace → inline enrollment is
        // the only way in for an unconfigured user.
        setSiteTotpSettings(SITE_KEY, true);
        setGlobalEnforcement('totp', 0);
    });

    after(() => {
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

    it('walks an unenrolled user through inline enrollment and signs them in', () => {
        cy.visit(getTotpLoginPageURL(SITE_KEY));

        // Stage 1: username/password.
        cy.get('[data-testid="login-username"]', {timeout: 30000}).should('be.visible');
        cy.get('[data-testid="login-username"]').type(username);
        cy.get('[data-testid="login-password"]').type(password);
        cy.get('[data-testid="login-submit"]').click();

        // Stage 2: the inline enrollment form (NOT a dashboard redirect): QR + secret.
        cy.get('[data-testid="enroll-qr"]', {timeout: 30000}).should('be.visible');
        cy.get('[data-testid="enroll-secret"]')
            .invoke('text')
            .then(rawSecret => {
                const secret = rawSecret.replace(/\s+/g, '');
                expect(secret, 'displayed secret').to.have.length.greaterThan(10);
                fillOtp('enroll-code-input', totpCode(secret));
            });

        // Stage 3: one-shot backup codes — the server already completed the MFA session
        // (confirmEnroll delegated the same code to the standard verify chokepoint).
        cy.get('[data-testid="enroll-backup-codes"]', {timeout: 30000})
            .should('be.visible')
            .invoke('text')
            .then(listText => {
                const codes = listText.trim().split('\n').map(s => s.trim()).filter(Boolean);
                expect(codes, 'backup codes count').to.have.length.greaterThan(0);
            });
        cy.get('[data-testid="enroll-backup-ack"]').click();

        // Stage 4: acknowledged → redirected off the login page as an authenticated user.
        cy.location('pathname', {timeout: 15000}).should('not.contain', '/myLoginPage.html');
    });

    it('still challenges (not enrolls) a user who configured TOTP', () => {
        // The pre-auth enrollment door must be CLOSED for configured users: after a first
        // inline enrollment, signing in again shows the verification form, never the QR.
        cy.visit(getTotpLoginPageURL(SITE_KEY));
        cy.get('[data-testid="login-username"]', {timeout: 30000}).type(username);
        cy.get('[data-testid="login-password"]').type(password);
        cy.get('[data-testid="login-submit"]').click();
        cy.get('[data-testid="enroll-qr"]', {timeout: 30000}).should('be.visible');
        cy.get('[data-testid="enroll-secret"]')
            .invoke('text')
            .then(rawSecret => {
                const secret = rawSecret.replace(/\s+/g, '');
                fillOtp('enroll-code-input', totpCode(secret));
                cy.get('[data-testid="enroll-backup-ack"]', {timeout: 30000}).click();
                cy.location('pathname', {timeout: 15000}).should('not.contain', '/myLoginPage.html');

                // Sign out and sign in again: now the verification form must show instead.
                cy.logout();
                cy.visit(getTotpLoginPageURL(SITE_KEY));
                cy.get('[data-testid="login-username"]', {timeout: 30000}).type(username);
                cy.get('[data-testid="login-password"]').type(password);
                cy.get('[data-testid="login-submit"]').click();
                cy.get('[data-testid="verification-code"]', {timeout: 30000}).should('be.visible');
                cy.get('[data-testid="enroll-qr"]').should('not.exist');
            });
    });
});
