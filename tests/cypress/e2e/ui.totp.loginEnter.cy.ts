/**
 * Keyboard-submission coverage for the TOTP login UI: pressing Enter in a form field must
 * validate the form, exactly like clicking the submit button.
 *
 * Stage 1 (username/password) and Stage 2 (TOTP code) are each submitted with the `{enter}`
 * keystroke instead of a button click. Reaching the verification step (then the post-login
 * redirect) proves Enter triggers submission.
 */
import {deleteSite, deleteUser, jfaker} from '@jahia/cypress';
import {
    createSiteWithTotpLoginPage,
    createUserForMFA,
    enrollUserInTotp,
    fillOtp,
    getTotpLoginPageURL,
    installTotpMFAConfig,
    setSiteTotpSettings,
    totpCode,
} from './utils';

const SITE_KEY = 'sample-totp-enter';

describe('TOTP login UI — Enter key submits the form', () => {
    let username: string;
    let password: string;
    let secret: string;

    before(() => {
        createSiteWithTotpLoginPage(SITE_KEY);
        installTotpMFAConfig();
        setSiteTotpSettings(SITE_KEY, true);
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
        createUserForMFA(username, password, jfaker.internet.email());
        enrollUserInTotp(username, password).then((result) => {
            secret = result.secret;
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

    it('submits the login form and the TOTP form with the Enter key (no button click)', () => {
        cy.visit(getTotpLoginPageURL(SITE_KEY));

        // Stage 1: type credentials and press Enter in the password field.
        cy.get('[data-testid="login-username"]', {timeout: 30000}).should('be.visible');
        cy.get('[data-testid="login-username"]').type(username);
        cy.get('[data-testid="login-password"]').type(`${password}{enter}`);

        // If Enter validated the login form, the TOTP verification step must appear.
        cy.get('[data-testid="verification-code"]', {timeout: 30000}).should('be.visible');

        // Stage 2: submit a fresh code (auto-verifies on last digit; full step boundary to avoid replay).
        cy.wait(31000);
        cy.wrap(null).then(() => {
            fillOtp('verification-code', totpCode(secret));
        });

        // Enter on the verify form must complete login and trigger the redirect.
        cy.location('pathname', {timeout: 15000}).should('not.contain', '/myLoginPage.html');
    });
});
