/**
 * Locked-out "request MFA reset" flow (Phase 2).
 *
 * A user proves their password but is stuck at the MFA step. The login UI offers a
 * "Lost access to your second factor?" affordance that calls the session-bound mfaRequestReset
 * mutation, which emails the configured administrator(s). We drive a TOTP-enrolled user to the
 * verify step, request a reset, and assert the generic confirmation + that the admin notification
 * lands in Mailpit. The actual reset stays admin-only (resetUserMfa) and is not exercised here.
 */
import {deleteSite, deleteUser, jfaker} from '@jahia/cypress';
import {
    createSiteWithTotpLoginPage,
    createUserForMFA,
    enrollUserInTotp,
    getTotpLoginPageURL,
    installTotpMFAConfig,
    setSiteTotpSettings,
} from './utils';

const SITE_KEY = 'sample-reset-ui';
const NOTIFY = 'mfa-admin@mfa-spec.test';

/** Set (or clear, with '') the reset-request notification recipient on the shared extensions PID. */
function setResetNotifyEmail(email: string) {
    const password = Cypress.env('SUPER_USER_PASSWORD') as string;
    cy.request({
        method: 'POST',
        url: '/modules/api/provisioning',
        auth: {user: 'root', pass: password},
        headers: {'Content-Type': 'application/json'},
        body: [{
            editConfiguration: 'org.jahia.modules.mfa.extensions',
            properties: {'resetRequest.notifyEmail': email},
        }],
    });
    // Give ConfigAdmin a moment to dispatch the @Modified event to MfaGlobalPolicy.
    cy.wait(2000);
}

describe('Locked-out MFA reset request', () => {
    let username: string;
    let password: string;

    before(() => {
        // Activate Jahia's mail service against the stack's Mailpit container (warm stacks lose it).
        cy.executeGroovy('groovy/setupMail.groovy');
        createSiteWithTotpLoginPage(SITE_KEY);
        installTotpMFAConfig();
        setSiteTotpSettings(SITE_KEY, true);
        setResetNotifyEmail(NOTIFY);
    });

    after(() => {
        setResetNotifyEmail('');
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
        // Enrol in TOTP so login challenges the factor and lands on the verify step.
        enrollUserInTotp(username, password);
        cy.logout();
        cy.mailpitDeleteAllEmails();
    });

    afterEach(() => {
        try {
            deleteUser(username);
        } catch (_e) {
            // ignore
        }
    });

    it('requests a reset from the MFA step and notifies the admin by email', () => {
        cy.visit(getTotpLoginPageURL(SITE_KEY));

        // Password stage.
        cy.get('[data-testid="login-username"]', {timeout: 30000}).should('be.visible').type(username);
        cy.get('[data-testid="login-password"]').type(password);
        cy.get('[data-testid="login-submit"]').click();

        // MFA verify stage: the reset affordance is available here.
        cy.get('[data-testid="verification-code"]', {timeout: 30000}).should('be.visible');
        cy.get('[data-testid="reset-request-open"]').click();
        cy.get('[data-testid="reset-request-submit"]').click();

        // Generic confirmation, regardless of outcome.
        cy.get('[data-testid="reset-request-confirmation"]', {timeout: 15000}).should('be.visible');

        // The configured administrator received a notification.
        cy.waitUntil(
            () => cy.mailpitSearchEmails(`to:${NOTIFY}`).then((result) => (result.messages ?? []).length > 0),
            {timeout: 20000, interval: 1000, errorMsg: `no admin reset-notification received for ${NOTIFY}`},
        );
    });
});
