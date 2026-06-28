/**
 * Live-site self-service MFA panel (totpui:mfaSettings) — TOTP section, as a logged-in user.
 *
 * Proves the authenticated browser session can drive the self-service GraphQL (status/enroll/
 * confirmEnroll/disable) from a front-end page, and the full enroll → backup-codes → disable flow.
 * Disable uses a BACKUP code so we don't have to wait out the 30s replay window after confirm.
 */
import {deleteSite, deleteUser, jfaker} from '@jahia/cypress';
import {createSiteWithMfaSettingsPage, createUserForMFA, fillOtp, getMfaSettingsPageURL, totpCode} from './utils';

const SITE_KEY = 'sample-mfa-settings';

describe('MFA self-service settings UI — TOTP', () => {
    let username: string;
    let password: string;

    before(() => {
        createSiteWithMfaSettingsPage(SITE_KEY);
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
        cy.login(username, password);
        cy.visit(getMfaSettingsPageURL(SITE_KEY));
        // The section has loaded once the status line (or its enable button) renders.
        cy.get('[data-testid="mfa-totp-section"]', {timeout: 30000}).should('be.visible');
    });

    afterEach(() => {
        cy.logout();
        try {
            deleteUser(username);
        } catch (_e) {
            // ignore
        }
    });

    it('enrolls TOTP, shows backup codes, then disables with a fresh code', () => {
        // 1. Not enrolled yet.
        cy.get('[data-testid="mfa-totp-enable"]', {timeout: 30000}).should('be.visible').click();

        // 2. Enrollment ceremony: QR + secret render; confirm with a fresh code. Keep the secret
        // (aliased) so we can compute a later code for disable.
        cy.get('[data-testid="mfa-totp-qr"]', {timeout: 15000}).should('be.visible');
        cy.get('[data-testid="mfa-totp-secret"]')
            .invoke('text')
            .then((raw) => {
                const secret = raw.replace(/\s+/g, '');
                expect(secret, 'displayed secret').to.have.length.greaterThan(10);
                cy.wrap(secret).as('secret');
                fillOtp('mfa-totp-confirm-input', totpCode(secret));
            });

        // 3. Backup codes shown; acknowledge.
        cy.get('[data-testid="mfa-backup-codes"]', {timeout: 15000})
            .invoke('text')
            .then((text) => {
                const codes = text.trim().split('\n').map((s) => s.trim()).filter(Boolean);
                expect(codes, 'backup codes generated').to.have.length.greaterThan(0);
            });
        cy.get('[data-testid="mfa-backup-ack"]').click();

        // 4. Now enrolled.
        cy.get('[data-testid="mfa-totp-status"]', {timeout: 15000}).should('contain', 'Enabled');

        // 5. Disable with a LIVE authenticator code (self-service management does not accept backup
        // codes). Wait past the 30s step so the disable code is on a counter strictly greater than
        // the one consumed by confirmEnroll, avoiding replay rejection.
        cy.get('[data-testid="mfa-totp-disable"]').click();
        cy.wait(31000);
        cy.get<string>('@secret').then((secret) => {
            fillOtp('mfa-totp-disable-input', totpCode(secret));
        });

        // 6. Back to not-enrolled.
        cy.get('[data-testid="mfa-totp-enable"]', {timeout: 15000}).should('be.visible');
    });
});
