/**
 * UI tests for the TOTP MFA dashboard page.
 *
 * Exercises the React UI registered by mfa-factors-totp at adminRoute
 * `mfa-factors-totp` (sidebar target `dashboard-mfa-community-dashboard:1`,
 * under the shared "MFA Community" dashboard group). The route lives at
 * `/jahia/dashboard/mfa-factors-totp`.
 *
 * Each test runs against a fresh user so enrollment state never bleeds
 * between specs. State is asserted via which action button is visible
 * (Enable vs. Disable/Regenerate) rather than via the moonstone Chip's
 * label text, because the Chip renders the label inside nested DOM that
 * isn't reliably reachable from a `.contain()` on the parent.
 */
import {jfaker, deleteUser} from '@jahia/cypress';
import {createUserForMFA, totpCode} from './utils';

const DASHBOARD_PATH = '/jahia/dashboard/mfa-factors-totp';

describe('TOTP dashboard UI', () => {
    let usr: string;
    let pwd: string;

    beforeEach(() => {
        usr = jfaker.internet.username();
        pwd = jfaker.internet.password();
        createUserForMFA(usr, pwd, jfaker.internet.email());
        cy.login(usr, pwd);
        cy.visit(DASHBOARD_PATH);
        // StatusQuery has resolved by the time the action button renders.
        cy.get('[data-testid="enable-mfa-btn"]', {timeout: 30000}).should('be.visible');
    });

    afterEach(() => {
        try { deleteUser(usr); } catch (_e) { /* ignore */ }
    });

    it('enrolls, shows backup codes, then disables — full UI flow', () => {
        // 1. Click "Enable" → the EnrollDialog opens with a QR + the Base32 secret.
        cy.get('[data-testid="enable-mfa-btn"]').click();
        cy.get('[data-testid="enroll-qr"]', {timeout: 15000}).should('be.visible');
        cy.get('[data-testid="enroll-secret"]')
            .invoke('text')
            .then(rawSecret => {
                const secret = rawSecret.replace(/\s+/g, '');
                expect(secret, 'displayed secret').to.have.length.greaterThan(10);

                // 2. Compute the current code and confirm (dashboard EnrollDialog uses a
                // single Moonstone input + an explicit confirm button, not the segmented
                // login-ui field).
                cy.get('[data-testid="enroll-code-input"]').type(totpCode(secret));
                cy.get('[data-testid="enroll-confirm-btn"]').click();

                // 3. BackupCodesDialog opens with the freshly-generated codes.
                cy.get('[data-testid="backup-codes-list"]', {timeout: 15000})
                    .should('be.visible')
                    .invoke('text')
                    .then(listText => {
                        const codes = listText.trim().split('\n').map(s => s.trim()).filter(Boolean);
                        expect(codes, 'backup codes count').to.have.length.greaterThan(0);
                        codes.forEach(bc => expect(bc).to.have.length.greaterThan(4));
                    });
                cy.get('[data-testid="backup-codes-ack"]').check();
                cy.get('[data-testid="backup-codes-close-btn"]').click();

                // 4. Enrolled-state buttons are now visible.
                cy.get('[data-testid="disable-mfa-btn"]', {timeout: 15000}).should('be.visible');
                cy.get('[data-testid="regen-backup-btn"]').should('be.visible');

                // 5. Disable: wait past the 30s step boundary to dodge replay rejection.
                //    The TOTP code MUST be computed inside .then() so it's evaluated at command
                //    execution time (after the wait), not when the cy chain is queued.
                cy.wait(31000);
                cy.get('[data-testid="disable-mfa-btn"]').click();
                cy.wrap(null).then(() => {
                    const liveCode = totpCode(secret);
                    cy.get('[data-testid="code-prompt-input"]').type(liveCode);
                    cy.get('[data-testid="code-prompt-accept-btn"]').click();
                });

                // 6. Back to the disabled state.
                cy.get('[data-testid="enable-mfa-btn"]', {timeout: 15000}).should('be.visible');
            });
    });

    it('regenerates backup codes after enrollment', () => {
        // Enroll first.
        cy.get('[data-testid="enable-mfa-btn"]').click();
        cy.get('[data-testid="enroll-secret"]')
            .invoke('text')
            .then(rawSecret => {
                const secret = rawSecret.replace(/\s+/g, '');
                cy.get('[data-testid="enroll-code-input"]').type(totpCode(secret));
                cy.get('[data-testid="enroll-confirm-btn"]').click();

                // Capture the original backup codes.
                cy.get('[data-testid="backup-codes-list"]', {timeout: 15000})
                    .invoke('text')
                    .then(firstSetRaw => {
                        const firstSet = firstSetRaw.trim();
                        cy.get('[data-testid="backup-codes-ack"]').check();
                        cy.get('[data-testid="backup-codes-close-btn"]').click();

                        // Wait past the 30s step to dodge replay rejection. The code must be
                        // computed AFTER the wait — see comment in test 1.
                        cy.wait(31000);

                        cy.get('[data-testid="regen-backup-btn"]').click();
                        cy.wrap(null).then(() => {
                            const liveCode = totpCode(secret);
                            cy.get('[data-testid="code-prompt-input"]').type(liveCode);
                            cy.get('[data-testid="code-prompt-accept-btn"]').click();
                        });

                        // New set must differ.
                        cy.get('[data-testid="backup-codes-list"]', {timeout: 15000})
                            .invoke('text')
                            .then(secondSetRaw => {
                                const secondSet = secondSetRaw.trim();
                                expect(secondSet).to.have.length.greaterThan(0);
                                expect(secondSet).to.not.equal(firstSet);
                            });
                        cy.get('[data-testid="backup-codes-ack"]').check();
                        cy.get('[data-testid="backup-codes-close-btn"]').click();
                    });
            });
    });

    it('rejects a wrong confirm code with the invalidCode error', () => {
        cy.get('[data-testid="enable-mfa-btn"]').click();
        cy.get('[data-testid="enroll-qr"]', {timeout: 15000}).should('be.visible');

        cy.get('[data-testid="enroll-code-input"]').type('000000');
        cy.get('[data-testid="enroll-confirm-btn"]').click();

        cy.get('[data-testid="enroll-error"]', {timeout: 15000})
            .should('be.visible')
            .and('contain', 'Invalid code');
    });
});
