/**
 * Server-administration panel for the global MFA configuration (extensions bundle):
 * Administration → Server → Configuration → "MFA Community", adminRoute key
 * `mfa-extensions-settings` (route /jahia/administration/mfa-extensions-settings, server
 * `admin` permission required).
 *
 * Edits a value through the UI, saves, reloads and asserts persistence; the defaults are
 * restored at the end (a leftover grace value is harmless, but stay clean anyway).
 */
const ADMIN_ROUTE = '/jahia/administration/mfa-extensions-settings';

describe('Global MFA configuration panel (server administration UI)', () => {
    beforeEach(() => {
        cy.login(); // Root: server administrator.
    });

    after(() => {
        cy.logout();
    });

    it('renders every configuration field', () => {
        cy.visit(ADMIN_ROUTE);
        cy.get('[data-testid="enforce-totp-toggle"]', {timeout: 30000}).should('exist');
        cy.get('[data-testid="enforce-webauthn-toggle"]').should('exist');
        cy.get('[data-testid="extensions-grace-input"]').should('exist');
        cy.get('[data-testid="extensions-gate-toggle"]').should('exist');
        cy.get('[data-testid="extensions-gate-trust-xff-toggle"]').should('exist');
        cy.get('[data-testid="extensions-gate-whitelist-input"]').should('exist');
        cy.get('[data-testid="extensions-login-url-input"]').should('exist');
        cy.get('[data-testid="extensions-logout-url-input"]').should('exist');
        cy.get('[data-testid="extensions-reset-notify-email-input"]').should('exist');
        cy.get('[data-testid="extensions-global-save-btn"]').should('be.visible');
    });

    it('saves the reset-notification email and rejects a malformed one', () => {
        cy.visit(ADMIN_ROUTE);
        // A valid recipient persists across a reload.
        cy.get('[data-testid="extensions-reset-notify-email-input"]', {timeout: 30000})
            .clear()
            .type('mfa-admin@example.com');
        cy.get('[data-testid="extensions-global-save-btn"]').click();
        cy.get('[data-testid="extensions-global-saved"]', {timeout: 15000}).should('be.visible');
        cy.reload();
        cy.get('[data-testid="extensions-reset-notify-email-input"]', {timeout: 30000})
            .should('have.value', 'mfa-admin@example.com');

        // A malformed address is rejected server-side and surfaced.
        cy.get('[data-testid="extensions-reset-notify-email-input"]').clear().type('not-an-email');
        cy.get('[data-testid="extensions-global-save-btn"]').click();
        cy.get('[data-testid="extensions-global-error"]', {timeout: 15000}).should('be.visible');

        // Restore the default (empty).
        cy.get('[data-testid="extensions-reset-notify-email-input"]').clear();
        cy.get('[data-testid="extensions-global-save-btn"]').click();
        cy.get('[data-testid="extensions-global-saved"]', {timeout: 15000}).should('be.visible');
    });

    it('saves a change and persists it across a reload', () => {
        cy.visit(ADMIN_ROUTE);
        cy.get('[data-testid="extensions-logout-url-input"]', {timeout: 30000})
            .clear()
            .type('/sites/uiTest/logout.html');
        cy.get('[data-testid="extensions-global-save-btn"]').click();
        cy.get('[data-testid="extensions-global-saved"]', {timeout: 15000}).should('be.visible');

        cy.reload();
        cy.get('[data-testid="extensions-logout-url-input"]', {timeout: 30000})
            .should('have.value', '/sites/uiTest/logout.html');

        // Restore the default.
        cy.get('[data-testid="extensions-logout-url-input"]').clear();
        cy.get('[data-testid="extensions-global-save-btn"]').click();
        cy.get('[data-testid="extensions-global-saved"]', {timeout: 15000}).should('be.visible');
    });

    it('toggles trust-X-Forwarded-For (default on) and persists it', () => {
        cy.visit(ADMIN_ROUTE);
        // Defaults to checked (backward-compatible default true).
        cy.get('[data-testid="extensions-gate-trust-xff-toggle"]', {timeout: 30000}).should('be.checked');

        // Turn it off and persist.
        cy.get('[data-testid="extensions-gate-trust-xff-toggle"]').uncheck();
        cy.get('[data-testid="extensions-global-save-btn"]').click();
        cy.get('[data-testid="extensions-global-saved"]', {timeout: 15000}).should('be.visible');
        cy.reload();
        cy.get('[data-testid="extensions-gate-trust-xff-toggle"]', {timeout: 30000}).should('not.be.checked');

        // Restore the default (on).
        cy.get('[data-testid="extensions-gate-trust-xff-toggle"]').check();
        cy.get('[data-testid="extensions-global-save-btn"]').click();
        cy.get('[data-testid="extensions-global-saved"]', {timeout: 15000}).should('be.visible');
    });

    it('surfaces a validation error from the server', () => {
        cy.visit(ADMIN_ROUTE);
        cy.get('[data-testid="extensions-gate-whitelist-input"]', {timeout: 30000})
            .clear()
            .type('not-an-ip');
        cy.get('[data-testid="extensions-global-save-btn"]').click();
        cy.get('[data-testid="extensions-global-error"]', {timeout: 15000}).should('be.visible');

        // Restore: clear the invalid value without saving garbage.
        cy.get('[data-testid="extensions-gate-whitelist-input"]').clear();
        cy.get('[data-testid="extensions-global-save-btn"]').click();
        cy.get('[data-testid="extensions-global-saved"]', {timeout: 15000}).should('be.visible');
    });
});
