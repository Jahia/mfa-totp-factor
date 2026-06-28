/**
 * Live-site self-service MFA panel (totpui:mfaSettings) — WebAuthn section, as a logged-in user.
 *
 * Drives the passkey lifecycle from a front-end page: add (registration ceremony via a CDP virtual
 * authenticator), rename, and remove. Post-auth registration completes directly (no assertion
 * "second touch" like the login flow). RP id is pointed at `jahia` because the browser runs on
 * http://jahia:8080 inside the compose network.
 */
import {deleteSite, deleteUser, jfaker} from '@jahia/cypress';
import {
    addVirtualAuthenticator,
    createSiteWithMfaSettingsPage,
    createUserForMFA,
    getMfaSettingsPageURL,
    setWebauthnRpId,
} from './utils';

const SITE_KEY = 'sample-mfa-settings';

describe('MFA self-service settings UI — WebAuthn', () => {
    let username: string;
    let password: string;

    before(() => {
        createSiteWithMfaSettingsPage(SITE_KEY);
        setWebauthnRpId('jahia');
    });

    after(() => {
        setWebauthnRpId('localhost');
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
        addVirtualAuthenticator();
        cy.visit(getMfaSettingsPageURL(SITE_KEY));
        cy.get('[data-testid="mfa-webauthn-section"]', {timeout: 30000}).should('be.visible');
    });

    afterEach(() => {
        cy.logout();
        try {
            deleteUser(username);
        } catch (_e) {
            // ignore
        }
    });

    it('adds, renames, then removes a passkey', () => {
        // Start empty.
        cy.get('[data-testid="mfa-webauthn-empty"]', {timeout: 30000}).should('be.visible');

        // Add: the virtual authenticator auto-answers the ceremony.
        cy.get('[data-testid="mfa-webauthn-add"]').click();
        cy.get('[data-testid="mfa-webauthn-credentials"]', {timeout: 30000}).should('be.visible');
        cy.get('[data-testid="mfa-webauthn-name"]').should('have.length', 1);

        // Rename.
        cy.get('[data-testid="mfa-webauthn-rename"]').click();
        cy.get('[data-testid="mfa-webauthn-rename-input"]').clear().type('My laptop');
        cy.get('[data-testid="mfa-webauthn-rename-save"]').click();
        cy.get('[data-testid="mfa-webauthn-name"]', {timeout: 15000}).should('contain', 'My laptop');

        // Remove (the window.confirm is auto-accepted).
        cy.on('window:confirm', () => true);
        cy.get('[data-testid="mfa-webauthn-remove"]').click();
        cy.get('[data-testid="mfa-webauthn-empty"]', {timeout: 15000}).should('be.visible');
    });
});
