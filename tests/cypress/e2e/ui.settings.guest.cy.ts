/**
 * Live-site self-service MFA panel (totpui:mfaSettings) — anonymous visitor.
 *
 * The component is POST-AUTH: a guest must see a sign-in prompt and NONE of the management
 * sections (which would call authenticated GraphQL). This also proves the component renders
 * server-side and the island hydrates.
 */
import {deleteSite} from '@jahia/cypress';
import {createSiteWithMfaSettingsPage, getMfaSettingsPageURL} from './utils';

const SITE_KEY = 'sample-mfa-settings';

describe('MFA self-service settings UI — guest', () => {
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

    it('shows a sign-in prompt and no management sections to an anonymous visitor', () => {
        cy.logout();
        cy.visit(getMfaSettingsPageURL(SITE_KEY));

        cy.get('[data-testid="mfa-settings-signin"]', {timeout: 30000}).should('be.visible');
        cy.get('[data-testid="mfa-totp-section"]').should('not.exist');
        cy.get('[data-testid="mfa-webauthn-section"]').should('not.exist');
    });
});
