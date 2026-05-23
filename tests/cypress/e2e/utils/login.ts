/**
 * Helpers for the TOTP login UI spec — site/page provisioning + a GraphQL-based
 * enrollment shortcut so tests don't have to drive the dashboard UI just to land
 * a user in an enrolled state.
 */
import {
    addNode,
    createSite,
    deleteSite,
    enableModule,
    publishAndWaitJobEnding,
} from '@jahia/cypress';
import {confirmEnroll, enroll} from './api';
import {totpCode} from './totp';

export const TOTP_LOGIN_PAGE_NAME = 'myLoginPage';

export function getTotpLoginPageURL(siteKey: string): string {
    return `/sites/${siteKey}/${TOTP_LOGIN_PAGE_NAME}.html`;
}

/**
 * Provision a site containing a published page that renders the totpui:authentication view.
 * The site uses UPA's `user-password-authentication-template-set-test-module` for the
 * baseline template-set so the page can declare `j:templateName=simple`.
 *
 * Modules enabled on the site:
 *   - user-password-authentication-ui     (provides the template-set scaffolding deps)
 *   - mfa-totp-factor-login-ui            (provides the totpui:authentication view)
 */
export function createSiteWithTotpLoginPage(siteKey: string): void {
    deleteSite(siteKey);
    createSite(siteKey, {
        locale: 'en',
        languages: 'en',
        serverName: 'localhost',
        templateSet: 'user-password-authentication-template-set-test-module',
    });
    enableModule('user-password-authentication-ui', siteKey);
    enableModule('mfa-totp-factor-login-ui', siteKey);

    addNode({
        parentPathOrId: `/sites/${siteKey}`,
        name: TOTP_LOGIN_PAGE_NAME,
        primaryNodeType: 'jnt:page',
        properties: [
            {name: 'jcr:title', value: 'TOTP login page', language: 'en'},
            {name: 'j:templateName', value: 'simple'},
        ],
    });
    addNode({
        parentPathOrId: `/sites/${siteKey}/${TOTP_LOGIN_PAGE_NAME}`,
        name: 'pagecontent',
        primaryNodeType: 'jnt:contentList',
        properties: [],
    });
    addNode({
        parentPathOrId: `/sites/${siteKey}/${TOTP_LOGIN_PAGE_NAME}/pagecontent`,
        name: 'authentication',
        primaryNodeType: 'totpui:authentication',
        properties: [],
    });
    publishAndWaitJobEnding(`/sites/${siteKey}`, ['en']);
}

export function deleteTotpLoginSite(siteKey: string): void {
    try {
        deleteSite(siteKey);
    } catch (_e) {
        // best-effort
    }
}

/** Install (or re-install) the MFA Karaf config via the provisioning servlet. */
export function installTotpMFAConfig(): void {
    cy.runProvisioningScript({
        script: {fileName: 'mfa-configuration/totp-login.yml', type: 'application/yaml'},
    });
}

/**
 * Enroll the currently-authenticated user in TOTP via GraphQL. Returns the Base32 secret
 * and the plaintext backup codes — both shown once, the caller is responsible for storing
 * them (typically in test-local state).
 *
 * Side-effect: leaves the user enrolled in JCR. The caller must reset the apollo client
 * to the user it wants to log in as.
 */
export function enrollUserInTotp(
    username: string,
    password: string,
): Cypress.Chainable<{secret: string; backupCodes: string[]}> {
    cy.apolloClient({username, password});
    return enroll().then((enrollResponse) => {
        const enrollData = enrollResponse?.data?.upa?.mfaFactors?.totp?.enroll;
        expect(enrollData, 'enroll should succeed').to.not.be.undefined;
        const secret = enrollData.secret as string;
        const code = totpCode(secret);
        return confirmEnroll(code).then((confirmResponse) => {
            const ce = confirmResponse?.data?.upa?.mfaFactors?.totp?.confirmEnroll;
            expect(ce, 'confirmEnroll should succeed').to.not.be.undefined;
            return {secret, backupCodes: ce.backupCodes as string[]};
        });
    });
}
