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
import gql from 'graphql-tag';
import {confirmEnroll, enroll} from './api';
import {totpCode} from './totp';

/**
 * Enable (or disable) TOTP MFA on a site via the per-site GraphQL mutation.
 * Must run as an authenticated site admin / root (the default apollo client is root).
 * Required because TOTP is opt-in per site — without this the factor is skipped at login
 * even when totp is in the global mfaEnabledFactors config. (Enforcement is GLOBAL: see
 * setGlobalEnforcement.)
 */
export function setSiteTotpSettings(siteKey: string, enabled: boolean) {
    return cy.apollo({
        mutation: gql`
            mutation SetSiteTotp($siteKey: String!, $enabled: Boolean!) {
                upa {
                    mfaFactors {
                        totp {
                            setSiteSettings(siteKey: $siteKey, enabled: $enabled) {
                                siteKey
                                enabled
                            }
                        }
                    }
                }
            }
        `,
        variables: {siteKey, enabled},
        errorPolicy: 'all',
    });
}

/**
 * Set the GLOBAL enforcement policy (PID org.jahia.modules.mfa.extensions) through the
 * provisioning API: which factors are enforced platform-wide and the grace window in days.
 * Pass an empty string to turn enforcement off. ALWAYS revert in after() — a leftover
 * enforcement policy would push every other spec's users through inline enrollment.
 */
export function setGlobalEnforcement(enforcedFactors: string, graceDays = 0) {
    const password = Cypress.env('SUPER_USER_PASSWORD') as string;
    cy.request({
        method: 'POST',
        url: '/modules/api/provisioning',
        auth: {user: 'root', pass: password},
        headers: {'Content-Type': 'application/json'},
        body: [{
            editConfiguration: 'org.jahia.modules.mfa.extensions',
            properties: {enforcedFactors, graceDays: String(graceDays)},
        }],
    });
    // Give ConfigAdmin a moment to dispatch the @Modified event to the policy component.
    cy.wait(2000);
}

/**
 * Set (or clear, with '') the GLOBAL MFA login/logout URLs (PID org.jahia.modules.mfa.extensions).
 * When set, MfaLoginLogoutProvider serves them to Jahia's 401/logout handling and appends a
 * `redirect=` param carrying the page the user was after. Specs MUST clear them in after() —
 * a leftover URL would reroute every other spec's 401s to a deleted page.
 */
export function setGlobalMfaUrls(loginUrl: string, logoutUrl = '') {
    const password = Cypress.env('SUPER_USER_PASSWORD') as string;
    cy.request({
        method: 'POST',
        url: '/modules/api/provisioning',
        auth: {user: 'root', pass: password},
        headers: {'Content-Type': 'application/json'},
        body: [{
            editConfiguration: 'org.jahia.modules.mfa.extensions',
            properties: {loginUrl, logoutUrl},
        }],
    });
    // Give ConfigAdmin a moment to dispatch the @Modified event to the provider.
    cy.wait(2000);
}

/**
 * Set UPA's `mfaEnabledFactors` (PID org.jahia.modules.upa) to a REAL string array.
 * The provisioning API can only submit strings, and UPA's String[] metatype never
 * comma-splits — `totp,email_code` through provisioning binds as ONE bogus entry. This
 * helper goes through ConfigurationAdmin (groovy console) instead, which accepts a typed
 * String[] and persists it in Felix's typed .config format. ALWAYS restore in after().
 */
export function setUpaEnabledFactors(factors: string[]) {
    const password = Cypress.env('SUPER_USER_PASSWORD') as string;
    const literal = factors.map(f => JSON.stringify(f)).join(', ');
    const script = [
        // BundleUtils, not getBundleContext().getServiceReference(): the console's framework
        // context cannot see ConfigurationAdmin directly (returns null).
        'def ca = org.jahia.osgi.BundleUtils.getOsgiService("org.osgi.service.cm.ConfigurationAdmin", null)',
        'def cfg = ca.getConfiguration("org.jahia.modules.upa", null)',
        'def props = cfg.getProperties() ?: new Hashtable()',
        `props.put("mfaEnabledFactors", [${literal}] as String[])`,
        'cfg.update(props)',
    ].join('\n');
    cy.request({
        method: 'POST',
        url: '/modules/tools/groovyConsole.jsp',
        auth: {user: 'root', pass: password},
        form: true,
        body: {script, runScript: 'true'},
    });
    // Give ConfigAdmin a moment to dispatch the @Modified event to UPA's config service.
    cy.wait(2000);
}

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
 *   - mfa-factors-login-ui            (provides the totpui:authentication view)
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
    enableModule('mfa-factors-login-ui', siteKey);

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

export const MFA_SETTINGS_PAGE_NAME = 'mfaSettings';

export function getMfaSettingsPageURL(siteKey: string): string {
    return `/sites/${siteKey}/${MFA_SETTINGS_PAGE_NAME}.html`;
}

/**
 * Provision a site containing a published page that renders the totpui:mfaSettings view
 * (the live-site self-service MFA panel). Mirrors createSiteWithTotpLoginPage. The component
 * is POST-AUTH: an anonymous visitor sees a sign-in prompt; a logged-in user manages their
 * own factors.
 */
export function createSiteWithMfaSettingsPage(siteKey: string): void {
    deleteSite(siteKey);
    createSite(siteKey, {
        locale: 'en',
        languages: 'en',
        serverName: 'localhost',
        templateSet: 'user-password-authentication-template-set-test-module',
    });
    enableModule('user-password-authentication-ui', siteKey);
    enableModule('mfa-factors-login-ui', siteKey);

    addNode({
        parentPathOrId: `/sites/${siteKey}`,
        name: MFA_SETTINGS_PAGE_NAME,
        primaryNodeType: 'jnt:page',
        properties: [
            {name: 'jcr:title', value: 'MFA settings page', language: 'en'},
            {name: 'j:templateName', value: 'simple'},
        ],
    });
    addNode({
        parentPathOrId: `/sites/${siteKey}/${MFA_SETTINGS_PAGE_NAME}`,
        name: 'pagecontent',
        primaryNodeType: 'jnt:contentList',
        properties: [],
    });
    addNode({
        parentPathOrId: `/sites/${siteKey}/${MFA_SETTINGS_PAGE_NAME}/pagecontent`,
        name: 'mfaSettings',
        primaryNodeType: 'totpui:mfaSettings',
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
