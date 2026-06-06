/**
 * E2E for INLINE security-key registration at sign-in (global enforcement):
 *
 * The global policy enforces totp+webauthn (pick-one), both factors are enabled on the site,
 * and UPA's mfaEnabledFactors stays "totp" — matching deployments where webauthn is offered
 * through enforcement only (requiredFactors=[totp]). A fresh user with NO factor configured
 * signs in, picks "Security key / passkey" on the enrollment chooser and registers through a
 * CDP virtual authenticator: attestation (create) → immediate assertion (get) → the
 * still-required totp factor must SKIP (pick-one satisfied in-session) → signed in.
 *
 * REQUIRES a Chromium secure context on http://jahia:8080 (WebAuthn is HTTPS/localhost-only),
 * so the runner must be started with:
 *   ELECTRON_EXTRA_LAUNCH_ARGS=--unsafely-treat-insecure-origin-as-secure=http://jahia:8080
 * The Relying Party is repointed to rpId=jahia for the suite and restored in after().
 */
import {deleteUser, jfaker} from '@jahia/cypress';
import gql from 'graphql-tag';
import {
    addVirtualAuthenticator,
    createSiteWithTotpLoginPage,
    createUserForMFA,
    deleteTotpLoginSite,
    getTotpLoginPageURL,
    installTotpMFAConfig,
    setGlobalEnforcement,
    setSiteTotpSettings,
    setSiteWebauthnSettings,
    setWebauthnRpId,
} from './utils';

const SITE_KEY = 'sample-webauthn-enroll';

describe('WebAuthn inline registration at sign-in (UI)', () => {
    let username: string;
    let password: string;

    before(() => {
        createSiteWithTotpLoginPage(SITE_KEY);
        installTotpMFAConfig();
        setSiteTotpSettings(SITE_KEY, true);
        setSiteWebauthnSettings(SITE_KEY, true);
        setWebauthnRpId('jahia'); // the in-network host the test browser is on
        setGlobalEnforcement('totp,webauthn', 0);
    });

    after(() => {
        setGlobalEnforcement('', 0);
        setWebauthnRpId('localhost');
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

    it('registers a security key inline and signs the user in (totp pick-one skips)', () => {
        addVirtualAuthenticator();
        cy.visit(getTotpLoginPageURL(SITE_KEY));

        // Stage 1: username/password.
        cy.get('[data-testid="login-username"]', {timeout: 30000}).should('be.visible');
        cy.get('[data-testid="login-username"]').type(username);
        cy.get('[data-testid="login-password"]').type(password);
        cy.get('[data-testid="login-submit"]').click();

        // Stage 2: the enrollment chooser offers BOTH enforced factors.
        cy.get('[data-testid="enroll-choose-webauthn"]', {timeout: 30000}).should('be.visible');
        cy.get('[data-testid="enroll-choose-totp"]').should('be.visible');
        cy.get('[data-testid="enroll-choose-webauthn"]').click();

        // Stage 3: one button drives the whole ceremony — the virtual authenticator
        // answers both touches (create for registration, get for the sign-in assertion).
        cy.get('[data-testid="enroll-webauthn-register"]', {timeout: 30000}).click();

        // Stage 4: attestation + assertion done, totp skipped (pick-one) → authenticated
        // and redirected off the login page.
        cy.location('pathname', {timeout: 30000}).should('not.contain', '/myLoginPage.html');
    });

    it('does not re-offer enrollment to a user who already owns a credential', () => {
        // First pass: register inline as above.
        addVirtualAuthenticator();
        cy.visit(getTotpLoginPageURL(SITE_KEY));
        cy.get('[data-testid="login-username"]', {timeout: 30000}).type(username);
        cy.get('[data-testid="login-password"]').type(password);
        cy.get('[data-testid="login-submit"]').click();
        cy.get('[data-testid="enroll-choose-webauthn"]', {timeout: 30000}).click();
        cy.get('[data-testid="enroll-webauthn-register"]', {timeout: 30000}).click();
        cy.location('pathname', {timeout: 30000}).should('not.contain', '/myLoginPage.html');

        // Second pass: the pre-auth enrollment door must be CLOSED. With UPA's
        // mfaEnabledFactors=totp (this suite's shape), the required totp factor skips via
        // pick-one (sibling webauthn is configured) and the user is signed straight in —
        // the provider logs a misconfiguration WARN because webauthn itself is never
        // challenged; deployments must list every enforced factor in mfaEnabledFactors
        // (see README). Either way: NO enrollment chooser, NO QR, no dead end.
        cy.logout();
        cy.visit(getTotpLoginPageURL(SITE_KEY));
        cy.get('[data-testid="login-username"]', {timeout: 30000}).type(username);
        cy.get('[data-testid="login-password"]').type(password);
        cy.get('[data-testid="login-submit"]').click();
        cy.location('pathname', {timeout: 30000}).should('not.contain', '/myLoginPage.html');
        cy.get('[data-testid="enroll-choose-webauthn"]').should('not.exist');
        cy.get('[data-testid="enroll-qr"]').should('not.exist');
    });

    it('offers enrollment again after an admin reset', () => {
        // First pass: register inline as in the previous test.
        addVirtualAuthenticator();
        cy.visit(getTotpLoginPageURL(SITE_KEY));
        cy.get('[data-testid="login-username"]', {timeout: 30000}).type(username);
        cy.get('[data-testid="login-password"]').type(password);
        cy.get('[data-testid="login-submit"]').click();
        cy.get('[data-testid="enroll-choose-webauthn"]', {timeout: 30000}).click();
        cy.get('[data-testid="enroll-webauthn-register"]', {timeout: 30000}).click();
        cy.location('pathname', {timeout: 30000}).should('not.contain', '/myLoginPage.html');

        // Real user nodes always carry unrelated children (preferences, files, ...). A fresh
        // test user may have none, so recreate that shape explicitly — hasCredentials() must
        // not mistake such children for credentials after the reset (the upaWebauthn mixin
        // legitimately survives deleteAll because it still tracks the grace window).
        cy.apollo({
            query: gql`
                query UserNodePath($query: String!) {
                    jcr {
                        nodesByQuery(query: $query) {
                            nodes {
                                path
                            }
                        }
                    }
                }
            `,
            variables: {query: `SELECT * FROM [jnt:user] WHERE localname() = '${username}'`},
        }).then(resp => {
            const userPath = resp.data.jcr.nodesByQuery.nodes[0].path as string;
            cy.apollo({
                mutation: gql`
                    mutation AddUserChild($parent: String!) {
                        jcr {
                            addNode(parentPathOrId: $parent, name: "files", primaryNodeType: "jnt:folder") {
                                uuid
                            }
                        }
                    }
                `,
                variables: {parent: userPath},
            });
        });

        // Admin recovery: wipe the user's credentials.
        cy.apollo({
            mutation: gql`
                mutation ResetUser($userId: String!, $siteKey: String!) {
                    upa {
                        mfaFactors {
                            webauthn {
                                resetUserWebauthn(userId: $userId, siteKey: $siteKey)
                            }
                        }
                    }
                }
            `,
            variables: {userId: username, siteKey: SITE_KEY},
        });

        // The user must be offered enrollment again — NOT an unsatisfiable passkey
        // assertion against zero stored credentials.
        cy.logout();
        cy.visit(getTotpLoginPageURL(SITE_KEY));
        cy.get('[data-testid="login-username"]', {timeout: 30000}).type(username);
        cy.get('[data-testid="login-password"]').type(password);
        cy.get('[data-testid="login-submit"]').click();
        cy.get('[data-testid="enroll-choose-webauthn"]', {timeout: 30000}).should('be.visible');
        cy.get('[data-testid="webauthn-authenticate"]').should('not.exist');
    });
});
