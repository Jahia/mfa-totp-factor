/**
 * UPA's built-in email_code factor offered as a pick-one alternative at sign-in.
 *
 * Server side under test:
 *   - EmailCodeFactorAdapter (extensions): makes the email factor visible to the chooser
 *     filter (`mfaSessionFactors.configuredFactors`) for any user with a j:email.
 *   - MfaForeignFactorDrain (extensions): a genuine TOTP verification releases the required
 *     email_code factor (UPA's provider cannot skip itself) WITHOUT sending an email.
 *   - The native pick-one rows: a genuine email verification makes totp skip itself.
 *
 * Harness notes:
 *   - mfaEnabledFactors needs a REAL String[] of two entries — impossible through the
 *     provisioning string API (metatype comma-trap), hence setUpaEnabledFactors (groovy →
 *     ConfigurationAdmin). This is also the first spec covering a multi-factor UPA shape.
 *   - Codes are read from Mailpit (cypress-mailpit; the stack's smtp-server container).
 */
import {deleteSite, deleteUser, jfaker} from '@jahia/cypress';
import {
    createSiteWithTotpLoginPage,
    createUserForMFA,
    enrollUserInTotp,
    fillOtp,
    getTotpLoginPageURL,
    setGlobalEnforcement,
    setSiteTotpSettings,
    setUpaEnabledFactors,
    totpCode,
} from './utils';

const SITE_KEY = 'sample-email-ui';

describe('Email-code factor at sign-in', () => {
    let username: string;
    let password: string;
    let email: string;

    before(() => {
        // Activate Jahia's mail service against the stack's Mailpit container so the email_code
        // factor can deliver its codes (the ci.startup.sh groovyConsole curl does not reliably
        // run, leaving mail inactive and EmailCodeFactorProvider.prepare failing the send).
        cy.executeGroovy('groovy/setupMail.groovy');
        createSiteWithTotpLoginPage(SITE_KEY);
        // Point UPA at this spec's login page and disable the prepare rate limit (each test
        // prepares the email factor for a fresh user; '0' mirrors totp-login.yml).
        cy.request({
            method: 'POST',
            url: '/modules/api/provisioning',
            auth: {user: 'root', pass: Cypress.env('SUPER_USER_PASSWORD') as string},
            headers: {'Content-Type': 'application/json'},
            body: [{
                editConfiguration: 'org.jahia.modules.upa',
                properties: {
                    loginUrl: getTotpLoginPageURL(SITE_KEY),
                    mfaFactorStartRateLimitSeconds: '0',
                },
            }],
        });
        setUpaEnabledFactors(['totp', 'email_code']);
        setSiteTotpSettings(SITE_KEY, true);
        // Pick-one across both factors: verifying either one must complete the session.
        setGlobalEnforcement('totp,email_code');
    });

    after(() => {
        // A leftover enforcement policy or factor list would reshape every other spec's logins.
        setGlobalEnforcement('');
        setUpaEnabledFactors(['totp']);
        try {
            deleteSite(SITE_KEY);
        } catch (_e) {
            // best-effort
        }
    });

    beforeEach(() => {
        username = jfaker.internet.username();
        password = jfaker.internet.password();
        email = `${username}@mfa-spec.test`.toLowerCase();
        createUserForMFA(username, password, email);
        cy.mailpitDeleteAllEmails();
    });

    afterEach(() => {
        try {
            deleteUser(username);
        } catch (_e) {
            // ignore
        }
    });

    const submitPassword = () => {
        cy.visit(getTotpLoginPageURL(SITE_KEY));
        cy.get('[data-testid="login-username"]', {timeout: 30000}).should('be.visible');
        cy.get('[data-testid="login-username"]').type(username);
        cy.get('[data-testid="login-password"]').type(password);
        cy.get('[data-testid="login-submit"]').click();
    };

    /** Poll Mailpit for the code emailed to this test's user and hand it to the callback. */
    const withEmailedCode = (handler: (code: string) => void) => {
        cy.waitUntil(
            () => cy.mailpitSearchEmails(`to:${email}`).then(result => (result.messages ?? []).length > 0),
            {timeout: 20000, interval: 1000, errorMsg: `no email received for ${email}`},
        );
        cy.mailpitSearchEmails(`to:${email}`).then(result => {
            // mailpitGetMailTextBody is a CHILD command: chain it off the fetched Message.
            cy.mailpitGetMail(result.messages[0].ID).mailpitGetMailTextBody().then(body => {
                const match = /\b(\d{6})\b/.exec(body);
                expect(match, 'mail body contains a 6-digit code').to.not.be.null;
                handler(match[1]);
            });
        });
    };

    it('offers both factors in the chooser and signs in with the emailed code', () => {
        let secret: string;
        enrollUserInTotp(username, password).then(result => {
            secret = result.secret;
            expect(secret).to.be.a('string');
        });
        cy.logout();
        submitPassword();

        // Both configured factors offered: totp (enrolled) + email_code (j:email present).
        cy.get('[data-testid="factor-choose-totp"]', {timeout: 30000}).should('be.visible');
        cy.get('[data-testid="factor-choose-email_code"]').should('be.visible').click();

        // Email verification screen: a code was generated and sent through Mailpit.
        cy.get('[data-testid="email-verification-code"]', {timeout: 30000}).should('be.visible');
        withEmailedCode(code => {
            fillOtp('email-verification-code', code);
        });

        // The remaining totp factor skips itself (pick-one satisfied by the genuine email
        // verification) and the client drains it — straight to the redirect.
        cy.location('pathname', {timeout: 30000}).should('not.contain', '/myLoginPage.html');
    });

    it('choosing the authenticator sends NO email (foreign drain releases email_code)', () => {
        let secret: string;
        enrollUserInTotp(username, password).then(result => {
            secret = result.secret;
        });
        cy.logout();
        submitPassword();

        cy.get('[data-testid="factor-choose-totp"]', {timeout: 30000}).should('be.visible').click();
        cy.get('[data-testid="verification-code"]', {timeout: 30000}).should('be.visible');
        // Strictly-next TOTP window, avoiding replay of the enrollment code.
        cy.wait(31000);
        cy.wrap(null).then(() => {
            fillOtp('verification-code', totpCode(secret));
        });

        // The foreign drain marks email_code verified server-side: login completes without
        // ever rendering the email screen — and without sending a single message.
        cy.location('pathname', {timeout: 30000}).should('not.contain', '/myLoginPage.html');
        cy.mailpitSearchEmails(`to:${email}`).then(result => {
            expect((result.messages ?? []).length, 'no email sent when totp was chosen').to.eq(0);
        });
    });

    it('a user with only an email address skips the chooser and lands on the email screen', () => {
        // No TOTP enrollment: email_code is the single configured factor, so the chooser is
        // bypassed (offer.length === 1) and totp later skips through its sibling row.
        cy.logout();
        submitPassword();

        cy.get('[data-testid="email-verification-code"]', {timeout: 30000}).should('be.visible');
        cy.get('[data-testid="factor-choose-totp"]').should('not.exist');
        withEmailedCode(code => {
            fillOtp('email-verification-code', code);
        });

        cy.location('pathname', {timeout: 30000}).should('not.contain', '/myLoginPage.html');
    });
});
