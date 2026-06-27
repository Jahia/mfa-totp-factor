/**
 * GraphQL coverage for the per-site policy + admin surfaces:
 *   - setSiteSettings / siteSettings round-trip (enabled, enabledGroups, login/logout URLs)
 *     — enforcement is GLOBAL (org.jahia.modules.mfa.extensions), not part of this surface
 *   - permission gate (non-admin is denied)
 *   - resetUserMfa (admin recovery)
 *   - auditEvents (the above actions are recorded)
 *   - enrollmentReport ("who hasn't enrolled?")
 *
 * Secret encryption-at-rest is exercised transparently by the enroll → confirm → re-enroll
 * cycle here (and by graphQL.totp.verify): the secret round-trips through AES-GCM, so a
 * successful enrollment proves encrypt/decrypt works.
 */
import {createSite, createUser, deleteSite, deleteUser, jfaker} from '@jahia/cypress';
import gql from 'graphql-tag';
import {confirmEnroll, createUserForMFA, enroll, firstErrorMessage, getSiteConfigFile, totpCode} from './utils';

const SITE_KEY = 'sample-totp-admin';

const ROOT = {username: 'root', password: Cypress.env('SUPER_USER_PASSWORD') as string};

const setSiteSettings = (vars: Record<string, unknown>) => cy.apollo({
    mutation: gql`
        mutation Set($siteKey: String!, $enabled: Boolean!, $enabledGroups: [String], $loginUrl: String, $logoutUrl: String) {
            upa { mfaFactors { totp { setSiteSettings(siteKey: $siteKey, enabled: $enabled, enabledGroups: $enabledGroups, loginUrl: $loginUrl, logoutUrl: $logoutUrl) {
                enabled enabledGroups loginUrl logoutUrl
            } } } }
        }`,
    variables: vars,
    errorPolicy: 'all'
});

const getSiteSettings = (siteKey: string) => cy.apollo({
    query: gql`query Get($siteKey: String!) { mfaTotp { siteSettings(siteKey: $siteKey) { enabled enabledGroups loginUrl logoutUrl } } }`,
    variables: {siteKey},
    fetchPolicy: 'no-cache',
    errorPolicy: 'all'
});

const resetUserMfa = (userId: string, siteKey: string) => cy.apollo({
    mutation: gql`mutation Reset($userId: String!, $siteKey: String!) { upa { mfaFactors { totp { resetUserMfa(userId: $userId, siteKey: $siteKey) } } } }`,
    variables: {userId, siteKey},
    errorPolicy: 'all'
});

const auditEvents = (siteKey: string) => cy.apollo({
    query: gql`query Audit($siteKey: String!) { mfaTotp { auditEvents(siteKey: $siteKey, limit: 50) { eventType outcome userId } } }`,
    variables: {siteKey},
    fetchPolicy: 'no-cache',
    errorPolicy: 'all'
});

const enrollmentReport = (siteKey: string) => cy.apollo({
    query: gql`query Report($siteKey: String!) { mfaTotp { enrollmentReport(siteKey: $siteKey, limit: 200) { totalUsers enrolledUsers notEnrolled truncated } } }`,
    variables: {siteKey},
    fetchPolicy: 'no-cache',
    errorPolicy: 'all'
});

describe('TOTP per-site policy & admin (GraphQL)', () => {
    before(() => {
        deleteSite(SITE_KEY);
        createSite(SITE_KEY, {
            locale: 'en',
            languages: 'en',
            templateSet: 'user-password-authentication-template-set-test-module',
            serverName: 'localhost'
        });
    });

    after(() => {
        try { deleteSite(SITE_KEY); } catch (e) { /* ignore */ }
    });

    beforeEach(() => {
        cy.apolloClient(ROOT);
    });

    it('round-trips per-site policy (enabled, enabledGroups, login/logout URLs)', () => {
        const loginUrl = `/sites/${SITE_KEY}/login.html`;
        const logoutUrl = `/sites/${SITE_KEY}/logout.html`;
        setSiteSettings({siteKey: SITE_KEY, enabled: true, enabledGroups: ['editors', 'reviewers'], loginUrl, logoutUrl})
            .then(res => {
                const s = res?.data?.upa?.mfaFactors?.totp?.setSiteSettings;
                expect(s.enabled).to.be.true;
                expect(s.enabledGroups).to.have.members(['editors', 'reviewers']);
                expect(s.loginUrl).to.eq(loginUrl);
                expect(s.logoutUrl).to.eq(logoutUrl);
            });
        getSiteSettings(SITE_KEY).then(res => {
            const s = res?.data?.mfaTotp?.siteSettings;
            expect(s.enabled).to.be.true;
            expect(s.enabledGroups).to.have.members(['editors', 'reviewers']);
            expect(s.loginUrl).to.eq(loginUrl);
            expect(s.logoutUrl).to.eq(logoutUrl);
        });
    });

    it('clears per-site login/logout URLs when set to empty string (falls back to global/default)', () => {
        // First set both URLs to non-empty values.
        setSiteSettings({siteKey: SITE_KEY, enabled: true, loginUrl: `/sites/${SITE_KEY}/login.html`, logoutUrl: `/sites/${SITE_KEY}/logout.html`});
        // Passing "" (empty string) is the signal to clear - null means "keep existing".
        setSiteSettings({siteKey: SITE_KEY, enabled: true, loginUrl: '', logoutUrl: ''});
        getSiteSettings(SITE_KEY).then(res => {
            const s = res?.data?.mfaTotp?.siteSettings;
            expect(s.loginUrl, 'empty-string loginUrl should clear to null').to.be.null;
            expect(s.logoutUrl, 'empty-string logoutUrl should clear to null').to.be.null;
        });
    });

    it('omitting URL args (null) keeps existing URLs unchanged', () => {
        const loginUrl = `/sites/${SITE_KEY}/login.html`;
        const logoutUrl = `/sites/${SITE_KEY}/logout.html`;
        // Establish known values for both URLs.
        setSiteSettings({siteKey: SITE_KEY, enabled: true, loginUrl, logoutUrl});
        // Toggle enabled with URL args omitted (null) - both URLs must survive independently.
        setSiteSettings({siteKey: SITE_KEY, enabled: false});
        getSiteSettings(SITE_KEY).then(res => {
            const s = res?.data?.mfaTotp?.siteSettings;
            expect(s.loginUrl, 'loginUrl must survive when URL arg is omitted').to.eq(loginUrl);
            expect(s.logoutUrl, 'logoutUrl must survive when URL arg is omitted').to.eq(logoutUrl);
        });
        // Restore to a clean state for subsequent tests.
        setSiteSettings({siteKey: SITE_KEY, enabled: true, loginUrl: '', logoutUrl: ''});
    });

    it('rejects absolute / protocol-relative / scheme login URLs (open-redirect guard)', () => {
        ['https://attacker.example/phish', '//attacker.example', 'javascript:alert(1)', 'sites/no-leading-slash']
            .forEach(bad => {
                setSiteSettings({siteKey: SITE_KEY, enabled: true, loginUrl: bad}).then(res => {
                    expect(firstErrorMessage(res), `"${bad}" must be rejected`).to.match(/invalid_url/);
                });
            });
        // Same guard applies to the logout URL.
        setSiteSettings({siteKey: SITE_KEY, enabled: true, logoutUrl: 'https://attacker.example'}).then(res => {
            expect(firstErrorMessage(res), 'absolute logout URL must be rejected').to.match(/invalid_url/);
        });
        // A rejected save must not have persisted anything.
        getSiteSettings(SITE_KEY).then(res => {
            const s = res?.data?.mfaTotp?.siteSettings;
            const stored = `${s.loginUrl ?? ''}${s.logoutUrl ?? ''}`;
            expect(stored, 'rejected URLs must not be stored').to.not.contain('attacker');
        });
    });

    it('denies setSiteSettings to a non site-admin user', () => {
        const usr = jfaker.internet.username();
        const pwd = jfaker.internet.password();
        createUser(usr, pwd);
        cy.apolloClient({username: usr, password: pwd});
        setSiteSettings({siteKey: SITE_KEY, enabled: true}).then(res => {
            expect(firstErrorMessage(res), 'non-admin must be denied').to.match(/permission_denied|not_authenticated/);
        });
        cy.apolloClient(ROOT);
        deleteUser(usr);
    });

    it('resets a user\'s enrollment (admin recovery)', () => {
        const usr = jfaker.internet.username();
        const pwd = jfaker.internet.password();
        createUserForMFA(usr, pwd, jfaker.internet.email());

        // Enrol as the user.
        cy.apolloClient({username: usr, password: pwd});
        enroll().then(r => {
            const secret = r?.data?.upa?.mfaFactors?.totp?.enroll?.secret;
            confirmEnroll(totpCode(secret)).then(c => {
                expect(firstErrorMessage(c)).to.be.undefined;
            });
        });

        // Admin resets it.
        cy.apolloClient(ROOT);
        resetUserMfa(usr, SITE_KEY).then(res => {
            expect(firstErrorMessage(res)).to.be.undefined;
            expect(res?.data?.upa?.mfaFactors?.totp?.resetUserMfa).to.be.true;
        });

        // The user can now start a fresh enrollment without force (proves they are un-enrolled).
        cy.apolloClient({username: usr, password: pwd});
        enroll().then(res => {
            expect(firstErrorMessage(res), 'after reset, enroll must NOT report already_enrolled').to.be.undefined;
        });

        cy.apolloClient(ROOT);
        deleteUser(usr);
    });

    it('writes the per-site .cfg file when TOTP is enabled on a site', () => {
        setSiteSettings({siteKey: SITE_KEY, enabled: true, enabledGroups: [], loginUrl: '', logoutUrl: ''});
        getSiteConfigFile(SITE_KEY).should('not.eq', 'ABSENT');
        getSiteConfigFile(SITE_KEY).should('include', 'totp.enabled=true');
    });

    it('deletes the per-site .cfg file when all settings revert to all-default', () => {
        // Confirm a file exists first.
        setSiteSettings({siteKey: SITE_KEY, enabled: true, enabledGroups: [], loginUrl: '', logoutUrl: ''});
        getSiteConfigFile(SITE_KEY).should('not.eq', 'ABSENT');
        // Disabling the last factor with no URLs is all-default: file must be deleted.
        setSiteSettings({siteKey: SITE_KEY, enabled: false, enabledGroups: [], loginUrl: '', logoutUrl: ''});
        getSiteConfigFile(SITE_KEY).should('eq', 'ABSENT');
    });

    it('records audit events and produces an enrollment report', () => {
        // Generate at least one auditable admin action.
        setSiteSettings({siteKey: SITE_KEY, enabled: true, enabledGroups: []});

        auditEvents(SITE_KEY).then(res => {
            const events = res?.data?.mfaTotp?.auditEvents;
            expect(events, 'audit events should be an array').to.be.an('array');
            expect(events.length, 'at least the setSiteSettings event').to.be.greaterThan(0);
            expect(events.map((e: {eventType: string}) => e.eventType)).to.include('setSiteSettings');
        });

        enrollmentReport(SITE_KEY).then(res => {
            const r = res?.data?.mfaTotp?.enrollmentReport;
            expect(r.totalUsers, 'report has a user total').to.be.greaterThan(0);
            expect(r.enrolledUsers).to.be.a('number');
            expect(r.notEnrolled).to.be.an('array');
        });
    });
});
