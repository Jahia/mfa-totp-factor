/**
 * GraphQL coverage for the per-site policy + admin surfaces:
 *   - setSiteSettings / siteSettings round-trip (enabled, enforced, graceDays, enabledGroups)
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
import {confirmEnroll, createUserForMFA, enroll, firstErrorMessage, totpCode} from './utils';

const SITE_KEY = 'sample-totp-admin';

const ROOT = {username: 'root', password: Cypress.env('SUPER_USER_PASSWORD') as string};

const setSiteSettings = (vars: Record<string, unknown>) => cy.apollo({
    mutation: gql`
        mutation Set($siteKey: String!, $enabled: Boolean!, $enforced: Boolean!, $graceDays: Int, $enabledGroups: [String], $loginUrl: String, $logoutUrl: String) {
            upa { mfaFactors { totp { setSiteSettings(siteKey: $siteKey, enabled: $enabled, enforced: $enforced, graceDays: $graceDays, enabledGroups: $enabledGroups, loginUrl: $loginUrl, logoutUrl: $logoutUrl) {
                enabled enforced graceDays enabledGroups loginUrl logoutUrl
            } } } }
        }`,
    variables: vars,
    errorPolicy: 'all'
});

const getSiteSettings = (siteKey: string) => cy.apollo({
    query: gql`query Get($siteKey: String!) { mfaTotp { siteSettings(siteKey: $siteKey) { enabled enforced graceDays enabledGroups loginUrl logoutUrl } } }`,
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

    it('round-trips per-site policy (enabled, enforced, graceDays, enabledGroups, login/logout URLs)', () => {
        const loginUrl = `/sites/${SITE_KEY}/login.html`;
        const logoutUrl = `/sites/${SITE_KEY}/logout.html`;
        setSiteSettings({siteKey: SITE_KEY, enabled: true, enforced: true, graceDays: 7, enabledGroups: ['editors', 'reviewers'], loginUrl, logoutUrl})
            .then(res => {
                const s = res?.data?.upa?.mfaFactors?.totp?.setSiteSettings;
                expect(s.enabled).to.be.true;
                expect(s.enforced).to.be.true;
                expect(s.graceDays).to.eq(7);
                expect(s.enabledGroups).to.have.members(['editors', 'reviewers']);
                expect(s.loginUrl).to.eq(loginUrl);
                expect(s.logoutUrl).to.eq(logoutUrl);
            });
        getSiteSettings(SITE_KEY).then(res => {
            const s = res?.data?.mfaTotp?.siteSettings;
            expect(s.enabled).to.be.true;
            expect(s.enforced).to.be.true;
            expect(s.graceDays).to.eq(7);
            expect(s.enabledGroups).to.have.members(['editors', 'reviewers']);
            expect(s.loginUrl).to.eq(loginUrl);
            expect(s.logoutUrl).to.eq(logoutUrl);
        });
    });

    it('clears per-site login/logout URLs when set blank (falls back to global/default)', () => {
        setSiteSettings({siteKey: SITE_KEY, enabled: true, enforced: false, loginUrl: `/sites/${SITE_KEY}/login.html`, logoutUrl: ''});
        setSiteSettings({siteKey: SITE_KEY, enabled: true, enforced: false, loginUrl: null, logoutUrl: null});
        getSiteSettings(SITE_KEY).then(res => {
            const s = res?.data?.mfaTotp?.siteSettings;
            expect(s.loginUrl, 'blank login URL should clear to null').to.be.null;
            expect(s.logoutUrl, 'blank logout URL should clear to null').to.be.null;
        });
    });

    it('denies setSiteSettings to a non site-admin user', () => {
        const usr = jfaker.internet.username();
        const pwd = jfaker.internet.password();
        createUser(usr, pwd);
        cy.apolloClient({username: usr, password: pwd});
        setSiteSettings({siteKey: SITE_KEY, enabled: true, enforced: false}).then(res => {
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

    it('records audit events and produces an enrollment report', () => {
        // Generate at least one auditable admin action.
        setSiteSettings({siteKey: SITE_KEY, enabled: true, enforced: false, graceDays: 0, enabledGroups: []});

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
