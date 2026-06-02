import gql from 'graphql-tag';

export const SiteSettingsQuery = gql`
    query MfaTotpSiteSettings($siteKey: String!) {
        mfaTotp {
            siteSettings(siteKey: $siteKey) {
                siteKey
                enabled
                enforced
                graceDays
                enabledGroups
                loginUrl
                logoutUrl
            }
        }
    }
`;

export const SetSiteSettingsMutation = gql`
    mutation MfaTotpSetSiteSettings(
        $siteKey: String!
        $enabled: Boolean!
        $enforced: Boolean!
        $graceDays: Int
        $enabledGroups: [String]
        $loginUrl: String
        $logoutUrl: String
    ) {
        upa {
            mfaFactors {
                totp {
                    setSiteSettings(
                        siteKey: $siteKey
                        enabled: $enabled
                        enforced: $enforced
                        graceDays: $graceDays
                        enabledGroups: $enabledGroups
                        loginUrl: $loginUrl
                        logoutUrl: $logoutUrl
                    ) {
                        siteKey
                        enabled
                        enforced
                        graceDays
                        enabledGroups
                        loginUrl
                        logoutUrl
                    }
                }
            }
        }
    }
`;

export const ResetUserMfaMutation = gql`
    mutation MfaTotpResetUser($userId: String!, $siteKey: String!) {
        upa {
            mfaFactors {
                totp {
                    resetUserMfa(userId: $userId, siteKey: $siteKey)
                }
            }
        }
    }
`;

export const AuditEventsQuery = gql`
    query MfaTotpAuditEvents($siteKey: String!, $limit: Int) {
        mfaTotp {
            auditEvents(siteKey: $siteKey, limit: $limit) {
                eventType
                outcome
                userId
                siteKey
                timestamp
                detail
            }
        }
    }
`;

export const EnrollmentReportQuery = gql`
    query MfaTotpEnrollmentReport($siteKey: String!, $limit: Int) {
        mfaTotp {
            enrollmentReport(siteKey: $siteKey, limit: $limit) {
                totalUsers
                enrolledUsers
                notEnrolled
                truncated
            }
        }
    }
`;
