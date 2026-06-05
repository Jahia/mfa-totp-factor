import gql from 'graphql-tag';

export const SiteSettingsQuery = gql`
    query MfaWebauthnSiteSettings($siteKey: String!) {
        mfaWebauthn {
            siteSettings(siteKey: $siteKey) {
                siteKey
                enabled
                enforced
                graceDays
                enabledGroups
            }
        }
    }
`;

export const SetSiteSettingsMutation = gql`
    mutation MfaWebauthnSetSiteSettings(
        $siteKey: String!
        $enabled: Boolean!
        $enforced: Boolean!
        $graceDays: Int
        $enabledGroups: [String]
    ) {
        upa {
            mfaFactors {
                webauthn {
                    setSiteSettings(
                        siteKey: $siteKey
                        enabled: $enabled
                        enforced: $enforced
                        graceDays: $graceDays
                        enabledGroups: $enabledGroups
                    ) {
                        siteKey
                        enabled
                        enforced
                        graceDays
                        enabledGroups
                    }
                }
            }
        }
    }
`;

export const ResetUserMfaMutation = gql`
    mutation MfaWebauthnResetUser($userId: String!, $siteKey: String!) {
        upa {
            mfaFactors {
                webauthn {
                    resetUserWebauthn(userId: $userId, siteKey: $siteKey)
                }
            }
        }
    }
`;

export const AuditEventsQuery = gql`
    query MfaWebauthnAuditEvents($siteKey: String!, $limit: Int) {
        mfaWebauthn {
            auditEvents(siteKey: $siteKey, limit: $limit) {
                eventType
                outcome
                userId
                timestamp
                detail
            }
        }
    }
`;

export const EnrollmentReportQuery = gql`
    query MfaWebauthnEnrollmentReport($siteKey: String!, $limit: Int) {
        mfaWebauthn {
            enrollmentReport(siteKey: $siteKey, limit: $limit) {
                totalUsers
                registeredUsers
                notRegistered
                truncated
            }
        }
    }
`;
