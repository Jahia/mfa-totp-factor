import gql from 'graphql-tag';

export const ConfigurationQuery = gql`
    query MfaExtensionsConfiguration {
        mfaExtensionsConfiguration {
            enforcedFactors
            graceDays
            loginGateEnabled
            loginGateTrustForwardedFor
            loginGateIpWhitelist
            loginUrl
            logoutUrl
            resetNotifyEmail
            registeredFactors
        }
    }
`;

export const SaveConfigurationMutation = gql`
    mutation MfaExtensionsSaveConfiguration(
        $enforcedFactors: [String]
        $graceDays: Int
        $loginGateEnabled: Boolean
        $loginGateTrustForwardedFor: Boolean
        $loginGateIpWhitelist: String
        $loginUrl: String
        $logoutUrl: String
        $resetNotifyEmail: String
    ) {
        mfaExtensionsSaveConfiguration(
            enforcedFactors: $enforcedFactors
            graceDays: $graceDays
            loginGateEnabled: $loginGateEnabled
            loginGateTrustForwardedFor: $loginGateTrustForwardedFor
            loginGateIpWhitelist: $loginGateIpWhitelist
            loginUrl: $loginUrl
            logoutUrl: $logoutUrl
            resetNotifyEmail: $resetNotifyEmail
        ) {
            enforcedFactors
            graceDays
            loginGateEnabled
            loginGateTrustForwardedFor
            loginGateIpWhitelist
            loginUrl
            logoutUrl
            resetNotifyEmail
            registeredFactors
        }
    }
`;
