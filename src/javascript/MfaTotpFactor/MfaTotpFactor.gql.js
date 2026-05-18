import gql from 'graphql-tag';

export const StatusQuery = gql`
    query MfaTotpStatus {
        mfaTotp {
            status {
                enrolled
                hasBackupCodes
                remainingBackupCodes
            }
        }
    }
`;

export const EnrollMutation = gql`
    mutation MfaTotpEnroll($force: Boolean, $currentCode: String) {
        upa {
            mfaFactors {
                totp {
                    enroll(force: $force, currentCode: $currentCode) {
                        secret
                        otpauthUri
                        issuer
                        accountName
                    }
                }
            }
        }
    }
`;

export const ConfirmEnrollMutation = gql`
    mutation MfaTotpConfirmEnroll($code: String!) {
        upa {
            mfaFactors {
                totp {
                    confirmEnroll(code: $code) {
                        backupCodes
                    }
                }
            }
        }
    }
`;

export const DisableMutation = gql`
    mutation MfaTotpDisable($code: String!) {
        upa {
            mfaFactors {
                totp {
                    disable(code: $code) {
                        session {
                            initiated
                        }
                    }
                }
            }
        }
    }
`;

export const RegenerateBackupCodesMutation = gql`
    mutation MfaTotpRegenerateBackupCodes($code: String!) {
        upa {
            mfaFactors {
                totp {
                    regenerateBackupCodes(code: $code) {
                        backupCodes
                    }
                }
            }
        }
    }
`;
