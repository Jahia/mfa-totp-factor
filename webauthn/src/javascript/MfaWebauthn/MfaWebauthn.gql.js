import gql from 'graphql-tag';

export const StatusQuery = gql`
    query WebauthnStatus {
        mfaWebauthn {
            status {
                registered
                credentials {
                    credentialId
                    nickname
                    signCount
                    createdAt
                    lastUsedAt
                    transports
                    aaguid
                }
            }
        }
    }
`;

export const StartRegistrationMutation = gql`
    mutation StartWebauthnRegistration {
        upa { mfaFactors { webauthn { startRegistration {
            publicKeyCredentialCreationOptions
        } } } }
    }
`;

export const FinishRegistrationMutation = gql`
    mutation FinishWebauthnRegistration($response: String!, $nickname: String) {
        upa { mfaFactors { webauthn { finishRegistration(response: $response, nickname: $nickname) {
            registered
            credentials { credentialId nickname signCount createdAt lastUsedAt transports }
        } } } }
    }
`;

export const RenameCredentialMutation = gql`
    mutation RenameWebauthnCredential($credentialId: String!, $nickname: String!) {
        upa { mfaFactors { webauthn { renameCredential(credentialId: $credentialId, nickname: $nickname) } } }
    }
`;

export const DeleteCredentialMutation = gql`
    mutation DeleteWebauthnCredential($credentialId: String!) {
        upa { mfaFactors { webauthn { deleteCredential(credentialId: $credentialId) } } }
    }
`;
