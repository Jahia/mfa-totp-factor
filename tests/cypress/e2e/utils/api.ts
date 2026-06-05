/**
 * GraphQL helpers for the TOTP factor surface.
 *
 * All operations are inlined gql tagged templates targeting the schema described in
 * mfa-factors-totp/src/main/java/.../gql/. The path is:
 *
 *   mutation { upa { mfaFactors { totp { <op> } } } }
 *
 * (The `totp` field on `MfaFactorsMutation` is contributed by
 *  TotpFactorMutationExtension in the TOTP module.)
 */
import gql from 'graphql-tag';

export interface EnrollResult {
    secret: string;
    otpauthUri: string;
    issuer: string;
    accountName: string;
}

/** Call totp.enroll for the currently-authenticated apollo client. */
export function enroll(force?: boolean, currentCode?: string) {
    return cy.apollo({
        mutation: gql`
            mutation Enroll($force: Boolean, $currentCode: String) {
                upa {
                    mfaFactors {
                        totp {
                            enroll(force: $force, currentCode: $currentCode) {
                                secret
                                otpauthUri
                                issuer
                                accountName
                                session { initiated }
                            }
                        }
                    }
                }
            }
        `,
        variables: {force, currentCode},
        errorPolicy: 'all'
    });
}

/** Call totp.confirmEnroll with the user-supplied first code. Returns backup codes. */
export function confirmEnroll(code: string) {
    return cy.apollo({
        mutation: gql`
            mutation ConfirmEnroll($code: String!) {
                upa {
                    mfaFactors {
                        totp {
                            confirmEnroll(code: $code) {
                                backupCodes
                                session { initiated }
                            }
                        }
                    }
                }
            }
        `,
        variables: {code},
        errorPolicy: 'all'
    });
}

/** Call totp.verify (during a login flow — must follow mfaInitiate + totp.prepare). */
export function verifyTotp(code: string) {
    return cy.apollo({
        mutation: gql`
            mutation Verify($code: String!) {
                upa {
                    mfaFactors {
                        totp {
                            verify(code: $code) {
                                session {
                                    initiated
                                    verifiedFactors
                                    error { code arguments { name value } }
                                    factorState(factorType: "totp") {
                                        verified
                                        error { code arguments { name value } }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        `,
        variables: {code},
        errorPolicy: 'all'
    });
}

/** Call totp.prepare (no-op marker during login flow). */
export function prepareTotp() {
    return cy.apollo({
        mutation: gql`
            mutation Prepare {
                upa {
                    mfaFactors {
                        totp {
                            prepare {
                                session { initiated }
                            }
                        }
                    }
                }
            }
        `,
        errorPolicy: 'all'
    });
}

export function regenerateBackupCodes(code: string) {
    return cy.apollo({
        mutation: gql`
            mutation Regen($code: String!) {
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
        `,
        variables: {code},
        errorPolicy: 'all'
    });
}

export function disableTotp(code: string) {
    return cy.apollo({
        mutation: gql`
            mutation Disable($code: String!) {
                upa {
                    mfaFactors {
                        totp {
                            disable(code: $code) {
                                session { initiated }
                            }
                        }
                    }
                }
            }
        `,
        variables: {code},
        errorPolicy: 'all'
    });
}

/** Extract the first error message from an Apollo response. */
export function firstErrorMessage(response: any): string | undefined {
    if (response?.errors && response.errors.length > 0) {
        return response.errors[0].message;
    }
    return undefined;
}
