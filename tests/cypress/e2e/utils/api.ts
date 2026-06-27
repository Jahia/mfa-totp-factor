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

/**
 * Read the per-site OSGi factory config file that the backend writes to
 * `<karaf.etc>/org.jahia.modules.mfa.extensions.site-<siteKey>.cfg`.
 *
 * Returns the file's text content when it exists, or the sentinel string
 * "ABSENT" when it does not. Uses cy.executeGroovy so the check runs
 * inside the Jahia container (where karaf.etc is accessible) rather than
 * from the Cypress host.
 *
 * Usage:
 *   getSiteConfigFile('my-site').should('include', 'totp.enabled=true');
 *   getSiteConfigFile('my-site').should('eq', 'ABSENT');
 */
export function getSiteConfigFile(siteKey: string): Cypress.Chainable<string> {
    const script = [
        `def f = new File(System.getProperty("karaf.etc"), "org.jahia.modules.mfa.extensions.site-${siteKey}.cfg")`,
        'return f.exists() ? f.text : "ABSENT"',
    ].join('\n');
    const password = Cypress.env('SUPER_USER_PASSWORD') as string;
    return cy.request({
        method: 'POST',
        url: '/modules/tools/groovyConsole.jsp',
        auth: {user: 'root', pass: password},
        form: true,
        body: {script, runScript: 'true'},
    }).then(response => {
        expect(response.status, 'groovy console must return HTTP 200').to.eq(200);
        // The groovy console renders the return value inside the result fieldset:
        // <strong>Result:</strong><br/> <pre>...</pre>. Extract that <pre> (the help text
        // further down also contains <pre> blocks, so anchor on the Result label).
        const body: string = response.body as string;
        const match = /<strong>Result:<\/strong>[\s\S]*?<pre>([\s\S]*?)<\/pre>/.exec(body);
        if (!match) {
            throw new Error('Could not parse groovy console result from response');
        }
        return match[1].trim();
    });
}
