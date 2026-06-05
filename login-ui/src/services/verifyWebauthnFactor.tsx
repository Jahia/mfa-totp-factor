import { type BaseError, type BaseSuccess, createError } from "./common";

export type VerifyWebauthnFactorResult = BaseSuccess | BaseError;

/**
 * Submits the navigator.credentials.get() assertion JSON to {@code webauthn.verify}. The server
 * validates the signature, origin/rpId binding and challenge, and bumps the signature counter.
 */
export default async function verifyWebauthnFactor(
  apiRoot: string,
  assertion: string,
): Promise<VerifyWebauthnFactorResult> {
  const response = await fetch(apiRoot, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      query: /* GraphQL */ `
        mutation verifyWebauthnFactor($assertion: String!, $factorType: String!) {
          upa {
            mfaFactors {
              webauthn {
                verify(assertion: $assertion) {
                  session {
                    initiated
                    remainingFactors
                    factorState(factorType: $factorType) {
                      verified
                      error { code arguments { name value } }
                    }
                    error { code arguments { name value } }
                  }
                }
              }
            }
          }
        }
      `,
      variables: { assertion, factorType: "webauthn" },
    }),
  });
  const result = await response.json();
  const verification = result?.data?.upa?.mfaFactors?.webauthn?.verify;
  const success = verification?.session?.factorState?.verified;
  if (success) {
    return {
      success: true,
      remainingFactors: verification.session.remainingFactors,
    };
  }

  return createError(verification?.session?.error, verification?.session?.factorState?.error);
}
