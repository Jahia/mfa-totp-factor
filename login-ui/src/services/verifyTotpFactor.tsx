import { type BaseError, type BaseSuccess, createError } from "./common";

type VerifyTotpFactorResultSuccess = BaseSuccess;
type VerifyTotpFactorResultError = BaseError;
export type VerifyTotpFactorResult = VerifyTotpFactorResultSuccess | VerifyTotpFactorResultError;

/**
 * Submits a 6-digit TOTP code (or a one-shot backup code) to the server.
 * The backend's {@code TotpUserStore.verifyAndConsumeTotp} atomically verifies and consumes
 * the code's counter in the same JCR transaction, preventing replay.
 */
export default async function verifyTotpFactor(
  apiRoot: string,
  code: string,
): Promise<VerifyTotpFactorResult> {
  const response = await fetch(apiRoot, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      query: /* GraphQL */ `
        mutation verifyTotpFactor($code: String!, $factorType: String!) {
          upa {
            mfaFactors {
              totp {
                verify(code: $code) {
                  session {
                    initiated
                    remainingFactors
                    factorState(factorType: $factorType) {
                      verified
                      error {
                        code
                        arguments {
                          name
                          value
                        }
                      }
                    }
                    error {
                      code
                      arguments {
                        name
                        value
                      }
                    }
                  }
                }
              }
            }
          }
        }
      `,
      variables: { code, factorType: "totp" },
    }),
  });
  const result = await response.json();
  const verification = result?.data?.upa?.mfaFactors?.totp?.verify;
  const success = verification?.session?.factorState?.verified;
  if (success) {
    return {
      success: true,
      remainingFactors: verification.session.remainingFactors,
    };
  } else {
    return createError(
      verification?.session?.error,
      verification?.session?.factorState?.error,
    );
  }
}
