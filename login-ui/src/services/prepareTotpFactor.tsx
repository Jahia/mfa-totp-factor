import { type BaseError, type BaseSuccess, createError } from "./common";

type PrepareTotpFactorResultSuccess = BaseSuccess;
type PrepareTotpFactorResultError = BaseError;
export type PrepareTotpFactorResult =
  | PrepareTotpFactorResultSuccess
  | PrepareTotpFactorResultError;

/**
 * Calls {@code totp.prepare}, which is a no-op marker on the server (TOTP doesn't push
 * anything out-of-band — the secret is already provisioned in the authenticator app).
 * It is still required to satisfy {@code MfaServiceImpl}'s prepare-before-verify gate.
 */
export default async function prepareTotpFactor(
  apiRoot: string,
): Promise<PrepareTotpFactorResult> {
  const response = await fetch(apiRoot, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      query: /* GraphQL */ `
        mutation prepareTotpFactor($factorType: String!) {
          upa {
            mfaFactors {
              totp {
                prepare {
                  session {
                    initiated
                    remainingFactors
                    factorState(factorType: $factorType) {
                      prepared
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
      variables: { factorType: "totp" },
    }),
  });
  const result = await response.json();
  const preparation = result?.data?.upa?.mfaFactors?.totp?.prepare;
  const success =
    preparation?.session?.factorState?.prepared && !preparation?.session?.factorState?.error;
  if (success) {
    return {
      success: true,
      remainingFactors: preparation.session.remainingFactors,
    };
  } else {
    return createError(
      preparation?.session?.error,
      preparation?.session?.factorState?.error,
    );
  }
}
