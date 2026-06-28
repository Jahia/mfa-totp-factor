import {
  type BaseError,
  type BaseSuccess,
  blockingFactorStateError,
  createError,
  networkError,
} from "./common";

interface PrepareTotpFactorResultSuccess extends BaseSuccess {
  /** True when the factor does not apply to this session — drain it with verify(""). */
  skipped: boolean;
}
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
  try {
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
                    skipped
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
    const factorState = preparation?.session?.factorState;
    const blockingError = blockingFactorStateError(factorState);
    const success = factorState?.prepared && !blockingError;
    if (success) {
      return {
        success: true,
        skipped: Boolean(preparation.skipped),
        remainingFactors: preparation.session.remainingFactors,
      };
    }
    return createError(
      preparation?.session?.error,
      preparation?.session?.factorState?.error,
    );
  } catch {
    return networkError();
  }
}
