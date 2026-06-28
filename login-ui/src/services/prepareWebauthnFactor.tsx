import {
  type BaseError,
  type BaseSuccess,
  blockingFactorStateError,
  createError,
  networkError,
} from "./common";

interface PrepareWebauthnFactorResultSuccess extends BaseSuccess {
  /** The navigator.credentials.get() options JSON, or null when the factor was skipped. */
  requestOptionsJson: string | null;
  /** True when the factor does not apply to this session — drain it with verify(""). */
  skipped: boolean;
}
export type PrepareWebauthnFactorResult = PrepareWebauthnFactorResultSuccess | BaseError;

/**
 * Calls {@code webauthn.prepare}, which starts an assertion ceremony server-side and returns the
 * PublicKeyCredentialRequestOptions (challenge + allowed credentials) for the browser. When the
 * factor is skipped for this session (pick-one enforcement satisfied elsewhere, site disabled…)
 * there are no options and {@code skipped} is true.
 */
export default async function prepareWebauthnFactor(
  apiRoot: string,
): Promise<PrepareWebauthnFactorResult> {
  try {
    const response = await fetch(apiRoot, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query: /* GraphQL */ `
          mutation prepareWebauthnFactor($factorType: String!) {
            upa {
              mfaFactors {
                webauthn {
                  prepare {
                    publicKeyCredentialRequestOptions
                    skipped
                    session {
                      initiated
                      remainingFactors
                      factorState(factorType: $factorType) {
                        prepared
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
        variables: { factorType: "webauthn" },
      }),
    });
    const result = await response.json();
    const preparation = result?.data?.upa?.mfaFactors?.webauthn?.prepare;
    const factorState = preparation?.session?.factorState;
    const blockingError = blockingFactorStateError(factorState);
    const success =
      factorState?.prepared &&
      !blockingError &&
      (preparation?.publicKeyCredentialRequestOptions || preparation?.skipped);
    if (success) {
      return {
        success: true,
        skipped: Boolean(preparation.skipped),
        remainingFactors: preparation.session.remainingFactors,
        requestOptionsJson: preparation.publicKeyCredentialRequestOptions ?? null,
      };
    }
    return createError(preparation?.session?.error, preparation?.session?.factorState?.error);
  } catch {
    return networkError();
  }
}
