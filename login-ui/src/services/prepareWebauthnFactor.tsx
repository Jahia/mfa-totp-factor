import { type BaseError, type BaseSuccess, createError } from "./common";

interface PrepareWebauthnFactorResultSuccess extends BaseSuccess {
  /** The navigator.credentials.get() options JSON the browser must consume. */
  requestOptionsJson: string;
}
export type PrepareWebauthnFactorResult = PrepareWebauthnFactorResultSuccess | BaseError;

/**
 * Calls {@code webauthn.prepare}, which starts an assertion ceremony server-side and returns the
 * PublicKeyCredentialRequestOptions (challenge + allowed credentials) for the browser.
 */
export default async function prepareWebauthnFactor(
  apiRoot: string,
): Promise<PrepareWebauthnFactorResult> {
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
  const success =
    preparation?.session?.factorState?.prepared &&
    !preparation?.session?.factorState?.error &&
    preparation?.publicKeyCredentialRequestOptions;
  if (success) {
    return {
      success: true,
      remainingFactors: preparation.session.remainingFactors,
      requestOptionsJson: preparation.publicKeyCredentialRequestOptions,
    };
  }

  return createError(preparation?.session?.error, preparation?.session?.factorState?.error);
}
