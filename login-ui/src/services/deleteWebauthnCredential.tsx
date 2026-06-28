import { type BaseError, networkError, topLevelError } from "./common";

export interface DeleteWebauthnCredentialResultSuccess {
  success: true;
}
export type DeleteWebauthnCredentialResult = DeleteWebauthnCredentialResultSuccess | BaseError;

/**
 * Removes one of the current user's registered passkeys (self-service). The server scopes the
 * operation to the logged-in user, so a user can only delete their own credentials.
 */
export default async function deleteWebauthnCredential(
  apiRoot: string,
  credentialId: string,
): Promise<DeleteWebauthnCredentialResult> {
  try {
    const response = await fetch(apiRoot, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query: /* GraphQL */ `
          mutation deleteWebauthnCredential($credentialId: String!) {
            upa {
              mfaFactors {
                webauthn {
                  deleteCredential(credentialId: $credentialId)
                }
              }
            }
          }
        `,
        variables: { credentialId },
      }),
    });
    const result = await response.json();
    if (result?.data?.upa?.mfaFactors?.webauthn?.deleteCredential === true) {
      return { success: true };
    }
    return {
      success: false,
      error: topLevelError(result) ?? { code: "unexpected_error" },
      fatalError: false,
    };
  } catch {
    return networkError();
  }
}
