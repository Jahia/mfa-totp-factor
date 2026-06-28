import { type BaseError, networkError, topLevelError } from "./common";

export interface RenameWebauthnCredentialResultSuccess {
  success: true;
}
export type RenameWebauthnCredentialResult = RenameWebauthnCredentialResultSuccess | BaseError;

/**
 * Renames one of the current user's registered passkeys (self-service). The server scopes the
 * operation to the logged-in user, so a user can only rename their own credentials.
 */
export default async function renameWebauthnCredential(
  apiRoot: string,
  credentialId: string,
  nickname: string,
): Promise<RenameWebauthnCredentialResult> {
  try {
    const response = await fetch(apiRoot, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query: /* GraphQL */ `
          mutation renameWebauthnCredential($credentialId: String!, $nickname: String!) {
            upa {
              mfaFactors {
                webauthn {
                  renameCredential(credentialId: $credentialId, nickname: $nickname)
                }
              }
            }
          }
        `,
        variables: { credentialId, nickname },
      }),
    });
    const result = await response.json();
    if (result?.data?.upa?.mfaFactors?.webauthn?.renameCredential === true) {
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
