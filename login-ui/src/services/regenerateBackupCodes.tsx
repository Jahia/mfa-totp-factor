import { type BaseError, networkError, topLevelError } from "./common";

export interface RegenerateBackupCodesResultSuccess {
  success: true;
  backupCodes: string[];
}
export type RegenerateBackupCodesResult = RegenerateBackupCodesResultSuccess | BaseError;

/**
 * Regenerates the current user's TOTP backup codes (self-service), returning the fresh one-shot
 * set to display. Requires proof via a current authenticator (or backup) code; an invalid code
 * comes back as a top-level GraphQL error.
 */
export default async function regenerateBackupCodes(
  apiRoot: string,
  code: string,
): Promise<RegenerateBackupCodesResult> {
  try {
    const response = await fetch(apiRoot, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query: /* GraphQL */ `
          mutation regenerateBackupCodes($code: String!) {
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
        variables: { code },
      }),
    });
    const result = await response.json();
    const codes = result?.data?.upa?.mfaFactors?.totp?.regenerateBackupCodes?.backupCodes;
    if (Array.isArray(codes)) {
      return { success: true, backupCodes: codes };
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
