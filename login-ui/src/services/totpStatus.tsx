import { type BaseError, networkError, topLevelError } from "./common";

export interface TotpStatusResultSuccess {
  success: true;
  enrolled: boolean;
  hasBackupCodes: boolean;
  remainingBackupCodes: number;
}
export type TotpStatusResult = TotpStatusResultSuccess | BaseError;

/**
 * Reads the current authenticated user's TOTP enrollment status (self-service). Drives the
 * settings panel's TOTP section: enrolled? how many backup codes remain? No MFA session is
 * required — the server resolves the factor state from the logged-in JCR user.
 */
export default async function totpStatus(apiRoot: string): Promise<TotpStatusResult> {
  try {
    const response = await fetch(apiRoot, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query: /* GraphQL */ `
          query totpStatus {
            mfaTotp {
              status {
                enrolled
                hasBackupCodes
                remainingBackupCodes
              }
            }
          }
        `,
      }),
    });
    const result = await response.json();
    const status = result?.data?.mfaTotp?.status;
    if (status) {
      return {
        success: true,
        enrolled: Boolean(status.enrolled),
        hasBackupCodes: Boolean(status.hasBackupCodes),
        remainingBackupCodes: Number(status.remainingBackupCodes ?? 0),
      };
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
