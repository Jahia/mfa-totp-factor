import { type BaseError, networkError, topLevelError } from "./common";

export interface DisableTotpResultSuccess {
  success: true;
}
export type DisableTotpResult = DisableTotpResultSuccess | BaseError;

/**
 * Disables TOTP for the current authenticated user (self-service). The submitted code may be a
 * live authenticator code OR a backup code (the server's chokepoint accepts both), so a user who
 * lost their authenticator can still turn the factor off with a backup code. An invalid code comes
 * back as a top-level GraphQL error.
 */
export default async function disableTotp(apiRoot: string, code: string): Promise<DisableTotpResult> {
  try {
    const response = await fetch(apiRoot, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query: /* GraphQL */ `
          mutation disableTotp($code: String!) {
            upa {
              mfaFactors {
                totp {
                  disable(code: $code) {
                    session {
                      initiated
                    }
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
    const top = topLevelError(result);
    if (!top && result?.data?.upa?.mfaFactors?.totp?.disable !== undefined) {
      return { success: true };
    }
    return { success: false, error: top ?? { code: "unexpected_error" }, fatalError: false };
  } catch {
    return networkError();
  }
}
