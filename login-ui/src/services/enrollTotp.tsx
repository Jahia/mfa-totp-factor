import { type BaseError, networkError, topLevelError } from "./common";

export interface EnrollTotpResultSuccess {
  success: true;
  secret: string;
  otpauthUri: string;
  issuer: string;
  accountName: string;
}
export type EnrollTotpResult = EnrollTotpResultSuccess | BaseError;

/** Re-enrollment options for an already-enrolled user (self-service settings panel). */
export interface EnrollTotpOptions {
  /** Replace an existing enrollment. The server requires proof via {@code currentCode}. */
  force?: boolean;
  /** A current authenticator (or backup) code, proving ownership when forcing a re-enroll. */
  currentCode?: string;
}

/**
 * Starts a TOTP enrollment. During sign-in (inline, pre-authentication) it is called with no
 * options for an initiated MFA session whose user has no enforced factor configured. From the
 * self-service settings panel it is called with {@code force: true} + the user's current code to
 * re-enroll. Returns the fresh secret + otpauth:// URI to render as a QR code.
 */
export default async function enrollTotp(
  apiRoot: string,
  options: EnrollTotpOptions = {},
): Promise<EnrollTotpResult> {
  try {
    const response = await fetch(apiRoot, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query: /* GraphQL */ `
          mutation enrollTotp($force: Boolean, $currentCode: String) {
            upa {
              mfaFactors {
                totp {
                  enroll(force: $force, currentCode: $currentCode) {
                    secret
                    otpauthUri
                    issuer
                    accountName
                  }
                }
              }
            }
          }
        `,
        variables: { force: options.force ?? null, currentCode: options.currentCode ?? null },
      }),
    });
    const result = await response.json();
    const enroll = result?.data?.upa?.mfaFactors?.totp?.enroll;
    if (enroll?.secret && enroll?.otpauthUri) {
      return {
        success: true,
        secret: enroll.secret,
        otpauthUri: enroll.otpauthUri,
        issuer: enroll.issuer,
        accountName: enroll.accountName,
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
