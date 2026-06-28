import { type BaseError, networkError, topLevelError } from "./common";

export interface WebauthnCredential {
  credentialId: string;
  nickname: string | null;
  signCount: number;
  createdAt: string | null;
  lastUsedAt: string | null;
  transports: string[];
  aaguid: string | null;
}
export interface WebauthnStatusResultSuccess {
  success: true;
  supported: boolean;
  registered: boolean;
  credentials: WebauthnCredential[];
}
export type WebauthnStatusResult = WebauthnStatusResultSuccess | BaseError;

/**
 * Reads the current authenticated user's WebAuthn state (self-service): whether the platform
 * supports it on this site and the list of registered passkeys. Drives the settings panel's
 * WebAuthn section.
 */
export default async function webauthnStatus(apiRoot: string): Promise<WebauthnStatusResult> {
  try {
    const response = await fetch(apiRoot, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query: /* GraphQL */ `
          query webauthnStatus {
            mfaWebauthn {
              supported
              status {
                registered
                credentials {
                  credentialId
                  nickname
                  signCount
                  createdAt
                  lastUsedAt
                  transports
                  aaguid
                }
              }
            }
          }
        `,
      }),
    });
    const result = await response.json();
    const root = result?.data?.mfaWebauthn;
    const status = root?.status;
    if (status) {
      return {
        success: true,
        supported: Boolean(root.supported),
        registered: Boolean(status.registered),
        credentials: Array.isArray(status.credentials) ? status.credentials : [],
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
