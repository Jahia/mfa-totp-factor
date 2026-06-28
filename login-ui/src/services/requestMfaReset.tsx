import { type BaseError, networkError, topLevelError } from "./common";

export interface RequestMfaResetResultSuccess {
  success: true;
}
export type RequestMfaResetResult = RequestMfaResetResultSuccess | BaseError;

/**
 * Asks the server to notify an administrator that the current sign-in session's user (password
 * proven, stuck at the MFA step) needs their factor reset. The server derives the subject from the
 * active MFA session — there is no user argument — and always returns a generic success, so this
 * never reveals whether a request was actually actioned. Offered only at the verification step.
 */
export default async function requestMfaReset(apiRoot: string): Promise<RequestMfaResetResult> {
  try {
    const response = await fetch(apiRoot, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query: /* GraphQL */ `
          mutation requestMfaReset {
            mfaRequestReset
          }
        `,
      }),
    });
    const result = await response.json();
    if (result?.data?.mfaRequestReset === true) {
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
