/**
 * Base structure for the GraphQL APIs on successful responses.
 */
export interface BaseSuccess {
  success: true;
  remainingFactors: Array<string>;
}

export interface MfaError {
  code: string;
  arguments?: Array<{ name: string; value: string }>;
}

/**
 * Base structure for the GraphQL APIs on error response.
 * The error contains a `code` and an optional array of `arguments` (with a `name` and `value`)
 */
export interface BaseError {
  success: false;
  error: MfaError;
  fatalError?: boolean;
}

/**
 * Extracts an MFA error code from a top-level GraphQL error (a server-side
 * DataFetchingException carries the error code as its message). Returns null when the
 * response has no top-level errors.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function topLevelError(result: any): MfaError | null {
  const message: string | undefined = result?.errors?.[0]?.message;
  if (!message) {
    return null;
  }
  const match = /factor\.[a-z0-9_.]+/.exec(message);
  return { code: match ? match[0] : "unexpected_error" };
}

/**
 * A network/transport failure (fetch rejected, or the response was not valid JSON). Returned by
 * every service so a dropped connection becomes a typed, non-fatal error the form can render and
 * recover from, instead of an unhandled promise rejection that hangs the UI silently.
 */
export function networkError(): BaseError {
  return {
    success: false,
    error: { code: "network_error" },
    fatalError: false,
  };
}

/** The per-factor state carried by a prepare response. */
export interface FactorState {
  prepared?: boolean;
  error?: MfaError | null;
}

/**
 * The factorState error a prepare call should SURFACE, or undefined when it must be ignored.
 *
 * A {@code prepare.rate_limit_exceeded} on an ALREADY-prepared factor is harmless: the server
 * returns the still-valid challenge/code/marker from the prior prepare, so the ceremony can
 * proceed. Re-mounting a verification form (e.g. via "use a different method", or a re-render)
 * re-fires prepare and trips the limiter, which would otherwise surface a spurious error even
 * though a usable artifact came back. The rate limit only genuinely blocks when the factor is not
 * prepared yet (nothing usable exists) — that case is still surfaced, with its nextRetryInSeconds.
 */
export function blockingFactorStateError(factorState?: FactorState | null): MfaError | undefined {
  const error = factorState?.error;
  if (!error) {
    return undefined;
  }
  if (factorState?.prepared && error.code === "prepare.rate_limit_exceeded") {
    return undefined;
  }
  return error;
}

/**
 * Creates an error response based on provided session and factor errors.
 * If neither session nor factor errors are provided, an "unexpected_error" error is returned
 * with a fatal flag set to true.
 */
export function createError(sessionError?: MfaError, factorError?: MfaError): BaseError {
  if (sessionError) {
    return {
      success: false,
      error: sessionError,
      fatalError: true,
    };
  }
  if (factorError) {
    return {
      success: false,
      error: factorError,
      fatalError: false,
    };
  }
  return {
    success: false,
    error: { code: "unexpected_error" },
    fatalError: true,
  };
}
