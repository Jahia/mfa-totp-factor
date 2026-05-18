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
