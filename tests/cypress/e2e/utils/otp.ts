/**
 * Helpers for the segmented one-time-code input (OtpInput): the login UI renders one box per
 * digit (data-testid `${groupTestId}-${i}`) and auto-verifies once the last box is filled.
 */

/**
 * Enter a code into a segmented OTP input one digit per box. Clears any existing digits first
 * (last box to first, so no internal gap is created), then types each digit; the final digit
 * triggers auto-verification.
 */
export function fillOtp(groupTestId: string, code: string): void {
  const digits = code.split("");
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    cy.get(`[data-testid="${groupTestId}-${i}"]`).type("{backspace}", { force: true });
  }
  digits.forEach((digit, i) => {
    cy.get(`[data-testid="${groupTestId}-${i}"]`).type(digit);
  });
}

/**
 * Paste a full code into the first box of a segmented OTP input. Exercises the paste-distribute
 * path (and, like a 6-digit fill, triggers auto-verification once all boxes are populated).
 */
export function pasteOtp(groupTestId: string, code: string): void {
  cy.get(`[data-testid="${groupTestId}-0"]`).trigger("paste", {
    clipboardData: { getData: () => code },
  });
}
