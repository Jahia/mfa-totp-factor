import { describe, expect, it } from "vitest";
import { blockingFactorStateError } from "./common";

/**
 * blockingFactorStateError decides which prepare-response factorState error the UI should surface.
 * The crux: a `prepare.rate_limit_exceeded` on an ALREADY-prepared factor must be ignored (the
 * prior challenge/code/marker is still valid, so the ceremony can proceed) - re-mounting a
 * verification form re-fires prepare and trips the limiter, which previously surfaced a spurious
 * error on screen even though a usable artifact came back.
 */
describe("blockingFactorStateError", () => {
  it("returns undefined when there is no error", () => {
    expect(blockingFactorStateError({ prepared: true })).toBeUndefined();
    expect(blockingFactorStateError({ prepared: false })).toBeUndefined();
    expect(blockingFactorStateError(null)).toBeUndefined();
    expect(blockingFactorStateError(undefined)).toBeUndefined();
  });

  it("ignores a rate-limit error when the factor is already prepared", () => {
    const state = {
      prepared: true,
      error: { code: "prepare.rate_limit_exceeded", arguments: [{ name: "nextRetryInSeconds", value: "16" }] },
    };
    expect(blockingFactorStateError(state)).toBeUndefined();
  });

  it("surfaces the rate-limit error when the factor is NOT prepared yet", () => {
    const error = { code: "prepare.rate_limit_exceeded" };
    expect(blockingFactorStateError({ prepared: false, error })).toBe(error);
  });

  it("always surfaces a non-rate-limit error, even when prepared", () => {
    const error = { code: "factor.webauthn.registration_required" };
    expect(blockingFactorStateError({ prepared: true, error })).toBe(error);
  });
});
