import { useEffect, useRef, useState } from "react";
import { useApiRoot } from "../../hooks/ApiRootContext";
import { prepareWebauthnFactor, verifyWebauthnFactor } from "../../services";
import { getAssertion, isWebauthnSupported } from "../../services/webauthnBrowser";
import classes from "./component.module.css";
import ErrorMessage from "./ErrorMessage.client";
import type { Props } from "./types";
import { translateError } from "../../services/i18n";
import { Trans, useTranslation } from "react-i18next";
import type { MfaError } from "../../services/common";
import ChangeMethodButton from "./ChangeMethodButton.client";

interface WebauthnVerificationFormProps {
  content: Props;
  onSuccess: (remainingFactors: string[]) => void;
  onEnrollmentRequired: (error: MfaError) => void;
  onFatalError: (error: MfaError) => void;
  /** When set, render a "Use a different method" control returning to the factor chooser. */
  onChangeMethod?: () => void;
}

/**
 * Drives a WebAuthn assertion at login: prepare (server challenge) → navigator.credentials.get()
 * on a user gesture → verify. Origin-bound, so it is resistant to real-time phishing.
 */
export default function WebauthnVerificationForm(props: Readonly<WebauthnVerificationFormProps>) {
  const { t } = useTranslation();
  const apiRoot = useApiRoot();
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const requestOptionsRef = useRef<string | null>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const unsupportedAlertRef = useRef<HTMLParagraphElement>(null);
  const supported = isWebauthnSupported();

  // Move focus to the primary action when the step becomes interactive, or to the unsupported
  // alert when WebAuthn is unavailable (mirrors WebauthnRegistrationForm; WCAG 2.4.3).
  useEffect(() => {
    if (!loading && supported) {
      buttonRef.current?.focus();
    } else if (!loading && !supported) {
      unsupportedAlertRef.current?.focus();
    }
  }, [loading, supported]);

  useEffect(() => {
    if (!supported) {
      setLoading(false);
      return;
    }

    prepareWebauthnFactor(apiRoot)
      .then((result) => {
        if (result.success && result.skipped) {
          // The factor does not apply to this session (pick-one enforcement satisfied by
          // another factor, site disabled, …) — drain it with an empty verify and move on.
          return verifyWebauthnFactor(apiRoot, "").then((drained) => {
            if (drained.success) {
              props.onSuccess(drained.remainingFactors);
            } else {
              props.onFatalError(drained.error);
            }
          });
        }
        if (result.success) {
          requestOptionsRef.current = result.requestOptionsJson;
          setError("");
        } else if (result.error?.code === "factor.webauthn.registration_required") {
          // Enforcement is active and the user has no enforced factor configured —
          // switch to the inline enrollment step (the error carries the offered factors).
          props.onEnrollmentRequired(result.error);
        } else if (result?.fatalError) {
          props.onFatalError(result.error);
        } else {
          setError(translateError(t, result.error));
        }
        return undefined;
      })
      .finally(() => setLoading(false));
    // Intentionally run once on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const authenticate = async () => {
    if (!requestOptionsRef.current) {
      return;
    }

    setSubmitting(true);
    setError("");
    try {
      const assertion = await getAssertion(requestOptionsRef.current);
      const result = await verifyWebauthnFactor(apiRoot, assertion);
      if (result.success) {
        props.onSuccess(result.remainingFactors);
      } else if (result?.fatalError) {
        props.onFatalError(result.error);
      } else {
        setError(translateError(t, result.error));
      }
    } catch (e) {
      // NotAllowedError = user cancelled / timed out.
      setError(
        t(
          (e as DOMException)?.name === "NotAllowedError"
            ? "factor.webauthn.cancelled"
            : "factor.webauthn.verification_failed",
        ),
      );
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div role="status" aria-live="polite">
        <Trans i18nKey="verify.loading" />
      </div>
    );
  }

  return (
    <div className={classes.otpFormWrapper}>
      <h2>
        <Trans i18nKey="factor.webauthn.title" />
      </h2>
      {supported ? (
        <>
          <p className={classes.helpText}>
            <Trans i18nKey="factor.webauthn.help" />
          </p>
          <ErrorMessage message={error} id="webauthn-verify-error" />
          <div style={{ textAlign: "center", marginTop: "0.5rem" }}>
            <button
              ref={buttonRef}
              type="button"
              disabled={submitting || !requestOptionsRef.current}
              aria-busy={submitting}
              aria-describedby="webauthn-verify-error"
              data-testid="webauthn-authenticate"
              className={classes.submitButton}
              onClick={authenticate}
            >
              {submitting
                ? t("factor.webauthn.inProgress")
                : t("factor.webauthn.authenticate")}
            </button>
          </div>
        </>
      ) : (
        <p ref={unsupportedAlertRef} tabIndex={-1} className={classes.helpText} role="alert" data-testid="webauthn-unsupported">
          <Trans i18nKey="factor.webauthn.unsupported" />
        </p>
      )}
      {props.onChangeMethod && (
        <div className={classes.additionalAction}>
          <ChangeMethodButton
            onClick={props.onChangeMethod}
            labelKey="chooser.useDifferentMethod"
            testId="change-method"
          />
        </div>
      )}
    </div>
  );
}
