import { useEffect, useRef, useState } from "react";
import { useApiRoot } from "../../hooks/ApiRootContext";
import { prepareWebauthnFactor, verifyWebauthnFactor } from "../../services";
import { getAssertion, isWebauthnSupported } from "../../services/webauthnBrowser";
import classes from "./component.module.css";
import ErrorMessage from "./ErrorMessage.client";
import type { Props } from "./types";
import { convertErrorArgsToInterpolation } from "../../services/i18n";
import { Trans, useTranslation } from "react-i18next";
import type { MfaError } from "../../services/common";

interface WebauthnVerificationFormProps {
  content: Props;
  onSuccess: () => void;
  onFatalError: (error: MfaError) => void;
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
  const supported = isWebauthnSupported();

  // Move focus to the primary action when the step becomes interactive (focus order on transition).
  useEffect(() => {
    if (!loading && supported) {
      buttonRef.current?.focus();
    }
  }, [loading, supported]);

  useEffect(() => {
    if (!supported) {
      setLoading(false);
      return;
    }

    prepareWebauthnFactor(apiRoot)
      .then((result) => {
        if (result.success) {
          requestOptionsRef.current = result.requestOptionsJson;
          setError("");
        } else if (result.error?.code === "factor.webauthn.registration_required") {
          // Site enforces WebAuthn and the user has no authenticator — bounce them to register.
          window.location.assign(props.content.contextPath + "/jahia/dashboard/mfa-factors-webauthn");
        } else if (result?.fatalError) {
          props.onFatalError(result.error);
        } else {
          const { key, interpolation } = convertErrorArgsToInterpolation(result.error);
          setError(t(key, interpolation));
        }
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
        props.onSuccess();
      } else if (result?.fatalError) {
        props.onFatalError(result.error);
      } else {
        const { key, interpolation } = convertErrorArgsToInterpolation(result.error);
        setError(t(key, interpolation));
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
          <ErrorMessage message={error} />
          <div style={{ textAlign: "center", marginTop: "0.5rem" }}>
            <button
              ref={buttonRef}
              type="button"
              disabled={submitting || !requestOptionsRef.current}
              aria-busy={submitting}
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
        <p className={classes.helpText} role="alert" data-testid="webauthn-unsupported">
          <Trans i18nKey="factor.webauthn.unsupported" />
        </p>
      )}
    </div>
  );
}
