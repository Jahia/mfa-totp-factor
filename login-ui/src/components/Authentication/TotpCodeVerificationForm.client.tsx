import { type ChangeEvent, type FormEvent, useEffect, useRef, useState } from "react";
import { useApiRoot } from "../../hooks/ApiRootContext";
import { prepareTotpFactor, verifyTotpFactor } from "../../services";
import classes from "./component.module.css";
import ErrorMessage from "./ErrorMessage.client";
import type { Props } from "./types";
import { translateError } from "../../services/i18n";
import { Trans, useTranslation } from "react-i18next";
import type { MfaError } from "../../services/common";
import { submitOnEnter } from "./formKeyboard";
import { sanitizeHtml } from "../../services/sanitizeHtml";
import ChangeMethodButton from "./ChangeMethodButton.client";
import OtpInput from "./OtpInput.client";

interface TotpCodeVerificationFormProps {
  content: Props;
  onSuccess: (remainingFactors: string[]) => void;
  onEnrollmentRequired: (error: MfaError) => void;
  onFatalError: (error: MfaError) => void;
  /** When set, render a "Use a different method" control returning to the factor chooser. */
  onChangeMethod?: () => void;
}

const TOTP_CODE_LENGTH = 6;
const BACKUP_CODE_MIN_LENGTH = 8; // 10 hex chars in the current generator, but tolerate 8+

export default function TotpCodeVerificationForm(props: Readonly<TotpCodeVerificationFormProps>) {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(true);
  const [code, setCode] = useState("");
  const [useBackupCode, setUseBackupCode] = useState(false);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const apiRoot = useApiRoot();

  const prepareFactor = () => {
    prepareTotpFactor(apiRoot)
      .then((result) => {
        if (result.success && result.skipped) {
          // The factor does not apply to this session (pick-one enforcement satisfied by
          // another factor, site disabled, …) — drain it with an empty verify and move on.
          return verifyTotpFactor(apiRoot, "").then((drained) => {
            if (drained.success) {
              props.onSuccess(drained.remainingFactors);
            } else {
              props.onFatalError(drained.error);
            }
          });
        }
        if (result.success) {
          setError("");
        } else if (result.error?.code === "factor.totp.enrollment_required") {
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
      .finally(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    prepareFactor();
    // Intentionally run once on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Focus the free-text backup-code input when the form is interactive in backup mode. The TOTP
  // segmented input focuses its first box itself (autoFocus) when it mounts.
  useEffect(() => {
    if (!loading && useBackupCode) {
      inputRef.current?.focus();
    }
  }, [loading, useBackupCode]);

  useEffect(() => {
    // Reset the code whenever the user toggles between TOTP and backup mode.
    setCode("");
    setError("");
  }, [useBackupCode]);

  if (loading) {
    return (
      <div role="status" aria-live="polite">
        <Trans i18nKey="verify.loading" />
      </div>
    );
  }

  const sanitize = (raw: string): string =>
    useBackupCode
      ? raw.replace(/[^A-Za-z0-9-]/g, "").slice(0, 24)
      : raw.replace(/\D/g, "").slice(0, TOTP_CODE_LENGTH);

  const handleCodeInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    setCode(sanitize(e.target.value));
  };

  const isCodeValid = useBackupCode
    ? code.length >= BACKUP_CODE_MIN_LENGTH
    : code.length === TOTP_CODE_LENGTH;

  const submit = (codeOverride?: string) => {
    const value = codeOverride ?? code;
    const valid = useBackupCode
      ? value.length >= BACKUP_CODE_MIN_LENGTH
      : value.length === TOTP_CODE_LENGTH;
    if (!valid || submitting) return;
    setSubmitting(true);
    verifyTotpFactor(apiRoot, value)
      .then((result) => {
        if (result.success) {
          setError("");
          props.onSuccess(result.remainingFactors);
        } else if (result?.fatalError) {
          props.onFatalError(result.error);
        } else {
          setError(translateError(t, result.error));
        }
      })
      .finally(() => setSubmitting(false));
  };

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    submit();
  };

  return (
    <div className={classes.otpFormWrapper}>
      <h2>
        {useBackupCode ? (
          <Trans i18nKey="factor.totp.backupCodeHeading" />
        ) : (
          <Trans i18nKey={props.content.totpCodeVerificationFieldLabel} />
        )}
      </h2>

      {!useBackupCode && props.content.totpCodeVerificationHelpHtml && (
        <div
          className={classes.helpText}
          dangerouslySetInnerHTML={{
            __html: sanitizeHtml(props.content.totpCodeVerificationHelpHtml),
          }}
        />
      )}

      <form onSubmit={handleSubmit}>
        {useBackupCode ? (
          <div style={{ textAlign: "center" }}>
            <input
              ref={inputRef}
              id="verificationCode"
              name="verificationCode"
              type="text"
              inputMode="text"
              autoComplete="one-time-code"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              placeholder="ABCD-1234"
              value={code}
              onChange={handleCodeInputChange}
              onKeyDown={submitOnEnter(submit)}
              aria-label={t("factor.totp.backupCodeHeading")}
              aria-describedby="verificationCode-error"
              data-testid="verification-backup-code"
              className={classes.backupCodeInput}
              required
            />
          </div>
        ) : (
          <OtpInput
            length={TOTP_CODE_LENGTH}
            value={code}
            onChange={setCode}
            onComplete={(v) => submit(v)}
            disabled={submitting}
            autoFocus
            groupLabel={t("factor.totp.codeInputLabel")}
            digitLabel={(index, count) => t("factor.otp.digitLabel", { index, count })}
            describedById="verificationCode-error"
            testId="verification-code"
          />
        )}
        <ErrorMessage message={error} id="verificationCode-error" />
        <div style={{ textAlign: "center", marginTop: "0.5rem" }}>
          <button
            type="submit"
            disabled={!isCodeValid || submitting}
            aria-busy={submitting}
            aria-describedby="verificationCode-error"
            data-testid="verification-submit"
            className={classes.submitButton}
          >
            {props.content.totpCodeVerificationSubmitButtonLabel}
          </button>
        </div>
        <hr aria-hidden="true" />
        <div className={classes.additionalAction}>
          <button
            type="button"
            className={classes.toggleMode}
            data-testid="toggle-backup-code"
            aria-pressed={useBackupCode}
            onClick={() => setUseBackupCode((v) => !v)}
          >
            {useBackupCode
              ? t("factor.totp.useAuthenticatorCode")
              : t("factor.totp.useBackupCode")}
          </button>
          {useBackupCode && props.content.totpCodeVerificationBackupCodeHintHtml && (
            <div
              style={{ marginTop: "0.5rem" }}
              dangerouslySetInnerHTML={{
                __html: sanitizeHtml(props.content.totpCodeVerificationBackupCodeHintHtml),
              }}
            />
          )}
          {props.onChangeMethod && (
            <div style={{ marginTop: "0.5rem" }}>
              <ChangeMethodButton
                onClick={props.onChangeMethod}
                labelKey="chooser.useDifferentMethod"
                testId="change-method"
              />
            </div>
          )}
        </div>
      </form>
    </div>
  );
}
