import { type ChangeEvent, type FormEvent, useEffect, useRef, useState } from "react";
import { useApiRoot } from "../../hooks/ApiRootContext";
import { prepareTotpFactor, verifyTotpFactor } from "../../services";
import classes from "./component.module.css";
import ErrorMessage from "./ErrorMessage.client";
import type { Props } from "./types";
import { convertErrorArgsToInterpolation } from "../../services/i18n";
import { Trans, useTranslation } from "react-i18next";
import type { MfaError } from "../../services/common";
import { submitOnEnter } from "./formKeyboard";

interface TotpCodeVerificationFormProps {
  content: Props;
  onSuccess: () => void;
  onFatalError: (error: MfaError) => void;
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
        if (result.success) {
          setError("");
        } else if (result.error?.code === "factor.totp.enrollment_required") {
          // Site enforces TOTP and the user hasn't enrolled — bounce them to the
          // dashboard enrollment page. They'll come back here after enrolment.
          window.location.assign(props.content.contextPath + "/jahia/dashboard/mfa-factors-totp");
        } else if (result?.fatalError) {
          props.onFatalError(result.error);
        } else {
          const { key, interpolation } = convertErrorArgsToInterpolation(result.error);
          setError(t(key, interpolation));
        }
      })
      .finally(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    inputRef.current?.focus();
    prepareFactor();
    // Intentionally run once on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    // Reset the code whenever the user toggles between TOTP and backup mode.
    setCode("");
    setError("");
    setTimeout(() => inputRef.current?.focus(), 0);
  }, [useBackupCode]);

  if (loading) {
    return (
      <div>
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

  const submit = () => {
    if (!isCodeValid || submitting) return;
    setSubmitting(true);
    verifyTotpFactor(apiRoot, code)
      .then((result) => {
        if (result.success) {
          setError("");
          props.onSuccess();
        } else if (result?.fatalError) {
          props.onFatalError(result.error);
        } else {
          const { key, interpolation } = convertErrorArgsToInterpolation(result.error);
          setError(t(key, interpolation));
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
        <Trans i18nKey={props.content.totpCodeVerificationFieldLabel} />
      </h2>

      {!useBackupCode && props.content.totpCodeVerificationHelpHtml && (
        <div
          className={classes.helpText}
          dangerouslySetInnerHTML={{ __html: props.content.totpCodeVerificationHelpHtml }}
        />
      )}

      <form onSubmit={handleSubmit}>
        <div style={{ textAlign: "center" }}>
          <input
            ref={inputRef}
            id="verificationCode"
            name="verificationCode"
            type="text"
            inputMode={useBackupCode ? "text" : "numeric"}
            autoComplete="one-time-code"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            placeholder={useBackupCode ? "ABCD-1234" : "123456"}
            value={code}
            onChange={handleCodeInputChange}
            onKeyDown={submitOnEnter(submit)}
            aria-label="Enter authenticator code"
            data-testid={useBackupCode ? "verification-backup-code" : "verification-code"}
            className={useBackupCode ? classes.backupCodeInput : classes.otpInput}
            required
          />
        </div>
        <ErrorMessage message={error} />
        <div style={{ textAlign: "center", marginTop: "0.5rem" }}>
          <button
            type="submit"
            disabled={!isCodeValid || submitting}
            data-testid="verification-submit"
            className={classes.submitButton}
          >
            {props.content.totpCodeVerificationSubmitButtonLabel}
          </button>
        </div>
        <hr />
        <div className={classes.additionalAction}>
          <button
            type="button"
            className={classes.toggleMode}
            data-testid="toggle-backup-code"
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
                __html: props.content.totpCodeVerificationBackupCodeHintHtml,
              }}
            />
          )}
        </div>
      </form>
    </div>
  );
}
