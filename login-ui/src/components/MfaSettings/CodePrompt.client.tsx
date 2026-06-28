import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import classes from "../Authentication/component.module.css";
import ErrorMessage from "../Authentication/ErrorMessage.client";
import OtpInput from "../Authentication/OtpInput.client";

const TOTP_CODE_LENGTH = 6;

/**
 * A code-confirmation prompt for a sensitive TOTP action (disable / regenerate / re-enroll).
 * These self-service management operations require a LIVE authenticator code (the server's
 * chokepoint does not accept backup codes here — those are login-recovery only), so this prompt
 * only takes the 6-digit authenticator code and auto-submits when complete.
 */
export default function CodePrompt({
  promptKey,
  submitting,
  error,
  testIdPrefix,
  onSubmit,
  onCancel,
}: Readonly<{
  promptKey: string;
  submitting: boolean;
  error: string;
  testIdPrefix: string;
  onSubmit: (value: string) => void;
  onCancel: () => void;
}>) {
  const { t } = useTranslation();
  const [code, setCode] = useState("");
  const errorId = `${testIdPrefix}-error`;

  return (
    <div className={classes.otpFormWrapper}>
      <p className={classes.helpText}>
        <Trans i18nKey={promptKey} />
      </p>
      <OtpInput
        length={TOTP_CODE_LENGTH}
        value={code}
        onChange={setCode}
        onComplete={(v) => !submitting && onSubmit(v)}
        disabled={submitting}
        autoFocus
        groupLabel={t("factor.totp.codeInputLabel")}
        digitLabel={(index, count) => t("factor.otp.digitLabel", { index, count })}
        describedById={errorId}
        testId={`${testIdPrefix}-input`}
      />
      <ErrorMessage message={error} id={errorId} />
      <div style={{ textAlign: "center", marginTop: "0.5rem" }}>
        <button
          type="button"
          className={classes.submitButton}
          data-testid={`${testIdPrefix}-submit`}
          disabled={code.length !== TOTP_CODE_LENGTH || submitting}
          aria-busy={submitting}
          onClick={() => onSubmit(code)}
        >
          {t("settings.confirm")}
        </button>
      </div>
      <div className={classes.additionalAction}>
        <button
          type="button"
          className={classes.secondaryButton}
          data-testid={`${testIdPrefix}-cancel`}
          onClick={onCancel}
        >
          {t("settings.cancel")}
        </button>
      </div>
    </div>
  );
}
