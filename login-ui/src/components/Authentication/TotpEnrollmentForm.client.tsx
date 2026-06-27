import { type ChangeEvent, type FormEvent, useEffect, useRef, useState } from "react";
import { QRCodeCanvas } from "qrcode.react";
import { Trans, useTranslation } from "react-i18next";
import { useApiRoot } from "../../hooks/ApiRootContext";
import { confirmEnrollTotp, enrollTotp } from "../../services";
import classes from "./component.module.css";
import ErrorMessage from "./ErrorMessage.client";
import { translateError } from "../../services/i18n";
import type { MfaError } from "../../services/common";
import { submitOnEnter } from "./formKeyboard";
import ChangeMethodButton from "./ChangeMethodButton.client";

interface TotpEnrollmentFormProps {
  onComplete: (remainingFactors: string[]) => void;
  onFatalError: (error: MfaError) => void;
  /** When set, render a "Choose a different setup method" control returning to the enroll chooser. */
  onChangeMethod?: () => void;
}

const TOTP_CODE_LENGTH = 6;

type Phase = "loading" | "setup" | "backupCodes";

/**
 * Inline TOTP enrollment during sign-in: the server generated a fresh secret for the MFA-session
 * user (pre-auth guarded); scan the QR (or copy the secret), confirm with the first authenticator
 * code — the server persists the enrollment AND verifies the code in the same request — then
 * acknowledge the one-shot backup codes to finish signing in.
 */
export default function TotpEnrollmentForm(props: Readonly<TotpEnrollmentFormProps>) {
  const { t } = useTranslation();
  const apiRoot = useApiRoot();
  const [phase, setPhase] = useState<Phase>("loading");
  const [secret, setSecret] = useState("");
  const [otpauthUri, setOtpauthUri] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [copyConfirmation, setCopyConfirmation] = useState("");
  const remainingRef = useRef<string[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);
  const backupHeadingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    // enrollTotp() returns its network failures as typed results (success: false with a
    // network_error code), handled in the .then() branch below; it does not reject, so no
    // .catch() is needed here.
    enrollTotp(apiRoot).then((result) => {
      if (result.success) {
        setSecret(result.secret);
        setOtpauthUri(result.otpauthUri);
        setPhase("setup");
      } else {
        props.onFatalError(result.error);
      }
    });
    // Intentionally run once on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Focus the code input once the setup form is shown (item 4: effect, not setTimeout).
  useEffect(() => {
    if (phase === "setup") {
      inputRef.current?.focus();
    }
  }, [phase]);

  // Move focus to the backup-codes heading when that phase appears (WCAG 2.4.3, item 9).
  useEffect(() => {
    if (phase === "backupCodes") {
      backupHeadingRef.current?.focus();
    }
  }, [phase]);

  const handleCodeInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    setCode(e.target.value.replace(/\D/g, "").slice(0, TOTP_CODE_LENGTH));
  };

  const isCodeValid = code.length === TOTP_CODE_LENGTH;

  const submit = () => {
    if (!isCodeValid || submitting) return;
    setSubmitting(true);
    confirmEnrollTotp(apiRoot, code)
      .then((result) => {
        if (result.success) {
          setError("");
          remainingRef.current = result.remainingFactors;
          setBackupCodes(result.backupCodes);
          setPhase("backupCodes");
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

  const copyBackupCodes = () => {
    const text = backupCodes.join("\n");
    navigator.clipboard
      ?.writeText(text)
      .then(() => setCopyConfirmation(t("enroll.totp.copied")))
      .catch(() => {
        /* Clipboard unavailable/denied: the codes remain visible and selectable above. */
      });
  };

  const downloadBackupCodes = () => {
    const blob = new Blob([backupCodes.join("\n") + "\n"], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "backup-codes.txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  if (phase === "loading") {
    return (
      <div role="status" aria-live="polite">
        <Trans i18nKey="enroll.totp.loading" />
      </div>
    );
  }

  if (phase === "backupCodes") {
    return (
      <div className={classes.otpFormWrapper}>
        <h2 ref={backupHeadingRef} tabIndex={-1}>
          <Trans i18nKey="enroll.totp.backupTitle" />
        </h2>
        <p className={classes.helpText} role="alert">
          <Trans i18nKey="enroll.totp.backupWarning" />
        </p>
        <pre
          data-testid="enroll-backup-codes"
          style={{ textAlign: "center", lineHeight: 1.7, userSelect: "all" }}
        >
          {backupCodes.join("\n")}
        </pre>
        <div
          style={{ display: "flex", gap: "0.75rem", justifyContent: "center", flexWrap: "wrap" }}
        >
          <button
            type="button"
            data-testid="enroll-backup-copy"
            className={classes.submitButton}
            onClick={copyBackupCodes}
          >
            {t("enroll.totp.copyCodes")}
          </button>
          <button
            type="button"
            data-testid="enroll-backup-download"
            className={classes.submitButton}
            onClick={downloadBackupCodes}
          >
            {t("enroll.totp.downloadCodes")}
          </button>
        </div>
        <div role="status" aria-live="polite" className={classes.helpText} data-testid="enroll-backup-copied">
          {copyConfirmation}
        </div>
        <div style={{ textAlign: "center", marginTop: "0.5rem" }}>
          <button
            type="button"
            data-testid="enroll-backup-ack"
            className={classes.submitButton}
            onClick={() => props.onComplete(remainingRef.current)}
          >
            {t("enroll.totp.backupAck")}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={classes.otpFormWrapper}>
      <h2>
        <Trans i18nKey="enroll.totp.title" />
      </h2>
      <p className={classes.helpText}>
        <Trans i18nKey="enroll.totp.scan" />
      </p>
      {/* The QR canvas has no intrinsic text alternative; wrap it as an image with a label
          (WCAG 1.1.1). The secret is also shown as selectable text below. */}
      <div
        style={{ textAlign: "center", margin: "1rem 0" }}
        role="img"
        aria-label={t("enroll.totp.qrAlt")}
        data-testid="enroll-qr"
      >
        <QRCodeCanvas value={otpauthUri} size={224} level="M" />
      </div>
      <p className={classes.helpText}>
        <Trans i18nKey="enroll.totp.secretLabel" />
      </p>
      <p style={{ textAlign: "center", userSelect: "all", overflowWrap: "anywhere" }}>
        <code data-testid="enroll-secret">{secret}</code>
      </p>
      <form onSubmit={handleSubmit}>
        <p className={classes.helpText}>
          <Trans i18nKey="enroll.totp.codeLabel" />
        </p>
        <div style={{ textAlign: "center" }}>
          <input
            ref={inputRef}
            id="enrollCode"
            name="enrollCode"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            placeholder="123456"
            value={code}
            onChange={handleCodeInputChange}
            onKeyDown={submitOnEnter(submit)}
            aria-label={t("enroll.totp.codeLabel")}
            data-testid="enroll-code-input"
            className={classes.otpInput}
            required
          />
        </div>
        <ErrorMessage message={error} />
        <div style={{ textAlign: "center", marginTop: "0.5rem" }}>
          <button
            type="submit"
            disabled={!isCodeValid || submitting}
            aria-busy={submitting}
            data-testid="enroll-confirm-btn"
            className={classes.submitButton}
          >
            {t("enroll.totp.confirm")}
          </button>
        </div>
        {props.onChangeMethod && (
          <div className={classes.additionalAction}>
            <ChangeMethodButton
              onClick={props.onChangeMethod}
              labelKey="enroll.chooser.useDifferentMethod"
              testId="change-enroll-method"
            />
          </div>
        )}
      </form>
    </div>
  );
}
