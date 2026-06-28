import { useEffect, useRef, useState } from "react";
import { QRCodeCanvas } from "qrcode.react";
import { Trans, useTranslation } from "react-i18next";
import { useApiRoot } from "../../hooks/ApiRootContext";
import {
  confirmEnrollTotp,
  disableTotp,
  enrollTotp,
  regenerateBackupCodes,
  totpStatus,
} from "../../services";
import { translateError } from "../../services/i18n";
import classes from "../Authentication/component.module.css";
import ErrorMessage from "../Authentication/ErrorMessage.client";
import OtpInput from "../Authentication/OtpInput.client";
import BackupCodes from "./BackupCodes.client";
import CodePrompt from "./CodePrompt.client";

const TOTP_CODE_LENGTH = 6;

type Mode = "loading" | "idle" | "enroll" | "backup" | "prompt";
type PendingAction = "disable" | "regenerate" | "reenroll" | null;

/**
 * Self-service TOTP management: enroll (QR + confirm), view remaining backup codes, regenerate
 * them, disable, and re-enroll. Every server op is scoped to the logged-in user; the disable /
 * regenerate / re-enroll prompts accept a live authenticator code OR a backup code, so a user who
 * lost their authenticator can still recover with a backup code.
 */
export default function TotpSection() {
  const { t } = useTranslation();
  const apiRoot = useApiRoot();

  const [mode, setMode] = useState<Mode>("loading");
  const [enrolled, setEnrolled] = useState(false);
  const [remaining, setRemaining] = useState(0);
  const [error, setError] = useState("");

  // Enroll ceremony state.
  const [secret, setSecret] = useState("");
  const [otpauthUri, setOtpauthUri] = useState("");
  const [code, setCode] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Freshly generated backup codes (after confirmEnroll or regenerate).
  const [backupCodes, setBackupCodes] = useState<string[]>([]);

  // Code-prompt state (disable / regenerate / re-enroll).
  const [pending, setPending] = useState<PendingAction>(null);

  const headingRef = useRef<HTMLHeadingElement>(null);

  const loadStatus = () => {
    totpStatus(apiRoot).then((res) => {
      if (res.success) {
        setEnrolled(res.enrolled);
        setRemaining(res.remainingBackupCodes);
        setMode("idle");
      } else {
        setError(translateError(t, res.error));
        setMode("idle");
      }
    });
  };

  useEffect(() => {
    loadStatus();
    // Load once on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // --- Enroll ceremony (used for first enrollment and re-enrollment) ----------------------------

  const beginEnroll = (currentCode?: string) => {
    setError("");
    setSubmitting(true);
    enrollTotp(apiRoot, currentCode ? { force: true, currentCode } : {})
      .then((res) => {
        if (res.success) {
          setSecret(res.secret);
          setOtpauthUri(res.otpauthUri);
          setCode("");
          setMode("enroll");
        } else {
          setError(translateError(t, res.error));
          setMode("idle");
        }
      })
      .finally(() => setSubmitting(false));
  };

  const confirmEnroll = (value: string) => {
    if (value.length !== TOTP_CODE_LENGTH || submitting) return;
    setSubmitting(true);
    confirmEnrollTotp(apiRoot, value)
      .then((res) => {
        if (res.success) {
          setError("");
          setBackupCodes(res.backupCodes);
          setEnrolled(true);
          setMode("backup");
        } else {
          setError(translateError(t, res.error));
        }
      })
      .finally(() => setSubmitting(false));
  };

  // --- Code-prompt actions (disable / regenerate / re-enroll) -----------------------------------

  const runPrompt = (value: string) => {
    setSubmitting(true);
    setError("");
    const done = () => setSubmitting(false);
    if (pending === "disable") {
      disableTotp(apiRoot, value)
        .then((res) => {
          if (res.success) {
            setPending(null);
            setEnrolled(false);
            setRemaining(0);
            setMode("idle");
          } else {
            setError(translateError(t, res.error));
          }
        })
        .finally(done);
    } else if (pending === "regenerate") {
      regenerateBackupCodes(apiRoot, value)
        .then((res) => {
          if (res.success) {
            setPending(null);
            setBackupCodes(res.backupCodes);
            setMode("backup");
          } else {
            setError(translateError(t, res.error));
          }
        })
        .finally(done);
    } else if (pending === "reenroll") {
      setPending(null);
      setSubmitting(false);
      beginEnroll(value);
    } else {
      setSubmitting(false);
    }
  };

  // --- Render -----------------------------------------------------------------------------------

  const wrap = (children: React.ReactNode) => (
    <section
      aria-labelledby="mfa-totp-heading"
      data-testid="mfa-totp-section"
      className={classes.mfaSection}
    >
      <h2 id="mfa-totp-heading" ref={headingRef} tabIndex={-1}>
        <Trans i18nKey="settings.totp.heading" />
      </h2>
      {children}
    </section>
  );

  if (mode === "loading") {
    return wrap(
      <div role="status" aria-live="polite" className={classes.helpText}>
        <Trans i18nKey="settings.loading" />
      </div>,
    );
  }

  if (mode === "backup") {
    return wrap(
      <BackupCodes
        codes={backupCodes}
        onDone={() => {
          setBackupCodes([]);
          loadStatus();
        }}
      />,
    );
  }

  if (mode === "enroll") {
    return wrap(
      <>
        <p className={classes.helpText}>
          <Trans i18nKey="enroll.totp.scan" />
        </p>
        <div
          style={{ textAlign: "center", margin: "1rem 0" }}
          role="img"
          aria-label={t("enroll.totp.qrAlt")}
          data-testid="mfa-totp-qr"
        >
          <QRCodeCanvas value={otpauthUri} size={224} level="M" />
        </div>
        <p className={classes.helpText}>
          <Trans i18nKey="enroll.totp.secretLabel" />
        </p>
        <p style={{ textAlign: "center", userSelect: "all", overflowWrap: "anywhere" }}>
          <code data-testid="mfa-totp-secret">{secret}</code>
        </p>
        <p className={classes.helpText}>
          <Trans i18nKey="enroll.totp.codeLabel" />
        </p>
        <OtpInput
          length={TOTP_CODE_LENGTH}
          value={code}
          onChange={setCode}
          onComplete={(v) => confirmEnroll(v)}
          disabled={submitting}
          autoFocus
          groupLabel={t("enroll.totp.codeLabel")}
          digitLabel={(index, count) => t("factor.otp.digitLabel", { index, count })}
          describedById="mfa-totp-enroll-error"
          testId="mfa-totp-confirm-input"
        />
        <ErrorMessage message={error} id="mfa-totp-enroll-error" />
        <div style={{ textAlign: "center", marginTop: "0.5rem" }}>
          <button
            type="button"
            data-testid="mfa-totp-confirm-btn"
            className={classes.submitButton}
            disabled={code.length !== TOTP_CODE_LENGTH || submitting}
            aria-busy={submitting}
            onClick={() => confirmEnroll(code)}
          >
            {t("enroll.totp.confirm")}
          </button>
        </div>
        <div className={classes.additionalAction}>
          <button
            type="button"
            className={classes.secondaryButton}
            data-testid="mfa-totp-cancel"
            onClick={() => {
              setError("");
              loadStatus();
            }}
          >
            {t("settings.cancel")}
          </button>
        </div>
      </>,
    );
  }

  if (mode === "prompt" && pending) {
    return wrap(
      <CodePrompt
        promptKey={`settings.totp.${pending}Prompt`}
        submitting={submitting}
        error={error}
        testIdPrefix={`mfa-totp-${pending}`}
        onCancel={() => {
          setPending(null);
          setError("");
          setMode("idle");
        }}
        onSubmit={runPrompt}
      />,
    );
  }

  // idle
  return wrap(
    <>
      <p className={classes.helpText} data-testid="mfa-totp-status">
        {enrolled
          ? t("settings.totp.statusEnrolled", { count: remaining })
          : t("settings.totp.statusNotEnrolled")}
      </p>
      <ErrorMessage message={error} id="mfa-totp-error" />
      <div className={classes.mfaActions}>
        {!enrolled && (
          <button
            type="button"
            className={classes.submitButton}
            data-testid="mfa-totp-enable"
            disabled={submitting}
            onClick={() => beginEnroll()}
          >
            {t("settings.totp.enable")}
          </button>
        )}
        {enrolled && (
          <>
            <button
              type="button"
              className={classes.secondaryButton}
              data-testid="mfa-totp-regenerate"
              onClick={() => {
                setError("");
                setPending("regenerate");
                setMode("prompt");
              }}
            >
              {t("settings.totp.regenerate")}
            </button>
            <button
              type="button"
              className={classes.secondaryButton}
              data-testid="mfa-totp-reenroll"
              onClick={() => {
                setError("");
                setPending("reenroll");
                setMode("prompt");
              }}
            >
              {t("settings.totp.reenroll")}
            </button>
            <button
              type="button"
              className={classes.dangerButton}
              data-testid="mfa-totp-disable"
              onClick={() => {
                setError("");
                setPending("disable");
                setMode("prompt");
              }}
            >
              {t("settings.totp.disable")}
            </button>
          </>
        )}
      </div>
    </>,
  );
}
