import { useEffect, useRef, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import classes from "../Authentication/component.module.css";

/**
 * One-shot backup-codes display shown after enrollment confirmation or regeneration. Lets the user
 * copy/download the codes, then acknowledge to return to the section. Mirrors the login-flow
 * enrollment display (copy/download/ack) for consistency.
 */
export default function BackupCodes({
  codes,
  onDone,
}: Readonly<{ codes: string[]; onDone: () => void }>) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState("");
  const headingRef = useRef<HTMLHeadingElement>(null);

  // Move focus to the heading when the codes appear (WCAG 2.4.3).
  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  const copy = () => {
    navigator.clipboard
      ?.writeText(codes.join("\n"))
      .then(() => setCopied(t("enroll.totp.copied")))
      .catch(() => {
        /* Clipboard unavailable: codes stay visible and selectable. */
      });
  };

  const download = () => {
    const blob = new Blob([codes.join("\n") + "\n"], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "backup-codes.txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className={classes.otpFormWrapper}>
      <h3 id="mfa-backup-heading" ref={headingRef} tabIndex={-1}>
        <Trans i18nKey="enroll.totp.backupTitle" />
      </h3>
      <p className={classes.helpText}>
        <Trans i18nKey="enroll.totp.backupWarning" />
      </p>
      <pre
        role="region"
        aria-labelledby="mfa-backup-heading"
        data-testid="mfa-backup-codes"
        style={{ textAlign: "center", lineHeight: 1.7, userSelect: "all" }}
      >
        {codes.join("\n")}
      </pre>
      <div style={{ display: "flex", gap: "0.75rem", justifyContent: "center", flexWrap: "wrap" }}>
        <button type="button" data-testid="mfa-backup-copy" className={classes.submitButton} onClick={copy}>
          {t("enroll.totp.copyCodes")}
        </button>
        <button type="button" data-testid="mfa-backup-download" className={classes.submitButton} onClick={download}>
          {t("enroll.totp.downloadCodes")}
        </button>
      </div>
      <div role="status" aria-live="polite" className={classes.helpText} data-testid="mfa-backup-copied">
        {copied}
      </div>
      <div style={{ textAlign: "center", marginTop: "0.5rem" }}>
        <button type="button" data-testid="mfa-backup-ack" className={classes.submitButton} onClick={onDone}>
          {t("settings.done")}
        </button>
      </div>
    </div>
  );
}
