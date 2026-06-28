import { Trans, useTranslation } from "react-i18next";
import classes from "../Authentication/component.module.css";

/** Mask an email for display: keep the first character and the domain (a***@example.com). */
function maskEmail(email: string): string {
  const at = email.indexOf("@");
  if (at <= 0) {
    return email;
  }
  const local = email.slice(0, at);
  const domain = email.slice(at);
  const head = local.charAt(0);
  return `${head}${"*".repeat(Math.max(local.length - 1, 1))}${domain}`;
}

/**
 * Read-only email_code section. The email factor has no enrollment — it is active whenever the
 * user has an email address on their profile — so this section only reports state and points the
 * user to their profile to change it. No mutation.
 */
export default function EmailSection({ email }: Readonly<{ email: string | null }>) {
  const { t } = useTranslation();
  const configured = Boolean(email);
  return (
    <section aria-labelledby="mfa-email-heading" data-testid="mfa-email-section" className={classes.mfaSection}>
      <h2 id="mfa-email-heading">
        <Trans i18nKey="settings.email.heading" />
      </h2>
      <p className={classes.helpText} data-testid="mfa-email-status">
        {configured
          ? t("settings.email.configured", { email: maskEmail(email as string) })
          : t("settings.email.notConfigured")}
      </p>
      <p className={classes.helpText}>
        <Trans i18nKey="settings.email.managedInProfile" />
      </p>
    </section>
  );
}
