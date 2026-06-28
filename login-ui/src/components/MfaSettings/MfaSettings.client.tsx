import { Trans } from "react-i18next";
import { ApiRootContext } from "../../hooks/ApiRootContext";
import { sanitizeHtml } from "../../services/sanitizeHtml";
import classes from "../Authentication/component.module.css";
import type { MfaSettingsContent } from "./types";
import TotpSection from "./TotpSection.client";
import WebauthnSection from "./WebauthnSection.client";
import EmailSection from "./EmailSection.client";

/**
 * Self-service MFA settings panel for an authenticated user on a live site page. Each factor
 * section loads and manages its own state independently (parallel, no waterfall); every operation
 * is scoped server-side to the logged-in user. Wraps children in the ApiRootContext the sections'
 * services read via useApiRoot().
 */
export default function MfaSettings({
  apiRoot,
  content,
}: Readonly<{ apiRoot: string; content: MfaSettingsContent }>) {
  if (!content.isAuthenticated) {
    return (
      <p className={classes.helpText} role="status" data-testid="mfa-settings-signin">
        <Trans i18nKey="settings.signInRequired" />
      </p>
    );
  }

  return (
    <ApiRootContext value={apiRoot}>
      {content.introHtml && (
        <div
          className={classes.helpText}
          data-testid="mfa-settings-intro"
          dangerouslySetInnerHTML={{ __html: sanitizeHtml(content.introHtml) }}
        />
      )}
      <TotpSection />
      <WebauthnSection />
      {content.showEmailFactor && <EmailSection email={content.userEmail ?? null} />}
    </ApiRootContext>
  );
}
