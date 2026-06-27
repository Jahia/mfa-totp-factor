import type { JCRNodeWrapper } from "org.jahia.services.content";

export interface Props {
  /**
   * The context path of Jahia. `''` by default; `'/<ctx>'` when `CATALINA_CONTEXT` is set.
   */
  contextPath: string;
  /**
   * The site key of the page hosting the component (resolved server-side — the page URL may be
   * a vanity/server-name URL that carries no /sites/<key> prefix).
   */
  siteKey?: string;
  logo?: JCRNodeWrapper;
  /**
   * Author-supplied alt text for the logo; falls back to the site title server-side.
   *
   * Server-side only: this is consumed in default.server.tsx to set the logo's `alt` attribute and
   * is intentionally NOT copied into the serialised Island `content` object. Client code must not
   * read `content.logoAlt` - it would always be undefined.
   */
  logoAlt?: string;
  loginEmailFieldLabel: string;
  loginPasswordFieldLabel: string;
  loginSubmitButtonLabel: string;
  loginBelowPasswordFieldHtml?: string;
  loginAdditionalActionHtml?: string;
  totpCodeVerificationFieldLabel: string;
  totpCodeVerificationSubmitButtonLabel: string;
  totpCodeVerificationHelpHtml?: string;
  totpCodeVerificationBackupCodeHintHtml?: string;
}
