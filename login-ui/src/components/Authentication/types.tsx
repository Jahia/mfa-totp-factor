import type { JCRNodeWrapper } from "org.jahia.services.content";

export interface Props {
  /**
   * The context path of Jahia. `''` by default; `'/<ctx>'` when `CATALINA_CONTEXT` is set.
   */
  contextPath: string;
  logo?: JCRNodeWrapper;
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
