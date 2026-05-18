import {
  AddResources,
  buildEndpointUrl,
  buildModuleFileUrl,
  buildNodeUrl,
  Island,
  jahiaComponent,
} from "@jahia/javascript-modules-library";
import classes from "./component.module.css";
import "@fontsource-variable/nunito-sans";
import Authentication from "./Authentication.client";
import type { Props } from "./types";

jahiaComponent(
  {
    nodeType: "totpui:authentication",
    displayName: "TOTP Authentication Component",
    componentType: "view",
  },
  (props: Props, { renderContext }) => {
    const apiRoot = buildEndpointUrl("/modules/graphql");
    const content: Props = {
      contextPath: renderContext.getRequest().getContextPath(),
      loginEmailFieldLabel: props.loginEmailFieldLabel,
      loginPasswordFieldLabel: props.loginPasswordFieldLabel,
      loginSubmitButtonLabel: props.loginSubmitButtonLabel,
      loginBelowPasswordFieldHtml: props.loginBelowPasswordFieldHtml,
      loginAdditionalActionHtml: props.loginAdditionalActionHtml,
      totpCodeVerificationFieldLabel: props.totpCodeVerificationFieldLabel,
      totpCodeVerificationSubmitButtonLabel: props.totpCodeVerificationSubmitButtonLabel,
      totpCodeVerificationHelpHtml: props.totpCodeVerificationHelpHtml,
      totpCodeVerificationBackupCodeHintHtml: props.totpCodeVerificationBackupCodeHintHtml,
    };
    return (
      <>
        <AddResources type="css" resources={buildModuleFileUrl("dist/assets/style.css")} />
        <header className={classes.header}>
          <img
            src={
              props.logo
                ? buildNodeUrl(props.logo)
                : buildModuleFileUrl("static/default-logo.svg")
            }
            alt="Logo"
          />
        </header>
        <main className={classes.main}>
          <Island
            component={Authentication}
            props={{
              apiRoot,
              content,
            }}
          />
        </main>
      </>
    );
  },
);
