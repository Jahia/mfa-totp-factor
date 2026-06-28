import {
  AddResources,
  buildEndpointUrl,
  buildModuleFileUrl,
  Island,
  jahiaComponent,
} from "@jahia/javascript-modules-library";
import classes from "../Authentication/component.module.css";
import "@fontsource-variable/nunito-sans";
import MfaSettings from "./MfaSettings.client";
import type { MfaSettingsContent } from "./types";

/** Jahia's anonymous user always carries this username. */
const GUEST_USERNAME = "guest";

interface ServerProps {
  title: string;
  introHtml?: string;
  showEmailFactor?: boolean;
}

/**
 * Live-site self-service MFA settings component. Unlike the (anonymous) login component, this view
 * is POST-AUTH: it resolves the current user from the render context and, for a guest, lets the
 * client render a "please sign in" message instead of the management sections (which would call
 * authenticated GraphQL). Every management operation is scoped server-side to the logged-in user.
 */
jahiaComponent(
  {
    nodeType: "totpui:mfaSettings",
    displayName: "MFA Self-Service Settings",
    componentType: "view",
  },
  (props: ServerProps, { renderContext }) => {
    const apiRoot = buildEndpointUrl("/modules/graphql");

    // WCAG 3.1.1: page language from the browsed content locale (BCP 47); fall back defensively.
    let locale: string | undefined;
    try {
      const resourceLocale = renderContext.getMainResource().getLocale();
      const language = resourceLocale.getLanguage();
      const country = resourceLocale.getCountry();
      locale = language ? (country ? `${language}-${country}` : language) : undefined;
    } catch {
      locale = undefined;
    }

    // Resolve the current user (the server is the source of truth for identity; the client never
    // supplies a user id — every op is scoped to this user server-side).
    let username = GUEST_USERNAME;
    let displayName: string | undefined;
    let userEmail: string | null = null;
    try {
      const user = renderContext.getUser();
      username = user.getUsername();
      const first = user.getProperty("j:firstName");
      const last = user.getProperty("j:lastName");
      const full = [first, last].filter(Boolean).join(" ").trim();
      displayName = full || username;
      userEmail = user.getProperty("j:email") || null;
    } catch {
      username = GUEST_USERNAME;
    }
    const isAuthenticated = Boolean(username) && username !== GUEST_USERNAME;

    const content: MfaSettingsContent = {
      contextPath: renderContext.getRequest().getContextPath(),
      siteKey: renderContext.getSite().getSiteKey(),
      isAuthenticated,
      username,
      displayName,
      userEmail,
      showEmailFactor: props.showEmailFactor !== false,
      title: props.title,
      introHtml: props.introHtml,
    };

    return (
      <>
        <AddResources type="css" resources={buildModuleFileUrl("dist/assets/style.css")} />
        <main className={classes.main} lang={locale}>
          <h1>{props.title}</h1>
          <Island component={MfaSettings} props={{ apiRoot, content }} />
        </main>
      </>
    );
  },
);
