/** Props for the self-service MFA settings panel (server-resolved, serialized to the Island). */
export interface MfaSettingsContent {
  /** Request context path ('' or '/<ctx>'), for building links. */
  contextPath: string;
  /** Current site key (server-resolved). */
  siteKey?: string;
  /** Whether a non-guest user is logged in. When false, the panel shows a sign-in prompt only. */
  isAuthenticated: boolean;
  /** The logged-in user's login name (display only; the server scopes every op to this user). */
  username: string;
  /** Best-effort display name (first/last or username). */
  displayName?: string;
  /** The user's email if set, else null — drives the read-only email_code section. */
  userEmail?: string | null;
  /** Whether to render the informational email_code section. */
  showEmailFactor: boolean;
  /** Optional author-supplied heading and intro (rich text, pre-sanitized server-side). */
  title?: string;
  introHtml?: string;
}
