import DOMPurify from "dompurify";

/**
 * Sanitizes CMS-editor-authored HTML before it is injected via dangerouslySetInnerHTML.
 *
 * The login surface renders as an island: the server pre-renders on GraalVM, then the browser
 * hydrates. DOMPurify needs a real DOM, which GraalVM's SSR runtime does not provide, so we only
 * sanitize on the client (typeof window guard) and render nothing for these slots during SSR - the
 * island re-renders the sanitized markup on hydration. This keeps SSR from crashing while still
 * guaranteeing the final, visible DOM is sanitized.
 *
 * Deliberate trade-off (the alternatives do not work on GraalVM): emitting the RAW editor HTML
 * during SSR would run any embedded event-handler attribute / javascript: URL before hydration can
 * strip it (an XSS window on the highest-trust page), so SSR must not output unsanitized markup. A
 * DOM-free server sanitizer is not viable either: isomorphic-dompurify statically pulls jsdom into
 * the SSR bundle and sanitize-html pulls Node's "path" module - both fail to load under GraalVM and
 * take the whole login UI down. Returning "" on the server and sanitizing on hydration is therefore
 * the security-first choice; the only cost is that these editor-authored help/link slots appear a
 * frame later than the rest of the form (they are non-essential adornments, not the login controls).
 *
 * The config is permissive-but-safe: intended formatting (links, emphasis, lists, line breaks)
 * survives, while scripts, event handlers and dangerous URL schemes are stripped.
 */
export function sanitizeHtml(dirty: string | undefined): string {
  if (!dirty) {
    return "";
  }
  if (typeof window === "undefined") {
    // Server-side (GraalVM): no DOM to sanitize against. The island re-sanitizes on hydration.
    return "";
  }
  return DOMPurify.sanitize(dirty, {
    USE_PROFILES: { html: true },
    ADD_ATTR: ["target", "rel"],
  });
}
