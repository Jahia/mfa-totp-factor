function getSafeRedirect(redirect: string | null, contextPath: string): string {
  const DANGEROUS_SCHEMES = ["javascript:", "data:", "vbscript:", "file:", "blob:"];

  if (!redirect) {
    return contextPath + "/";
  }

  try {
    const decoded = decodeURIComponent(redirect).toLowerCase();

    if (DANGEROUS_SCHEMES.some((scheme) => decoded.startsWith(scheme))) {
      return contextPath + "/";
    }

    if (redirect.startsWith("/") && !redirect.startsWith("//")) {
      return redirect;
    }

    const url = new URL(redirect, window.location.origin);
    if (url.origin === window.location.origin) {
      return url.pathname + url.search + url.hash;
    }
  } catch (e) {
    console.warn("Invalid redirect URL", e);
  }

  return contextPath + "/";
}

/**
 * Redirects the user after a successful authentication, honouring a `redirect=`
 * query-string param only if it is a safe same-origin URL.
 */
export default function redirect(contextPath: string): void {
  const urlParams = new URLSearchParams(window.location.search);
  const redirectParam = urlParams.get("redirect");
  window.location.href = getSafeRedirect(redirectParam, contextPath);
}
