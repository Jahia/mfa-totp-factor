package org.jahia.modules.upa.mfa.extensions.internal;

import org.apache.commons.lang3.StringUtils;
import org.jahia.modules.upa.mfa.extensions.MfaSiteProvider;
import org.jahia.modules.upa.mfa.extensions.MfaUrls;
import org.jahia.params.valves.LoginUrlProvider;
import org.jahia.params.valves.LogoutUrlProvider;
import org.jahia.services.SpringContextSingleton;
import org.jahia.services.render.URLResolver;
import org.jahia.services.render.URLResolverFactory;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Routes a site's login (and, optionally, logout) through the shared MFA login UI — the page that
 * renders username/password and then lets the user choose between the enrolled factors (TOTP,
 * WebAuthn, ...). This is the factor-agnostic "login provider" form shown in the
 * {@code OSGi-modules-samples/login-provider} example, generalized so it serves the whole MFA
 * factor family rather than any single factor.
 * <p>
 * Jahia consults registered {@link LoginUrlProvider}s from its authentication valve: an
 * unauthenticated user who hits a protected (HTTP&nbsp;401) resource is redirected to a custom
 * login page if a provider supplies one. {@link LogoutUrlProvider} works the same way for
 * sign-out. This single component implements <b>both</b> SPIs.
 * <p>
 * The target URLs are resolved <b>per request</b>, with a per-site override taking precedence
 * over a global default:
 * <ol>
 *   <li><b>per-site</b> — the first non-blank, safe {@code loginUrl} / {@code logoutUrl} reported
 *       by any registered {@link MfaSiteProvider} for the request's site (each factor surfaces its
 *       own per-site administration values through the SPI); falling back to</li>
 *   <li><b>global</b> — the {@code loginUrl} / {@code logoutUrl} keys of the shared OSGi
 *       configuration (PID {@code org.jahia.modules.mfa.extensions}); falling back to</li>
 *   <li><b>none</b> — {@code null}, i.e. Jahia's default {@code /cms/login} / logout handling.</li>
 * </ol>
 * <p>
 * <b>Why {@link #hasCustomLoginUrl()} / {@link #hasCustomLogoutUrl()} always return {@code true}:</b>
 * Jahia's {@code LoginConfig} filters out blank/null {@code getLoginUrl} results per request and
 * tries the next provider, so an always-{@code true} flag with a request-time {@code null} return
 * is safe and non-blocking. {@code LogoutConfig} evaluates {@code hasCustomLogoutUrl()} only at
 * bind time and then consults just the first registered provider — so a <i>stable</i>
 * {@code true} is required for per-site logout URLs (unknowable at bind time) to ever be consulted;
 * when nothing is configured for the request's site, {@code getLogoutUrl} returns {@code null} and
 * Jahia applies its default logout. The trade-off is that, while deployed, this module occupies the
 * first logout-provider slot. The {@link MfaSiteProvider} reference is optional ({@code 0..n}) so
 * this component registers — and claims that slot — even before any factor binds.
 * <p>
 * The global URLs live in an {@link AtomicReference} refreshed by {@link #activate(Map)} (bound to
 * {@code @Modified}), so an operator can change the default by editing the {@code .cfg} with no
 * restart; per-site URLs are read live on each request.
 */
@Component(service = {LoginUrlProvider.class, LogoutUrlProvider.class, MfaLoginLogoutProvider.class},
        immediate = true, configurationPid = "org.jahia.modules.mfa.extensions")
public class MfaLoginLogoutProvider implements LoginUrlProvider, LogoutUrlProvider {

    private static final Logger logger = LoggerFactory.getLogger(MfaLoginLogoutProvider.class);

    static final String CONFIG_LOGIN_URL = "loginUrl";
    static final String CONFIG_LOGOUT_URL = "logoutUrl";

    /** Consumed by the login UI's post-authentication redirect (see {@code services/redirect.tsx}). */
    static final String PARAM_REDIRECT = "redirect";

    private static final String ATTR_SITE_KEY = "siteKey";
    private static final String ATTR_URL_RESOLVER = "urlResolver";
    private static final String BEAN_URL_RESOLVER_FACTORY = "urlResolverFactory";

    /** Global (OSGi config) defaults; per-site values, when set, take precedence. */
    private final AtomicReference<String> loginUrl = new AtomicReference<>();
    private final AtomicReference<String> logoutUrl = new AtomicReference<>();

    /** Each factor's per-site URL view. Read-heavy on the request path → copy-on-write. */
    private final List<MfaSiteProvider> siteProviders = new CopyOnWriteArrayList<>();

    @Reference(service = MfaSiteProvider.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC)
    public void bindSiteProvider(MfaSiteProvider provider) {
        siteProviders.add(provider);
    }

    public void unbindSiteProvider(MfaSiteProvider provider) {
        siteProviders.remove(provider);
    }

    @Activate
    @Modified
    public void activate(Map<String, Object> properties) {
        String login = readUrl(properties, CONFIG_LOGIN_URL);
        String logout = readUrl(properties, CONFIG_LOGOUT_URL);
        this.loginUrl.set(login);
        this.logoutUrl.set(logout);
        logger.info("MFA login/logout URL provider configured (global loginUrl={}, logoutUrl={})",
                login == null ? "<default>" : login, logout == null ? "<default>" : logout);
    }

    /** Read a URL property as a trimmed, non-empty string (or {@code null} if absent/blank). */
    private static String readUrl(Map<String, Object> properties, String key) {
        if (properties == null) {
            return null;
        }
        Object value = properties.get(key);
        return value == null ? null : StringUtils.trimToNull(value.toString());
    }

    @Override
    public boolean hasCustomLoginUrl() {
        return true;
    }

    @Override
    public String getLoginUrl(HttpServletRequest request) {
        return appendRedirect(chooseUrl(perSiteUrl(request, true), loginUrl.get()), redirectTarget(request));
    }

    @Override
    public boolean hasCustomLogoutUrl() {
        return true;
    }

    @Override
    public String getLogoutUrl(HttpServletRequest request) {
        return appendRedirect(chooseUrl(perSiteUrl(request, false), logoutUrl.get()), redirectTarget(request));
    }

    /** Per-site URL wins when set; otherwise fall back to the (trimmed) global default. */
    static String chooseUrl(String perSite, String global) {
        return StringUtils.isNotBlank(perSite) ? perSite : StringUtils.trimToNull(global);
    }

    /**
     * The page the user was actually after, as a safe server-relative URL, or {@code null}.
     * <p>
     * An explicit {@code redirect} parameter wins — Jahia core and templates pass one on
     * {@code /cms/login} / {@code /cms/logout} links, and it must survive the hop to the custom
     * page. Otherwise the target is the original request URI: Jahia's 401 handling FORWARDS to
     * the error servlet before consulting the providers, so the URI the user asked for lives in
     * the standard {@code ERROR} / {@code FORWARD} dispatch attributes, with the request's own
     * URI as the no-dispatch fallback. The auth endpoints (and the error servlet) are never a
     * useful target. Everything is funneled through {@link MfaUrls#isSafeSiteRelativeUrl} — a
     * hostile {@code redirect} parameter must not turn the login flow into an open redirect.
     */
    static String redirectTarget(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String explicit = StringUtils.trimToNull(request.getParameter(PARAM_REDIRECT));
        if (explicit != null) {
            return MfaUrls.isSafeSiteRelativeUrl(explicit) ? explicit : null;
        }
        String uri;
        String query;
        String errorUri = stringAttribute(request, RequestDispatcher.ERROR_REQUEST_URI);
        String forwardUri = stringAttribute(request, RequestDispatcher.FORWARD_REQUEST_URI);
        if (errorUri != null) {
            uri = errorUri;
            query = null; // the servlet spec exposes no query string for ERROR dispatches
        } else if (forwardUri != null) {
            uri = forwardUri;
            query = stringAttribute(request, RequestDispatcher.FORWARD_QUERY_STRING);
        } else {
            uri = request.getRequestURI();
            query = request.getQueryString();
        }
        if (uri == null || isAuthOrErrorEndpoint(uri, request.getContextPath())) {
            return null;
        }
        String target = StringUtils.isBlank(query) ? uri : uri + "?" + query;
        return MfaUrls.isSafeSiteRelativeUrl(target) ? target : null;
    }

    private static String stringAttribute(HttpServletRequest request, String name) {
        Object value = request.getAttribute(name);
        return value instanceof String ? StringUtils.trimToNull((String) value) : null;
    }

    private static boolean isAuthOrErrorEndpoint(String uri, String contextPath) {
        String path = StringUtils.isNotEmpty(contextPath) && uri.startsWith(contextPath)
                ? uri.substring(contextPath.length())
                : uri;
        return path.startsWith("/cms/login") || path.startsWith("/cms/logout") || path.equals("/error");
    }

    /**
     * Append {@code redirect=<target>} to the chosen login/logout URL so the login UI can send
     * the user back to the page they wanted ({@code services/redirect.tsx} validates and consumes
     * the parameter after authentication). Left untouched when there is no URL or no target, when
     * the target IS the chosen page itself (a self-redirect loop), or when the operator hardcoded
     * a {@code redirect} parameter in the configured URL.
     */
    static String appendRedirect(String url, String target) {
        if (url == null || StringUtils.isBlank(target)) {
            return url;
        }
        String urlPath = StringUtils.substringBefore(url, "?");
        String targetPath = StringUtils.substringBefore(target, "?");
        if (urlPath.equals(targetPath) || url.contains(PARAM_REDIRECT + "=")) {
            return url;
        }
        String separator = url.contains("?") ? "&" : "?";
        return url + separator + PARAM_REDIRECT + "=" + URLEncoder.encode(target, StandardCharsets.UTF_8);
    }

    /**
     * The first non-blank, safe {@code loginUrl}/{@code logoutUrl} any registered factor reports
     * for the request's site, or {@code null}. A provider that throws is skipped (fail to "no
     * custom URL" → Jahia default), and an unsafe value is skipped (open-redirect guard).
     */
    private String perSiteUrl(HttpServletRequest request, boolean login) {
        String siteKey = resolveSiteKey(request);
        if (StringUtils.isBlank(siteKey)) {
            return null;
        }
        for (MfaSiteProvider provider : siteProviders) {
            String url = safeUrlFrom(provider, siteKey, login);
            if (url != null) {
                return url;
            }
        }
        return null;
    }

    /**
     * The safe per-site URL a single factor reports, or {@code null} when it reports nothing,
     * throws (→ "no custom URL", Jahia default), or reports an unsafe value (open-redirect guard:
     * stores validate on save, but values written before that guard existed — or via direct JCR
     * tooling — must never be allowed to redirect the login flow off-site).
     */
    private String safeUrlFrom(MfaSiteProvider provider, String siteKey, boolean login) {
        String url;
        try {
            url = login ? provider.getLoginUrl(siteKey) : provider.getLogoutUrl(siteKey);
        } catch (RuntimeException e) {
            logger.debug("Failed to read per-site MFA {} URL from {} for site {}: {}",
                    login ? "login" : "logout", provider.getClass().getName(), siteKey, e.getMessage());
            return null;
        }
        if (StringUtils.isBlank(url)) {
            return null;
        }
        if (!MfaUrls.isSafeSiteRelativeUrl(url)) {
            logger.warn("Ignoring unsafe per-site MFA {} URL on site {} (not a server-relative path)",
                    login ? "login" : "logout", siteKey);
            return null;
        }
        return url;
    }

    /**
     * Resolve the site key for the current request, mirroring Jahia's own
     * {@code ErrorServlet.resolveSiteKey}: the {@code siteKey} request attribute, then a
     * {@code URLResolver} (present for {@code /cms/**} render requests), then a freshly built one.
     * Returns {@code null} when the site cannot be determined.
     */
    private String resolveSiteKey(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        Object attr = request.getAttribute(ATTR_SITE_KEY);
        if (attr instanceof String && StringUtils.isNotBlank((String) attr)) {
            return (String) attr;
        }
        try {
            Object resolver = request.getAttribute(ATTR_URL_RESOLVER);
            if (!(resolver instanceof URLResolver)) {
                Object factory = SpringContextSingleton.getBean(BEAN_URL_RESOLVER_FACTORY);
                if (factory instanceof URLResolverFactory) {
                    resolver = ((URLResolverFactory) factory).createURLResolver(
                            request.getPathInfo(), request.getServerName(), request);
                }
            }
            if (resolver instanceof URLResolver) {
                return StringUtils.trimToNull(((URLResolver) resolver).getSiteKey());
            }
        } catch (Exception e) {
            logger.debug("Could not resolve site for MFA login/logout URL: {}", e.getMessage());
        }
        return null;
    }
}
