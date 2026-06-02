package org.jahia.modules.upa.mfa.totp;

import org.apache.commons.lang3.StringUtils;
import org.jahia.params.valves.LoginUrlProvider;
import org.jahia.params.valves.LogoutUrlProvider;
import org.jahia.services.SpringContextSingleton;
import org.jahia.services.render.URLResolver;
import org.jahia.services.render.URLResolverFactory;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Routes a site's login (and, optionally, logout) through the TOTP MFA login UI.
 * <p>
 * Jahia consults registered {@link LoginUrlProvider}s from its authentication valve: an
 * unauthenticated user who hits a protected (HTTP&nbsp;401) resource is redirected to a custom
 * login page if a provider supplies one. {@link LogoutUrlProvider} works the same way for
 * sign-out. This single component implements <b>both</b> SPIs (the "login/logout" provider form
 * shown in the {@code OSGi-modules-samples/login-provider} example).
 * <p>
 * The target URLs are resolved <b>per request</b>, with a per-site override taking precedence
 * over a global default:
 * <ol>
 *   <li><b>per-site</b> — the {@code loginUrl} / {@code logoutUrl} stored on the
 *       {@code upaTotp:siteSettings} mixin of the request's site (set from the per-site
 *       administration UI); falling back to</li>
 *   <li><b>global</b> — the {@code loginUrl} / {@code logoutUrl} keys of the module's OSGi
 *       configuration (PID {@code org.jahia.modules.totp}); falling back to</li>
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
 * first logout-provider slot.
 * <p>
 * The global URLs live in an {@link AtomicReference} refreshed by {@link #activate(Map)} (bound to
 * {@code @Modified}), so an operator can change the default by editing the {@code .cfg} with no
 * restart; per-site URLs are read live from the JCR on each request.
 */
@Component(service = {LoginUrlProvider.class, LogoutUrlProvider.class}, immediate = true,
        configurationPid = "org.jahia.modules.totp")
public class MfaTotpLoginLogoutProvider implements LoginUrlProvider, LogoutUrlProvider {

    private static final Logger logger = LoggerFactory.getLogger(MfaTotpLoginLogoutProvider.class);

    static final String CONFIG_LOGIN_URL = "loginUrl";
    static final String CONFIG_LOGOUT_URL = "logoutUrl";

    private static final String ATTR_SITE_KEY = "siteKey";
    private static final String ATTR_URL_RESOLVER = "urlResolver";
    private static final String BEAN_URL_RESOLVER_FACTORY = "urlResolverFactory";

    /** Global (OSGi config) defaults; per-site values, when set, take precedence. */
    private final AtomicReference<String> loginUrl = new AtomicReference<>();
    private final AtomicReference<String> logoutUrl = new AtomicReference<>();

    private TotpSiteSettingsStore siteSettingsStore;

    @Reference
    public void setSiteSettingsStore(TotpSiteSettingsStore siteSettingsStore) {
        this.siteSettingsStore = siteSettingsStore;
    }

    @Activate
    @Modified
    public void activate(Map<String, Object> properties) {
        String login = readUrl(properties, CONFIG_LOGIN_URL);
        String logout = readUrl(properties, CONFIG_LOGOUT_URL);
        this.loginUrl.set(login);
        this.logoutUrl.set(logout);
        logger.info("MFA TOTP login/logout URL provider configured (global loginUrl={}, logoutUrl={})",
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
        return chooseUrl(perSiteUrl(request, true), loginUrl.get());
    }

    @Override
    public boolean hasCustomLogoutUrl() {
        return true;
    }

    @Override
    public String getLogoutUrl(HttpServletRequest request) {
        return chooseUrl(perSiteUrl(request, false), logoutUrl.get());
    }

    /** Per-site URL wins when set; otherwise fall back to the (trimmed) global default. */
    static String chooseUrl(String perSite, String global) {
        return StringUtils.isNotBlank(perSite) ? perSite : StringUtils.trimToNull(global);
    }

    /** The {@code loginUrl}/{@code logoutUrl} stored on the request's site, or {@code null}. */
    private String perSiteUrl(HttpServletRequest request, boolean login) {
        if (siteSettingsStore == null) {
            return null;
        }
        String siteKey = resolveSiteKey(request);
        if (StringUtils.isBlank(siteKey)) {
            return null;
        }
        try {
            TotpSiteSettingsStore.TotpSiteSettings settings = siteSettingsStore.load(siteKey);
            return login ? settings.getLoginUrl() : settings.getLogoutUrl();
        } catch (RepositoryException e) {
            logger.debug("Failed to read per-site TOTP {} URL for site {}: {}",
                    login ? "login" : "logout", siteKey, e.getMessage());
            return null;
        }
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
            logger.debug("Could not resolve site for TOTP login/logout URL: {}", e.getMessage());
        }
        return null;
    }
}
