package org.jahia.modules.upa.mfa.totp;

import org.apache.commons.lang3.StringUtils;
import org.jahia.params.valves.LoginUrlProvider;
import org.jahia.params.valves.LogoutUrlProvider;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Modified;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Routes a site's login (and, optionally, logout) through the TOTP MFA login UI.
 * <p>
 * Jahia consults registered {@link LoginUrlProvider}s from its authentication valve: when one
 * reports {@link #hasCustomLoginUrl()} {@code == true}, an unauthenticated user who hits a
 * protected (HTTP&nbsp;401) resource is redirected to {@link #getLoginUrl(HttpServletRequest)}
 * instead of the built-in {@code /cms/login}. {@link LogoutUrlProvider} works the same way for
 * sign-out. This single component implements <b>both</b> SPIs (the "login/logout" provider form
 * shown in the {@code OSGi-modules-samples/login-provider} example), so dropping the module on a
 * site is all it takes to make the MFA login UI the site's login page.
 * <p>
 * The target URLs are read from the module's OSGi configuration (PID
 * {@code org.jahia.modules.totp}, the same PID used by {@link TotpSecretCipher}):
 * <ul>
 *   <li>{@code loginUrl}  — the page that renders the {@code totpui:authentication} login UI;</li>
 *   <li>{@code logoutUrl} — an optional custom sign-out page.</li>
 * </ul>
 * Each provider stays <b>inert until its URL is configured</b>: with a blank/absent value
 * {@code hasCustom*Url()} returns {@code false} and Jahia's default handling applies, so simply
 * deploying the module never hijacks login on its own. Because the URLs live in an
 * {@link AtomicReference} refreshed by {@link #activate(Map)} (bound to {@code @Modified}), an
 * operator can re-point or disable the redirect by editing the {@code .cfg} — no restart needed.
 */
@Component(service = {LoginUrlProvider.class, LogoutUrlProvider.class}, immediate = true,
        configurationPid = "org.jahia.modules.totp")
public class MfaTotpLoginLogoutProvider implements LoginUrlProvider, LogoutUrlProvider {

    private static final Logger logger = LoggerFactory.getLogger(MfaTotpLoginLogoutProvider.class);

    static final String CONFIG_LOGIN_URL = "loginUrl";
    static final String CONFIG_LOGOUT_URL = "logoutUrl";

    private final AtomicReference<String> loginUrl = new AtomicReference<>();
    private final AtomicReference<String> logoutUrl = new AtomicReference<>();

    @Activate
    @Modified
    public void activate(Map<String, Object> properties) {
        String login = readUrl(properties, CONFIG_LOGIN_URL);
        String logout = readUrl(properties, CONFIG_LOGOUT_URL);
        this.loginUrl.set(login);
        this.logoutUrl.set(logout);
        logger.info("MFA TOTP login/logout URL provider configured (loginUrl={}, logoutUrl={})",
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
        return StringUtils.isNotBlank(loginUrl.get());
    }

    @Override
    public String getLoginUrl(HttpServletRequest request) {
        return loginUrl.get();
    }

    @Override
    public boolean hasCustomLogoutUrl() {
        return StringUtils.isNotBlank(logoutUrl.get());
    }

    @Override
    public String getLogoutUrl(HttpServletRequest request) {
        return logoutUrl.get();
    }
}
