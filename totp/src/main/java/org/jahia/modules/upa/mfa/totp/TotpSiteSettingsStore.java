package org.jahia.modules.upa.mfa.totp;

import org.jahia.modules.upa.mfa.extensions.MfaSiteConfig;
import org.jahia.modules.upa.mfa.extensions.MfaSiteConfigService;
import org.jahia.modules.upa.mfa.extensions.MfaUrls;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Reads and writes the per-site TOTP policy (enabled / enabledGroups) plus the factor-agnostic
 * per-site login/logout URLs, backed by the file OSGi <b>factory</b> configuration in
 * {@link MfaSiteConfigService} (PID {@code org.jahia.modules.mfa.extensions.site}, one {@code .cfg}
 * per site) — no longer the JCR. Enforcement (and its grace window) is GLOBAL — see the extensions
 * {@code MfaGlobalPolicy}.
 * <p>
 * Writes go through {@link MfaSiteConfigService#save}, which merges only this factor's slice (and
 * the shared URLs) so a concurrent WebAuthn write is never clobbered. Authorization is enforced in
 * the GraphQL layer ({@code MfaAdminAccess}); the URL open-redirect guard
 * ({@link MfaUrls#validateSiteRelativeUrl}) is applied here as the single chokepoint every writer
 * goes through.
 */
@Component(service = TotpSiteSettingsStore.class, immediate = true)
public class TotpSiteSettingsStore {

    private static final Logger logger = LoggerFactory.getLogger(TotpSiteSettingsStore.class);

    private MfaSiteConfigService siteConfigService;

    @Reference
    public void setSiteConfigService(MfaSiteConfigService siteConfigService) {
        this.siteConfigService = siteConfigService;
    }

    /**
     * Snapshot of the TOTP settings for a site.
     * <p>
     * The login/logout URLs are factor-agnostic and shared in the same per-site {@code .cfg}, and
     * each is tracked INDEPENDENTLY by its own "provided" flag so an omitted field is never erased
     * by a write that only touches the other one. Per field: when its provided flag is {@code false}
     * the store keeps the previously stored value (true PARTIAL update); when {@code true} the value
     * is written through ({@code null}/blank clears, a path sets).
     */
    public static final class TotpSiteSettings {
        public static final TotpSiteSettings DISABLED =
                new TotpSiteSettings(false, Collections.emptyList(), null, null, false, false);

        private final boolean enabled;
        private final List<String> enabledGroups;
        private final String loginUrl;
        private final String logoutUrl;
        private final boolean loginUrlProvided;
        private final boolean logoutUrlProvided;

        public TotpSiteSettings(boolean enabled, List<String> enabledGroups,
                                String loginUrl, String logoutUrl,
                                boolean loginUrlProvided, boolean logoutUrlProvided) {
            this.enabled = enabled;
            this.enabledGroups = enabledGroups == null
                    ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(enabledGroups));
            this.loginUrl = loginUrl;
            this.logoutUrl = logoutUrl;
            this.loginUrlProvided = loginUrlProvided;
            this.logoutUrlProvided = logoutUrlProvided;
        }

        public boolean isEnabled()  { return enabled; }
        public List<String> getEnabledGroups() { return enabledGroups; }

        /** Per-site custom login page URL, or {@code null} if not set (falls back to global config). */
        public String getLoginUrl()  { return loginUrl; }

        /** Per-site custom logout page URL, or {@code null} if not set (falls back to global config). */
        public String getLogoutUrl() { return logoutUrl; }

        /**
         * Whether the login URL should be written. When {@code false} the store keeps the previously
         * stored login URL (partial update); when {@code true} it writes the value (a {@code null}
         * clears it, a path sets it).
         */
        public boolean isLoginUrlProvided() { return loginUrlProvided; }

        /**
         * Whether the logout URL should be written. When {@code false} the store keeps the previously
         * stored logout URL (partial update); when {@code true} it writes the value (a {@code null}
         * clears it, a path sets it).
         */
        public boolean isLogoutUrlProvided() { return logoutUrlProvided; }
    }

    /**
     * Read the settings for the given site key. Returns {@link TotpSiteSettings#DISABLED} when the
     * site has no per-site config — "no config" means TOTP is OFF for that site.
     */
    public TotpSiteSettings load(String siteKey) {
        MfaSiteConfig config = siteConfigService.getConfig(siteKey);
        return new TotpSiteSettings(config.isEnabled(TotpFactorProvider.FACTOR_TYPE),
                config.enabledGroups(TotpFactorProvider.FACTOR_TYPE),
                config.getLoginUrl(), config.getLogoutUrl(), true, true);
    }

    /** Whether at least one site currently has TOTP enabled. */
    public boolean isAnySiteEnabled() {
        return siteConfigService.anySiteEnabled(TotpFactorProvider.FACTOR_TYPE);
    }

    /**
     * Persist the settings to the site's {@code .cfg}. The caller MUST have already validated
     * site-administrator access - this method does no permission check of its own. It DOES validate
     * the values: the URLs must be safe server-relative paths
     * ({@link MfaUrls#validateSiteRelativeUrl}).
     * <p>
     * The login/logout URLs are factor-agnostic and shared in the same per-site {@code .cfg}. Each
     * URL is a true PARTIAL update driven INDEPENDENTLY by its own flag
     * ({@link TotpSiteSettings#isLoginUrlProvided()} / {@link TotpSiteSettings#isLogoutUrlProvided()}):
     * when a field's flag is {@code false} its previously stored value is kept (only the sibling URL
     * and this factor's slice are written); when {@code true} that field is written through, where a
     * blank value (validated to {@code null}) CLEARS it and a path SETS it. An omitted field can
     * therefore never erase its sibling.
     *
     * @throws IllegalArgumentException when a URL is not a safe server-relative path
     * @throws IOException              when the {@code .cfg} cannot be written
     */
    public void save(String siteKey, TotpSiteSettings settings) throws IOException {
        // validateSiteRelativeUrl("") returns null, which is the correct "clear" value here. Validate
        // up front so an invalid path fails fast (and before the merge lambda runs).
        String cleanLoginUrl = settings.isLoginUrlProvided()
                ? MfaUrls.validateSiteRelativeUrl(settings.getLoginUrl()) : null;
        String cleanLogoutUrl = settings.isLogoutUrlProvided()
                ? MfaUrls.validateSiteRelativeUrl(settings.getLogoutUrl()) : null;
        siteConfigService.save(siteKey, current -> {
            // Per field: use the validated submitted value when provided, otherwise keep the current
            // stored value so an omitted field is preserved (never erases its sibling).
            String newLogin = settings.isLoginUrlProvided() ? cleanLoginUrl : current.getLoginUrl();
            String newLogout = settings.isLogoutUrlProvided() ? cleanLogoutUrl : current.getLogoutUrl();
            return current
                    .withFactor(TotpFactorProvider.FACTOR_TYPE, settings.isEnabled(), settings.getEnabledGroups())
                    .withUrls(newLogin, newLogout);
        });
        logger.info("TOTP site settings saved for {}: enabled={}, groups={}, loginUrlProvided={}, "
                        + "logoutUrlProvided={}", siteKey, settings.isEnabled(), settings.getEnabledGroups(),
                settings.isLoginUrlProvided(), settings.isLogoutUrlProvided());
    }
}
