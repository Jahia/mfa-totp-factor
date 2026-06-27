package org.jahia.modules.upa.mfa.webauthn;

import org.jahia.modules.upa.mfa.extensions.MfaSiteConfig;
import org.jahia.modules.upa.mfa.extensions.MfaSiteConfigService;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Reads and writes the per-site WebAuthn policy (enabled / enabledGroups), backed by the file OSGi
 * <b>factory</b> configuration in {@link MfaSiteConfigService} (PID
 * {@code org.jahia.modules.mfa.extensions.site}, one {@code .cfg} per site) — no longer the JCR.
 * Mirrors {@code TotpSiteSettingsStore} without the login/logout URL fields (those are
 * factor-agnostic and owned by the shared per-site config). Enforcement (and its grace window) is
 * GLOBAL — see the extensions {@code MfaGlobalPolicy}.
 * <p>
 * Writes go through {@link MfaSiteConfigService#save}, which merges only this factor's slice so a
 * concurrent TOTP write (which also carries the shared URLs) is never clobbered. Authorization is
 * enforced in the GraphQL layer ({@code MfaAdminAccess}).
 */
@Component(service = WebAuthnSiteSettingsStore.class, immediate = true)
public class WebAuthnSiteSettingsStore {

    private static final Logger logger = LoggerFactory.getLogger(WebAuthnSiteSettingsStore.class);

    private MfaSiteConfigService siteConfigService;

    @Reference
    public void setSiteConfigService(MfaSiteConfigService siteConfigService) {
        this.siteConfigService = siteConfigService;
    }

    /** Snapshot of the WebAuthn settings for a site. */
    public static final class WebAuthnSiteSettings {
        public static final WebAuthnSiteSettings DISABLED =
                new WebAuthnSiteSettings(false, Collections.emptyList());

        private final boolean enabled;
        private final List<String> enabledGroups;

        public WebAuthnSiteSettings(boolean enabled, List<String> enabledGroups) {
            this.enabled = enabled;
            this.enabledGroups = enabledGroups == null
                    ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(enabledGroups));
        }

        public boolean isEnabled()  { return enabled; }
        public List<String> getEnabledGroups() { return enabledGroups; }
    }

    /**
     * Read the settings for the given site key. Returns {@link WebAuthnSiteSettings#DISABLED} when
     * the site has no per-site config — "no config" means WebAuthn is OFF for that site.
     */
    public WebAuthnSiteSettings load(String siteKey) {
        MfaSiteConfig config = siteConfigService.getConfig(siteKey);
        return new WebAuthnSiteSettings(config.isEnabled(WebAuthnFactorProvider.FACTOR_TYPE),
                config.enabledGroups(WebAuthnFactorProvider.FACTOR_TYPE));
    }

    /** Whether at least one site currently has WebAuthn enabled. */
    public boolean isAnySiteEnabled() {
        return siteConfigService.anySiteEnabled(WebAuthnFactorProvider.FACTOR_TYPE);
    }

    /**
     * Persist the settings to the site's {@code .cfg}. The caller MUST have already validated
     * site-administrator access.
     *
     * @throws IOException when the {@code .cfg} cannot be written
     */
    public void save(String siteKey, WebAuthnSiteSettings settings) throws IOException {
        siteConfigService.save(siteKey, current -> current.withFactor(
                WebAuthnFactorProvider.FACTOR_TYPE, settings.isEnabled(), settings.getEnabledGroups()));
        logger.info("WebAuthn site settings saved for {}: enabled={}, groups={}",
                siteKey, settings.isEnabled(), settings.getEnabledGroups());
    }
}
