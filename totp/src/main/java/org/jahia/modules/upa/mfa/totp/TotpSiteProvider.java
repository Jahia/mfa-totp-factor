package org.jahia.modules.upa.mfa.totp;

import org.jahia.modules.upa.mfa.extensions.MfaSiteProvider;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

import javax.jcr.RepositoryException;

/**
 * Exposes TOTP's per-site activation, per-user enrollment state and custom login/logout URLs to
 * the shared factor-agnostic infrastructure in the {@code mfa-factors-extensions} bundle (the
 * {@code /cms/login} gate, the login/logout URL provider and the global enforcement policy),
 * through the {@link MfaSiteProvider} SPI. This is the only seam between TOTP and that bundle for
 * these concerns — it keeps the shared code free of any compile-time dependency on
 * {@link TotpSiteSettingsStore}.
 * <p>
 * Activation and configuration queries feed access-control decisions (the gate, the cross-factor
 * "at least one" check), which must fail CLOSED, so a JCR error is rethrown unchecked rather than
 * swallowed. URL queries feed the URL provider, which falls back to Jahia's default when no safe
 * URL is available, so a JCR error there simply yields {@code null} ("no custom URL").
 */
@Component(service = MfaSiteProvider.class, immediate = true)
public class TotpSiteProvider implements MfaSiteProvider {

    private TotpSiteSettingsStore siteSettingsStore;
    private TotpUserStore userStore;

    @Reference
    public void setSiteSettingsStore(TotpSiteSettingsStore siteSettingsStore) {
        this.siteSettingsStore = siteSettingsStore;
    }

    @Reference
    public void setUserStore(TotpUserStore userStore) {
        this.userStore = userStore;
    }

    @Override
    public String getFactorType() {
        return TotpFactorProvider.FACTOR_TYPE;
    }

    @Override
    public boolean isEnabledForSite(String siteKey) {
        try {
            return siteSettingsStore.load(siteKey).isEnabled();
        } catch (RepositoryException e) {
            // Access-control callers fail CLOSED: propagate so an unhealthy repository blocks.
            throw new IllegalStateException("Could not read TOTP settings for site " + siteKey, e);
        }
    }

    @Override
    public boolean isAnySiteEnabled() {
        try {
            return siteSettingsStore.isAnySiteEnabled();
        } catch (RepositoryException e) {
            throw new IllegalStateException("Could not evaluate TOTP activation across sites", e);
        }
    }

    @Override
    public boolean isConfiguredForUser(String userId) {
        try {
            return userStore.isEnrolled(userId);
        } catch (RepositoryException e) {
            throw new IllegalStateException("Could not read TOTP enrollment state for user " + userId, e);
        }
    }

    @Override
    public String getLoginUrl(String siteKey) {
        return perSiteUrl(siteKey, true);
    }

    @Override
    public String getLogoutUrl(String siteKey) {
        return perSiteUrl(siteKey, false);
    }

    /** The per-site login/logout URL stored for TOTP, or {@code null} (incl. on a JCR error). */
    private String perSiteUrl(String siteKey, boolean login) {
        try {
            TotpSiteSettingsStore.TotpSiteSettings settings = siteSettingsStore.load(siteKey);
            return login ? settings.getLoginUrl() : settings.getLogoutUrl();
        } catch (RepositoryException e) {
            // URL provider falls back to Jahia default; a read error is just "no custom URL".
            return null;
        }
    }
}
