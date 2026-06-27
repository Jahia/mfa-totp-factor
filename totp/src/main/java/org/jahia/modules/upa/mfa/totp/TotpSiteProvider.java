package org.jahia.modules.upa.mfa.totp;

import org.jahia.modules.upa.mfa.extensions.MfaSiteProvider;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

import javax.jcr.RepositoryException;

/**
 * Exposes TOTP's per-site activation and per-user enrollment state to the shared factor-agnostic
 * infrastructure in the {@code mfa-factors-extensions} bundle (the {@code /cms/login} gate and the
 * global enforcement policy), through the {@link MfaSiteProvider} SPI. This is the only seam
 * between TOTP and that bundle for these concerns.
 * <p>
 * Per-site activation now comes from the file-backed {@code MfaSiteConfigService} (via
 * {@link TotpSiteSettingsStore}), an in-memory read that does not throw. Per-user enrollment state
 * still comes from the JCR; that feeds an access-control decision which must fail CLOSED, so a JCR
 * error is rethrown unchecked rather than swallowed. Per-site login/logout URLs are no longer a
 * factor concern — they are read directly from {@code MfaSiteConfigService} by the URL provider.
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
        return siteSettingsStore.load(siteKey).isEnabled();
    }

    @Override
    public boolean isAnySiteEnabled() {
        return siteSettingsStore.isAnySiteEnabled();
    }

    @Override
    public boolean isConfiguredForUser(String userId) {
        try {
            return userStore.isEnrolled(userId);
        } catch (RepositoryException e) {
            throw new IllegalStateException("Could not read TOTP enrollment state for user " + userId, e);
        }
    }
}
