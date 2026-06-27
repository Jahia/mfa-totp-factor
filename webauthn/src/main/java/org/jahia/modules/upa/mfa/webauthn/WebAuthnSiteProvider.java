package org.jahia.modules.upa.mfa.webauthn;

import org.jahia.modules.upa.mfa.extensions.MfaSiteProvider;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

import javax.jcr.RepositoryException;

/**
 * Exposes WebAuthn's per-site activation and per-user registration state to the shared
 * factor-agnostic infrastructure in the {@code mfa-factors-extensions} bundle (the
 * {@code /cms/login} gate and the global enforcement policy), through the {@link MfaSiteProvider}
 * SPI.
 * <p>
 * Per-site activation now comes from the file-backed {@code MfaSiteConfigService} (via
 * {@link WebAuthnSiteSettingsStore}), an in-memory read that does not throw. Per-user registration
 * state still comes from the JCR; that feeds an access-control decision which must fail CLOSED, so
 * a JCR error is rethrown unchecked rather than swallowed.
 */
@Component(service = MfaSiteProvider.class, immediate = true)
public class WebAuthnSiteProvider implements MfaSiteProvider {

    private WebAuthnSiteSettingsStore siteSettingsStore;
    private WebAuthnCredentialStore credentialStore;

    @Reference
    public void setSiteSettingsStore(WebAuthnSiteSettingsStore siteSettingsStore) {
        this.siteSettingsStore = siteSettingsStore;
    }

    @Reference
    public void setCredentialStore(WebAuthnCredentialStore credentialStore) {
        this.credentialStore = credentialStore;
    }

    @Override
    public String getFactorType() {
        return WebAuthnFactorProvider.FACTOR_TYPE;
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
            return credentialStore.hasCredentials(userId);
        } catch (RepositoryException e) {
            throw new IllegalStateException("Could not read WebAuthn credentials for user " + userId, e);
        }
    }
}
