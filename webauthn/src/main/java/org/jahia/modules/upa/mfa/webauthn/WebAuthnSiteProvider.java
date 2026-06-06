package org.jahia.modules.upa.mfa.webauthn;

import org.jahia.modules.upa.mfa.extensions.MfaSiteProvider;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

import javax.jcr.RepositoryException;

/**
 * Exposes WebAuthn's per-site activation and per-user registration state to the shared
 * factor-agnostic infrastructure in the {@code mfa-factors-extensions} bundle (the
 * {@code /cms/login} gate, the global enforcement policy), through the {@link MfaSiteProvider}
 * SPI. WebAuthn has no custom per-site login/logout pages of its own, so the URL methods keep
 * the SPI defaults ({@code null} — defer to the global config / Jahia default).
 * <p>
 * These queries feed access-control decisions, which must fail CLOSED, so a JCR error is
 * rethrown unchecked rather than swallowed.
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
        try {
            return siteSettingsStore.load(siteKey).isEnabled();
        } catch (RepositoryException e) {
            // Access-control callers fail CLOSED: propagate so an unhealthy repository blocks.
            throw new IllegalStateException("Could not read WebAuthn settings for site " + siteKey, e);
        }
    }

    @Override
    public boolean isAnySiteEnabled() {
        try {
            return siteSettingsStore.isAnySiteEnabled();
        } catch (RepositoryException e) {
            throw new IllegalStateException("Could not evaluate WebAuthn activation across sites", e);
        }
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
