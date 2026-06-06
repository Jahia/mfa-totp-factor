package org.jahia.modules.upa.mfa.extensions;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Aggregated view over every registered {@link MfaSiteProvider}, combined with the
 * {@link MfaGlobalPolicy}. Used by security-sensitive callers (the pre-authentication inline
 * enrollment mutations) that need ONE answer across all factors.
 */
@Component(service = MfaFactorDirectory.class, immediate = true)
public class MfaFactorDirectory {

    private MfaGlobalPolicy globalPolicy;
    private final List<MfaSiteProvider> siteProviders = new CopyOnWriteArrayList<>();

    @Reference
    public void setGlobalPolicy(MfaGlobalPolicy globalPolicy) {
        this.globalPolicy = globalPolicy;
    }

    @Reference(service = MfaSiteProvider.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC)
    public void bindSiteProvider(MfaSiteProvider provider) {
        siteProviders.add(provider);
    }

    public void unbindSiteProvider(MfaSiteProvider provider) {
        siteProviders.remove(provider);
    }

    /**
     * The factor types currently registered through the {@link MfaSiteProvider} SPI (distinct,
     * registration order). Used by the administration UI to offer one enforcement checkbox per
     * installed factor, and by the configuration mutation to refuse unknown factor names (a typo
     * in {@code enforcedFactors} would create an unsatisfiable policy).
     */
    public List<String> getRegisteredFactorTypes() {
        List<String> types = new ArrayList<>();
        for (MfaSiteProvider provider : siteProviders) {
            String type = provider.getFactorType();
            if (type != null && !types.contains(type)) {
                types.add(type);
            }
        }
        return Collections.unmodifiableList(types);
    }

    /**
     * The factor types the user has configured, among the registered providers — scoped to the
     * site when one is given (a factor disabled on the site cannot be used to verify there).
     * Drives the login UI's factor chooser: offering an unconfigured factor is a dead end (its
     * pick-one row defers to a configured sibling and the user lands on a different factor than
     * the one they picked).
     * <p>
     * <b>Error contract:</b> a provider that cannot answer propagates its unchecked exception —
     * the GraphQL layer surfaces it and the CLIENT falls back to the unfiltered list. That
     * fallback is safe here (unlike {@link #hasAnyEnforcedFactorConfigured}): the chooser is
     * cosmetic, verification stays enforced server-side either way.
     */
    public List<String> configuredFactorsForUser(String userId, String siteKey) {
        List<String> result = new ArrayList<>();
        for (MfaSiteProvider provider : siteProviders) {
            String type = provider.getFactorType();
            if (type == null || result.contains(type)) {
                continue;
            }
            boolean usableOnSite = siteKey == null || siteKey.trim().isEmpty() || provider.isEnabledForSite(siteKey);
            if (usableOnSite && provider.isConfiguredForUser(userId)) {
                result.add(type);
            }
        }
        return Collections.unmodifiableList(result);
    }

    /**
     * Whether the user has at least one globally enforced factor configured.
     * <p>
     * <b>Error contract:</b> a provider that cannot answer (unhealthy repository) propagates its
     * unchecked exception — callers that guard pre-authentication enrollment MUST fail closed
     * (refuse the enrollment) rather than assume "not configured", because this check is the
     * anti-takeover barrier: an account that already owns a factor must never accept a new one
     * from a caller who only proved the password.
     */
    public boolean hasAnyEnforcedFactorConfigured(String userId) {
        for (MfaSiteProvider provider : siteProviders) {
            if (globalPolicy.isEnforced(provider.getFactorType()) && provider.isConfiguredForUser(userId)) {
                return true;
            }
        }
        return false;
    }
}
