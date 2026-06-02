package org.jahia.modules.upa.mfa.totp.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@GraphQLName("MfaTotpSiteSettingsResult")
@GraphQLDescription("Per-site TOTP policy: active flag, enforcement, grace period and group scoping.")
public class TotpSiteSettingsResult {

    private final String siteKey;
    private final boolean enabled;
    private final boolean enforced;
    private final long graceDays;
    private final List<String> enabledGroups;

    public TotpSiteSettingsResult(String siteKey, boolean enabled, boolean enforced,
                                  long graceDays, List<String> enabledGroups) {
        this.siteKey = siteKey;
        this.enabled = enabled;
        this.enforced = enforced;
        this.graceDays = graceDays;
        this.enabledGroups = enabledGroups == null
                ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(enabledGroups));
    }

    @GraphQLField
    @GraphQLName("siteKey")
    public String getSiteKey() {
        return siteKey;
    }

    @GraphQLField
    @GraphQLName("enabled")
    @GraphQLDescription("True if TOTP MFA is active on this site. False means the factor is skipped at login.")
    public boolean isEnabled() {
        return enabled;
    }

    @GraphQLField
    @GraphQLName("enforced")
    @GraphQLDescription("True if enrollment is mandatory; non-enrolled users are redirected to enrollment (subject to the grace period).")
    public boolean isEnforced() {
        return enforced;
    }

    @GraphQLField
    @GraphQLName("graceDays")
    @GraphQLDescription("When enforcing, the number of days a newly-prompted, not-yet-enrolled user may still sign in (0 = immediate).")
    public long getGraceDays() {
        return graceDays;
    }

    @GraphQLField
    @GraphQLName("enabledGroups")
    @GraphQLDescription("If non-empty, the policy applies ONLY to members of these groups; empty = all users of the site.")
    public List<String> getEnabledGroups() {
        return enabledGroups;
    }
}
