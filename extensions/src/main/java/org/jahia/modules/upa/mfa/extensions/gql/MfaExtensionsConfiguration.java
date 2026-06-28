package org.jahia.modules.upa.mfa.extensions.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The global MFA configuration (PID {@code org.jahia.modules.mfa.extensions}) as exposed to the
 * server administration UI.
 */
@GraphQLName("MfaExtensionsConfiguration")
@GraphQLDescription("Global MFA configuration: enforcement policy, /cms/login gate and login/logout routing.")
public class MfaExtensionsConfiguration {

    private final List<String> enforcedFactors;
    private final long graceDays;
    private final boolean loginGateEnabled;
    private final String loginGateIpWhitelist;
    private final String loginUrl;
    private final String logoutUrl;
    private final String resetNotifyEmail;
    private final boolean loginGateTrustForwardedFor;
    private final List<String> registeredFactors;

    public MfaExtensionsConfiguration(List<String> enforcedFactors, long graceDays, boolean loginGateEnabled,
                                      String loginGateIpWhitelist, String loginUrl, String logoutUrl,
                                      String resetNotifyEmail, boolean loginGateTrustForwardedFor,
                                      List<String> registeredFactors) {
        this.enforcedFactors = immutable(enforcedFactors);
        this.graceDays = graceDays;
        this.loginGateEnabled = loginGateEnabled;
        this.loginGateIpWhitelist = loginGateIpWhitelist;
        this.loginUrl = loginUrl;
        this.logoutUrl = logoutUrl;
        this.resetNotifyEmail = resetNotifyEmail;
        this.loginGateTrustForwardedFor = loginGateTrustForwardedFor;
        this.registeredFactors = immutable(registeredFactors);
    }

    private static List<String> immutable(List<String> values) {
        return values == null ? Collections.emptyList()
                : Collections.unmodifiableList(new ArrayList<>(values));
    }

    @GraphQLField
    @GraphQLName("enforcedFactors")
    @GraphQLDescription("Factor types enforced platform-wide; a user must have at least one configured. Empty = no enforcement.")
    public List<String> getEnforcedFactors() {
        return enforcedFactors;
    }

    @GraphQLField
    @GraphQLName("graceDays")
    @GraphQLDescription("Days a user with no enforced factor configured may still sign in (0 = immediate, max 365).")
    public long getGraceDays() {
        return graceDays;
    }

    @GraphQLField
    @GraphQLName("loginGateEnabled")
    @GraphQLDescription("Master switch for the /cms/login gate.")
    public boolean isLoginGateEnabled() {
        return loginGateEnabled;
    }

    @GraphQLField
    @GraphQLName("loginGateIpWhitelist")
    @GraphQLDescription("Comma-separated IPv4/IPv6 addresses or CIDR blocks allowed through the gate.")
    public String getLoginGateIpWhitelist() {
        return loginGateIpWhitelist;
    }

    @GraphQLField
    @GraphQLName("loginGateTrustForwardedFor")
    @GraphQLDescription("Whether the gate reads the client IP from the first X-Forwarded-For entry (default true). "
            + "Set false when NOT behind a proxy that overwrites the header, so the spoof-proof socket address is used.")
    public boolean isLoginGateTrustForwardedFor() {
        return loginGateTrustForwardedFor;
    }

    @GraphQLField
    @GraphQLName("loginUrl")
    @GraphQLDescription("Global default login page URL (per-site values take precedence).")
    public String getLoginUrl() {
        return loginUrl;
    }

    @GraphQLField
    @GraphQLName("logoutUrl")
    @GraphQLDescription("Global default logout page URL (per-site values take precedence).")
    public String getLogoutUrl() {
        return logoutUrl;
    }

    @GraphQLField
    @GraphQLName("resetNotifyEmail")
    @GraphQLDescription("Comma-separated administrator email(s) notified when a locked-out user requests an MFA reset. Empty = feature off.")
    public String getResetNotifyEmail() {
        return resetNotifyEmail;
    }

    @GraphQLField
    @GraphQLName("registeredFactors")
    @GraphQLDescription("Factor types currently installed (one enforcement option per entry).")
    public List<String> getRegisteredFactors() {
        return registeredFactors;
    }
}
