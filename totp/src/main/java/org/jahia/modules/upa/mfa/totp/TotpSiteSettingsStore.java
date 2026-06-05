package org.jahia.modules.upa.mfa.totp;

import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.JCRTemplate;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.PathNotFoundException;
import javax.jcr.RepositoryException;
import javax.jcr.Value;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Reads and writes the {@code upaTotp:siteSettings} mixin on site nodes.
 * <p>
 * Per-site policy:
 * <ul>
 *   <li>{@code enabled}  — whether TOTP MFA is active on this site. When false the
 *       {@link TotpFactorProvider} short-circuits with a "skipped" marker.</li>
 *   <li>{@code enforced} — whether enrollment is mandatory.</li>
 *   <li>{@code graceDays} — when enforcing, how many days a newly-prompted, not-yet-enrolled
 *       user may still sign in before enrollment becomes hard-required ({@code 0} = immediate).</li>
 *   <li>{@code enabledGroups} — if non-empty, the policy applies ONLY to members of these
 *       groups (e.g. {@code editors}); empty = all users of the site.</li>
 * </ul>
 * <p>
 * Reads go through a system session. Writes go through the caller-provided session because
 * they are gated by a {@code siteAdmin} permission check in the GraphQL layer — the standard
 * Jahia ACL applies.
 */
@Component(service = TotpSiteSettingsStore.class, immediate = true)
public class TotpSiteSettingsStore {

    private static final Logger logger = LoggerFactory.getLogger(TotpSiteSettingsStore.class);

    public static final String MIXIN_SITE_SETTINGS = "upaTotp:siteSettings";
    public static final String PROP_ENABLED = "upaTotp:enabled";
    public static final String PROP_ENFORCED = "upaTotp:enforced";
    public static final String PROP_GRACE_DAYS = "upaTotp:graceDays";
    public static final String PROP_ENABLED_GROUPS = "upaTotp:enabledGroups";
    public static final String PROP_LOGIN_URL = "upaTotp:loginUrl";
    public static final String PROP_LOGOUT_URL = "upaTotp:logoutUrl";

    /**
     * Upper bound on the enrollment grace period. An unbounded value would let a site admin
     * effectively disable enforcement forever with a single huge number (silent policy bypass).
     */
    public static final long MAX_GRACE_DAYS = 365L;

    /** Snapshot of the TOTP settings for a site. */
    public static final class TotpSiteSettings {
        public static final TotpSiteSettings DISABLED =
                new TotpSiteSettings(false, false, 0L, Collections.emptyList(), null, null);

        private final boolean enabled;
        private final boolean enforced;
        private final long graceDays;
        private final List<String> enabledGroups;
        private final String loginUrl;
        private final String logoutUrl;

        public TotpSiteSettings(boolean enabled, boolean enforced, long graceDays, List<String> enabledGroups,
                                String loginUrl, String logoutUrl) {
            this.enabled = enabled;
            this.enforced = enforced;
            this.graceDays = graceDays;
            this.enabledGroups = enabledGroups == null
                    ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(enabledGroups));
            this.loginUrl = loginUrl;
            this.logoutUrl = logoutUrl;
        }

        public boolean isEnabled()  { return enabled; }
        public boolean isEnforced() { return enforced; }
        public long getGraceDays()  { return graceDays; }
        public List<String> getEnabledGroups() { return enabledGroups; }

        /** Per-site custom login page URL, or {@code null} if not set (falls back to global config). */
        public String getLoginUrl()  { return loginUrl; }

        /** Per-site custom logout page URL, or {@code null} if not set (falls back to global config). */
        public String getLogoutUrl() { return logoutUrl; }
    }

    /**
     * Whether the value is a safe server-relative redirect target: it must start with a
     * single {@code /}, must NOT be protocol-relative ({@code //host} or the {@code /\host}
     * browser quirk), and must not contain whitespace, control characters or backslashes.
     * Anything else (absolute {@code http(s)://}, {@code javascript:}, …) is rejected —
     * a site admin must never be able to turn the login redirect into an open redirect.
     */
    public static boolean isSafeSiteRelativeUrl(String value) {
        if (value == null || value.isEmpty() || value.charAt(0) != '/') {
            return false;
        }
        if (value.length() > 1 && (value.charAt(1) == '/' || value.charAt(1) == '\\')) {
            return false; // protocol-relative: //host or /\host
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c <= ' ' || c == '\\' || c == 0x7F) {
                return false;
            }
        }
        return true;
    }

    /**
     * Normalize and validate a per-site login/logout URL submitted by a site admin.
     *
     * @return the trimmed value, or {@code null} when blank (= "not configured")
     * @throws IllegalArgumentException when the value is not a safe server-relative path
     *         (see {@link #isSafeSiteRelativeUrl})
     */
    public static String validateSiteRelativeUrl(String value) {
        String trimmed = value == null ? null : value.trim();
        if (trimmed == null || trimmed.isEmpty()) {
            return null;
        }
        if (!isSafeSiteRelativeUrl(trimmed)) {
            throw new IllegalArgumentException(
                    "URL must be a server-relative path starting with '/' (got a value that is absolute, "
                            + "protocol-relative, or contains illegal characters)");
        }
        return trimmed;
    }

    /**
     * Read the settings for the given site key via a JCR system session.
     * Returns {@link TotpSiteSettings#DISABLED} if the site is missing, blank, or has
     * never had the mixin applied — "no config" means TOTP is OFF for that site.
     */
    public TotpSiteSettings load(String siteKey) throws RepositoryException {
        if (siteKey == null || siteKey.isEmpty()) {
            return TotpSiteSettings.DISABLED;
        }
        return JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRNodeWrapper siteNode;
            try {
                siteNode = systemSession.getNode("/sites/" + siteKey);
            } catch (PathNotFoundException e) {
                return TotpSiteSettings.DISABLED;
            }
            if (!siteNode.isNodeType(MIXIN_SITE_SETTINGS)) {
                return TotpSiteSettings.DISABLED;
            }
            boolean enabled = siteNode.hasProperty(PROP_ENABLED)
                    && siteNode.getProperty(PROP_ENABLED).getBoolean();
            boolean enforced = siteNode.hasProperty(PROP_ENFORCED)
                    && siteNode.getProperty(PROP_ENFORCED).getBoolean();
            long graceDays = siteNode.hasProperty(PROP_GRACE_DAYS)
                    ? siteNode.getProperty(PROP_GRACE_DAYS).getLong() : 0L;
            return new TotpSiteSettings(enabled, enforced, graceDays, readGroups(siteNode),
                    readString(siteNode, PROP_LOGIN_URL), readString(siteNode, PROP_LOGOUT_URL));
        });
    }

    /** Read a single-valued string property as a trimmed, non-empty value (or {@code null}). */
    private static String readString(JCRNodeWrapper siteNode, String property) throws RepositoryException {
        if (!siteNode.hasProperty(property)) {
            return null;
        }
        String value = siteNode.getProperty(property).getString();
        return (value == null || value.trim().isEmpty()) ? null : value.trim();
    }

    /** Read the non-blank, trimmed group names from the multi-valued enabledGroups property. */
    private static List<String> readGroups(JCRNodeWrapper siteNode) throws RepositoryException {
        List<String> groups = new ArrayList<>();
        if (!siteNode.hasProperty(PROP_ENABLED_GROUPS)) {
            return groups;
        }
        for (Value v : siteNode.getProperty(PROP_ENABLED_GROUPS).getValues()) {
            String g = v.getString();
            if (g != null && !g.trim().isEmpty()) {
                groups.add(g.trim());
            }
        }
        return groups;
    }

    /**
     * Whether at least one site currently has TOTP {@code enabled} AND {@code enforced}.
     * Used by the {@code /cms/login} gate filter for requests that carry no site context:
     * if any site enforces enrollment, the legacy login endpoint is a potential MFA bypass.
     */
    public boolean isAnySiteEnforcing() throws RepositoryException {
        return Boolean.TRUE.equals(JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
            javax.jcr.query.Query query = session.getWorkspace().getQueryManager().createQuery(
                    "SELECT * FROM [" + MIXIN_SITE_SETTINGS + "] WHERE [" + PROP_ENABLED + "] = true AND ["
                            + PROP_ENFORCED + "] = true",
                    javax.jcr.query.Query.JCR_SQL2);
            query.setLimit(1);
            return query.execute().getNodes().hasNext();
        }));
    }

    /**
     * Persist the settings via the caller's session (i.e. the authenticated admin's session).
     * The caller MUST have already validated site-administrator access — this method does no
     * permission check of its own. It DOES validate the values: graceDays is clamped to
     * {@code [0, MAX_GRACE_DAYS]} and the URLs must be safe server-relative paths
     * (see {@link #validateSiteRelativeUrl}) — this is the single chokepoint every writer
     * goes through, so the open-redirect guard cannot be bypassed by a future caller.
     *
     * @throws IllegalArgumentException when a URL is not a safe server-relative path
     */
    public void save(JCRSessionWrapper session, String siteKey, TotpSiteSettings settings)
            throws RepositoryException {
        if (siteKey == null || siteKey.isEmpty()) {
            throw new IllegalArgumentException("siteKey must not be empty");
        }
        String cleanLoginUrl = validateSiteRelativeUrl(settings.getLoginUrl());
        String cleanLogoutUrl = validateSiteRelativeUrl(settings.getLogoutUrl());
        JCRNodeWrapper siteNode = session.getNode("/sites/" + siteKey);
        if (!siteNode.isNodeType(MIXIN_SITE_SETTINGS)) {
            siteNode.addMixin(MIXIN_SITE_SETTINGS);
        }
        siteNode.setProperty(PROP_ENABLED, settings.isEnabled());
        siteNode.setProperty(PROP_ENFORCED, settings.isEnforced());
        siteNode.setProperty(PROP_GRACE_DAYS, Math.min(Math.max(0L, settings.getGraceDays()), MAX_GRACE_DAYS));
        List<String> cleaned = new ArrayList<>();
        for (String g : settings.getEnabledGroups()) {
            if (g != null && !g.trim().isEmpty()) {
                cleaned.add(g.trim());
            }
        }
        siteNode.setProperty(PROP_ENABLED_GROUPS, cleaned.toArray(new String[0]));
        setOrRemove(siteNode, PROP_LOGIN_URL, cleanLoginUrl);
        setOrRemove(siteNode, PROP_LOGOUT_URL, cleanLogoutUrl);
        session.save();
        logger.info("TOTP site settings saved for {}: enabled={}, enforced={}, graceDays={}, groups={}, "
                        + "loginUrl={}, logoutUrl={}",
                siteKey, settings.isEnabled(), settings.isEnforced(), settings.getGraceDays(), cleaned,
                cleanLoginUrl, cleanLogoutUrl);
    }

    /** Set a single-valued string property to its trimmed value, or remove it when blank. */
    private static void setOrRemove(JCRNodeWrapper siteNode, String property, String value) throws RepositoryException {
        String trimmed = (value == null) ? null : value.trim();
        if (trimmed == null || trimmed.isEmpty()) {
            if (siteNode.hasProperty(property)) {
                siteNode.getProperty(property).remove();
            }
        } else {
            siteNode.setProperty(property, trimmed);
        }
    }
}
