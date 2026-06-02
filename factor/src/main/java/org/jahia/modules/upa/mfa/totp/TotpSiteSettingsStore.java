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

    /** Snapshot of the TOTP settings for a site. */
    public static final class TotpSiteSettings {
        public static final TotpSiteSettings DISABLED =
                new TotpSiteSettings(false, false, 0L, Collections.emptyList());

        private final boolean enabled;
        private final boolean enforced;
        private final long graceDays;
        private final List<String> enabledGroups;

        public TotpSiteSettings(boolean enabled, boolean enforced, long graceDays, List<String> enabledGroups) {
            this.enabled = enabled;
            this.enforced = enforced;
            this.graceDays = graceDays;
            this.enabledGroups = enabledGroups == null
                    ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(enabledGroups));
        }

        public boolean isEnabled()  { return enabled; }
        public boolean isEnforced() { return enforced; }
        public long getGraceDays()  { return graceDays; }
        public List<String> getEnabledGroups() { return enabledGroups; }
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
            List<String> groups = new ArrayList<>();
            if (siteNode.hasProperty(PROP_ENABLED_GROUPS)) {
                for (Value v : siteNode.getProperty(PROP_ENABLED_GROUPS).getValues()) {
                    String g = v.getString();
                    if (g != null && !g.trim().isEmpty()) {
                        groups.add(g.trim());
                    }
                }
            }
            return new TotpSiteSettings(enabled, enforced, graceDays, groups);
        });
    }

    /**
     * Persist the settings via the caller's session (i.e. the authenticated admin's session).
     * The caller MUST have already validated site-administrator access — this method does no
     * permission check of its own.
     */
    public void save(JCRSessionWrapper session, String siteKey, boolean enabled, boolean enforced,
                     long graceDays, List<String> enabledGroups) throws RepositoryException {
        if (siteKey == null || siteKey.isEmpty()) {
            throw new IllegalArgumentException("siteKey must not be empty");
        }
        JCRNodeWrapper siteNode = session.getNode("/sites/" + siteKey);
        if (!siteNode.isNodeType(MIXIN_SITE_SETTINGS)) {
            siteNode.addMixin(MIXIN_SITE_SETTINGS);
        }
        siteNode.setProperty(PROP_ENABLED, enabled);
        siteNode.setProperty(PROP_ENFORCED, enforced);
        siteNode.setProperty(PROP_GRACE_DAYS, Math.max(0L, graceDays));
        List<String> cleaned = new ArrayList<>();
        if (enabledGroups != null) {
            for (String g : enabledGroups) {
                if (g != null && !g.trim().isEmpty()) {
                    cleaned.add(g.trim());
                }
            }
        }
        siteNode.setProperty(PROP_ENABLED_GROUPS, cleaned.toArray(new String[0]));
        session.save();
        logger.info("TOTP site settings saved for {}: enabled={}, enforced={}, graceDays={}, groups={}",
                siteKey, enabled, enforced, graceDays, cleaned);
    }
}
